/* client.c — a client of the NeuroMZ protocol: the handshake and its authentication
 * (PROTOCOL §5, §6), frames in and out, and calls — one request and its
 * answer, uploads and downloads in DATA frames with their END (§8), and
 * subscriptions (§9). One request at a time per nmzp_client; frames of
 * other requests are dropped. PING is answered as frames are read. */
#include "nmzp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK (256u * 1024u) /* DATA frames we send */

void nmzp_frame_init(nmzp_frame *f) {
    memset(f, 0, sizeof *f);
    nmzp_buf_init(&f->payload);
}

void nmzp_frame_free(nmzp_frame *f) { nmzp_buf_free(&f->payload); }

void nmzp_client_init(nmzp_client *c, const char *host, int port, const char *token) {
    memset(c, 0, sizeof *c);
    snprintf(c->host, sizeof c->host, "%s", host ? host : "127.0.0.1");
    c->port = port > 0 ? port : NMZP_DEFAULT_PORT;
    snprintf(c->token, sizeof c->token, "%s", token ? token : "");
    snprintf(c->name, sizeof c->name, "nmzp");
    snprintf(c->version, sizeof c->version, "%s", NMZP_VERSION);
    c->timeout_ms = 30000;
    c->sock = NMZP_NO_SOCKET;
    nmzp_buf_init(&c->rx);
}

void nmzp_client_close(nmzp_client *c) {
    if (c->sock != NMZP_NO_SOCKET) nmzp_close(c->sock);
    c->sock = NMZP_NO_SOCKET;
    c->connected = 0;
    nmzp_buf_free(&c->rx);
}

uint32_t nmzp_client_id(nmzp_client *c) {
    if (++c->next_id == 0) c->next_id = 1;
    return c->next_id;
}

static void set_err(nmzp_client *c, nmzp_error *e, const char *msg) {
    snprintf(c->err, sizeof c->err, "%s", msg);
    if (e) {
        e->code = -1;
        snprintf(e->name, sizeof e->name, "connection");
        snprintf(e->message, sizeof e->message, "%s", msg);
    }
}

/* the connection failed: close it (the next call reconnects) */
static int broken(nmzp_client *c, nmzp_error *e, const char *msg) {
    set_err(c, e, msg);
    nmzp_client_close(c);
    return -1;
}

int nmzp_client_send(nmzp_client *c, int type, int flags, uint32_t id, const void *p, size_t n) {
    if (c->sock == NMZP_NO_SOCKET) return -1;
    if (nmzp_frame_send(c->sock, type, flags, id, p, n)) {
        snprintf(c->err, sizeof c->err, "sending to %s:%d failed: the connection is gone", c->host, c->port);
        return -1;
    }
    return 0;
}

int nmzp_client_recv(nmzp_client *c, nmzp_frame *f, int timeout_ms) {
    double deadline = nmzp_clock() + timeout_ms / 1000.0;
    uint32_t max = c->connected ? (c->max_frame_out > NMZP_MIN_FRAME ? c->max_frame_out : NMZP_MIN_FRAME) : NMZP_HANDSHAKE_MAX;
    if (c->sock == NMZP_NO_SOCKET) {
        snprintf(c->err, sizeof c->err, "not connected");
        return -1;
    }
    for (;;) {
        nmzp_frame_head h;
        const unsigned char *payload;
        size_t used;
        int code = 0, r = nmzp_frame_next(c->rx.data ? c->rx.data : "", c->rx.len, max, &h, &payload, &used, &code);
        if (r < 0) {
            snprintf(c->err, sizeof c->err, "%s:%d sent a bad frame (%s)", c->host, c->port,
                     nmzp_error_name(code) ? nmzp_error_name(code) : "?");
            return -1;
        }
        if (r == 1) {
            f->h = h;
            nmzp_buf_clear(&f->payload);
            if (nmzp_buf_add(&f->payload, payload, h.length)) {
                snprintf(c->err, sizeof c->err, "out of memory");
                return -1;
            }
            nmzp_buf_consume(&c->rx, used);
            if (h.type == NMZP_PING && c->connected) { /* §10: answered at once, not returned */
                if (nmzp_client_send(c, NMZP_PONG, 0, h.id, f->payload.data, f->payload.len)) return -1;
                continue;
            }
            return 1;
        }
        {
            char tmp[65536];
            double left = deadline - nmzp_clock();
            long k;
            /* timeout 0 still looks once at the socket (a poll) */
            k = nmzp_recv(c->sock, tmp, sizeof tmp, timeout_ms < 0 ? 3600000 : left > 0 ? (int)(left * 1000) + 1 : 0);
            if (k == -2) {
                if (timeout_ms < 0) continue;
                return 0;
            }
            if (k <= 0) {
                snprintf(c->err, sizeof c->err, "%s:%d closed the connection%s", c->host, c->port,
                         c->rx.len ? " in the middle of a frame" : "");
                return -1;
            }
            if (nmzp_buf_add(&c->rx, tmp, (size_t)k)) {
                snprintf(c->err, sizeof c->err, "out of memory");
                return -1;
            }
        }
    }
}

/* an ERROR payload into e */
static void read_error(const nmzp_buf *payload, nmzp_error *e) {
    nmzp_val *v = nmzp_decode(payload->data, payload->len, NULL, 0);
    long long code = 0;
    memset(e, 0, sizeof *e);
    if (v && nmzp_get_int(v, "code", &code)) e->code = (int)code;
    else e->code = NMZP_E_INTERNAL;
    snprintf(e->name, sizeof e->name, "%s",
             nmzp_get_str(v, "name") ? nmzp_get_str(v, "name") : nmzp_error_name(e->code) ? nmzp_error_name(e->code) : "?");
    snprintf(e->message, sizeof e->message, "%s", nmzp_get_str(v, "message") ? nmzp_get_str(v, "message") : "");
    nmzp_val_free(v);
}

/* ------------------------------------------------------- the handshake */

static int join_strs(const nmzp_val *arr, char *out, size_t n) {
    size_t i, w = 0;
    out[0] = '\0';
    if (!arr || arr->type != NMZP_ARRAY) return 0;
    for (i = 0; i < arr->n; i++) {
        const char *s = nmzp_str(arr->items[i]);
        int k;
        if (!s) continue;
        k = snprintf(out + w, n - w, "%s%s", w ? "," : "", s);
        if (k < 0 || (size_t)k >= n - w) break;
        w += (size_t)k;
    }
    return 1;
}

int nmzp_client_connect(nmzp_client *c, nmzp_error *e) {
    char err[400], msg[1100];
    nmzp_frame f;
    nmzp_val *g = NULL, *wv = NULL;
    nmzp_buf hello;
    nmzp_mw w;
    unsigned char key[32], kid[8], nc[32], proof[32], expect[32], ns[32], prefix[NMZP_PREFIX];
    const unsigned char *nonce;
    size_t nn = 0;
    const char *auth;
    long long mf = 0, minmaj = 2, v;
    int major = 0, minor = 0, r, use_auth;
    nmzp_error tmp;
    if (!e) e = &tmp;
    memset(e, 0, sizeof *e);
    nmzp_client_close(c);
    nmzp_buf_init(&c->rx);
    c->sock = nmzp_connect(c->host, c->port, c->timeout_ms, err, sizeof err);
    if (c->sock == NMZP_NO_SOCKET) {
        snprintf(msg, sizeof msg, "cannot connect to %s:%d: %s", c->host, c->port, err);
        set_err(c, e, msg);
        return -1;
    }
    nmzp_frame_init(&f);
    nmzp_buf_init(&hello);
    /* the greeting */
    r = nmzp_client_recv(c, &f, c->timeout_ms);
    if (r <= 0) {
        if (r == 0)
            snprintf(msg, sizeof msg,
                     "%s:%d sent no greeting within %d s: it is not a NeuroMZ server",
                     c->host, c->port, c->timeout_ms / 1000);
        else snprintf(msg, sizeof msg, "%s", c->err);
        goto fail;
    }
    if (f.h.type == NMZP_ERROR && f.h.id == 0) {
        read_error(&f.payload, e);
        snprintf(msg, sizeof msg, "%.255s:%d refused the connection: %.39s: %.380s", c->host, c->port, e->name, e->message);
        snprintf(c->err, sizeof c->err, "%.599s", msg);
        nmzp_frame_free(&f);
        nmzp_client_close(c);
        return -1;
    }
    if (f.h.type != NMZP_GREETING || nmzp_prefix_get(f.payload.data, f.payload.len, &major, &minor)) {
        snprintf(msg, sizeof msg, "%s:%d is not a NeuroMZ server (no protocol greeting)", c->host, c->port);
        goto fail;
    }
    g = nmzp_decode(f.payload.data + NMZP_PREFIX, f.payload.len - NMZP_PREFIX, err, sizeof err);
    if (!g) {
        snprintf(msg, sizeof msg, "%s:%d sent a greeting this client cannot read: %s", c->host, c->port, err);
        goto fail;
    }
    nmzp_get_int(g, "min_major", &minmaj);
    if (NMZP_PROTOCOL_MAJOR < minmaj || NMZP_PROTOCOL_MAJOR > major) {
        snprintf(msg, sizeof msg, "the server at %s:%d speaks protocol %lld.x to %d.%d; this client speaks %s", c->host,
                 c->port, minmaj, major, minor, NMZP_PROTOCOL);
        goto fail;
    }
    c->major = NMZP_PROTOCOL_MAJOR;
    c->minor = major == NMZP_PROTOCOL_MAJOR && minor < NMZP_PROTOCOL_MINOR ? minor : NMZP_PROTOCOL_MINOR;
    snprintf(c->server, sizeof c->server, "%s", nmzp_get_str(g, "server") ? nmzp_get_str(g, "server") : "?");
    snprintf(c->server_version, sizeof c->server_version, "%s",
             nmzp_get_str(g, "version") ? nmzp_get_str(g, "version") : "?");
    join_strs(nmzp_get(g, "capabilities"), c->capabilities, sizeof c->capabilities);
    if (!nmzp_get_int(g, "max_frame", &mf) || mf < (long long)NMZP_MIN_FRAME || mf > 0xffffffffLL) mf = NMZP_MIN_FRAME;
    c->max_frame = (uint32_t)mf;
    auth = nmzp_get_str(g, "auth");
    nonce = nmzp_bin(nmzp_get(g, "nonce"), &nn);
    if (!auth || (!strcmp(auth, "hmac-sha256") && (!nonce || nn != 32))) {
        snprintf(msg, sizeof msg, "%s:%d sent a greeting without auth or nonce", c->host, c->port);
        goto fail;
    }
    use_auth = !strcmp(auth, "hmac-sha256");
    if (!use_auth && strcmp(auth, "none")) {
        snprintf(msg, sizeof msg, "%s:%d asks for authentication by '%.40s', which this client does not know", c->host,
                 c->port, auth);
        goto fail;
    }
    if (use_auth && !c->token[0]) {
        snprintf(msg, sizeof msg, "%s:%d needs a token (`token =` in the profile, or --token)", c->host, c->port);
        goto fail;
    }
    if (!use_auth && c->token[0] && !c->allow_no_auth) {
        snprintf(msg, sizeof msg,
                 "%s:%d does not authenticate clients (auth = none), but this client has a token: it stops, since "
                 "anyone on the path could pose as that server. Remove the token to use it.",
                 c->host, c->port);
        goto fail;
    }
    c->server_auth = use_auth;
    /* the hello */
    nmzp_prefix_put(prefix, c->major, c->minor);
    nmzp_buf_add(&hello, prefix, sizeof prefix);
    nmzp_mw_init(&w, &hello);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "client", c->name);
    nmzp_mw_kstr(&w, "version", c->version);
    nmzp_mw_kstr(&w, "auth", use_auth ? "hmac-sha256" : "none");
    if (use_auth) {
        memcpy(ns, nonce, 32);
        if (nmzp_random(nc, sizeof nc)) {
            snprintf(msg, sizeof msg, "the system's random generator failed");
            goto fail;
        }
        nmzp_auth_key(c->token, strlen(c->token), key);
        nmzp_auth_key_id(key, kid);
        nmzp_auth_proof(key, 0, ns, nc, proof);
        nmzp_mw_kbin(&w, "key_id", kid, 8);
        nmzp_mw_kbin(&w, "nonce", nc, 32);
        nmzp_mw_kbin(&w, "proof", proof, 32);
    }
    if (c->max_frame_in >= (int)NMZP_MIN_FRAME) nmzp_mw_kint(&w, "max_frame", c->max_frame_in);
    nmzp_mw_end_map(&w);
    if (nmzp_mw_done(&w) || nmzp_client_send(c, NMZP_HELLO, 0, 0, hello.data, hello.len)) {
        snprintf(msg, sizeof msg, "%s", c->err[0] ? c->err : "cannot send the hello");
        goto fail;
    }
    /* the welcome */
    r = nmzp_client_recv(c, &f, c->timeout_ms);
    if (r <= 0) {
        snprintf(msg, sizeof msg, "%s", r == 0 ? "no answer to the hello in time" : c->err);
        goto fail;
    }
    if (f.h.type == NMZP_ERROR) {
        read_error(&f.payload, e);
        snprintf(msg, sizeof msg, "%.255s:%d: %.39s: %.380s", c->host, c->port, e->name, e->message);
        snprintf(c->err, sizeof c->err, "%.599s", msg);
        nmzp_val_free(g);
        nmzp_buf_free(&hello);
        nmzp_frame_free(&f);
        nmzp_client_close(c);
        return -1;
    }
    if (f.h.type != NMZP_WELCOME || !(wv = nmzp_decode(f.payload.data, f.payload.len, err, sizeof err))) {
        snprintf(msg, sizeof msg, "%s:%d answered the hello with a %s frame", c->host, c->port,
                 nmzp_frame_name(f.h.type) ? nmzp_frame_name(f.h.type) : "bad");
        goto fail;
    }
    if (use_auth) {
        size_t pn = 0;
        const unsigned char *sp = nmzp_bin(nmzp_get(wv, "proof"), &pn);
        nmzp_auth_proof(key, 1, ns, nc, expect);
        if (!sp || pn != 32 || !nmzp_ct_equal(sp, expect, 32)) {
            snprintf(msg, sizeof msg,
                     "%s:%d could not prove that it holds this token's key: it is not the server the token belongs to",
                     c->host, c->port);
            goto fail;
        }
    }
    snprintf(c->user, sizeof c->user, "%s", nmzp_get_str(wv, "user") ? nmzp_get_str(wv, "user") : "?");
    snprintf(c->session, sizeof c->session, "%s", nmzp_get_str(wv, "session") ? nmzp_get_str(wv, "session") : "");
    join_strs(nmzp_get(wv, "permissions"), c->permissions, sizeof c->permissions);
    if (nmzp_get_int(wv, "max_frame", &v) && v >= (long long)NMZP_MIN_FRAME && v <= 0xffffffffLL) c->max_frame = (uint32_t)v;
    c->max_frame_out = c->max_frame;
    if (nmzp_get_int(wv, "max_frame_out", &v) && v >= (long long)NMZP_MIN_FRAME && v <= 0xffffffffLL)
        c->max_frame_out = (uint32_t)v;
    c->max_inflight = nmzp_get_int(wv, "max_inflight", &v) && v > 0 ? (uint32_t)v : 1;
    c->idle_timeout = nmzp_get_int(wv, "idle_timeout", &v) && v > 0 ? (uint32_t)v : 0;
    c->connected = 1;
    c->err[0] = '\0';
    memset(key, 0, sizeof key);
    nmzp_val_free(g);
    nmzp_val_free(wv);
    nmzp_buf_free(&hello);
    nmzp_frame_free(&f);
    return 0;
fail:
    memset(key, 0, sizeof key);
    nmzp_val_free(g);
    nmzp_val_free(wv);
    nmzp_buf_free(&hello);
    nmzp_frame_free(&f);
    return broken(c, e, msg);
}

/* connected and still open: an idle server may have closed us (its ERROR
 * timeout, or the end of the stream, waits unread) — then connect again */
static int ready(nmzp_client *c, nmzp_error *e) {
    if (c->connected && c->sock != NMZP_NO_SOCKET) {
        nmzp_frame f;
        int r;
        nmzp_frame_init(&f);
        r = nmzp_client_recv(c, &f, 0);
        while (r == 1 && f.h.id != 0) r = nmzp_client_recv(c, &f, 0); /* late frames of an old request */
        nmzp_frame_free(&f);
        if (r == 0) return 0;
        nmzp_client_close(c); /* an ERROR on id 0, or closed: start again */
    }
    return nmzp_client_connect(c, e);
}

/* the next frame of request id (others dropped); 1 = got one, -1 = broken */
static int next_of(nmzp_client *c, uint32_t id, nmzp_frame *f, int timeout_ms, nmzp_error *e) {
    for (;;) {
        int r = nmzp_client_recv(c, f, timeout_ms);
        if (r == 0) return broken(c, e, "the server did not answer in time");
        if (r < 0) return broken(c, e, c->err);
        if (f->h.type == NMZP_ERROR && f->h.id == 0) { /* about the connection: it closes */
            read_error(&f->payload, e);
            snprintf(c->err, sizeof c->err, "%.39s: %.550s", e->name, e->message);
            nmzp_client_close(c);
            return 0;
        }
        if (f->h.id == id) return 1;
    }
}

static int send_request(nmzp_client *c, const nmzp_buf *req, int flags, uint32_t *id, nmzp_error *e) {
    if (ready(c, e)) return -1;
    if (req->len > c->max_frame) {
        set_err(c, e, "the request is larger than the server's max_frame");
        e->code = NMZP_E_PAYLOAD_TOO_LARGE;
        snprintf(e->name, sizeof e->name, "payload_too_large");
        return 1;
    }
    *id = nmzp_client_id(c);
    if (nmzp_client_send(c, NMZP_REQUEST, flags, *id, req->data, req->len)) return broken(c, e, c->err);
    return 0;
}

/* a RESPONSE payload decoded into *out */
static int response(nmzp_client *c, const nmzp_frame *f, nmzp_val **out, nmzp_error *e) {
    char err[200];
    nmzp_val *v = nmzp_decode(f->payload.data, f->payload.len, err, sizeof err);
    if (!v) {
        char msg[300];
        snprintf(msg, sizeof msg, "the server's answer cannot be read: %s", err);
        return broken(c, e, msg);
    }
    if (out) *out = v;
    else nmzp_val_free(v);
    return 0;
}

int nmzp_call(nmzp_client *c, const nmzp_buf *req, nmzp_val **out, nmzp_error *e) {
    nmzp_frame f;
    uint32_t id;
    int r;
    nmzp_error tmp;
    if (!e) e = &tmp;
    memset(e, 0, sizeof *e);
    if (out) *out = NULL;
    if ((r = send_request(c, req, 0, &id, e)) != 0) return r;
    nmzp_frame_init(&f);
    r = next_of(c, id, &f, c->timeout_ms, e);
    if (r == 1) {
        if (f.h.type == NMZP_ERROR) {
            read_error(&f.payload, e);
            r = 1;
        } else if (f.h.type == NMZP_RESPONSE && !(f.h.flags & NMZP_MORE)) {
            r = response(c, &f, out, e);
        } else {
            r = broken(c, e, "the server answered a plain request with a stream");
        }
    } else if (r == 0) {
        r = 1; /* the server's ERROR about the connection, in e */
    }
    nmzp_frame_free(&f);
    return r;
}

/* ------------------------------------------------------------ uploads */

typedef struct mem_src {
    const unsigned char *p;
    size_t left;
} mem_src;

static long mem_read(void *user, void *buf, size_t max) {
    mem_src *m = (mem_src *)user;
    size_t k = m->left < max ? m->left : max;
    memcpy(buf, m->p, k);
    m->p += k;
    m->left -= k;
    return (long)k;
}

int nmzp_call_upload_mem(nmzp_client *c, const nmzp_buf *req, const void *data, size_t n, nmzp_val **out, nmzp_error *e) {
    mem_src m;
    m.p = (const unsigned char *)data;
    m.left = n;
    return nmzp_call_upload(c, req, n, mem_read, &m, out, e);
}

int nmzp_call_upload(nmzp_client *c, const nmzp_buf *req, uint64_t size, nmzp_read_fn rd, void *user, nmzp_val **out,
                     nmzp_error *e) {
    nmzp_frame f;
    nmzp_sha256 sh;
    unsigned char digest[32];
    nmzp_buf end;
    nmzp_mw w;
    char *chunk = NULL;
    uint32_t id;
    uint64_t sent = 0;
    size_t csize;
    int r;
    nmzp_error tmp;
    if (!e) e = &tmp;
    memset(e, 0, sizeof *e);
    if (out) *out = NULL;
    if ((r = send_request(c, req, NMZP_MORE, &id, e)) != 0) return r;
    csize = c->max_frame < CHUNK ? c->max_frame : CHUNK;
    nmzp_frame_init(&f);
    nmzp_buf_init(&end);
    nmzp_sha256_init(&sh);
    if (!(chunk = malloc(csize))) {
        r = broken(c, e, "out of memory");
        goto done;
    }
    while (sent < size) {
        size_t want = size - sent < csize ? (size_t)(size - sent) : csize;
        long k = rd(user, chunk, want);
        if (k <= 0) { /* the source gave up: abort the upload */
            nmzp_client_send(c, NMZP_ABORT, 0, id, NULL, 0);
            r = next_of(c, id, &f, c->timeout_ms, e);
            if (r == 1 && f.h.type == NMZP_ERROR) read_error(&f.payload, e);
            set_err(c, NULL, "reading the file to upload failed");
            if (r == 1) {
                e->code = NMZP_E_CANCELLED;
                snprintf(e->name, sizeof e->name, "cancelled");
                snprintf(e->message, sizeof e->message, "reading the file to upload failed");
                r = 1;
            }
            goto done;
        }
        nmzp_sha256_update(&sh, chunk, (size_t)k);
        if (nmzp_client_send(c, NMZP_DATA, NMZP_MORE, id, chunk, (size_t)k)) {
            r = broken(c, e, c->err);
            goto done;
        }
        sent += (uint64_t)k;
        { /* an early refusal (too large, forbidden): stop sending */
            int q = nmzp_client_recv(c, &f, 0);
            if (q < 0) {
                r = broken(c, e, c->err);
                goto done;
            }
            if (q == 1 && f.h.id == id && f.h.type == NMZP_ERROR) {
                read_error(&f.payload, e);
                r = 1;
                goto done;
            }
            if (q == 1 && f.h.id == 0 && f.h.type == NMZP_ERROR) {
                read_error(&f.payload, e);
                nmzp_client_close(c);
                r = 1;
                goto done;
            }
        }
    }
    nmzp_sha256_final(&sh, digest);
    nmzp_mw_init(&w, &end);
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "size", (long long)size);
    nmzp_mw_kbin(&w, "sha256", digest, 32);
    nmzp_mw_end_map(&w);
    if (nmzp_client_send(c, NMZP_END, 0, id, end.data, end.len)) {
        r = broken(c, e, c->err);
        goto done;
    }
    r = next_of(c, id, &f, c->timeout_ms, e);
    if (r == 1) {
        if (f.h.type == NMZP_ERROR) {
            read_error(&f.payload, e);
            r = 1;
        } else if (f.h.type == NMZP_RESPONSE && !(f.h.flags & NMZP_MORE)) {
            r = response(c, &f, out, e);
        } else {
            r = broken(c, e, "an unexpected frame after an upload");
        }
    } else if (r == 0) {
        r = 1;
    }
done:
    free(chunk);
    nmzp_buf_free(&end);
    nmzp_frame_free(&f);
    return r;
}

/* ---------------------------------------------------------- downloads */

int nmzp_write_to_buf(void *user, const void *p, size_t n) { return nmzp_buf_add((nmzp_buf *)user, p, n); }

/* after ABORT: read until the request's last frame */
static int drain(nmzp_client *c, uint32_t id, nmzp_frame *f, nmzp_error *e) {
    for (;;) {
        int r = next_of(c, id, f, c->timeout_ms, e);
        if (r != 1) return r;
        if (!(f->h.flags & NMZP_MORE)) return 1;
    }
}

int nmzp_call_download(nmzp_client *c, const nmzp_buf *req, nmzp_val **head, nmzp_write_fn wr, void *user,
                       nmzp_error *e) {
    nmzp_frame f;
    nmzp_sha256 sh;
    uint64_t got = 0;
    uint32_t id;
    int r;
    nmzp_error tmp;
    if (!e) e = &tmp;
    memset(e, 0, sizeof *e);
    if (head) *head = NULL;
    if ((r = send_request(c, req, 0, &id, e)) != 0) return r;
    nmzp_frame_init(&f);
    nmzp_sha256_init(&sh);
    r = next_of(c, id, &f, c->timeout_ms, e);
    if (r != 1) {
        nmzp_frame_free(&f);
        return r == 0 ? 1 : r;
    }
    if (f.h.type == NMZP_ERROR) {
        read_error(&f.payload, e);
        nmzp_frame_free(&f);
        return 1;
    }
    if (f.h.type != NMZP_RESPONSE || !(f.h.flags & NMZP_MORE)) {
        nmzp_frame_free(&f);
        return broken(c, e, "the server answered a download without a stream");
    }
    if ((r = response(c, &f, head, e)) != 0) {
        nmzp_frame_free(&f);
        return r;
    }
    for (;;) {
        r = next_of(c, id, &f, c->timeout_ms, e);
        if (r != 1) {
            r = r == 0 ? 1 : r;
            break;
        }
        if (f.h.type == NMZP_ERROR) {
            read_error(&f.payload, e);
            r = 1;
            break;
        }
        if (f.h.type == NMZP_DATA) {
            nmzp_sha256_update(&sh, f.payload.data, f.payload.len);
            got += f.payload.len;
            if (wr && wr(user, f.payload.data, f.payload.len)) { /* the caller stops: ABORT */
                nmzp_client_send(c, NMZP_ABORT, 0, id, NULL, 0);
                r = drain(c, id, &f, e);
                e->code = NMZP_E_CANCELLED;
                snprintf(e->name, sizeof e->name, "cancelled");
                snprintf(e->message, sizeof e->message, "the download was stopped (writing it failed)");
                r = r < 0 ? r : 1;
                break;
            }
            continue;
        }
        if (f.h.type == NMZP_END) {
            nmzp_val *v = nmzp_decode(f.payload.data, f.payload.len, NULL, 0);
            long long size = -1;
            size_t hn = 0;
            const unsigned char *hash = nmzp_bin(nmzp_get(v, "sha256"), &hn);
            unsigned char digest[32];
            nmzp_sha256_final(&sh, digest);
            nmzp_get_int(v, "size", &size);
            if (size < 0 || (uint64_t)size != got || !hash || hn != 32 || memcmp(hash, digest, 32)) {
                e->code = NMZP_E_INTEGRITY;
                snprintf(e->name, sizeof e->name, "integrity_error");
                snprintf(e->message, sizeof e->message,
                         "the download does not match its END (%llu bytes received, %lld announced, or another SHA-256)",
                         (unsigned long long)got, size);
                r = 1;
            } else {
                r = 0;
            }
            nmzp_val_free(v);
            break;
        }
        r = broken(c, e, "an unexpected frame in a download");
        break;
    }
    if (r != 0 && head) {
        nmzp_val_free(*head);
        *head = NULL;
    }
    nmzp_frame_free(&f);
    return r;
}

/* ------------------------------------------------------- subscriptions */

int nmzp_call_events(nmzp_client *c, const nmzp_buf *req, nmzp_val **head, nmzp_event_fn fn, void *user,
                     nmzp_error *e) {
    nmzp_frame f;
    uint32_t id;
    int r, wait = c->timeout_ms > 120000 ? c->timeout_ms : 120000; /* the server pings every 30 s */
    nmzp_error tmp;
    if (!e) e = &tmp;
    memset(e, 0, sizeof *e);
    if (head) *head = NULL;
    if ((r = send_request(c, req, 0, &id, e)) != 0) return r;
    nmzp_frame_init(&f);
    r = next_of(c, id, &f, c->timeout_ms, e);
    if (r != 1) {
        nmzp_frame_free(&f);
        return r == 0 ? 1 : r;
    }
    if (f.h.type == NMZP_ERROR) {
        read_error(&f.payload, e);
        nmzp_frame_free(&f);
        return 1;
    }
    if (f.h.type != NMZP_RESPONSE || !(f.h.flags & NMZP_MORE)) {
        nmzp_frame_free(&f);
        return broken(c, e, "the server answered a subscription without events");
    }
    if ((r = response(c, &f, head, e)) != 0) {
        nmzp_frame_free(&f);
        return r;
    }
    for (;;) {
        nmzp_val *v;
        long long seq = 0;
        int stop;
        r = next_of(c, id, &f, wait, e);
        if (r != 1) {
            r = r == 0 ? 1 : r;
            break;
        }
        if (f.h.type == NMZP_ERROR) {
            read_error(&f.payload, e);
            r = 1;
            break;
        }
        if (f.h.type != NMZP_EVENT) {
            r = broken(c, e, "an unexpected frame in a subscription");
            break;
        }
        v = nmzp_decode(f.payload.data, f.payload.len, NULL, 0);
        nmzp_get_int(v, "seq", &seq);
        stop = fn && v ? fn(user, nmzp_get_str(v, "event") ? nmzp_get_str(v, "event") : "", seq, nmzp_get(v, "data")) : 0;
        nmzp_val_free(v);
        if (!(f.h.flags & NMZP_MORE)) {
            r = 0;
            break;
        }
        if (stop) { /* unsubscribe */
            nmzp_client_send(c, NMZP_ABORT, 0, id, NULL, 0);
            r = drain(c, id, &f, e);
            r = r < 0 ? r : 0;
            memset(e, 0, sizeof *e);
            break;
        }
    }
    if (r != 0 && head) {
        nmzp_val_free(*head);
        *head = NULL;
    }
    nmzp_frame_free(&f);
    return r;
}

/* ---------------------------------------------------------- addresses */

int nmzp_parse_hostport(const char *s, char *host, size_t hostn, int *port) {
    const char *p = s, *colon;
    size_t hl;
    if (!s || !*s) return -1;
    if (strstr(p, "://")) return -1; /* no URLs: host or host:port */
    if (*p == '[') { /* [::1]:6769 */
        const char *close = strchr(p, ']');
        if (!close) return -1;
        hl = (size_t)(close - p - 1);
        if (!hl || hl + 1 > hostn) return -1;
        memcpy(host, p + 1, hl);
        host[hl] = '\0';
        p = close + 1;
        if (*p && *p != ':') return -1;
        colon = *p == ':' ? p : NULL;
    } else {
        colon = strchr(p, ':');
        if (colon && strchr(colon + 1, ':')) return -1; /* a bare IPv6 address needs [ ] */
        hl = colon ? (size_t)(colon - p) : strlen(p);
        if (!hl || hl + 1 > hostn || strpbrk(p, "/ ")) return -1;
        memcpy(host, p, hl);
        host[hl] = '\0';
    }
    if (colon) {
        long v = 0;
        const char *d = colon + 1;
        if (!*d) return -1;
        for (; *d; d++) {
            if (*d < '0' || *d > '9') return -1;
            v = v * 10 + (*d - '0');
            if (v > 65535) return -1;
        }
        if (v < 1) return -1;
        *port = (int)v;
    } else {
        *port = NMZP_DEFAULT_PORT;
    }
    return 0;
}
