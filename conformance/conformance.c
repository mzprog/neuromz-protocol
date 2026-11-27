/* conformance.c — check a live NeuroMZ server against PROTOCOL.md 2.0.
 *
 *   nmz-conformance --host HOST[:PORT] [--token T] [--read-token T]
 *                   [--prefix P] [--verbose]
 *
 * --token needs the train permission (admin is fine); --read-token, if
 * given, is a token with only `read` (the permission checks). Every model
 * and dataset it creates is named PREFIX-... (default: a random prefix)
 * and deleted at the end, so it can run against a shared server. It
 * checks the protocol itself — the greeting, the handshake and its proofs,
 * refusals of bad magic, versions, tokens, frames and payloads, requests
 * in flight together, aborts, uploads and downloads with their hashes,
 * disconnects in the middle of a stream — and then every operation. Output
 * is TAP-like ("ok N - what", "not ok N - what: why"); the exit status is 0
 * only if every check passed. The suite brings its own tiny datasets. */
#include "nmzp.h"
#include "nmzp_json.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_host[256], g_token[512], g_rtoken[512];
static int g_port, g_have_read, g_verbose, g_auth = 1;
static int g_n, g_pass, g_fail, g_skip;
static char g_prefix[48];
static char g_why[600];
static int g_allow_client = 1, g_allow_server = 1, g_trace_enabled = 1;
static long long g_max_epochs = 1000, g_max_layer = 0, g_max_frame = 65536, g_max_inflight = 1, g_idle = 0;
static nmzp_client g_c; /* the main connection (train token) */

/* ---------------------------------------------------------- reporting */

static int failf(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;
static int failf(const char *fmt, ...) {
    va_list ap;
    if (g_why[0]) return 0; /* keep the first reason */
    va_start(ap, fmt);
    vsnprintf(g_why, sizeof g_why, fmt, ap);
    va_end(ap);
    return 0;
}

#define EXPECT(cond, ...)                                                                                              \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            failf(__VA_ARGS__);                                                                                        \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

typedef void (*test_fn)(void);

static void run(const char *name, test_fn fn) {
    g_why[0] = '\0';
    g_n++;
    fn();
    if (!strcmp(g_why, "SKIP")) {
        g_skip++;
        printf("ok %d - %s # SKIP\n", g_n, name);
    } else if (g_why[0]) {
        g_fail++;
        printf("not ok %d - %s: %s\n", g_n, name, g_why);
    } else {
        g_pass++;
        printf("ok %d - %s\n", g_n, name);
    }
    fflush(stdout);
}

static void skip(void) { snprintf(g_why, sizeof g_why, "SKIP"); }

static const char *nm(const char *suffix) {
    static char b[8][128];
    static int k;
    k = (k + 1) % 8;
    snprintf(b[k], sizeof b[k], "%s-%s", g_prefix, suffix);
    return b[k];
}

/* -------------------------------------------------------- requests */

/* a request map: op and key/value pairs built by the caller */
typedef struct req {
    nmzp_buf b;
    nmzp_mw w;
} req;

static void req_begin(req *r, const char *op) {
    nmzp_buf_init(&r->b);
    nmzp_mw_init(&r->w, &r->b);
    nmzp_mw_map(&r->w);
    nmzp_mw_kstr(&r->w, "op", op);
}

static const nmzp_buf *req_end(req *r) {
    nmzp_mw_end_map(&r->w);
    return &r->b;
}

typedef struct reply {
    int status; /* 0 = RESPONSE, 1 = ERROR, -1 = the connection failed */
    nmzp_val *v;
    nmzp_error e;
} reply;

static void reply_free(reply *rp) {
    nmzp_val_free(rp->v);
    memset(rp, 0, sizeof *rp);
}

static int call_on(nmzp_client *c, req *r, reply *rp) {
    memset(rp, 0, sizeof *rp);
    rp->status = nmzp_call(c, req_end(r), &rp->v, &rp->e);
    if (g_verbose) fprintf(stderr, "  -> %d %s %s\n", rp->status, rp->e.name, rp->e.message);
    nmzp_buf_free(&r->b);
    return rp->status;
}

static int call(req *r, reply *rp) { return call_on(&g_c, r, rp); }

/* an ERROR with this name (and its code from the table) */
static int is_error(const reply *rp, const char *name) {
    if (rp->status != 1) return failf("expected the error %s, got %s", name, rp->status == 0 ? "an answer" : rp->e.message);
    if (strcmp(rp->e.name, name)) return failf("expected %s, got %s (%s)", name, rp->e.name, rp->e.message);
    if (rp->e.code != nmzp_error_code(name)) return failf("%s with code %d, not %d", name, rp->e.code, nmzp_error_code(name));
    if (!rp->e.message[0]) return failf("%s without a message", name);
    return 1;
}

static int simple(const char *op, const char *key, const char *value, reply *rp) {
    req r;
    req_begin(&r, op);
    if (key) nmzp_mw_kstr(&r.w, key, value);
    return call(&r, rp);
}

static int upload_on(nmzp_client *c, const char *op, const char *name, const char *format, const void *data, size_t n,
                     const char *extra_key, int overwrite, reply *rp) {
    req r;
    memset(rp, 0, sizeof *rp);
    req_begin(&r, op);
    nmzp_mw_kstr(&r.w, "name", name);
    if (format) nmzp_mw_kstr(&r.w, "format", format);
    if (extra_key) nmzp_mw_kstr(&r.w, extra_key, g_allow_server ? "server" : "client");
    if (overwrite) nmzp_mw_kbool(&r.w, "overwrite", 1);
    nmzp_mw_kint(&r.w, "size", (long long)n);
    rp->status = nmzp_call_upload_mem(c, req_end(&r), data, n, &rp->v, &rp->e);
    nmzp_buf_free(&r.b);
    return rp->status;
}

/* ------------------------------------------------------- raw frames */

typedef struct raw {
    nmzp_socket s;
    nmzp_buf rx;
    nmzp_val *greeting;
    unsigned char ns[32];
} raw;

/* the next frame within ms: 1 = one (h, payload), 0 = closed, -2 = nothing in time */
static int raw_frame(raw *r, nmzp_frame_head *h, nmzp_buf *payload, int ms) {
    double end = nmzp_clock() + ms / 1000.0;
    for (;;) {
        const unsigned char *p;
        size_t used;
        int code, k = nmzp_frame_next(r->rx.data ? r->rx.data : "", r->rx.len, 0x7fffffffu, h, &p, &used, &code);
        char tmp[65536];
        long got;
        if (k == 1) {
            nmzp_buf_clear(payload);
            nmzp_buf_add(payload, p, h->length);
            nmzp_buf_consume(&r->rx, used);
            return 1;
        }
        if (k < 0) return 0;
        if (nmzp_clock() > end) return -2;
        got = nmzp_recv(r->s, tmp, sizeof tmp, 200);
        if (got == -2) continue;
        if (got <= 0) return 0;
        nmzp_buf_add(&r->rx, tmp, (size_t)got);
    }
}

/* connect and read the greeting */
static int raw_open(raw *r) {
    char err[200];
    nmzp_frame_head h;
    nmzp_buf p;
    memset(r, 0, sizeof *r);
    nmzp_buf_init(&r->rx);
    r->s = nmzp_connect(g_host, g_port, 10000, err, sizeof err);
    if (r->s == NMZP_NO_SOCKET) return failf("connect: %s", err);
    nmzp_buf_init(&p);
    if (raw_frame(r, &h, &p, 10000) != 1 || h.type != NMZP_GREETING || nmzp_prefix_get(p.data, p.len, NULL, NULL)) {
        nmzp_buf_free(&p);
        return failf("no greeting");
    }
    r->greeting = nmzp_decode(p.data + NMZP_PREFIX, p.len - NMZP_PREFIX, NULL, 0);
    if (r->greeting) {
        size_t n = 0;
        const unsigned char *ns = nmzp_bin(nmzp_get(r->greeting, "nonce"), &n);
        if (ns && n == 32) memcpy(r->ns, ns, 32);
    }
    nmzp_buf_free(&p);
    return r->greeting != NULL;
}

static void raw_close(raw *r) {
    if (r->s != NMZP_NO_SOCKET) nmzp_close(r->s);
    nmzp_buf_free(&r->rx);
    nmzp_val_free(r->greeting);
    memset(r, 0, sizeof *r);
}

static void raw_send(raw *r, int type, int flags, uint32_t id, const void *p, size_t n) {
    nmzp_buf f;
    nmzp_buf_init(&f);
    nmzp_frame_put(&f, type, flags, id, p, n);
    nmzp_send_all(r->s, f.data, f.len);
    nmzp_buf_free(&f);
}

/* the next frame is an ERROR with this name; with closes: then the connection closes */
static int raw_expect_error(raw *r, uint32_t id, const char *name, int closes) {
    nmzp_frame_head h;
    nmzp_buf p;
    nmzp_val *v;
    int k;
    nmzp_buf_init(&p);
    k = raw_frame(r, &h, &p, 15000);
    if (k != 1) {
        nmzp_buf_free(&p);
        return failf("expected ERROR %s, got %s", name, k == 0 ? "the connection closed" : "nothing");
    }
    v = nmzp_decode(p.data, p.len, NULL, 0);
    nmzp_buf_free(&p);
    if (h.type != NMZP_ERROR || h.id != id || !v || !nmzp_get_str(v, "name") || strcmp(nmzp_get_str(v, "name"), name)) {
        failf("expected ERROR %s on id %lu, got %s id %lu %s", name, (unsigned long)id,
              nmzp_frame_name(h.type) ? nmzp_frame_name(h.type) : "?", (unsigned long)h.id,
              v && nmzp_get_str(v, "name") ? nmzp_get_str(v, "name") : "");
        nmzp_val_free(v);
        return 0;
    }
    {
        long long code = 0;
        if (!nmzp_get_int(v, "code", &code) || code != nmzp_error_code(name) || !nmzp_get_str(v, "message")) {
            nmzp_val_free(v);
            return failf("ERROR %s without its code %d or a message", name, nmzp_error_code(name));
        }
    }
    nmzp_val_free(v);
    if (closes) {
        nmzp_frame_head h2;
        nmzp_buf p2;
        nmzp_buf_init(&p2);
        k = raw_frame(r, &h2, &p2, 5000);
        nmzp_buf_free(&p2);
        if (k != 0) return failf("the connection did not close after ERROR %s", name);
    }
    return 1;
}

/* a HELLO: magic (or not), a version, the proof of token (or none) */
static void raw_hello(raw *r, int good_magic, int major, const char *token, int bad_proof) {
    nmzp_buf p;
    nmzp_mw w;
    unsigned char pre[NMZP_PREFIX];
    nmzp_buf_init(&p);
    nmzp_prefix_put(pre, major, 0);
    if (!good_magic) pre[2] = 'X';
    nmzp_buf_add(&p, pre, sizeof pre);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "client", "nmz-conformance");
    nmzp_mw_kstr(&w, "version", NMZP_VERSION);
    if (token) {
        unsigned char key[32], kid[8], nc[32], proof[32];
        nmzp_auth_key(token, strlen(token), key);
        nmzp_auth_key_id(key, kid);
        nmzp_random(nc, 32);
        nmzp_auth_proof(key, 0, r->ns, nc, proof);
        if (bad_proof) proof[0] ^= 1;
        nmzp_mw_kstr(&w, "auth", "hmac-sha256");
        nmzp_mw_kbin(&w, "key_id", kid, 8);
        nmzp_mw_kbin(&w, "nonce", nc, 32);
        nmzp_mw_kbin(&w, "proof", proof, 32);
    } else {
        nmzp_mw_kstr(&w, "auth", "none");
    }
    nmzp_mw_end_map(&w);
    raw_send(r, NMZP_HELLO, 0, 0, p.data, p.len);
    nmzp_buf_free(&p);
}

/* the server still answers (a new connection, health) */
static int alive(void) {
    nmzp_client c;
    req r;
    reply rp;
    int ok;
    nmzp_client_init(&c, g_host, g_port, g_token);
    snprintf(c.name, sizeof c.name, "nmz-conformance");
    c.allow_no_auth = 1;
    req_begin(&r, "health");
    ok = call_on(&c, &r, &rp) == 0 && nmzp_get_str(rp.v, "status");
    reply_free(&rp);
    nmzp_client_close(&c);
    return ok ? 1 : failf("the server does not answer any more");
}

/* ------------------------------------------------------------- data */

static const char k_xor[] = "0,0,0\n0,1,1\n1,0,1\n1,1,0\n";
static const char *const k_names[] = {
    "Anna", "Ben", "Clara", "David", "Emma", "Felix", "Greta", "Hugo", "Ida", "Jonas", "Klara", "Leon", "Mia",
    "Noah", "Olga", "Paul", "Rosa", "Simon", "Tara", "Ugo", "Vera", "Wim", "Xenia", "Yann", "Zoe", "Alma",
    "Bruno", "Cleo", "Dora", "Emil", "Frida", "Gustav", "Hanna", "Igor", "Jana", "Karl", "Lena", "Max", "Nina",
    "Oskar", "Pia", "Quirin", "Rita", "Sven", "Tilda", "Udo", "Viktor", "Wanda", "Yara", "Zeno", NULL};

static void names_text(nmzp_buf *b) {
    int i, r;
    for (r = 0; r < 6; r++)
        for (i = 0; k_names[i]; i++) nmzp_buf_printf(b, "%s\n", k_names[i]);
}

/* --------------------------------------------------- the protocol itself */

static void t_greeting(void) {
    raw r;
    const nmzp_val *g;
    long long mf = 0, mm = 0;
    size_t n = 0;
    const char *auth;
    if (!raw_open(&r)) return;
    g = r.greeting;
    EXPECT(nmzp_get_str(g, "server") && nmzp_get_str(g, "version"), "the greeting lacks server or version");
    EXPECT(nmzp_get_int(g, "min_major", &mm) && mm >= 1 && mm <= 2, "min_major missing or not 2 (%lld)", mm);
    auth = nmzp_get_str(g, "auth");
    EXPECT(auth && (!strcmp(auth, "hmac-sha256") || !strcmp(auth, "none")), "auth is %s", auth ? auth : "missing");
    g_auth = !strcmp(auth, "hmac-sha256");
    EXPECT(nmzp_bin(nmzp_get(g, "nonce"), &n) && n == 32, "the nonce is not 32 bytes");
    EXPECT(nmzp_get_int(g, "max_frame", &mf) && mf >= 65536, "max_frame missing or below 65536");
    EXPECT(nmzp_get(g, "capabilities") && nmzp_get(g, "capabilities")->type == NMZP_ARRAY, "capabilities missing");
    EXPECT(nmzp_get_str(g, "status"), "status missing");
    g_max_frame = mf;
    { /* every connection gets a fresh nonce */
        raw r2;
        unsigned char first[32];
        memcpy(first, r.ns, 32);
        raw_close(&r);
        if (!raw_open(&r2)) return;
        EXPECT(memcmp(first, r2.ns, 32) != 0, "two connections got the same nonce");
        raw_close(&r2);
    }
}

static void t_handshake(void) {
    nmzp_client c;
    nmzp_error e;
    nmzp_client_init(&c, g_host, g_port, g_token);
    snprintf(c.name, sizeof c.name, "nmz-conformance");
    c.allow_no_auth = 1;
    EXPECT(nmzp_client_connect(&c, &e) == 0, "the handshake: %s", c.err);
    EXPECT(c.major == 2 && c.user[0] && c.permissions[0] && c.max_inflight >= 1, "WELCOME lacks user, permissions or max_inflight");
    g_max_inflight = c.max_inflight;
    g_idle = c.idle_timeout;
    EXPECT(c.max_frame >= 65536 && c.max_frame_out >= 65536, "max_frame below 65536");
    /* the server's proof was checked by nmzp_client_connect */
    nmzp_client_close(&c);
}

static void t_auth(void) {
    raw r;
    if (!g_auth) {
        skip();
        return;
    }
    if (!raw_open(&r)) return;
    raw_hello(&r, 1, 2, "not-a-real-token-0123456789", 0);
    EXPECT(raw_expect_error(&r, 0, "unauthorized", 1), "an unknown token: %s", g_why);
    raw_close(&r);
    if (!raw_open(&r)) return;
    raw_hello(&r, 1, 2, g_token, 1);
    EXPECT(raw_expect_error(&r, 0, "unauthorized", 1), "the right key id with a wrong proof: %s", g_why);
    raw_close(&r);
    if (!raw_open(&r)) return;
    raw_hello(&r, 1, 2, NULL, 0);
    EXPECT(raw_expect_error(&r, 0, "unauthorized", 1), "no proof at all: %s", g_why);
    raw_close(&r);
    if (!raw_open(&r)) return;
    { /* a replayed proof: one made for another connection's nonce */
        raw r2;
        unsigned char ns[32];
        memcpy(ns, r.ns, 32);
        if (!raw_open(&r2)) return;
        memcpy(r2.ns, ns, 32); /* the old nonce */
        raw_hello(&r2, 1, 2, g_token, 0);
        EXPECT(raw_expect_error(&r2, 0, "unauthorized", 1), "a proof for another connection's nonce: %s", g_why);
        raw_close(&r2);
    }
    raw_close(&r);
}

static void t_magic_version(void) {
    raw r;
    if (!raw_open(&r)) return;
    raw_hello(&r, 0, 2, g_token[0] ? g_token : NULL, 0);
    EXPECT(raw_expect_error(&r, 0, "bad_magic", 1), "a hello without the magic: %s", g_why);
    raw_close(&r);
    if (!raw_open(&r)) return;
    raw_hello(&r, 1, 9, g_token[0] ? g_token : NULL, 0);
    {
        nmzp_frame_head h;
        nmzp_buf p;
        nmzp_val *v;
        long long mm = 0;
        nmzp_buf_init(&p);
        EXPECT(raw_frame(&r, &h, &p, 15000) == 1 && h.type == NMZP_ERROR, "protocol 9: no ERROR");
        v = nmzp_decode(p.data, p.len, NULL, 0);
        nmzp_buf_free(&p);
        EXPECT(v && nmzp_get_str(v, "name") && !strcmp(nmzp_get_str(v, "name"), "unsupported_version"),
               "protocol 9: not unsupported_version");
        EXPECT(nmzp_get_int(nmzp_get(v, "details"), "min_major", &mm) && mm == 2, "unsupported_version without details");
        nmzp_val_free(v);
    }
    raw_close(&r);
    if (!raw_open(&r)) return;
    {
        static const char http[] = "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n";
        nmzp_send_all(r.s, http, sizeof http - 1);
        EXPECT(raw_expect_error(&r, 0, "protocol_error", 1), "an HTTP request: %s", g_why);
    }
    raw_close(&r);
    if (!raw_open(&r)) return;
    raw_send(&r, NMZP_REQUEST, 0, 1, "\x81\xa2op\xa6health", 11); /* a request before the hello */
    EXPECT(raw_expect_error(&r, 0, "protocol_error", 1), "a REQUEST before HELLO: %s", g_why);
    raw_close(&r);
}

/* an open connection, through the client's handshake, for raw frames */
static int session(nmzp_client *c) {
    nmzp_client_init(c, g_host, g_port, g_token);
    snprintf(c->name, sizeof c->name, "nmz-conformance");
    c->allow_no_auth = 1;
    if (nmzp_client_connect(c, NULL)) return failf("connect: %s", c->err);
    return 1;
}

/* the next frame on a client connection, as a raw one */
static int next(nmzp_client *c, nmzp_frame *f, int ms) { return nmzp_client_recv(c, f, ms); }

static int expect_error_on(nmzp_client *c, uint32_t id, const char *name, int closes) {
    nmzp_frame f;
    nmzp_val *v;
    int k;
    nmzp_frame_init(&f);
    k = next(c, &f, 15000);
    if (k != 1) {
        nmzp_frame_free(&f);
        return failf("expected ERROR %s, got %s", name, k == 0 ? "nothing" : c->err);
    }
    v = nmzp_decode(f.payload.data, f.payload.len, NULL, 0);
    if (f.h.type != NMZP_ERROR || f.h.id != id || !nmzp_get_str(v, "name") || strcmp(nmzp_get_str(v, "name"), name)) {
        failf("expected ERROR %s on id %lu, got %s id %lu %s", name, (unsigned long)id,
              nmzp_frame_name(f.h.type) ? nmzp_frame_name(f.h.type) : "?", (unsigned long)f.h.id,
              nmzp_get_str(v, "name") ? nmzp_get_str(v, "name") : "");
        nmzp_val_free(v);
        nmzp_frame_free(&f);
        return 0;
    }
    nmzp_val_free(v);
    if (closes && next(c, &f, 5000) != -1) {
        nmzp_frame_free(&f);
        return failf("the connection did not close after ERROR %s", name);
    }
    nmzp_frame_free(&f);
    return 1;
}

static void t_frames(void) {
    nmzp_client c;
    unsigned char h[NMZP_FRAME_HEADER];
    /* too large: refused from the header */
    if (!session(&c)) return;
    nmzp_head_encode(h, NMZP_REQUEST, 0, 1, (uint32_t)c.max_frame + 1);
    nmzp_send_all(c.sock, h, sizeof h);
    EXPECT(expect_error_on(&c, 0, "frame_too_large", 1), "a frame over max_frame: %s", g_why);
    nmzp_client_close(&c);
    /* unknown type, reserved type */
    if (!session(&c)) return;
    nmzp_client_send(&c, 0x7f, 0, 1, "", 0);
    EXPECT(expect_error_on(&c, 0, "unknown_frame", 1), "frame type 0x7f: %s", g_why);
    nmzp_client_close(&c);
    if (!session(&c)) return;
    nmzp_client_send(&c, 0x04, 0, 0, "", 0);
    EXPECT(expect_error_on(&c, 0, "unknown_frame", 1), "frame type 0x04 (reserved): %s", g_why);
    nmzp_client_close(&c);
    /* flags and reserved bits */
    if (!session(&c)) return;
    nmzp_client_send(&c, NMZP_PING, 0x04, 0, "", 0);
    EXPECT(expect_error_on(&c, 0, "protocol_error", 1), "an undefined flag: %s", g_why);
    nmzp_client_close(&c);
    if (!session(&c)) return;
    nmzp_head_encode(h, NMZP_PING, 0, 0, 0);
    h[7] = 1;
    nmzp_send_all(c.sock, h, sizeof h);
    EXPECT(expect_error_on(&c, 0, "protocol_error", 1), "reserved bits: %s", g_why);
    nmzp_client_close(&c);
    /* request id 0, a frame of the wrong direction */
    if (!session(&c)) return;
    nmzp_client_send(&c, NMZP_REQUEST, 0, 0, "\x81\xa2op\xa6health", 11);
    EXPECT(expect_error_on(&c, 0, "protocol_error", 1), "a REQUEST with id 0: %s", g_why);
    nmzp_client_close(&c);
    if (!session(&c)) return;
    nmzp_client_send(&c, NMZP_RESPONSE, 0, 5, "\x80", 1);
    EXPECT(expect_error_on(&c, 0, "protocol_error", 1), "a RESPONSE from the client: %s", g_why);
    nmzp_client_close(&c);
    /* truncated: half a frame, then the client goes; the server is still there */
    if (!session(&c)) return;
    nmzp_head_encode(h, NMZP_REQUEST, 0, 1, 100);
    nmzp_send_all(c.sock, h, sizeof h);
    nmzp_send_all(c.sock, "\x81\xa2op", 4);
    nmzp_client_close(&c);
    EXPECT(alive(), "after a truncated frame: %s", g_why);
    /* PING / PONG, and DATA / END / ABORT for ids not in flight are ignored */
    if (!session(&c)) return;
    nmzp_client_send(&c, NMZP_DATA, NMZP_MORE, 77, "x", 1);
    nmzp_client_send(&c, NMZP_ABORT, 0, 78, "", 0);
    nmzp_client_send(&c, NMZP_PING, 0, 42, "hello", 5);
    {
        nmzp_frame f;
        nmzp_frame_init(&f);
        /* nmzp_client_recv answers PINGs, not PONGs: the PONG arrives as a frame */
        EXPECT(next(&c, &f, 10000) == 1 && f.h.type == NMZP_PONG && f.h.id == 42 && f.payload.len == 5 &&
                   !memcmp(f.payload.data, "hello", 5),
               "PING 42 \"hello\": no PONG with the same id and payload");
        nmzp_frame_free(&f);
    }
    nmzp_client_close(&c);
}

static void t_requests(void) {
    nmzp_client c;
    if (!session(&c)) return;
    nmzp_client_send(&c, NMZP_REQUEST, 0, 1, "\x81\xa2op", 4); /* cut short */
    EXPECT(expect_error_on(&c, 1, "bad_request", 0), "an invalid payload: %s", g_why);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 2, "\x92\x01\x02", 3); /* an array */
    EXPECT(expect_error_on(&c, 2, "bad_request", 0), "a payload that is not a map: %s", g_why);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 3, "\x81\xa1x\x01", 4); /* no op */
    EXPECT(expect_error_on(&c, 3, "bad_request", 0), "a request without op: %s", g_why);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 4, "\x81\xa2op\xa8no.such!", 13);
    EXPECT(expect_error_on(&c, 4, "unknown_operation", 0), "an unknown op: %s", g_why);
    nmzp_client_send(&c, NMZP_REQUEST, NMZP_MORE, 5, "\x81\xa2op\xa6health", 11); /* MORE on an op without a stream */
    EXPECT(expect_error_on(&c, 5, "bad_request", 0), "MORE on health: %s", g_why);
    {
        req r;
        req_begin(&r, "datasets.upload");
        nmzp_mw_kstr(&r.w, "name", nm("nomore"));
        nmzp_mw_kstr(&r.w, "format", "csv");
        nmzp_mw_kint(&r.w, "size", 3);
        req_end(&r);
        nmzp_client_send(&c, NMZP_REQUEST, 0, 6, r.b.data, r.b.len); /* an upload without MORE */
        nmzp_buf_free(&r.b);
        EXPECT(expect_error_on(&c, 6, "bad_request", 0), "an upload without MORE: %s", g_why);
    }
    { /* the connection is still fine */
        reply rp;
        req r;
        req_begin(&r, "health");
        EXPECT(call_on(&c, &r, &rp) == 0, "health after refused requests: %s", rp.e.message);
        reply_free(&rp);
    }
    nmzp_client_close(&c);
}

/* REQUEST MORE of an upload, left open */
static void open_upload(nmzp_client *c, uint32_t id, const char *name, long long size) {
    req r;
    req_begin(&r, "datasets.upload");
    nmzp_mw_kstr(&r.w, "name", name);
    nmzp_mw_kstr(&r.w, "format", "csv");
    nmzp_mw_kbool(&r.w, "overwrite", 1);
    nmzp_mw_kint(&r.w, "size", size);
    req_end(&r);
    nmzp_client_send(c, NMZP_REQUEST, NMZP_MORE, id, r.b.data, r.b.len);
    nmzp_buf_free(&r.b);
}

static void end_frame(nmzp_buf *b, const void *data, size_t n, long long size) {
    unsigned char d[32];
    nmzp_mw w;
    nmzp_sha256_of(data, n, d);
    nmzp_buf_init(b);
    nmzp_mw_init(&w, b);
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "size", size);
    nmzp_mw_kbin(&w, "sha256", d, 32);
    nmzp_mw_end_map(&w);
}

static void t_interleaved(void) {
    nmzp_client c;
    nmzp_frame f;
    nmzp_buf end;
    int got[4] = {0, 0, 0, 0}, i, order[4], k = 0;
    static const uint32_t ids[4] = {7, 3, 11, 20};
    if (!session(&c)) return;
    /* an upload in pieces, with other requests between its frames */
    open_upload(&c, 20, nm("inter"), (long long)strlen(k_xor));
    nmzp_client_send(&c, NMZP_DATA, NMZP_MORE, 20, k_xor, 6);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 7, "\x81\xa2op\xa6health", 11);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 3, "\x81\xa2op\xabserver.info", 16);
    nmzp_client_send(&c, NMZP_DATA, NMZP_MORE, 20, k_xor + 6, strlen(k_xor) - 6);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 11, "\x81\xa2op\xabmodels.list", 16);
    end_frame(&end, k_xor, strlen(k_xor), (long long)strlen(k_xor));
    nmzp_client_send(&c, NMZP_END, 0, 20, end.data, end.len);
    nmzp_buf_free(&end);
    nmzp_frame_init(&f);
    while (k < 4) {
        int r = next(&c, &f, 30000);
        EXPECT(r == 1, "fewer answers than requests (%d of 4): %s", k, r < 0 ? c.err : "nothing in time");
        for (i = 0; i < 4; i++)
            if (f.h.id == ids[i]) break;
        EXPECT(i < 4, "an answer to request id %lu, which was not sent", (unsigned long)f.h.id);
        EXPECT(f.h.type == NMZP_RESPONSE && !(f.h.flags & NMZP_MORE), "request %lu: %s, not one RESPONSE",
               (unsigned long)f.h.id, nmzp_frame_name(f.h.type) ? nmzp_frame_name(f.h.type) : "?");
        EXPECT(!got[i], "two answers to request %lu", (unsigned long)f.h.id);
        got[i] = 1;
        order[k++] = (int)f.h.id;
    }
    nmzp_frame_free(&f);
    if (g_verbose) fprintf(stderr, "  answers in the order %d %d %d %d\n", order[0], order[1], order[2], order[3]);
    nmzp_client_close(&c);
    { /* the interleaved upload arrived whole */
        reply rp;
        char hex[65];
        simple("datasets.describe", "name", nm("inter"), &rp);
        nmzp_sha256_hex(k_xor, strlen(k_xor), hex);
        EXPECT(rp.status == 0 && nmzp_get_str(rp.v, "sha256") && !strcmp(nmzp_get_str(rp.v, "sha256"), hex),
               "the interleaved upload is not the file");
        reply_free(&rp);
        simple("datasets.delete", "name", nm("inter"), &rp);
        reply_free(&rp);
    }
}

static void t_inflight_abort(void) {
    nmzp_client c;
    uint32_t i, n;
    if (!session(&c)) return;
    n = c.max_inflight;
    if (n > 64) {
        skip();
        nmzp_client_close(&c);
        return;
    }
    for (i = 0; i < n; i++) open_upload(&c, 100 + i, nm("open"), 10);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 999, "\x81\xa2op\xa6health", 11);
    EXPECT(expect_error_on(&c, 999, "too_many_requests", 0), "one request over max_inflight (%lu): %s", (unsigned long)n,
           g_why);
    for (i = 0; i < n; i++) {
        nmzp_client_send(&c, NMZP_ABORT, 0, 100 + i, "", 0);
        EXPECT(expect_error_on(&c, 100 + i, "cancelled", 0), "ABORT of upload %lu: %s", (unsigned long)(100 + i), g_why);
    }
    { /* a duplicate id in flight closes the connection */
        open_upload(&c, 500, nm("dup"), 10);
        open_upload(&c, 500, nm("dup"), 10);
        EXPECT(expect_error_on(&c, 0, "protocol_error", 1), "a request id already in flight: %s", g_why);
    }
    nmzp_client_close(&c);
}

static void t_integrity(void) {
    nmzp_client c;
    nmzp_buf end;
    if (!session(&c)) return;
    open_upload(&c, 1, nm("hash"), (long long)strlen(k_xor));
    nmzp_client_send(&c, NMZP_DATA, NMZP_MORE, 1, k_xor, strlen(k_xor));
    end_frame(&end, "something else", 14, (long long)strlen(k_xor));
    nmzp_client_send(&c, NMZP_END, 0, 1, end.data, end.len);
    nmzp_buf_free(&end);
    EXPECT(expect_error_on(&c, 1, "integrity_error", 0), "an upload whose SHA-256 differs: %s", g_why);
    open_upload(&c, 2, nm("hash"), 4);
    nmzp_client_send(&c, NMZP_DATA, NMZP_MORE, 2, k_xor, strlen(k_xor)); /* more than announced */
    EXPECT(expect_error_on(&c, 2, "integrity_error", 0), "more bytes than the size: %s", g_why);
    open_upload(&c, 3, nm("hash"), (long long)strlen(k_xor));
    nmzp_client_send(&c, NMZP_DATA, NMZP_MORE, 3, k_xor, 5);
    end_frame(&end, k_xor, 5, 5);
    nmzp_client_send(&c, NMZP_END, 0, 3, end.data, end.len);
    nmzp_buf_free(&end);
    EXPECT(expect_error_on(&c, 3, "integrity_error", 0), "fewer bytes than the size: %s", g_why);
    nmzp_client_close(&c);
    {
        reply rp;
        simple("datasets.describe", "name", nm("hash"), &rp);
        EXPECT(is_error(&rp, "not_found"), "a refused upload was stored: %s", g_why);
        reply_free(&rp);
    }
}

/* ------------------------------------------------------- operations */

static void t_server(void) {
    reply rp;
    const nmzp_val *u;
    long long up = -1, started = 0;
    EXPECT(simple("health", NULL, NULL, &rp) == 0 && nmzp_get_str(rp.v, "status") && !strcmp(nmzp_get_str(rp.v, "status"), "ok"),
           "health: %s", rp.e.message);
    EXPECT(nmzp_get_str(rp.v, "protocol") && !strncmp(nmzp_get_str(rp.v, "protocol"), "2.", 2), "health: protocol is not 2.x");
    reply_free(&rp);
    EXPECT(simple("server.info", NULL, NULL, &rp) == 0, "server.info: %s", rp.e.message);
    EXPECT(nmzp_get_str(rp.v, "name") && nmzp_get_str(rp.v, "version") && nmzp_get_str(rp.v, "library"),
           "name, version or library missing");
    EXPECT(nmzp_get_int(rp.v, "started", &started) && started > 1000000000 && nmzp_get_int(rp.v, "uptime_s", &up) && up >= 0,
           "started/uptime_s missing (times are ints)");
    u = nmzp_get(rp.v, "user");
    EXPECT(u && nmzp_get_str(u, "name") && nmzp_get(u, "permissions"), "user missing");
    reply_free(&rp);
}

static void t_capabilities(void) {
    reply rp;
    const nmzp_val *b, *sv, *al, *tr, *lim;
    size_t i;
    int cpu = 0, auth = 1;
    EXPECT(simple("server.capabilities", NULL, NULL, &rp) == 0, "server.capabilities: %s", rp.e.message);
    EXPECT(nmzp_get_bool(rp.v, "auth", &auth), "auth missing");
    b = nmzp_get(rp.v, "backends");
    EXPECT(b && b->type == NMZP_ARRAY && b->n > 0, "backends missing");
    for (i = 0; i < b->n; i++) {
        const char *n = nmzp_get_str(b->items[i], "name");
        int av = 0;
        EXPECT(n && nmzp_get_bool(b->items[i], "available", &av), "a backend without name/available");
        if (!strcmp(n, "cpu") && av) cpu = 1;
    }
    EXPECT(cpu, "the cpu backend is not available");
    EXPECT(nmzp_get_str(rp.v, "default_device"), "default_device missing");
    EXPECT(nmzp_get(rp.v, "presets") && nmzp_get(rp.v, "presets")->n > 0, "no presets");
    sv = nmzp_get(rp.v, "save");
    al = nmzp_get(sv, "allowed");
    EXPECT(sv && nmzp_get_str(sv, "default") && al && al->n > 0, "save.default/allowed missing");
    g_allow_client = g_allow_server = 0;
    for (i = 0; i < al->n; i++) {
        if (nmzp_str(al->items[i]) && !strcmp(nmzp_str(al->items[i]), "client")) g_allow_client = 1;
        if (nmzp_str(al->items[i]) && !strcmp(nmzp_str(al->items[i]), "server")) g_allow_server = 1;
    }
    lim = nmzp_get(rp.v, "limits");
    EXPECT(lim, "limits missing");
    if (nmzp_get_int(lim, "max_epochs", &g_max_epochs) && g_max_epochs < 1) g_max_epochs = 1000;
    if (!nmzp_get_int(lim, "max_layer_size", &g_max_layer) || g_max_layer < 1 || g_max_layer > 1000000000) g_max_layer = 0;
    tr = nmzp_get(rp.v, "trace");
    EXPECT(tr && nmzp_get_bool(tr, "enabled", &g_trace_enabled), "trace.enabled missing");
    EXPECT(nmzp_get(rp.v, "capabilities") && nmzp_get(rp.v, "capabilities")->type == NMZP_ARRAY, "capabilities missing");
    reply_free(&rp);
}

static void t_errors(void) {
    reply rp;
    req r;
    req_begin(&r, "models.create");
    nmzp_mw_kstr(&r.w, "name", "../evil");
    nmzp_mw_key(&r.w, "args");
    nmzp_mw_arr(&r.w);
    nmzp_mw_str(&r.w, "2");
    nmzp_mw_str(&r.w, "1");
    nmzp_mw_end_arr(&r.w);
    call(&r, &rp);
    EXPECT(is_error(&rp, "invalid_name"), "name ../evil: %s", g_why);
    reply_free(&rp);
    req_begin(&r, "models.create");
    nmzp_mw_kstr(&r.w, "name", "CON");
    nmzp_mw_key(&r.w, "args");
    nmzp_mw_arr(&r.w);
    nmzp_mw_str(&r.w, "2");
    nmzp_mw_str(&r.w, "1");
    nmzp_mw_end_arr(&r.w);
    call(&r, &rp);
    EXPECT(is_error(&rp, "invalid_name"), "name CON: %s", g_why);
    reply_free(&rp);
    req_begin(&r, "models.create");
    nmzp_mw_kint(&r.w, "name", 5);
    call(&r, &rp);
    EXPECT(is_error(&rp, "bad_request"), "a name that is an int: %s", g_why);
    reply_free(&rp);
    simple("models.describe", "name", "no-such-model-0042", &rp);
    EXPECT(is_error(&rp, "not_found"), "unknown model: %s", g_why);
    reply_free(&rp);
    simple("jobs.status", "id", "j999999999", &rp);
    EXPECT(is_error(&rp, "not_found"), "unknown job: %s", g_why);
    reply_free(&rp);
}

static void t_datasets(void) {
    reply rp;
    char hex[65];
    nmzp_buf names;
    EXPECT(upload_on(&g_c, "datasets.upload", nm("xor"), "csv", k_xor, strlen(k_xor), NULL, 0, &rp) == 0,
           "upload a CSV dataset: %s", rp.e.message);
    nmzp_sha256_hex(k_xor, strlen(k_xor), hex);
    {
        const nmzp_val *d = nmzp_get(rp.v, "dataset");
        int created = 0;
        EXPECT(nmzp_get_str(d, "sha256") && !strcmp(nmzp_get_str(d, "sha256"), hex), "the dataset's sha256 is wrong");
        EXPECT(nmzp_get_str(d, "format") && !strcmp(nmzp_get_str(d, "format"), "csv"), "format not csv");
        EXPECT(nmzp_get_bool(rp.v, "created", &created) && created, "created is not true");
    }
    reply_free(&rp);
    upload_on(&g_c, "datasets.upload", nm("xor"), "csv", k_xor, strlen(k_xor), NULL, 0, &rp);
    EXPECT(is_error(&rp, "conflict"), "the same name again: %s", g_why);
    reply_free(&rp);
    EXPECT(upload_on(&g_c, "datasets.upload", nm("xor"), "csv", k_xor, strlen(k_xor), NULL, 1, &rp) == 0,
           "overwrite: %s", rp.e.message);
    reply_free(&rp);
    upload_on(&g_c, "datasets.upload", nm("noformat"), NULL, k_xor, strlen(k_xor), NULL, 0, &rp);
    EXPECT(is_error(&rp, "bad_request"), "no format: %s", g_why);
    reply_free(&rp);
    nmzp_buf_init(&names);
    names_text(&names);
    EXPECT(upload_on(&g_c, "datasets.upload", nm("names"), "text", names.data, names.len, NULL, 0, &rp) == 0,
           "upload a text dataset: %s", rp.e.message);
    nmzp_buf_free(&names);
    reply_free(&rp);
    EXPECT(simple("datasets.list", NULL, NULL, &rp) == 0 && nmzp_get(rp.v, "items"), "datasets.list");
    {
        const nmzp_val *it = nmzp_get(rp.v, "items");
        size_t i;
        int found = 0;
        for (i = 0; i < it->n; i++)
            found += nmzp_get_str(it->items[i], "name") && !strcmp(nmzp_get_str(it->items[i], "name"), nm("xor"));
        EXPECT(found == 1, "the uploaded dataset is not listed");
    }
    reply_free(&rp);
    EXPECT(simple("datasets.describe", "name", nm("names"), &rp) == 0 && nmzp_get_str(rp.v, "owner"), "datasets.describe");
    reply_free(&rp);
}

static void create_xor(req *r, const char *name, const char *save) {
    req_begin(r, "models.create");
    nmzp_mw_kstr(&r->w, "name", name);
    nmzp_mw_key(&r->w, "args");
    nmzp_mw_arr(&r->w);
    nmzp_mw_str(&r->w, "2");
    nmzp_mw_str(&r->w, "4");
    nmzp_mw_str(&r->w, "1");
    nmzp_mw_end_arr(&r->w);
    if (save) nmzp_mw_kstr(&r->w, "save", save);
}

static void t_models(void) {
    reply rp;
    req r;
    const nmzp_val *m, *ex;
    long long params = 0;
    size_t i;
    int created = 0;
    create_xor(&r, nm("xor"), g_allow_server ? "server" : "client");
    EXPECT(call(&r, &rp) == 0, "models.create 2 4 1: %s", rp.e.message);
    m = nmzp_get(rp.v, "model");
    ex = nmzp_get(rp.v, "explanation");
    EXPECT(m && nmzp_get_int(m, "params", &params) && params == 17, "params is not 17");
    EXPECT(ex && ex->type == NMZP_ARRAY, "no explanation");
    for (i = 0; i < ex->n; i++)
        if (nmzp_str(ex->items[i]) && strstr(nmzp_str(ex->items[i]), "Created a network with 17 parameters")) created = 1;
    EXPECT(created, "the explanation lacks 'Created a network with 17 parameters.'");
    reply_free(&rp);
    create_xor(&r, nm("xor"), g_allow_server ? "server" : "client");
    call(&r, &rp);
    EXPECT(is_error(&rp, "conflict"), "a second create: %s", g_why);
    reply_free(&rp);
    EXPECT(simple("models.describe", "name", nm("xor"), &rp) == 0, "models.describe: %s", rp.e.message);
    EXPECT(nmzp_get(rp.v, "layers") && nmzp_get(rp.v, "layers")->n >= 2, "no layers");
    EXPECT(nmzp_get_str(rp.v, "storage") && nmzp_get_int(rp.v, "version", NULL) && nmzp_get_int(rp.v, "created", NULL),
           "storage/version/created missing");
    reply_free(&rp);
    req_begin(&r, "models.create");
    nmzp_mw_kstr(&r.w, "name", nm("bad"));
    nmzp_mw_key(&r.w, "args");
    nmzp_mw_arr(&r.w);
    nmzp_mw_str(&r.w, "2");
    nmzp_mw_str(&r.w, "x");
    nmzp_mw_str(&r.w, "1");
    nmzp_mw_end_arr(&r.w);
    call(&r, &rp);
    EXPECT(is_error(&rp, "invalid_argument"), "a bad layer spec: %s", g_why);
    EXPECT(strstr(rp.e.message, "layer spec"), "the library's message is not passed on: %s", rp.e.message);
    reply_free(&rp);
    if (g_max_layer > 0) { /* a layer above the server's limit is refused before it is built (§15) */
        char spec[40];
        snprintf(spec, sizeof spec, "%lld:relu", g_max_layer + 1);
        req_begin(&r, "models.create");
        nmzp_mw_kstr(&r.w, "name", nm("huge"));
        nmzp_mw_key(&r.w, "args");
        nmzp_mw_arr(&r.w);
        nmzp_mw_str(&r.w, "2");
        nmzp_mw_str(&r.w, spec);
        nmzp_mw_str(&r.w, "1");
        nmzp_mw_end_arr(&r.w);
        call(&r, &rp);
        EXPECT(is_error(&rp, "invalid_argument"), "a layer above max_layer_size: %s", g_why);
        reply_free(&rp);
        simple("models.describe", "name", nm("huge"), &rp);
        EXPECT(is_error(&rp, "not_found"), "a refused model was stored: %s", g_why);
        reply_free(&rp);
    }
    req_begin(&r, "models.create"); /* the structured form, options of each type */
    nmzp_mw_kstr(&r.w, "name", nm("fields"));
    nmzp_mw_kstr(&r.w, "input", "4");
    nmzp_mw_key(&r.w, "layers");
    nmzp_mw_arr(&r.w);
    nmzp_mw_str(&r.w, "8:relu");
    nmzp_mw_str(&r.w, "3:softmax");
    nmzp_mw_end_arr(&r.w);
    nmzp_mw_key(&r.w, "options");
    nmzp_mw_map(&r.w);
    nmzp_mw_kfloat(&r.w, "lr", 0.02);
    nmzp_mw_kint(&r.w, "epochs", 5);
    nmzp_mw_kbool(&r.w, "shuffle", 0);
    nmzp_mw_end_map(&r.w);
    EXPECT(call(&r, &rp) == 0, "the structured form: %s", rp.e.message);
    {
        double lr = 0;
        EXPECT(nmzp_get_num(nmzp_get(nmzp_get(rp.v, "model"), "config"), "lr", &lr) && lr > 0.0199 && lr < 0.0201,
               "options.lr did not reach the model's config");
    }
    reply_free(&rp);
    req_begin(&r, "models.create");
    nmzp_mw_kstr(&r.w, "name", nm("badopt"));
    nmzp_mw_kstr(&r.w, "input", "2");
    nmzp_mw_key(&r.w, "layers");
    nmzp_mw_arr(&r.w);
    nmzp_mw_str(&r.w, "4");
    nmzp_mw_str(&r.w, "1");
    nmzp_mw_end_arr(&r.w);
    nmzp_mw_key(&r.w, "options");
    nmzp_mw_map(&r.w);
    nmzp_mw_kint(&r.w, "lr", -1);
    nmzp_mw_end_map(&r.w);
    call(&r, &rp);
    EXPECT(is_error(&rp, "invalid_argument"), "options.lr = -1: %s", g_why);
    EXPECT(strstr(rp.e.message, "--lr"), "the option's message: %s", rp.e.message);
    reply_free(&rp);
    req_begin(&r, "models.create");
    nmzp_mw_kstr(&r.w, "name", nm("names"));
    nmzp_mw_kstr(&r.w, "preset", "names");
    nmzp_mw_kstr(&r.w, "dataset", nm("names"));
    nmzp_mw_key(&r.w, "options");
    nmzp_mw_map(&r.w);
    nmzp_mw_kint(&r.w, "epochs", 1);
    nmzp_mw_end_map(&r.w);
    EXPECT(call(&r, &rp) == 0, "a preset with a dataset: %s", rp.e.message);
    {
        int seq = 0;
        long long v = 0;
        m = nmzp_get(rp.v, "model");
        EXPECT(nmzp_get_bool(m, "sequence", &seq) && seq, "a text model is not a sequence");
        EXPECT(nmzp_get_int(m, "vocab_size", &v) && v > 10, "no vocabulary");
    }
    reply_free(&rp);
    EXPECT(simple("models.list", NULL, NULL, &rp) == 0 && nmzp_get(rp.v, "items"), "models.list");
    reply_free(&rp);
}

static void t_model_files(void) {
    reply rp;
    req r;
    nmzp_val *head = NULL;
    nmzp_error e;
    nmzp_buf file;
    long long size = 0;
    nmzp_buf_init(&file);
    req_begin(&r, "models.download");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    EXPECT(nmzp_call_download(&g_c, req_end(&r), &head, nmzp_write_to_buf, &file, &e) == 0, "models.download: %s", e.message);
    nmzp_buf_free(&r.b);
    EXPECT(file.len > 16 && !memcmp(file.data + 1, "NMZ", 3), "not a model file (no 0x89 NMZ magic)");
    EXPECT(nmzp_get_int(head, "size", &size) && (size_t)size == file.len, "the head's size differs from the file");
    EXPECT(nmzp_get_int(head, "version", NULL), "the head has no version");
    nmzp_val_free(head);
    EXPECT(upload_on(&g_c, "models.upload", nm("copy"), NULL, file.data, file.len, "save", 0, &rp) == 0,
           "upload under another name: %s", rp.e.message);
    {
        long long p = 0;
        EXPECT(nmzp_get_int(nmzp_get(rp.v, "model"), "params", &p) && p == 17, "the uploaded model has %lld parameters", p);
    }
    reply_free(&rp);
    upload_on(&g_c, "models.upload", nm("copy"), NULL, file.data, file.len, "save", 0, &rp);
    EXPECT(is_error(&rp, "conflict"), "a second upload without overwrite: %s", g_why);
    reply_free(&rp);
    nmzp_buf_free(&file);
    upload_on(&g_c, "models.upload", nm("garbage"), NULL, "not a model", 11, "save", 0, &rp);
    EXPECT(is_error(&rp, "invalid_argument"), "a file that is not a model: %s", g_why);
    reply_free(&rp);
}

/* ------------------------------------------------------------ jobs */

typedef struct events {
    int states, epochs, batches, ended, order_ok;
    long long last_seq;
    char final_state[32];
} events;

static int on_event(void *user, const char *event, long long seq, const nmzp_val *data) {
    events *s = (events *)user;
    if (seq) {
        if (seq <= s->last_seq) s->order_ok = 0;
        s->last_seq = seq;
    }
    if (!strcmp(event, "state")) s->states++;
    if (!strcmp(event, "epoch")) s->epochs++;
    if (!strcmp(event, "batch")) s->batches++;
    if (!strcmp(event, "end")) {
        snprintf(s->final_state, sizeof s->final_state, "%s", nmzp_get_str(data, "state") ? nmzp_get_str(data, "state") : "?");
        s->ended = 1;
    }
    return 0;
}

static char g_job_xor[32];

static void wait_state(const char *id, const char *want, double seconds, char *got, size_t gotn) {
    double t0 = nmzp_clock();
    got[0] = '\0';
    while (nmzp_clock() - t0 < seconds) {
        reply rp;
        if (simple("jobs.status", "id", id, &rp) == 0 && nmzp_get_str(rp.v, "state"))
            snprintf(got, gotn, "%s", nmzp_get_str(rp.v, "state"));
        reply_free(&rp);
        if (!strcmp(got, want) || !strcmp(got, "failed") || !strcmp(got, "succeeded") || !strcmp(got, "cancelled")) return;
        nmzp_sleep_ms(100);
    }
}

static int submit(const char *model, const char *dataset, const char *save, long long epochs, int batch1, char *id,
                  size_t idn, reply *rp) {
    req r;
    req_begin(&r, "jobs.train");
    nmzp_mw_kstr(&r.w, "model", model);
    nmzp_mw_kstr(&r.w, "dataset", dataset);
    nmzp_mw_kstr(&r.w, "device", "auto");
    nmzp_mw_kstr(&r.w, "save", save);
    nmzp_mw_key(&r.w, "options");
    nmzp_mw_map(&r.w);
    if (epochs) nmzp_mw_kint(&r.w, "epochs", epochs);
    if (batch1) {
        nmzp_mw_kint(&r.w, "batch", 1);
        nmzp_mw_kint(&r.w, "patience", 0);
    }
    nmzp_mw_end_map(&r.w);
    if (call(&r, rp) != 0) return -1;
    snprintf(id, idn, "%s", nmzp_get_str(rp->v, "id") ? nmzp_get_str(rp->v, "id") : "");
    return 0;
}

static void t_train_job(void) {
    reply rp;
    req r;
    events ev;
    nmzp_val *head = NULL;
    nmzp_error e;
    long long steps = 0, v0 = 0, v1 = 0;
    int conv = 0;
    EXPECT(simple("models.describe", "name", nm("xor"), &rp) == 0, "the xor model");
    nmzp_get_int(rp.v, "version", &v0);
    reply_free(&rp);
    EXPECT(submit(nm("xor"), nm("xor"), g_allow_server ? "server" : "client", 0, 0, g_job_xor, sizeof g_job_xor, &rp) == 0,
           "jobs.train: %s", rp.e.message);
    EXPECT(nmzp_get_str(rp.v, "id") && nmzp_get_str(rp.v, "state"), "no id/state");
    reply_free(&rp);
    memset(&ev, 0, sizeof ev);
    ev.order_ok = 1;
    req_begin(&r, "jobs.subscribe");
    nmzp_mw_kstr(&r.w, "id", g_job_xor);
    EXPECT(nmzp_call_events(&g_c, req_end(&r), &head, on_event, &ev, &e) == 0, "jobs.subscribe: %s", e.message);
    nmzp_buf_free(&r.b);
    EXPECT(nmzp_get(head, "job"), "the subscription's RESPONSE has no job");
    nmzp_val_free(head);
    EXPECT(ev.ended && ev.states >= 1 && ev.epochs >= 1, "the events: %d state, %d epoch, end %d", ev.states, ev.epochs,
           ev.ended);
    EXPECT(ev.order_ok, "numbered events out of order");
    EXPECT(!strcmp(ev.final_state, "succeeded"), "the job ended %s", ev.final_state);
    EXPECT(simple("jobs.status", "id", g_job_xor, &rp) == 0, "jobs.status");
    EXPECT(nmzp_get_bool(nmzp_get(rp.v, "result"), "converged", &conv) && conv, "XOR did not converge");
    EXPECT(nmzp_get_str(rp.v, "device") && nmzp_get_str(rp.v, "config"), "device/config missing");
    reply_free(&rp);
    EXPECT(simple("models.describe", "name", nm("xor"), &rp) == 0, "the xor model after training");
    nmzp_get_int(rp.v, "train_steps", &steps);
    nmzp_get_int(rp.v, "version", &v1);
    EXPECT(steps > 0 && v1 > v0, "the trained model was not stored (steps %lld, version %lld -> %lld)", steps, v0, v1);
    reply_free(&rp);
    /* a late subscriber gets the history, then end; "after" skips what it has */
    {
        long long all;
        memset(&ev, 0, sizeof ev);
        ev.order_ok = 1;
        req_begin(&r, "jobs.subscribe");
        nmzp_mw_kstr(&r.w, "id", g_job_xor);
        EXPECT(nmzp_call_events(&g_c, req_end(&r), NULL, on_event, &ev, &e) == 0 && ev.ended && ev.epochs >= 1,
               "replay of a finished job: %d epochs, end %d (%s)", ev.epochs, ev.ended, e.message);
        nmzp_buf_free(&r.b);
        all = ev.last_seq;
        memset(&ev, 0, sizeof ev);
        req_begin(&r, "jobs.subscribe");
        nmzp_mw_kstr(&r.w, "id", g_job_xor);
        nmzp_mw_kint(&r.w, "after", all - 1);
        EXPECT(nmzp_call_events(&g_c, req_end(&r), NULL, on_event, &ev, &e) == 0 && ev.ended && ev.epochs == 0 &&
                   ev.states == 0,
               "after = the last but one: only the end should come");
        nmzp_buf_free(&r.b);
    }
}

static int stop_at_first(void *user, const char *event, long long seq, const nmzp_val *data) {
    (void)seq, (void)data;
    (*(int *)user)++;
    return !strcmp(event, "state") || !strcmp(event, "epoch") || !strcmp(event, "batch"); /* unsubscribe at once */
}

static void t_cancel(void) {
    reply rp;
    char state[32], jid[32];
    EXPECT(submit(nm("names"), nm("names"), g_allow_server ? "server" : "client", g_max_epochs, 1, jid, sizeof jid, &rp) == 0,
           "a long job: %s", rp.e.message);
    reply_free(&rp);
    wait_state(jid, "running", 60, state, sizeof state);
    EXPECT(!strcmp(state, "running"), "the long job is %s, not running", state);
    { /* a subscription answered while the job runs: an unsubscribe (ABORT) ends it */
        req r;
        nmzp_error e;
        int seen = 0;
        req_begin(&r, "jobs.subscribe");
        nmzp_mw_kstr(&r.w, "id", jid);
        EXPECT(nmzp_call_events(&g_c, req_end(&r), NULL, stop_at_first, &seen, &e) == 0 && seen >= 1,
               "unsubscribing from a running job: %s", e.message);
        nmzp_buf_free(&r.b);
    }
    { /* the subscription of a running job, a request beside it on the same connection */
        nmzp_client c;
        nmzp_frame f;
        req r;
        int answered = 0, i;
        if (!session(&c)) return;
        req_begin(&r, "jobs.subscribe");
        nmzp_mw_kstr(&r.w, "id", jid);
        req_end(&r);
        nmzp_client_send(&c, NMZP_REQUEST, 0, 1, r.b.data, r.b.len);
        nmzp_buf_free(&r.b);
        nmzp_client_send(&c, NMZP_REQUEST, 0, 2, "\x81\xa2op\xa6health", 11);
        nmzp_frame_init(&f);
        for (i = 0; i < 200 && !answered; i++) {
            if (next(&c, &f, 10000) != 1) break;
            if (f.h.id == 2 && f.h.type == NMZP_RESPONSE) answered = 1;
        }
        nmzp_frame_free(&f);
        nmzp_client_close(&c); /* closes in the middle of the subscription */
        EXPECT(answered, "health was not answered beside an open subscription");
    }
    EXPECT(simple("jobs.cancel", "id", jid, &rp) == 0, "jobs.cancel: %s", rp.e.message);
    reply_free(&rp);
    wait_state(jid, "cancelled", 60, state, sizeof state);
    EXPECT(!strcmp(state, "cancelled"), "after cancel the job is %s", state);
    simple("jobs.cancel", "id", jid, &rp);
    EXPECT(is_error(&rp, "conflict"), "cancelling a finished job: %s", g_why);
    reply_free(&rp);
    EXPECT(alive(), "after a disconnect in a subscription: %s", g_why);
}

static void t_disconnects(void) {
    nmzp_client c;
    nmzp_frame f;
    req r;
    /* an upload, cut in the middle */
    if (!session(&c)) return;
    open_upload(&c, 1, nm("cut"), 1000);
    nmzp_client_send(&c, NMZP_DATA, NMZP_MORE, 1, k_xor, 10);
    nmzp_client_close(&c);
    EXPECT(alive(), "after an upload cut short: %s", g_why);
    /* a download, left after its head */
    if (!session(&c)) return;
    req_begin(&r, "models.download");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    req_end(&r);
    nmzp_client_send(&c, NMZP_REQUEST, 0, 1, r.b.data, r.b.len);
    nmzp_buf_free(&r.b);
    nmzp_frame_init(&f);
    EXPECT(next(&c, &f, 10000) == 1 && f.h.type == NMZP_RESPONSE && (f.h.flags & NMZP_MORE), "no download head");
    nmzp_frame_free(&f);
    nmzp_client_close(&c);
    EXPECT(alive(), "after a download left half-way: %s", g_why);
    {
        reply rp;
        simple("datasets.describe", "name", nm("cut"), &rp);
        EXPECT(is_error(&rp, "not_found"), "a cut upload was stored: %s", g_why);
        reply_free(&rp);
    }
}

static void t_job_list(void) {
    reply rp;
    req r;
    const nmzp_val *it;
    size_t i;
    int found = 0;
    req_begin(&r, "jobs.list");
    nmzp_mw_kstr(&r.w, "state", "succeeded");
    EXPECT(call(&r, &rp) == 0, "jobs.list state=succeeded: %s", rp.e.message);
    it = nmzp_get(rp.v, "items");
    EXPECT(it && it->type == NMZP_ARRAY, "no items");
    for (i = 0; i < it->n; i++) {
        const char *st = nmzp_get_str(it->items[i], "state");
        EXPECT(st && !strcmp(st, "succeeded"), "the filter let a %s job through", st ? st : "?");
        if (nmzp_get_str(it->items[i], "id") && !strcmp(nmzp_get_str(it->items[i], "id"), g_job_xor)) found = 1;
    }
    EXPECT(found || !g_job_xor[0], "the finished job %s is not listed", g_job_xor);
    reply_free(&rp);
}

static void t_save_policy(void) {
    reply rp;
    req r;
    char state[32], jid[32];
    const char *out;
    long long v0 = 0, v1 = 0;
    if (!g_allow_client) {
        create_xor(&r, nm("cl"), "client");
        call(&r, &rp);
        EXPECT(is_error(&rp, "save_not_allowed"), "save=client on a server that does not allow it: %s", g_why);
        reply_free(&rp);
        return;
    }
    create_xor(&r, nm("cl"), "client");
    EXPECT(call(&r, &rp) == 0, "save=client: %s", rp.e.message);
    EXPECT(nmzp_get_str(nmzp_get(rp.v, "model"), "storage") && !strcmp(nmzp_get_str(nmzp_get(rp.v, "model"), "storage"), "client"),
           "storage is not client");
    EXPECT(nmzp_get_int(nmzp_get(rp.v, "model"), "expires", NULL), "a client model without expires");
    reply_free(&rp);
    if (!g_allow_server) return;
    EXPECT(simple("models.describe", "name", nm("xor"), &rp) == 0, "the xor model");
    nmzp_get_int(rp.v, "version", &v0);
    reply_free(&rp);
    EXPECT(submit(nm("xor"), nm("xor"), "client", 5, 0, jid, sizeof jid, &rp) == 0, "a save=client job: %s", rp.e.message);
    reply_free(&rp);
    wait_state(jid, "succeeded", 60, state, sizeof state);
    EXPECT(!strcmp(state, "succeeded"), "the save=client job: %s", state);
    EXPECT(simple("jobs.status", "id", jid, &rp) == 0, "the job");
    out = nmzp_get_str(rp.v, "output_model");
    EXPECT(out && strcmp(out, nm("xor")), "save=client on a server model must not overwrite it (output_model %s)",
           out ? out : "nil");
    reply_free(&rp);
    EXPECT(simple("models.describe", "name", nm("xor"), &rp) == 0, "the xor model again");
    nmzp_get_int(rp.v, "version", &v1);
    EXPECT(v1 == v0, "the stored model changed (version %lld -> %lld)", v0, v1);
    reply_free(&rp);
    {
        nmzp_buf file;
        nmzp_error e;
        nmzp_buf_init(&file);
        req_begin(&r, "jobs.model");
        nmzp_mw_kstr(&r.w, "id", jid);
        EXPECT(nmzp_call_download(&g_c, req_end(&r), NULL, nmzp_write_to_buf, &file, &e) == 0 && file.len > 16,
               "jobs.model: %s", e.message);
        nmzp_buf_free(&r.b);
        nmzp_buf_free(&file);
    }
}

static void t_inference(void) {
    reply rp;
    req r;
    size_t n = 0;
    const unsigned char *out;
    float y[4];
    req_begin(&r, "models.predict");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    nmzp_mw_key(&r.w, "inputs");
    nmzp_mw_arr(&r.w);
    {
        int a, b;
        for (a = 0; a < 2; a++)
            for (b = 0; b < 2; b++) {
                nmzp_mw_arr(&r.w);
                nmzp_mw_int(&r.w, a);
                nmzp_mw_int(&r.w, b);
                nmzp_mw_end_arr(&r.w);
            }
    }
    nmzp_mw_end_arr(&r.w);
    EXPECT(call(&r, &rp) == 0, "models.predict: %s", rp.e.message);
    out = nmzp_bin(nmzp_get(rp.v, "outputs"), &n);
    EXPECT(out && n == 16, "outputs are not a bin of 4 float32");
    {
        long long s0 = 0, s1 = 0;
        EXPECT(nmzp_int(nmzp_at(nmzp_get(rp.v, "shape"), 0), &s0) && s0 == 4 &&
                   nmzp_int(nmzp_at(nmzp_get(rp.v, "shape"), 1), &s1) && s1 == 1,
               "shape is not [4, 1]");
    }
    nmzp_f32_read(out, 4, y);
    EXPECT(y[0] < 0.5f && y[1] > 0.5f && y[2] > 0.5f && y[3] < 0.5f, "the trained XOR predicts %g %g %g %g", y[0], y[1],
           y[2], y[3]);
    EXPECT(nmzp_get_str(rp.v, "device"), "no device in the answer");
    reply_free(&rp);
    { /* the same inputs as float32 */
        static const float in[8] = {0, 0, 0, 1, 1, 0, 1, 1};
        float y2[4];
        req_begin(&r, "models.predict");
        nmzp_mw_kstr(&r.w, "name", nm("xor"));
        nmzp_mw_key(&r.w, "inputs");
        nmzp_mw_f32(&r.w, in, 8);
        EXPECT(call(&r, &rp) == 0, "models.predict with a bin of float32: %s", rp.e.message);
        out = nmzp_bin(nmzp_get(rp.v, "outputs"), &n);
        EXPECT(out && n == 16, "float32 inputs: outputs are not 4 float32");
        nmzp_f32_read(out, 4, y2);
        EXPECT(!memcmp(y, y2, sizeof y), "float32 inputs give other outputs than numbers");
        reply_free(&rp);
    }
    req_begin(&r, "models.predict");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    nmzp_mw_key(&r.w, "inputs");
    nmzp_mw_arr(&r.w);
    nmzp_mw_int(&r.w, 1);
    nmzp_mw_int(&r.w, 2);
    nmzp_mw_int(&r.w, 3);
    nmzp_mw_end_arr(&r.w);
    call(&r, &rp);
    EXPECT(is_error(&rp, "invalid_argument"), "3 inputs for a 2-input model: %s", g_why);
    reply_free(&rp);
    req_begin(&r, "models.test");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    nmzp_mw_kstr(&r.w, "dataset", nm("xor"));
    EXPECT(call(&r, &rp) == 0, "models.test: %s", rp.e.message);
    {
        long long samples = 0;
        double acc = 0;
        EXPECT(nmzp_get_int(rp.v, "samples", &samples) && samples == 4, "test samples: %lld", samples);
        EXPECT(nmzp_get_num(rp.v, "accuracy", &acc) && acc > 0.99, "accuracy %g", acc);
        EXPECT(nmzp_get_num(rp.v, "loss", NULL), "no loss");
    }
    reply_free(&rp);
    req_begin(&r, "models.generate");
    nmzp_mw_kstr(&r.w, "name", nm("names"));
    nmzp_mw_kint(&r.w, "count", 3);
    nmzp_mw_kint(&r.w, "seed", 5);
    EXPECT(call(&r, &rp) == 0, "models.generate: %s", rp.e.message);
    EXPECT(nmzp_get_str(rp.v, "kind") && !strcmp(nmzp_get_str(rp.v, "kind"), "items"), "kind is not items");
    EXPECT(nmzp_get(rp.v, "items") && nmzp_get(rp.v, "items")->type == NMZP_ARRAY && nmzp_get(rp.v, "items")->n <= 3, "items");
    reply_free(&rp);
    req_begin(&r, "models.predict");
    nmzp_mw_kstr(&r.w, "name", nm("names"));
    nmzp_mw_kstr(&r.w, "text", "An");
    EXPECT(call(&r, &rp) == 0, "predict text: %s", rp.e.message);
    EXPECT(nmzp_get(rp.v, "next") && nmzp_get(rp.v, "next")->n > 0, "no next characters");
    reply_free(&rp);
    req_begin(&r, "models.generate");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    nmzp_mw_kint(&r.w, "count", 1);
    call(&r, &rp);
    EXPECT(is_error(&rp, "invalid_argument"), "generate on a model that is not a text model: %s", g_why);
    reply_free(&rp);
}

static void t_trace(void) {
    req r;
    nmzp_val *head = NULL;
    nmzp_error e;
    nmzp_buf lines;
    int st;
    long long n_events = 0;
    req_begin(&r, "models.trace");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    nmzp_mw_key(&r.w, "inputs");
    nmzp_mw_arr(&r.w);
    nmzp_mw_int(&r.w, 1);
    nmzp_mw_int(&r.w, 0);
    nmzp_mw_end_arr(&r.w);
    nmzp_mw_key(&r.w, "target");
    nmzp_mw_arr(&r.w);
    nmzp_mw_int(&r.w, 1);
    nmzp_mw_end_arr(&r.w);
    nmzp_buf_init(&lines);
    st = nmzp_call_download(&g_c, req_end(&r), &head, nmzp_write_to_buf, &lines, &e);
    nmzp_buf_free(&r.b);
    if (!g_trace_enabled) {
        EXPECT(st == 1 && !strcmp(e.name, "forbidden"), "trace on a server that disables it: %s", e.message);
        nmzp_buf_free(&lines);
        return;
    }
    EXPECT(st == 0, "models.trace: %s", e.message);
    EXPECT(nmzp_get_int(head, "events", &n_events) && n_events > 0, "the trace's head has no events");
    EXPECT(nmzp_get_str(head, "format") && !strcmp(nmzp_get_str(head, "format"), "jsonl"), "the format is not jsonl");
    {
        const char *p = lines.data;
        int n = 0, fwd = 0, bwd = 0;
        while (p && *p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            nmzp_json *j = nmzp_json_parse(p, len, 64, NULL, 0);
            const char *ph = nmzp_json_get_str(j, "phase");
            if (!j || !ph || !nmzp_json_get(j, "items")) {
                nmzp_json_free(j);
                nmzp_val_free(head);
                nmzp_buf_free(&lines);
                EXPECT(0, "trace line %d is not an event", n + 1);
            }
            fwd += !strcmp(ph, "forward");
            bwd += !strcmp(ph, "backward");
            nmzp_json_free(j);
            n++;
            p = nl ? nl + 1 : NULL;
        }
        nmzp_val_free(head);
        nmzp_buf_free(&lines);
        EXPECT(n == (int)n_events && fwd > 0 && bwd > 0, "%d lines (%d forward, %d backward), the head says %lld", n, fwd, bwd,
               n_events);
    }
}

static void t_permissions(void) {
    nmzp_client c;
    reply rp;
    req r;
    if (!g_have_read) {
        skip();
        return;
    }
    nmzp_client_init(&c, g_host, g_port, g_rtoken);
    snprintf(c.name, sizeof c.name, "nmz-conformance");
    req_begin(&r, "models.list");
    EXPECT(call_on(&c, &r, &rp) == 0, "read token: models.list %s", rp.e.message);
    reply_free(&rp);
    create_xor(&r, nm("ro"), NULL);
    call_on(&c, &r, &rp);
    EXPECT(is_error(&rp, "forbidden"), "a read token creating a model: %s", g_why);
    reply_free(&rp);
    req_begin(&r, "models.delete");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    call_on(&c, &r, &rp);
    EXPECT(is_error(&rp, "forbidden"), "a read token deleting a model: %s", g_why);
    reply_free(&rp);
    req_begin(&r, "models.predict");
    nmzp_mw_kstr(&r.w, "name", nm("xor"));
    nmzp_mw_key(&r.w, "inputs");
    nmzp_mw_arr(&r.w);
    nmzp_mw_int(&r.w, 0);
    nmzp_mw_int(&r.w, 1);
    nmzp_mw_end_arr(&r.w);
    EXPECT(call_on(&c, &r, &rp) == 0, "a read token predicting: %s", rp.e.message);
    reply_free(&rp);
    nmzp_client_close(&c);
}

static void t_idle(void) {
    nmzp_client c;
    if (!g_idle || g_idle > 15) { /* the reference server's 300 s is too long to wait for here */
        skip();
        return;
    }
    if (!session(&c)) return;
    EXPECT(expect_error_on(&c, 0, "timeout", 1), "an idle connection (idle_timeout %lld s): %s", g_idle, g_why);
    nmzp_client_close(&c);
}

static void t_cleanup(void) {
    static const char *const models[] = {"xor", "fields", "names", "copy", "cl", NULL};
    static const char *const sets[] = {"xor", "names", NULL};
    int i;
    for (i = 0; models[i]; i++) {
        reply rp;
        int st = simple("models.delete", "name", nm(models[i]), &rp);
        EXPECT(st == 0 || (st == 1 && !strcmp(rp.e.name, "not_found")), "models.delete %s: %s", nm(models[i]), rp.e.message);
        reply_free(&rp);
    }
    for (i = 0; sets[i]; i++) {
        reply rp;
        int st = simple("datasets.delete", "name", nm(sets[i]), &rp);
        EXPECT(st == 0, "datasets.delete %s: %s", nm(sets[i]), rp.e.message);
        reply_free(&rp);
    }
    {
        reply rp;
        simple("models.describe", "name", nm("xor"), &rp);
        EXPECT(is_error(&rp, "not_found"), "a deleted model is still there: %s", g_why);
        reply_free(&rp);
    }
}

/* -------------------------------------------------------------- main */

static int usage(void) {
    fprintf(stderr, "usage: nmz-conformance --host HOST[:PORT] [--token T] [--read-token T] [--prefix P] [--verbose]\n");
    return 2;
}

int main(int argc, char **argv) {
    const char *host = NULL;
    int i;
    unsigned char rnd[4];
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else if (!strcmp(argv[i], "--token") && i + 1 < argc) snprintf(g_token, sizeof g_token, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--read-token") && i + 1 < argc) {
            snprintf(g_rtoken, sizeof g_rtoken, "%s", argv[++i]);
            g_have_read = 1;
        } else if (!strcmp(argv[i], "--prefix") && i + 1 < argc) snprintf(g_prefix, sizeof g_prefix, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--verbose")) g_verbose = 1;
        else return usage();
    }
    if (!host || nmzp_parse_hostport(host, g_host, sizeof g_host, &g_port)) return usage();
    if (nmzp_net_init()) {
        fprintf(stderr, "error: the socket library did not start\n");
        return 2;
    }
    if (!g_prefix[0]) {
        char hex[9];
        nmzp_random(rnd, sizeof rnd);
        nmzp_hex(rnd, sizeof rnd, hex);
        snprintf(g_prefix, sizeof g_prefix, "cf%s", hex);
    }
    nmzp_client_init(&g_c, g_host, g_port, g_token);
    snprintf(g_c.name, sizeof g_c.name, "nmz-conformance");
    g_c.timeout_ms = 120000;
    g_c.allow_no_auth = 1;
    printf("# NeuroMZ protocol %s conformance: %s:%d (names %s-*)\n", NMZP_PROTOCOL, g_host, g_port, g_prefix);
    run("greeting", t_greeting);
    run("handshake", t_handshake);
    run("authentication", t_auth);
    run("bad magic, versions, HTTP", t_magic_version);
    run("frames", t_frames);
    run("requests", t_requests);
    run("interleaved requests", t_interleaved);
    run("in flight, abort", t_inflight_abort);
    run("upload integrity", t_integrity);
    run("server", t_server);
    run("capabilities", t_capabilities);
    run("errors", t_errors);
    run("datasets", t_datasets);
    run("models", t_models);
    run("model files", t_model_files);
    run("training job and events", t_train_job);
    run("cancelling a job, unsubscribing", t_cancel);
    run("disconnects in streams", t_disconnects);
    run("listing jobs", t_job_list);
    run("save policy", t_save_policy);
    run("inference", t_inference);
    run("trace", t_trace);
    run("permissions", t_permissions);
    run("idle timeout", t_idle);
    run("cleanup", t_cleanup);
    printf("1..%d\n# %d passed, %d failed, %d skipped\n", g_n, g_pass, g_fail, g_skip);
    nmzp_client_close(&g_c);
    return g_fail ? 1 : 0;
}
