/* client.c — Server-Sent Events (parsing and writing) and a small HTTP/1.1
 * client: one connection kept alive between requests (reopened once if
 * the server closed it), bodies by Content-Length, chunked or until the
 * connection closes, and streaming for event streams. Plain HTTP only:
 * TLS is the job of a reverse proxy (PROTOCOL.md §1). */
#include "nmzp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------- Server-Sent Events */

void nmzp_sse_init(nmzp_sse *s, nmzp_sse_fn fn, void *user) {
    memset(s, 0, sizeof *s);
    nmzp_buf_init(&s->line);
    nmzp_buf_init(&s->data);
    s->fn = fn;
    s->user = user;
}

void nmzp_sse_free(nmzp_sse *s) {
    nmzp_buf_free(&s->line);
    nmzp_buf_free(&s->data);
}

/* one complete line (without its end); 1 = the callback asked to stop */
static int sse_line(nmzp_sse *s) {
    const char *l = s->line.data ? s->line.data : "", *colon, *v;
    size_t n = s->line.len, flen;
    if (n == 0) { /* dispatch */
        int stop = 0;
        if (s->data.len || s->event[0]) {
            if (s->data.len && s->data.data[s->data.len - 1] == '\n') s->data.data[--s->data.len] = '\0';
            if (s->fn) stop = s->fn(s->event[0] ? s->event : "message", s->id, s->data.data ? s->data.data : "", s->user);
        }
        nmzp_buf_clear(&s->data);
        s->event[0] = '\0';
        return stop ? 1 : 0;
    }
    if (l[0] == ':') return 0; /* a comment */
    colon = memchr(l, ':', n);
    flen = colon ? (size_t)(colon - l) : n;
    v = colon ? colon + 1 : l + n;
    if (*v == ' ') v++;
    if (flen == 4 && !memcmp(l, "data", 4)) {
        nmzp_buf_add(&s->data, v, (size_t)(l + n - v));
        nmzp_buf_add(&s->data, "\n", 1);
    } else if (flen == 5 && !memcmp(l, "event", 5)) {
        snprintf(s->event, sizeof s->event, "%.*s", (int)(l + n - v), v);
    } else if (flen == 2 && !memcmp(l, "id", 2)) {
        if (!memchr(v, '\0', (size_t)(l + n - v))) snprintf(s->id, sizeof s->id, "%.*s", (int)(l + n - v), v);
    } /* retry and unknown fields: ignored */
    return 0;
}

int nmzp_sse_feed(nmzp_sse *s, const char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        char c = p[i];
        if (s->skip_lf) {
            s->skip_lf = 0;
            if (c == '\n') continue;
        }
        if (c == '\r' || c == '\n') {
            int r = sse_line(s);
            s->skip_lf = c == '\r';
            nmzp_buf_clear(&s->line);
            if (r) return 1;
            continue;
        }
        if (s->line.len > 4u << 20) return -1; /* a 4 MB line is not an event */
        if (nmzp_buf_add(&s->line, &c, 1)) return -1;
    }
    return s->line.oom || s->data.oom ? -1 : 0;
}

void nmzp_sse_write(nmzp_buf *b, const char *event, const char *id, const char *data) {
    const char *p = data ? data : "";
    if (id) nmzp_buf_printf(b, "id: %s\n", id);
    if (event) nmzp_buf_printf(b, "event: %s\n", event);
    for (;;) {
        const char *nl = strchr(p, '\n');
        nmzp_buf_str(b, "data: ");
        nmzp_buf_add(b, p, nl ? (size_t)(nl - p) : strlen(p));
        nmzp_buf_str(b, "\n");
        if (!nl) break;
        p = nl + 1;
    }
    nmzp_buf_str(b, "\n");
}

/* ------------------------------------------------------------- client */

void nmzp_client_init(nmzp_client *c, const char *host, int port, const char *token) {
    memset(c, 0, sizeof *c);
    snprintf(c->host, sizeof c->host, "%s", host ? host : "127.0.0.1");
    c->port = port > 0 ? port : NMZP_DEFAULT_PORT;
    snprintf(c->token, sizeof c->token, "%s", token ? token : "");
    snprintf(c->user_agent, sizeof c->user_agent, "nmzp/%d.%d", NMZP_VERSION_MAJOR, NMZP_VERSION_MINOR);
    c->timeout_ms = 30000;
    c->sock = NMZP_NO_SOCKET;
}

void nmzp_client_close(nmzp_client *c) {
    nmzp_close(c->sock);
    c->sock = NMZP_NO_SOCKET;
}

void nmzp_response_free(nmzp_response *r) {
    if (!r) return;
    nmzp_http_head_free(&r->head);
    nmzp_buf_free(&r->body);
    memset(r, 0, sizeof *r);
}

static int cfail(nmzp_client *c, const char *msg) {
    snprintf(c->err, sizeof c->err, "%s", msg);
    nmzp_client_close(c);
    return -1;
}

static int send_request(nmzp_client *c, const char *method, const char *path, const char *ctype, const void *body,
                        size_t n, const char *extra) {
    nmzp_buf h;
    int r;
    nmzp_buf_init(&h);
    nmzp_buf_printf(&h, "%s %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: %s\r\nAccept: */*\r\n", method, path, c->host,
                    c->port, c->user_agent);
    if (c->token[0]) nmzp_buf_printf(&h, "Authorization: Bearer %s\r\n", c->token);
    if (body || !strcmp(method, "POST") || !strcmp(method, "PUT")) {
        nmzp_buf_printf(&h, "Content-Length: %lu\r\n", (unsigned long)n);
        if (ctype) nmzp_buf_printf(&h, "Content-Type: %s\r\n", ctype);
    }
    if (extra) nmzp_buf_str(&h, extra);
    nmzp_buf_str(&h, "\r\n");
    if (h.oom) {
        nmzp_buf_free(&h);
        return -1;
    }
    r = nmzp_send_all(c->sock, h.data, h.len);
    if (r == 0 && n) r = nmzp_send_all(c->sock, body, n);
    nmzp_buf_free(&h);
    return r;
}

/* read the response head into r; `got` = bytes received at all (to tell a
 * stale kept-alive connection from a real failure). Leftover body bytes
 * stay in *in. */
static int read_head(nmzp_client *c, nmzp_response *r, nmzp_buf *in, size_t *got) {
    char tmp[8192], err[200];
    for (;;) {
        size_t end = nmzp_http_head_end(in->data ? in->data : "", in->len);
        long k;
        if (end) {
            int st = nmzp_http_parse_response(in->data, end, &r->head, err, sizeof err);
            if (st) {
                char msg[260];
                snprintf(msg, sizeof msg, "a bad response from the server: %s", err);
                return cfail(c, msg);
            }
            r->status = r->head.status;
            nmzp_buf_consume(in, end);
            return 0;
        }
        if (in->len > NMZP_MAX_HEAD) return cfail(c, "the response head is too large");
        k = nmzp_recv(c->sock, tmp, sizeof tmp, c->timeout_ms);
        if (k == -2) return cfail(c, "the server did not answer in time");
        if (k <= 0) return cfail(c, k == 0 ? "the server closed the connection" : "the connection failed");
        *got += (size_t)k;
        if (nmzp_buf_add(in, tmp, (size_t)k)) return cfail(c, "out of memory");
    }
}

/* the body: through fn (streaming) or into r->body */
static int read_body(nmzp_client *c, nmzp_response *r, nmzp_buf *in, int head_request, nmzp_body_fn fn, void *user) {
    char tmp[16384];
    long long left = r->head.content_length;
    int chunked = r->head.chunked, until_close = !chunked && left < 0;
    nmzp_chunked ch;
    nmzp_buf dec;
    int stopped = 0;
    if (head_request || r->status == 204 || r->status == 304 || (r->status >= 100 && r->status < 200)) left = 0, chunked = 0, until_close = 0;
    nmzp_chunked_init(&ch);
    nmzp_buf_init(&dec);
    for (;;) {
        /* consume what is buffered */
        if (in->len) {
            if (chunked) {
                long k = nmzp_chunked_feed(&ch, in->data, in->len, &dec, (size_t)1 << 40);
                if (k < 0) {
                    nmzp_buf_free(&dec);
                    return cfail(c, "a malformed chunked body");
                }
                nmzp_buf_consume(in, (size_t)k);
                if (dec.len) {
                    if (fn) stopped = stopped || fn(dec.data, dec.len, user);
                    else nmzp_buf_add(&r->body, dec.data, dec.len);
                    nmzp_buf_clear(&dec);
                }
                if (ch.done) break;
            } else {
                size_t take = in->len;
                if (!until_close && (long long)take > left) take = (size_t)left;
                if (take) {
                    if (fn) stopped = stopped || fn(in->data, take, user);
                    else nmzp_buf_add(&r->body, in->data, take);
                }
                nmzp_buf_consume(in, take);
                if (!until_close) left -= (long long)take;
            }
        }
        if (stopped) {
            nmzp_buf_free(&dec);
            nmzp_client_close(c); /* the rest of the stream is not wanted */
            return 0;
        }
        if (!chunked && !until_close && left <= 0) break;
        {
            long k = nmzp_recv(c->sock, tmp, sizeof tmp, fn ? -1 : c->timeout_ms);
            if (k == 0 && until_close) break;
            if (k == -2) {
                nmzp_buf_free(&dec);
                return cfail(c, "the server stopped sending");
            }
            if (k <= 0) {
                nmzp_buf_free(&dec);
                return cfail(c, "the connection closed in the middle of a response");
            }
            if (nmzp_buf_add(in, tmp, (size_t)k)) {
                nmzp_buf_free(&dec);
                return cfail(c, "out of memory");
            }
        }
    }
    nmzp_buf_free(&dec);
    if (r->body.oom) return cfail(c, "out of memory");
    if (until_close || !r->head.keep_alive || in->len) nmzp_client_close(c);
    return 0;
}

static int exchange(nmzp_client *c, const char *method, const char *path, const char *ctype, const void *body, size_t n,
                    const char *extra, nmzp_body_fn fn, void *user, nmzp_response *r) {
    int attempt;
    memset(r, 0, sizeof *r);
    nmzp_buf_init(&r->body);
    c->err[0] = '\0';
    for (attempt = 0; attempt < 2; attempt++) {
        nmzp_buf in;
        size_t got = 0;
        int reused = c->sock != NMZP_NO_SOCKET, rc;
        if (!reused) {
            char err[400];
            c->sock = nmzp_connect(c->host, c->port, c->timeout_ms, err, sizeof err);
            if (c->sock == NMZP_NO_SOCKET) return cfail(c, err);
        }
        if (send_request(c, method, path, ctype, body, n, extra)) {
            nmzp_client_close(c);
            if (reused) continue; /* the server had closed the kept-alive connection */
            return cfail(c, "cannot send the request");
        }
        nmzp_buf_init(&in);
        rc = read_head(c, r, &in, &got);
        if (rc && reused && got == 0) { /* stale connection: once more on a new one */
            nmzp_buf_free(&in);
            continue;
        }
        if (rc) {
            nmzp_buf_free(&in);
            return -1;
        }
        /* error statuses of a stream request: collect the (JSON) body instead */
        rc = read_body(c, r, &in, !strcmp(method, "HEAD"), fn && r->status < 300 ? fn : NULL, user);
        nmzp_buf_free(&in);
        return rc;
    }
    return cfail(c, "the server keeps closing the connection");
}

int nmzp_client_request(nmzp_client *c, const char *method, const char *path, const char *content_type,
                        const void *body, size_t n, const char *extra, nmzp_response *r) {
    return exchange(c, method, path, content_type, body, n, extra, NULL, NULL, r);
}

int nmzp_client_stream(nmzp_client *c, const char *method, const char *path, const char *extra, nmzp_body_fn fn,
                       void *user, nmzp_response *r) {
    return exchange(c, method, path, NULL, NULL, 0, extra, fn, user, r);
}

const char *nmzp_response_error(const nmzp_response *r, char *buf, size_t n) {
    nmzp_json *j = NULL;
    const nmzp_json *e;
    if (!buf || !n) return "";
    snprintf(buf, n, "HTTP %d %s", r->status, nmzp_http_reason(r->status));
    if (r->body.len) j = nmzp_json_parse(r->body.data, r->body.len, 8, NULL, 0);
    e = nmzp_json_get(j, "error");
    if (e && nmzp_json_get_str(e, "message"))
        snprintf(buf, n, "%s: %s", nmzp_json_get_str(e, "code") ? nmzp_json_get_str(e, "code") : "error",
                 nmzp_json_get_str(e, "message"));
    nmzp_json_free(j);
    return buf;
}

int nmzp_parse_hostport(const char *s, char *host, size_t hostn, int *port) {
    const char *p = s, *colon;
    size_t hl;
    if (!s || !*s) return -1;
    if (!strncmp(p, "http://", 7)) p += 7;
    if (!strncmp(p, "https://", 8)) return -1; /* TLS: through a proxy's plain-HTTP side */
    if (*p == '[') { /* [::1]:8470 */
        const char *close = strchr(p, ']');
        if (!close) return -1;
        hl = (size_t)(close - p - 1);
        if (hl + 1 > hostn) return -1;
        memcpy(host, p + 1, hl);
        host[hl] = '\0';
        p = close + 1;
        colon = *p == ':' ? p : NULL;
    } else {
        colon = strrchr(p, ':');
        hl = colon ? (size_t)(colon - p) : strcspn(p, "/");
        if (!hl || hl + 1 > hostn) return -1;
        memcpy(host, p, hl);
        host[hl] = '\0';
    }
    if (colon) {
        long v = 0;
        const char *d = colon + 1;
        if (!*d) return -1;
        for (; *d && *d != '/'; d++) {
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
