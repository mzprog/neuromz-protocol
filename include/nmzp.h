/* nmzp.h — the NeuroMZ protocol's wire format in C11 (PROTOCOL.md):
 * JSON, HTTP/1.1 messages, Server-Sent Events, sockets, a small HTTP
 * client, SHA-256 and the protocol's name rules. Used by neuromz-server and
 * by the `neuromz` program's remote mode; no dependencies beyond the C
 * library and the system's sockets (Winsock on Windows). Every function is
 * safe to call from several threads on different objects. */
#ifndef NMZP_H
#define NMZP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NMZP_PROTOCOL "1.0.0" /* the protocol version this library speaks */
#define NMZP_VERSION_MAJOR 1
#define NMZP_VERSION_MINOR 0
#define NMZP_VERSION_PATCH 0
#define NMZP_DEFAULT_PORT 8470

/* ------------------------------------------------------------ buffers */

/* A growing byte buffer, always NUL-terminated (data[len] == 0). After an
 * allocation failure `oom` is set and further appends do nothing. */
typedef struct nmzp_buf {
    char *data;
    size_t len, cap;
    int oom;
} nmzp_buf;

void nmzp_buf_init(nmzp_buf *b);
void nmzp_buf_free(nmzp_buf *b);
void nmzp_buf_clear(nmzp_buf *b);
int nmzp_buf_add(nmzp_buf *b, const void *p, size_t n); /* 0 ok, -1 out of memory */
int nmzp_buf_str(nmzp_buf *b, const char *s);
int nmzp_buf_printf(nmzp_buf *b, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
/* drop the first n bytes */
void nmzp_buf_consume(nmzp_buf *b, size_t n);

/* --------------------------------------------------------------- JSON */

typedef enum nmzp_json_type {
    NMZP_JSON_NULL,
    NMZP_JSON_FALSE,
    NMZP_JSON_TRUE,
    NMZP_JSON_NUMBER,
    NMZP_JSON_STRING,
    NMZP_JSON_ARRAY,
    NMZP_JSON_OBJECT
} nmzp_json_type;

typedef struct nmzp_json nmzp_json;
struct nmzp_json {
    nmzp_json_type type;
    double number;    /* NUMBER                                     */
    char *string;     /* STRING: UTF-8, NUL-terminated              */
    size_t len;       /* STRING: bytes (a "\u0000" counts)          */
    char *key;        /* the member name, for members of an object  */
    nmzp_json **items; /* ARRAY elements, OBJECT members            */
    size_t n;
};

/* Parse JSON text (RFC 8259, UTF-8; strings must be valid UTF-8). At most
 * max_depth nested arrays/objects (0 = 64). NULL on error, with a message
 * (and the byte offset) in err. */
nmzp_json *nmzp_json_parse(const char *text, size_t n, int max_depth, char *err, size_t errn);
void nmzp_json_free(nmzp_json *j);
const nmzp_json *nmzp_json_get(const nmzp_json *obj, const char *key); /* the first member named key */
const nmzp_json *nmzp_json_at(const nmzp_json *arr, size_t i);
const char *nmzp_json_str(const nmzp_json *j); /* the string, or NULL if j is not one */
int nmzp_json_num(const nmzp_json *j, double *out);
int nmzp_json_bool(const nmzp_json *j, int *out);
const char *nmzp_json_get_str(const nmzp_json *obj, const char *key);
int nmzp_json_get_num(const nmzp_json *obj, const char *key, double *out); /* 1 = present and a number */
int nmzp_json_get_bool(const nmzp_json *obj, const char *key, int *out);

/* Writing: append values to a buffer; the writer places the commas. */
typedef struct nmzp_jw {
    nmzp_buf *b;
    int depth;
    unsigned char fresh[64]; /* no element written yet at this depth */
    int after_key;
} nmzp_jw;

void nmzp_jw_init(nmzp_jw *w, nmzp_buf *b);
void nmzp_jw_obj(nmzp_jw *w);
void nmzp_jw_end_obj(nmzp_jw *w);
void nmzp_jw_arr(nmzp_jw *w);
void nmzp_jw_end_arr(nmzp_jw *w);
void nmzp_jw_key(nmzp_jw *w, const char *k);
void nmzp_jw_str(nmzp_jw *w, const char *s); /* NULL: null */
void nmzp_jw_strn(nmzp_jw *w, const char *s, size_t n);
void nmzp_jw_num(nmzp_jw *w, double v); /* not finite: null */
void nmzp_jw_int(nmzp_jw *w, long long v);
void nmzp_jw_bool(nmzp_jw *w, int v);
void nmzp_jw_null(nmzp_jw *w);
void nmzp_jw_raw(nmzp_jw *w, const char *json); /* an already encoded value */
void nmzp_jw_kstr(nmzp_jw *w, const char *k, const char *s);
void nmzp_jw_knum(nmzp_jw *w, const char *k, double v);
void nmzp_jw_kint(nmzp_jw *w, const char *k, long long v);
void nmzp_jw_kbool(nmzp_jw *w, const char *k, int v);
void nmzp_jw_knull(nmzp_jw *w, const char *k);
/* s[0..n) as a JSON string literal, quotes included */
void nmzp_json_escape(nmzp_buf *b, const char *s, size_t n);

/* ---------------------------------------------------- HTTP/1.1 messages */

#define NMZP_MAX_HEADERS 64
#define NMZP_MAX_HEAD 16384 /* bytes of a request or response head */

typedef struct nmzp_header {
    const char *name, *value;
} nmzp_header;

typedef struct nmzp_http_head {
    /* request */
    char method[16];
    const char *target; /* as sent: path?query */
    const char *path;   /* the path, percent-decoded */
    const char *query;  /* the raw query after '?', or "" */
    /* response */
    int status;
    const char *reason;
    /* both */
    int minor; /* HTTP/1.minor */
    nmzp_header headers[NMZP_MAX_HEADERS];
    int n_headers;
    long long content_length; /* -1: none */
    int chunked;
    int keep_alive;
    char *storage; /* owns every string above */
} nmzp_http_head;

/* Bytes of the head at the start of buf (through the blank line), 0 if it
 * is not complete yet. */
size_t nmzp_http_head_end(const char *buf, size_t n);
/* Parse the head buf[0..n) (from nmzp_http_head_end). 0 = ok; otherwise
 * the HTTP status to answer with (400, 431, 505, ...) and a message. */
int nmzp_http_parse_request(const char *buf, size_t n, nmzp_http_head *h, char *err, size_t errn);
int nmzp_http_parse_response(const char *buf, size_t n, nmzp_http_head *h, char *err, size_t errn);
void nmzp_http_head_free(nmzp_http_head *h);
const char *nmzp_http_header(const nmzp_http_head *h, const char *name); /* case-insensitive; NULL if absent */
const char *nmzp_http_reason(int status);

/* Chunked transfer coding, decoded incrementally. */
typedef struct nmzp_chunked {
    int state;
    unsigned long long left; /* bytes left in the current chunk */
    unsigned line;           /* bytes of the current size or trailer line */
    int done;
} nmzp_chunked;

void nmzp_chunked_init(nmzp_chunked *c);
/* Decode in[0..n), appending data to out (at most max_total bytes in out).
 * Returns the bytes consumed (stops after the last chunk: c->done), -1 on a
 * malformed stream, -2 when max_total would be exceeded. */
long nmzp_chunked_feed(nmzp_chunked *c, const char *in, size_t n, nmzp_buf *out, size_t max_total);

/* A query parameter, percent-decoded into out: 1 = found. */
int nmzp_query_get(const char *query, const char *key, char *out, size_t n);
/* Percent-decode (and '+' as space when form != 0); -1 on bad escapes, a NUL, or overflow. */
int nmzp_url_decode(const char *in, size_t n, char *out, size_t outn, int form);
/* Percent-encode a path segment. */
void nmzp_url_encode(nmzp_buf *b, const char *s);

/* ------------------------------------------------ Server-Sent Events */

typedef int (*nmzp_sse_fn)(const char *event, const char *id, const char *data, void *user); /* non-zero: stop */

typedef struct nmzp_sse {
    nmzp_buf line, data;
    char event[64], id[64];
    int skip_lf; /* a CR ended the last line */
    nmzp_sse_fn fn;
    void *user;
} nmzp_sse;

void nmzp_sse_init(nmzp_sse *s, nmzp_sse_fn fn, void *user);
/* 0 = ok, 1 = the callback asked to stop, -1 = out of memory */
int nmzp_sse_feed(nmzp_sse *s, const char *p, size_t n);
void nmzp_sse_free(nmzp_sse *s);
/* Append one event (data may span lines; event and id may be NULL). */
void nmzp_sse_write(nmzp_buf *b, const char *event, const char *id, const char *data);

/* ------------------------------------------------------------ sockets */

typedef intptr_t nmzp_socket;
#define NMZP_NO_SOCKET ((nmzp_socket)-1)

int nmzp_net_init(void); /* once per process (Winsock); 0 = ok */
nmzp_socket nmzp_connect(const char *host, int port, int timeout_ms, char *err, size_t errn);
/* Listen on bind:port (port 0 = any free port, *bound tells which). */
nmzp_socket nmzp_listen(const char *bind, int port, int backlog, int *bound, char *err, size_t errn);
/* Wait up to timeout_ms for a connection: the socket, or NMZP_NO_SOCKET
 * (*timed_out = 1 when nothing came). peer: "address:port". */
nmzp_socket nmzp_accept(nmzp_socket s, int timeout_ms, int *timed_out, char *peer, size_t peern);
int nmzp_send_all(nmzp_socket s, const void *p, size_t n); /* 0 = ok */
/* > 0 bytes, 0 = closed by the peer, -1 = error, -2 = nothing within timeout_ms */
long nmzp_recv(nmzp_socket s, void *p, size_t n, int timeout_ms);
void nmzp_close(nmzp_socket s);
/* close after the peer has read what was sent: stop sending, discard what
 * the peer still sends (at most ms milliseconds), then close (a plain close
 * with unread input makes the system reset the connection, and the peer
 * may lose the answer) */
void nmzp_close_graceful(nmzp_socket s, int ms);
const char *nmzp_sock_error(char *buf, size_t n); /* the last socket error, as text */

/* ------------------------------------------------------------ client */

typedef struct nmzp_response {
    int status;
    nmzp_http_head head;
    nmzp_buf body;
} nmzp_response;

typedef struct nmzp_client {
    char host[256];
    int port;
    char token[512];      /* "" = no Authorization header */
    char user_agent[64];
    int timeout_ms;       /* connect and each read (default 30000) */
    nmzp_socket sock;     /* kept alive between requests */
    char err[512];        /* why the last call failed (transport errors) */
} nmzp_client;

void nmzp_client_init(nmzp_client *c, const char *host, int port, const char *token);
/* One request. extra: more header lines ("Name: value\r\n...") or NULL.
 * 0 = a response arrived (any status, in r); -1 = transport error (c->err).
 * Free r with nmzp_response_free. */
int nmzp_client_request(nmzp_client *c, const char *method, const char *path, const char *content_type,
                        const void *body, size_t n, const char *extra, nmzp_response *r);
/* A request whose response body is handed to fn as it arrives (an event
 * stream); r gets the status and head (and, for an error status, the
 * body). 0 = done (or fn stopped it), -1 = transport error. */
typedef int (*nmzp_body_fn)(const char *p, size_t n, void *user);
int nmzp_client_stream(nmzp_client *c, const char *method, const char *path, const char *extra, nmzp_body_fn fn,
                       void *user, nmzp_response *r);
void nmzp_client_close(nmzp_client *c);
void nmzp_response_free(nmzp_response *r);
/* "code: message" of an error response (the protocol's error body), or the reason phrase */
const char *nmzp_response_error(const nmzp_response *r, char *buf, size_t n);
/* "host", "host:port", "http://host:port" -> host and port (default if absent); 0 = ok */
int nmzp_parse_hostport(const char *s, char *host, size_t hostn, int *port);

/* ------------------------------------------------------------ SHA-256 */

typedef struct nmzp_sha256 {
    uint32_t h[8];
    uint64_t bytes;
    unsigned char block[64];
    size_t used;
} nmzp_sha256;

void nmzp_sha256_init(nmzp_sha256 *s);
void nmzp_sha256_update(nmzp_sha256 *s, const void *p, size_t n);
void nmzp_sha256_final(nmzp_sha256 *s, unsigned char out[32]);
void nmzp_sha256_hex(const void *p, size_t n, char out[65]);
void nmzp_hex(const unsigned char *p, size_t n, char *out); /* 2n+1 bytes */
/* compare without an early exit (tokens): 1 = equal */
int nmzp_ct_equal(const void *a, const void *b, size_t n);
/* n random bytes from the operating system: 0 = ok */
int nmzp_random(void *p, size_t n);

/* ----------------------------------------------------- names and time */

/* A model or dataset name by PROTOCOL.md §1: 1 = valid. */
int nmzp_name_valid(const char *name);
void nmzp_time_rfc3339(long long unix_seconds, char out[32]);
long long nmzp_now(void); /* seconds since 1970 (UTC) */
double nmzp_clock(void);  /* seconds, monotonic */
void nmzp_sleep_ms(int ms);

#ifdef __cplusplus
}
#endif

#endif /* NMZP_H */
