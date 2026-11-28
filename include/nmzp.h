/* nmzp.h — the NeuroMZ protocol (PROTOCOL.md) in C11: frames, the
 * payload codec (a MessagePack subset), the handshake and its HMAC-SHA256
 * authentication, a client, sockets, SHA-256 and the protocol's name
 * rules. Used by neuromz-server and by the `neuromz` program's remote mode;
 * no dependencies beyond the C library and the system's sockets (Winsock on
 * Windows). Every function is safe to call from several threads on
 * different objects. JSON (for trace lines and files, not for the wire) is
 * in nmzp_json.h. */
#ifndef NMZP_H
#define NMZP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The protocol this library speaks: protocol 1. Its number is the major of
 * the handshake; it changes only when the bytes on the wire change
 * incompatibly (PROTOCOL §5.4, §16), and this repository's MAJOR with it. */
#define NMZP_PROTOCOL "1.0" /* major.minor, as WELCOME and health say it */
#define NMZP_PROTOCOL_MAJOR 1
#define NMZP_PROTOCOL_MINOR 0
/* This library, the repository's version: "1.0.0-dev" until its first
 * release, 1.0.0 (docs/DESIGN.md P39). */
#define NMZP_VERSION "1.0.0-dev"
#define NMZP_VERSION_MAJOR 1
#define NMZP_VERSION_MINOR 0
#define NMZP_VERSION_PATCH 0
#define NMZP_DEFAULT_PORT 6769 /* N-R-M-Z on a phone keypad (PROTOCOL §2) */

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

/* -------------------------------------------- payload values (PROTOCOL §4) */

typedef enum nmzp_type {
    NMZP_NIL,
    NMZP_BOOL,
    NMZP_INT,
    NMZP_FLOAT,
    NMZP_STR,
    NMZP_BIN,
    NMZP_ARRAY,
    NMZP_MAP
} nmzp_type;

typedef struct nmzp_val nmzp_val;
struct nmzp_val {
    nmzp_type type;
    int b;             /* BOOL                                              */
    long long i;       /* INT                                               */
    double f;          /* FLOAT                                             */
    int f32;           /* FLOAT: it arrived as float 32                     */
    char *s;           /* STR: UTF-8, NUL-terminated; BIN: the bytes        */
    size_t len;        /* STR, BIN: bytes                                   */
    char *key;         /* the member's key, for the values of a MAP         */
    nmzp_val **items;  /* ARRAY elements, MAP values (keys in ->key)        */
    size_t n;
};

#define NMZP_MAX_DEPTH 32
#define NMZP_MAX_VALUES 262144 /* values in one payload (a bin is one) */

/* Decode one payload (§4.2: one map, the subset, UTF-8, depth 32, no
 * duplicate keys, at most 262144 values, no trailing bytes). NULL on
 * error, with a message. */
nmzp_val *nmzp_decode(const void *p, size_t n, char *err, size_t errn);
/* the same for any top-level value (test vectors) */
nmzp_val *nmzp_decode_value(const void *p, size_t n, char *err, size_t errn);
void nmzp_val_free(nmzp_val *v);
const nmzp_val *nmzp_get(const nmzp_val *map, const char *key); /* NULL if absent or not a map */
const nmzp_val *nmzp_at(const nmzp_val *arr, size_t i);
const char *nmzp_str(const nmzp_val *v);                       /* NULL unless a str */
int nmzp_num(const nmzp_val *v, double *out);                  /* int or float: 1 */
int nmzp_int(const nmzp_val *v, long long *out);               /* int, or a whole float: 1 */
int nmzp_bool(const nmzp_val *v, int *out);                    /* 1 = a bool */
const unsigned char *nmzp_bin(const nmzp_val *v, size_t *n);   /* NULL unless a bin */
int nmzp_is_nil(const nmzp_val *v);                            /* absent or nil */
const char *nmzp_get_str(const nmzp_val *map, const char *key);
int nmzp_get_num(const nmzp_val *map, const char *key, double *out);
int nmzp_get_int(const nmzp_val *map, const char *key, long long *out);
int nmzp_get_bool(const nmzp_val *map, const char *key, int *out);
const char *nmzp_type_name(nmzp_type t);

/* Writing (canonical form, §4.3): the writer counts the members of maps and
 * arrays and writes their headers when they end. Keys and values alternate
 * inside maps. */
typedef struct nmzp_mw {
    nmzp_buf *b;
    int depth;
    size_t start[NMZP_MAX_DEPTH + 1];
    unsigned long count[NMZP_MAX_DEPTH + 1];
    unsigned char map[NMZP_MAX_DEPTH + 1], expect_value[NMZP_MAX_DEPTH + 1];
    int bad; /* nested too deep, or a map key that is not a str */
} nmzp_mw;

void nmzp_mw_init(nmzp_mw *w, nmzp_buf *b);
void nmzp_mw_map(nmzp_mw *w);
void nmzp_mw_end_map(nmzp_mw *w);
void nmzp_mw_arr(nmzp_mw *w);
void nmzp_mw_end_arr(nmzp_mw *w);
void nmzp_mw_key(nmzp_mw *w, const char *k);
void nmzp_mw_str(nmzp_mw *w, const char *s); /* NULL: nil */
void nmzp_mw_strn(nmzp_mw *w, const char *s, size_t n);
void nmzp_mw_int(nmzp_mw *w, long long v);
void nmzp_mw_float(nmzp_mw *w, double v); /* float 64; not finite: nil */
void nmzp_mw_float32(nmzp_mw *w, float v); /* float 32 (test vectors; canonical writers use float 64) */
void nmzp_mw_bool(nmzp_mw *w, int v);
void nmzp_mw_nil(nmzp_mw *w);
void nmzp_mw_bin(nmzp_mw *w, const void *p, size_t n);
void nmzp_mw_f32(nmzp_mw *w, const float *v, size_t n); /* a bin of little-endian float32 (§4.4) */
void nmzp_mw_raw(nmzp_mw *w, const void *encoded, size_t n); /* one value, already encoded */
void nmzp_mw_kstr(nmzp_mw *w, const char *k, const char *s);
void nmzp_mw_kint(nmzp_mw *w, const char *k, long long v);
void nmzp_mw_kfloat(nmzp_mw *w, const char *k, double v);
void nmzp_mw_kbool(nmzp_mw *w, const char *k, int v);
void nmzp_mw_knil(nmzp_mw *w, const char *k);
void nmzp_mw_kbin(nmzp_mw *w, const char *k, const void *p, size_t n);
/* the members of an encoded map, added to the map being written */
void nmzp_mw_members(nmzp_mw *w, const void *encoded_map, size_t n);
/* 0 = the payload is complete and well formed */
int nmzp_mw_done(const nmzp_mw *w);
/* a decoded value written again (canonical form) */
void nmzp_mw_val(nmzp_mw *w, const nmzp_val *v);

/* float32 values from a bin (§4.4): n = len / 4 values into out */
void nmzp_f32_read(const void *bin, size_t n_values, float *out);
void nmzp_f32_write(const float *v, size_t n_values, void *out);

/* Valid UTF-8 (no overlong forms, no surrogates, at most U+10FFFF): 1 */
int nmzp_utf8_valid(const char *s, size_t n);

/* ----------------------------------------------------- frames (PROTOCOL §3) */

#define NMZP_FRAME_HEADER 12
#define NMZP_HANDSHAKE_MAX 65536u /* frame payloads before WELCOME */
#define NMZP_MIN_FRAME 65536u     /* the smallest max_frame a peer may announce */
#define NMZP_MORE 0x01

enum {
    NMZP_GREETING = 0x01,
    NMZP_HELLO = 0x02,
    NMZP_WELCOME = 0x03,
    NMZP_REQUEST = 0x10,
    NMZP_RESPONSE = 0x11,
    NMZP_ERROR = 0x12,
    NMZP_DATA = 0x13,
    NMZP_END = 0x14,
    NMZP_EVENT = 0x15,
    NMZP_ABORT = 0x16,
    NMZP_PING = 0x20,
    NMZP_PONG = 0x21
};

typedef struct nmzp_frame_head {
    uint32_t length;
    uint8_t type, flags;
    uint16_t reserved;
    uint32_t id;
} nmzp_frame_head;

void nmzp_head_encode(unsigned char out[NMZP_FRAME_HEADER], int type, int flags, uint32_t id, uint32_t length);
void nmzp_head_decode(const unsigned char in[NMZP_FRAME_HEADER], nmzp_frame_head *h);
/* §3's checks of a header: 0 = fine; else the error code (frame_too_large,
 * unknown_frame, protocol_error for flags or reserved bits) */
int nmzp_head_check(const nmzp_frame_head *h, uint32_t max_payload);
const char *nmzp_frame_name(int type); /* "REQUEST", ...; NULL if unknown */
/* append a whole frame to b: 0 = ok */
int nmzp_frame_put(nmzp_buf *b, int type, int flags, uint32_t id, const void *payload, size_t n);
/* a whole frame to a socket (small frames in one write): 0 = ok (declared
 * here, nmzp_socket below) */
typedef intptr_t nmzp_socket;
int nmzp_frame_send(nmzp_socket s, int type, int flags, uint32_t id, const void *payload, size_t n);
/* The next frame at the start of buf[0..n): 1 = a frame (*h, *payload,
 * *consumed = its whole size), 0 = incomplete, -1 = a bad header (*code). */
int nmzp_frame_next(const void *buf, size_t n, uint32_t max_payload, nmzp_frame_head *h, const unsigned char **payload,
                    size_t *consumed, int *code);

/* ------------------------------------------------- errors (PROTOCOL §11) */

enum {
    NMZP_E_PROTOCOL = 100,
    NMZP_E_BAD_MAGIC = 101,
    NMZP_E_VERSION = 102,
    NMZP_E_FRAME_TOO_LARGE = 103,
    NMZP_E_UNKNOWN_FRAME = 104,
    NMZP_E_TIMEOUT = 105,
    NMZP_E_TOO_MANY_CONNECTIONS = 106,
    NMZP_E_SHUTTING_DOWN = 107,
    NMZP_E_UNAUTHORIZED = 108,
    NMZP_E_BAD_REQUEST = 200,
    NMZP_E_UNKNOWN_OPERATION = 201,
    NMZP_E_INVALID_NAME = 202,
    NMZP_E_INVALID_ARGUMENT = 203,
    NMZP_E_PAYLOAD_TOO_LARGE = 204,
    NMZP_E_INTEGRITY = 205,
    NMZP_E_TOO_MANY_REQUESTS = 206,
    NMZP_E_CANCELLED = 207,
    NMZP_E_FORBIDDEN = 300,
    NMZP_E_SAVE_NOT_ALLOWED = 301,
    NMZP_E_NOT_FOUND = 400,
    NMZP_E_CONFLICT = 401,
    NMZP_E_QUEUE_FULL = 402,
    NMZP_E_QUOTA_EXCEEDED = 403,
    NMZP_E_INTERNAL = 500,
    NMZP_E_UNAVAILABLE = 501,
    NMZP_E_OUT_OF_MEMORY = 502,
    NMZP_E_NUMERIC = 503
};

const char *nmzp_error_name(int code); /* "invalid_argument"; NULL if unknown */
int nmzp_error_code(const char *name); /* 0 if unknown */
/* an ERROR frame's payload: {"code", "name", "message"} (details: NULL, or an encoded map) */
int nmzp_error_payload(nmzp_buf *b, int code, const char *message, const void *details, size_t details_n);

/* ---------------------------------------------- handshake (PROTOCOL §5, §6) */

extern const unsigned char NMZP_MAGIC[8]; /* 4e 4d 5a 50 0d 0a 1a 0a */
#define NMZP_PREFIX 12                    /* magic, u16 major, u16 minor */

void nmzp_prefix_put(unsigned char out[NMZP_PREFIX], int major, int minor);
/* 0 = the magic and a version (*major, *minor); -1 = too short or not the magic */
int nmzp_prefix_get(const void *p, size_t n, int *major, int *minor);

/* HMAC-SHA256 (RFC 2104) */
typedef struct nmzp_sha256 {
    uint32_t h[8];
    uint64_t bytes;
    unsigned char block[64];
    size_t used;
} nmzp_sha256;

typedef struct nmzp_hmac {
    nmzp_sha256 inner, outer;
} nmzp_hmac;

void nmzp_hmac_init(nmzp_hmac *h, const void *key, size_t kn);
void nmzp_hmac_update(nmzp_hmac *h, const void *p, size_t n);
void nmzp_hmac_final(nmzp_hmac *h, unsigned char out[32]);
void nmzp_hmac_sha256(const void *key, size_t kn, const void *msg, size_t n, unsigned char out[32]);

/* §6.1: K = SHA-256(token); key_id; the proofs (server = 1: proof_s) */
void nmzp_auth_key(const char *token, size_t n, unsigned char key[32]);
void nmzp_auth_key_id(const unsigned char key[32], unsigned char id[8]);
void nmzp_auth_proof(const unsigned char key[32], int server, const unsigned char ns[32], const unsigned char nc[32],
                     unsigned char out[32]);

/* ------------------------------------------------------------ sockets */

/* nmzp_socket: an intptr_t (declared with the frames above) */
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
 * may lose the last frame) */
void nmzp_close_graceful(nmzp_socket s, int ms);
/* stop both directions now: a thread blocked in nmzp_recv on s returns */
void nmzp_shutdown(nmzp_socket s);
const char *nmzp_sock_error(char *buf, size_t n); /* the last socket error, as text */

/* ------------------------------------------------------------ client */

/* The outcome of a call: the server's ERROR (code > 0), or a broken
 * connection (code -1, the message says why). */
typedef struct nmzp_error {
    int code;
    char name[40];
    char message[1024];
} nmzp_error;

typedef struct nmzp_frame {
    nmzp_frame_head h;
    nmzp_buf payload;
} nmzp_frame;

typedef struct nmzp_client {
    /* set before connecting (nmzp_client_init sets defaults) */
    char host[256];
    int port;
    char token[512];   /* "" = no token */
    char name[64];     /* the client program, for the server's log */
    char version[32];
    int timeout_ms;    /* connect, the handshake, and each wait for a frame (default 30000) */
    int allow_no_auth; /* accept a server without authentication though a token is set */
    int max_frame_in;  /* announced in HELLO (0: the server's) */
    /* from the handshake */
    int connected, major, minor;
    char server[64], server_version[32], user[64], session[32];
    char permissions[64];   /* "read,train" */
    char capabilities[256]; /* "events,generate,..." */
    uint32_t max_frame;     /* the limit for what we send */
    uint32_t max_frame_out; /* the limit the server keeps to */
    uint32_t max_inflight, idle_timeout;
    int server_auth; /* 1 = hmac-sha256, 0 = none */
    /* state */
    nmzp_socket sock;
    uint32_t next_id;
    nmzp_buf rx;
    char err[600]; /* why the last call failed (also in its nmzp_error) */
} nmzp_client;

void nmzp_client_init(nmzp_client *c, const char *host, int port, const char *token);
/* connect and do the handshake: 0 = ok; -1 = failed (c->err; e, if given, gets the server's ERROR) */
int nmzp_client_connect(nmzp_client *c, nmzp_error *e);
void nmzp_client_close(nmzp_client *c);
uint32_t nmzp_client_id(nmzp_client *c); /* a new request id */
/* one frame out: 0 = ok */
int nmzp_client_send(nmzp_client *c, int type, int flags, uint32_t id, const void *p, size_t n);
/* the next frame in (PING is answered here and not returned): 1 = a frame,
 * 0 = nothing within timeout_ms, -1 = the connection failed (c->err).
 * Free f with nmzp_frame_free. */
int nmzp_client_recv(nmzp_client *c, nmzp_frame *f, int timeout_ms);
void nmzp_frame_init(nmzp_frame *f);
void nmzp_frame_free(nmzp_frame *f);

/* Calls. req is an encoded request map (with "op"). They return 0 = the
 * answer arrived (*out: the RESPONSE map, free with nmzp_val_free), 1 = the
 * server answered with ERROR (*e), -1 = the connection failed (*e: code -1,
 * c->err); a connection that failed is closed, and the next call
 * reconnects. Frames of other requests that arrive meanwhile are dropped. */
int nmzp_call(nmzp_client *c, const nmzp_buf *req, nmzp_val **out, nmzp_error *e);
/* an upload (§8.1): req gets "size"; the bytes come from read(user, buf,
 * max) (> 0 bytes, 0 at the end, < 0 to give up) */
typedef long (*nmzp_read_fn)(void *user, void *buf, size_t max);
int nmzp_call_upload(nmzp_client *c, const nmzp_buf *req, uint64_t size, nmzp_read_fn read, void *user, nmzp_val **out,
                     nmzp_error *e);
int nmzp_call_upload_mem(nmzp_client *c, const nmzp_buf *req, const void *data, size_t n, nmzp_val **out, nmzp_error *e);
/* a download (§8.2): *head = the RESPONSE map; the bytes to write(user, p, n)
 * (non-zero: stop, ABORT); the size and SHA-256 are checked (integrity_error) */
typedef int (*nmzp_write_fn)(void *user, const void *p, size_t n);
int nmzp_call_download(nmzp_client *c, const nmzp_buf *req, nmzp_val **head, nmzp_write_fn write, void *user,
                       nmzp_error *e);
int nmzp_write_to_buf(void *user, const void *p, size_t n); /* user = an nmzp_buf */
/* a subscription (§9): *head = the RESPONSE map; each event to fn (non-zero:
 * unsubscribe, ABORT); 0 when the subscription ended with its last event
 * (or after fn stopped it) */
typedef int (*nmzp_event_fn)(void *user, const char *event, long long seq, const nmzp_val *data);
int nmzp_call_events(nmzp_client *c, const nmzp_buf *req, nmzp_val **head, nmzp_event_fn fn, void *user,
                     nmzp_error *e);

/* "host", "host:port", "[v6]:port" -> host and port (default if absent); 0 = ok */
int nmzp_parse_hostport(const char *s, char *host, size_t hostn, int *port);

/* ------------------------------------------------------------ SHA-256 */

void nmzp_sha256_init(nmzp_sha256 *s);
void nmzp_sha256_update(nmzp_sha256 *s, const void *p, size_t n);
void nmzp_sha256_final(nmzp_sha256 *s, unsigned char out[32]);
void nmzp_sha256_of(const void *p, size_t n, unsigned char out[32]);
void nmzp_sha256_hex(const void *p, size_t n, char out[65]);
void nmzp_hex(const unsigned char *p, size_t n, char *out); /* 2n+1 bytes */
/* compare without an early exit: 1 = equal */
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
