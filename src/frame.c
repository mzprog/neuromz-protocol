/* frame.c — frames (PROTOCOL §3), the error codes (§11) and the fixed
 * start of the handshake frames (§5). A header is checked before its
 * payload is read, so a frame over the limit costs nothing. */
#include "nmzp.h"

#include <stdio.h>
#include <string.h>

const unsigned char NMZP_MAGIC[8] = {0x4e, 0x4d, 0x5a, 0x50, 0x0d, 0x0a, 0x1a, 0x0a};

static void le32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void nmzp_head_encode(unsigned char out[NMZP_FRAME_HEADER], int type, int flags, uint32_t id, uint32_t length) {
    le32(out, length);
    out[4] = (unsigned char)type;
    out[5] = (unsigned char)flags;
    out[6] = out[7] = 0;
    le32(out + 8, id);
}

void nmzp_head_decode(const unsigned char in[NMZP_FRAME_HEADER], nmzp_frame_head *h) {
    h->length = rd32(in);
    h->type = in[4];
    h->flags = in[5];
    h->reserved = (uint16_t)(in[6] | in[7] << 8);
    h->id = rd32(in + 8);
}

const char *nmzp_frame_name(int type) {
    switch (type) {
    case NMZP_GREETING: return "GREETING";
    case NMZP_HELLO: return "HELLO";
    case NMZP_WELCOME: return "WELCOME";
    case NMZP_REQUEST: return "REQUEST";
    case NMZP_RESPONSE: return "RESPONSE";
    case NMZP_ERROR: return "ERROR";
    case NMZP_DATA: return "DATA";
    case NMZP_END: return "END";
    case NMZP_EVENT: return "EVENT";
    case NMZP_ABORT: return "ABORT";
    case NMZP_PING: return "PING";
    case NMZP_PONG: return "PONG";
    default: return NULL;
    }
}

int nmzp_head_check(const nmzp_frame_head *h, uint32_t max_payload) {
    if (h->length > max_payload) return NMZP_E_FRAME_TOO_LARGE;
    if (!nmzp_frame_name(h->type)) return NMZP_E_UNKNOWN_FRAME;
    if (h->flags & ~NMZP_MORE || h->reserved) return NMZP_E_PROTOCOL;
    return 0;
}

int nmzp_frame_put(nmzp_buf *b, int type, int flags, uint32_t id, const void *payload, size_t n) {
    unsigned char h[NMZP_FRAME_HEADER];
    if (n > 0xffffffffu) return -1;
    nmzp_head_encode(h, type, flags, id, (uint32_t)n);
    if (nmzp_buf_add(b, h, sizeof h)) return -1;
    return n ? nmzp_buf_add(b, payload, n) : 0;
}

int nmzp_frame_next(const void *buf, size_t n, uint32_t max_payload, nmzp_frame_head *h, const unsigned char **payload,
                    size_t *consumed, int *code) {
    const unsigned char *p = (const unsigned char *)buf;
    int c;
    if (n < NMZP_FRAME_HEADER) return 0;
    nmzp_head_decode(p, h);
    if ((c = nmzp_head_check(h, max_payload)) != 0) {
        if (code) *code = c;
        return -1;
    }
    if (n - NMZP_FRAME_HEADER < h->length) return 0;
    *payload = p + NMZP_FRAME_HEADER;
    *consumed = NMZP_FRAME_HEADER + (size_t)h->length;
    return 1;
}

/* ------------------------------------------------------------- errors */

static const struct {
    int code;
    const char *name;
} k_errors[] = {{NMZP_E_PROTOCOL, "protocol_error"},
                {NMZP_E_BAD_MAGIC, "bad_magic"},
                {NMZP_E_VERSION, "unsupported_version"},
                {NMZP_E_FRAME_TOO_LARGE, "frame_too_large"},
                {NMZP_E_UNKNOWN_FRAME, "unknown_frame"},
                {NMZP_E_TIMEOUT, "timeout"},
                {NMZP_E_TOO_MANY_CONNECTIONS, "too_many_connections"},
                {NMZP_E_SHUTTING_DOWN, "shutting_down"},
                {NMZP_E_UNAUTHORIZED, "unauthorized"},
                {NMZP_E_BAD_REQUEST, "bad_request"},
                {NMZP_E_UNKNOWN_OPERATION, "unknown_operation"},
                {NMZP_E_INVALID_NAME, "invalid_name"},
                {NMZP_E_INVALID_ARGUMENT, "invalid_argument"},
                {NMZP_E_PAYLOAD_TOO_LARGE, "payload_too_large"},
                {NMZP_E_INTEGRITY, "integrity_error"},
                {NMZP_E_TOO_MANY_REQUESTS, "too_many_requests"},
                {NMZP_E_CANCELLED, "cancelled"},
                {NMZP_E_FORBIDDEN, "forbidden"},
                {NMZP_E_SAVE_NOT_ALLOWED, "save_not_allowed"},
                {NMZP_E_NOT_FOUND, "not_found"},
                {NMZP_E_CONFLICT, "conflict"},
                {NMZP_E_QUEUE_FULL, "queue_full"},
                {NMZP_E_QUOTA_EXCEEDED, "quota_exceeded"},
                {NMZP_E_INTERNAL, "internal"},
                {NMZP_E_UNAVAILABLE, "unavailable"},
                {NMZP_E_OUT_OF_MEMORY, "out_of_memory"},
                {NMZP_E_NUMERIC, "numeric"},
                {0, NULL}};

const char *nmzp_error_name(int code) {
    int i;
    for (i = 0; k_errors[i].name; i++)
        if (k_errors[i].code == code) return k_errors[i].name;
    return NULL;
}

int nmzp_error_code(const char *name) {
    int i;
    if (!name) return 0;
    for (i = 0; k_errors[i].name; i++)
        if (!strcmp(k_errors[i].name, name)) return k_errors[i].code;
    return 0;
}

int nmzp_error_payload(nmzp_buf *b, int code, const char *message, const void *details, size_t details_n) {
    nmzp_mw w;
    const char *name = nmzp_error_name(code);
    nmzp_mw_init(&w, b);
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "code", code);
    nmzp_mw_kstr(&w, "name", name ? name : "internal");
    /* a message is UTF-8: a library message that is not becomes a plain note */
    nmzp_mw_kstr(&w, "message", message && nmzp_utf8_valid(message, strlen(message)) ? message : "(a message that is not UTF-8)");
    if (details && details_n) {
        nmzp_mw_key(&w, "details");
        nmzp_mw_raw(&w, details, details_n);
    }
    nmzp_mw_end_map(&w);
    return nmzp_mw_done(&w);
}

/* ------------------------------------------------------ the handshake */

void nmzp_prefix_put(unsigned char out[NMZP_PREFIX], int major, int minor) {
    memcpy(out, NMZP_MAGIC, 8);
    out[8] = (unsigned char)major;
    out[9] = (unsigned char)(major >> 8);
    out[10] = (unsigned char)minor;
    out[11] = (unsigned char)(minor >> 8);
}

int nmzp_prefix_get(const void *p, size_t n, int *major, int *minor) {
    const unsigned char *b = (const unsigned char *)p;
    if (n < NMZP_PREFIX || memcmp(b, NMZP_MAGIC, 8)) return -1;
    if (major) *major = b[8] | b[9] << 8;
    if (minor) *minor = b[10] | b[11] << 8;
    return 0;
}
