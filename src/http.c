/* http.c — HTTP/1.1 message heads (RFC 9110/9112), chunked bodies, query
 * strings. Strict where leniency would be a risk: a request with both
 * Content-Length and Transfer-Encoding, or two different lengths, is
 * refused (request smuggling); folded header lines are refused; a head is
 * at most NMZP_MAX_HEAD bytes and NMZP_MAX_HEADERS lines. */
#include "nmzp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int ieq(const char *a, const char *b) {
    while (*a && *b && lower((unsigned char)*a) == lower((unsigned char)*b)) a++, b++;
    return *a == '\0' && *b == '\0';
}

static int is_tchar(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

size_t nmzp_http_head_end(const char *buf, size_t n) {
    size_t i;
    for (i = 3; i < n; i++)
        if (buf[i] == '\n' && buf[i - 1] == '\r' && buf[i - 2] == '\n' && buf[i - 3] == '\r') return i + 1;
    return 0;
}

void nmzp_http_head_free(nmzp_http_head *h) {
    if (!h) return;
    free(h->storage);
    memset(h, 0, sizeof *h);
}

static int seterr(char *err, size_t errn, int status, const char *msg) {
    if (err && errn) snprintf(err, errn, "%s", msg);
    return status;
}

const char *nmzp_http_header(const nmzp_http_head *h, const char *name) {
    int i;
    for (i = 0; h && i < h->n_headers; i++)
        if (ieq(h->headers[i].name, name)) return h->headers[i].value;
    return NULL;
}

/* "1.1" after "HTTP/" -> minor version, -1 if not HTTP/1.x */
static int version(const char *v) {
    if (strncmp(v, "HTTP/1.", 7) || v[7] < '0' || v[7] > '9' || v[8]) return -1;
    return v[7] - '0';
}

/* the header lines from s (a copy, NUL-terminated lines), shared by
 * requests and responses; 0 = ok, else a status */
static int parse_headers(char *s, nmzp_http_head *h, int request, char *err, size_t errn) {
    char *line = s;
    int te_seen = 0;
    h->content_length = -1;
    while (*line) {
        char *eol = strstr(line, "\r\n"), *colon, *v, *e;
        if (!eol) return seterr(err, errn, 400, "a header line does not end in CRLF");
        *eol = '\0';
        if (!*line) break; /* the blank line */
        if (*line == ' ' || *line == '\t') return seterr(err, errn, 400, "folded header lines are not allowed");
        if (h->n_headers >= NMZP_MAX_HEADERS) return seterr(err, errn, 431, "too many header lines");
        colon = strchr(line, ':');
        if (!colon || colon == line) return seterr(err, errn, 400, "a header line without a name");
        for (e = line; e < colon; e++)
            if (!is_tchar((unsigned char)*e)) return seterr(err, errn, 400, "a bad character in a header name");
        *colon = '\0';
        v = colon + 1;
        while (*v == ' ' || *v == '\t') v++;
        e = v + strlen(v);
        while (e > v && (e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
        for (e = v; *e; e++)
            if ((unsigned char)*e < 0x20 && *e != '\t') return seterr(err, errn, 400, "a control character in a header");
        h->headers[h->n_headers].name = line;
        h->headers[h->n_headers].value = v;
        h->n_headers++;
        if (ieq(line, "Content-Length")) {
            long long n = 0;
            const char *d = v;
            if (!*d) return seterr(err, errn, 400, "an empty Content-Length");
            for (; *d; d++) {
                if (*d < '0' || *d > '9') return seterr(err, errn, 400, "a bad Content-Length");
                if (n > (long long)1 << 50) return seterr(err, errn, 413, "Content-Length too large");
                n = n * 10 + (*d - '0');
            }
            if (h->content_length >= 0 && h->content_length != n)
                return seterr(err, errn, 400, "two different Content-Length values");
            h->content_length = n;
        } else if (ieq(line, "Transfer-Encoding")) {
            if (te_seen || !ieq(v, "chunked"))
                return seterr(err, errn, request ? 501 : 400, "only Transfer-Encoding: chunked is supported");
            te_seen = 1;
            h->chunked = 1;
        }
        line = eol + 2;
    }
    if (h->chunked && h->content_length >= 0)
        return seterr(err, errn, 400, "both Content-Length and Transfer-Encoding");
    {
        const char *c = nmzp_http_header(h, "Connection");
        h->keep_alive = h->minor >= 1;
        if (c && ieq(c, "close")) h->keep_alive = 0;
        if (c && ieq(c, "keep-alive")) h->keep_alive = 1;
    }
    return 0;
}

int nmzp_http_parse_request(const char *buf, size_t n, nmzp_http_head *h, char *err, size_t errn) {
    char *s, *sp1, *sp2, *eol, *q;
    size_t plen;
    int st;
    memset(h, 0, sizeof *h);
    if (err && errn) err[0] = '\0';
    if (n > NMZP_MAX_HEAD) return seterr(err, errn, 431, "the request head is too large");
    if (n < 4 || nmzp_http_head_end(buf, n) != n) return seterr(err, errn, 400, "an incomplete request head");
    if (memchr(buf, '\0', n)) return seterr(err, errn, 400, "a NUL byte in the request head");
    /* the copy holds the strings; room for the decoded path after it */
    if (!(s = malloc(2 * n + 2))) return seterr(err, errn, 500, "out of memory");
    memcpy(s, buf, n);
    s[n] = '\0';
    h->storage = s;
    eol = strstr(s, "\r\n");
    if (!eol) return seterr(err, errn, 400, "no request line");
    *eol = '\0';
    sp1 = strchr(s, ' ');
    sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!sp1 || !sp2 || strchr(sp2 + 1, ' ')) return seterr(err, errn, 400, "a malformed request line");
    *sp1 = *sp2 = '\0';
    if ((size_t)(sp1 - s) >= sizeof h->method || sp1 == s) return seterr(err, errn, 400, "a bad method");
    for (q = s; *q; q++)
        if (!is_tchar((unsigned char)*q)) return seterr(err, errn, 400, "a bad method");
    memcpy(h->method, s, (size_t)(sp1 - s) + 1);
    h->target = sp1 + 1;
    if (h->target[0] != '/') return seterr(err, errn, 400, "the request target must start with '/'");
    if (strlen(h->target) > 4096) return seterr(err, errn, 414, "the request target is too long");
    for (q = sp1 + 1; *q; q++)
        if ((unsigned char)*q <= 0x20 || (unsigned char)*q >= 0x7F) return seterr(err, errn, 400, "a bad character in the target");
    if ((h->minor = version(sp2 + 1)) < 0)
        return seterr(err, errn, strncmp(sp2 + 1, "HTTP/", 5) ? 400 : 505, "only HTTP/1.0 and HTTP/1.1 are supported");
    if ((st = parse_headers(eol + 2, h, 1, err, errn)) != 0) return st;
    if (h->minor >= 1 && !nmzp_http_header(h, "Host")) return seterr(err, errn, 400, "HTTP/1.1 requires a Host header");
    /* path (decoded) and query (raw) */
    q = strchr(h->target, '?');
    plen = q ? (size_t)(q - h->target) : strlen(h->target);
    h->query = q ? q + 1 : "";
    {
        char *path = s + n + 1;
        if (nmzp_url_decode(h->target, plen, path, n + 1, 0) < 0)
            return seterr(err, errn, 400, "a bad percent escape in the path");
        h->path = path;
    }
    return 0;
}

int nmzp_http_parse_response(const char *buf, size_t n, nmzp_http_head *h, char *err, size_t errn) {
    char *s, *eol, *sp1;
    int st, code = 0, i;
    memset(h, 0, sizeof *h);
    if (err && errn) err[0] = '\0';
    if (n > NMZP_MAX_HEAD) return seterr(err, errn, 431, "the response head is too large");
    if (n < 4 || nmzp_http_head_end(buf, n) != n) return seterr(err, errn, 400, "an incomplete response head");
    if (!(s = malloc(n + 1))) return seterr(err, errn, 500, "out of memory");
    memcpy(s, buf, n);
    s[n] = '\0';
    h->storage = s;
    eol = strstr(s, "\r\n");
    if (!eol) return seterr(err, errn, 400, "no status line");
    *eol = '\0';
    sp1 = strchr(s, ' ');
    if (!sp1) return seterr(err, errn, 400, "a malformed status line");
    *sp1 = '\0';
    if ((h->minor = version(s)) < 0) return seterr(err, errn, 505, "not an HTTP/1.x response");
    for (i = 1; i <= 3; i++) {
        if (sp1[i] < '0' || sp1[i] > '9') return seterr(err, errn, 400, "a bad status code");
        code = code * 10 + (sp1[i] - '0');
    }
    if (sp1[4] != ' ' && sp1[4] != '\0') return seterr(err, errn, 400, "a bad status code");
    h->status = code;
    h->reason = sp1[4] ? sp1 + 5 : "";
    h->path = h->query = h->target = "";
    if ((st = parse_headers(eol + 2, h, 0, err, errn)) != 0) return st;
    return 0;
}

const char *nmzp_http_reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Content";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    case 507: return "Insufficient Storage";
    default: return "Unknown";
    }
}

/* ----------------------------------------------------------- chunked */

enum { CH_SIZE, CH_EXT, CH_SIZE_LF, CH_DATA, CH_DATA_CR, CH_DATA_LF, CH_TRAILER, CH_TRAILER_LF, CH_END_LF };

void nmzp_chunked_init(nmzp_chunked *c) { memset(c, 0, sizeof *c); }

long nmzp_chunked_feed(nmzp_chunked *c, const char *in, size_t n, nmzp_buf *out, size_t max_total) {
    size_t i = 0;
    while (i < n && !c->done) {
        char ch = in[i];
        switch (c->state) {
        case CH_SIZE: {
            int h = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10
                                                       : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10
                                                                                : -1;
            if (h >= 0) {
                if (++c->line > 15) return -1; /* 15 hex digits are plenty */
                c->left = c->left * 16 + (unsigned)h;
                i++;
            } else if (c->line && (ch == ';' || ch == ' ' || ch == '\t')) {
                c->state = CH_EXT;
                i++;
            } else if (c->line && ch == '\r') {
                c->state = CH_SIZE_LF;
                i++;
            } else {
                return -1;
            }
            break;
        }
        case CH_EXT:
            if (ch == '\r') c->state = CH_SIZE_LF;
            else if (++c->line > 256 || ch == '\n') return -1;
            i++;
            break;
        case CH_SIZE_LF:
            if (ch != '\n') return -1;
            i++;
            c->line = 0;
            c->state = c->left ? CH_DATA : CH_TRAILER;
            break;
        case CH_DATA: {
            size_t take = n - i;
            if ((unsigned long long)take > c->left) take = (size_t)c->left;
            if (out->len + take > max_total) return -2;
            if (nmzp_buf_add(out, in + i, take)) return -1;
            i += take;
            c->left -= take;
            if (!c->left) c->state = CH_DATA_CR;
            break;
        }
        case CH_DATA_CR:
            if (ch != '\r') return -1;
            c->state = CH_DATA_LF;
            i++;
            break;
        case CH_DATA_LF:
            if (ch != '\n') return -1;
            c->state = CH_SIZE;
            c->line = 0;
            i++;
            break;
        case CH_TRAILER: /* trailer lines, ignored, until an empty line */
            if (ch == '\r') {
                c->state = c->line ? CH_TRAILER_LF : CH_END_LF;
            } else {
                if (ch == '\n' || ++c->line > 4096) return -1;
            }
            i++;
            break;
        case CH_TRAILER_LF:
            if (ch != '\n') return -1;
            c->line = 0;
            c->state = CH_TRAILER;
            i++;
            break;
        case CH_END_LF:
            if (ch != '\n') return -1;
            c->done = 1;
            i++;
            break;
        default: return -1;
        }
    }
    return (long)i;
}

/* ------------------------------------------------------------- queries */

static int hexdig(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int nmzp_url_decode(const char *in, size_t n, char *out, size_t outn, int form) {
    size_t i, k = 0;
    for (i = 0; i < n; i++) {
        int c = (unsigned char)in[i];
        if (c == '%') {
            int a, b;
            if (i + 2 >= n) return -1;
            a = hexdig((unsigned char)in[i + 1]);
            b = hexdig((unsigned char)in[i + 2]);
            if (a < 0 || b < 0) return -1;
            c = a * 16 + b;
            if (!c) return -1; /* no NUL bytes in names and values */
            i += 2;
        } else if (c == '+' && form) {
            c = ' ';
        }
        if (k + 1 >= outn) return -1;
        out[k++] = (char)c;
    }
    if (k >= outn) return -1;
    out[k] = '\0';
    return (int)k;
}

int nmzp_query_get(const char *query, const char *key, char *out, size_t n) {
    const char *p = query;
    size_t klen = strlen(key);
    while (p && *p) {
        const char *amp = strchr(p, '&'), *eq = strchr(p, '=');
        size_t len = amp ? (size_t)(amp - p) : strlen(p);
        if (eq && (size_t)(eq - p) < len) {
            char name[128];
            int nl = nmzp_url_decode(p, (size_t)(eq - p), name, sizeof name, 1);
            if (nl >= 0 && (size_t)nl == klen && !memcmp(name, key, klen))
                return nmzp_url_decode(eq + 1, len - (size_t)(eq - p) - 1, out, n, 1) >= 0;
        } else {
            char name[128];
            int nl = nmzp_url_decode(p, len, name, sizeof name, 1);
            if (nl >= 0 && (size_t)nl == klen && !memcmp(name, key, klen)) {
                if (n) out[0] = '\0';
                return 1;
            }
        }
        p = amp ? amp + 1 : NULL;
    }
    return 0;
}

void nmzp_url_encode(nmzp_buf *b, const char *s) {
    static const char hex[] = "0123456789ABCDEF";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
            c == '_' || c == '~') {
            nmzp_buf_add(b, s, 1);
        } else {
            char e[3];
            e[0] = '%';
            e[1] = hex[c >> 4];
            e[2] = hex[c & 15];
            nmzp_buf_add(b, e, 3);
        }
    }
}
