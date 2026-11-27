/* json.c — buffers, a JSON parser (RFC 8259, UTF-8 checked, depth-limited)
 * and a JSON writer. The parser never reads past n bytes and never
 * recurses deeper than max_depth, so any input is safe (fuzzed in CI). */
#include "nmzp.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ buffers */

void nmzp_buf_init(nmzp_buf *b) { memset(b, 0, sizeof *b); }

void nmzp_buf_free(nmzp_buf *b) {
    free(b->data);
    memset(b, 0, sizeof *b);
}

void nmzp_buf_clear(nmzp_buf *b) {
    b->len = 0;
    if (b->data) b->data[0] = '\0';
}

static int grow(nmzp_buf *b, size_t need) {
    size_t cap;
    char *p;
    if (b->oom) return -1;
    if (need + 1 <= b->cap) return 0;
    cap = b->cap ? b->cap : 256;
    while (cap < need + 1) {
        if (cap > ((size_t)-1) / 2) {
            b->oom = 1;
            return -1;
        }
        cap *= 2;
    }
    p = realloc(b->data, cap);
    if (!p) {
        b->oom = 1;
        return -1;
    }
    b->data = p;
    b->cap = cap;
    return 0;
}

int nmzp_buf_add(nmzp_buf *b, const void *p, size_t n) {
    if (n > ((size_t)-1) - b->len - 1 || grow(b, b->len + n)) {
        b->oom = 1;
        return -1;
    }
    if (n) memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

int nmzp_buf_str(nmzp_buf *b, const char *s) { return nmzp_buf_add(b, s, strlen(s)); }

int nmzp_buf_printf(nmzp_buf *b, const char *fmt, ...) {
    va_list ap;
    int k;
    char small[256];
    va_start(ap, fmt);
    k = vsnprintf(small, sizeof small, fmt, ap);
    va_end(ap);
    if (k < 0) return -1;
    if ((size_t)k < sizeof small) return nmzp_buf_add(b, small, (size_t)k);
    if (grow(b, b->len + (size_t)k)) return -1;
    va_start(ap, fmt);
    vsnprintf(b->data + b->len, (size_t)k + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)k;
    return 0;
}

void nmzp_buf_consume(nmzp_buf *b, size_t n) {
    if (n >= b->len) {
        nmzp_buf_clear(b);
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
    b->data[b->len] = '\0';
}

/* ------------------------------------------------------------- parser */

typedef struct parser {
    const char *p, *end, *start;
    int depth, max_depth;
    char *err;
    size_t errn;
} parser;

static int failp(parser *ps, const char *what) {
    if (ps->err && ps->errn && !ps->err[0])
        snprintf(ps->err, ps->errn, "%s at byte %lu", what, (unsigned long)(ps->p - ps->start));
    return -1;
}

static void skip_ws(parser *ps) {
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')) ps->p++;
}

static nmzp_json *node(nmzp_json_type t) {
    nmzp_json *j = calloc(1, sizeof *j);
    if (j) j->type = t;
    return j;
}

void nmzp_json_free(nmzp_json *j) {
    size_t i;
    if (!j) return;
    for (i = 0; i < j->n; i++) nmzp_json_free(j->items[i]);
    free(j->items);
    free(j->string);
    free(j->key);
    free(j);
}

static int push(nmzp_json *parent, nmzp_json *child, size_t *cap) {
    if (parent->n == *cap) {
        size_t nc = *cap ? *cap * 2 : 4;
        nmzp_json **ni = realloc(parent->items, nc * sizeof *ni);
        if (!ni) return -1;
        parent->items = ni;
        *cap = nc;
    }
    parent->items[parent->n++] = child;
    return 0;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void put_utf8(nmzp_buf *b, unsigned long cp) {
    unsigned char u[4];
    size_t n;
    if (cp < 0x80) {
        u[0] = (unsigned char)cp;
        n = 1;
    } else if (cp < 0x800) {
        u[0] = (unsigned char)(0xC0 | (cp >> 6));
        u[1] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {
        u[0] = (unsigned char)(0xE0 | (cp >> 12));
        u[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        u[2] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        u[0] = (unsigned char)(0xF0 | (cp >> 18));
        u[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        u[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        u[3] = (unsigned char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    nmzp_buf_add(b, u, n);
}

/* length of a valid UTF-8 sequence at p (bytes before end), 0 if invalid */
static size_t utf8_len(const unsigned char *p, const unsigned char *end) {
    unsigned c = p[0];
    size_t n, i;
    unsigned long cp;
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) n = 2, cp = c & 0x1F;
    else if (c >= 0xE0 && c <= 0xEF) n = 3, cp = c & 0x0F;
    else if (c >= 0xF0 && c <= 0xF4) n = 4, cp = c & 0x07;
    else return 0;
    if ((size_t)(end - p) < n) return 0;
    for (i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (p[i] & 0x3Fu);
    }
    if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;
    return n;
}

static int parse_string(parser *ps, nmzp_buf *out) {
    ps->p++; /* the opening quote */
    while (ps->p < ps->end) {
        unsigned char c = (unsigned char)*ps->p;
        if (c == '"') {
            ps->p++;
            return out->oom ? failp(ps, "out of memory") : 0;
        }
        if (c < 0x20) return failp(ps, "control character in a string");
        if (c == '\\') {
            unsigned long cp;
            int i;
            if (ps->end - ps->p < 2) return failp(ps, "unterminated escape");
            ps->p++;
            switch (*ps->p) {
            case '"': nmzp_buf_add(out, "\"", 1); break;
            case '\\': nmzp_buf_add(out, "\\", 1); break;
            case '/': nmzp_buf_add(out, "/", 1); break;
            case 'b': nmzp_buf_add(out, "\b", 1); break;
            case 'f': nmzp_buf_add(out, "\f", 1); break;
            case 'n': nmzp_buf_add(out, "\n", 1); break;
            case 'r': nmzp_buf_add(out, "\r", 1); break;
            case 't': nmzp_buf_add(out, "\t", 1); break;
            case 'u':
                if (ps->end - ps->p < 5) return failp(ps, "short \\u escape");
                for (cp = 0, i = 1; i <= 4; i++) {
                    int h = hexval((unsigned char)ps->p[i]);
                    if (h < 0) return failp(ps, "bad \\u escape");
                    cp = cp * 16 + (unsigned long)h;
                }
                ps->p += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF) { /* a surrogate pair */
                    unsigned long lo = 0;
                    if (ps->end - ps->p < 7 || ps->p[1] != '\\' || ps->p[2] != 'u')
                        return failp(ps, "lone high surrogate");
                    for (i = 3; i <= 6; i++) {
                        int h = hexval((unsigned char)ps->p[i]);
                        if (h < 0) return failp(ps, "bad \\u escape");
                        lo = lo * 16 + (unsigned long)h;
                    }
                    if (lo < 0xDC00 || lo > 0xDFFF) return failp(ps, "bad low surrogate");
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    ps->p += 6;
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    return failp(ps, "lone low surrogate");
                }
                put_utf8(out, cp);
                break;
            default: return failp(ps, "bad escape");
            }
            ps->p++;
            continue;
        }
        {
            size_t k = utf8_len((const unsigned char *)ps->p, (const unsigned char *)ps->end);
            if (!k) return failp(ps, "invalid UTF-8 in a string");
            nmzp_buf_add(out, ps->p, k);
            ps->p += k;
        }
    }
    return failp(ps, "unterminated string");
}

static int parse_number(parser *ps, double *out) {
    const char *s = ps->p;
    char tmp[64];
    size_t n;
    if (ps->p < ps->end && *ps->p == '-') ps->p++;
    if (ps->p >= ps->end) return failp(ps, "bad number");
    if (*ps->p == '0') {
        ps->p++;
    } else if (*ps->p >= '1' && *ps->p <= '9') {
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    } else {
        return failp(ps, "bad number");
    }
    if (ps->p < ps->end && *ps->p == '.') {
        ps->p++;
        if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') return failp(ps, "bad number");
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
        if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9') return failp(ps, "bad number");
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    n = (size_t)(ps->p - s);
    if (n >= sizeof tmp) return failp(ps, "number too long");
    memcpy(tmp, s, n);
    tmp[n] = '\0';
    *out = strtod(tmp, NULL);
    if (!isfinite(*out)) return failp(ps, "number out of range");
    return 0;
}

static nmzp_json *parse_value(parser *ps);

static nmzp_json *parse_container(parser *ps, int object) {
    nmzp_json *j = node(object ? NMZP_JSON_OBJECT : NMZP_JSON_ARRAY);
    size_t cap = 0;
    if (!j) return failp(ps, "out of memory"), NULL;
    if (++ps->depth > ps->max_depth) {
        failp(ps, "nested too deeply");
        nmzp_json_free(j);
        return NULL;
    }
    ps->p++; /* [ or { */
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == (object ? '}' : ']')) {
        ps->p++;
        ps->depth--;
        return j;
    }
    for (;;) {
        nmzp_json *child;
        char *key = NULL;
        skip_ws(ps);
        if (object) {
            nmzp_buf kb;
            if (ps->p >= ps->end || *ps->p != '"') {
                failp(ps, "expected a member name");
                goto bad;
            }
            nmzp_buf_init(&kb);
            if (parse_string(ps, &kb)) {
                nmzp_buf_free(&kb);
                goto bad;
            }
            key = kb.data ? kb.data : calloc(1, 1);
            if (!key) {
                failp(ps, "out of memory");
                goto bad;
            }
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') {
                free(key);
                failp(ps, "expected ':'");
                goto bad;
            }
            ps->p++;
            skip_ws(ps);
        }
        child = parse_value(ps);
        if (!child) {
            free(key);
            goto bad;
        }
        child->key = key;
        if (push(j, child, &cap)) {
            nmzp_json_free(child);
            failp(ps, "out of memory");
            goto bad;
        }
        skip_ws(ps);
        if (ps->p < ps->end && *ps->p == ',') {
            ps->p++;
            continue;
        }
        if (ps->p < ps->end && *ps->p == (object ? '}' : ']')) {
            ps->p++;
            ps->depth--;
            return j;
        }
        failp(ps, object ? "expected ',' or '}'" : "expected ',' or ']'");
        goto bad;
    }
bad:
    nmzp_json_free(j);
    return NULL;
}

static int literal(parser *ps, const char *word) {
    size_t n = strlen(word);
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, word, n)) return 0;
    ps->p += n;
    return 1;
}

static nmzp_json *parse_value(parser *ps) {
    nmzp_json *j;
    skip_ws(ps);
    if (ps->p >= ps->end) return failp(ps, "unexpected end"), NULL;
    switch (*ps->p) {
    case '{': return parse_container(ps, 1);
    case '[': return parse_container(ps, 0);
    case '"': {
        nmzp_buf b;
        nmzp_buf_init(&b);
        if (parse_string(ps, &b)) {
            nmzp_buf_free(&b);
            return NULL;
        }
        if (!(j = node(NMZP_JSON_STRING))) {
            nmzp_buf_free(&b);
            return failp(ps, "out of memory"), NULL;
        }
        j->len = b.len;
        j->string = b.data ? b.data : calloc(1, 1);
        if (!j->string) {
            free(j);
            return failp(ps, "out of memory"), NULL;
        }
        return j;
    }
    case 't':
        if (!literal(ps, "true")) break;
        return node(NMZP_JSON_TRUE);
    case 'f':
        if (!literal(ps, "false")) break;
        return node(NMZP_JSON_FALSE);
    case 'n':
        if (!literal(ps, "null")) break;
        return node(NMZP_JSON_NULL);
    default:
        if (*ps->p == '-' || (*ps->p >= '0' && *ps->p <= '9')) {
            double d;
            if (parse_number(ps, &d)) return NULL;
            if (!(j = node(NMZP_JSON_NUMBER))) return failp(ps, "out of memory"), NULL;
            j->number = d;
            return j;
        }
    }
    return failp(ps, "unexpected character"), NULL;
}

nmzp_json *nmzp_json_parse(const char *text, size_t n, int max_depth, char *err, size_t errn) {
    parser ps;
    nmzp_json *j;
    if (err && errn) err[0] = '\0';
    if (!text) {
        if (err && errn) snprintf(err, errn, "no text");
        return NULL;
    }
    ps.p = ps.start = text;
    ps.end = text + n;
    ps.depth = 0;
    ps.max_depth = max_depth > 0 ? max_depth : 64;
    ps.err = err;
    ps.errn = errn;
    j = parse_value(&ps);
    if (!j) return NULL;
    skip_ws(&ps);
    if (ps.p != ps.end) {
        failp(&ps, "text after the value");
        nmzp_json_free(j);
        return NULL;
    }
    return j;
}

const nmzp_json *nmzp_json_get(const nmzp_json *obj, const char *key) {
    size_t i;
    if (!obj || obj->type != NMZP_JSON_OBJECT || !key) return NULL;
    for (i = 0; i < obj->n; i++)
        if (obj->items[i]->key && !strcmp(obj->items[i]->key, key)) return obj->items[i];
    return NULL;
}

const nmzp_json *nmzp_json_at(const nmzp_json *arr, size_t i) {
    if (!arr || arr->type != NMZP_JSON_ARRAY || i >= arr->n) return NULL;
    return arr->items[i];
}

const char *nmzp_json_str(const nmzp_json *j) { return j && j->type == NMZP_JSON_STRING ? j->string : NULL; }

int nmzp_json_num(const nmzp_json *j, double *out) {
    if (!j || j->type != NMZP_JSON_NUMBER) return 0;
    if (out) *out = j->number;
    return 1;
}

int nmzp_json_bool(const nmzp_json *j, int *out) {
    if (!j || (j->type != NMZP_JSON_TRUE && j->type != NMZP_JSON_FALSE)) return 0;
    if (out) *out = j->type == NMZP_JSON_TRUE;
    return 1;
}

const char *nmzp_json_get_str(const nmzp_json *obj, const char *key) { return nmzp_json_str(nmzp_json_get(obj, key)); }

int nmzp_json_get_num(const nmzp_json *obj, const char *key, double *out) {
    return nmzp_json_num(nmzp_json_get(obj, key), out);
}

int nmzp_json_get_bool(const nmzp_json *obj, const char *key, int *out) {
    return nmzp_json_bool(nmzp_json_get(obj, key), out);
}

/* ------------------------------------------------------------- writer */

void nmzp_json_escape(nmzp_buf *b, const char *s, size_t n) {
    size_t i, run = 0;
    nmzp_buf_add(b, "\"", 1);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *esc = NULL;
        char u[8];
        if (c == '"') esc = "\\\"";
        else if (c == '\\') esc = "\\\\";
        else if (c == '\n') esc = "\\n";
        else if (c == '\r') esc = "\\r";
        else if (c == '\t') esc = "\\t";
        else if (c < 0x20 || c == 0x7F) {
            snprintf(u, sizeof u, "\\u%04x", c);
            esc = u;
        }
        if (esc) {
            nmzp_buf_add(b, s + i - run, run);
            run = 0;
            nmzp_buf_str(b, esc);
        } else {
            run++;
        }
    }
    nmzp_buf_add(b, s + n - run, run);
    nmzp_buf_add(b, "\"", 1);
}

void nmzp_jw_init(nmzp_jw *w, nmzp_buf *b) {
    memset(w, 0, sizeof *w);
    w->b = b;
    w->fresh[0] = 1;
}

static void before_value(nmzp_jw *w) {
    if (w->after_key) {
        w->after_key = 0;
        return;
    }
    if (!w->fresh[w->depth]) nmzp_buf_add(w->b, ",", 1);
    w->fresh[w->depth] = 0;
}

static void open_(nmzp_jw *w, const char *c) {
    before_value(w);
    nmzp_buf_add(w->b, c, 1);
    if (w->depth < 63) w->depth++;
    w->fresh[w->depth] = 1;
}

static void close_(nmzp_jw *w, const char *c) {
    nmzp_buf_add(w->b, c, 1);
    if (w->depth > 0) w->depth--;
}

void nmzp_jw_obj(nmzp_jw *w) { open_(w, "{"); }
void nmzp_jw_end_obj(nmzp_jw *w) { close_(w, "}"); }
void nmzp_jw_arr(nmzp_jw *w) { open_(w, "["); }
void nmzp_jw_end_arr(nmzp_jw *w) { close_(w, "]"); }

void nmzp_jw_key(nmzp_jw *w, const char *k) {
    before_value(w);
    nmzp_json_escape(w->b, k, strlen(k));
    nmzp_buf_add(w->b, ":", 1);
    w->after_key = 1;
}

void nmzp_jw_strn(nmzp_jw *w, const char *s, size_t n) {
    before_value(w);
    nmzp_json_escape(w->b, s, n);
}

void nmzp_jw_str(nmzp_jw *w, const char *s) {
    if (!s) {
        nmzp_jw_null(w);
        return;
    }
    nmzp_jw_strn(w, s, strlen(s));
}

void nmzp_jw_num(nmzp_jw *w, double v) {
    before_value(w);
    if (!isfinite(v))
        nmzp_buf_str(w->b, "null");
    else if (v == floor(v) && fabs(v) < 1e15)
        nmzp_buf_printf(w->b, "%.0f", v);
    else
        nmzp_buf_printf(w->b, "%.9g", v);
}

void nmzp_jw_int(nmzp_jw *w, long long v) {
    before_value(w);
    nmzp_buf_printf(w->b, "%lld", v);
}

void nmzp_jw_bool(nmzp_jw *w, int v) {
    before_value(w);
    nmzp_buf_str(w->b, v ? "true" : "false");
}

void nmzp_jw_null(nmzp_jw *w) {
    before_value(w);
    nmzp_buf_str(w->b, "null");
}

void nmzp_jw_raw(nmzp_jw *w, const char *json) {
    before_value(w);
    nmzp_buf_str(w->b, json);
}

void nmzp_jw_kstr(nmzp_jw *w, const char *k, const char *s) {
    nmzp_jw_key(w, k);
    nmzp_jw_str(w, s);
}

void nmzp_jw_knum(nmzp_jw *w, const char *k, double v) {
    nmzp_jw_key(w, k);
    nmzp_jw_num(w, v);
}

void nmzp_jw_kint(nmzp_jw *w, const char *k, long long v) {
    nmzp_jw_key(w, k);
    nmzp_jw_int(w, v);
}

void nmzp_jw_kbool(nmzp_jw *w, const char *k, int v) {
    nmzp_jw_key(w, k);
    nmzp_jw_bool(w, v);
}

void nmzp_jw_knull(nmzp_jw *w, const char *k) {
    nmzp_jw_key(w, k);
    nmzp_jw_null(w);
}
