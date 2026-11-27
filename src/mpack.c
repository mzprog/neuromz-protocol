/* mpack.c — the payload codec of PROTOCOL §4: a MessagePack subset (nil,
 * bool, int, float, str, bin, array, map; no extension types), decoded
 * into a tree and written in canonical form. The decoder never reads past
 * n bytes, never recurses deeper than 32, checks UTF-8 and duplicate keys,
 * and never trusts a count before the bytes are there (fuzzed in CI). */
#include "nmzp.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- values */

void nmzp_val_free(nmzp_val *v) {
    size_t i;
    if (!v) return;
    for (i = 0; i < v->n; i++) nmzp_val_free(v->items[i]);
    free(v->items);
    free(v->s);
    free(v->key);
    free(v);
}

const nmzp_val *nmzp_get(const nmzp_val *map, const char *key) {
    size_t i;
    if (!map || map->type != NMZP_MAP || !key) return NULL;
    for (i = 0; i < map->n; i++)
        if (!strcmp(map->items[i]->key, key)) return map->items[i];
    return NULL;
}

const nmzp_val *nmzp_at(const nmzp_val *arr, size_t i) {
    if (!arr || arr->type != NMZP_ARRAY || i >= arr->n) return NULL;
    return arr->items[i];
}

const char *nmzp_str(const nmzp_val *v) { return v && v->type == NMZP_STR ? v->s : NULL; }

int nmzp_num(const nmzp_val *v, double *out) {
    double d;
    if (!v) return 0;
    if (v->type == NMZP_INT) d = (double)v->i;
    else if (v->type == NMZP_FLOAT) d = v->f;
    else return 0;
    if (out) *out = d;
    return 1;
}

int nmzp_int(const nmzp_val *v, long long *out) {
    if (!v) return 0;
    if (v->type == NMZP_INT) {
        if (out) *out = v->i;
        return 1;
    }
    /* a whole float within the range a long long holds exactly enough */
    if (v->type == NMZP_FLOAT && isfinite(v->f) && v->f == floor(v->f) && fabs(v->f) <= 9007199254740992.0) {
        if (out) *out = (long long)v->f;
        return 1;
    }
    return 0;
}

int nmzp_bool(const nmzp_val *v, int *out) {
    if (!v || v->type != NMZP_BOOL) return 0;
    if (out) *out = v->b;
    return 1;
}

const unsigned char *nmzp_bin(const nmzp_val *v, size_t *n) {
    if (!v || v->type != NMZP_BIN) return NULL;
    if (n) *n = v->len;
    return v->s ? (const unsigned char *)v->s : (const unsigned char *)"";
}

int nmzp_is_nil(const nmzp_val *v) { return !v || v->type == NMZP_NIL; }

const char *nmzp_get_str(const nmzp_val *map, const char *key) { return nmzp_str(nmzp_get(map, key)); }
int nmzp_get_num(const nmzp_val *map, const char *key, double *out) { return nmzp_num(nmzp_get(map, key), out); }
int nmzp_get_int(const nmzp_val *map, const char *key, long long *out) { return nmzp_int(nmzp_get(map, key), out); }
int nmzp_get_bool(const nmzp_val *map, const char *key, int *out) { return nmzp_bool(nmzp_get(map, key), out); }

const char *nmzp_type_name(nmzp_type t) {
    static const char *const names[] = {"nil", "bool", "int", "float", "str", "bin", "array", "map"};
    return (unsigned)t < 8 ? names[t] : "?";
}

/* ------------------------------------------------------------- decoding */

typedef struct dec {
    const unsigned char *p, *end, *start;
    char *err;
    size_t errn;
    unsigned long values; /* decoded so far: at most NMZP_MAX_VALUES */
} dec;

static int failf(dec *d, const char *what) {
    if (d->err && d->errn && !d->err[0])
        snprintf(d->err, d->errn, "%s at byte %lu", what, (unsigned long)(d->p - d->start));
    return -1;
}

static int need(dec *d, size_t k) {
    if ((size_t)(d->end - d->p) < k) return failf(d, "the payload ends inside a value");
    return 0;
}

static uint64_t be(const unsigned char *p, int k) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < k; i++) v = (v << 8) | p[i];
    return v;
}

static nmzp_val *node(nmzp_type t) {
    nmzp_val *v = calloc(1, sizeof *v);
    if (v) v->type = t;
    return v;
}

/* FNV-1a, for finding duplicate keys in large maps */
static uint32_t fnv(const char *s, size_t n) {
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0; i < n; i++) h = (h ^ (unsigned char)s[i]) * 16777619u;
    return h;
}

/* 1 = the key is already in the map: a linear look for small maps, a
 * hash set (slots: indexes + 1, 0 = free) for large ones */
static int seen_key(const nmzp_val *map, const char *k, size_t kn, uint32_t *slots, size_t nslots) {
    size_t j;
    if (!slots) {
        for (j = 0; j < map->n; j++)
            if (strlen(map->items[j]->key) == kn && !memcmp(map->items[j]->key, k, kn)) return 1;
        return 0;
    }
    for (j = fnv(k, kn) & (nslots - 1);; j = (j + 1) & (nslots - 1)) {
        const char *o;
        if (!slots[j]) return 0;
        o = map->items[slots[j] - 1]->key;
        if (strlen(o) == kn && !memcmp(o, k, kn)) return 1;
    }
}

static void add_key(uint32_t *slots, size_t nslots, const char *k, size_t kn, uint32_t index) {
    size_t j;
    if (!slots) return;
    for (j = fnv(k, kn) & (nslots - 1); slots[j]; j = (j + 1) & (nslots - 1)) {
    }
    slots[j] = index + 1;
}

/* the bytes of a str or bin: copied, NUL-terminated */
static int take(dec *d, nmzp_val *v, size_t n, int is_str) {
    if (need(d, n)) return -1;
    if (is_str && !nmzp_utf8_valid((const char *)d->p, n)) return failf(d, "a str that is not valid UTF-8");
    if (!(v->s = malloc(n + 1))) return failf(d, "out of memory");
    if (n) memcpy(v->s, d->p, n);
    v->s[n] = '\0';
    v->len = n;
    d->p += n;
    return 0;
}

static nmzp_val *value(dec *d, int depth);

static nmzp_val *container(dec *d, nmzp_val *v, uint64_t count, int depth) {
    uint64_t k;
    int is_map = v->type == NMZP_MAP;
    uint32_t *slots = NULL;
    size_t nslots = 0;
    if (depth > NMZP_MAX_DEPTH) {
        failf(d, "containers nested deeper than 32");
        nmzp_val_free(v);
        return NULL;
    }
    /* every value takes a byte at least (a pair two): a count cannot be more than what is left */
    if (count > (uint64_t)(d->end - d->p) / (is_map ? 2u : 1u)) {
        failf(d, is_map ? "a map that claims more pairs than the payload holds"
                        : "an array that claims more values than the payload holds");
        nmzp_val_free(v);
        return NULL;
    }
    if (count > NMZP_MAX_VALUES) {
        failf(d, "more values than a payload may hold (262144)");
        nmzp_val_free(v);
        return NULL;
    }
    if (count) {
        if (!(v->items = calloc((size_t)count, sizeof *v->items))) {
            failf(d, "out of memory");
            nmzp_val_free(v);
            return NULL;
        }
    }
    if (is_map && count > 16) {
        for (nslots = 64; nslots < 2 * count; nslots *= 2) {
        }
        if (!(slots = calloc(nslots, sizeof *slots))) {
            failf(d, "out of memory");
            nmzp_val_free(v);
            return NULL;
        }
    }
    for (k = 0; k < count; k++) {
        char *key = NULL;
        nmzp_val *item;
        if (is_map) {
            nmzp_val *kv = value(d, depth + 1);
            const char *why = NULL;
            if (!kv) goto fail;
            if (kv->type != NMZP_STR) why = "a map key that is not a str";
            else if (memchr(kv->s, 0, kv->len)) why = "a map key with a U+0000 character";
            else if (seen_key(v, kv->s, kv->len, slots, nslots)) why = "a key that occurs twice in one map";
            if (why) {
                nmzp_val_free(kv);
                failf(d, why);
                goto fail;
            }
            add_key(slots, nslots, kv->s, kv->len, (uint32_t)v->n);
            key = kv->s;
            kv->s = NULL;
            nmzp_val_free(kv);
        }
        item = value(d, depth + 1);
        if (!item) {
            free(key);
            goto fail;
        }
        item->key = key ? key : NULL;
        if (is_map && !item->key) { /* keep the invariant: every map value has its key */
            nmzp_val_free(item);
            goto fail;
        }
        v->items[v->n++] = item;
    }
    free(slots);
    return v;
fail:
    free(slots);
    nmzp_val_free(v);
    return NULL;
}

static nmzp_val *value(dec *d, int depth) {
    unsigned c;
    nmzp_val *v;
    if (need(d, 1)) return NULL;
    if (++d->values > NMZP_MAX_VALUES) return failf(d, "more values than a payload may hold (262144)"), NULL;
    c = *d->p++;
    if (c <= 0x7f || c >= 0xe0) {
        if (!(v = node(NMZP_INT))) return failf(d, "out of memory"), NULL;
        v->i = c <= 0x7f ? (long long)c : (long long)c - 256;
        return v;
    }
    if (c >= 0x80 && c <= 0x8f) {
        if (!(v = node(NMZP_MAP))) return failf(d, "out of memory"), NULL;
        return container(d, v, c & 0x0f, depth);
    }
    if (c >= 0x90 && c <= 0x9f) {
        if (!(v = node(NMZP_ARRAY))) return failf(d, "out of memory"), NULL;
        return container(d, v, c & 0x0f, depth);
    }
    if (c >= 0xa0 && c <= 0xbf) {
        if (!(v = node(NMZP_STR))) return failf(d, "out of memory"), NULL;
        if (take(d, v, c & 0x1f, 1)) return nmzp_val_free(v), NULL;
        return v;
    }
    switch (c) {
    case 0xc0: return node(NMZP_NIL);
    case 0xc2:
    case 0xc3:
        if (!(v = node(NMZP_BOOL))) return failf(d, "out of memory"), NULL;
        v->b = c == 0xc3;
        return v;
    case 0xc4:
    case 0xc5:
    case 0xc6:
    case 0xd9:
    case 0xda:
    case 0xdb: {
        int k = c == 0xc4 || c == 0xd9 ? 1 : c == 0xc5 || c == 0xda ? 2 : 4, is_str = c >= 0xd9;
        uint64_t n;
        if (need(d, (size_t)k)) return NULL;
        n = be(d->p, k);
        d->p += k;
        if (!(v = node(is_str ? NMZP_STR : NMZP_BIN))) return failf(d, "out of memory"), NULL;
        if (n > (uint64_t)(d->end - d->p)) {
            failf(d, "the payload ends inside a value");
            nmzp_val_free(v);
            return NULL;
        }
        if (take(d, v, (size_t)n, is_str)) return nmzp_val_free(v), NULL;
        return v;
    }
    case 0xca: {
        uint32_t bits;
        float f;
        if (need(d, 4)) return NULL;
        bits = (uint32_t)be(d->p, 4);
        d->p += 4;
        memcpy(&f, &bits, 4);
        if (!(v = node(NMZP_FLOAT))) return failf(d, "out of memory"), NULL;
        v->f = f;
        v->f32 = 1;
        return v;
    }
    case 0xcb: {
        uint64_t bits;
        double f;
        if (need(d, 8)) return NULL;
        bits = be(d->p, 8);
        d->p += 8;
        memcpy(&f, &bits, 8);
        if (!(v = node(NMZP_FLOAT))) return failf(d, "out of memory"), NULL;
        v->f = f;
        return v;
    }
    case 0xcc:
    case 0xcd:
    case 0xce:
    case 0xcf: {
        int k = 1 << (c - 0xcc);
        uint64_t u;
        if (need(d, (size_t)k)) return NULL;
        u = be(d->p, k);
        if (u > (uint64_t)INT64_MAX) return failf(d, "a uint 64 above 2^63-1"), NULL;
        d->p += k;
        if (!(v = node(NMZP_INT))) return failf(d, "out of memory"), NULL;
        v->i = (long long)u;
        return v;
    }
    case 0xd0:
    case 0xd1:
    case 0xd2:
    case 0xd3: {
        int k = 1 << (c - 0xd0);
        uint64_t u;
        long long s;
        if (need(d, (size_t)k)) return NULL;
        u = be(d->p, k);
        d->p += k;
        if (k < 8 && (u >> (8 * k - 1)) & 1) u |= ~(uint64_t)0 << (8 * k); /* sign extension */
        memcpy(&s, &u, sizeof s);
        if (!(v = node(NMZP_INT))) return failf(d, "out of memory"), NULL;
        v->i = s;
        return v;
    }
    case 0xdc:
    case 0xdd:
    case 0xde:
    case 0xdf: {
        int k = c == 0xdc || c == 0xde ? 2 : 4;
        uint64_t n;
        if (need(d, (size_t)k)) return NULL;
        n = be(d->p, k);
        d->p += k;
        if (!(v = node(c <= 0xdd ? NMZP_ARRAY : NMZP_MAP))) return failf(d, "out of memory"), NULL;
        return container(d, v, n, depth);
    }
    default:
        d->p--;
        failf(d, c == 0xc1 ? "the byte c1 (never used)" : "an extension type (not in the subset)");
        return NULL;
    }
}

static nmzp_val *decode(const void *p, size_t n, int want_map, char *err, size_t errn) {
    dec d;
    nmzp_val *v;
    d.p = d.start = (const unsigned char *)p;
    d.end = d.p + n;
    d.err = err;
    d.errn = errn;
    d.values = 0;
    if (err && errn) err[0] = '\0';
    if (!p && n) return NULL;
    if (want_map && (n == 0 || !((d.p[0] >= 0x80 && d.p[0] <= 0x8f) || d.p[0] == 0xde || d.p[0] == 0xdf))) {
        failf(&d, n == 0 ? "an empty payload (it must be a map)" : "the payload is not a map");
        return NULL;
    }
    if (!(v = value(&d, 1))) return NULL;
    if (d.p != d.end) {
        failf(&d, "trailing bytes after the value");
        nmzp_val_free(v);
        return NULL;
    }
    return v;
}

nmzp_val *nmzp_decode(const void *p, size_t n, char *err, size_t errn) { return decode(p, n, 1, err, errn); }
nmzp_val *nmzp_decode_value(const void *p, size_t n, char *err, size_t errn) { return decode(p, n, 0, err, errn); }

/* ------------------------------------------------------------- writing */

static void put_be(nmzp_buf *b, int lead, uint64_t v, int k) {
    unsigned char t[9];
    int i, n = 0;
    if (lead >= 0) t[n++] = (unsigned char)lead;
    for (i = k - 1; i >= 0; i--) t[n++] = (unsigned char)(v >> (8 * i));
    nmzp_buf_add(b, t, (size_t)n);
}

void nmzp_mw_init(nmzp_mw *w, nmzp_buf *b) {
    memset(w, 0, sizeof *w);
    w->b = b;
}

/* a value is about to be written at the current depth */
static void before(nmzp_mw *w, int is_key) {
    int d = w->depth;
    if (d == 0) return;
    if (w->map[d]) {
        if (is_key == w->expect_value[d]) w->bad = 1; /* a key where a value belongs, or the other way round */
        if (is_key) w->count[d]++;
        w->expect_value[d] = (unsigned char)is_key;
    } else {
        if (is_key) w->bad = 1;
        w->count[d]++;
    }
}

static void open_(nmzp_mw *w, int is_map) {
    static const unsigned char room[5] = {0, 0, 0, 0, 0};
    before(w, 0);
    if (w->depth >= NMZP_MAX_DEPTH) {
        w->bad = 1;
        return;
    }
    w->depth++;
    w->start[w->depth] = w->b->len;
    w->count[w->depth] = 0;
    w->map[w->depth] = (unsigned char)is_map;
    w->expect_value[w->depth] = 0;
    nmzp_buf_add(w->b, room, 5); /* the largest header; the real one is written at the end */
}

static void close_(nmzp_mw *w, int is_map) {
    unsigned char h[5];
    size_t hn, start, body;
    unsigned long n;
    if (w->depth == 0 || w->map[w->depth] != is_map || w->b->oom) {
        w->bad = 1;
        return;
    }
    if (is_map && w->expect_value[w->depth]) w->bad = 1; /* a key without its value */
    n = w->count[w->depth];
    start = w->start[w->depth];
    if (n <= 15) {
        h[0] = (unsigned char)((is_map ? 0x80 : 0x90) | n);
        hn = 1;
    } else if (n <= 0xffff) {
        h[0] = is_map ? 0xde : 0xdc;
        h[1] = (unsigned char)(n >> 8);
        h[2] = (unsigned char)n;
        hn = 3;
    } else {
        h[0] = is_map ? 0xdf : 0xdd;
        h[1] = (unsigned char)(n >> 24);
        h[2] = (unsigned char)(n >> 16);
        h[3] = (unsigned char)(n >> 8);
        h[4] = (unsigned char)n;
        hn = 5;
    }
    body = w->b->len - start - 5;
    memcpy(w->b->data + start, h, hn);
    if (hn < 5) {
        memmove(w->b->data + start + hn, w->b->data + start + 5, body);
        w->b->len -= 5 - hn;
        w->b->data[w->b->len] = '\0';
    }
    w->depth--;
}

void nmzp_mw_map(nmzp_mw *w) { open_(w, 1); }
void nmzp_mw_end_map(nmzp_mw *w) { close_(w, 1); }
void nmzp_mw_arr(nmzp_mw *w) { open_(w, 0); }
void nmzp_mw_end_arr(nmzp_mw *w) { close_(w, 0); }

static void put_str(nmzp_buf *b, const char *s, size_t n) {
    if (n <= 31) put_be(b, (int)(0xa0 | n), 0, 0);
    else if (n <= 0xff) put_be(b, 0xd9, n, 1);
    else if (n <= 0xffff) put_be(b, 0xda, n, 2);
    else put_be(b, 0xdb, n, 4);
    nmzp_buf_add(b, s, n);
}

void nmzp_mw_key(nmzp_mw *w, const char *k) {
    before(w, 1);
    put_str(w->b, k, strlen(k));
}

void nmzp_mw_strn(nmzp_mw *w, const char *s, size_t n) {
    before(w, 0);
    put_str(w->b, s, n);
}

void nmzp_mw_str(nmzp_mw *w, const char *s) {
    if (!s) nmzp_mw_nil(w);
    else nmzp_mw_strn(w, s, strlen(s));
}

void nmzp_mw_int(nmzp_mw *w, long long v) {
    before(w, 0);
    if (v >= 0) {
        uint64_t u = (uint64_t)v;
        if (u <= 0x7f) put_be(w->b, (int)u, 0, 0);
        else if (u <= 0xff) put_be(w->b, 0xcc, u, 1);
        else if (u <= 0xffff) put_be(w->b, 0xcd, u, 2);
        else if (u <= 0xffffffffu) put_be(w->b, 0xce, u, 4);
        else put_be(w->b, 0xcf, u, 8);
    } else {
        uint64_t u;
        memcpy(&u, &v, sizeof u);
        if (v >= -32) put_be(w->b, (int)(u & 0xff), 0, 0);
        else if (v >= -128) put_be(w->b, 0xd0, u & 0xff, 1);
        else if (v >= -32768) put_be(w->b, 0xd1, u & 0xffff, 2);
        else if (v >= -2147483647LL - 1) put_be(w->b, 0xd2, u & 0xffffffffu, 4);
        else put_be(w->b, 0xd3, u, 8);
    }
}

void nmzp_mw_float(nmzp_mw *w, double v) {
    uint64_t bits;
    if (!isfinite(v)) {
        nmzp_mw_nil(w);
        return;
    }
    before(w, 0);
    memcpy(&bits, &v, 8);
    put_be(w->b, 0xcb, bits, 8);
}

void nmzp_mw_float32(nmzp_mw *w, float v) {
    uint32_t bits;
    before(w, 0);
    memcpy(&bits, &v, 4);
    put_be(w->b, 0xca, bits, 4);
}

void nmzp_mw_bool(nmzp_mw *w, int v) {
    before(w, 0);
    put_be(w->b, v ? 0xc3 : 0xc2, 0, 0);
}

void nmzp_mw_nil(nmzp_mw *w) {
    before(w, 0);
    put_be(w->b, 0xc0, 0, 0);
}

static void bin_head(nmzp_buf *b, size_t n) {
    if (n <= 0xff) put_be(b, 0xc4, n, 1);
    else if (n <= 0xffff) put_be(b, 0xc5, n, 2);
    else put_be(b, 0xc6, n, 4);
}

void nmzp_mw_bin(nmzp_mw *w, const void *p, size_t n) {
    before(w, 0);
    bin_head(w->b, n);
    nmzp_buf_add(w->b, p, n);
}

void nmzp_f32_write(const float *v, size_t n, void *out) {
    unsigned char *o = (unsigned char *)out;
    size_t i;
    for (i = 0; i < n; i++) {
        uint32_t bits;
        memcpy(&bits, &v[i], 4);
        o[4 * i] = (unsigned char)bits;
        o[4 * i + 1] = (unsigned char)(bits >> 8);
        o[4 * i + 2] = (unsigned char)(bits >> 16);
        o[4 * i + 3] = (unsigned char)(bits >> 24);
    }
}

void nmzp_f32_read(const void *bin, size_t n, float *out) {
    const unsigned char *p = (const unsigned char *)bin;
    size_t i;
    for (i = 0; i < n; i++) {
        uint32_t bits = (uint32_t)p[4 * i] | (uint32_t)p[4 * i + 1] << 8 | (uint32_t)p[4 * i + 2] << 16 |
                        (uint32_t)p[4 * i + 3] << 24;
        memcpy(&out[i], &bits, 4);
    }
}

void nmzp_mw_f32(nmzp_mw *w, const float *v, size_t n) {
    size_t at;
    before(w, 0);
    bin_head(w->b, n * 4);
    at = w->b->len;
    {
        static const unsigned char zero[256] = {0};
        size_t left = n * 4;
        while (left) {
            size_t k = left < sizeof zero ? left : sizeof zero;
            nmzp_buf_add(w->b, zero, k);
            left -= k;
        }
    }
    if (!w->b->oom) nmzp_f32_write(v, n, w->b->data + at);
}

void nmzp_mw_raw(nmzp_mw *w, const void *encoded, size_t n) {
    before(w, 0);
    nmzp_buf_add(w->b, encoded, n);
}

void nmzp_mw_kstr(nmzp_mw *w, const char *k, const char *s) {
    nmzp_mw_key(w, k);
    nmzp_mw_str(w, s);
}
void nmzp_mw_kint(nmzp_mw *w, const char *k, long long v) {
    nmzp_mw_key(w, k);
    nmzp_mw_int(w, v);
}
void nmzp_mw_kfloat(nmzp_mw *w, const char *k, double v) {
    nmzp_mw_key(w, k);
    nmzp_mw_float(w, v);
}
void nmzp_mw_kbool(nmzp_mw *w, const char *k, int v) {
    nmzp_mw_key(w, k);
    nmzp_mw_bool(w, v);
}
void nmzp_mw_knil(nmzp_mw *w, const char *k) {
    nmzp_mw_key(w, k);
    nmzp_mw_nil(w);
}
void nmzp_mw_kbin(nmzp_mw *w, const char *k, const void *p, size_t n) {
    nmzp_mw_key(w, k);
    nmzp_mw_bin(w, p, n);
}

void nmzp_mw_members(nmzp_mw *w, const void *encoded_map, size_t n) {
    const unsigned char *p = (const unsigned char *)encoded_map;
    unsigned long count;
    size_t h;
    int d = w->depth;
    if (!n) return;
    if (d == 0 || !w->map[d] || w->expect_value[d]) {
        w->bad = 1;
        return;
    }
    if (p[0] >= 0x80 && p[0] <= 0x8f) count = p[0] & 0x0f, h = 1;
    else if (p[0] == 0xde && n >= 3) count = (unsigned long)p[1] << 8 | p[2], h = 3;
    else if (p[0] == 0xdf && n >= 5)
        count = (unsigned long)p[1] << 24 | (unsigned long)p[2] << 16 | (unsigned long)p[3] << 8 | p[4], h = 5;
    else {
        w->bad = 1;
        return;
    }
    w->count[d] += count;
    nmzp_buf_add(w->b, p + h, n - h);
}

int nmzp_mw_done(const nmzp_mw *w) { return w->bad || w->depth != 0 || w->b->oom ? -1 : 0; }

void nmzp_mw_val(nmzp_mw *w, const nmzp_val *v) {
    size_t i;
    if (!v) {
        nmzp_mw_nil(w);
        return;
    }
    switch (v->type) {
    case NMZP_NIL: nmzp_mw_nil(w); break;
    case NMZP_BOOL: nmzp_mw_bool(w, v->b); break;
    case NMZP_INT: nmzp_mw_int(w, v->i); break;
    case NMZP_FLOAT:
        if (isfinite(v->f)) nmzp_mw_float(w, v->f);
        else { /* a NaN or an infinity that arrived: written as it came, not as nil */
            uint64_t bits;
            before(w, 0);
            memcpy(&bits, &v->f, 8);
            put_be(w->b, 0xcb, bits, 8);
        }
        break;
    case NMZP_STR: nmzp_mw_strn(w, v->s, v->len); break;
    case NMZP_BIN: nmzp_mw_bin(w, v->s, v->len); break;
    case NMZP_ARRAY:
        nmzp_mw_arr(w);
        for (i = 0; i < v->n; i++) nmzp_mw_val(w, v->items[i]);
        nmzp_mw_end_arr(w);
        break;
    case NMZP_MAP:
        nmzp_mw_map(w);
        for (i = 0; i < v->n; i++) {
            nmzp_mw_key(w, v->items[i]->key);
            nmzp_mw_val(w, v->items[i]);
        }
        nmzp_mw_end_map(w);
        break;
    }
}
