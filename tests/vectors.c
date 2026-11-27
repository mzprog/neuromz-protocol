/* vectors.c — the shared test vectors of PROTOCOL §17.
 *
 *   nmz-vectors write DIR     write every vector (NAME.bin, NAME.json, index.json, auth.json)
 *   nmz-vectors check DIR     check a directory of vectors against this implementation
 *
 * The C implementation is the source of the vectors; `check` is what any
 * implementation does with them: every valid vector decodes to the value
 * its description gives and encodes (from the description) to the same
 * bytes, every invalid one is refused, every frame is rebuilt byte for
 * byte. CI writes them afresh, compares with the committed ones, and
 * checks the committed ones.
 *
 * Descriptions are JSON; a value is typed so that nothing is lost: nil is
 * null, a bool true/false, a str a JSON string, an array a JSON array, and
 * the other types are one-key objects —
 *   {"int": "-33"}  {"float": 1.5, "bits": "3ff8000000000000"}
 *   {"float32": 1.5, "bits": "3fc00000"}  {"bin": "00ff"}
 *   {"map": [["key", value], ...]}
 * (bits are the IEEE 754 pattern in hexadecimal, and they decide). */
#include "nmzp.h"
#include "nmzp_json.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_checked;
static const char *g_dir;
static nmzp_buf g_index;
static int g_first_index = 1;

/* -------------------------------------------------- typed JSON (write) */

static void typed(nmzp_buf *o, const nmzp_val *v) {
    size_t i;
    switch (v->type) {
    case NMZP_NIL: nmzp_buf_str(o, "null"); break;
    case NMZP_BOOL: nmzp_buf_str(o, v->b ? "true" : "false"); break;
    case NMZP_INT: nmzp_buf_printf(o, "{\"int\": \"%lld\"}", v->i); break;
    case NMZP_FLOAT:
        if (v->f32) {
            float f = (float)v->f;
            uint32_t bits;
            memcpy(&bits, &f, 4);
            if (isfinite(v->f)) nmzp_buf_printf(o, "{\"float32\": %.17g, \"bits\": \"%08lx\"}", v->f, (unsigned long)bits);
            else nmzp_buf_printf(o, "{\"float32\": null, \"bits\": \"%08lx\"}", (unsigned long)bits);
        } else {
            uint64_t bits;
            memcpy(&bits, &v->f, 8);
            if (isfinite(v->f)) nmzp_buf_printf(o, "{\"float\": %.17g, \"bits\": \"%016llx\"}", v->f, (unsigned long long)bits);
            else nmzp_buf_printf(o, "{\"float\": null, \"bits\": \"%016llx\"}", (unsigned long long)bits);
        }
        break;
    case NMZP_STR: nmzp_json_escape(o, v->s, v->len); break;
    case NMZP_BIN: {
        char *hex = malloc(v->len * 2 + 1);
        if (!hex) break;
        nmzp_hex((const unsigned char *)(v->s ? v->s : ""), v->len, hex);
        nmzp_buf_printf(o, "{\"bin\": \"%s\"}", hex);
        free(hex);
        break;
    }
    case NMZP_ARRAY:
        nmzp_buf_str(o, "[");
        for (i = 0; i < v->n; i++) {
            if (i) nmzp_buf_str(o, ", ");
            typed(o, v->items[i]);
        }
        nmzp_buf_str(o, "]");
        break;
    case NMZP_MAP:
        nmzp_buf_str(o, "{\"map\": [");
        for (i = 0; i < v->n; i++) {
            if (i) nmzp_buf_str(o, ", ");
            nmzp_buf_str(o, "[");
            nmzp_json_escape(o, v->items[i]->key, strlen(v->items[i]->key));
            nmzp_buf_str(o, ", ");
            typed(o, v->items[i]);
            nmzp_buf_str(o, "]");
        }
        nmzp_buf_str(o, "]}");
        break;
    }
}

/* any JSON, written the way typed() writes (for comparing descriptions) */
static void rejson(nmzp_buf *o, const nmzp_json *j) {
    size_t i;
    switch (j->type) {
    case NMZP_JSON_NULL: nmzp_buf_str(o, "null"); break;
    case NMZP_JSON_TRUE: nmzp_buf_str(o, "true"); break;
    case NMZP_JSON_FALSE: nmzp_buf_str(o, "false"); break;
    case NMZP_JSON_NUMBER: nmzp_buf_printf(o, "%.17g", j->number); break;
    case NMZP_JSON_STRING: nmzp_json_escape(o, j->string, j->len); break;
    case NMZP_JSON_ARRAY:
        nmzp_buf_str(o, "[");
        for (i = 0; i < j->n; i++) {
            if (i) nmzp_buf_str(o, ", ");
            rejson(o, j->items[i]);
        }
        nmzp_buf_str(o, "]");
        break;
    case NMZP_JSON_OBJECT:
        nmzp_buf_str(o, "{");
        for (i = 0; i < j->n; i++) {
            if (i) nmzp_buf_str(o, ", ");
            nmzp_json_escape(o, j->items[i]->key, strlen(j->items[i]->key));
            nmzp_buf_str(o, ": ");
            rejson(o, j->items[i]);
        }
        nmzp_buf_str(o, "}");
        break;
    }
}

/* ------------------------------------------------- typed JSON (encode) */

static int unhex(const char *h, nmzp_buf *out) {
    size_t i, n = strlen(h);
    if (n % 2) return -1;
    for (i = 0; i < n; i += 2) {
        unsigned char b = 0;
        int k;
        for (k = 0; k < 2; k++) {
            char c = h[i + k];
            b = (unsigned char)(b << 4);
            if (c >= '0' && c <= '9') b = (unsigned char)(b | (c - '0'));
            else if (c >= 'a' && c <= 'f') b = (unsigned char)(b | (c - 'a' + 10));
            else if (c >= 'A' && c <= 'F') b = (unsigned char)(b | (c - 'A' + 10));
            else return -1;
        }
        nmzp_buf_add(out, &b, 1);
    }
    return 0;
}

static int encode_typed(nmzp_mw *w, const nmzp_json *j) {
    size_t i;
    switch (j->type) {
    case NMZP_JSON_NULL: nmzp_mw_nil(w); return 0;
    case NMZP_JSON_TRUE: nmzp_mw_bool(w, 1); return 0;
    case NMZP_JSON_FALSE: nmzp_mw_bool(w, 0); return 0;
    case NMZP_JSON_STRING: nmzp_mw_strn(w, j->string, j->len); return 0;
    case NMZP_JSON_ARRAY:
        nmzp_mw_arr(w);
        for (i = 0; i < j->n; i++)
            if (encode_typed(w, j->items[i])) return -1;
        nmzp_mw_end_arr(w);
        return 0;
    case NMZP_JSON_NUMBER: return -1; /* numbers are typed objects */
    case NMZP_JSON_OBJECT: break;
    }
    if (nmzp_json_get_str(j, "int")) {
        nmzp_mw_int(w, strtoll(nmzp_json_get_str(j, "int"), NULL, 10));
        return 0;
    }
    if (nmzp_json_get(j, "float") && nmzp_json_get_str(j, "bits")) {
        unsigned long long bits = strtoull(nmzp_json_get_str(j, "bits"), NULL, 16);
        double d;
        memcpy(&d, &bits, 8);
        if (isfinite(d)) nmzp_mw_float(w, d);
        else { /* a non-finite float as written: its bits */
            unsigned char b[9];
            int k;
            b[0] = 0xcb;
            for (k = 0; k < 8; k++) b[1 + k] = (unsigned char)(bits >> (56 - 8 * k));
            nmzp_mw_raw(w, b, 9);
        }
        return 0;
    }
    if (nmzp_json_get(j, "float32") && nmzp_json_get_str(j, "bits")) {
        unsigned long bits = strtoul(nmzp_json_get_str(j, "bits"), NULL, 16);
        uint32_t b32 = (uint32_t)bits;
        float f;
        memcpy(&f, &b32, 4);
        nmzp_mw_float32(w, f);
        return 0;
    }
    if (nmzp_json_get_str(j, "bin")) {
        nmzp_buf b;
        int r;
        nmzp_buf_init(&b);
        r = unhex(nmzp_json_get_str(j, "bin"), &b);
        nmzp_mw_bin(w, b.data ? b.data : "", b.len);
        nmzp_buf_free(&b);
        return r;
    }
    if (nmzp_json_get(j, "map")) {
        const nmzp_json *m = nmzp_json_get(j, "map");
        nmzp_mw_map(w);
        for (i = 0; i < m->n; i++) {
            const nmzp_json *pair = m->items[i];
            if (pair->type != NMZP_JSON_ARRAY || pair->n != 2 || pair->items[0]->type != NMZP_JSON_STRING) return -1;
            nmzp_mw_key(w, pair->items[0]->string);
            if (encode_typed(w, pair->items[1])) return -1;
        }
        nmzp_mw_end_map(w);
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------- files */

static void path_of(char *out, size_t n, const char *name, const char *ext) {
    snprintf(out, n, "%s/%s%s", g_dir, name, ext);
}

static int write_file(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(p, 1, n, f) != n) {
        if (f) fclose(f);
        fprintf(stderr, "cannot write %s\n", path);
        g_fail++;
        return -1;
    }
    fclose(f);
    return 0;
}

static char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    char *b;
    long len;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0 || !(b = malloc((size_t)len + 1))) {
        fclose(f);
        return NULL;
    }
    if (fread(b, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        free(b);
        return NULL;
    }
    fclose(f);
    b[len] = '\0';
    *n = (size_t)len;
    return b;
}

static void index_add(const char *name, const char *group) {
    nmzp_buf_printf(&g_index, "%s\n    {\"name\": \"%s\", \"group\": \"%s\"}", g_first_index ? "" : ",", name, group);
    g_first_index = 0;
}

/* NAME.bin and NAME.json (description: a JSON object's members, without braces) */
static void emit(const char *name, const char *group, const void *bytes, size_t n, const char *members) {
    char path[1024];
    nmzp_buf j;
    nmzp_buf_init(&j);
    nmzp_buf_printf(&j, "{\"name\": \"%s\", \"group\": \"%s\", \"size\": %lu, %s}\n", name, group, (unsigned long)n,
                    members);
    path_of(path, sizeof path, name, ".bin");
    write_file(path, bytes, n);
    path_of(path, sizeof path, name, ".json");
    write_file(path, j.data, j.len);
    nmzp_buf_free(&j);
    index_add(name, group);
}

/* a valid value: the bytes are the writer's; the description is what they decode to */
static void value_vector(const char *name, const char *group, const nmzp_buf *bytes, const char *note) {
    char err[200];
    nmzp_val *v = nmzp_decode_value(bytes->data, bytes->len, err, sizeof err);
    nmzp_buf m, esc;
    if (!v) {
        fprintf(stderr, "vector %s does not decode: %s\n", name, err);
        g_fail++;
        return;
    }
    nmzp_buf_init(&m);
    nmzp_buf_init(&esc);
    nmzp_json_escape(&esc, note, strlen(note));
    nmzp_buf_printf(&m, "\"canonical\": true, \"note\": %s, \"value\": ", esc.data);
    typed(&m, v);
    emit(name, group, bytes->data, bytes->len, m.data);
    nmzp_buf_free(&m);
    nmzp_buf_free(&esc);
    nmzp_val_free(v);
}

/* bytes given in hex: accepted but not canonical (canonical_hex: how a writer writes it) */
static void noncanonical_vector(const char *name, const char *hex, const char *note) {
    nmzp_buf b, m, c, esc;
    nmzp_mw w;
    char err[200], *ch;
    nmzp_val *v;
    nmzp_buf_init(&b);
    unhex(hex, &b);
    if (!(v = nmzp_decode_value(b.data, b.len, err, sizeof err))) {
        fprintf(stderr, "vector %s does not decode: %s\n", name, err);
        g_fail++;
        nmzp_buf_free(&b);
        return;
    }
    nmzp_buf_init(&m);
    nmzp_buf_init(&c);
    nmzp_buf_init(&esc);
    nmzp_mw_init(&w, &c);
    nmzp_mw_val(&w, v);
    ch = malloc(c.len * 2 + 1);
    nmzp_hex((const unsigned char *)c.data, c.len, ch);
    nmzp_json_escape(&esc, note, strlen(note));
    nmzp_buf_printf(&m, "\"canonical\": false, \"canonical_hex\": \"%s\", \"note\": %s, \"value\": ", ch, esc.data);
    typed(&m, v);
    emit(name, "value", b.data, b.len, m.data);
    free(ch);
    nmzp_val_free(v);
    nmzp_buf_free(&b);
    nmzp_buf_free(&m);
    nmzp_buf_free(&c);
    nmzp_buf_free(&esc);
}

/* bytes a reader must refuse */
static void invalid_vector(const char *name, const char *group, const void *bytes, size_t n, const char *rule) {
    char members[400], err[200];
    nmzp_val *v = !strcmp(group, "payload-invalid") ? nmzp_decode(bytes, n, err, sizeof err)
                                                     : nmzp_decode_value(bytes, n, err, sizeof err);
    if (v) {
        fprintf(stderr, "invalid vector %s decodes\n", name);
        g_fail++;
        nmzp_val_free(v);
    }
    snprintf(members, sizeof members, "\"rule\": \"%s\"", rule);
    emit(name, group, bytes, n, members);
}

static void invalid_hex(const char *name, const char *group, const char *hex, const char *rule) {
    nmzp_buf b;
    nmzp_buf_init(&b);
    unhex(hex, &b);
    invalid_vector(name, group, b.data ? b.data : "", b.len, rule);
    nmzp_buf_free(&b);
}

/* ------------------------------------------------------- the values */

static void one(const char *name, const char *note, void (*fill)(nmzp_mw *, long long), long long arg) {
    nmzp_buf b;
    nmzp_mw w;
    nmzp_buf_init(&b);
    nmzp_mw_init(&w, &b);
    fill(&w, arg);
    value_vector(name, "value", &b, note);
    nmzp_buf_free(&b);
}

static void f_nil(nmzp_mw *w, long long a) { (void)a, nmzp_mw_nil(w); }
static void f_bool(nmzp_mw *w, long long a) { nmzp_mw_bool(w, (int)a); }
static void f_int(nmzp_mw *w, long long a) { nmzp_mw_int(w, a); }
static void f_str_n(nmzp_mw *w, long long n) {
    char *s = malloc((size_t)n + 1);
    long long i;
    for (i = 0; i < n; i++) s[i] = (char)('a' + i % 26);
    nmzp_mw_strn(w, s, (size_t)n);
    free(s);
}
static void f_bin_n(nmzp_mw *w, long long n) {
    unsigned char *s = malloc((size_t)n + 1);
    long long i;
    for (i = 0; i < n; i++) s[i] = (unsigned char)(i * 7);
    nmzp_mw_bin(w, s, (size_t)n);
    free(s);
}
static void f_arr_n(nmzp_mw *w, long long n) {
    long long i;
    nmzp_mw_arr(w);
    for (i = 0; i < n; i++) nmzp_mw_int(w, i % 128);
    nmzp_mw_end_arr(w);
}
static void f_map_n(nmzp_mw *w, long long n) {
    long long i;
    nmzp_mw_map(w);
    for (i = 0; i < n; i++) {
        char k[16];
        snprintf(k, sizeof k, "k%02lld", i);
        nmzp_mw_kint(w, k, i);
    }
    nmzp_mw_end_map(w);
}
static void f_nest(nmzp_mw *w, long long n) {
    long long i;
    for (i = 0; i < n; i++) nmzp_mw_arr(w);
    for (i = 0; i < n; i++) nmzp_mw_end_arr(w);
}

static void floats(void) {
    static const struct {
        const char *name;
        double v;
        const char *note;
    } k[] = {{"float-zero", 0.0, "0.0 (float 64, never an int)"},
             {"float-negative-zero", -0.0, "-0.0"},
             {"float-1.5", 1.5, "1.5"},
             {"float-0.1", 0.1, "0.1, not exact in binary"},
             {"float-minus-2.25", -2.25, "-2.25"},
             {"float-1e300", 1e300, "1e300"},
             {"float-subnormal", 4.9406564584124654e-324, "the smallest subnormal"},
             {"float-max-float32", 3.4028234663852886e38, "the largest float32, as float 64"}};
    size_t i;
    for (i = 0; i < sizeof k / sizeof k[0]; i++) {
        nmzp_buf b;
        nmzp_mw w;
        nmzp_buf_init(&b);
        nmzp_mw_init(&w, &b);
        nmzp_mw_float(&w, k[i].v);
        value_vector(k[i].name, "value", &b, k[i].note);
        nmzp_buf_free(&b);
    }
}

static void strings(void) {
    static const struct {
        const char *name, *s, *note;
    } k[] = {{"str-utf8-2", "\xc3\xa9", "U+00E9, two bytes"},
             {"str-utf8-3", "\xe2\x82\xac", "U+20AC, three bytes"},
             {"str-utf8-4", "\xf0\x9f\x98\x80", "U+1F600, four bytes"},
             {"str-arabic", "\xd9\x86\xd9\x88\xd8\xb1", "Arabic letters"}};
    size_t i;
    for (i = 0; i < sizeof k / sizeof k[0]; i++) {
        nmzp_buf b;
        nmzp_mw w;
        nmzp_buf_init(&b);
        nmzp_mw_init(&w, &b);
        nmzp_mw_str(&w, k[i].s);
        value_vector(k[i].name, "value", &b, k[i].note);
        nmzp_buf_free(&b);
    }
    {
        nmzp_buf b;
        nmzp_mw w;
        nmzp_buf_init(&b);
        nmzp_mw_init(&w, &b);
        nmzp_mw_strn(&w, "a\0b", 3);
        value_vector("str-nul", "value", &b, "a str may hold U+0000");
        nmzp_buf_free(&b);
    }
}

static void f32s(void) {
    static const float v[] = {1.0f, -2.5f, 0.1f, 3.4028235e38f};
    nmzp_buf b;
    nmzp_mw w;
    nmzp_buf_init(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_key(&w, "outputs");
    nmzp_mw_f32(&w, v, 4);
    nmzp_mw_key(&w, "shape");
    nmzp_mw_arr(&w);
    nmzp_mw_int(&w, 2);
    nmzp_mw_int(&w, 2);
    nmzp_mw_end_arr(&w);
    nmzp_mw_end_map(&w);
    value_vector("payload-f32", "payload", &b, "a bin (f32): 1.0, -2.5, 0.1, 3.4028235e38 as little-endian float32");
    nmzp_buf_free(&b);
}

static void payloads(void) {
    nmzp_buf b;
    nmzp_mw w;
    unsigned char digest[32];
    static const char xor_csv[] = "0,0,0\n0,1,1\n1,0,1\n1,1,0\n";
    /* a request */
    nmzp_buf_init(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "op", "models.create");
    nmzp_mw_kstr(&w, "name", "xor");
    nmzp_mw_key(&w, "args");
    nmzp_mw_arr(&w);
    nmzp_mw_str(&w, "2");
    nmzp_mw_str(&w, "4");
    nmzp_mw_str(&w, "1");
    nmzp_mw_end_arr(&w);
    nmzp_mw_kstr(&w, "save", "server");
    nmzp_mw_end_map(&w);
    value_vector("payload-request-create", "payload", &b, "models.create, the program's arguments");
    /* training options */
    nmzp_buf_clear(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "op", "jobs.train");
    nmzp_mw_kstr(&w, "model", "xor");
    nmzp_mw_kstr(&w, "dataset", "xor");
    nmzp_mw_kstr(&w, "device", "auto");
    nmzp_mw_key(&w, "options");
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "epochs", 200);
    nmzp_mw_kfloat(&w, "lr", 0.5);
    nmzp_mw_kbool(&w, "shuffle", 0);
    nmzp_mw_kstr(&w, "optimizer", "adam");
    nmzp_mw_end_map(&w);
    nmzp_mw_kint(&w, "limit", 1000);
    nmzp_mw_end_map(&w);
    value_vector("payload-request-train", "payload", &b, "jobs.train with options of every type");
    /* an error */
    nmzp_buf_clear(&b);
    nmzp_error_payload(&b, NMZP_E_INVALID_ARGUMENT, "--lr needs a positive number, got '-1'", NULL, 0);
    value_vector("payload-error", "payload", &b, "an ERROR payload");
    /* an END */
    nmzp_buf_clear(&b);
    nmzp_sha256_of(xor_csv, sizeof xor_csv - 1, digest);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "size", (long long)(sizeof xor_csv - 1));
    nmzp_mw_kbin(&w, "sha256", digest, 32);
    nmzp_mw_end_map(&w);
    value_vector("payload-end", "payload", &b, "an END: the size and SHA-256 of 0,0,0\\n0,1,1\\n1,0,1\\n1,1,0\\n");
    /* an event, with nil and floats */
    nmzp_buf_clear(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "event", "epoch");
    nmzp_mw_kint(&w, "seq", 2);
    nmzp_mw_key(&w, "data");
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "epoch", 1);
    nmzp_mw_kfloat(&w, "loss", 2.05);
    nmzp_mw_kfloat(&w, "accuracy", 0.41);
    nmzp_mw_knil(&w, "val_loss");
    nmzp_mw_knil(&w, "val_accuracy");
    nmzp_mw_kfloat(&w, "learning_rate", 0.01);
    nmzp_mw_kint(&w, "clipped_batches", 0);
    nmzp_mw_kbool(&w, "improved", 1);
    nmzp_mw_kfloat(&w, "elapsed_s", 0.71);
    nmzp_mw_end_map(&w);
    nmzp_mw_end_map(&w);
    value_vector("payload-event-epoch", "payload", &b, "an EVENT: an epoch");
    nmzp_buf_free(&b);
    f32s();
}

/* --------------------------------------------------------- the frames */

static const char k_token[] = "nmz_0123456789abcdef0123456789abcdef0123456789abcdef";

static void nonces(unsigned char ns[32], unsigned char nc[32]) {
    int i;
    for (i = 0; i < 32; i++) {
        ns[i] = (unsigned char)(0x10 + i);
        nc[i] = (unsigned char)(0xa0 + i);
    }
}

/* a frame vector: the header's fields, the prefix (handshake), the payload typed or in hex */
static void frame_vector(const char *name, int type, int flags, uint32_t id, int with_prefix, const nmzp_buf *payload,
                         int raw, const char *note) {
    nmzp_buf f, m, esc;
    unsigned char pre[NMZP_PREFIX];
    nmzp_buf_init(&f);
    nmzp_buf_init(&m);
    nmzp_buf_init(&esc);
    {
        nmzp_buf whole;
        nmzp_buf_init(&whole);
        if (with_prefix) {
            nmzp_prefix_put(pre, NMZP_PROTOCOL_MAJOR, NMZP_PROTOCOL_MINOR);
            nmzp_buf_add(&whole, pre, sizeof pre);
        }
        nmzp_buf_add(&whole, payload->data ? payload->data : "", payload->len);
        nmzp_frame_put(&f, type, flags, id, whole.data ? whole.data : "", whole.len);
        nmzp_buf_free(&whole);
    }
    nmzp_json_escape(&esc, note, strlen(note));
    nmzp_buf_printf(&m, "\"note\": %s, \"type\": %d, \"type_name\": \"%s\", \"flags\": %d, \"id\": %lu, \"length\": %lu", esc.data,
                    type, nmzp_frame_name(type), flags, (unsigned long)id,
                    (unsigned long)(payload->len + (with_prefix ? NMZP_PREFIX : 0)));
    if (with_prefix) nmzp_buf_printf(&m, ", \"prefix\": {\"major\": %d, \"minor\": %d}", NMZP_PROTOCOL_MAJOR, NMZP_PROTOCOL_MINOR);
    if (raw) {
        char *hex = malloc(payload->len * 2 + 1);
        nmzp_hex((const unsigned char *)(payload->data ? payload->data : ""), payload->len, hex);
        nmzp_buf_printf(&m, ", \"payload_hex\": \"%s\"", hex);
        free(hex);
    } else {
        nmzp_val *v = nmzp_decode(payload->data, payload->len, NULL, 0);
        nmzp_buf_str(&m, ", \"payload\": ");
        if (v) typed(&m, v);
        else {
            nmzp_buf_str(&m, "null");
            fprintf(stderr, "frame vector %s: the payload does not decode\n", name);
            g_fail++;
        }
        nmzp_val_free(v);
    }
    emit(name, "frame", f.data, f.len, m.data);
    nmzp_buf_free(&f);
    nmzp_buf_free(&m);
    nmzp_buf_free(&esc);
}

static void frames(void) {
    nmzp_buf p;
    nmzp_mw w;
    unsigned char ns[32], nc[32], key[32], kid[8], pc[32], ps[32], digest[32];
    static const char xor_csv[] = "0,0,0\n0,1,1\n1,0,1\n1,1,0\n";
    nonces(ns, nc);
    nmzp_auth_key(k_token, strlen(k_token), key);
    nmzp_auth_key_id(key, kid);
    nmzp_auth_proof(key, 0, ns, nc, pc);
    nmzp_auth_proof(key, 1, ns, nc, ps);
    nmzp_buf_init(&p);
    /* GREETING */
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "server", "neuromz-server");
    nmzp_mw_kstr(&w, "version", "0.2.0");
    nmzp_mw_kint(&w, "min_major", 2);
    nmzp_mw_kstr(&w, "auth", "hmac-sha256");
    nmzp_mw_kbin(&w, "nonce", ns, 32);
    nmzp_mw_kint(&w, "max_frame", 4194304);
    nmzp_mw_key(&w, "capabilities");
    nmzp_mw_arr(&w);
    nmzp_mw_str(&w, "events");
    nmzp_mw_str(&w, "generate");
    nmzp_mw_str(&w, "trace");
    nmzp_mw_str(&w, "f32");
    nmzp_mw_end_arr(&w);
    nmzp_mw_kstr(&w, "status", "ok");
    nmzp_mw_end_map(&w);
    frame_vector("frame-greeting", NMZP_GREETING, 0, 0, 1, &p, 0, "the server's greeting (nonce Ns of auth.json)");
    /* HELLO */
    nmzp_buf_clear(&p);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "client", "neuromz-cli");
    nmzp_mw_kstr(&w, "version", "2.3.0");
    nmzp_mw_kstr(&w, "auth", "hmac-sha256");
    nmzp_mw_kbin(&w, "key_id", kid, 8);
    nmzp_mw_kbin(&w, "nonce", nc, 32);
    nmzp_mw_kbin(&w, "proof", pc, 32);
    nmzp_mw_end_map(&w);
    frame_vector("frame-hello", NMZP_HELLO, 0, 0, 1, &p, 0, "the client's hello: key id, nonce Nc and proof of auth.json");
    /* WELCOME */
    nmzp_buf_clear(&p);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "protocol", "2.0");
    nmzp_mw_kstr(&w, "user", "alice");
    nmzp_mw_key(&w, "permissions");
    nmzp_mw_arr(&w);
    nmzp_mw_str(&w, "read");
    nmzp_mw_str(&w, "train");
    nmzp_mw_end_arr(&w);
    nmzp_mw_kbin(&w, "proof", ps, 32);
    nmzp_mw_kstr(&w, "session", "c1");
    nmzp_mw_kint(&w, "max_frame", 4194304);
    nmzp_mw_kint(&w, "max_frame_out", 4194304);
    nmzp_mw_kint(&w, "max_inflight", 8);
    nmzp_mw_kint(&w, "idle_timeout", 300);
    nmzp_mw_end_map(&w);
    frame_vector("frame-welcome", NMZP_WELCOME, 0, 0, 0, &p, 0, "the server's welcome, with its proof");
    /* a request and its response */
    nmzp_buf_clear(&p);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "op", "health");
    nmzp_mw_end_map(&w);
    frame_vector("frame-request", NMZP_REQUEST, 0, 1, 0, &p, 0, "REQUEST id 1: health");
    nmzp_buf_clear(&p);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "status", "ok");
    nmzp_mw_kstr(&w, "protocol", "2.0");
    nmzp_mw_end_map(&w);
    frame_vector("frame-response", NMZP_RESPONSE, 0, 1, 0, &p, 0, "its RESPONSE");
    /* an upload: REQUEST MORE, DATA, END */
    nmzp_buf_clear(&p);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "op", "datasets.upload");
    nmzp_mw_kstr(&w, "name", "xor");
    nmzp_mw_kstr(&w, "format", "csv");
    nmzp_mw_kint(&w, "size", (long long)(sizeof xor_csv - 1));
    nmzp_mw_end_map(&w);
    frame_vector("frame-request-upload", NMZP_REQUEST, NMZP_MORE, 2, 0, &p, 0, "REQUEST id 2 with MORE: an upload follows");
    nmzp_buf_clear(&p);
    nmzp_buf_add(&p, xor_csv, sizeof xor_csv - 1);
    frame_vector("frame-data", NMZP_DATA, NMZP_MORE, 2, 0, &p, 1, "DATA of request 2: the file's bytes");
    nmzp_buf_clear(&p);
    nmzp_sha256_of(xor_csv, sizeof xor_csv - 1, digest);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "size", (long long)(sizeof xor_csv - 1));
    nmzp_mw_kbin(&w, "sha256", digest, 32);
    nmzp_mw_end_map(&w);
    frame_vector("frame-end", NMZP_END, 0, 2, 0, &p, 0, "END of request 2's stream");
    /* a download's head */
    nmzp_buf_clear(&p);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "name", "xor");
    nmzp_mw_kint(&w, "version", 3);
    nmzp_mw_kint(&w, "size", 1404);
    nmzp_mw_kstr(&w, "storage", "server");
    nmzp_mw_end_map(&w);
    frame_vector("frame-response-more", NMZP_RESPONSE, NMZP_MORE, 5, 0, &p, 0, "RESPONSE with MORE: a download's head");
    /* errors */
    nmzp_buf_clear(&p);
    nmzp_error_payload(&p, NMZP_E_NOT_FOUND, "no model named 'nope'", NULL, 0);
    frame_vector("frame-error", NMZP_ERROR, 0, 3, 0, &p, 0, "ERROR ending request 3");
    nmzp_buf_clear(&p);
    nmzp_error_payload(&p, NMZP_E_UNAUTHORIZED, "the token is not valid", NULL, 0);
    frame_vector("frame-error-connection", NMZP_ERROR, 0, 0, 0, &p, 0, "ERROR with id 0: about the connection, which closes");
    /* an event */
    nmzp_buf_clear(&p);
    nmzp_mw_init(&w, &p);
    nmzp_mw_map(&w);
    nmzp_mw_kstr(&w, "event", "batch");
    nmzp_mw_kint(&w, "seq", 0);
    nmzp_mw_key(&w, "data");
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "epoch", 1);
    nmzp_mw_kint(&w, "batch", 20);
    nmzp_mw_kint(&w, "batches", 127);
    nmzp_mw_kfloat(&w, "loss", 2.31);
    nmzp_mw_kfloat(&w, "learning_rate", 0.01);
    nmzp_mw_end_map(&w);
    nmzp_mw_end_map(&w);
    frame_vector("frame-event", NMZP_EVENT, NMZP_MORE, 4, 0, &p, 0, "EVENT with MORE: a live batch event of subscription 4");
    nmzp_buf_clear(&p);
    frame_vector("frame-abort", NMZP_ABORT, 0, 4, 0, &p, 1, "ABORT of request 4 (unsubscribe): an empty payload");
    nmzp_buf_clear(&p);
    nmzp_buf_add(&p, "abcd", 4);
    frame_vector("frame-ping", NMZP_PING, 0, 0, 0, &p, 1, "PING with 4 bytes");
    frame_vector("frame-pong", NMZP_PONG, 0, 0, 0, &p, 1, "its PONG");
    nmzp_buf_free(&p);
}

static void frame_invalid(const char *name, const unsigned char *bytes, size_t n, const char *expect, uint32_t max,
                          const char *note) {
    char members[500];
    snprintf(members, sizeof members, "\"note\": \"%s\", \"max_frame\": %lu, \"expect\": \"%s\"", note, (unsigned long)max,
             expect);
    emit(name, "frame-invalid", bytes, n, members);
}

static void frames_invalid(void) {
    unsigned char b[64];
    nmzp_head_encode(b, NMZP_REQUEST, 0x02, 1, 0);
    frame_invalid("frame-bad-flags", b, 12, "protocol_error", 65536, "flag bit 1 is not defined");
    nmzp_head_encode(b, NMZP_REQUEST, 0, 1, 0);
    b[6] = 1;
    frame_invalid("frame-bad-reserved", b, 12, "protocol_error", 65536, "the reserved bytes are not zero");
    nmzp_head_encode(b, 0x7f, 0, 1, 0);
    frame_invalid("frame-unknown-type", b, 12, "unknown_frame", 65536, "type 0x7f is not defined");
    nmzp_head_encode(b, 0x04, 0, 0, 0);
    frame_invalid("frame-reserved-type", b, 12, "unknown_frame", 65536, "type 0x04 is reserved (STARTTLS, later)");
    nmzp_head_encode(b, NMZP_REQUEST, 0, 1, 65537);
    frame_invalid("frame-too-large", b, 12, "frame_too_large", 65536,
                  "65537 bytes announced, over a limit of 65536: refused from the header alone");
    nmzp_head_encode(b, NMZP_DATA, NMZP_MORE, 1, 10);
    memcpy(b + 12, "abc", 3);
    frame_invalid("frame-truncated", b, 15, "incomplete", 65536, "10 bytes announced, 3 present: not a frame yet");
    memcpy(b, "GET /v1/health HTTP/1.1\r\n", 25);
    frame_invalid("frame-http", b, 25, "frame_too_large", 65536,
                  "an HTTP request read as a frame header: 542393671 bytes announced");
    { /* a hello whose payload lacks the magic */
        nmzp_buf f, p;
        unsigned char pre[NMZP_PREFIX];
        nmzp_mw w;
        nmzp_buf_init(&f);
        nmzp_buf_init(&p);
        nmzp_prefix_put(pre, 2, 0);
        pre[0] = 'X';
        nmzp_buf_add(&p, pre, sizeof pre);
        nmzp_mw_init(&w, &p);
        nmzp_mw_map(&w);
        nmzp_mw_kstr(&w, "client", "x");
        nmzp_mw_end_map(&w);
        nmzp_frame_put(&f, NMZP_HELLO, 0, 0, p.data, p.len);
        frame_invalid("hello-bad-magic", (const unsigned char *)f.data, f.len, "bad_magic", 65536,
                      "a well-formed HELLO frame whose payload does not start with the magic");
        nmzp_buf_free(&f);
        nmzp_buf_free(&p);
    }
}

/* ----------------------------------------------------------- auth.json */

static void hexs(nmzp_buf *o, const char *k, const unsigned char *p, size_t n, int last) {
    char h[200];
    nmzp_hex(p, n, h);
    nmzp_buf_printf(o, "  \"%s\": \"%s\"%s\n", k, h, last ? "" : ",");
}

static void auth_vectors(int write) {
    unsigned char ns[32], nc[32], key[32], kid[8], pc[32], ps[32];
    nmzp_buf o;
    static const struct {
        const char *key, *data, *mac;
    } rfc[] = { /* RFC 4231 test cases 1, 2, 3, 4, 6, 7 (hex) */
                {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                 "4869205468657265",
                 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
                {"4a656665",
                 "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
                 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
                {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                 "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
                {"0102030405060708090a0b0c0d0e0f10111213141516171819",
                 "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                 "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
                {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
                 "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
                {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
                 "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"}};
    size_t i;
    nonces(ns, nc);
    nmzp_auth_key(k_token, strlen(k_token), key);
    nmzp_auth_key_id(key, kid);
    nmzp_auth_proof(key, 0, ns, nc, pc);
    nmzp_auth_proof(key, 1, ns, nc, ps);
    /* the RFC's cases, through this implementation */
    for (i = 0; i < sizeof rfc / sizeof rfc[0]; i++) {
        nmzp_buf k, d;
        unsigned char mac[32];
        char hex[65];
        nmzp_buf_init(&k);
        nmzp_buf_init(&d);
        unhex(rfc[i].key, &k);
        unhex(rfc[i].data, &d);
        nmzp_hmac_sha256(k.data, k.len, d.data, d.len, mac);
        nmzp_hex(mac, 32, hex);
        g_checked++;
        if (strcmp(hex, rfc[i].mac)) {
            fprintf(stderr, "HMAC-SHA256: RFC 4231 case %lu gives %s\n", (unsigned long)i + 1, hex);
            g_fail++;
        }
        nmzp_buf_free(&k);
        nmzp_buf_free(&d);
    }
    nmzp_buf_init(&o);
    nmzp_buf_printf(&o, "{\n  \"note\": \"PROTOCOL 6.1: K = SHA-256(token); key_id = HMAC-SHA256(K, 'neuromz key id')[0..8]; "
                        "proof_c = HMAC-SHA256(K, 'neuromz client proof' || Ns || Nc); proof_s = HMAC-SHA256(K, 'neuromz "
                        "server proof' || Ns || Nc)\",\n");
    nmzp_buf_printf(&o, "  \"token\": \"%s\",\n", k_token);
    hexs(&o, "K", key, 32, 0);
    hexs(&o, "key_id", kid, 8, 0);
    hexs(&o, "Ns", ns, 32, 0);
    hexs(&o, "Nc", nc, 32, 0);
    hexs(&o, "proof_c", pc, 32, 0);
    hexs(&o, "proof_s", ps, 32, 0);
    nmzp_buf_str(&o, "  \"hmac_sha256_rfc4231\": [\n");
    for (i = 0; i < sizeof rfc / sizeof rfc[0]; i++)
        nmzp_buf_printf(&o, "    {\"key\": \"%s\", \"data\": \"%s\", \"mac\": \"%s\"}%s\n", rfc[i].key, rfc[i].data, rfc[i].mac,
                        i + 1 < sizeof rfc / sizeof rfc[0] ? "," : "");
    nmzp_buf_str(&o, "  ]\n}\n");
    if (write) {
        char path[1024];
        path_of(path, sizeof path, "auth", ".json");
        write_file(path, o.data, o.len);
    } else { /* check the committed file's derivation */
        char path[1024];
        size_t n;
        char *text;
        nmzp_json *j;
        path_of(path, sizeof path, "auth", ".json");
        text = read_file(path, &n);
        j = text ? nmzp_json_parse(text, n, 0, NULL, 0) : NULL;
        g_checked++;
        if (!j) {
            fprintf(stderr, "auth.json: missing or not JSON\n");
            g_fail++;
        } else {
            static const char *const keys[] = {"K", "key_id", "Ns", "Nc", "proof_c", "proof_s", NULL};
            nmzp_buf have;
            const char *tok = nmzp_json_get_str(j, "token");
            int k;
            nmzp_buf_init(&have);
            if (!tok || strcmp(tok, k_token)) {
                fprintf(stderr, "auth.json: another token\n");
                g_fail++;
            }
            for (k = 0; keys[k]; k++) {
                char line[200];
                const char *v = nmzp_json_get_str(j, keys[k]);
                snprintf(line, sizeof line, "  \"%s\": \"%s\"", keys[k], v ? v : "");
                if (!strstr(o.data, line)) {
                    fprintf(stderr, "auth.json: %s differs from this implementation\n", keys[k]);
                    g_fail++;
                }
            }
            nmzp_buf_free(&have);
        }
        nmzp_json_free(j);
        free(text);
    }
    nmzp_buf_free(&o);
}

/* ----------------------------------------------------------- writing */

static void write_all(void) {
    static const long long ints[] = {0, 1, 127, 128, 255, 256, 65535, 65536, 4294967295LL, 4294967296LL,
                                     9223372036854775807LL, -1, -32, -33, -128, -129, -32768, -32769,
                                     -2147483647LL - 1, -2147483649LL, -9223372036854775807LL - 1};
    size_t i;
    char name[64], note[100];
    nmzp_buf_init(&g_index);
    one("nil", "nil", f_nil, 0);
    one("false", "false", f_bool, 0);
    one("true", "true", f_bool, 1);
    for (i = 0; i < sizeof ints / sizeof ints[0]; i++) {
        snprintf(name, sizeof name, "int-%lld", ints[i]);
        snprintf(note, sizeof note, "%lld in its shortest form", ints[i]);
        one(name, note, f_int, ints[i]);
    }
    floats();
    one("str-empty", "an empty str (fixstr)", f_str_n, 0);
    one("str-31", "31 bytes: the longest fixstr", f_str_n, 31);
    one("str-32", "32 bytes: str 8", f_str_n, 32);
    one("str-255", "255 bytes: the longest str 8", f_str_n, 255);
    one("str-256", "256 bytes: str 16", f_str_n, 256);
    one("str-65536", "65536 bytes: str 32", f_str_n, 65536);
    strings();
    one("bin-empty", "an empty bin (bin 8)", f_bin_n, 0);
    one("bin-255", "255 bytes: the longest bin 8", f_bin_n, 255);
    one("bin-256", "256 bytes: bin 16", f_bin_n, 256);
    one("bin-65536", "65536 bytes: bin 32", f_bin_n, 65536);
    one("array-empty", "[] (fixarray)", f_arr_n, 0);
    one("array-15", "15 values: the longest fixarray", f_arr_n, 15);
    one("array-16", "16 values: array 16", f_arr_n, 16);
    one("map-empty", "{} (fixmap)", f_map_n, 0);
    one("map-15", "15 pairs: the longest fixmap", f_map_n, 15);
    one("map-16", "16 pairs: map 16", f_map_n, 16);
    one("nested-32", "32 nested arrays: the deepest allowed", f_nest, 32);
    /* accepted, not canonical */
    noncanonical_vector("noncanonical-uint8-5", "cc05", "5 as uint 8 (canonical: positive fixint)");
    noncanonical_vector("noncanonical-uint64-5", "cf0000000000000005", "5 as uint 64");
    noncanonical_vector("noncanonical-int8-5", "d005", "5 as int 8");
    noncanonical_vector("noncanonical-int64-minus-1", "d3ffffffffffffffff", "-1 as int 64");
    noncanonical_vector("noncanonical-float32", "ca3fc00000", "1.5 as float 32 (canonical: float 64)");
    noncanonical_vector("noncanonical-str8-a", "d90161", "\"a\" as str 8");
    noncanonical_vector("noncanonical-str32-abc", "db00000003616263", "\"abc\" as str 32");
    noncanonical_vector("noncanonical-bin32", "c6000000020102", "a 2-byte bin as bin 32");
    noncanonical_vector("noncanonical-array32", "dd000000020102", "[1, 2] as array 32");
    noncanonical_vector("noncanonical-map16", "de0001a16101", "{a: 1} as map 16");
    noncanonical_vector("noncanonical-map32", "df00000001a16101", "{a: 1} as map 32");
    noncanonical_vector("noncanonical-float-nan", "cb7ff8000000000000", "a NaN: readers accept it (writers send nil for a number that is not finite)");
    payloads();
    /* refused */
    invalid_hex("invalid-empty", "value-invalid", "", "no value");
    invalid_hex("invalid-c1", "value-invalid", "c1", "the byte c1");
    invalid_hex("invalid-fixext1", "value-invalid", "d40001", "an extension type (fixext 1)");
    invalid_hex("invalid-ext8", "value-invalid", "c7010001", "an extension type (ext 8)");
    invalid_hex("invalid-timestamp", "value-invalid", "d6ff00000000", "MessagePack's timestamp (an extension)");
    invalid_hex("invalid-truncated-uint16", "value-invalid", "cd01", "uint 16 with one byte");
    invalid_hex("invalid-truncated-str", "value-invalid", "a56162", "a fixstr of 5 with 2 bytes");
    invalid_hex("invalid-truncated-array", "value-invalid", "9201", "a fixarray of 2 with 1 value");
    invalid_hex("invalid-truncated-map", "value-invalid", "81a161", "a pair without its value");
    invalid_hex("invalid-trailing", "value-invalid", "0102", "a byte after the value");
    invalid_hex("invalid-utf8-bad-byte", "value-invalid", "a2c328", "a str that is not UTF-8");
    invalid_hex("invalid-utf8-overlong", "value-invalid", "a2c080", "an overlong encoding of U+0000");
    invalid_hex("invalid-utf8-surrogate", "value-invalid", "a3eda080", "U+D800, a surrogate");
    invalid_hex("invalid-utf8-too-high", "value-invalid", "a4f4908080", "above U+10FFFF");
    invalid_hex("invalid-utf8-continuation", "value-invalid", "a180", "a stray continuation byte");
    invalid_hex("invalid-key-not-str", "value-invalid", "810102", "a map key that is an int");
    invalid_hex("invalid-key-duplicate", "value-invalid", "82a16101a16102", "the key a twice");
    invalid_hex("invalid-key-nul", "value-invalid", "81a20061" "01", "a key with U+0000");
    invalid_hex("invalid-uint64-too-big", "value-invalid", "cf8000000000000000", "2^63: above the int range");
    invalid_hex("invalid-array32-bomb", "value-invalid", "ddffffffff", "4294967295 values claimed, none present");
    invalid_hex("invalid-str32-bomb", "value-invalid", "dbffffffff61", "a str of 4294967295 bytes claimed");
    {
        unsigned char deep[33];
        memset(deep, 0x91, 32);
        deep[32] = 0x90;
        invalid_vector("invalid-nested-33", "value-invalid", deep, 33, "33 nested arrays");
    }
    { /* 262145 values in one array */
        size_t n = 5 + 262144;
        unsigned char *b = calloc(n, 1);
        b[0] = 0xdd;
        b[1] = 0x00;
        b[2] = 0x04;
        b[3] = 0x00;
        b[4] = 0x00; /* 262144 values + the array = 262145 */
        invalid_vector("invalid-too-many-values", "value-invalid", b, n, "262145 values (the array and 262144 ints)");
        free(b);
    }
    invalid_hex("payload-not-map-int", "payload-invalid", "01", "a payload that is not a map");
    invalid_hex("payload-not-map-array", "payload-invalid", "90", "a payload that is an array");
    invalid_hex("payload-empty", "payload-invalid", "", "an empty payload");
    invalid_hex("payload-two-maps", "payload-invalid", "8080", "two maps");
    frames();
    frames_invalid();
    auth_vectors(1);
    {
        char path[1024];
        nmzp_buf ix;
        nmzp_buf_init(&ix);
        nmzp_buf_printf(&ix, "{\n  \"protocol\": \"%s\",\n  \"note\": \"PROTOCOL.md section 17; values are typed JSON (see vectors.c)\",\n  \"vectors\": [%s\n  ]\n}\n",
                        NMZP_PROTOCOL, g_index.data);
        path_of(path, sizeof path, "index", ".json");
        write_file(path, ix.data, ix.len);
        nmzp_buf_free(&ix);
    }
    nmzp_buf_free(&g_index);
}

/* ----------------------------------------------------------- checking */

static void fail(const char *name, const char *what) {
    fprintf(stderr, "FAIL %s: %s\n", name, what);
    g_fail++;
}

static int bytes_equal(const nmzp_buf *a, const char *b, size_t bn) { return a->len == bn && !memcmp(a->data, b, bn); }

static void check_value(const char *name, const nmzp_json *d, const nmzp_json *val, const char *bin, size_t n,
                        int is_payload) {
    char err[200];
    nmzp_val *v = is_payload ? nmzp_decode(bin, n, err, sizeof err) : nmzp_decode_value(bin, n, err, sizeof err);
    nmzp_buf a, b, enc;
    nmzp_mw w;
    int canonical = 1;
    if (!v) {
        fail(name, err);
        return;
    }
    nmzp_buf_init(&a);
    nmzp_buf_init(&b);
    nmzp_buf_init(&enc);
    typed(&a, v);
    if (val) rejson(&b, val);
    if (!val || strcmp(a.data, b.data)) fail(name, "decodes to another value than the description says");
    nmzp_json_get_bool(d, "canonical", &canonical);
    nmzp_mw_init(&w, &enc);
    if (!val || encode_typed(&w, val) || nmzp_mw_done(&w)) fail(name, "the description cannot be encoded");
    else if (canonical && !bytes_equal(&enc, bin, n)) fail(name, "the description encodes to other bytes");
    else if (!canonical) { /* the decoded value, written by a canonical writer */
        const char *ch = nmzp_json_get_str(d, "canonical_hex");
        nmzp_buf cw;
        char *hex;
        nmzp_buf_init(&cw);
        nmzp_mw_init(&w, &cw);
        nmzp_mw_val(&w, v);
        hex = malloc(cw.len * 2 + 1);
        nmzp_hex((const unsigned char *)cw.data, cw.len, hex);
        if (!ch || strcmp(ch, hex)) fail(name, "the canonical form differs from canonical_hex");
        free(hex);
        nmzp_buf_free(&cw);
    }
    nmzp_buf_free(&a);
    nmzp_buf_free(&b);
    nmzp_buf_free(&enc);
    nmzp_val_free(v);
}

static void check_frame(const char *name, const nmzp_json *d, const char *bin, size_t n) {
    nmzp_frame_head h;
    const unsigned char *payload;
    size_t used;
    int code = 0;
    double type = 0, flags = 0, id = 0, length = 0;
    nmzp_buf whole, f;
    nmzp_json_get_num(d, "type", &type);
    nmzp_json_get_num(d, "flags", &flags);
    nmzp_json_get_num(d, "id", &id);
    nmzp_json_get_num(d, "length", &length);
    if (nmzp_frame_next(bin, n, 0xffffffffu, &h, &payload, &used, &code) != 1 || used != n) {
        fail(name, "not one whole frame");
        return;
    }
    if (h.type != (int)type || h.flags != (int)flags || h.id != (uint32_t)id || h.length != (uint32_t)length)
        fail(name, "the header differs from the description");
    nmzp_buf_init(&whole);
    nmzp_buf_init(&f);
    if (nmzp_json_get(d, "prefix")) {
        unsigned char pre[NMZP_PREFIX];
        double ma = 0, mi = 0;
        int a = -1, b = -1;
        nmzp_json_get_num(nmzp_json_get(d, "prefix"), "major", &ma);
        nmzp_json_get_num(nmzp_json_get(d, "prefix"), "minor", &mi);
        nmzp_prefix_put(pre, (int)ma, (int)mi);
        nmzp_buf_add(&whole, pre, sizeof pre);
        if (nmzp_prefix_get(payload, h.length, &a, &b) || a != (int)ma || b != (int)mi) fail(name, "the prefix differs");
        if (h.length >= NMZP_PREFIX)
            check_value(name, d, nmzp_json_get(d, "payload"), (const char *)payload + NMZP_PREFIX, h.length - NMZP_PREFIX, 1);
    } else if (nmzp_json_get(d, "payload")) {
        check_value(name, d, nmzp_json_get(d, "payload"), (const char *)payload, h.length, 1);
    }
    if (nmzp_json_get_str(d, "payload_hex")) {
        unhex(nmzp_json_get_str(d, "payload_hex"), &whole);
    } else if (nmzp_json_get(d, "payload")) {
        nmzp_mw w;
        nmzp_mw_init(&w, &whole);
        encode_typed(&w, nmzp_json_get(d, "payload"));
    }
    nmzp_frame_put(&f, (int)type, (int)flags, (uint32_t)id, whole.data ? whole.data : "", whole.len);
    if (!bytes_equal(&f, bin, n)) fail(name, "the description builds another frame");
    nmzp_buf_free(&whole);
    nmzp_buf_free(&f);
}

static void check_frame_invalid(const char *name, const nmzp_json *d, const char *bin, size_t n) {
    const char *expect = nmzp_json_get_str(d, "expect");
    double max = 65536;
    nmzp_frame_head h;
    const unsigned char *payload;
    size_t used;
    int code = 0, r;
    nmzp_json_get_num(d, "max_frame", &max);
    r = nmzp_frame_next(bin, n, (uint32_t)max, &h, &payload, &used, &code);
    if (!expect) fail(name, "no expect");
    else if (!strcmp(expect, "incomplete")) {
        if (r != 0) fail(name, "taken for a whole frame");
    } else if (!strcmp(expect, "bad_magic")) {
        if (r != 1 || !nmzp_prefix_get(payload, h.length, NULL, NULL)) fail(name, "the bad magic is not noticed");
    } else if (r != -1 || !nmzp_error_name(code) || strcmp(nmzp_error_name(code), expect)) {
        fail(name, "not refused the way the description says");
    }
}

static int check_all(void) {
    char path[1024];
    size_t n, i;
    char *text;
    nmzp_json *ix;
    const nmzp_json *list;
    path_of(path, sizeof path, "index", ".json");
    if (!(text = read_file(path, &n)) || !(ix = nmzp_json_parse(text, n, 0, NULL, 0))) {
        fprintf(stderr, "cannot read %s\n", path);
        free(text);
        return 1;
    }
    free(text);
    list = nmzp_json_get(ix, "vectors");
    for (i = 0; list && i < list->n; i++) {
        const char *name = nmzp_json_get_str(list->items[i], "name"), *group = nmzp_json_get_str(list->items[i], "group");
        char *bin, *dtext;
        size_t bn, dn;
        nmzp_json *d;
        if (!name || !group) continue;
        path_of(path, sizeof path, name, ".bin");
        bin = read_file(path, &bn);
        path_of(path, sizeof path, name, ".json");
        dtext = read_file(path, &dn);
        d = dtext ? nmzp_json_parse(dtext, dn, 0, NULL, 0) : NULL;
        g_checked++;
        if (!bin || !d) fail(name, "the .bin or .json is missing or unreadable");
        else if (!strcmp(group, "value")) check_value(name, d, nmzp_json_get(d, "value"), bin, bn, 0);
        else if (!strcmp(group, "payload")) check_value(name, d, nmzp_json_get(d, "value"), bin, bn, 1);
        else if (!strcmp(group, "value-invalid") || !strcmp(group, "payload-invalid")) {
            nmzp_val *v = !strcmp(group, "payload-invalid") ? nmzp_decode(bin, bn, NULL, 0) : nmzp_decode_value(bin, bn, NULL, 0);
            if (v) fail(name, "accepted");
            nmzp_val_free(v);
        } else if (!strcmp(group, "frame")) check_frame(name, d, bin, bn);
        else if (!strcmp(group, "frame-invalid")) check_frame_invalid(name, d, bin, bn);
        else fail(name, "unknown group");
        nmzp_json_free(d);
        free(dtext);
        free(bin);
    }
    nmzp_json_free(ix);
    auth_vectors(0);
    printf("%d vectors checked, %d failure(s)\n", g_checked, g_fail);
    return g_fail ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "write") && strcmp(argv[1], "check"))) {
        fprintf(stderr, "usage: nmz-vectors write|check DIR\n");
        return 2;
    }
    g_dir = argv[2];
    if (!strcmp(argv[1], "write")) {
        write_all();
        if (g_fail) fprintf(stderr, "%d problem(s) while writing\n", g_fail);
        else printf("vectors written to %s\n", g_dir);
        return g_fail ? 1 : 0;
    }
    return check_all();
}
