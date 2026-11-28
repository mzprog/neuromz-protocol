/* nmzp_json.h — JSON (RFC 8259) for the one payload of the protocol that is
 * JSON by definition — trace lines in the library's format (PROTOCOL §12.6)
 * — and for files (the reference server's store metadata, the test
 * vectors' descriptions). Not used for framing or payloads: the wire is
 * nmzp.h. The parser checks UTF-8 and has a depth limit; it is fuzzed. */
#ifndef NMZP_JSON_H
#define NMZP_JSON_H

#include "nmzp.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    double number;     /* NUMBER                                     */
    char *string;      /* STRING: UTF-8, NUL-terminated              */
    size_t len;        /* STRING: bytes (a "\u0000" counts)          */
    char *key;         /* the member name, for members of an object  */
    nmzp_json **items; /* ARRAY elements, OBJECT members             */
    size_t n;
};

/* Parse JSON text (UTF-8; strings must be valid UTF-8). At most max_depth
 * nested arrays/objects (0 = 64). NULL on error, with a message (and the
 * byte offset) in err. */
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

#ifdef __cplusplus
}
#endif

#endif /* NMZP_JSON_H */
