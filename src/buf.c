/* buf.c — the growing byte buffer of nmzp.h. */
#include "nmzp.h"

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
