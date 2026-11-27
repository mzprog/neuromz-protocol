/* fuzz.c — feed the parsers random and mutated inputs: they must never
 * crash, read out of bounds or leak (run under ASan + UBSan in CI). With
 * Clang, -DNMZP_LIBFUZZER builds a libFuzzer target of the same checks.
 *
 *   fuzz_wire [ITERATIONS] [SEED] */
#include "nmzp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void one(const unsigned char *data, size_t n) {
    char err[128];
    nmzp_json *j = nmzp_json_parse((const char *)data, n, 32, err, sizeof err);
    nmzp_http_head h;
    nmzp_chunked c;
    nmzp_buf out;
    nmzp_sse s;
    if (j) { /* what parsed must also serialize */
        nmzp_buf b;
        nmzp_jw w;
        nmzp_buf_init(&b);
        nmzp_jw_init(&w, &b);
        nmzp_jw_str(&w, nmzp_json_str(j) ? nmzp_json_str(j) : "");
        nmzp_buf_free(&b);
    }
    nmzp_json_free(j);
    if (n <= NMZP_MAX_HEAD && nmzp_http_head_end((const char *)data, n) == n) {
        nmzp_http_parse_request((const char *)data, n, &h, err, sizeof err);
        if (h.storage) {
            char v[64];
            nmzp_http_header(&h, "Host");
            nmzp_query_get(h.query ? h.query : "", "save", v, sizeof v);
        }
        nmzp_http_head_free(&h);
        nmzp_http_parse_response((const char *)data, n, &h, err, sizeof err);
        nmzp_http_head_free(&h);
    }
    nmzp_chunked_init(&c);
    nmzp_buf_init(&out);
    nmzp_chunked_feed(&c, (const char *)data, n, &out, 1 << 16);
    nmzp_buf_free(&out);
    nmzp_sse_init(&s, NULL, NULL);
    nmzp_sse_feed(&s, (const char *)data, n);
    nmzp_sse_free(&s);
    {
        char d[256];
        nmzp_url_decode((const char *)data, n < 200 ? n : 200, d, sizeof d, 1);
    }
    if (n < 80) {
        char z[80], host[64];
        int port;
        memcpy(z, data, n);
        z[n] = '\0';
        nmzp_name_valid(z);
        nmzp_parse_hostport(z, host, sizeof host, &port);
    }
}

#if defined(NMZP_LIBFUZZER)
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t n);
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t n) {
    one(data, n);
    return 0;
}
#else
static unsigned long long g_state;
static unsigned rnd(void) {
    g_state = g_state * 6364136223846793005ull + 1442695040888963407ull;
    return (unsigned)(g_state >> 33);
}

/* seeds the mutations start from */
static const char *const k_seeds[] = {
    "{\"a\":[1,2.5e-3,\"x\\u00e9\\ud83d\\ude00\",true,null,{\"b\":false}]}",
    "POST /v1/models?save=client HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
    "GET /v1/jobs/j1/events HTTP/1.1\r\nHost: h:1\r\nAuthorization: Bearer abc\r\nLast-Event-ID: 3\r\n\r\n",
    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
    "4\r\nWiki\r\n5;x\r\npedia\r\n0\r\nT: v\r\n\r\n",
    "id: 1\nevent: epoch\ndata: {\"epoch\":1}\n\n: ping\r\ndata: a\rdata: b\n\n",
    "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
    "\"\\ud800\\udc00\\u0000\\\"\\\\\\/\\b\\f\\n\\r\\t\"",
    NULL};

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 200000, i;
    unsigned char buf[2048];
    int n_seeds = 0;
    g_state = argc > 2 ? strtoull(argv[2], NULL, 10) : 12345;
    while (k_seeds[n_seeds]) n_seeds++;
    for (i = 0; i < iters; i++) {
        size_t n, k;
        if (rnd() % 4 == 0) { /* pure noise */
            n = rnd() % sizeof buf;
            for (k = 0; k < n; k++) buf[k] = (unsigned char)rnd();
        } else { /* a seed, mutated */
            const char *s = k_seeds[rnd() % (unsigned)n_seeds];
            int m, muts = 1 + (int)(rnd() % 8);
            n = strlen(s);
            memcpy(buf, s, n);
            for (m = 0; m < muts; m++) {
                unsigned op = rnd() % 4, at = n ? rnd() % (unsigned)n : 0;
                if (op == 0 && n) buf[at] = (unsigned char)rnd();                     /* flip a byte */
                else if (op == 1 && n) memmove(buf + at, buf + at + 1, n - at - 1), n--; /* delete */
                else if (op == 2 && n + 1 < sizeof buf) {                              /* insert */
                    memmove(buf + at + 1, buf + at, n - at);
                    buf[at] = (unsigned char)"\r\n:{}[]\",\\0x;%"[rnd() % 15];
                    n++;
                } else if (n) n = at; /* truncate */
            }
        }
        one(buf, n);
    }
    printf("%ld inputs, no crash\n", iters);
    return 0;
}
#endif
