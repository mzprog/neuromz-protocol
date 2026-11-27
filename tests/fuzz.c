/* fuzz.c — feed the parsers random and mutated inputs: the frame parser,
 * the payload decoder, the handshake prefix, JSON (trace lines), names and
 * addresses. They must never crash, read out of bounds or leak (run under
 * ASan + UBSan in CI), and what decodes must re-encode to bytes that decode
 * to the same canonical bytes again. With Clang, -DNMZP_LIBFUZZER builds a
 * libFuzzer target of the same checks.
 *
 *   fuzz_wire [ITERATIONS] [SEED] */
#include "nmzp.h"
#include "nmzp_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void payload(const unsigned char *data, size_t n) {
    char err[160];
    nmzp_val *v = nmzp_decode_value(data, n, err, sizeof err);
    if (v) { /* canonical once is canonical for good */
        nmzp_buf a, b;
        nmzp_mw w;
        nmzp_val *again;
        nmzp_buf_init(&a);
        nmzp_buf_init(&b);
        nmzp_mw_init(&w, &a);
        nmzp_mw_val(&w, v);
        again = nmzp_decode_value(a.data, a.len, NULL, 0);
        if (!again) {
            fprintf(stderr, "a decoded value re-encodes to bytes that do not decode\n");
            abort();
        }
        nmzp_mw_init(&w, &b);
        nmzp_mw_val(&w, again);
        if (a.len != b.len || memcmp(a.data, b.data, a.len)) {
            fprintf(stderr, "re-encoding is not stable\n");
            abort();
        }
        nmzp_get(v, "op");
        nmzp_get_str(v, "name");
        nmzp_val_free(again);
        nmzp_buf_free(&a);
        nmzp_buf_free(&b);
    }
    nmzp_val_free(v);
    nmzp_val_free(nmzp_decode(data, n, err, sizeof err));
}

static void one(const unsigned char *data, size_t n) {
    char err[128];
    size_t at = 0;
    int guard = 0;
    /* frames, one after another, at two limits */
    while (at < n && guard++ < 64) {
        nmzp_frame_head h;
        const unsigned char *p;
        size_t used;
        int code = 0, r = nmzp_frame_next(data + at, n - at, guard % 2 ? 65536u : 64u, &h, &p, &used, &code);
        if (r != 1) break;
        if (h.type == NMZP_GREETING || h.type == NMZP_HELLO) {
            int ma, mi;
            if (!nmzp_prefix_get(p, h.length, &ma, &mi)) payload(p + NMZP_PREFIX, h.length - NMZP_PREFIX);
        } else {
            payload(p, h.length);
        }
        at += used;
    }
    payload(data, n);
    {
        nmzp_json *j = nmzp_json_parse((const char *)data, n, 32, err, sizeof err);
        nmzp_json_free(j);
    }
    if (n < 80) {
        char z[80], host[64];
        int port;
        memcpy(z, data, n);
        z[n] = '\0';
        nmzp_name_valid(z);
        nmzp_parse_hostport(z, host, sizeof host, &port);
    }
    nmzp_utf8_valid((const char *)data, n);
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

/* seeds the mutations start from: frames and payloads in hex */
static const char *const k_seeds[] = {
    /* REQUEST {"op":"health"} id 1, then PING */
    "0b0000001000000001000000" "81a26f70a66865616c7468" "0400000020000000000000006162 6364",
    /* a map with every type */
    "8aa16ec0a162c3a169d1ff00a166cb3ff8000000000000a173a3616263a178c4020102a161929001a16d81a16b00a175cf00000000000000"
    "05a17aca3fc00000",
    /* the greeting's start and a map */
    "4e4d5a500d0a1a0a0200000083a6736572766572a1"
    "78a56e6f6e6365c42000000000000000000000000000000000000000000000000000000000000000a46175746ha46e6f6e65",
    /* an END */
    "82a473697a6518a6736861323536c420" "0000000000000000000000000000000000000000000000000000000000000000",
    /* deep nesting, 16-bit headers */
    "81a161919191919191919191919191919191919101",
    "de0010a16100a16201a16302a16403a16504a16605a16706a16807a16908a16a09a16b0aa16c0ba16d0ca16e0da16f0ea1700f",
    "dc0003d90161da0001 62db0000000163",
    /* a trace line (JSON) */
    "7b2273746570223a312c227068617365223a22666f7277617264222c226974656d73223a7b7d7d",
    NULL};

static size_t seed_bytes(const char *hex, unsigned char *out, size_t max) {
    size_t n = 0;
    while (*hex && n < max) {
        unsigned x;
        if (*hex == ' ') {
            hex++;
            continue;
        }
        if (!hex[1] || sscanf(hex, "%2x", &x) != 1) break;
        out[n++] = (unsigned char)x;
        hex += 2;
    }
    return n;
}

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
            int m, muts = 1 + (int)(rnd() % 8);
            n = seed_bytes(k_seeds[rnd() % (unsigned)n_seeds], buf, sizeof buf);
            for (m = 0; m < muts; m++) {
                unsigned op = rnd() % 5, at = n ? rnd() % (unsigned)n : 0;
                if (op == 0 && n) buf[at] = (unsigned char)rnd();                       /* any byte */
                else if (op == 1 && n) memmove(buf + at, buf + at + 1, n - at - 1), n--; /* delete */
                else if (op == 2 && n + 1 < sizeof buf) {                                /* insert a type byte */
                    static const unsigned char interesting[] = {0x00, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1,
                                                                0xc4, 0xc6, 0xca, 0xcb, 0xcf, 0xd3, 0xd9, 0xdb, 0xdd, 0xdf,
                                                                0xe0, 0xff, 0x10, 0x13, 0x14};
                    memmove(buf + at + 1, buf + at, n - at);
                    buf[at] = interesting[rnd() % sizeof interesting];
                    n++;
                } else if (op == 3 && n) buf[at] ^= (unsigned char)(1u << (rnd() % 8)); /* flip a bit */
                else if (n) n = at;                                                     /* truncate */
            }
        }
        one(buf, n);
    }
    printf("%ld inputs, no crash\n", iters);
    return 0;
}
#endif
