/* util.c — SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and the
 * protocol's key derivation (PROTOCOL §6), constant-time comparison, UTF-8
 * validation, the protocol's name rules, RFC 3339 times. Plain C11: what
 * the operating system does (randomness, sleeping, clocks) is in sock.c. */
#include "nmzp.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------ SHA-256 */

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void compress(nmzp_sha256 *s, const unsigned char *b) {
    uint32_t w[64], a, bb, c, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)b[4 * i] << 24) | ((uint32_t)b[4 * i + 1] << 16) | ((uint32_t)b[4 * i + 2] << 8) |
               (uint32_t)b[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = s->h[0], bb = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25), ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22), maj = (a & bb) ^ (a & c) ^ (bb & c);
        uint32_t t2 = S0 + maj;
        h = g, g = f, f = e, e = d + t1, d = c, c = bb, bb = a, a = t1 + t2;
    }
    s->h[0] += a, s->h[1] += bb, s->h[2] += c, s->h[3] += d, s->h[4] += e, s->h[5] += f, s->h[6] += g, s->h[7] += h;
}

void nmzp_sha256_init(nmzp_sha256 *s) {
    static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                   0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    memcpy(s->h, iv, sizeof iv);
    s->bytes = 0;
    s->used = 0;
}

void nmzp_sha256_update(nmzp_sha256 *s, const void *p, size_t n) {
    const unsigned char *c = (const unsigned char *)p;
    s->bytes += n;
    while (n > 0) {
        size_t take = 64 - s->used;
        if (take > n) take = n;
        memcpy(s->block + s->used, c, take);
        s->used += take;
        c += take;
        n -= take;
        if (s->used == 64) {
            compress(s, s->block);
            s->used = 0;
        }
    }
}

void nmzp_sha256_final(nmzp_sha256 *s, unsigned char out[32]) {
    uint64_t bits = s->bytes * 8;
    unsigned char pad = 0x80, zero = 0, len[8];
    int i;
    nmzp_sha256_update(s, &pad, 1);
    while (s->used != 56) nmzp_sha256_update(s, &zero, 1);
    for (i = 0; i < 8; i++) len[i] = (unsigned char)(bits >> (56 - 8 * i));
    nmzp_sha256_update(s, len, 8);
    for (i = 0; i < 8; i++) {
        out[4 * i] = (unsigned char)(s->h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(s->h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(s->h[i] >> 8);
        out[4 * i + 3] = (unsigned char)s->h[i];
    }
}

void nmzp_hex(const unsigned char *p, size_t n, char *out) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i] = hex[p[i] >> 4];
        out[2 * i + 1] = hex[p[i] & 15];
    }
    out[2 * n] = '\0';
}

void nmzp_sha256_hex(const void *p, size_t n, char out[65]) {
    nmzp_sha256 s;
    unsigned char d[32];
    nmzp_sha256_init(&s);
    nmzp_sha256_update(&s, p, n);
    nmzp_sha256_final(&s, d);
    nmzp_hex(d, 32, out);
}

void nmzp_sha256_of(const void *p, size_t n, unsigned char out[32]) {
    nmzp_sha256 s;
    nmzp_sha256_init(&s);
    nmzp_sha256_update(&s, p, n);
    nmzp_sha256_final(&s, out);
}

/* --------------------------------------------------------------- HMAC */

void nmzp_hmac_init(nmzp_hmac *h, const void *key, size_t kn) {
    unsigned char k[64], pad[64];
    int i;
    memset(k, 0, sizeof k);
    if (kn > 64) nmzp_sha256_of(key, kn, k); /* a long key is hashed first */
    else if (kn) memcpy(k, key, kn);
    for (i = 0; i < 64; i++) pad[i] = (unsigned char)(k[i] ^ 0x36);
    nmzp_sha256_init(&h->inner);
    nmzp_sha256_update(&h->inner, pad, 64);
    for (i = 0; i < 64; i++) pad[i] = (unsigned char)(k[i] ^ 0x5c);
    nmzp_sha256_init(&h->outer);
    nmzp_sha256_update(&h->outer, pad, 64);
    memset(k, 0, sizeof k);
    memset(pad, 0, sizeof pad);
}

void nmzp_hmac_update(nmzp_hmac *h, const void *p, size_t n) { nmzp_sha256_update(&h->inner, p, n); }

void nmzp_hmac_final(nmzp_hmac *h, unsigned char out[32]) {
    unsigned char d[32];
    nmzp_sha256_final(&h->inner, d);
    nmzp_sha256_update(&h->outer, d, 32);
    nmzp_sha256_final(&h->outer, out);
    memset(d, 0, sizeof d);
}

void nmzp_hmac_sha256(const void *key, size_t kn, const void *msg, size_t n, unsigned char out[32]) {
    nmzp_hmac h;
    nmzp_hmac_init(&h, key, kn);
    nmzp_hmac_update(&h, msg, n);
    nmzp_hmac_final(&h, out);
}

/* ------------------------------------------- the key and the proofs (§6) */

void nmzp_auth_key(const char *token, size_t n, unsigned char key[32]) { nmzp_sha256_of(token, n, key); }

void nmzp_auth_key_id(const unsigned char key[32], unsigned char id[8]) {
    static const char label[] = "neuromz key id";
    unsigned char d[32];
    nmzp_hmac_sha256(key, 32, label, sizeof label - 1, d);
    memcpy(id, d, 8);
}

void nmzp_auth_proof(const unsigned char key[32], int server, const unsigned char ns[32], const unsigned char nc[32],
                     unsigned char out[32]) {
    static const char lc[] = "neuromz client proof", ls[] = "neuromz server proof";
    nmzp_hmac h;
    nmzp_hmac_init(&h, key, 32);
    if (server) nmzp_hmac_update(&h, ls, sizeof ls - 1);
    else nmzp_hmac_update(&h, lc, sizeof lc - 1);
    nmzp_hmac_update(&h, ns, 32);
    nmzp_hmac_update(&h, nc, 32);
    nmzp_hmac_final(&h, out);
}

int nmzp_ct_equal(const void *a, const void *b, size_t n) {
    const volatile unsigned char *x = (const volatile unsigned char *)a, *y = (const volatile unsigned char *)b;
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) diff |= (unsigned char)(x[i] ^ y[i]);
    return diff == 0;
}

/* --------------------------------------------------------------- UTF-8 */

int nmzp_utf8_valid(const char *s, size_t n) {
    const unsigned char *p = (const unsigned char *)s, *end = p + n;
    while (p < end) {
        unsigned c = *p;
        size_t k, i;
        unsigned long cp;
        if (c < 0x80) {
            p++;
            continue;
        }
        if (c >= 0xC2 && c <= 0xDF) k = 2, cp = c & 0x1F;
        else if (c >= 0xE0 && c <= 0xEF) k = 3, cp = c & 0x0F;
        else if (c >= 0xF0 && c <= 0xF4) k = 4, cp = c & 0x07;
        else return 0; /* a continuation byte, C0/C1 (overlong), F5..FF */
        if ((size_t)(end - p) < k) return 0;
        for (i = 1; i < k; i++) {
            if ((p[i] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (p[i] & 0x3Fu);
        }
        if ((k == 3 && cp < 0x800) || (k == 4 && (cp < 0x10000 || cp > 0x10FFFF)) || (cp >= 0xD800 && cp <= 0xDFFF))
            return 0;
        p += k;
    }
    return 1;
}

/* -------------------------------------------------------------- names */

int nmzp_name_valid(const char *name) {
    static const char *const devices[] = {"con", "prn", "aux", "nul", NULL};
    size_t n, i, stem;
    char low[8];
    if (!name) return 0;
    n = strlen(name);
    if (n < 1 || n > 64) return 0;
    if (!((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= '0' && name[0] <= '9')))
        return 0;
    if (name[n - 1] == '.') return 0;
    for (i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
              c == '-'))
            return 0;
    }
    /* Windows device names, alone or before a dot: con, con.txt, COM1 */
    for (stem = 0; stem < n && name[stem] != '.'; stem++) {
    }
    if (stem <= 4) {
        for (i = 0; i < stem; i++) low[i] = (char)(name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i]);
        low[stem] = '\0';
        for (i = 0; devices[i]; i++)
            if (!strcmp(low, devices[i])) return 0;
        if (stem == 4 && (!strncmp(low, "com", 3) || !strncmp(low, "lpt", 3)) && low[3] >= '1' && low[3] <= '9') return 0;
    }
    return 1;
}

/* --------------------------------------------------------------- time */

void nmzp_time_rfc3339(long long t, char out[32]) {
    /* days from civil (Howard Hinnant), no gmtime: thread-safe everywhere */
    long long days = t >= 0 ? t / 86400 : -((-t + 86399) / 86400), secs = t - days * 86400;
    long long z = days + 719468, era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long long y = (long long)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned d = doy - (153 * mp + 2) / 5 + 1;
    unsigned m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    { /* room for any value (GCC cannot see that the fields are small), then the 20 characters */
        char b[96];
        snprintf(b, sizeof b, "%04lld-%02u-%02uT%02u:%02u:%02uZ", y, m, d, (unsigned)(secs / 3600),
                 (unsigned)(secs % 3600 / 60), (unsigned)(secs % 60));
        snprintf(out, 32, "%.31s", b);
    }
}

long long nmzp_now(void) { return (long long)time(NULL); }

