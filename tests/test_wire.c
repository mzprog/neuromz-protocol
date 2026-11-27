/* test_wire.c — unit tests of nmzp: the payload codec (MessagePack subset),
 * frames, the handshake prefix, HMAC-SHA256 and the key derivation, UTF-8,
 * SHA-256, JSON, names, times and addresses. The shared vectors are
 * checked by nmz-vectors (tests/vectors.c). */
#include "nmzp.h"
#include "nmzp_json.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks, g_fails;

#define CHECK(c)                                                                                                       \
    do {                                                                                                               \
        g_checks++;                                                                                                    \
        if (!(c)) {                                                                                                    \
            g_fails++;                                                                                                 \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                                               \
        }                                                                                                              \
    } while (0)

static int hex_is(const nmzp_buf *b, const char *hex) {
    char *h = malloc(b->len * 2 + 1);
    int r;
    nmzp_hex((const unsigned char *)b->data, b->len, h);
    r = !strcmp(h, hex);
    if (!r) fprintf(stderr, "  got %s\n  want %s\n", h, hex);
    free(h);
    return r;
}

static size_t unhex(const char *hex, unsigned char *out) {
    size_t len = strlen(hex) / 2, j;
    for (j = 0; j < len; j++) {
        unsigned x = 0;
        sscanf(hex + 2 * j, "%2x", &x);
        out[j] = (unsigned char)x;
    }
    return len;
}

static nmzp_json *parse(const char *s) { return nmzp_json_parse(s, strlen(s), 0, NULL, 0); }

static void test_json(void) {
    nmzp_json *j;
    char err[128];
    double d;
    int b;
    nmzp_buf out;
    nmzp_jw w;
    j = parse("{\"a\": [1, -2.5e3, true, null, \"x\\u00e9\\ud83d\\ude00\\n\"], \"b\": {}, \"c\": false}");
    CHECK(j && j->type == NMZP_JSON_OBJECT && j->n == 3);
    CHECK(nmzp_json_num(nmzp_json_at(nmzp_json_get(j, "a"), 1), &d) && d == -2500);
    CHECK(nmzp_json_bool(nmzp_json_at(nmzp_json_get(j, "a"), 2), &b) && b == 1);
    CHECK(nmzp_json_at(nmzp_json_get(j, "a"), 3)->type == NMZP_JSON_NULL);
    CHECK(!strcmp(nmzp_json_str(nmzp_json_at(nmzp_json_get(j, "a"), 4)), "x\xc3\xa9\xf0\x9f\x98\x80\n"));
    CHECK(nmzp_json_get_bool(j, "c", &b) && b == 0);
    CHECK(nmzp_json_get(j, "missing") == NULL && nmzp_json_get_str(j, "a") == NULL);
    nmzp_json_free(j);
    /* invalid inputs: never a crash, always a message */
    {
        static const char *const bad[] = {"", "{", "[1,]", "{\"a\" 1}", "01", "1.", "-", "\"\\x\"", "\"\x01\"", "tru",
                                          "[1 2]", "{\"a\":1,}", "\"\\ud800\"", "\"\xc3\x28\"", "\"\xed\xa0\x80\"",
                                          "1e", "nul", "\"abc", "[[[]", "1 2", "{1:2}", NULL};
        int i;
        for (i = 0; bad[i]; i++) {
            err[0] = '\0';
            j = nmzp_json_parse(bad[i], strlen(bad[i]), 0, err, sizeof err);
            CHECK(j == NULL && err[0]);
            if (j) fprintf(stderr, "  accepted: %s\n", bad[i]);
            nmzp_json_free(j);
        }
    }
    {
        char deep[200];
        int i;
        for (i = 0; i < 100; i++) deep[i] = '[';
        for (i = 100; i < 200; i++) deep[i] = ']';
        CHECK(nmzp_json_parse(deep, 200, 64, err, sizeof err) == NULL && strstr(err, "deeply"));
        j = nmzp_json_parse(deep + 40, 120, 64, err, sizeof err); /* 60 deep: fine */
        CHECK(j != NULL);
        nmzp_json_free(j);
    }
    /* writing, and back */
    nmzp_buf_init(&out);
    nmzp_jw_init(&w, &out);
    nmzp_jw_obj(&w);
    nmzp_jw_kstr(&w, "s", "q\"\\\n\t\x01");
    nmzp_jw_knum(&w, "n", 0.1);
    nmzp_jw_kint(&w, "i", -42);
    nmzp_jw_knum(&w, "nan", NAN);
    nmzp_jw_kbool(&w, "t", 1);
    nmzp_jw_key(&w, "a");
    nmzp_jw_arr(&w);
    nmzp_jw_num(&w, 3);
    nmzp_jw_str(&w, NULL);
    nmzp_jw_obj(&w);
    nmzp_jw_end_obj(&w);
    nmzp_jw_end_arr(&w);
    nmzp_jw_end_obj(&w);
    CHECK(!strcmp(out.data, "{\"s\":\"q\\\"\\\\\\n\\t\\u0001\",\"n\":0.1,\"i\":-42,\"nan\":null,\"t\":true,\"a\":[3,null,{}]}"));
    j = parse(out.data);
    CHECK(j && !strcmp(nmzp_json_get_str(j, "s"), "q\"\\\n\t\x01"));
    nmzp_json_free(j);
    nmzp_buf_free(&out);
}



static void test_mpack_write(void) {
    nmzp_buf b;
    nmzp_mw w;
    nmzp_buf_init(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_kint(&w, "a", 200);
    nmzp_mw_kint(&w, "b", -33);
    nmzp_mw_kint(&w, "c", 65536);
    nmzp_mw_kfloat(&w, "d", 1.5);
    nmzp_mw_kfloat(&w, "e", NAN); /* not finite: nil */
    nmzp_mw_kbool(&w, "f", 1);
    nmzp_mw_kstr(&w, "g", NULL);
    nmzp_mw_end_map(&w);
    CHECK(nmzp_mw_done(&w) == 0);
    CHECK(hex_is(&b, "87a161ccc8a162d0dfa163ce00010000a164cb3ff8000000000000a165c0a166c3a167c0"));
    /* headers grow with the counts and shrink back: 16 elements are an array 16 */
    nmzp_buf_clear(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_arr(&w);
    {
        int i;
        for (i = 0; i < 16; i++) nmzp_mw_int(&w, i);
    }
    nmzp_mw_end_arr(&w);
    CHECK(b.len == 3 + 16 && (unsigned char)b.data[0] == 0xdc && b.data[1] == 0 && b.data[2] == 16);
    /* nested: the inner header shrinks first, then the outer */
    nmzp_buf_clear(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_key(&w, "x");
    nmzp_mw_arr(&w);
    nmzp_mw_arr(&w);
    nmzp_mw_end_arr(&w);
    nmzp_mw_int(&w, -1);
    nmzp_mw_end_arr(&w);
    nmzp_mw_end_map(&w);
    CHECK(hex_is(&b, "81a1789290ff"));
    /* misuse is noticed */
    nmzp_buf_clear(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_int(&w, 1); /* a value where a key belongs */
    nmzp_mw_end_map(&w);
    CHECK(nmzp_mw_done(&w) != 0);
    nmzp_buf_clear(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_map(&w);
    nmzp_mw_key(&w, "k"); /* a key without its value */
    nmzp_mw_end_map(&w);
    CHECK(nmzp_mw_done(&w) != 0);
    nmzp_buf_clear(&b);
    nmzp_mw_init(&w, &b);
    nmzp_mw_arr(&w); /* not closed */
    CHECK(nmzp_mw_done(&w) != 0);
    { /* f32 */
        float v[2] = {1.0f, -2.0f}, back[2];
        nmzp_buf_clear(&b);
        nmzp_mw_init(&w, &b);
        nmzp_mw_f32(&w, v, 2);
        CHECK(hex_is(&b, "c4080000803f000000c0"));
        nmzp_f32_read(b.data + 2, 2, back);
        CHECK(back[0] == 1.0f && back[1] == -2.0f);
    }
    nmzp_buf_free(&b);
}

static void test_mpack_read(void) {
    unsigned char doc[64];
    size_t dn = unhex("83a26f70a66865616c7468a16ed1ff00a17892cb3ff8000000000000c40107", doc);
    char err[200];
    nmzp_val *v = nmzp_decode(doc, dn, err, sizeof err);
    long long i = 0;
    double d = 0;
    size_t n = 0;
    CHECK(v && v->type == NMZP_MAP && v->n == 3);
    CHECK(v && !strcmp(nmzp_get_str(v, "op"), "health"));
    CHECK(nmzp_get_int(v, "n", &i) && i == -256);
    CHECK(nmzp_num(nmzp_at(nmzp_get(v, "x"), 0), &d) && d == 1.5);
    CHECK(nmzp_bin(nmzp_at(nmzp_get(v, "x"), 1), &n) && n == 1 && nmzp_bin(nmzp_at(nmzp_get(v, "x"), 1), NULL)[0] == 7);
    CHECK(nmzp_get(v, "missing") == NULL && nmzp_is_nil(nmzp_get(v, "missing")) && nmzp_get_str(v, "n") == NULL);
    CHECK(nmzp_int(nmzp_at(nmzp_get(v, "x"), 0), &i) == 0); /* 1.5 is not a whole number */
    { /* written again, it is the same bytes (they are canonical) */
        nmzp_buf b;
        nmzp_mw w;
        nmzp_buf_init(&b);
        nmzp_mw_init(&w, &b);
        nmzp_mw_val(&w, v);
        CHECK(b.len == dn && !memcmp(b.data, doc, dn));
        nmzp_buf_free(&b);
    }
    nmzp_val_free(v);
    /* whole floats count as ints, ints as floats */
    dn = unhex("82a161cb4000000000000000a16205", doc);
    v = nmzp_decode(doc, dn, NULL, 0);
    CHECK(v && nmzp_get_int(v, "a", &i) && i == 2 && nmzp_get_num(v, "b", &d) && d == 5);
    nmzp_val_free(v);
    /* refusals, with a reason */
    {
        static const struct {
            const char *hex, *why;
        } bad[] = {{"", "empty"},
                   {"01", "not a map"},
                   {"81a16101ff", "trailing"},
                   {"82a16101a16102", "twice"},
                   {"81a2006101", "U+0000"},
                   {"8101a161", "not a str"},
                   {"81a161c1", "c1"},
                   {"81a161d40000", "extension"},
                   {"81a161a2c328", "UTF-8"},
                   {"81a161cf8000000000000000", "2^63"},
                   {"81a161ddffffffff", "claims more"},
                   {"81a161dbffffffff", "ends inside"},
                   {NULL, NULL}};
        int k;
        for (k = 0; bad[k].hex; k++) {
            unsigned char raw[64];
            size_t len = unhex(bad[k].hex, raw);
            err[0] = '\0';
            v = nmzp_decode(raw, len, err, sizeof err);
            CHECK(v == NULL && strstr(err, bad[k].why));
            if (v || !strstr(err, bad[k].why)) fprintf(stderr, "  %s: %s\n", bad[k].hex, err);
            nmzp_val_free(v);
        }
    }
    { /* depth: 31 arrays in the top map are fine, 32 are too deep */
        unsigned char deep[40];
        int k;
        deep[0] = 0x81;
        deep[1] = 0xa1;
        deep[2] = 'a';
        for (k = 0; k < 31; k++) deep[3 + k] = 0x91;
        deep[3 + 31] = 0x01;
        v = nmzp_decode(deep, 35, err, sizeof err);
        CHECK(v != NULL);
        nmzp_val_free(v);
        for (k = 0; k < 32; k++) deep[3 + k] = 0x91;
        deep[3 + 32] = 0x01;
        v = nmzp_decode(deep, 36, err, sizeof err);
        CHECK(v == NULL && strstr(err, "deeper"));
        nmzp_val_free(v);
    }
    { /* a large map: its keys are checked for duplicates by hashing */
        nmzp_buf b;
        nmzp_mw w;
        int k;
        nmzp_buf_init(&b);
        nmzp_mw_init(&w, &b);
        nmzp_mw_map(&w);
        for (k = 0; k < 5000; k++) {
            char key[16];
            snprintf(key, sizeof key, "k%04d", k);
            nmzp_mw_kint(&w, key, k);
        }
        nmzp_mw_end_map(&w);
        v = nmzp_decode(b.data, b.len, err, sizeof err);
        CHECK(v && v->n == 5000 && nmzp_get_int(v, "k4999", &i) && i == 4999);
        nmzp_val_free(v);
        /* the last key made equal to the first: "k4999" -> "k0000" */
        {
            char *last = b.data + b.len - 3 - 5; /* the key's bytes, before its value cd 13 87 */
            CHECK(!memcmp(last, "k4999", 5));
            memcpy(last, "k0000", 5);
            v = nmzp_decode(b.data, b.len, err, sizeof err);
            CHECK(v == NULL && strstr(err, "twice"));
            nmzp_val_free(v);
        }
        nmzp_buf_free(&b);
    }
    { /* the value limit: a map, its key, an array of 262144 ints = 262147 values */
        size_t n2 = 8 + NMZP_MAX_VALUES;
        unsigned char *big = calloc(n2, 1);
        if (big) {
            memcpy(big, "\x81\xa1" "a" "\xdd\x00\x04\x00\x00", 8);
            v = nmzp_decode(big, n2, err, sizeof err);
            CHECK(v == NULL && strstr(err, "262144"));
            nmzp_val_free(v);
            free(big);
        }
    }
}

static void test_utf8(void) {
    CHECK(nmzp_utf8_valid("", 0) && nmzp_utf8_valid("a\0b", 3));
    CHECK(nmzp_utf8_valid("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 9));
    CHECK(!nmzp_utf8_valid("\xc0\x80", 2) && !nmzp_utf8_valid("\xe0\x80\x80", 3) && !nmzp_utf8_valid("\xed\xa0\x80", 3));
    CHECK(!nmzp_utf8_valid("\xf4\x90\x80\x80", 4) && !nmzp_utf8_valid("\x80", 1) && !nmzp_utf8_valid("\xc3", 1));
    CHECK(!nmzp_utf8_valid("\xff", 1) && !nmzp_utf8_valid("\xe2\x82", 2));
}

static void test_frames(void) {
    unsigned char h[12], two[40];
    nmzp_frame_head fh;
    const unsigned char *payload;
    size_t used;
    int code = 0, major = 0, minor = 0;
    nmzp_buf b;
    nmzp_head_encode(h, NMZP_REQUEST, NMZP_MORE, 0x01020304u, 5);
    CHECK(!memcmp(h, "\x05\x00\x00\x00\x10\x01\x00\x00\x04\x03\x02\x01", 12));
    nmzp_head_decode(h, &fh);
    CHECK(fh.length == 5 && fh.type == NMZP_REQUEST && fh.flags == NMZP_MORE && fh.id == 0x01020304u && !fh.reserved);
    CHECK(nmzp_head_check(&fh, 65536) == 0 && nmzp_head_check(&fh, 4) == NMZP_E_FRAME_TOO_LARGE);
    fh.flags = 0x80;
    CHECK(nmzp_head_check(&fh, 65536) == NMZP_E_PROTOCOL);
    fh.flags = 0;
    fh.reserved = 1;
    CHECK(nmzp_head_check(&fh, 65536) == NMZP_E_PROTOCOL);
    fh.reserved = 0;
    fh.type = 0x04;
    CHECK(nmzp_head_check(&fh, 65536) == NMZP_E_UNKNOWN_FRAME);
    /* two frames back to back, then a partial one */
    nmzp_buf_init(&b);
    nmzp_frame_put(&b, NMZP_PING, 0, 0, "ab", 2);
    nmzp_frame_put(&b, NMZP_DATA, NMZP_MORE, 7, "xyz", 3);
    CHECK(b.len == 29);
    memcpy(two, b.data, b.len);
    CHECK(nmzp_frame_next(two, b.len, 65536, &fh, &payload, &used, &code) == 1 && used == 14 && fh.type == NMZP_PING &&
          !memcmp(payload, "ab", 2));
    CHECK(nmzp_frame_next(two + 14, b.len - 14, 65536, &fh, &payload, &used, &code) == 1 && fh.id == 7 && fh.length == 3);
    CHECK(nmzp_frame_next(two, 11, 65536, &fh, &payload, &used, &code) == 0);
    CHECK(nmzp_frame_next(two + 14, 14, 65536, &fh, &payload, &used, &code) == 0); /* 14 of the 15 bytes */
    CHECK(nmzp_frame_next("GET / HTTP/1.1\r\n", 16, 65536, &fh, &payload, &used, &code) == -1 &&
          code == NMZP_E_FRAME_TOO_LARGE);
    nmzp_buf_free(&b);
    /* the handshake prefix */
    nmzp_prefix_put(h, 2, 1);
    CHECK(!memcmp(h, "NMZP\r\n\x1a\n\x02\x00\x01\x00", 12));
    CHECK(nmzp_prefix_get(h, 12, &major, &minor) == 0 && major == 2 && minor == 1);
    CHECK(nmzp_prefix_get(h, 11, &major, &minor) == -1);
    h[3] = 'Q';
    CHECK(nmzp_prefix_get(h, 12, &major, &minor) == -1);
    /* errors */
    CHECK(!strcmp(nmzp_error_name(203), "invalid_argument") && nmzp_error_code("queue_full") == 402);
    CHECK(nmzp_error_name(999) == NULL && nmzp_error_code("nope") == 0);
    {
        nmzp_val *v;
        long long c = 0;
        nmzp_buf_init(&b);
        CHECK(nmzp_error_payload(&b, NMZP_E_NOT_FOUND, "no model named 'x'", NULL, 0) == 0);
        v = nmzp_decode(b.data, b.len, NULL, 0);
        CHECK(v && nmzp_get_int(v, "code", &c) && c == 400 && !strcmp(nmzp_get_str(v, "name"), "not_found") &&
              !strcmp(nmzp_get_str(v, "message"), "no model named 'x'"));
        nmzp_val_free(v);
        nmzp_buf_free(&b);
    }
}

static void test_hmac_auth(void) {
    unsigned char mac[32], key[32], id[8], ns[32], nc[32], pc[32], ps[32];
    char hex[65];
    int i;
    /* RFC 4231 test case 2 */
    nmzp_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, mac);
    nmzp_hex(mac, 32, hex);
    CHECK(!strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    { /* case 6: a key longer than the block */
        unsigned char k[131];
        memset(k, 0xaa, sizeof k);
        nmzp_hmac_sha256(k, sizeof k, "Test Using Larger Than Block-Size Key - Hash Key First", 54, mac);
        nmzp_hex(mac, 32, hex);
        CHECK(!strcmp(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    }
    { /* incremental equals one-shot */
        nmzp_hmac h;
        unsigned char m2[32];
        nmzp_hmac_init(&h, "Jefe", 4);
        nmzp_hmac_update(&h, "what do ya want ", 16);
        nmzp_hmac_update(&h, "for nothing?", 12);
        nmzp_hmac_final(&h, m2);
        nmzp_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, mac);
        CHECK(!memcmp(mac, m2, 32));
    }
    /* the derivation: K is what the tokens file keeps (sha256:...) */
    nmzp_auth_key("abc", 3, key);
    nmzp_hex(key, 32, hex);
    CHECK(!strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    nmzp_auth_key_id(key, id);
    nmzp_hmac_sha256(key, 32, "neuromz key id", 14, mac);
    CHECK(!memcmp(id, mac, 8));
    for (i = 0; i < 32; i++) ns[i] = (unsigned char)i, nc[i] = (unsigned char)(255 - i);
    nmzp_auth_proof(key, 0, ns, nc, pc);
    nmzp_auth_proof(key, 1, ns, nc, ps);
    CHECK(memcmp(pc, ps, 32) != 0);
    {
        unsigned char msg[20 + 64];
        memcpy(msg, "neuromz client proof", 20);
        memcpy(msg + 20, ns, 32);
        memcpy(msg + 52, nc, 32);
        nmzp_hmac_sha256(key, 32, msg, sizeof msg, mac);
        CHECK(!memcmp(mac, pc, 32));
    }
    nc[0] ^= 1; /* another nonce, another proof */
    nmzp_auth_proof(key, 0, ns, nc, mac);
    CHECK(memcmp(mac, pc, 32) != 0);
}

static void test_sha256(void) {
    char hex[65];
    nmzp_sha256 s;
    unsigned char d[32];
    int i;
    nmzp_sha256_hex("", 0, hex);
    CHECK(!strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    nmzp_sha256_hex("abc", 3, hex);
    CHECK(!strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    nmzp_sha256_init(&s);
    for (i = 0; i < 1000000; i++) nmzp_sha256_update(&s, "a", 1);
    nmzp_sha256_final(&s, d);
    nmzp_hex(d, 32, hex);
    CHECK(!strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    CHECK(nmzp_ct_equal("abcd", "abcd", 4) && !nmzp_ct_equal("abcd", "abce", 4));
    {
        unsigned char r1[16], r2[16];
        CHECK(nmzp_random(r1, 16) == 0 && nmzp_random(r2, 16) == 0 && memcmp(r1, r2, 16) != 0);
    }
}

static void test_names_time_hosts(void) {
    char t[32], host[64];
    int port = 0;
    CHECK(nmzp_name_valid("xor") && nmzp_name_valid("mnist-cnn.v2") && nmzp_name_valid("A_1"));
    CHECK(nmzp_name_valid("console") && nmzp_name_valid("com10") && nmzp_name_valid("xor.j12"));
    CHECK(!nmzp_name_valid("") && !nmzp_name_valid(".hidden") && !nmzp_name_valid("-x") && !nmzp_name_valid("a/b"));
    CHECK(!nmzp_name_valid("a\\b") && !nmzp_name_valid("..") && !nmzp_name_valid("x.") && !nmzp_name_valid("a b"));
    CHECK(!nmzp_name_valid("CON") && !nmzp_name_valid("nul.txt") && !nmzp_name_valid("Com1") && !nmzp_name_valid("lpt9.x"));
    CHECK(!nmzp_name_valid("x\xc3\xa9"));
    {
        char longname[70];
        memset(longname, 'a', 65);
        longname[65] = '\0';
        CHECK(!nmzp_name_valid(longname));
        longname[64] = '\0';
        CHECK(nmzp_name_valid(longname));
    }
    nmzp_time_rfc3339(0, t);
    CHECK(!strcmp(t, "1970-01-01T00:00:00Z"));
    nmzp_time_rfc3339(951782400, t); /* a leap day */
    CHECK(!strcmp(t, "2000-02-29T00:00:00Z"));
    nmzp_time_rfc3339(1764252309, t);
    CHECK(!strcmp(t, "2025-11-27T14:05:09Z"));
    CHECK(nmzp_parse_hostport("10.0.0.2:9000", host, sizeof host, &port) == 0 && !strcmp(host, "10.0.0.2") && port == 9000);
    CHECK(nmzp_parse_hostport("http://10.0.0.2:9000", host, sizeof host, &port) != 0); /* protocol 1's URLs */
    CHECK(nmzp_parse_hostport("gpu-box", host, sizeof host, &port) == 0 && port == NMZP_DEFAULT_PORT);
    CHECK(nmzp_parse_hostport("[::1]:81", host, sizeof host, &port) == 0 && !strcmp(host, "::1") && port == 81);
    CHECK(nmzp_parse_hostport("h:0", host, sizeof host, &port) != 0 && nmzp_parse_hostport("h:x", host, sizeof host, &port) != 0);
    CHECK(nmzp_parse_hostport("https://h", host, sizeof host, &port) != 0);
    CHECK(nmzp_parse_hostport("::1", host, sizeof host, &port) != 0 && nmzp_parse_hostport("h:1:2", host, sizeof host, &port) != 0);
}


int main(void) {
    test_mpack_write();
    test_mpack_read();
    test_utf8();
    test_frames();
    test_hmac_auth();
    test_sha256();
    test_json();
    test_names_time_hosts();
    printf("%d checks, %d failed\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
