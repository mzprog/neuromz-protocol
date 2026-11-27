/* test_wire.c — unit tests of the wire library: JSON, HTTP heads, chunked
 * bodies, query strings, Server-Sent Events, SHA-256, names, times. */
#include "nmzp.h"

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

static const char k_req[] = "POST /v1/models/a%20b?x=1&save=client&q=a%2Bb+c HTTP/1.1\r\n"
                            "Host: localhost:8470\r\nContent-Length: 12\r\nAuthorization: Bearer t0k\r\n"
                            "X-Pad:   spaced value  \r\n\r\n";

static int parse_req(const char *s, nmzp_http_head *h) {
    char err[200];
    return nmzp_http_parse_request(s, strlen(s), h, err, sizeof err);
}

static void test_http(void) {
    nmzp_http_head h;
    char v[64];
    CHECK(nmzp_http_head_end(k_req, strlen(k_req)) == strlen(k_req));
    CHECK(nmzp_http_head_end(k_req, strlen(k_req) - 1) == 0);
    CHECK(parse_req(k_req, &h) == 0);
    CHECK(!strcmp(h.method, "POST") && !strcmp(h.path, "/v1/models/a b") && h.content_length == 12 && h.keep_alive);
    CHECK(!strcmp(nmzp_http_header(&h, "authorization"), "Bearer t0k"));
    CHECK(!strcmp(nmzp_http_header(&h, "x-pad"), "spaced value"));
    CHECK(nmzp_query_get(h.query, "save", v, sizeof v) && !strcmp(v, "client"));
    CHECK(nmzp_query_get(h.query, "q", v, sizeof v) && !strcmp(v, "a+b c"));
    CHECK(!nmzp_query_get(h.query, "nope", v, sizeof v));
    nmzp_http_head_free(&h);
    /* refused heads */
    CHECK(parse_req("GET / HTTP/1.1\r\n\r\n", &h) == 400); /* no Host */
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET / HTTP/2.0\r\nHost: x\r\n\r\n", &h) == 505);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET / HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET /a\x01 HTTP/1.1\r\nHost: x\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET /%zz HTTP/1.1\r\nHost: x\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET /%00 HTTP/1.1\r\nHost: x\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n", &h) == 400);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n", &h) == 501);
    nmzp_http_head_free(&h);
    CHECK(parse_req("GET / HTTP/1.0\r\n\r\n", &h) == 0 && !h.keep_alive);
    nmzp_http_head_free(&h);
    {
        char err[100];
        const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";
        CHECK(nmzp_http_parse_response(resp, strlen(resp), &h, err, sizeof err) == 0);
        CHECK(h.status == 404 && !strcmp(h.reason, "Not Found") && h.content_length == 2 && !h.keep_alive);
        nmzp_http_head_free(&h);
    }
}

static void test_chunked(void) {
    const char *body = "4\r\nWiki\r\n6;ext=1\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\nTrailer: x\r\n\r\nNEXT";
    nmzp_chunked c;
    nmzp_buf out;
    size_t i, n = strlen(body), used = 0;
    long k;
    /* fed one byte at a time */
    nmzp_chunked_init(&c);
    nmzp_buf_init(&out);
    for (i = 0; i < n && !c.done; i++) {
        k = nmzp_chunked_feed(&c, body + i, 1, &out, 1 << 20);
        CHECK(k == 1);
        used += (size_t)k;
    }
    CHECK(c.done && !strcmp(out.data, "Wikipedia in \r\n\r\nchunks.") && !strcmp(body + used, "NEXT"));
    nmzp_buf_free(&out);
    /* all at once, with a limit */
    nmzp_chunked_init(&c);
    nmzp_buf_init(&out);
    CHECK(nmzp_chunked_feed(&c, body, n, &out, 5) == -2);
    nmzp_buf_free(&out);
    nmzp_chunked_init(&c);
    nmzp_buf_init(&out);
    CHECK(nmzp_chunked_feed(&c, "zz\r\n", 4, &out, 100) == -1);
    nmzp_chunked_init(&c);
    CHECK(nmzp_chunked_feed(&c, "ffffffffffffffffff\r\n", 20, &out, 100) == -1);
    nmzp_buf_free(&out);
}

typedef struct got {
    int n;
    char event[8][32], id[8][32], data[8][64];
} got;

static int on_ev(const char *e, const char *id, const char *d, void *u) {
    got *g = (got *)u;
    if (g->n < 8) {
        snprintf(g->event[g->n], 32, "%s", e);
        snprintf(g->id[g->n], 32, "%s", id);
        snprintf(g->data[g->n], 64, "%s", d);
    }
    g->n++;
    return 0;
}

static void test_sse(void) {
    nmzp_sse s;
    got g;
    nmzp_buf b;
    const char *text;
    size_t i;
    memset(&g, 0, sizeof g);
    nmzp_buf_init(&b);
    nmzp_sse_write(&b, "epoch", "3", "{\"a\":1}");
    nmzp_sse_write(&b, NULL, NULL, "two\nlines");
    nmzp_buf_str(&b, ": a comment\r\nevent: end\r\ndata: x\r\n\r\n");
    text = b.data;
    nmzp_sse_init(&s, on_ev, &g);
    for (i = 0; text[i]; i++) CHECK(nmzp_sse_feed(&s, text + i, 1) == 0);
    nmzp_sse_free(&s);
    CHECK(g.n == 3);
    CHECK(!strcmp(g.event[0], "epoch") && !strcmp(g.id[0], "3") && !strcmp(g.data[0], "{\"a\":1}"));
    CHECK(!strcmp(g.event[1], "message") && !strcmp(g.data[1], "two\nlines"));
    CHECK(!strcmp(g.event[2], "end") && !strcmp(g.data[2], "x") && !strcmp(g.id[2], "3"));
    nmzp_buf_free(&b);
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
    CHECK(nmzp_parse_hostport("http://10.0.0.2:9000", host, sizeof host, &port) == 0 && !strcmp(host, "10.0.0.2") &&
          port == 9000);
    CHECK(nmzp_parse_hostport("gpu-box", host, sizeof host, &port) == 0 && port == NMZP_DEFAULT_PORT);
    CHECK(nmzp_parse_hostport("[::1]:81", host, sizeof host, &port) == 0 && !strcmp(host, "::1") && port == 81);
    CHECK(nmzp_parse_hostport("h:0", host, sizeof host, &port) != 0 && nmzp_parse_hostport("h:x", host, sizeof host, &port) != 0);
    CHECK(nmzp_parse_hostport("https://h", host, sizeof host, &port) != 0);
    {
        nmzp_buf b;
        char d[64];
        nmzp_buf_init(&b);
        nmzp_url_encode(&b, "a b/é");
        CHECK(!strcmp(b.data, "a%20b%2F%C3%A9"));
        CHECK(nmzp_url_decode(b.data, b.len, d, sizeof d, 0) > 0 && !strcmp(d, "a b/é"));
        nmzp_buf_free(&b);
    }
}

int main(void) {
    test_json();
    test_http();
    test_chunked();
    test_sse();
    test_sha256();
    test_names_time_hosts();
    printf("%d checks, %d failed\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
