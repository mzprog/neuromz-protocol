/* conformance.c — check a live NeuroMZ server against PROTOCOL.md 1.0.0.
 *
 *   nmz-conformance --url http://127.0.0.1:8470 [--token T] [--read-token T]
 *                   [--prefix P] [--verbose]
 *
 * --token needs the train permission (admin is fine); --read-token, if
 * given, is a token with only `read` (the permission checks). Every model
 * and dataset it creates is named PREFIX-... (default: a random prefix)
 * and deleted at the end, so it can run against a shared server. Output is
 * TAP-like ("ok N - what", "not ok N - what: why"); the exit status is 0
 * only if every check passed. The suite brings its own tiny datasets. */
#include "nmzp.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nmzp_client g_c, g_read, g_anon;
static int g_have_read, g_verbose, g_auth = 1;
static int g_n, g_pass, g_fail, g_skip;
static char g_prefix[48];
static char g_why[600];
static int g_allow_client = 1, g_allow_server = 1, g_trace_enabled = 1;
static long g_max_epochs = 1000;
static double g_max_layer = 0; /* limits.max_layer_size, when the server reports one */

/* ---------------------------------------------------------- reporting */

static int failf(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;
static int failf(const char *fmt, ...) {
    va_list ap;
    if (g_why[0]) return 0; /* keep the first reason */
    va_start(ap, fmt);
    vsnprintf(g_why, sizeof g_why, fmt, ap);
    va_end(ap);
    return 0;
}

#define EXPECT(cond, ...)                                                                                              \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            failf(__VA_ARGS__);                                                                                        \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

typedef void (*test_fn)(void);

static void run(const char *name, test_fn fn) {
    g_why[0] = '\0';
    g_n++;
    fn();
    if (!strcmp(g_why, "SKIP")) {
        g_skip++;
        printf("ok %d - %s # SKIP\n", g_n, name);
    } else if (g_why[0]) {
        g_fail++;
        printf("not ok %d - %s: %s\n", g_n, name, g_why);
    } else {
        g_pass++;
        printf("ok %d - %s\n", g_n, name);
    }
    fflush(stdout);
}

static void skip(void) { snprintf(g_why, sizeof g_why, "SKIP"); }

/* ------------------------------------------------------------ requests */

typedef struct reply {
    nmzp_response r;
    nmzp_json *j;
} reply;

static void reply_free(reply *rp) {
    nmzp_response_free(&rp->r);
    nmzp_json_free(rp->j);
    memset(rp, 0, sizeof *rp);
}

/* a request; the body is JSON when ctype is NULL and body is not */
static int call(nmzp_client *c, const char *method, const char *path, const char *ctype, const char *body, size_t n,
                reply *rp) {
    memset(rp, 0, sizeof *rp);
    if (nmzp_client_request(c, method, path, body ? (ctype ? ctype : "application/json") : NULL, body,
                            body ? (n ? n : strlen(body)) : 0, NULL, &rp->r)) {
        failf("%s %s: %s", method, path, c->err);
        return -1;
    }
    if (rp->r.body.len && rp->r.body.data[0] == '{')
        rp->j = nmzp_json_parse(rp->r.body.data, rp->r.body.len, 64, NULL, 0);
    if (g_verbose)
        fprintf(stderr, "  %s %s -> %d %.300s\n", method, path, rp->r.status, rp->r.body.data ? rp->r.body.data : "");
    return rp->r.status;
}

static int json_call(const char *method, const char *path, const char *body, reply *rp) {
    return call(&g_c, method, path, NULL, body, 0, rp);
}

static const char *err_code(const reply *rp) { return nmzp_json_get_str(nmzp_json_get(rp->j, "error"), "code"); }
static const char *err_msg(const reply *rp) { return nmzp_json_get_str(nmzp_json_get(rp->j, "error"), "message"); }

/* the error shape of §3 with this code */
static int is_error(const reply *rp, int status, const char *code) {
    if (rp->r.status != status) return failf("expected %d %s, got %d: %.200s", status, code, rp->r.status,
                                             rp->r.body.data ? rp->r.body.data : "");
    if (!err_code(rp) || !err_msg(rp)) return failf("no {\"error\":{\"code\",\"message\"}} body: %.200s", rp->r.body.data);
    if (strcmp(err_code(rp), code)) return failf("expected code %s, got %s (%s)", code, err_code(rp), err_msg(rp));
    return 1;
}

static const char *nm(const char *suffix) {
    static char b[8][128];
    static int k;
    k = (k + 1) % 8;
    snprintf(b[k], sizeof b[k], "%s-%s", g_prefix, suffix);
    return b[k];
}

static const char *pth(const char *fmt, const char *a) {
    static char b[8][300];
    static int k;
    k = (k + 1) % 8;
    snprintf(b[k], sizeof b[k], fmt, a);
    return b[k];
}

/* ------------------------------------------------------------- data */

static const char k_xor[] = "0,0,0\n0,1,1\n1,0,1\n1,1,0\n";
static const char *const k_names[] = {
    "Anna", "Ben", "Clara", "David", "Emma", "Felix", "Greta", "Hugo", "Ida", "Jonas", "Klara", "Leon", "Mia",
    "Noah", "Olga", "Paul", "Rosa", "Simon", "Tara", "Ugo", "Vera", "Wim", "Xenia", "Yann", "Zoe", "Alma",
    "Bruno", "Cleo", "Dora", "Emil", "Frida", "Gustav", "Hanna", "Igor", "Jana", "Karl", "Lena", "Max", "Nina",
    "Oskar", "Pia", "Quirin", "Rita", "Sven", "Tilda", "Udo", "Viktor", "Wanda", "Yara", "Zeno", NULL};

static void names_text(nmzp_buf *b) {
    int i, r;
    for (r = 0; r < 6; r++)
        for (i = 0; k_names[i]; i++) nmzp_buf_printf(b, "%s\n", k_names[i]);
}

/* ------------------------------------------------------------- tests */

static void t_health(void) {
    reply rp;
    const char *proto, *rid;
    int st = call(&g_anon, "GET", "/v1/health", NULL, NULL, 0, &rp);
    EXPECT(st == 200, "GET /v1/health without a token: %d", st);
    EXPECT(rp.j && nmzp_json_get_str(rp.j, "status") && !strcmp(nmzp_json_get_str(rp.j, "status"), "ok"), "no status ok");
    proto = nmzp_json_get_str(rp.j, "protocol");
    EXPECT(proto && !strncmp(proto, "1.", 2), "protocol is %s, not 1.x", proto ? proto : "missing");
    rid = nmzp_http_header(&rp.r.head, "X-Request-Id");
    EXPECT(rid && *rid, "no X-Request-Id header");
    EXPECT(nmzp_http_header(&rp.r.head, "X-NeuroMZ-Protocol"), "no X-NeuroMZ-Protocol header");
    reply_free(&rp);
}

static void t_server(void) {
    reply rp;
    const nmzp_json *u;
    int st = json_call("GET", "/v1/server", NULL, &rp);
    EXPECT(st == 200, "GET /v1/server: %d", st);
    EXPECT(nmzp_json_get_str(rp.j, "name") && nmzp_json_get_str(rp.j, "version") && nmzp_json_get_str(rp.j, "library"),
           "name, version or library missing");
    EXPECT(nmzp_json_get_str(rp.j, "started") && nmzp_json_get_num(rp.j, "uptime_s", NULL), "started/uptime_s missing");
    u = nmzp_json_get(rp.j, "user");
    EXPECT(u && nmzp_json_get_str(u, "name") && nmzp_json_get(u, "permissions"), "user missing");
    reply_free(&rp);
}

static void t_capabilities(void) {
    reply rp;
    const nmzp_json *b, *sv, *al, *tr;
    size_t i;
    int cpu = 0, auth = 1;
    int st = json_call("GET", "/v1/capabilities", NULL, &rp);
    EXPECT(st == 200, "GET /v1/capabilities: %d", st);
    EXPECT(nmzp_json_get_bool(rp.j, "auth", &auth), "auth missing");
    g_auth = auth;
    b = nmzp_json_get(rp.j, "backends");
    EXPECT(b && b->type == NMZP_JSON_ARRAY && b->n > 0, "backends missing");
    for (i = 0; i < b->n; i++) {
        const char *n = nmzp_json_get_str(b->items[i], "name");
        int av = 0;
        EXPECT(n && nmzp_json_get_bool(b->items[i], "available", &av), "a backend without name/available");
        if (!strcmp(n, "cpu") && av) cpu = 1;
    }
    EXPECT(cpu, "the cpu backend is not available");
    EXPECT(nmzp_json_get_str(rp.j, "default_device"), "default_device missing");
    EXPECT(nmzp_json_get(rp.j, "presets") && nmzp_json_get(rp.j, "presets")->n > 0, "no presets");
    sv = nmzp_json_get(rp.j, "save");
    al = nmzp_json_get(sv, "allowed");
    EXPECT(sv && nmzp_json_get_str(sv, "default") && al && al->n > 0, "save.default/allowed missing");
    g_allow_client = g_allow_server = 0;
    for (i = 0; i < al->n; i++) {
        if (nmzp_json_str(al->items[i]) && !strcmp(nmzp_json_str(al->items[i]), "client")) g_allow_client = 1;
        if (nmzp_json_str(al->items[i]) && !strcmp(nmzp_json_str(al->items[i]), "server")) g_allow_server = 1;
    }
    EXPECT(nmzp_json_get(rp.j, "limits"), "limits missing");
    {
        double me = 0;
        if (nmzp_json_get_num(nmzp_json_get(rp.j, "limits"), "max_epochs", &me) && me >= 1) g_max_epochs = (long)me;
        if (nmzp_json_get_num(nmzp_json_get(rp.j, "limits"), "max_layer_size", &me) && me >= 1 && me < 1e9)
            g_max_layer = me;
    }
    tr = nmzp_json_get(rp.j, "trace");
    EXPECT(tr && nmzp_json_get_bool(tr, "enabled", &g_trace_enabled), "trace.enabled missing");
    reply_free(&rp);
}

static void t_auth(void) {
    reply rp;
    nmzp_client bad;
    int st;
    if (!g_auth) {
        skip();
        return;
    }
    st = call(&g_anon, "GET", "/v1/models", NULL, NULL, 0, &rp);
    EXPECT(is_error(&rp, 401, "unauthorized"), "%s", g_why);
    EXPECT(nmzp_http_header(&rp.r.head, "WWW-Authenticate"), "401 without WWW-Authenticate");
    reply_free(&rp);
    nmzp_client_init(&bad, g_c.host, g_c.port, "not-a-real-token-0123456789");
    st = call(&bad, "GET", "/v1/server", NULL, NULL, 0, &rp);
    nmzp_client_close(&bad);
    EXPECT(st == 401 && is_error(&rp, 401, "unauthorized"), "a wrong token: %s", g_why);
    reply_free(&rp);
}

static void t_errors(void) {
    reply rp;
    char body[300];
    json_call("GET", "/v1/no-such-endpoint", NULL, &rp);
    EXPECT(is_error(&rp, 404, "not_found"), "unknown path: %s", g_why);
    reply_free(&rp);
    json_call("DELETE", "/v1/capabilities", NULL, &rp);
    EXPECT(is_error(&rp, 405, "method_not_allowed"), "DELETE /v1/capabilities: %s", g_why);
    EXPECT(nmzp_http_header(&rp.r.head, "Allow"), "405 without Allow");
    reply_free(&rp);
    json_call("POST", "/v1/models", "{\"name\": \"x\", \"args\": [", &rp);
    EXPECT(is_error(&rp, 400, "bad_request"), "malformed JSON: %s", g_why);
    reply_free(&rp);
    json_call("POST", "/v1/models", "{\"name\": \"../evil\", \"args\": [\"2\", \"4\", \"1\"]}", &rp);
    EXPECT(is_error(&rp, 400, "invalid_name"), "name ../evil: %s", g_why);
    reply_free(&rp);
    json_call("POST", "/v1/models", "{\"name\": \"CON\", \"args\": [\"2\", \"4\", \"1\"]}", &rp);
    EXPECT(is_error(&rp, 400, "invalid_name"), "name CON: %s", g_why);
    reply_free(&rp);
    snprintf(body, sizeof body, "{\"name\": \"%s\", \"args\": [\"2\", \"4\", \"1\"]}", nm("plain"));
    call(&g_c, "POST", "/v1/models", "text/plain", body, 0, &rp);
    EXPECT(is_error(&rp, 415, "unsupported_media_type"), "a text/plain body: %s", g_why);
    reply_free(&rp);
    json_call("GET", "/v1/models/no-such-model-0042", NULL, &rp);
    EXPECT(is_error(&rp, 404, "not_found"), "unknown model: %s", g_why);
    reply_free(&rp);
    json_call("GET", "/v1/jobs/j999999999", NULL, &rp);
    EXPECT(is_error(&rp, 404, "not_found"), "unknown job: %s", g_why);
    reply_free(&rp);
    json_call("GET", "/v1/models/%2e%2e%2fsecret", NULL, &rp);
    EXPECT(rp.r.status == 400 || rp.r.status == 404, "an encoded ../ in a path: %d", rp.r.status);
    reply_free(&rp);
}

static void t_datasets(void) {
    reply rp;
    char hex[65];
    const char *sha;
    nmzp_buf names;
    int st;
    st = call(&g_c, "PUT", pth("/v1/datasets/%s?format=csv", nm("xor")), "text/csv", k_xor, 0, &rp);
    EXPECT(st == 201, "PUT a CSV dataset: %d %.200s", st, rp.r.body.data);
    nmzp_sha256_hex(k_xor, strlen(k_xor), hex);
    sha = nmzp_json_get_str(rp.j, "sha256");
    EXPECT(sha && !strcmp(sha, hex), "sha256 %s, expected %s", sha ? sha : "missing", hex);
    EXPECT(nmzp_json_get_str(rp.j, "format") && !strcmp(nmzp_json_get_str(rp.j, "format"), "csv"), "format not csv");
    reply_free(&rp);
    st = call(&g_c, "PUT", pth("/v1/datasets/%s?format=csv", nm("xor")), "text/csv", k_xor, 0, &rp);
    EXPECT(is_error(&rp, 409, "conflict"), "the same name again: %s", g_why);
    reply_free(&rp);
    st = call(&g_c, "PUT", pth("/v1/datasets/%s?format=csv&overwrite=true", nm("xor")), "text/csv", k_xor, 0, &rp);
    EXPECT(st == 200 || st == 201, "overwrite=true: %d", st);
    reply_free(&rp);
    st = call(&g_c, "PUT", pth("/v1/datasets/%s", nm("noformat")), "text/csv", k_xor, 0, &rp);
    EXPECT(is_error(&rp, 400, "bad_request"), "no format: %s", g_why);
    reply_free(&rp);
    nmzp_buf_init(&names);
    names_text(&names);
    st = call(&g_c, "PUT", pth("/v1/datasets/%s?format=text", nm("names")), "text/plain", names.data, names.len, &rp);
    nmzp_buf_free(&names);
    EXPECT(st == 201, "PUT a text dataset: %d", st);
    reply_free(&rp);
    st = json_call("GET", "/v1/datasets", NULL, &rp);
    EXPECT(st == 200 && nmzp_json_get(rp.j, "items"), "GET /v1/datasets: %d", st);
    {
        const nmzp_json *it = nmzp_json_get(rp.j, "items");
        size_t i;
        int found = 0;
        for (i = 0; i < it->n; i++) found += nmzp_json_get_str(it->items[i], "name") && !strcmp(nmzp_json_get_str(it->items[i], "name"), nm("xor"));
        EXPECT(found == 1, "the uploaded dataset is not listed");
    }
    reply_free(&rp);
    st = json_call("GET", pth("/v1/datasets/%s", nm("names")), NULL, &rp);
    EXPECT(st == 200 && nmzp_json_get_str(rp.j, "owner"), "GET a dataset: %d", st);
    reply_free(&rp);
}

static void t_models(void) {
    reply rp;
    char body[600];
    const nmzp_json *m, *ex;
    double params = 0;
    size_t i;
    int created = 0;
    snprintf(body, sizeof body, "{\"name\": \"%s\", \"args\": [\"2\", \"4\", \"1\"], \"save\": \"%s\"}", nm("xor"),
             g_allow_server ? "server" : "client");
    EXPECT(json_call("POST", "/v1/models", body, &rp) == 201, "POST /v1/models 2 4 1: %d %.300s", rp.r.status,
           rp.r.body.data);
    m = nmzp_json_get(rp.j, "model");
    ex = nmzp_json_get(rp.j, "explanation");
    EXPECT(m && nmzp_json_get_num(m, "params", &params) && params == 17, "params is not 17");
    EXPECT(ex && ex->type == NMZP_JSON_ARRAY, "no explanation");
    for (i = 0; i < ex->n; i++)
        if (nmzp_json_str(ex->items[i]) && strstr(nmzp_json_str(ex->items[i]), "Created a network with 17 parameters"))
            created = 1;
    EXPECT(created, "the explanation lacks 'Created a network with 17 parameters.'");
    reply_free(&rp);
    EXPECT(json_call("POST", "/v1/models", body, &rp) == 409 && is_error(&rp, 409, "conflict"), "a second create: %s",
           g_why);
    reply_free(&rp);
    EXPECT(json_call("GET", pth("/v1/models/%s", nm("xor")), NULL, &rp) == 200, "GET the model: %d", rp.r.status);
    EXPECT(nmzp_json_get(rp.j, "layers") && nmzp_json_get(rp.j, "layers")->n >= 2, "no layers");
    EXPECT(nmzp_json_get_str(rp.j, "storage") && nmzp_json_get_num(rp.j, "version", NULL), "storage/version missing");
    reply_free(&rp);
    snprintf(body, sizeof body, "{\"name\": \"%s\", \"args\": [\"2\", \"x\", \"1\"]}", nm("bad"));
    json_call("POST", "/v1/models", body, &rp);
    EXPECT(is_error(&rp, 422, "invalid_argument"), "a bad layer spec: %s", g_why);
    EXPECT(strstr(err_msg(&rp), "layer spec"), "the library's message is not passed on: %s", err_msg(&rp));
    reply_free(&rp);
    if (g_max_layer > 0) { /* a layer above the server's limit is refused before it is built (PROTOCOL §11) */
        snprintf(body, sizeof body, "{\"name\": \"%s\", \"args\": [\"2\", \"%.0f:relu\", \"1\"]}", nm("huge"),
                 g_max_layer + 1);
        json_call("POST", "/v1/models", body, &rp);
        EXPECT(is_error(&rp, 422, "invalid_argument"), "a layer above max_layer_size: %s", g_why);
        reply_free(&rp);
        EXPECT(json_call("GET", pth("/v1/models/%s", nm("huge")), NULL, &rp) == 404, "a refused model was stored: %d",
               rp.r.status);
        reply_free(&rp);
    }
    snprintf(body, sizeof body,
             "{\"name\": \"%s\", \"input\": \"4\", \"layers\": [\"8:relu\", \"3:softmax\"], \"options\": {\"lr\": 0.02, "
             "\"epochs\": 5, \"shuffle\": false}}",
             nm("fields"));
    EXPECT(json_call("POST", "/v1/models", body, &rp) == 201, "the structured form: %d %.300s", rp.r.status,
           rp.r.body.data);
    m = nmzp_json_get(rp.j, "model");
    {
        double lr = 0;
        EXPECT(nmzp_json_get_num(nmzp_json_get(m, "config"), "lr", &lr) && lr > 0.0199 && lr < 0.0201,
               "options.lr did not reach the model's config");
    }
    reply_free(&rp);
    snprintf(body, sizeof body, "{\"name\": \"%s\", \"input\": \"2\", \"layers\": [\"4\", \"1\"], \"options\": {\"lr\": -1}}",
             nm("badopt"));
    json_call("POST", "/v1/models", body, &rp);
    EXPECT(is_error(&rp, 422, "invalid_argument"), "options.lr = -1: %s", g_why);
    EXPECT(strstr(err_msg(&rp), "--lr"), "the option's message: %s", err_msg(&rp));
    reply_free(&rp);
    snprintf(body, sizeof body, "{\"name\": \"%s\", \"preset\": \"names\", \"dataset\": \"%s\", \"options\": {\"epochs\": 1}}",
             nm("names"), nm("names"));
    EXPECT(json_call("POST", "/v1/models", body, &rp) == 201, "a preset with a dataset: %d %.300s", rp.r.status,
           rp.r.body.data);
    m = nmzp_json_get(rp.j, "model");
    {
        int seq = 0;
        double v = 0;
        EXPECT(nmzp_json_get_bool(m, "sequence", &seq) && seq, "a text model is not a sequence");
        EXPECT(nmzp_json_get_num(m, "vocab_size", &v) && v > 10, "no vocabulary");
    }
    reply_free(&rp);
    EXPECT(json_call("GET", "/v1/models", NULL, &rp) == 200 && nmzp_json_get(rp.j, "items"), "GET /v1/models");
    reply_free(&rp);
}

static void t_model_files(void) {
    reply rp, up;
    int st;
    EXPECT(json_call("GET", pth("/v1/models/%s/file", nm("xor")), NULL, &rp) == 200, "download: %d", rp.r.status);
    EXPECT(rp.r.body.len > 16 && !memcmp(rp.r.body.data + 1, "NMZ", 3), "not a model file (no 0x89 NMZ magic)");
    EXPECT(nmzp_http_header(&rp.r.head, "ETag"), "no ETag");
    st = call(&g_c, "PUT", pth("/v1/models/%s/file", nm("copy")), "application/octet-stream", rp.r.body.data, rp.r.body.len,
              &up);
    EXPECT(st == 201, "upload under another name: %d %.200s", st, up.r.body.data);
    {
        double p = 0;
        EXPECT(nmzp_json_get_num(up.j, "params", &p) && p == 17, "the uploaded model has %g parameters", p);
    }
    reply_free(&up);
    st = call(&g_c, "PUT", pth("/v1/models/%s/file", nm("copy")), "application/octet-stream", rp.r.body.data, rp.r.body.len,
              &up);
    EXPECT(is_error(&up, 409, "conflict"), "a second upload without overwrite: %s", g_why);
    reply_free(&up);
    reply_free(&rp);
    st = call(&g_c, "PUT", pth("/v1/models/%s/file", nm("garbage")), "application/octet-stream", "not a model", 11, &rp);
    EXPECT(is_error(&rp, 422, "invalid_argument"), "a file that is not a model: %s", g_why);
    reply_free(&rp);
}

/* ------------------------------------------------------------ jobs */

typedef struct stream_state {
    nmzp_sse sse;
    int states, epochs, batches, ended;
    char final_state[32];
    char last_id[32];
} stream_state;

static int on_event(const char *event, const char *id, const char *data, void *user) {
    stream_state *s = (stream_state *)user;
    if (id && *id) snprintf(s->last_id, sizeof s->last_id, "%s", id);
    if (!strcmp(event, "state")) s->states++;
    if (!strcmp(event, "epoch")) s->epochs++;
    if (!strcmp(event, "batch")) s->batches++;
    if (!strcmp(event, "end")) {
        nmzp_json *j = nmzp_json_parse(data, strlen(data), 64, NULL, 0);
        snprintf(s->final_state, sizeof s->final_state, "%s",
                 nmzp_json_get_str(j, "state") ? nmzp_json_get_str(j, "state") : "?");
        nmzp_json_free(j);
        s->ended = 1;
        return 1;
    }
    return 0;
}

static int on_bytes(const char *p, size_t n, void *user) {
    stream_state *s = (stream_state *)user;
    return nmzp_sse_feed(&s->sse, p, n) != 0;
}

static char g_job_xor[32];

static void wait_state(const char *id, const char *want, double seconds, char *got, size_t gotn) {
    double t0 = nmzp_clock();
    got[0] = '\0';
    while (nmzp_clock() - t0 < seconds) {
        reply rp;
        if (json_call("GET", pth("/v1/jobs/%s", id), NULL, &rp) == 200 && nmzp_json_get_str(rp.j, "state"))
            snprintf(got, gotn, "%s", nmzp_json_get_str(rp.j, "state"));
        reply_free(&rp);
        if (!strcmp(got, want) || !strcmp(got, "failed") || !strcmp(got, "succeeded") || !strcmp(got, "cancelled")) return;
        nmzp_sleep_ms(100);
    }
}

static void t_train_job(void) {
    reply rp;
    char body[400];
    stream_state ss;
    nmzp_response sr;
    const char *id;
    double steps = 0, v0 = 0, v1 = 0;
    int conv = 0;
    EXPECT(json_call("GET", pth("/v1/models/%s", nm("xor")), NULL, &rp) == 200, "the xor model");
    nmzp_json_get_num(rp.j, "version", &v0);
    reply_free(&rp);
    snprintf(body, sizeof body,
             "{\"type\": \"train\", \"model\": \"%s\", \"dataset\": \"%s\", \"device\": \"auto\", \"save\": \"%s\", "
             "\"options\": {}}",
             nm("xor"), nm("xor"), g_allow_server ? "server" : "client");
    EXPECT(json_call("POST", "/v1/jobs", body, &rp) == 202, "POST /v1/jobs: %d %.300s", rp.r.status, rp.r.body.data);
    id = nmzp_json_get_str(rp.j, "id");
    EXPECT(id && nmzp_json_get_str(rp.j, "state"), "no id/state");
    snprintf(g_job_xor, sizeof g_job_xor, "%s", id);
    reply_free(&rp);
    memset(&ss, 0, sizeof ss);
    nmzp_sse_init(&ss.sse, on_event, &ss);
    if (nmzp_client_stream(&g_c, "GET", pth("/v1/jobs/%s/events", g_job_xor), "Accept: text/event-stream\r\n", on_bytes,
                           &ss, &sr)) {
        nmzp_sse_free(&ss.sse);
        EXPECT(0, "the event stream: %s", g_c.err);
    }
    EXPECT(sr.status == 200, "events: HTTP %d", sr.status);
    EXPECT(nmzp_http_header(&sr.head, "Content-Type") && strstr(nmzp_http_header(&sr.head, "Content-Type"), "text/event-stream"),
           "events are not text/event-stream");
    nmzp_response_free(&sr);
    nmzp_sse_free(&ss.sse);
    EXPECT(ss.ended && ss.states >= 1 && ss.epochs >= 1, "the stream: %d state, %d epoch events, end %d", ss.states,
           ss.epochs, ss.ended);
    EXPECT(!strcmp(ss.final_state, "succeeded"), "the job ended %s", ss.final_state);
    EXPECT(json_call("GET", pth("/v1/jobs/%s", g_job_xor), NULL, &rp) == 200, "GET the job");
    EXPECT(nmzp_json_get_bool(nmzp_json_get(rp.j, "result"), "converged", &conv) && conv, "XOR did not converge");
    EXPECT(nmzp_json_get_str(rp.j, "device") && nmzp_json_get_str(rp.j, "config"), "device/config missing");
    reply_free(&rp);
    EXPECT(json_call("GET", pth("/v1/models/%s", nm("xor")), NULL, &rp) == 200, "the xor model after training");
    nmzp_json_get_num(rp.j, "train_steps", &steps);
    nmzp_json_get_num(rp.j, "version", &v1);
    EXPECT(steps > 0 && v1 > v0, "the trained model was not stored (steps %g, version %g -> %g)", steps, v0, v1);
    reply_free(&rp);
    /* a late subscriber gets the history, then end */
    memset(&ss, 0, sizeof ss);
    nmzp_sse_init(&ss.sse, on_event, &ss);
    if (nmzp_client_stream(&g_c, "GET", pth("/v1/jobs/%s/events", g_job_xor), NULL, on_bytes, &ss, &sr) == 0) {
        nmzp_response_free(&sr);
        nmzp_sse_free(&ss.sse);
        EXPECT(ss.ended && ss.epochs >= 1, "replay of a finished job: %d epochs, end %d", ss.epochs, ss.ended);
    } else {
        nmzp_sse_free(&ss.sse);
        EXPECT(0, "replay: %s", g_c.err);
    }
}

static void t_cancel(void) {
    reply rp;
    char body[400], state[32];
    const char *id;
    snprintf(body, sizeof body,
             "{\"type\": \"train\", \"model\": \"%s\", \"dataset\": \"%s\", \"save\": \"%s\", \"options\": {\"epochs\": "
             "%ld, \"patience\": 0, \"batch\": 1}}",
             nm("names"), nm("names"), g_allow_server ? "server" : "client", g_max_epochs);
    EXPECT(json_call("POST", "/v1/jobs", body, &rp) == 202, "POST a long job: %d %.300s", rp.r.status, rp.r.body.data);
    id = nmzp_json_get_str(rp.j, "id");
    EXPECT(id, "no id");
    {
        char jid[32];
        snprintf(jid, sizeof jid, "%s", id);
        reply_free(&rp);
        wait_state(jid, "running", 60, state, sizeof state);
        EXPECT(!strcmp(state, "running"), "the long job is %s, not running", state);
        EXPECT(json_call("POST", pth("/v1/jobs/%s/cancel", jid), "", &rp) == 202, "cancel: %d %.200s", rp.r.status,
               rp.r.body.data);
        reply_free(&rp);
        wait_state(jid, "cancelled", 60, state, sizeof state);
        EXPECT(!strcmp(state, "cancelled"), "after cancel the job is %s", state);
        EXPECT(json_call("POST", pth("/v1/jobs/%s/cancel", jid), "", &rp) == 409 && is_error(&rp, 409, "conflict"),
               "cancelling a finished job: %s", g_why);
        reply_free(&rp);
    }
}

static void t_job_list(void) {
    reply rp;
    const nmzp_json *it;
    size_t i;
    int found = 0;
    EXPECT(json_call("GET", "/v1/jobs?state=succeeded", NULL, &rp) == 200, "GET /v1/jobs?state=succeeded");
    it = nmzp_json_get(rp.j, "items");
    EXPECT(it && it->type == NMZP_JSON_ARRAY, "no items");
    for (i = 0; i < it->n; i++) {
        const char *st = nmzp_json_get_str(it->items[i], "state");
        EXPECT(st && !strcmp(st, "succeeded"), "the filter let a %s job through", st ? st : "?");
        if (nmzp_json_get_str(it->items[i], "id") && !strcmp(nmzp_json_get_str(it->items[i], "id"), g_job_xor)) found = 1;
    }
    EXPECT(found || !g_job_xor[0], "the finished job %s is not listed", g_job_xor);
    reply_free(&rp);
}

static void t_save_policy(void) {
    reply rp;
    char body[400], state[32], jid[32];
    const char *out;
    double v0 = 0, v1 = 0;
    if (!g_allow_client) {
        snprintf(body, sizeof body, "{\"name\": \"%s\", \"args\": [\"2\", \"4\", \"1\"], \"save\": \"client\"}", nm("cl"));
        json_call("POST", "/v1/models", body, &rp);
        EXPECT(is_error(&rp, 403, "save_not_allowed"), "save=client on a server that does not allow it: %s", g_why);
        reply_free(&rp);
        return;
    }
    snprintf(body, sizeof body, "{\"name\": \"%s\", \"args\": [\"2\", \"4\", \"1\"], \"save\": \"client\"}", nm("cl"));
    EXPECT(json_call("POST", "/v1/models", body, &rp) == 201, "save=client: %d", rp.r.status);
    EXPECT(nmzp_json_get_str(nmzp_json_get(rp.j, "model"), "storage") &&
               !strcmp(nmzp_json_get_str(nmzp_json_get(rp.j, "model"), "storage"), "client"),
           "storage is not client");
    EXPECT(nmzp_json_get_str(nmzp_json_get(rp.j, "model"), "expires"), "a client model without expires");
    reply_free(&rp);
    if (!g_allow_server) return;
    EXPECT(json_call("GET", pth("/v1/models/%s", nm("xor")), NULL, &rp) == 200, "the xor model");
    nmzp_json_get_num(rp.j, "version", &v0);
    reply_free(&rp);
    snprintf(body, sizeof body,
             "{\"type\": \"train\", \"model\": \"%s\", \"dataset\": \"%s\", \"save\": \"client\", \"options\": {\"epochs\": 5}}",
             nm("xor"), nm("xor"));
    EXPECT(json_call("POST", "/v1/jobs", body, &rp) == 202, "a save=client job: %d %.200s", rp.r.status, rp.r.body.data);
    snprintf(jid, sizeof jid, "%s", nmzp_json_get_str(rp.j, "id") ? nmzp_json_get_str(rp.j, "id") : "");
    reply_free(&rp);
    wait_state(jid, "succeeded", 60, state, sizeof state);
    EXPECT(!strcmp(state, "succeeded"), "the save=client job: %s", state);
    EXPECT(json_call("GET", pth("/v1/jobs/%s", jid), NULL, &rp) == 200, "the job");
    out = nmzp_json_get_str(rp.j, "output_model");
    EXPECT(out && strcmp(out, nm("xor")), "save=client on a server model must not overwrite it (output_model %s)",
           out ? out : "null");
    reply_free(&rp);
    EXPECT(json_call("GET", pth("/v1/models/%s", nm("xor")), NULL, &rp) == 200, "the xor model again");
    nmzp_json_get_num(rp.j, "version", &v1);
    EXPECT(v1 == v0, "the stored model changed (version %g -> %g)", v0, v1);
    reply_free(&rp);
    EXPECT(json_call("GET", pth("/v1/jobs/%s/model", jid), NULL, &rp) == 200 && rp.r.body.len > 16, "the job's model: %d",
           rp.r.status);
    reply_free(&rp);
}

static void t_inference(void) {
    reply rp;
    char body[300];
    const nmzp_json *o, *it;
    double acc = 0, n = 0;
    EXPECT(json_call("POST", pth("/v1/models/%s/predict", nm("xor")), "{\"inputs\": [[0,0],[0,1],[1,0],[1,1]]}", &rp) == 200,
           "predict: %d %.200s", rp.r.status, rp.r.body.data);
    o = nmzp_json_get(rp.j, "outputs");
    EXPECT(o && o->n == 4 && nmzp_json_at(o, 0) && nmzp_json_at(o, 0)->n == 1, "outputs are not 4 x 1");
    {
        double a = 1, b = 0;
        nmzp_json_num(nmzp_json_at(nmzp_json_at(o, 0), 0), &a);
        nmzp_json_num(nmzp_json_at(nmzp_json_at(o, 1), 0), &b);
        EXPECT(a < 0.5 && b > 0.5, "the trained XOR predicts %g for 0,0 and %g for 0,1", a, b);
    }
    reply_free(&rp);
    json_call("POST", pth("/v1/models/%s/predict", nm("xor")), "{\"inputs\": [1, 2, 3]}", &rp);
    EXPECT(is_error(&rp, 422, "invalid_argument"), "3 inputs for a 2-input model: %s", g_why);
    reply_free(&rp);
    snprintf(body, sizeof body, "{\"dataset\": \"%s\"}", nm("xor"));
    EXPECT(json_call("POST", pth("/v1/models/%s/test", nm("xor")), body, &rp) == 200, "test: %d %.200s", rp.r.status,
           rp.r.body.data);
    EXPECT(nmzp_json_get_num(rp.j, "samples", &n) && n == 4, "test samples: %g", n);
    EXPECT(nmzp_json_get_num(rp.j, "accuracy", &acc) && acc > 0.99, "accuracy %g", acc);
    EXPECT(nmzp_json_get_num(rp.j, "loss", NULL), "no loss");
    reply_free(&rp);
    EXPECT(json_call("POST", pth("/v1/models/%s/generate", nm("names")), "{\"count\": 3, \"seed\": 5}", &rp) == 200,
           "generate: %d %.200s", rp.r.status, rp.r.body.data);
    EXPECT(nmzp_json_get_str(rp.j, "kind") && !strcmp(nmzp_json_get_str(rp.j, "kind"), "items"), "kind is not items");
    it = nmzp_json_get(rp.j, "items");
    EXPECT(it && it->type == NMZP_JSON_ARRAY && it->n <= 3, "items");
    reply_free(&rp);
    EXPECT(json_call("POST", pth("/v1/models/%s/predict", nm("names")), "{\"text\": \"An\"}", &rp) == 200,
           "predict text: %d %.200s", rp.r.status, rp.r.body.data);
    EXPECT(nmzp_json_get(rp.j, "next") && nmzp_json_get(rp.j, "next")->n > 0, "no next characters");
    reply_free(&rp);
    json_call("POST", pth("/v1/models/%s/generate", nm("xor")), "{\"count\": 1}", &rp);
    EXPECT(is_error(&rp, 422, "invalid_argument"), "generate on a non-text model: %s", g_why);
    reply_free(&rp);
}

static void t_trace(void) {
    reply rp;
    const char *ct, *ev;
    int st = json_call("POST", pth("/v1/models/%s/trace", nm("xor")), "{\"inputs\": [1, 0], \"target\": [1]}", &rp);
    if (!g_trace_enabled) {
        EXPECT(is_error(&rp, 403, "forbidden"), "trace on a server that disables it: %s", g_why);
        reply_free(&rp);
        return;
    }
    EXPECT(st == 200, "trace: %d %.200s", st, rp.r.body.data);
    ct = nmzp_http_header(&rp.r.head, "Content-Type");
    ev = nmzp_http_header(&rp.r.head, "X-Trace-Events");
    EXPECT(ct && strstr(ct, "application/x-ndjson"), "trace is not application/x-ndjson");
    EXPECT(ev && atoi(ev) > 0, "X-Trace-Events missing");
    {
        const char *p = rp.r.body.data;
        int lines = 0, fwd = 0, bwd = 0;
        while (p && *p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            nmzp_json *j = nmzp_json_parse(p, len, 64, NULL, 0);
            const char *ph = nmzp_json_get_str(j, "phase");
            EXPECT(j && ph && nmzp_json_get(j, "items"), "trace line %d is not an event", lines + 1);
            fwd += !strcmp(ph, "forward");
            bwd += !strcmp(ph, "backward");
            nmzp_json_free(j);
            lines++;
            p = nl ? nl + 1 : NULL;
        }
        EXPECT(lines == atoi(ev) && fwd > 0 && bwd > 0, "%d lines (%d forward, %d backward), header says %s", lines, fwd,
               bwd, ev);
    }
    reply_free(&rp);
}

static void t_permissions(void) {
    reply rp;
    char body[200];
    if (!g_have_read) {
        skip();
        return;
    }
    EXPECT(call(&g_read, "GET", "/v1/models", NULL, NULL, 0, &rp) == 200, "read token: GET /v1/models %d", rp.r.status);
    reply_free(&rp);
    snprintf(body, sizeof body, "{\"name\": \"%s\", \"args\": [\"2\", \"4\", \"1\"]}", nm("ro"));
    call(&g_read, "POST", "/v1/models", NULL, body, 0, &rp);
    EXPECT(is_error(&rp, 403, "forbidden"), "read token creating a model: %s", g_why);
    reply_free(&rp);
    call(&g_read, "DELETE", pth("/v1/models/%s", nm("xor")), NULL, NULL, 0, &rp);
    EXPECT(is_error(&rp, 403, "forbidden"), "read token deleting a model: %s", g_why);
    reply_free(&rp);
    EXPECT(call(&g_read, "POST", pth("/v1/models/%s/predict", nm("xor")), NULL, "{\"inputs\": [0, 1]}", 0, &rp) == 200,
           "read token predicting: %d", rp.r.status);
    reply_free(&rp);
}

static void t_cleanup(void) {
    static const char *const models[] = {"xor", "fields", "names", "copy", "cl", NULL};
    static const char *const sets[] = {"xor", "names", NULL};
    int i;
    for (i = 0; models[i]; i++) {
        reply rp;
        int st = json_call("DELETE", pth("/v1/models/%s", nm(models[i])), NULL, &rp);
        reply_free(&rp);
        EXPECT(st == 204 || st == 404, "DELETE model %s: %d", nm(models[i]), st);
    }
    for (i = 0; sets[i]; i++) {
        reply rp;
        int st = json_call("DELETE", pth("/v1/datasets/%s", nm(sets[i])), NULL, &rp);
        reply_free(&rp);
        EXPECT(st == 204, "DELETE dataset %s: %d", nm(sets[i]), st);
    }
    {
        reply rp;
        json_call("GET", pth("/v1/models/%s", nm("xor")), NULL, &rp);
        EXPECT(rp.r.status == 404, "a deleted model is still there");
        reply_free(&rp);
    }
}

/* -------------------------------------------------------------- main */

static int usage(void) {
    fprintf(stderr, "usage: nmz-conformance --url http://HOST:PORT [--token T] [--read-token T] [--prefix P] [--verbose]\n");
    return 2;
}

int main(int argc, char **argv) {
    const char *url = NULL, *token = "", *rtoken = NULL;
    char host[256];
    int port, i;
    unsigned char rnd[4];
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--url") && i + 1 < argc) url = argv[++i];
        else if (!strcmp(argv[i], "--token") && i + 1 < argc) token = argv[++i];
        else if (!strcmp(argv[i], "--read-token") && i + 1 < argc) rtoken = argv[++i];
        else if (!strcmp(argv[i], "--prefix") && i + 1 < argc) snprintf(g_prefix, sizeof g_prefix, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--verbose")) g_verbose = 1;
        else return usage();
    }
    if (!url || nmzp_parse_hostport(url, host, sizeof host, &port)) return usage();
    if (nmzp_net_init()) {
        fprintf(stderr, "error: the socket library did not start\n");
        return 2;
    }
    if (!g_prefix[0]) {
        char hex[9];
        nmzp_random(rnd, sizeof rnd);
        nmzp_hex(rnd, sizeof rnd, hex);
        snprintf(g_prefix, sizeof g_prefix, "cf%s", hex);
    }
    nmzp_client_init(&g_c, host, port, token);
    nmzp_client_init(&g_anon, host, port, NULL);
    nmzp_client_init(&g_read, host, port, rtoken);
    snprintf(g_c.user_agent, sizeof g_c.user_agent, "nmz-conformance/%s", NMZP_PROTOCOL);
    g_c.timeout_ms = 120000;
    g_have_read = rtoken != NULL;
    printf("# NeuroMZ protocol %s conformance: %s (names %s-*)\n", NMZP_PROTOCOL, url, g_prefix);
    run("health", t_health);
    run("server", t_server);
    run("capabilities", t_capabilities);
    run("authentication", t_auth);
    run("errors", t_errors);
    run("datasets", t_datasets);
    run("models", t_models);
    run("model files", t_model_files);
    run("training job and events", t_train_job);
    run("cancelling a job", t_cancel);
    run("listing jobs", t_job_list);
    run("save policy", t_save_policy);
    run("inference", t_inference);
    run("trace", t_trace);
    run("permissions", t_permissions);
    run("cleanup", t_cleanup);
    printf("1..%d\n# %d passed, %d failed, %d skipped\n", g_n, g_pass, g_fail, g_skip);
    nmzp_client_close(&g_c);
    nmzp_client_close(&g_read);
    nmzp_client_close(&g_anon);
    return g_fail ? 1 : 0;
}
