# neuromz-protocol — design

Why the NeuroMZ protocol looks the way it does. The protocol itself is
[`PROTOCOL.md`](../PROTOCOL.md); the library's design (decisions 1–165) is
in [neuromz/docs/DESIGN.md](https://github.com/mzprog/neuromz/blob/master/docs/DESIGN.md),
the reference server's in
[neuromz-server/docs/DESIGN.md](https://github.com/mzprog/neuromz-server/blob/master/docs/DESIGN.md).
Decisions here are numbered P1, P2, ….

## Goals

Three kinds of client use the same API: the `neuromz` program's remote
mode (C, a terminal), the planned `neuromz-web` (a browser, no build
step needed to talk to it), and scripts (`curl`). The server hosts models
like a database hosts tables, and runs training as jobs on the CPU or a
GPU. Everything a local `neuromz` does with a model should be possible
remotely, with the same words and the same messages.

## Decisions

P1. **HTTP/1.1 and JSON, under `/v1`.** Every language and every browser
    speaks it; it goes through proxies and is easy to debug with `curl`.
    No gRPC (a code generator and HTTP/2 for every client, poor browser
    support) and no binary framing (the payloads that are large — model
    files and datasets — travel as raw bytes anyway). The version is in
    the path so that an incompatible change can live next to the old one.
    Default port 8470 (unassigned).

P2. **No TLS in the protocol's servers, for now.** TLS is a large
    dependency (or a large amount of code) and a reverse proxy (nginx,
    Caddy, IIS) does it better: certificates, renewal, HTTP/2 to the
    outside. The reference server binds to 127.0.0.1 by default. Bearer
    tokens are only safe over TLS or on a trusted network; PROTOCOL §1
    says so.

P3. **Progress as Server-Sent Events.** A browser's `EventSource` reads
    them with no library, they are plain HTTP (one long response), and
    they reconnect by themselves. WebSockets would add a second protocol
    (an upgrade, framing, masking) for a stream that only flows one way.
    `state` and `epoch` events are numbered and kept with the job, so a
    client that connects late or reconnects (`Last-Event-ID`) misses
    nothing that matters; `batch` events are live only and rate-limited
    (a thousand batches a second must not become a thousand events).
    `end` closes every stream, so a client never has to guess. Keep-alive
    comments every 15 s keep proxies from closing an idle stream.

P4. **A bearer token, and `?access_token=` for GET.** One header, any
    client. `EventSource` cannot set headers, hence the query parameter —
    for GET only, and servers must keep it out of their logs. Three
    permissions (`read`, `train`, `admin`) cover a classroom and a lab:
    readers run inference, trainers own what they create, admins own
    everything. A server may run without authentication (a laptop on
    127.0.0.1): every request is then `anonymous` with every permission,
    and the capabilities say so.

P5. **One error shape, with codes.** `{"error": {"code", "message",
    "details"}}` and the HTTP status. `code` is a stable word for programs
    (`invalid_name`, `queue_full`, `save_not_allowed`), `message` is the
    library's own message where the library refused, so a remote user
    reads exactly what a local one reads. A failed job carries the same
    shape in the job object, plus `out_of_memory` and `numeric`.

P6. **Models are described the way the program describes them.** `POST
    /v1/models` takes the arguments of `neuromz new` verbatim (`args`) or
    the same in fields (`layers`, `preset`, `loss`, …), and the server
    builds the model with the library's own parser (`nmz_model_new`,
    library decision 159). No second model grammar to design, document and
    keep in step; the same description gives the same model and the same
    error message everywhere; the explanation of every default comes back
    with the model, ready for a web page. Training options likewise:
    `options` keyed by the program's option names, or `args`.

P7. **Where a trained model goes is the request's choice, within the
    server's policy.** `save: server` keeps it in the server's store
    (persistent, counted in a quota); `save: client` keeps it only for the
    client to download (forgotten after `client_model_hours` and at a
    restart). Training with `save: client` on a stored model never changes
    the stored model: the result becomes a new client model `NAME.jID`.
    So a reader-trainer can experiment on a shared model without touching
    it, and an administrator can forbid storing anything (`allowed =
    client`). A cancelled job writes the batches it finished (it is a
    clean stop, library decision 160); a failed job writes nothing.

P8. **Names are file-name safe on every system.** Models and datasets are
    addressed by name in URLs and stored as files: `[A-Za-z0-9._-]`, 1–64
    characters, starting with a letter or digit, not ending in a dot, no
    Windows device names. Path traversal is impossible by construction,
    not by filtering, and a name means the same on Linux and Windows.

P9. **Datasets are uploaded once, or registered from the server's disk.**
    `PUT /datasets/{name}?format=` takes the file's bytes (no multipart
    encoding: a browser `fetch` and `curl --data-binary` send it as is);
    the dataset's `sha256` lets a client skip an upload the server already
    has. Large data that is already on the server (MNIST, a corpus) is
    registered by a path relative to a root the server's configuration
    allows — never an absolute path, never `..`.

P10. **Inference is synchronous; training is a job.** Predicting,
    testing, generating and tracing take a fraction of a second to
    seconds and are bounded by the request's size, so the answer is the
    response. Training takes minutes to hours, may wait for a GPU, and
    must survive the client going away, so it is a job with a state, a
    queue and an event stream.

P11. **Traces are the library's JSON lines.** `POST /models/{name}/trace`
    returns `application/x-ndjson`, one event per line exactly as
    `nmz_trace_event_write_json` writes them — the format the program's
    `trace --json` already writes and the web viewer will read. The
    server's `max_events` bounds the response.

P12. **Samples count from 0 on the wire.** The program counts from 1 for
    people; programs count from 0. The program converts.

P13. **Lists are objects; unknown fields are ignored.** `{"items": [...]}`
    leaves room for paging later; clients ignore fields they do not know
    and servers ignore unknown request fields, so 1.x can add fields
    without breaking anyone (semantic versioning, PROTOCOL §13).

P14. **Browsers are first-class.** Servers may answer CORS preflights for
    configured origins; every endpoint returns JSON a page can show
    directly; the event stream works with `EventSource`. The web client
    needs nothing the program does not also use.

P15. **One C implementation of the wire format, in this repository.**
    `nmzp` (C11, no dependencies, Winsock and POSIX) is the JSON parser
    and writer, the HTTP/1.1 head parser, chunked bodies, the SSE parser
    and writer, sockets, a keep-alive client, SHA-256 and helpers (names,
    times, constant-time comparison, random bytes). The server and the
    program both link it, so they cannot disagree about the wire, and the
    conformance suite uses it too. It is written for hostile input: the
    JSON parser checks UTF-8 (overlong forms, surrogates, code points
    above U+10FFFF) and has a depth limit instead of unbounded recursion;
    the HTTP parser refuses request-smuggling forms (`Content-Length`
    with `Transfer-Encoding`, two different lengths, folded lines, NUL
    bytes) and bounds heads and chunk sizes.

P16. **The conformance suite is a C program.** It builds wherever a
    server builds (Windows included, no Python or Node), runs against any
    URL, brings its own tiny datasets, names what it creates with a random
    prefix and deletes it, so it can check a shared or production server.
    It reads the server's capabilities and checks what the server says it
    allows (a server without traces is checked to refuse them). Output is
    TAP-like; the exit status says whether everything passed. The
    reference server runs it in its integration tests and in CI; this
    repository's CI builds that server from its repository and runs the
    suite against it live.

P17. **Fuzzed under sanitizers.** `fuzz_wire` feeds random and mutated
    inputs (from a corpus of valid messages) into every parser; CI runs
    it under ASan + UBSan with GCC and Clang.

## Deferred

TLS in the server; paging of lists; resumable uploads; WebSockets for
interactive sessions (step-by-step training from a browser); per-model
access lists beyond owner/admin; a job type for `step`, `gradcheck` and
`compare` (the program runs those locally for now).
