# neuromz-protocol — design

Why the NeuroMZ protocol looks the way it does. The protocol itself is
[`PROTOCOL.md`](../PROTOCOL.md); the library's design (decisions 1–172) is
in [neuromz/docs/DESIGN.md](https://github.com/mzprog/neuromz/blob/2.0.0-dev/docs/DESIGN.md),
the reference server's in
[neuromz-server/docs/DESIGN.md](https://github.com/mzprog/neuromz-server/blob/2.0.0-dev/docs/DESIGN.md).
Decisions here are numbered P1, P2, …; P1–P17 are protocol 1 (HTTP, 2026,
withdrawn), P18 onwards protocol 2; P38–P41 are the versions, branches and
pins that every NeuroMZ repository shares.

## Goals

The clients of protocol 2 are programs: the `neuromz` program's remote mode
(C, through `nmzp`), and a PHP client library (`neuromz-php`, planned: pure
PHP first, a compiled extension with the same API later) through which a
web application will reach the server — the browser talks to the web
application, not to the server. The server hosts models like a database
hosts tables and runs training as jobs on the CPU or a GPU. Everything a
local `neuromz` does with a model should be possible remotely, with the same
words and the same messages.

## Protocol 2

P18. **A binary protocol of its own over TCP; no HTTP at all** (the
    owner's decision for 2.0). A client keeps one connection and sends
    requests, files and subscriptions over it, as a MySQL, SQL Server (TDS)
    or Redis (RESP) client does; the server pushes training progress on the
    same connection. Compared with protocol 1 this removes the HTTP
    machinery from both ends (heads, chunked bodies, keep-alive rules,
    request smuggling, CORS, Server-Sent Events as a second channel) and
    lets one connection carry several requests at once. The price: `curl`
    and browsers cannot talk to a server directly any more; a web
    application talks to it through the PHP client, the way it talks to
    its database. Protocol 1 stays in the history and the changelog (its
    tag `v1.0.0` was withdrawn with the others, P38).

P19. **Port 8470, unchanged.** A 2.0 server replaces a 1.0 server on the
    same machine, so existing firewall rules, SSH tunnels and client
    profiles keep working; a client of the wrong version fails at once
    and says why (P23), so sharing the port costs nothing.

P20. **Frames: a 12-byte little-endian header, then the payload.**
    `u32 length, u8 type, u8 flags, u16 reserved, u32 request id`. The
    length comes first, so a reader knows from four bytes how much
    follows, and refuses a frame over its limit before reading it (P32).
    Little-endian because every machine the server runs on is, and `pack('V')`
    reads it in PHP. Twelve frame types, one flag (`MORE`) and reserved
    bits that must be zero: a receiver that meets anything else closes the
    connection, so a later version cannot be misread by an older peer — new
    behaviour comes with a new minor version or a capability (P23), never
    silently. *(Since P42: with a capability; the minor stays 0.)*

P21. **Payloads: a documented MessagePack subset, not a TLV of our own.**
    Both are easy to write in pure PHP (`pack`/`unpack` have every integer
    and float width in both byte orders). MessagePack wins because it
    already exists everywhere: pure-PHP libraries and the PECL extension
    (which a future C extension of the PHP client could lean on), Python,
    JavaScript, Go, Java — so debugging tools and third-party clients come
    for free, and our test vectors are checked against an independent
    implementation (`msgpack-python` agrees byte for byte with every
    canonical vector). The subset drops extension types (including the
    timestamp: times are ints, P31), keeps map keys to `str` and ints to the
    signed 64-bit range PHP has. Its numbers are big-endian, as MessagePack
    defines them; the frame header is little-endian. The boundary is
    sharp — a payload is an opaque blob to the framing — so the two orders
    never meet in one field. A canonical form (shortest integers and
    headers, every float as float 64) makes the vectors deterministic and
    lets two implementations compare bytes, but readers accept any form of
    the subset.

P22. **Large arrays of numbers are raw float32, little-endian, in a
    `bin`.** Model outputs and inputs are float32 in the library; sending
    them as MessagePack floats would cost 9 bytes and a conversion per
    number on both ends. A `bin` of the library's own bytes costs 4 and no
    conversion, and a PHP client passes it on as a string (to a file, a
    response, a JavaScript `Float32Array`) without decoding it, or reads it
    with `unpack('g*')` when it must. Fields say so (`bin (f32)`) and carry
    their shape. Small inputs may still be arrays of numbers.

P23. **The server speaks first; magic and version in both handshake
    frames.** As MySQL does, the server greets: a client learns at once
    whether it reached a NeuroMZ server, which version, and the nonce for
    its proof. The greeting and the hello start with 12 fixed bytes —
    the magic `NMZP\r\n\x1a\n` (the PNG trick: line-end conversions and a
    DOS end-of-file byte show) and the major and minor version — so a
    future major version may change everything after them, even the
    payload encoding, and still be recognised and refused cleanly. The
    server announces its highest version and its lowest major; the client
    picks; a mismatch is `unsupported_version` with the server's range in
    `details`. A protocol 1 client (HTTP) gets an ERROR frame saying that
    the server speaks protocol 2; a protocol 2 client that reaches a
    protocol 1 server waits for a greeting that never comes and says so.

P24. **Authentication: HMAC-SHA256 challenge and response, keyed by
    SHA-256 of the token.** The server never stored tokens, only their
    SHA-256 (the tokens file's `sha256:` lines, server decision S8); that
    hash is exactly the key the server needs, so existing tokens files and
    tokens work unchanged and the token itself never crosses the network.
    The client sends a key id (8 bytes of an HMAC of the key, so the server
    finds the entry without trying every key) and its proof over both
    nonces; the server answers with its own proof, so the client knows it
    reached the server that holds its token (mutual). Every proof is
    compared in constant time; an unknown key id and a wrong proof get the
    same answer. The limits are written down in PROTOCOL §6.2: the tokens
    file is now token-equivalent for this protocol, a recorded handshake
    allows offline guessing of weak tokens (the generated ones have 192
    random bits), and nothing after the handshake is protected. A client
    that holds a token refuses a server that offers no authentication
    unless told otherwise, so an attacker cannot strip the challenge from
    the greeting to pose as the server.

P25. **TLS deferred; the handshake leaves the door open.** TLS is a large
    dependency, and a reverse proxy no longer helps (there is no HTTP to
    proxy). The way in is MySQL's: a server lists `starttls` in its
    greeting, a client answers with a STARTTLS frame (type `0x04`,
    reserved now) instead of HELLO, both run TLS on the same connection,
    and the handshake starts again inside it with a new nonce; the proofs
    could then bind the TLS channel. Until then: a trusted network, an SSH
    tunnel or a VPN — PROTOCOL §2 and §6.2 say so.

P26. **Several requests at once on one connection, answered in any
    order.** The client numbers its requests; the server runs each in its
    own thread and answers when it is done, so a quick `health` is not
    stuck behind a long `test`, and frames of different requests
    interleave (a large download travels in DATA frames between other
    answers). A request ends with its sender's frame without `MORE`; then
    its id is free. `max_inflight` (announced in WELCOME) bounds the work
    one connection can start; one more is refused with
    `too_many_requests`, not a broken connection.

P27. **Files travel as DATA frames with an END that carries their size
    and SHA-256.** No frame has to hold a whole model or dataset, the
    receiver checks what arrived (`integrity_error`), and an upload
    announces its size in its REQUEST so the server refuses one that is too
    large before a byte of it is sent. The same shape serves model
    downloads and traces. ABORT stops either direction.

P28. **Training progress is pushed on the same connection.** A
    subscription is a request whose answer is a stream of EVENT frames:
    numbered `state`, `epoch` and `end` events kept with the job (a client
    that comes late or reconnects asks for the events `after` the last it
    has, as protocol 1's `Last-Event-ID` did) and live `batch` events at
    most four a second. `end` is the last frame, so a client never has to
    guess. Unsubscribing is ABORT. A quiet subscription gets a PING every
    30 s, so a dead client is found and NAT tables stay warm. Several
    subscriptions and other requests share the connection.

P29. **One error frame; stable numeric codes in ranges, and v1's names.**
    `{"code", "name", "message", "details"}`: the code for programs (and
    a future extension's exception classes), the name for people and logs
    — the same words as protocol 1 where they still apply (`invalid_name`,
    `queue_full`, `save_not_allowed`, …) — and the library's own message
    where the library refused. Ranges (1xx the connection, 2xx the request,
    3xx permission, 4xx state, 5xx the server) let a client handle a code
    it does not know. An error about the connection uses request id 0 and
    is followed by the close, so a client never has to tell a broken
    connection from a refused request by guessing.

P30. **The operations of protocol 1, under dotted names, with the same
    arguments.** `models.create` takes what `POST /v1/models` took, and so
    on: the semantics, the save policy (P7), the limits and the library's
    messages are unchanged, so the server's logic stayed and only its
    transport changed. The model grammar is still the program's (P6).

P31. **Times are ints (seconds since 1970, UTC); a number that is not
    finite is nil.** A typed encoding has integers, so the RFC 3339
    strings of protocol 1 (JSON has no time type) give way to the
    simplest thing every language can use (`new DateTime('@' . $t)`).

P32. **A payload holds at most 262 144 values, 32 levels deep.** A decoded
    value costs memory out of proportion to its bytes (a one-byte integer
    becomes a node), so without a limit a 4 MiB frame of tiny integers
    could make a server allocate hundreds of MiB. Counts are checked
    against the bytes left before anything is allocated, duplicate keys are
    found with a hash set in large maps (no quadratic scan), and big arrays
    of numbers have their own form (P22). The limits are part of the
    protocol, not of one server, so every client knows them.

P33. **`nmzp` keeps JSON, for what is JSON.** The trace is the library's
    JSON lines by definition (P11; a viewer reads it as it is), so the C
    client parses those lines, and the reference server keeps its store's
    metadata files in JSON for people to read. The JSON code moved to its
    own header (`nmzp_json.h`), apart from the wire.

P34. **Shared test vectors, written by the C implementation and checked
    everywhere.** `tests/vectors/` holds bytes and typed descriptions of
    every encoding at its boundaries, the non-canonical forms a reader must
    accept, what a reader must refuse, every frame type, and the handshake
    with proofs for a test token. CI writes them afresh and compares them
    with the committed files, and checks the committed files; another
    implementation (neuromz-php) passes the same files in its own CI. The
    descriptions are typed JSON (`{"int": "-33"}`, `{"float": ..., "bits":
    ...}`, `{"bin": "..."}`, `{"map": [[k, v], ...]}`) so nothing is lost
    between two languages' number types.

P35. **The conformance suite checks the protocol, not only the
    operations.** Beside every operation of protocol 1's suite it sends
    what a careless or hostile client would: a bad magic, an unknown
    version, an HTTP request, a wrong token, a proof for another
    connection's nonce, an oversized or truncated frame, unknown types,
    flags and reserved bits, a request id twice, more requests than
    allowed, interleaved uploads and requests, uploads with the wrong hash,
    disconnects in the middle of streams — and checks that the server
    answers as the spec says and stays up.

P36. **Fuzzed where bytes come in.** `fuzz_wire` feeds random and
    mutated frames and payloads to the frame parser and the decoder under
    ASan + UBSan, and checks that whatever decodes re-encodes to bytes that
    decode to the same canonical bytes; the reference server's tests send
    mutated frames to a live server.

P37. **Every choice checked against pure PHP.** Little-endian `u32`
    (`unpack('V')`), MessagePack's big-endian widths (`'n'`, `'N'`, `'J'`,
    `'E'`, `'G'`), ints within PHP's signed 64 bits, maps whose keys are
    strings (PHP arrays), `hash('sha256')`, `hash_hmac('sha256')`,
    `random_bytes`, `stream_socket_client` and `stream_select` for several
    requests and pushed events: nothing in the protocol needs an extension
    PHP does not ship. The PHP library itself is the next step
    (`neuromz-php`); PROTOCOL.md and the vectors are written to be enough
    to build it.

## Versions, branches and pins

The owner's decision of 2026-11-28, in the same words in the DESIGN.md of
every NeuroMZ repository (neuromz, neuromz-cli, neuromz-protocol,
neuromz-server).

P38. **No releases and no version tags until the owner says the project is
    ready.** NeuroMZ is in active development. The version tags and GitHub
    releases published before 2026-11-28 (library 2.0.0 to 2.2.0, program
    2.0.0 to 2.3.0, protocol 1.0.0 and 2.0.0, server 0.1.0 and 0.2.0) were
    development snapshots and are withdrawn; where older decisions and
    changelog entries name those numbers, they name the snapshots. The
    NeuroMZ 1 code keeps its tags (`v1-legacy`, and `v1.0` in the library).
    No tag and no release is made in any repository until the owner says the
    project is ready.

P39. **Versions move in lockstep by MAJOR; the wire protocol has its own
    number.** All repositories share the same MAJOR version: the first
    release will be 2.0.0 for every repository, including repositories
    created later that never had a 1.x. MINOR and PATCH are each
    repository's own: several repositories may move together while others
    stay on older numbers. Any 2.x repository works with any other 2.x
    repository: newer features are negotiated through the capabilities of
    the protocol's handshake, and a missing feature gives a clear error,
    never a crash. A breaking change means 3.0.0 for all repositories. The
    wire protocol's version (the number in the handshake, now 2) is separate
    from the repositories' versions and changes only when the bytes on the
    wire change incompatibly. Until the release the version string of every
    repository is `2.0.0-dev`: CMake's `project(VERSION)` holds numbers
    only, so it says 2.0.0, and the full string is carried in a variable
    next to it and in a macro in the code. `neuromz --version` names the
    program, the library and the wire protocol (`neuromz-cli 2.0.0-dev
    (library 2.0.0-dev, wire protocol 2)`), and `neuromz-server --version`
    the same way.

P40. **Development happens on `2.0.0-dev`; `master` waits for the release.**
    Every repository has the branch `2.0.0-dev`, created from `master` on
    2026-11-28 and its default branch on GitHub; all development continues
    there. `master` stays where it was and is updated only at release time
    (until then the program's and the server's `master` pin the withdrawn
    tags, so they no longer build from a fresh clone). CI runs in full on
    pushes to `2.0.0-dev` and to `master` and on pull requests.

P41. **The repositories pin each other by full commit SHA.** Every
    FetchContent declaration between the repositories (the program and the
    server fetch the library and the protocol) and every ref that CI checks
    out by default (the program's and the protocol's CI build the server)
    names the full 40-digit SHA of a commit on the dependency's `2.0.0-dev`,
    never a tag or a branch, so a build is reproducible. The local-path
    options (`-DNMZ_LOCAL_PATH`, `-DNMZP_LOCAL_PATH`) and the manual CI
    inputs (`protocol_ref`, `server_ref`) stay, for working on several
    repositories at once or trying another commit; one job of the program's
    CI also builds against the library's `2.0.0-dev` as it is, to show
    breakage before a pin moves. **When a dependency changes, the pinned
    SHAs in the dependent repositories are updated in the same piece of
    work**, and the dependents' CI passes with the new pins before the work
    is done. A pin is a commit on `2.0.0-dev`, not necessarily the newest: a
    commit that changes only a dependency's CI or documentation needs no new
    pins, which also ends the one cycle (the protocol's CI builds the
    server, which pins the protocol).

For the protocol itself:

P42. **The protocol's number is its major; features are capabilities.**
    Following P39, a feature added within protocol 2 is announced as a
    capability in the greeting (and in `server.capabilities`); a client
    checks for it before using it, and a server without it answers with a
    clear error (`unknown_operation`, `invalid_argument`) rather than a
    broken connection. The handshake's minor stays 0: it keeps its place
    and its rules (PROTOCOL §5.4), so the bytes on the wire do not change,
    and a second way to announce features would only be one more thing for
    two peers to disagree on. `--version` lines say `wire protocol 2`; the
    `"2.0"` strings of WELCOME and `health` stay as they are on the wire.

## Protocol 1 (HTTP, withdrawn)

Kept for the record; where protocol 2 replaced a decision, it says so.

P1. HTTP/1.1 and JSON, under `/v1` — *replaced by P18–P21.*
P2. No TLS in the servers, a reverse proxy instead — *replaced by P25.*
P3. Progress as Server-Sent Events — *replaced by P28.*
P4. A bearer token, and `?access_token=` for GET — *replaced by P24* (the
    permissions `read`, `train`, `admin` and the anonymous mode stay).
P5. One error shape, with codes — *refined by P29.*
P6. **Models are described the way the program describes them** (the
    library's `nmz_model_new`) — *kept.*
P7. **Where a trained model goes is the request's choice, within the
    server's policy** (`save: server | client`, `NAME.jID`) — *kept.*
P8. **Names are file-name safe on every system** — *kept.*
P9. **Datasets are uploaded once, or registered from the server's disk**
    — *kept* (uploads are streams now, P27).
P10. **Inference is synchronous; training is a job** — *kept.*
P11. **Traces are the library's JSON lines** — *kept*, carried as bytes
    in a stream (P27).
P12. **Samples count from 0 on the wire** — *kept.*
P13. Lists are objects; unknown fields are ignored — *kept* as maps (P30).
P14. Browsers are first-class — *withdrawn*: browsers reach a server
    through a web application and its PHP client (P18).
P15. One C implementation of the wire format, in this repository (`nmzp`)
    — *kept*, for protocol 2.
P16. The conformance suite is a C program — *kept*, extended by P35.
P17. Fuzzed under sanitizers — *kept*, P36.

## Deferred

TLS (P25); paging of lists; resumable uploads; per-model access lists
beyond owner and admin; job types for `step`, `gradcheck` and `compare`;
the PHP client library (`neuromz-php`: pure PHP, then a C extension with
the same API).
