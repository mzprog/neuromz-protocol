# Changelog

All notable changes to the NeuroMZ protocol and its C wire library. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The wire protocol has its own number (2, [PROTOCOL §16](PROTOCOL.md#16-versions-and-extensions)),
apart from this repository's version.

## Unreleased (2.0.0-dev)

Nothing is released yet. The version numbers below (1.0.0, 2.0.0) were
development snapshots: their tags and GitHub releases were withdrawn on
2026-11-28, and the first release will be 2.0.0 of every NeuroMZ
repository ([`docs/DESIGN.md`](docs/DESIGN.md) P38–P41). The wire protocol
of these entries is protocol 1 (HTTP, withdrawn) and protocol 2.

### Versions and branches — 2026-11-28

- **Version `2.0.0-dev`** of this repository (`NMZP_VERSION`; CMake's
  `project(VERSION)` 2.0.0 with the full string in `NMZP_VERSION_STRING`
  next to it, checked against `nmzp.h` when configuring). The wire protocol
  is still **2**, its bytes unchanged.
- **Additions within protocol 2 come with capabilities**; the handshake's
  minor stays 0 (PROTOCOL §5.4 and §16, P42).
- The test vectors' greeting and hello carry the version `2.0.0-dev`
  instead of withdrawn version numbers: `frame-greeting` and `frame-hello`
  are 4 bytes longer, and PROTOCOL §18 shows the new bytes.
- The client's message for a peer that sends no greeting names protocol 1
  instead of a withdrawn server version.
- **Development on the branch `2.0.0-dev`**, the default branch; CI runs on
  pushes to it and to `master` and on pull requests; the conformance jobs
  build neuromz-server at a pinned commit (P41).
- **No releases and no version tags** until the owner says the project is
  ready (P38–P41).

### 2.0.0 — development snapshot, 2026-11-27 (withdrawn)

Protocol 2: a binary protocol of its own over TCP. **HTTP is removed
completely** — servers of protocol 2 do not speak HTTP, `openapi.yaml` is
gone, and protocol 1 lives on only in this history (tag `v1.0.0`). Design:
[`docs/DESIGN.md`](docs/DESIGN.md) P18–P37.

#### Added
- **The protocol** ([`PROTOCOL.md`](PROTOCOL.md), byte by byte): one TCP
  connection (port 8470) of length-prefixed frames (`u32 length, u8 type,
  u8 flags, u16 reserved, u32 request id`, little-endian; 12 frame types,
  a `MORE` flag, a strict frame limit); payloads in a documented
  MessagePack subset with a canonical form; raw little-endian float32
  arrays in `bin`; a handshake in which the server speaks first (magic,
  version, nonce, capabilities) and versions are negotiated with clear
  refusals; authentication by HMAC-SHA256 challenge and response keyed by
  SHA-256 of the token — the token never travels, both sides prove the key,
  the limits are documented; several requests at once with answers in any
  order; uploads, downloads and traces in DATA frames with an END carrying
  their size and SHA-256; training progress pushed as EVENT frames
  (numbered and replayable with `after`, live batch events); ABORT; PING
  and PONG; idle and handshake timeouts; one ERROR frame with stable
  numeric codes in ranges and protocol 1's names; times as ints. The
  operations are protocol 1's under dotted names with the same arguments
  (`models.create`, `jobs.train`, `jobs.subscribe`, `models.trace`, …).
  STARTTLS is reserved (frame type `0x04`) for TLS later.
- **Shared test vectors** ([`tests/vectors/`](tests/vectors/)): 129
  vectors (values at every encoding boundary, non-canonical forms, payloads
  and frames a reader must refuse, every frame type, the handshake with its
  proofs) and `auth.json`, described in typed JSON; `nmz-vectors` writes
  and checks them; CI checks them with msgpack-python and Python's `hmac`
  too.
- **nmzp**: the frame codec, the payload codec (decoder: UTF-8, depth 32,
  262 144 values, duplicate keys found by hashing, counts checked before
  allocation), the handshake and its HMAC-SHA256, and a client (calls,
  uploads, downloads, subscriptions, PING answered).
- **nmz-conformance** for protocol 2: 25 areas, among them bad magic,
  unsupported versions, HTTP clients, wrong tokens and replayed proofs,
  oversized, truncated and unknown frames, interleaved request ids,
  in-flight limits, aborts, upload integrity and disconnects in the middle
  of streams.

#### Changed
- `nmzp_parse_hostport` takes `host` or `host:port` (`[v6]:port`); URLs are
  refused.
- JSON is no longer part of the wire: `nmzp_json.h` keeps the parser and
  writer for the trace's JSON lines and for files.

#### Removed
- HTTP/1.1 (heads, chunked bodies, the keep-alive client), Server-Sent
  Events, bearer tokens and `?access_token=`, CORS, `openapi.yaml`.

### 1.0.0 — development snapshot, 2026-11-27 (withdrawn)

The first version. Design: [`docs/DESIGN.md`](docs/DESIGN.md) P1–P17.

#### Added
- **The protocol** ([`PROTOCOL.md`](PROTOCOL.md), [`openapi.yaml`](openapi.yaml),
  OpenAPI 3.1): HTTP/1.1 + JSON under `/v1`; a bearer token (and
  `?access_token=` for GET, for `EventSource`) with the permissions `read`,
  `train` and `admin`; one error shape with codes; `X-Request-Id` and
  `X-NeuroMZ-Protocol` on every response.
  - server: `health`, `server`, `capabilities` (backends, devices, GPU
    memory, presets, save policy, limits, trace settings, features);
  - models: create from the program's arguments or the same in fields
    (preset or layer spec, with the explanation of every default), list,
    describe, delete, upload and download `.nmz` files;
  - datasets: upload (CSV, text, MNIST IDX), register a file under a root
    the server allows, list, describe, delete;
  - jobs: training with every option of the program, a device and a save
    policy; status, list, cancel; progress as Server-Sent Events (`state`,
    `batch`, `epoch`, `end`, replayable with `Last-Event-ID`); the trained
    model file;
  - inference: predict (samples, a dataset sample, the next character),
    test (loss, accuracy, perplexity, confusion matrix), generate (every
    option of the program);
  - trace: one sample forward and backward, the library's JSON-lines events;
  - where models are kept: `save: server | client`, within the server's
    policy.
- **nmzp**, the wire format in C11 for servers and clients: JSON (checked
  UTF-8, a depth limit), HTTP/1.1 heads (request-smuggling forms refused),
  chunked bodies, Server-Sent Events, Winsock/POSIX sockets, a keep-alive
  HTTP client, SHA-256, constant-time comparison, random bytes, names,
  times.
- **nmz-conformance**: the protocol's checks against a live server (16
  areas), TAP-like output, safe on a shared server.
- Tests: `test_wire` (241 checks) and `fuzz_wire` (random and mutated
  inputs into every parser), run under ASan + UBSan in CI; CI on Linux
  (GCC, Clang) and Windows (MSVC), and the conformance suite against a live
  neuromz-server on both.
