# neuromz-protocol

The network protocol of [NeuroMZ](https://github.com/mzprog/neuromz): how
clients create models, upload data, train, follow the progress, run
inference and fetch traces on a NeuroMZ server. **Protocol 2** is a binary
protocol of its own over one TCP connection — in the family of MySQL's
client/server protocol, SQL Server's TDS and Redis's RESP: length-prefixed
frames, a MessagePack subset for structured payloads, raw float32 arrays,
an HMAC-SHA256 challenge so the token never travels, several requests at
once, files in chunks with their SHA-256, and training progress pushed on
the same connection. There is no HTTP.

NeuroMZ is in active development, with no releases yet (this repository's
version is `2.0.0-dev`; development happens on the `2.0.0-dev` branch).

| | |
|---|---|
| [`PROTOCOL.md`](PROTOCOL.md) | the protocol, version **2.0**, byte by byte: enough to write a client or a server from it alone |
| [`tests/vectors/`](tests/vectors/) | canonical bytes of every encoding, frame and handshake, with typed JSON descriptions: what another implementation tests against |
| [`conformance/`](conformance/conformance.c) | `nmz-conformance`: checks a live server against the protocol |
| [`include/nmzp.h`](include/nmzp.h), [`src/`](src/) | `nmzp`, the protocol in C11 (frames, the payload codec, the handshake and HMAC-SHA256, a client, sockets, SHA-256), shared by the server and the program |
| [`docs/DESIGN.md`](docs/DESIGN.md) | why it looks the way it does (P18–P37 and P42; P1–P17 were protocol 1; P38–P41 are the versions, branches and pins of every repository) |

The NeuroMZ repositories:
[`neuromz`](https://github.com/mzprog/neuromz) (the library) ·
[`neuromz-cli`](https://github.com/mzprog/neuromz-cli) (the `neuromz`
program; its remote mode speaks this protocol through `nmzp`) ·
[`neuromz-server`](https://github.com/mzprog/neuromz-server) (the reference
server) · **neuromz-protocol** (this one) · `neuromz-php` (planned: a pure-PHP
client library, later a C extension with the same API, through which a web
application will reach a server).

## The protocol in one page

```
client                                    server            TCP port 8470
  | <---- GREETING  magic, version 2.0, nonce Ns, auth, max_frame, capabilities
  | ----> HELLO     magic, version, key id, nonce Nc, proof = HMAC(SHA-256(token), label | Ns | Nc)
  | <---- WELCOME   user, permissions, the server's proof, max_inflight, idle_timeout
  | ----> REQUEST id 1  {"op": "models.create", "name": "xor", "args": ["2", "4", "1"]}
  | ----> REQUEST id 2  {"op": "jobs.subscribe", "id": "j7"}
  | <---- RESPONSE id 1 {"model": {...}, "explanation": [...], "created": true}
  | <---- RESPONSE id 2 MORE, EVENT id 2 MORE ..., EVENT id 2 {"event": "end", ...}
```

* **Frames**: `u32 length, u8 type, u8 flags (MORE), u16 reserved, u32
  request id`, little-endian, then the payload; a frame over the limit is
  refused from its header.
* **Payloads**: one MessagePack map (nil, bool, int, float, str, bin,
  array, map; no extension types; canonical form for writers); large
  arrays of numbers as `bin` of little-endian float32.
* **Authentication**: the server keeps SHA-256 of each token (its tokens
  file); that hash keys an HMAC over both nonces, the server proves the
  same back. No token on the wire, no replay; the limits are in
  [§6.2](PROTOCOL.md#62-what-it-protects-and-what-not). TLS is deferred,
  with a STARTTLS frame type reserved for it.
* **Requests**: `server.*`, `models.*` (create, list, describe, delete,
  upload, download, predict, test, generate, trace), `datasets.*` (upload,
  register, list, describe, delete), `jobs.*` (train, list, status,
  cancel, subscribe, model) — the operations of protocol 1 with the same
  arguments; answers in any order; errors with stable numeric codes
  (`203 invalid_argument`, `402 queue_full`, …).
* **Streams**: uploads, downloads and traces in DATA frames closed by END
  `{"size", "sha256"}`; ABORT stops a stream or a subscription.

## Build, test, check a server

CMake ≥ 3.21 and a C11 compiler (GCC, Clang, MSVC); no other dependency.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure    # unit tests, the vectors, a fuzz run
build/nmz-conformance --host 127.0.0.1:8470 --token TRAIN_OR_ADMIN_TOKEN [--read-token READ_TOKEN]
```

(`build/Release/nmz-conformance.exe` with Visual Studio.) The suite brings
its own tiny datasets, names everything it creates with a random prefix
and deletes it at the end, so it can run against a shared server. It checks
25 areas — the greeting, the handshake and both proofs, refused tokens and
replayed proofs, bad magic, versions and HTTP, malformed, oversized,
truncated and unknown frames, refused requests, interleaved requests and
uploads, the in-flight limit and ABORT, upload integrity, then every
operation (server, capabilities, errors, datasets, models, model files, a
training job and its events, cancelling and unsubscribing, disconnects in
streams, job lists, the save policy, inference, trace, permissions, the
idle timeout, clean-up) — and prints TAP-like lines; the exit status is 0
only when every check passed.

Tests: `test_wire` (124 checks: the codec at its boundaries and every
refusal, frames, the prefix, HMAC-SHA256 with RFC 4231 cases, the proofs,
UTF-8, SHA-256, JSON, names, addresses), `nmz-vectors check` (the 129
vectors), `vectors-written` (this implementation writes exactly the
committed vectors), and `fuzz_wire` (random and mutated frames and payloads;
under ASan + UBSan in CI). CI also checks the vectors with an independent
implementation, msgpack-python, and Python's `hmac`
([`tests/xcheck_msgpack.py`](tests/xcheck_msgpack.py)).

## The test vectors

[`tests/vectors/index.json`](tests/vectors/index.json) lists every vector;
each is `NAME.bin` (the bytes) and `NAME.json` (what they are). Values are
described in typed JSON so that nothing is lost between languages:

```json
{"map": [["op", "health"], ["n", {"int": "-256"}], ["x", [{"float": 1.5, "bits": "3ff8000000000000"}, {"bin": "07"}]]]}
```

An implementation passes when every `value`/`payload` vector decodes to
the described value and (when `canonical`) encodes back to the same bytes,
every `*-invalid` vector is refused, every `frame` vector is rebuilt byte
for byte, and `auth.json`'s key, key id and proofs come out the same.
`nmz-vectors write DIR` writes them; `nmz-vectors check DIR` checks a
directory of them.

## Using nmzp

```cmake
include(FetchContent)
# no releases yet: pin a full commit SHA of the 2.0.0-dev branch, as the server and the program do
FetchContent_Declare(neuromz_protocol GIT_REPOSITORY https://github.com/mzprog/neuromz-protocol.git GIT_TAG <commit SHA>)
FetchContent_MakeAvailable(neuromz_protocol)
target_link_libraries(app PRIVATE nmzp::nmzp)
```

```c
nmzp_client c;
nmzp_buf req;
nmzp_mw w;
nmzp_val *out;
nmzp_error e;
nmzp_net_init();
nmzp_client_init(&c, "gpu-box", 8470, token);
nmzp_buf_init(&req);
nmzp_mw_init(&w, &req);
nmzp_mw_map(&w);
nmzp_mw_kstr(&w, "op", "server.info");
nmzp_mw_end_map(&w);
if (nmzp_call(&c, &req, &out, &e) == 0)          /* connects and authenticates on first use */
    printf("%s %s\n", nmzp_get_str(out, "name"), nmzp_get_str(out, "version"));
```

`nmzp_call_upload` / `nmzp_call_download` move files in DATA frames and
check their END; `nmzp_call_events` follows a subscription; `nmzp_decode`
and `nmzp_mw_*` read and write payloads; `nmzp_frame_next` splits frames
(the server uses it); `nmzp_json.h` reads the trace's JSON lines.

## Versions

The wire protocol has its own number, 2 (PROTOCOL [§5.4](PROTOCOL.md#54-versions)
and [§16](PROTOCOL.md#16-versions-and-extensions)): it changes only when
the bytes on the wire change incompatibly, and then it is a new major,
negotiated in the handshake; additions within protocol 2 come with
capabilities. It is not this repository's version: every NeuroMZ
repository is `2.0.0-dev` until the first release, which will be 2.0.0 of
all of them ([DESIGN](docs/DESIGN.md) P38–P41). Protocol 1 (HTTP + JSON) is
withdrawn. Changes: [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT — see [`LICENSE`](LICENSE).
