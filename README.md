# neuromz-protocol

The network API of [NeuroMZ](https://github.com/mzprog/neuromz): how
clients create models, upload data, train, watch the progress, run
inference and fetch traces from a NeuroMZ server. HTTP/1.1 + JSON under
`/v1`, progress as Server-Sent Events, a bearer token, one error shape —
plain enough for `curl`, a browser's `fetch`/`EventSource` and a C program
alike.

| | |
|---|---|
| [`PROTOCOL.md`](PROTOCOL.md) | the protocol, version **1.0.0**, for people |
| [`openapi.yaml`](openapi.yaml) | the same as OpenAPI 3.1, for tools and code generators |
| [`conformance/`](conformance/conformance.c) | `nmz-conformance`: checks a live server against the protocol |
| [`include/nmzp.h`](include/nmzp.h), [`src/`](src/) | `nmzp`, the wire format in C11 (JSON, HTTP/1.1, chunked bodies, SSE, sockets, a client, SHA-256), shared by the server and the program |
| [`docs/DESIGN.md`](docs/DESIGN.md) | why it looks the way it does |

The NeuroMZ repositories:
[`neuromz`](https://github.com/mzprog/neuromz) (the library) ·
[`neuromz-cli`](https://github.com/mzprog/neuromz-cli) (the `neuromz`
program; its remote mode speaks this protocol) ·
[`neuromz-server`](https://github.com/mzprog/neuromz-server) (the reference
server) · **neuromz-protocol** (this one) · `neuromz-web` (planned: a
browser client of this protocol).

## The API in one table

Every path is under `/v1`; every request but `GET /v1/health` carries
`Authorization: Bearer TOKEN` (permissions `read`, `train`, `admin`).

| | |
|---|---|
| `GET /health` · `GET /server` · `GET /capabilities` | liveness; the server and the caller; backends, devices, GPU memory, presets, save policy, limits |
| `POST /models` | build a model as `neuromz new` does (`{"name":"xor","args":["2","4","1"]}`), with the explanation of every default |
| `GET /models` · `GET`/`DELETE /models/{name}` | list, describe, delete |
| `PUT`/`GET /models/{name}/file` | upload or download a `.nmz` file |
| `PUT /datasets/{name}?format=csv` · `POST /datasets` | upload a file (CSV, text, MNIST IDX), or register a file on the server under an allowed root |
| `GET /datasets` · `GET`/`DELETE /datasets/{name}` | list, describe, delete |
| `POST /jobs` | train (every training option of the program, `device`, `save`) |
| `GET /jobs` · `GET /jobs/{id}` · `POST /jobs/{id}/cancel` | status, list, cancel (stops after the current batch) |
| `GET /jobs/{id}/events` | progress as Server-Sent Events: `state`, `batch`, `epoch`, `end`; replayable with `Last-Event-ID` |
| `GET /jobs/{id}/model` | a job's trained model file |
| `POST /models/{name}/predict` · `/test` · `/generate` | inference, with the program's options |
| `POST /models/{name}/trace` | one sample forward and backward: the library's trace events as JSON lines |

Errors: `{"error": {"code": "invalid_argument", "message": "...", "details": {}}}`
with the HTTP status (codes in [PROTOCOL §3](PROTOCOL.md#3-errors)).
Where a trained model goes is the request's `save: server|client`, within
what the server allows ([§10](PROTOCOL.md#10-where-models-are-kept-save)).

## A session with curl

```sh
S=http://127.0.0.1:8470/v1; A="Authorization: Bearer $TOKEN"
curl -s "$S/capabilities" -H "$A"
curl -s "$S/datasets/xor?format=csv" -H "$A" -X PUT --data-binary @xor.csv
curl -s "$S/models" -H "$A" -H 'Content-Type: application/json' -d '{"name":"xor","args":["2","4","1"]}'
curl -s "$S/jobs" -H "$A" -H 'Content-Type: application/json' \
     -d '{"type":"train","model":"xor","dataset":"xor","device":"auto","options":{"lr":0.5}}'
curl -sN "$S/jobs/j1/events" -H "$A"                    # progress, until event: end
curl -s "$S/models/xor/predict" -H "$A" -H 'Content-Type: application/json' -d '{"inputs":[[1,0]]}'
curl -s "$S/models/xor/file" -H "$A" -o xor.nmz         # loads in the local program and library
```

In a browser: `new EventSource(S + "/jobs/j1/events?access_token=" + token)`.

## Build, test, check a server

CMake ≥ 3.21 and a C11 compiler (GCC, Clang, MSVC); no other dependency.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure      # the wire tests and a fuzz run
build/nmz-conformance --url http://127.0.0.1:8470 --token TRAIN_OR_ADMIN_TOKEN [--read-token READ_TOKEN]
```

(`build/Release/nmz-conformance.exe` with Visual Studio.) The suite brings
its own tiny datasets, names everything it creates with a random prefix
and deletes it at the end, so it can run against a shared server. It checks
16 areas — health, server, capabilities, authentication, errors, datasets,
models, model files, a training job and its event stream, cancelling,
listing jobs, the save policy, inference, trace, permissions, clean-up —
and prints TAP-like lines (`ok 12 - ...`, `not ok 13 - ...: why`); the
exit status is 0 only when every check passed. A server that is not the
reference one can run it in its own CI the same way.

Tests: `test_wire` (241 checks: JSON incl. every class of bad UTF-8 and
surrogates, the depth limit, HTTP heads incl. request-smuggling cases,
chunked bodies, SSE, SHA-256 test vectors, names, times) and `fuzz_wire`
(random and mutated inputs into every parser; under ASan + UBSan in CI).

## Using nmzp

```cmake
include(FetchContent)
FetchContent_Declare(neuromz_protocol GIT_REPOSITORY https://github.com/mzprog/neuromz-protocol.git GIT_TAG v1.0.0)
FetchContent_MakeAvailable(neuromz_protocol)
target_link_libraries(app PRIVATE nmzp::nmzp)
```

`nmzp_client_request` sends a request and reads the answer (keep-alive,
chunked or sized bodies); `nmzp_client_stream` hands an event stream to an
`nmzp_sse` parser; `nmzp_json_parse` / `nmzp_jw_*` read and write JSON.
Plain HTTP only: TLS belongs to a reverse proxy in this version.

## Versions

The protocol follows semantic versioning (PROTOCOL §13): a 1.x server
answers every 1.0 request as documented; minor versions only add
endpoints, fields and error codes; an incompatible change would be `/v2`.
The repository's tags are the protocol versions. Changes:
[`CHANGELOG.md`](CHANGELOG.md).

## License

MIT — see [`LICENSE`](LICENSE).
