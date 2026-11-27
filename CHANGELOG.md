# Changelog

All notable changes to the NeuroMZ protocol and its C wire library. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the protocol follows [semantic versioning](PROTOCOL.md#13-versions).

## [1.0.0] — 2026-11-27

The first version. Design: [`docs/DESIGN.md`](docs/DESIGN.md) P1–P17.

### Added
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

[1.0.0]: https://github.com/mzprog/neuromz-protocol/releases/tag/v1.0.0
