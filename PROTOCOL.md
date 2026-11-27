# The NeuroMZ protocol, version 1.0.0

How clients talk to a NeuroMZ server: HTTP/1.1 and JSON, everything under
`/v1`. The reference server is
[neuromz-server](https://github.com/mzprog/neuromz-server); the reference
clients are the [`neuromz` program](https://github.com/mzprog/neuromz-cli)
in remote mode and (later) neuromz-web. The machine-readable form of this
document is [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1); the
[conformance suite](conformance/) checks a live server against it. The
models themselves are those of the
[NeuroMZ library](https://github.com/mzprog/neuromz).

Contents: [conventions](#1-conventions) · [authentication](#2-authentication) ·
[errors](#3-errors) · [server](#4-server) · [models](#5-models) ·
[datasets](#6-datasets) · [jobs and progress](#7-jobs-and-progress) ·
[inference](#8-inference) · [trace](#9-trace) · [where models are kept](#10-where-models-are-kept-save) ·
[limits](#11-limits) · [browsers](#12-browsers) · [versions](#13-versions)

## 1. Conventions

* **Transport.** HTTP/1.1 over TCP. Servers need not speak TLS: put one
  behind a reverse proxy for that (the reference server binds to
  127.0.0.1 by default). Connections may be kept alive.
* **Bodies.** JSON in UTF-8 (`Content-Type: application/json`), except
  model files (`application/octet-stream`), dataset uploads (the file's
  bytes), progress streams (`text/event-stream`) and traces
  (`application/x-ndjson`). A request body needs `Content-Length` or
  `Transfer-Encoding: chunked`.
* **Every response** carries `X-Request-Id` (also in the server's log) and
  `X-NeuroMZ-Protocol: 1.0.0`.
* **Names** of models and datasets: 1–64 characters `A-Z a-z 0-9 . _ -`,
  starting with a letter or digit, not ending in `.`, and not a Windows
  device name (`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`,
  in any case, alone or before a dot). Names are case-sensitive. Anything
  else is `400 invalid_name`: names become file names on the server.
* **Times** are RFC 3339 in UTC (`"2026-11-27T14:05:09Z"`), sizes are bytes,
  durations seconds. Numbers that are not finite (a NaN loss) are `null`.
* **Unknown fields** in requests are ignored; clients must ignore unknown
  fields in responses (§13).
* **Lists** are objects: `{"items": [...]}`.

## 2. Authentication

`Authorization: Bearer TOKEN` on every request except `GET /v1/health`.
For `GET` requests a browser's `EventSource` cannot set headers, so
`?access_token=TOKEN` is accepted there too (servers must keep it out of
their logs). A token belongs to a user and carries permissions:

| permission | allows |
|---|---|
| `read` | every `GET`; `predict`, `test`, `generate`, `trace`; downloading files |
| `train` | `read`, and creating, uploading and deleting **one's own** models and datasets, starting and cancelling **one's own** jobs |
| `admin` | everything, on everyone's resources |

Missing or wrong token: `401 unauthorized` (with
`WWW-Authenticate: Bearer`). Not allowed: `403 forbidden`. A server may run
without authentication (`"auth": false` in its capabilities): every request
is then the user `anonymous` with all permissions. Every model, dataset and
job has an `owner`; all users who can read see all of them.

## 3. Errors

Every error has the HTTP status and one body shape:

```json
{"error": {"code": "invalid_argument", "message": "--lr needs a positive number, got '-1'", "details": {}}}
```

`message` is for people (it is the library's own message where the library
refused); `code` is for programs; `details` (optional) carries specifics.

| status | code | when |
|---|---|---|
| 400 | `bad_request` | malformed JSON, a missing or mistyped field, a bad query |
| 400 | `invalid_name` | a model or dataset name breaks §1 |
| 401 | `unauthorized` | no token, or an unknown one |
| 403 | `forbidden` | the token lacks the permission, or the resource is someone else's |
| 403 | `save_not_allowed` | `save` asks for a place the server does not allow (§10) |
| 404 | `not_found` | no such model, dataset, job or endpoint |
| 405 | `method_not_allowed` | the path exists, the method does not (`Allow` lists the methods) |
| 408 | `request_timeout` | the request did not arrive in time |
| 409 | `conflict` | the name exists (without `"overwrite": true`), the job already finished, the model is busy |
| 411 | `length_required` | a body without a length |
| 413 | `payload_too_large` | the body is over the limit (§11) |
| 415 | `unsupported_media_type` | a JSON endpoint got another `Content-Type` |
| 422 | `invalid_argument` | well-formed but refused: a layer spec, an option, data that does not fit the model |
| 429 | `queue_full` | the job queue is full: try again later |
| 431 | `headers_too_large` | the request head is over the limit |
| 500 | `internal` | a bug in the server |
| 503 | `unavailable` | the requested device is not available, or the server is stopping |
| 505 | `http_version_not_supported` | not HTTP/1.0 or 1.1 |
| 507 | `quota_exceeded` | the user's storage quota would be exceeded |

A job that fails reports its error in the job object (§7) with the same
codes, plus `out_of_memory` (the model and batch do not fit the device:
try a smaller batch) and `numeric` (the loss became NaN/Inf).

## 4. Server

### `GET /v1/health` — no authentication

```json
{"status": "ok", "protocol": "1.0.0"}
```

### `GET /v1/server`

```json
{"name": "neuromz-server", "version": "0.1.0", "protocol": "1.0.0", "library": "2.2.0",
 "started": "2026-11-27T14:00:00Z", "uptime_s": 3600,
 "user": {"name": "alice", "permissions": ["read", "train"]}}
```

### `GET /v1/capabilities`

What the server can do and its limits — enough for a client to choose a
device, a batch size and a save policy before it sends work:

```json
{"protocol": "1.0.0", "auth": true,
 "backends": [
   {"name": "cpu", "available": true, "device": "host CPU (6 threads)", "threads": 6},
   {"name": "cuda", "available": true, "device": "NVIDIA GeForce GTX 1660 Ti",
    "compute_capability": "7.5", "memory_total_mb": 6144, "memory_free_mb": 5120,
    "memory_limit_mb": 4096, "memory_used_mb": 0}],
 "default_device": "cuda",
 "presets": [{"name": "mnist-cnn", "summary": "small convolutional network for MNIST digits", "input": "1x28x28"}],
 "save": {"default": "server", "allowed": ["server", "client"]},
 "limits": {"max_upload_mb": 64, "max_json_kb": 1024, "max_model_mb": 512, "max_layer_size": 16384, "max_epochs": 1000,
            "max_concurrent_jobs": 2, "queue_size": 16, "quota_per_user_mb": 2048,
            "client_model_hours": 24, "keep_finished_hours": 24},
 "trace": {"enabled": true, "max_events": 2000},
 "dataset_formats": ["csv", "text", "idx-images", "idx-labels"],
 "features": ["sse", "generate", "trace", "server-paths"]}
```

An unavailable backend has `"available": false` and `"reason"`.

## 5. Models

The model object:

```json
{"name": "xor", "owner": "alice", "storage": "server", "version": 3,
 "created": "2026-11-27T14:01:00Z", "updated": "2026-11-27T14:02:30Z", "expires": null,
 "size": 1404, "params": 17, "sequence": false, "input_shape": [2], "outputs": 1,
 "loss": "mse", "normalization": "none", "vocab_size": null, "train_steps": 172,
 "layers": [{"index": 0, "type": "dense", "description": "dense 2->4", "params": 12},
            {"index": 1, "type": "activation", "description": "tanh", "params": 0}],
 "config": {"summary": "sgd lr 0.5, momentum 0.9, batch 4, max epochs 1000, target loss 0.001, shuffle on",
            "optimizer": "sgd", "lr": 0.5, "batch": 4, "epochs": 1000}}
```

`version` increases with every change to the model's weights or file.
`storage` and `expires`: §10. `input_shape` is `[-1]` for text models (any
length).

### `POST /v1/models` — permission `train`

Builds a model the way `neuromz new` does — the same grammar, presets,
defaults and explanation (the library's `nmz_model_new`). Either the
program's arguments verbatim:

```json
{"name": "xor", "args": ["2", "4", "1"]}
{"name": "names", "args": ["--preset", "names", "--data", "names-en"]}
```

or the same in fields:

```json
{"name": "cnn", "input": "1x28x28",
 "layers": ["conv:8:3:relu", "pool:2", "conv:16:3:relu", "pool:2", "64:relu", "10:softmax"],
 "loss": "ce", "normalize": "zscore", "seed": 7, "options": {"lr": 0.001, "batch": 32}}
{"name": "alice", "preset": "char-lstm", "dataset": "alice", "options": {"epochs": 5}}
```

Fields: `name` (required), `args` **or** any of `preset`, `input`,
`layers`, `dataset` (a dataset name: the text that builds a text model's
vocabulary; `--data` in `args` also names a dataset), `loss`, `normalize`,
`seed`, `items` (bool), `strip_diacritics`, `unify_alef`, `options`
(training options, below); `save` (§10); `overwrite` (default `false`:
`409 conflict` if the name exists).

**Training options** (`options` here and in jobs) are the program's, one
key per option: `lr`, `momentum`, `batch`, `epochs`, `target_loss`,
`optimizer` (`sgd`, `adam`, `adamw`), `beta1`, `beta2`, `eps`, `schedule`
(`constant`, `step`, `cosine`, `warmup-cosine`), `step_size`, `gamma`,
`min_lr`, `weight_decay`, `decay_all` (bool), `warmup`, `shuffle` (bool),
`carry` (bool), `val`, `clip`, `patience`, `seq_len`. Key `k` means the
option `--k` with `_` written as `-`; values are numbers, strings or
booleans. They are checked by the library's parser, so a bad value gets the
program's message (`422 invalid_argument`).

`201 Created`, with the explanation the program prints:

```json
{"model": {"name": "xor", "...": "..."},
 "explanation": ["Input 2   2 value(s) per sample",
                 "  dense 2->4               tanh            [default] zero-centred and smooth; ...",
                 "Created a network with 17 parameters."]}
```

### `GET /v1/models` — `read`

`{"items": [model, ...]}` without `layers` and `config`.

### `GET /v1/models/{name}` — `read`

The model object.

### `DELETE /v1/models/{name}` — `train` (owner) or `admin`

`204 No Content`. `409 conflict` while a job trains it.

### `PUT /v1/models/{name}/file` — `train`

Uploads a model file (`.nmz`, any format the library reads) as the body,
`Content-Type: application/octet-stream`. Query: `save` (§10),
`overwrite=true` to replace a model of the same name (owner or admin). The
server loads the file to check it. `201 Created` (new) or `200 OK`
(replaced), with the model object.

### `GET /v1/models/{name}/file` — `read`

The model file (`application/octet-stream`, `ETag: "<version>"`).
Model files are the same on every device.

## 6. Datasets

The dataset object:

```json
{"name": "xor", "owner": "alice", "format": "csv", "size": 52, "sha256": "9f1c...",
 "created": "2026-11-27T14:00:30Z", "source": "upload", "labels": null}
```

Formats: `csv` (numbers, the first columns inputs, the rest targets; a
text last column is a class label), `text` (UTF-8: names one per line, or
running text), `idx-images` and `idx-labels` (the MNIST files). `source`
is `"upload"` or `"path"` (a file on the server, below). For
`idx-images`, `labels` names the `idx-labels` dataset that goes with it.

### `PUT /v1/datasets/{name}` — `train`

The file's bytes as the body. Query: `format` (required: `csv`, `text`,
`idx-images`, `idx-labels`), `labels` (for `idx-images`), `overwrite`.
`201 Created` with the dataset object. The `sha256` lets a client skip
uploading a file the server already has.

### `POST /v1/datasets` — `train`

Registers a file that is already on the server, if the server's
configuration allows its directory:

```json
{"name": "mnist-train", "path": "mnist/train-images-idx3-ubyte", "format": "idx-images",
 "labels": "mnist-train-labels"}
```

`path` is relative to one of the server's allowed roots (no `..`, no
absolute paths: `403 forbidden` otherwise). `201 Created`.

### `GET /v1/datasets`, `GET /v1/datasets/{name}` — `read`

### `DELETE /v1/datasets/{name}` — `train` (owner) or `admin`

`204`. A registered path is forgotten; the file itself stays.

## 7. Jobs and progress

Training runs as a job: queued, then run by one of the server's workers
(at most `max_concurrent_jobs` at once).

### `POST /v1/jobs` — `train`

```json
{"type": "train", "model": "xor", "dataset": "xor", "device": "auto", "save": "server",
 "options": {"epochs": 200, "lr": 0.5}}
```

Fields: `type` (`"train"`), `model`, `dataset` (required); `validation`
(a dataset trained on as the validation set, like `--val-file`);
`device` (`auto`, `cpu`, `cuda`; default: the server's); `save` (§10);
`options` (§5) **or** `args` (the program's option arguments, e.g.
`["--epochs", "5", "--lr", "0.01"]`); `limit` (train on the first N
samples); `header` (CSV: `true`/`false`; default: detected). Options
override the model's stored training configuration for this run.
`202 Accepted` with the job object; `429 queue_full`; `503 unavailable`
when the device cannot be used.

The job object:

```json
{"id": "j12", "type": "train", "state": "running", "owner": "alice",
 "model": "xor", "dataset": "xor", "validation": null,
 "device_requested": "auto", "device": "cuda", "save": "server",
 "created": "2026-11-27T14:02:00Z", "started": "2026-11-27T14:02:00Z", "finished": null,
 "config": "sgd lr 0.5, momentum 0.9, batch 4, max epochs 200, target loss 0.001, shuffle on",
 "progress": {"epoch": 41, "epochs": 200, "batch": 1, "batches": 1, "loss": 0.21,
              "accuracy": 0.75, "val_loss": null, "val_accuracy": null,
              "learning_rate": 0.5, "elapsed_s": 0.03},
 "result": null, "error": null, "output_model": null, "gpu_memory_peak_mb": null}
```

`state`: `queued` → `running` → `succeeded` | `failed` | `cancelled`.
`result` (when it succeeded or was cancelled after at least one batch):
`{"epochs", "loss", "accuracy", "val_loss", "val_accuracy", "converged",
"stopped", "best_epoch"}`, as the library reports them. `error`:
`{"code", "message"}`. `output_model`: where the trained model went (§10).
Finished jobs are kept for `keep_finished_hours`.

### `GET /v1/jobs`, `GET /v1/jobs/{id}` — `read`

`GET /v1/jobs?state=running` filters by state.

### `POST /v1/jobs/{id}/cancel` — `train` (owner) or `admin`

A queued job is cancelled at once; a running one stops after its current
batch (the model keeps the weights of the batches already done only when
`save` writes them, §10). `202 Accepted` with the job object; `409
conflict` if it already finished.

### `GET /v1/jobs/{id}/events` — `read`: progress as Server-Sent Events

`text/event-stream`, one event per epoch, plus the job's state changes:

```
retry: 2000

id: 1
event: state
data: {"id":"j12","state":"running", ...the job object...}

event: batch
data: {"epoch":1,"batch":20,"batches":127,"loss":2.31,"learning_rate":0.01}

id: 2
event: epoch
data: {"epoch":1,"loss":2.05,"accuracy":0.41,"val_loss":2.1,"val_accuracy":0.4,"learning_rate":0.01,"clipped_batches":0,"improved":true,"elapsed_s":0.71}

id: 9
event: end
data: {"id":"j12","state":"succeeded", ...the final job object...}
```

* `state` and `epoch` events are numbered (`id`) and kept with the job: a
  client that connects late, or reconnects with `Last-Event-ID: N`, gets
  every numbered event after N first. `batch` events are live only (at
  most a few per second) and have no id.
* `end` is the last event; then the server closes the stream. A finished
  job's stream replays its events and ends at once.
* Lines starting with `:` are keep-alive comments (every 15 s).

### `GET /v1/jobs/{id}/model` — `read`

The trained model file of a job whose result was not written over a
stored model (§10), while the job is kept.

## 8. Inference

Synchronous: the answer is the response. `device` (`auto`, `cpu`, `cuda`)
is optional in each.

### `POST /v1/models/{name}/predict` — `read`

```json
{"inputs": [[1, 0], [0, 1]]}
{"dataset": "mnist-test", "sample": 0}
{"text": "Alice was"}
```

`inputs`: one sample (an array of numbers) or several (an array of
arrays), as many numbers as the model's input. `dataset` + `sample`
(0-based): a sample of a dataset, with its target. `text`: for a text
model, the distribution of the next character. Response:

```json
{"outputs": [[0.954], [0.031]], "predicted": [0, 0], "classes": null, "targets": null}
{"next": [{"char": " ", "p": 0.41}, {"char": "s", "p": 0.12}], "text": "Alice was"}
```

`predicted` is the index of the largest output of each sample; `classes`
the class names when the data has them.

### `POST /v1/models/{name}/test` — `read`

```json
{"dataset": "iris", "limit": 0, "header": null}
```

```json
{"dataset": "iris", "samples": 150, "loss": 0.105, "accuracy": 0.973, "perplexity": null,
 "classes": ["setosa", "versicolor", "virginica"], "confusion": [[50, 0, 0], [0, 47, 3], [0, 1, 49]]}
```

`confusion[t][p]`: samples of true class `t` predicted as `p` (classifiers
only); `perplexity` for text models.

### `POST /v1/models/{name}/generate` — `read`

The program's `generate`: `prime`, `length`, `temperature`, `top_k`,
`seed`, `count`, `new_only`, `context`, `no_cache`, and `dataset` (the
items that count as known for `new_only`; default: the ones the model
recorded). Line-per-item models (names) return distinct items:

```json
{"kind": "items", "items": [{"text": "Marla", "known": false}, {"text": "Anna", "known": true}],
 "attempts": 12}
```

running-text models return passages (one per seed `seed`, `seed+1`, ...):

```json
{"kind": "text", "texts": ["Alice was beginning to get very tired..."]}
```

## 9. Trace

### `POST /v1/models/{name}/trace` — `read`

One sample forward and backward, nothing changed (the update is only
previewed) — the program's `trace`. The sample: `{"inputs": [...],
"target": [...]}`, or `{"dataset": "...", "sample": N}`, or `{"text":
"..."}` for text models. Response: `application/x-ndjson`, one event per
line, exactly as the library's `nmz_trace_event_write_json` writes them:

```
{"step":1,"phase":"forward","layer":0,"time_step":-1,"type":"dense","detail":"","scalars":{},"items":{"x":{"shape":[1,2],"data":[1,0]},"W":{"shape":[2,4],"data":[...]},"z":{"shape":[1,4],"data":[...]}}}
```

Header `X-Trace-Events: N`; `X-Trace-Truncated: 1` when the server's
`max_events` cut the trace short. `403 forbidden` if the server disables
traces.

## 10. Where models are kept (`save`)

Every model has a `storage`:

* `"server"`: kept in the server's model store; survives restarts; counts
  towards the owner's quota.
* `"client"`: kept for the client only: not written to the server's store,
  forgotten `client_model_hours` after its last use (`expires`) and at a
  restart. The client downloads it to keep it.

Requests that create or change a model take `"save": "server" | "client"`
(a query parameter for uploads); without it the server's default applies.
A server allows one or both (`capabilities.save`); others get `403
save_not_allowed`.

* **Creating, uploading**: the new model gets that storage.
* **Training** (`POST /v1/jobs`):
  * `save: "server"`: the trained weights replace the model's, which is (or
    becomes) stored on the server. `output_model` is the model's name.
  * `save: "client"` on a `client` model: the model is updated in place.
  * `save: "client"` on a `server` model: the stored model is left as it
    was; the result becomes a new `client` model named `NAME.jID` (e.g.
    `xor.j12`), in `output_model`, also downloadable from the job.
  * A cancelled job writes the batches it finished, by the same rules; a
    failed job writes nothing.

## 11. Limits

`capabilities.limits` lists the server's limits. Bodies above
`max_upload_mb` (model and dataset files) or the JSON limit get `413`;
`epochs` above `max_epochs` get `422`; a model description with a number
(units, filters, a dimension) above `max_layer_size` gets `422` before
anything is built; a model above `max_model_mb` gets `413`. A request
head must arrive within the header timeout and the body within the body
timeout (`408`). Inference is bounded by the size of its request (samples,
characters to generate, trace events), not by a clock.

## 12. Browsers

Servers may allow cross-origin requests for configured origins (`OPTIONS`
preflight, `Access-Control-Allow-*` headers). `EventSource` uses
`?access_token=` (§2). Every endpoint returns JSON a page can show
directly; the explanation of a new model and the trace events are meant
for a web viewer.

## 13. Versions

This is protocol 1.0.0 (semantic versioning): a 1.x server answers every
1.0 request as documented here; later minor versions only add endpoints,
fields and error codes (clients ignore what they do not know). An
incompatible change would move to `/v2`. Servers report their protocol
version in `/v1/health`, `/v1/server`, `/v1/capabilities` and the
`X-NeuroMZ-Protocol` header.
