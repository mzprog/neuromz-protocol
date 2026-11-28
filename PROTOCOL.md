# The NeuroMZ protocol 1

How clients talk to a NeuroMZ server: a binary protocol of its own over
one TCP connection, in the family of MySQL's client/server protocol, SQL
Server's TDS and Redis's RESP. This document is the whole protocol, down
to the byte: a client (or a server) can be written from it alone. The
reference server is [neuromz-server](https://github.com/mzprog/neuromz-server);
the reference client is the [`neuromz` program](https://github.com/mzprog/neuromz-cli)
in remote mode, through the C library `nmzp` in this repository. The
[test vectors](tests/vectors/) give canonical bytes for every frame and
payload form described here; the [conformance suite](conformance/) checks
a live server. The models are those of the
[NeuroMZ library](https://github.com/mzprog/neuromz).

This is protocol 1 (major 1, minor 0 in the handshake). The protocol's
number is its own, not the version of a program or a repository (§16).

Contents:
[1 conventions](#1-conventions) ·
[2 the connection](#2-the-connection) ·
[3 frames](#3-frames) ·
[4 payloads](#4-payloads-a-messagepack-subset) ·
[5 the handshake](#5-the-handshake) ·
[6 authentication](#6-authentication) ·
[7 requests](#7-requests-and-responses) ·
[8 byte streams](#8-byte-streams) ·
[9 events](#9-events) ·
[10 keep-alive and timeouts](#10-keep-alive-and-timeouts) ·
[11 errors](#11-errors) ·
[12 operations](#12-operations) ·
[13 objects](#13-objects) ·
[14 where models are kept](#14-where-models-are-kept-save) ·
[15 limits](#15-limits) ·
[16 versions and extensions](#16-versions-and-extensions) ·
[17 test vectors](#17-test-vectors) ·
[18 a session, byte by byte](#18-a-session-byte-by-byte)

## 1. Conventions

* **Byte order.** Frame headers (§3), the fixed start of the handshake
  frames (§5) and raw `float32` arrays (§4.4) are **little-endian**.
  Inside payloads, MessagePack's own numbers are big-endian, as the
  MessagePack specification defines them (§4).
* **Notation.** `u8`, `u16`, `u32`: unsigned integers of 1, 2, 4 bytes.
  Bytes are written in hexadecimal (`4e 4d`). In payload descriptions,
  `{"key": type}` is a MessagePack map; `str`, `int`, `float`, `bool`,
  `bin`, `nil`, `array`, `map` are the types of §4; `float` fields accept
  an `int` too (§4.3).
* **Names** of models and datasets: 1–64 characters `A-Z a-z 0-9 . _ -`,
  starting with a letter or digit, not ending in `.`, and not a Windows
  device name (`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`,
  in any case, alone or before a dot). Names are case-sensitive. Anything
  else is the error `invalid_name`: names become file names on the server.
* **Times** are `int` seconds since 1970-01-01 00:00 UTC; sizes are bytes;
  durations are seconds (`float` unless said otherwise). A number that is
  not finite (a NaN loss) is sent as `nil`.
* **Unknown map keys** are ignored by both sides: later additions bring new
  keys (§16).
* **Lists** are maps: `{"items": [...]}`.
* **Samples count from 0.**

## 2. The connection

The server listens on TCP port **6769** by default (N-R-M-Z on a phone
keypad). IANA lists 6769 for another service (ADInstruments GxP Server,
`adi-gxp-srvprt`), so a machine that runs that one configures another port
for the server and its clients. The conversation:

```
client                                  server
  | ---------- TCP connect -------------> |
  | <--------- GREETING (id 0) ---------- |   magic, version, nonce, auth method, limits
  | ---------- HELLO (id 0) ------------> |   magic, version, client nonce, key id, proof
  | <--------- WELCOME (id 0) ----------- |   user, permissions, server proof   (or ERROR, close)
  | ---------- REQUEST (id 1) ----------> |
  | ---------- REQUEST (id 2) ----------> |   several requests at once
  | <--------- RESPONSE (id 2) ---------- |   answers in any order
  | <--------- RESPONSE (id 1) ---------- |
  | ---------- PING ---------------------> |
  | <--------- PONG ---------------------- |
  | ---------- TCP close ----------------> |
```

1. On accepting a connection the server sends GREETING at once. If it is
   at its connection limit it sends an ERROR `too_many_connections`
   (request id 0) instead and closes.
2. The client checks the greeting (magic, version, §5.4) and answers with
   HELLO within the handshake timeout (10 s on the reference server).
3. The server checks the hello and the proof (§6) and sends WELCOME, or an
   ERROR with request id 0 and closes.
4. After WELCOME, the client sends requests (§7). Either side may close
   the TCP connection at any time; requests in flight are then abandoned
   (a training job keeps running: jobs belong to the server, not to the
   connection).

Before WELCOME, the only frames are GREETING, HELLO, WELCOME and ERROR,
each at most 65 536 bytes of payload. Anything else is a `protocol_error`.

The protocol has no TLS of its own yet (§16.2): use it on a trusted
network, through an SSH tunnel or a VPN. The token never travels (§6),
but the rest of the conversation is readable on the path.

## 3. Frames

Everything after the TCP connect is a sequence of frames, in both
directions. A frame is a 12-byte header and a payload:

| offset | size | field | |
|---|---|---|---|
| 0 | 4 | `length` | `u32`, little-endian: the payload's size in bytes (the header not counted) |
| 4 | 1 | `type` | `u8`: the frame type, below |
| 5 | 1 | `flags` | `u8`: bit 0 = `MORE` (`0x01`); bits 1–7 must be 0 |
| 6 | 2 | `reserved` | must be `00 00` |
| 8 | 4 | `request id` | `u32`, little-endian |
| 12 | `length` | payload | |

Frame types:

| type | name | direction | request id | payload |
|---|---|---|---|---|
| `0x01` | GREETING | server → client | 0 | §5.1 |
| `0x02` | HELLO | client → server | 0 | §5.2 |
| `0x03` | WELCOME | server → client | 0 | §5.3 |
| `0x10` | REQUEST | client → server | ≥ 1 | a map with `"op"` (§7) |
| `0x11` | RESPONSE | server → client | the request's | a map: the result |
| `0x12` | ERROR | server → client | the request's, or 0 | a map (§11) |
| `0x13` | DATA | both | the request's | raw bytes of a stream (§8), at least 1 byte |
| `0x14` | END | both | the request's | a map: the end of a stream (§8) |
| `0x15` | EVENT | server → client | the subscription's | a map (§9) |
| `0x16` | ABORT | client → server | the request's | empty |
| `0x20` | PING | both | any | 0–64 opaque bytes |
| `0x21` | PONG | both | the PING's | the PING's payload |

Type `0x04` is reserved for a future STARTTLS (§16.2); all other values are
unknown. Rules for receivers:

* **Size.** A frame whose `length` is over the receiver's limit is an
  error before its payload is read: `frame_too_large`. The limit is
  65 536 bytes during the handshake and `max_frame` after it (§5.3, at
  least 65 536 bytes). The receiver does not read the payload: it sends
  ERROR (request id 0) and closes.
* **Unknown type**: `unknown_frame`, and the connection closes.
* **Flags or reserved bits set** that this version does not define, a
  frame in the wrong direction or out of place (a REQUEST before WELCOME,
  a second HELLO, a HELLO after WELCOME, request id 0 on a REQUEST, an id
  that is already in flight on a REQUEST): `protocol_error`, and the
  connection closes.
* **Truncation.** A connection that closes in the middle of a frame has
  lost that frame; there is nothing to answer.

`MORE` says "more frames of this request follow from the same sender"; the
frame without `MORE` is the sender's last for that request (§7.2).

## 4. Payloads: a MessagePack subset

Structured payloads (every type except DATA, PING, PONG, ABORT, and the
first 12 bytes of GREETING and HELLO) are exactly one MessagePack value —
always a **map** at the top — encoded with the subset below. The
[MessagePack specification](https://github.com/msgpack/msgpack/blob/master/spec.md)
describes the same encodings; any MessagePack library can read and write
these payloads if it keeps to the subset.

### 4.1 The encodings

| first byte | type | then | value |
|---|---|---|---|
| `00`–`7f` | positive fixint | — | the byte, 0–127 |
| `80`–`8f` | fixmap | N = byte & `0f` pairs | map |
| `90`–`9f` | fixarray | N = byte & `0f` values | array |
| `a0`–`bf` | fixstr | N = byte & `1f` bytes | str |
| `c0` | nil | — | nil |
| `c2` / `c3` | false / true | — | bool |
| `c4` | bin 8 | `u8` N, N bytes | bin |
| `c5` | bin 16 | `u16` N (big-endian), N bytes | bin |
| `c6` | bin 32 | `u32` N (big-endian), N bytes | bin |
| `ca` | float 32 | 4 bytes, IEEE 754 binary32, big-endian | float |
| `cb` | float 64 | 8 bytes, IEEE 754 binary64, big-endian | float |
| `cc` / `cd` / `ce` / `cf` | uint 8 / 16 / 32 / 64 | 1 / 2 / 4 / 8 bytes, big-endian | int |
| `d0` / `d1` / `d2` / `d3` | int 8 / 16 / 32 / 64 | 1 / 2 / 4 / 8 bytes, big-endian, two's complement | int |
| `d9` | str 8 | `u8` N, N bytes | str |
| `da` | str 16 | `u16` N (big-endian), N bytes | str |
| `db` | str 32 | `u32` N (big-endian), N bytes | str |
| `dc` / `dd` | array 16 / 32 | `u16` / `u32` N (big-endian), N values | array |
| `de` / `df` | map 16 / 32 | `u16` / `u32` N (big-endian), N key-value pairs | map |
| `e0`–`ff` | negative fixint | — | the byte − 256, −32 to −1 |

**Not in the subset**, and invalid: `c1`, the extension types (`c7`, `c8`,
`c9`, `d4`–`d8`, including MessagePack's timestamp).

### 4.2 Validity

A payload is invalid (`bad_request` for a REQUEST's payload, `protocol_error`
for the others) when:

* it is not exactly one value: trailing bytes after the value, or a value
  cut short by the end of the payload;
* the top value is not a map;
* a map key is not a `str`, contains U+0000, or occurs twice in one map;
* a `str` is not valid UTF-8 (overlong forms, UTF-16 surrogates
  U+D800–U+DFFF, code points above U+10FFFF and stray continuation bytes
  are all invalid; U+0000 is valid);
* containers nest deeper than 32 (the top map is depth 1);
* it holds more than 262 144 values (every key, value and container counts
  one; a `str` or `bin` is one value however long): larger arrays of
  numbers travel as `bin (f32)` (§4.4);
* a `uint 64` is above 2⁶³ − 1 (every `int` fits a signed 64-bit integer,
  as in PHP, Java or JavaScript's BigInt);
* it uses a byte of §4.1's "not in the subset".

Readers must not trust counts: an array that claims 4 billion values in a
payload of 20 bytes is simply cut short (every value takes at least one
byte).

### 4.3 Canonical form

Writers should write, and the reference implementation and the test
vectors do write:

* integers in their shortest form: 0–127 positive fixint; −32 to −1
  negative fixint; otherwise the smallest of `uint 8/16/32/64` for
  non-negative values and of `int 8/16/32/64` for negative ones
  (200 → `cc c8`, −33 → `d0 df`, 65 536 → `ce 00 01 00 00`);
* the shortest header for each `str`, `bin`, `array` and `map`;
* every `float` as `float 64` (readers accept `float 32` as well);
* map members in the writer's order (readers must not depend on order).

A field documented as `float` accepts an `int` (2 is 2.0). A field
documented as `int` accepts a `float` whose value is a whole number. Booleans
are `bool`, not 0 and 1.

### 4.4 Raw arrays of `float32`

Large arrays of numbers (model outputs, inputs) may travel as a `bin`
holding IEEE 754 binary32 values, **little-endian**, packed one after
another (4 bytes each, no header, no padding) — the bytes a C `float[]`
has on every common machine. Such fields say `bin (f32)` below and come
with their shape. A PHP client reads them with `unpack('g*', $bytes)`.
Never re-encoded: the bytes are the numbers.

## 5. The handshake

### 5.1 GREETING (server → client)

The payload starts with 12 fixed bytes, then a map:

| offset | size | field |
|---|---|---|
| 0 | 8 | magic: `4e 4d 5a 50 0d 0a 1a 0a` (`"NMZP\r\n\x1a\n"`) |
| 8 | 2 | `u16` little-endian: the highest protocol major the server speaks (1) |
| 10 | 2 | `u16` little-endian: its minor (0) |
| 12 | … | a map (§4) |

The magic is fixed for every version, so a client can tell a NeuroMZ
server from anything else before it parses a payload whose encoding might
belong to a later major version. The `\r\n` and `\x1a` bytes show a
connection that mangles line ends or stops at a DOS end-of-file byte.

The map:

| key | type | |
|---|---|---|
| `"server"` | str | the server program (`"neuromz-server"`) |
| `"version"` | str | the program's version (`"2.0.0-dev"`), not the protocol's |
| `"min_major"` | int | the lowest protocol major it accepts (1) |
| `"auth"` | str | `"hmac-sha256"` (§6) or `"none"` (every client is `anonymous`) |
| `"nonce"` | bin | 32 random bytes from the operating system, new for every connection |
| `"max_frame"` | int | the largest frame payload it accepts after the handshake (≥ 65 536) |
| `"capabilities"` | array of str | what it supports beyond the core (§16.1) |
| `"status"` | str | `"ok"`, or `"stopping"` when it is shutting down |

The greeting is all an unauthenticated peer learns: a health probe
connects, reads it, checks `status` and closes. Devices, presets and
limits are told only after authentication (`server.capabilities`).

### 5.2 HELLO (client → server)

The same 12 fixed bytes (magic, then the protocol major and minor the
client will speak), then a map:

| key | type | |
|---|---|---|
| `"client"` | str | the client program (`"neuromz-cli"`), at most 64 bytes |
| `"version"` | str | its version, at most 32 bytes |
| `"auth"` | str | `"hmac-sha256"` or `"none"` |
| `"key_id"` | bin (8) | with `hmac-sha256`: which token (§6) |
| `"nonce"` | bin (32) | with `hmac-sha256`: 32 random bytes of the client's |
| `"proof"` | bin (32) | with `hmac-sha256`: the client's proof (§6) |
| `"max_frame"` | int | optional: the largest frame payload the client accepts (≥ 65 536); the server's frames stay within it and its own `max_frame` |

### 5.3 WELCOME (server → client)

A map:

| key | type | |
|---|---|---|
| `"protocol"` | str | the version in use, `"MAJOR.MINOR"` (`"1.0"`) |
| `"user"` | str | the token's user (`"anonymous"` without authentication) |
| `"permissions"` | array of str | `"read"`, `"train"`, `"admin"` (§6.3) |
| `"proof"` | bin (32) | with `hmac-sha256`: the server's proof (§6) |
| `"session"` | str | the connection's id, as the server's log names it |
| `"max_frame"` | int | the limit for frames the client sends (as in the greeting) |
| `"max_frame_out"` | int | the limit the server keeps to in what it sends (the smaller of both) |
| `"max_inflight"` | int | requests the client may have in flight at once (§7.3) |
| `"idle_timeout"` | int | seconds without frames, and nothing in flight, before the server closes (§10) |

### 5.4 Versions

The handshake carries a major and a minor version. The major is the
protocol's number (1 here), and majors are incompatible with each other.
The minor is 0 and stays 0: additions within a major come as capabilities
and as operations, map keys and error codes that older peers ignore
(§16). The rules below still say what a peer does with a minor it does not
know.

* The **client** reads the greeting's magic first: anything else means the
  peer is not a NeuroMZ server (one that sends nothing first, an HTTP
  server for one, makes the client's wait for a greeting time out). It then
  chooses a major in
  [`min_major`, the greeting's major] that it speaks — the highest one — and
  the minor: the smaller of its own and the server's when the majors are
  equal, its own otherwise. If there is none, it closes and says so ("the
  server speaks protocol 1.0 to 2.1; this client speaks 3").
* The **server** checks the hello's magic (`bad_magic` otherwise) and its
  major (`unsupported_version` unless it is in [`min_major`, its major]),
  answering with ERROR, request id 0, and closing. The error's `details`
  carry `{"min_major": int, "major": int, "minor": int}`. WELCOME confirms
  the version both now speak. A hello whose minor is higher than the
  server's is accepted at the server's minor.
* A server that receives `GET `, `POST`, `PUT `, `HEAD`, `DELE` or `OPTI`
  as its first four bytes (an HTTP client) answers with ERROR
  `protocol_error` saying that it speaks the NeuroMZ protocol, not HTTP, and
  closes.

## 6. Authentication

### 6.1 Challenge and response

Tokens are strings (the reference server makes `nmz_` and 48 hexadecimal
digits: 192 random bits). The server does not keep tokens: it keeps
`SHA-256(token)`. That hash is the key of a challenge and response, so the
token never crosses the network:

```
K        = SHA-256(token)                                       32 bytes; token = its bytes (UTF-8)
key_id   = first 8 bytes of HMAC-SHA256(K, "neuromz key id")
proof_c  = HMAC-SHA256(K, "neuromz client proof" || Ns || Nc)  32 bytes
proof_s  = HMAC-SHA256(K, "neuromz server proof" || Ns || Nc)  32 bytes
```

`Ns` is the greeting's `nonce`, `Nc` the hello's, `||` concatenation; the
labels are their ASCII bytes, without a terminating NUL. HMAC-SHA256 is
RFC 2104 with SHA-256 (block size 64 bytes); the vectors of RFC 4231 test
it (and [`tests/vectors/auth.json`](tests/vectors/auth.json) the whole
derivation).

1. The client computes `K`, `key_id`, draws `Nc` (32 bytes from the
   operating system's random generator) and sends `key_id`, `Nc` and
   `proof_c` in HELLO.
2. The server looks `key_id` up among its tokens' keys (comparing with
   every entry, without stopping at a match), computes `proof_c` with the
   key it found and compares it with the client's in constant time. A
   wrong key id and a wrong proof get the same answer: ERROR
   `unauthorized` ("the token is not valid"), request id 0, and the
   connection closes.
3. Otherwise the server sends WELCOME with `proof_s`. The client checks it
   (constant time) and closes the connection if it is wrong: the peer is
   not the server that holds its token.

With `"auth": "none"` in the greeting, the server accepts every client as
the user `anonymous` with every permission. A client that was given a
token must refuse such a server unless its user asked for it: an attacker
on the path could otherwise rewrite the greeting and pose as the server
(the reference client says so and stops).

### 6.2 What it protects, and what not

* **The token is never sent.** A passive eavesdropper sees `key_id`, the
  nonces and two proofs: not enough to compute a proof for another
  connection, whose server nonce will differ.
* **No replay.** Both nonces are fresh for every connection; a recorded
  HELLO is worthless against a new greeting.
* **Mutual.** The server proves it holds `K` (`proof_s`), so a client can
  tell when it reached the wrong server.
* **The tokens file is the secret.** `K` is what a client needs: whoever
  reads the server's tokens file (`sha256:` lines) can authenticate as any
  of its users with this protocol. It cannot recover the tokens themselves
  (a SHA-256 preimage), so a token used elsewhere is not exposed. Keep the
  file readable by the server's account only.
* **Guessing offline.** A recorded handshake lets an attacker test
  candidate tokens at the speed of SHA-256. Against the reference server's
  192-bit random tokens that is hopeless; a short hand-written token
  (the tokens file accepts 16 characters and more) could fall. Use
  generated tokens.
* **Sessions are not protected.** After the handshake nothing is encrypted
  or authenticated: an attacker who can change traffic on the path can
  read models and data, alter answers, or take over the connection after
  WELCOME. `key_id` is constant for a token, so a passive observer can
  tell connections of the same token apart from others. TLS (§16.2) will
  close these gaps; until then, a trusted network, an SSH tunnel or a VPN.

### 6.3 Permissions

| permission | allows |
|---|---|
| `read` | every listing and description; `predict`, `test`, `generate`, `trace`; downloading files; subscribing to jobs |
| `train` | `read`, and creating, uploading and deleting **one's own** models and datasets, starting and cancelling **one's own** jobs |
| `admin` | everything, on everyone's resources |

Not allowed: `forbidden`. Every model, dataset and job has an `owner`;
everyone who can read sees all of them.

## 7. Requests and responses

### 7.1 A request

A REQUEST frame's payload is a map with the operation's name and its
arguments:

```
{"op": "models.describe", "name": "xor"}
```

`"op"` is a `str` (§12 lists them); unknown arguments are ignored; a
missing or mistyped argument is `bad_request`; an unknown operation is
`unknown_operation`. The client chooses the request id: any `u32` but 0
that is not in flight on this connection. Clients should not reuse ids on
a connection (a counter from 1 does).

### 7.2 Its answer

For every request the server sends one or more frames with the request's
id; the last one has `MORE` clear and **ends the request**:

| the request | the server sends |
|---|---|
| most operations | RESPONSE |
| a download (§8.2) | RESPONSE (`MORE`), DATA (`MORE`) …, END |
| a subscription (§9) | RESPONSE (`MORE`), EVENT (`MORE`) …, EVENT without `MORE` |
| any of them, on failure | ERROR — at any point, always the last frame |

An ERROR never has `MORE`. After the last frame the id is free.

### 7.3 Several at once

A client may send further requests without waiting: up to `max_inflight`
(WELCOME) at once; one more gets ERROR `too_many_requests` on its id and
the connection stays open. Answers come in whatever order the work
finishes, and frames of different requests interleave (a large download
does not hold up a small answer: it travels in DATA frames). A request is
in flight from its REQUEST until the server's last frame for it.

### 7.4 ABORT

ABORT (empty payload) with a request's id asks the server to stop it: an
upload that the client gives up, a download it no longer wants, a
subscription it is done with (that is how one unsubscribes). The server
ends the request with ERROR `cancelled` — unless its last frame was already
on the way, in which case the ABORT is ignored. A client that sent ABORT
keeps reading until the request's last frame. An ABORT of an inference
request that is already computing may only take effect when it finishes.
(Stopping a training job is the operation `jobs.cancel`: a job is not a
request.)

The server ignores DATA, END and ABORT frames whose id is not in flight:
they may have crossed the request's last frame on the wire.

## 8. Byte streams

Model files, datasets and traces travel as streams of DATA frames, so
that a large file never needs a large frame and other requests keep
moving between its chunks.

* A **DATA** frame's payload is raw bytes, at least one, at most the
  receiver's `max_frame`. The reference implementations send 256 KiB
  chunks.
* An **END** frame closes the stream: `{"size": int, "sha256": bin (32)}`
  — the number of bytes in all the stream's DATA frames and their SHA-256.
  The receiver checks both.

### 8.1 Uploads (client → server)

```
C: REQUEST  MORE   {"op": "datasets.upload", "name": "xor", "format": "csv", "size": 24}
C: DATA     MORE   30 2c 30 2c 30 0a ...            (24 bytes in all, in one or more frames)
C: END             {"size": 24, "sha256": <32 bytes>}
S: RESPONSE        {"dataset": {...}, "created": true}
```

The REQUEST has `MORE` set and gives the stream's `size` in advance, so
the server can refuse a file it will not take before it arrives. The
server may answer with ERROR before END (`payload_too_large`,
`forbidden`, `conflict`, …); the client then stops sending DATA for that
request (frames already sent are ignored, §7.4). A size or hash that does
not match END is `integrity_error`. An operation that takes a stream sent
without `MORE`, or one that takes none sent with it, is `bad_request`.

### 8.2 Downloads (server → client)

```
C: REQUEST         {"op": "models.download", "name": "xor"}
S: RESPONSE MORE   {"name": "xor", "version": 3, "size": 1404}
S: DATA     MORE   89 4e 4d 5a ...
S: END             {"size": 1404, "sha256": <32 bytes>}
```

The RESPONSE says what follows and how large it is; the client checks
END's size and hash against what it received, and refuses the file if they
differ.

## 9. Events

Training progress is pushed by the server on the same connection.

```
C: REQUEST         {"op": "jobs.subscribe", "id": "j12", "after": 0}
S: RESPONSE MORE   {"job": {...the job object...}}
S: EVENT    MORE   {"event": "state", "seq": 1, "data": {...the job object...}}
S: EVENT    MORE   {"event": "batch", "seq": 0, "data": {"epoch": 1, "batch": 20, "batches": 127, "loss": 2.31, "learning_rate": 0.01}}
S: EVENT    MORE   {"event": "epoch", "seq": 2, "data": {"epoch": 1, "loss": 2.05, "accuracy": 0.41, ...}}
S: EVENT           {"event": "end", "seq": 9, "data": {...the final job object...}}
```

An EVENT's payload: `{"event": str, "seq": int, "data": map}`.

| event | `seq` | `data` |
|---|---|---|
| `state` | ≥ 1 | the job object (§13.3), when its state changes (queued, running with its device and configuration, queued again after running out of GPU memory) |
| `epoch` | ≥ 1 | `{"epoch": int, "loss": float, "accuracy": float, "val_loss": float\|nil, "val_accuracy": float\|nil, "learning_rate": float, "clipped_batches": int, "improved": bool, "elapsed_s": float}` |
| `batch` | 0 | `{"epoch": int, "batch": int, "batches": int, "loss": float, "learning_rate": float}`: live only, at most 4 a second |
| `end` | ≥ 1 | the final job object; the last event, without `MORE` |

* `state`, `epoch` and `end` are **numbered** (`seq` 1, 2, 3 … per job) and
  kept with the job: a subscriber that arrives late, or comes back with
  `"after": N`, first gets every numbered event after N, then the live
  ones. `batch` events are not kept and carry `seq` 0.
* A finished job's subscription replays its events and ends at once.
* Several subscriptions (to the same or other jobs) may be open on one
  connection, each under its own request id. ABORT ends one (§7.4).
* `after` is optional (default 0).

## 10. Keep-alive and timeouts

* **PING / PONG.** Either side may send PING (0–64 bytes, any request id)
  after the handshake; the other answers with PONG carrying the same id
  and payload, promptly. A PING and its PONG are not requests and never in
  flight. The reference server pings a connection that has a subscription
  open and has sent nothing for 30 s, so dead clients and stale NAT
  entries show.
* **Idle.** A connection with nothing in flight that receives no frame for
  `idle_timeout` seconds (WELCOME; 300 on the reference server) is closed
  by the server, after an ERROR `timeout` with request id 0. A client that
  wants to keep an idle connection sends PING now and then.
* **Handshake.** A client that has not sent a complete HELLO within the
  server's handshake timeout (10 s on the reference server) gets ERROR
  `timeout` and the connection closes. A client that receives no complete
  greeting within its own timeout gives up (it is probably not talking to
  a NeuroMZ server).
* **Requests** have no time limit: inference is bounded by the size of its
  request (samples, characters to generate, trace events), training runs
  as a job.

## 11. Errors

An ERROR frame's payload:

```
{"code": 203, "name": "invalid_argument", "message": "--lr needs a positive number, got '-1'", "details": {}}
```

`code` (`int`) and `name` (`str`) are stable — `name` is the code in words,
for people and logs; `message` is for people (the library's own message
where the library refused); `details` (a map, optional) carries specifics.
An ERROR with request id 0 is about the connection: the server closes it
after sending (codes 100–199). Any other ERROR ends one request and the
connection stays open.

| code | name | when |
|---|---|---|
| 100 | `protocol_error` | a malformed frame, a frame out of place, flags or reserved bits set, an invalid payload outside a REQUEST, a request id already in flight, an HTTP client |
| 101 | `bad_magic` | the hello does not start with the magic |
| 102 | `unsupported_version` | the hello's major is not one the server speaks (`details`: §5.4) |
| 103 | `frame_too_large` | a frame over the limit (§3) |
| 104 | `unknown_frame` | an unknown frame type |
| 105 | `timeout` | the handshake did not finish in time, or the connection was idle (§10) |
| 106 | `too_many_connections` | the server is at its connection limit: try again later |
| 107 | `shutting_down` | the server is stopping |
| 108 | `unauthorized` | the token is not valid, or authentication is required (§6) |
| 200 | `bad_request` | an invalid REQUEST payload, a missing or mistyped argument, a stream where none belongs |
| 201 | `unknown_operation` | `op` names no operation |
| 202 | `invalid_name` | a model or dataset name breaks §1 |
| 203 | `invalid_argument` | well-formed but refused: a layer spec, an option, data that does not fit the model |
| 204 | `payload_too_large` | an upload or answer over a limit (§15) |
| 205 | `integrity_error` | an upload whose size or SHA-256 does not match its END |
| 206 | `too_many_requests` | more than `max_inflight` requests at once |
| 207 | `cancelled` | the request was ended by ABORT |
| 300 | `forbidden` | the token lacks the permission, the resource is someone else's, or the server disables the feature |
| 301 | `save_not_allowed` | `save` asks for a place the server does not allow (§14) |
| 400 | `not_found` | no such model, dataset or job |
| 401 | `conflict` | the name exists (without `"overwrite": true`), the job already finished, the model is busy |
| 402 | `queue_full` | the job queue is full: try again later |
| 403 | `quota_exceeded` | the user's storage quota would be exceeded |
| 500 | `internal` | a bug in the server |
| 501 | `unavailable` | the requested device is not available |
| 502 | `out_of_memory` | the model and batch do not fit the device: try a smaller batch |
| 503 | `numeric` | the loss became NaN or infinite |

A job that fails reports the same three fields in its `error` (§13.3).
Clients must handle codes they do not know by their range: 1xx the
connection, 2xx the request, 3xx permission, 4xx the state of things, 5xx
the server.

## 12. Operations

Each operation lists its arguments (the REQUEST map besides `"op"`), the
permission it needs, and its result (the RESPONSE map). `device` is
`"auto"`, `"cpu"` or `"cuda"`, optional; without it the server's default
applies. Operations that compute say in their result which device they
used (`"device"`).

### 12.1 The server

| op | arguments | permission | result |
|---|---|---|---|
| `health` | — | any | `{"status": "ok", "protocol": "1.0"}` |
| `server.info` | — | any | `{"name", "version", "protocol", "library", "started": int, "uptime_s": int, "session", "user": {"name", "permissions": [str]}}` |
| `server.capabilities` | — | any | below |

`server.capabilities`, enough to choose a device, a batch size and a save
policy before sending work:

```
{"protocol": "1.0", "auth": true,
 "backends": [
   {"name": "cpu", "available": true, "device": "host CPU (6 threads)", "threads": 6},
   {"name": "cuda", "available": true, "device": "NVIDIA GeForce GTX 1660 Ti",
    "compute_capability": "7.5", "memory_total_mb": 6144, "memory_free_mb": 5120,
    "memory_limit_mb": 4096, "memory_used_mb": 0.0, "memory_peak_mb": 0.0, "jobs_running": 0}],
 "default_device": "cuda",
 "presets": [{"name": "mnist-cnn", "summary": "small convolutional network for MNIST digits", "input": "1x28x28"}],
 "save": {"default": "server", "allowed": ["server", "client"]},
 "limits": {"max_frame_mb": 4, "max_upload_mb": 64, "max_model_mb": 512, "max_layer_size": 16384,
            "max_epochs": 1000, "max_concurrent_jobs": 2, "queue_size": 16, "quota_per_user_mb": 2048,
            "client_model_hours": 24, "keep_finished_hours": 24, "max_inflight": 8,
            "idle_timeout_s": 300, "max_connections": 64},
 "trace": {"enabled": true, "max_events": 2000},
 "dataset_formats": ["csv", "text", "idx-images", "idx-labels"],
 "capabilities": ["events", "generate", "trace", "server-paths", "f32"]}
```

An unavailable backend has `"available": false` and `"reason": str`.
`memory_*` are MiB (`memory_used_mb` and `memory_peak_mb` are `float`).

### 12.2 Models

| op | arguments | permission | result |
|---|---|---|---|
| `models.create` | below | `train` | `{"model": model, "explanation": [str], "created": bool}` |
| `models.list` | — | `read` | `{"items": [model]}` (without `layers` and `config`) |
| `models.describe` | `name` | `read` | the model object (§13.1) |
| `models.delete` | `name` | `train` (owner) or `admin` | `{}`; `conflict` while a job trains it |
| `models.upload` | `name`, `size`, `save`?, `overwrite`? + stream (§8.1) | `train` | `{"model": model, "created": bool}` |
| `models.download` | `name` | `read` | download (§8.2): `{"name", "version", "size", "storage"}`, then the file |

**`models.create`** builds a model the way `neuromz new` does — the same
grammar, presets, defaults and explanation (the library's `nmz_model_new`).
Either the program's arguments verbatim:

```
{"op": "models.create", "name": "xor", "args": ["2", "4", "1"]}
{"op": "models.create", "name": "names", "args": ["--preset", "names", "--data", "names-en"]}
```

or the same in fields:

```
{"op": "models.create", "name": "cnn", "input": "1x28x28",
 "layers": ["conv:8:3:relu", "pool:2", "conv:16:3:relu", "pool:2", "64:relu", "10:softmax"],
 "loss": "ce", "normalize": "zscore", "seed": 7, "options": {"lr": 0.001, "batch": 32}}
```

Arguments: `name` (str, required); `args` (array of str) **or** any of
`preset` (str), `input` (str), `layers` (array of str), `dataset` (str: a
dataset whose text builds a text model's vocabulary; `--data NAME` in
`args` names one too), `loss` (str), `normalize` (str), `seed` (int ≥ 0),
`items` (bool), `strip_diacritics` (bool), `unify_alef` (bool), `options`
(map, below); `save` (str, §14); `overwrite` (bool, default false:
`conflict` if the name exists). `explanation` is what the program prints:
one line per element.

**Training options** (`options` here and in `jobs.train`) are the
program's, one key per option: `lr`, `momentum`, `batch`, `epochs`,
`target_loss`, `optimizer` (`sgd`, `adam`, `adamw`), `beta1`, `beta2`,
`eps`, `schedule` (`constant`, `step`, `cosine`, `warmup-cosine`),
`step_size`, `gamma`, `min_lr`, `weight_decay`, `decay_all` (bool),
`warmup`, `shuffle` (bool), `carry` (bool), `val`, `clip`, `patience`,
`seq_len`. Key `k` is the option `--k` with `_` written as `-`; values are
`int`, `float`, `str` or `bool`. The library's parser checks them, so a bad
value gets the program's message (`invalid_argument`).

**`models.upload`** takes a model file (`.nmz`, any format the library
reads); the server loads it to check it (`invalid_argument` if it cannot).
`overwrite` replaces a model of the same name (owner or admin).
`created` is false when it replaced one. Model files are the same on every
device.

### 12.3 Datasets

| op | arguments | permission | result |
|---|---|---|---|
| `datasets.upload` | `name`, `format`, `size`, `labels`?, `overwrite`? + stream (§8.1) | `train` | `{"dataset": dataset, "created": bool}` |
| `datasets.register` | `name`, `path`, `format`, `labels`?, `overwrite`? | `train` | `{"dataset": dataset, "created": bool}` |
| `datasets.list` | — | `read` | `{"items": [dataset]}` |
| `datasets.describe` | `name` | `read` | the dataset object (§13.2) |
| `datasets.delete` | `name` | `train` (owner) or `admin` | `{}`; a registered path is forgotten, the file stays |

`format`: `"csv"` (numbers, the first columns inputs, the rest targets; a
text last column is a class label), `"text"` (UTF-8: names one per line,
or running text), `"idx-images"` and `"idx-labels"` (the MNIST files).
`labels` names the `idx-labels` dataset that goes with an `idx-images`
one. The dataset's `sha256` lets a client skip uploading a file the server
already has.

`datasets.register` names a file that is already on the server, if the
server's configuration allows its directory: `path` is relative to one of
the allowed roots, with `/` between its parts (no `..`, nothing absolute:
`forbidden`; a server without roots forbids it).

### 12.4 Jobs

| op | arguments | permission | result |
|---|---|---|---|
| `jobs.train` | below | `train` | the job object (§13.3) |
| `jobs.list` | `state`? | `read` | `{"items": [job]}`, newest first; `state` filters |
| `jobs.status` | `id` | `read` | the job object |
| `jobs.cancel` | `id` | `train` (owner) or `admin` | the job object; `conflict` if it finished |
| `jobs.subscribe` | `id`, `after`? | `read` | a subscription (§9) |
| `jobs.model` | `id` | `read` | download (§8.2) of the job's trained model, while the job is kept |

**`jobs.train`**: `model`, `dataset` (str, required); `validation` (str: a
dataset used as the validation set, like `--val-file`); `device`; `save`
(§14); `options` (map, §12.2) **or** `args` (array of str: the program's
option arguments, `["--epochs", "5", "--lr", "0.01"]`); `limit` (int: train
on the first N samples); `header` (bool, CSV: whether the first line is a
header; detected without it). Options override the model's stored
training configuration for this run. The job is queued and run by one of
the server's workers (at most `max_concurrent_jobs` at once):
`queue_full`, or `unavailable` when the requested device cannot be used.

**`jobs.cancel`**: a queued job is cancelled at once; a running one stops
after its current batch (the model keeps the weights of the batches
already done only when `save` writes them, §14).

### 12.5 Inference

Synchronous: the answer is the RESPONSE.

**`models.predict`** (`read`): `name`, `device`?, and one of

* `inputs`: one sample (an array of numbers), several (an array of arrays
  of numbers), or a `bin (f32)` of N samples (N × the model's input size
  values, row after row);
* `dataset` (str) and `sample` (int): one sample of a dataset, with its
  target;
* `text` (str), for a text model: the distribution of the next character.

```
{"outputs": bin (f32), "shape": [2, 1], "predicted": [0, 0], "classes": nil, "targets": nil, "device": "cuda"}
{"text": "Alice was", "next": [{"char": " ", "p": 0.41}, {"char": "s", "p": 0.12}], "device": "cpu"}
```

`outputs` is `shape[0]` samples × `shape[1]` outputs as `float32`
(§4.4); `predicted` the index of each sample's largest output; `classes`
the class names when the data has them (else nil); `targets` (`bin (f32)`
of the same shape, or nil) the dataset sample's target. At most 100 000
samples per request.

**`models.test`** (`read`): `name`, `dataset` (required), `limit` (int),
`header` (bool), `device`?.

```
{"dataset": "iris", "samples": 150, "loss": 0.105, "accuracy": 0.973, "perplexity": nil,
 "classes": ["setosa", "versicolor", "virginica"], "confusion": [[50, 0, 0], [0, 47, 3], [0, 1, 49]], "device": "cpu"}
```

`confusion[t][p]`: samples of true class `t` predicted as `p` (classifiers
with 2–100 outputs; else nil); `perplexity` for text models.

**`models.generate`** (`read`): the program's `generate` — `prime` (str),
`length` (int), `temperature` (float), `top_k` (int), `seed` (int ≥ 0),
`count` (int), `new_only` (bool), `context` (int), `no_cache` (bool),
`dataset` (str: the items that count as known for `new_only`; default:
the ones the model recorded), `device`?. Line-per-item models (names)
return distinct items:

```
{"kind": "items", "items": [{"text": "Marla", "known": false}, {"text": "Anna", "known": true}], "attempts": 12, "device": "cpu"}
```

running-text models return passages (one per seed `seed`, `seed+1`, …):

```
{"kind": "text", "texts": ["Alice was beginning to get very tired..."], "device": "cpu"}
```

### 12.6 Trace

**`models.trace`** (`read`): one sample forward and backward, nothing
changed (the update is only previewed) — the program's `trace`. The
sample: `inputs` (array of numbers or `bin (f32)`) and `target` (the same),
or `dataset` and `sample`, or `text` for text models; `device`?. The answer
is a download (§8.2):

```
S: RESPONSE MORE   {"events": 41, "truncated": false, "format": "jsonl", "size": 52311, "device": "cpu"}
S: DATA     MORE   {"step":1,"phase":"forward","layer":0, ...}\n ...
S: END             {"size": 52311, "sha256": <32 bytes>}
```

The stream is the library's trace format — JSON, one event per line, each
line ending with `\n`, exactly as `nmz_trace_event_write_json` writes it —
carried as bytes, not re-encoded: a web page or the program reads it as
it is. `truncated` is true when the server's `max_events` cut it short.
A server that disables traces answers `forbidden`.

## 13. Objects

### 13.1 Model

```
{"name": "xor", "owner": "alice", "storage": "server", "version": 3,
 "created": 1795874460, "updated": 1795874550, "expires": nil,
 "size": 1404, "training_job": nil, "params": 17, "sequence": false, "input_shape": [2], "outputs": 1,
 "loss": "mse", "normalization": "none", "vocab_size": nil, "train_steps": 172, "classes": ["a", "b"],
 "layers": [{"index": 0, "type": "dense", "description": "dense 2->4", "params": 12},
            {"index": 1, "type": "activation", "description": "tanh", "params": 0}],
 "config": {"summary": "sgd lr 0.5, momentum 0.9, batch 4, max epochs 1000, target loss 0.001, shuffle on",
            "optimizer": "sgd", "lr": 0.5, "momentum": 0.9, "batch": 4, "epochs": 1000, "target_loss": 0.001,
            "schedule": "constant", "shuffle": true}}
```

`version` increases with every change to the model's weights or file.
`storage` and `expires` (a time, or nil): §14. `input_shape` is `[-1]` for
text models (any length). `training_job`: the job that trains it now, or
absent. `classes` is present when the model has class names. `config` may
also hold `weight_decay`, `seq_len`, `val`, `clip`, `patience` when they
apply.

### 13.2 Dataset

```
{"name": "xor", "owner": "alice", "format": "csv", "size": 24, "sha256": "9f1c...64 hex digits...",
 "created": 1795874430, "source": "upload", "labels": nil}
```

`source` is `"upload"` or `"path"` (then `path` gives the registered
path). `sha256` is lowercase hexadecimal.

### 13.3 Job

```
{"id": "j12", "type": "train", "state": "running", "owner": "alice",
 "model": "xor", "dataset": "xor", "validation": nil,
 "device_requested": "auto", "device": "cuda", "save": "server",
 "created": 1795874520, "started": 1795874520, "finished": nil,
 "config": "sgd lr 0.5, momentum 0.9, batch 4, max epochs 200, target loss 0.001, shuffle on",
 "progress": {"epoch": 41, "epochs": 200, "batch": 1, "batches": 1, "loss": 0.21,
              "accuracy": 0.75, "val_loss": nil, "val_accuracy": nil,
              "learning_rate": 0.5, "elapsed_s": 0.03},
 "result": nil, "error": nil, "output_model": nil, "gpu_memory_peak_mb": nil}
```

`state`: `queued` → `running` → `succeeded` | `failed` | `cancelled`.
`progress` is nil until the job starts. `result` (when it succeeded, or
was cancelled after at least one batch): `{"epochs": int, "loss",
"accuracy", "val_loss", "val_accuracy" (float or nil), "converged": bool,
"stopped": bool, "best_epoch": int}`, as the library reports them.
`error`: `{"code": int, "name": str, "message": str}` (§11). `output_model`:
where the trained model went (§14). Finished jobs are kept for
`keep_finished_hours`; a restart of the server forgets jobs.

## 14. Where models are kept (`save`)

Every model has a `storage`:

* `"server"`: kept in the server's model store; survives restarts; counts
  towards the owner's quota.
* `"client"`: kept for the client only: not written to the server's
  store, forgotten `client_model_hours` after its last use (`expires`) and
  at a restart. The client downloads it to keep it.

Operations that create or change a model take `"save": "server"` or
`"client"`; without it the server's default applies. A server allows one
or both (`server.capabilities` → `save`); others get `save_not_allowed`.

* **Creating, uploading**: the new model gets that storage.
* **Training** (`jobs.train`):
  * `save: "server"`: the trained weights replace the model's, which is (or
    becomes) stored on the server. `output_model` is the model's name.
  * `save: "client"` on a `client` model: the model is updated in place.
  * `save: "client"` on a `server` model: the stored model is left as it
    was; the result becomes a new `client` model named `NAME.jID` (e.g.
    `xor.j12`), in `output_model`, also downloadable with `jobs.model`.
  * A cancelled job writes the batches it finished, by the same rules; a
    failed job writes nothing.

## 15. Limits

`server.capabilities` → `limits` lists them.

* Frames over `max_frame` (GREETING, WELCOME): `frame_too_large`, and the
  connection closes.
* A REQUEST's payload is a frame: at most `max_frame` bytes, so a request
  of more numbers than that goes as `bin (f32)` in several requests, or as
  a dataset.
* Uploads (`size`) over `max_upload_mb` MiB, a model over `max_model_mb`
  MiB: `payload_too_large`. An answer that would not fit in one frame for
  the client (`max_frame_out`): `payload_too_large` — ask for less.
* `epochs` above `max_epochs`: `invalid_argument`. A model description
  with a number (units, filters, a dimension) above `max_layer_size`:
  `invalid_argument`, before anything is built.
* `max_inflight` requests at once per connection (§7.3),
  `max_connections` connections per server (§2), `idle_timeout_s` (§10).

## 16. Versions and extensions

This is protocol **1** (major 1, minor 0 in the handshake). The number is
the protocol's own: it is not the version of neuromz-server, of the
program or of this repository, and it changes only when the bytes on the
wire change incompatibly — then it is a new major, negotiated in the
handshake (§5.4). Within protocol 1 a server answers every request as
documented here, and additions (operations, map keys, error codes, event
types) never change a frame header or the meaning of what exists. A new
feature comes with a capability (§16.1): a client checks the greeting's
`capabilities` before it uses the feature, and a server without it answers
with a clear error (`unknown_operation` for an operation it does not have,
`invalid_argument` for an argument it does not take), never a broken
connection. Peers ignore map keys and event types they do not know, and
treat unknown error codes by their range (§11).

### 16.1 Capabilities

The greeting's `capabilities` (and `server.capabilities` → `capabilities`)
name optional parts; in protocol 1 so far:

| capability | |
|---|---|
| `events` | `jobs.subscribe` (every 2.0 server has it) |
| `generate` | `models.generate` |
| `trace` | `models.trace` is enabled |
| `server-paths` | `datasets.register` is allowed |
| `f32` | `bin (f32)` inputs |

### 16.2 TLS, later

The handshake leaves room for TLS the way MySQL does it: a server that can
will list `"starttls"` in its greeting's capabilities; a client that wants
it sends a STARTTLS frame (type `0x04`, reserved now) instead of HELLO;
both then run a TLS handshake on the same TCP connection, and the server
sends a new GREETING (with a new nonce) inside TLS, where the handshake of
§5 proceeds as usual. The proofs could then also bind the TLS channel
(an RFC 9266 exporter in the HMAC input). Nothing in 2.0 depends on it.

## 17. Test vectors

[`tests/vectors/`](tests/vectors/) holds canonical bytes: `NAME.bin` and,
next to it, `NAME.json` saying what the bytes are (the frame's fields, the
payload as JSON with `bin` as hexadecimal, or the reason it is invalid).
`index.json` lists them in three groups:

* `payload`: valid payloads — every encoding of §4.1 at its boundaries, in
  canonical form (§4.3), plus non-canonical forms a reader must accept;
* `payload-invalid`: payloads a reader must refuse (§4.2), each with the
  rule it breaks;
* `frame`: whole frames — every frame type, a greeting, a hello with its
  proof computed from a test token, a welcome, requests, a stream with its
  END, an error, and invalid frames;
* `auth.json`: the key, key id and proofs for a test token and nonces,
  and HMAC-SHA256 checks (RFC 4231).

The vectors are written by the C implementation (`nmzp`) and checked by
its tests in CI; another implementation passes when it decodes every valid
vector to the described value, re-encodes it to the same bytes, and
refuses every invalid one.

## 18. A session, byte by byte

A client with the token `nmz_0123456789abcdef0123456789abcdef0123456789abcdef`
(the test token of `auth.json`) asks for the server's health. The nonces
are those of the vectors; a real connection draws new ones.

The server's GREETING — header, the fixed 12 bytes, the map
(`tests/vectors/frame-greeting.bin`):

```
ba 00 00 00 01 00 00 00 00 00 00 00   header: length 186, type 0x01, flags 0, reserved 0, request id 0
4e 4d 5a 50 0d 0a 1a 0a 01 00 00 00   magic "NMZP\r\n\x1a\n", major 1, minor 0
88 a6 73 65 72 76 65 72 ae 6e 65 75 72 6f 6d 7a
2d 73 65 72 76 65 72 a7 76 65 72 73 69 6f 6e a9
32 2e 30 2e 30 2d 64 65 76 a9 6d 69 6e 5f 6d 61
6a 6f 72 01 a4 61 75 74 68 ab 68 6d 61 63 2d 73
68 61 32 35 36 a5 6e 6f 6e 63 65 c4 20 10 11 12
13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22
23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f a9 6d 61
78 5f 66 72 61 6d 65 ce 00 40 00 00 ac 63 61 70
61 62 69 6c 69 74 69 65 73 94 a6 65 76 65 6e 74
73 a8 67 65 6e 65 72 61 74 65 a5 74 72 61 63 65
a3 66 33 32 a6 73 74 61 74 75 73 a2 6f 6b
```

Reading the map: `88` is a map of 8 pairs; `a6 73 65 72 76 65 72` the str
`"server"`, `ae …` the 14 bytes of `"neuromz-server"`; `a9 6d 69 6e 5f 6d 61
6a 6f 72 01` is `"min_major": 1`; `c4 20` starts a `bin` of 32 bytes (the
nonce); `ce 00 40 00 00` is 4 194 304 as `uint 32` (big-endian, inside the
payload); `94` an array of 4 str. The client checks the magic, then the
version, then reads the map.

The client's HELLO (`frame-hello.bin`) — `key_id`, `nonce` and `proof` are
the `auth.json` values for the test token and these nonces:

```
a4 00 00 00 02 00 00 00 00 00 00 00   header: length 164, type 0x02, flags 0, reserved 0, request id 0
4e 4d 5a 50 0d 0a 1a 0a 01 00 00 00   magic "NMZP\r\n\x1a\n", major 1, minor 0
86 a6 63 6c 69 65 6e 74 ab 6e 65 75 72 6f 6d 7a
2d 63 6c 69 a7 76 65 72 73 69 6f 6e a9 32 2e 30
2e 30 2d 64 65 76 a4 61 75 74 68 ab 68 6d 61 63
2d 73 68 61 32 35 36 a6 6b 65 79 5f 69 64 c4 08
89 4d 4c 6a 41 59 dd 49 a5 6e 6f 6e 63 65 c4 20
a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af
b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf
a5 70 72 6f 6f 66 c4 20 90 39 9e 87 d0 19 31 ee
54 9c 9c 95 c2 81 10 c8 0a e1 5e 09 02 7f c1 d2
23 bf 90 52 bc 03 1b 2f
```

The server's WELCOME (`frame-welcome.bin`):

```
a4 00 00 00 03 00 00 00 00 00 00 00   header: length 164, type 0x03, flags 0, reserved 0, request id 0
89 a8 70 72 6f 74 6f 63 6f 6c a3 31 2e 30 a4 75
73 65 72 a5 61 6c 69 63 65 ab 70 65 72 6d 69 73
73 69 6f 6e 73 92 a4 72 65 61 64 a5 74 72 61 69
6e a5 70 72 6f 6f 66 c4 20 79 36 18 65 56 d3 1d
80 b5 ab 85 ff 88 e0 04 db 85 e9 b0 69 e6 f2 e8
91 9d 44 be 94 1e a4 b7 e8 a7 73 65 73 73 69 6f
6e a2 63 31 a9 6d 61 78 5f 66 72 61 6d 65 ce 00
40 00 00 ad 6d 61 78 5f 66 72 61 6d 65 5f 6f 75
74 ce 00 40 00 00 ac 6d 61 78 5f 69 6e 66 6c 69
67 68 74 08 ac 69 64 6c 65 5f 74 69 6d 65 6f 75
74 cd 01 2c
```

The request `{"op": "health"}` with id 1 and its answer:

```
0b 00 00 00 10 00 00 00 01 00 00 00   header: length 11, type 0x10, flags 0, reserved 0, request id 1
81 a2 6f 70 a6 68 65 61 6c 74 68

18 00 00 00 11 00 00 00 01 00 00 00   header: length 24, type 0x11, flags 0, reserved 0, request id 1
82 a6 73 74 61 74 75 73 a2 6f 6b a8 70 72 6f 74
6f 63 6f 6c a3 31 2e 30
```
