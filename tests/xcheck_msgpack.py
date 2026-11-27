"""The shared test vectors (PROTOCOL.md section 17), checked by another
implementation than the one that wrote them: msgpack-python decodes every
valid value to the described value and re-encodes the canonical ones to the
same bytes; Python's hashlib and hmac give auth.json's key, key id and
proofs. CI runs it (pip install msgpack):

    python tests/xcheck_msgpack.py tests/vectors"""
import hashlib, hmac, json, struct, sys

import msgpack

d = sys.argv[1]
ix = json.load(open(d + '/index.json', encoding='utf-8'))


def from_typed(t):
    if t is None or isinstance(t, bool) or isinstance(t, str):
        return t
    if isinstance(t, list):
        return [from_typed(x) for x in t]
    if 'int' in t:
        return int(t['int'])
    if 'float' in t:
        return struct.unpack('>d', bytes.fromhex(t['bits']))[0]
    if 'float32' in t:
        return struct.unpack('>f', bytes.fromhex(t['bits']))[0]
    if 'bin' in t:
        return bytes.fromhex(t['bin'])
    if 'map' in t:
        return {k: from_typed(v) for k, v in t['map']}
    raise ValueError(t)


def same(a, b):
    if isinstance(a, float) and isinstance(b, float):
        return struct.pack('>d', a) == struct.pack('>d', b) or (a != a and b != b)
    if type(a) != type(b):
        return False
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        return list(a) == list(b) and all(same(a[k], b[k]) for k in a)
    return a == b


ok = bad = 0
for v in ix['vectors']:
    name, group = v['name'], v['group']
    if group not in ('value', 'payload', 'frame'):
        continue
    desc = json.load(open(f'{d}/{name}.json', encoding='utf-8'))
    raw = open(f'{d}/{name}.bin', 'rb').read()
    if group == 'frame':
        if 'payload' not in desc:
            continue
        length, typ, flags, res, rid = struct.unpack('<IBBHI', raw[:12])
        assert (length, typ, flags, rid) == (desc['length'], desc['type'], desc['flags'], desc['id']), name
        body = raw[12:]
        if 'prefix' in desc:
            assert body[:8] == b'NMZP\r\n\x1a\n', name
            body = body[12:]
        want, canonical = desc['payload'], True
    else:
        body, want, canonical = raw, desc['value'], desc.get('canonical', True)
    got = msgpack.unpackb(body, raw=False, strict_map_key=True, use_list=True)
    if not same(got, from_typed(want)):
        print('DIFF', name)
        bad += 1
        continue
    if canonical and not any(isinstance(x, float) and x != x for x in [got]):
        again = msgpack.packb(got, use_bin_type=True)
        if again != body:
            print('NOT CANONICAL for msgpack-python', name)
            bad += 1
            continue
    ok += 1
a = json.load(open(d + '/auth.json', encoding='utf-8'))
K = hashlib.sha256(a['token'].encode()).digest()
ns, nc = bytes.fromhex(a['Ns']), bytes.fromhex(a['Nc'])
checks = [K.hex() == a['K'],
          hmac.new(K, b'neuromz key id', hashlib.sha256).digest()[:8].hex() == a['key_id'],
          hmac.new(K, b'neuromz client proof' + ns + nc, hashlib.sha256).hexdigest() == a['proof_c'],
          hmac.new(K, b'neuromz server proof' + ns + nc, hashlib.sha256).hexdigest() == a['proof_s']]
checks += [hmac.new(bytes.fromhex(c['key']), bytes.fromhex(c['data']), hashlib.sha256).hexdigest() == c['mac']
           for c in a['hmac_sha256_rfc4231']]
if not all(checks):
    print('auth.json differs from hashlib/hmac')
    bad += 1
print(ok, 'vectors agree with msgpack-python,', len(checks), 'auth checks with hashlib/hmac,', bad, 'differ')
sys.exit(1 if bad else 0)
