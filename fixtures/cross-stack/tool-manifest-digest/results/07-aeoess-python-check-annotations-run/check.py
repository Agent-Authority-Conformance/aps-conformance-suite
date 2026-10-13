# aeoess Python check of AgentAvow tool-manifest-digest-v1-annotations (3fbda96f). Author-produced.
# Written from the packet's prose (axes, derivation), not from its verify.mjs.
# Usage: python3 -I check.py <vectors.json> <source.json> [live_tools.json]
import base64, hashlib, json, sys
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

vec_path, src_path = sys.argv[1], sys.argv[2]
live_path = sys.argv[3] if len(sys.argv) > 3 else None
S = json.load(open(vec_path, encoding='utf-8'))
SRC = json.load(open(src_path, encoding='utf-8'))
fails = 0

def ok(label, got, want):
    global fails
    good = got == want
    if not good: fails += 1
    print(('  ok    ' if good else '  FAIL  ') + label + ('' if good else f'  got={got!r} want={want!r}'))

def no_floats(o):
    if isinstance(o, float): raise ValueError('float present, this JCS does not format floats')
    if isinstance(o, dict): [no_floats(v) for v in o.values()]
    if isinstance(o, list): [no_floats(v) for v in o]

def jcs(o):
    # RFC 8785 for data without floats. Keys sorted by UTF-16 code units.
    if isinstance(o, dict):
        ks = sorted(o.keys(), key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + jcs(o[k]) for k in ks) + '}'
    if isinstance(o, list):
        return '[' + ','.join(jcs(v) for v in o) + ']'
    return json.dumps(o, ensure_ascii=False)

def b64d(x): return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))

FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations']
def tool_digest(t):
    body = {f: t[f] for f in FIELDS if f in t and t[f] is not None}
    no_floats(body)
    return 'sha256:' + hashlib.sha256(jcs({'profile': 'agentavow.mcp-tool-definition.v1', 'tool': body}).encode('utf-8')).hexdigest()

def instant(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00'))

print('provenance')
ok('source.json jws equals vectors attestation jws', SRC['jws'], S['attestation']['jws'])
ok('source.json observed_tools equals vectors observed_tools', jcs(SRC['observed_tools']), jcs(S['observed_tools']))
ok('source.json jwk equals vectors issuer jwk', jcs(SRC['jwk']), jcs(S['issuer']['jwk']))

jws = S['attestation']['jws']
h64, p64, s64 = jws.split('.')
hdr = json.loads(b64d(h64))
payload_bytes = b64d(p64)
P = json.loads(payload_bytes)
jwk = S['issuer']['jwk']
ok('header alg EdDSA', hdr.get('alg'), 'EdDSA')
ok('header kid matches pinned jwk', hdr.get('kid'), jwk['kid'])
ok('payload_sha256 field matches payload bytes', S['attestation'].get('payload_sha256', '').removeprefix('sha256:'), hashlib.sha256(payload_bytes).hexdigest())

print('\nper-tool digests from the served definitions')
signed = P['scan']['toolDigests']
for t in S['observed_tools']:
    ok(f'tool:{t["name"]}', tool_digest(t), signed.get('tool:' + t['name']))
ok('served tool count equals signed tool count', len(S['observed_tools']), len(signed))

print('\nannotation-only drift')
dd = S['drift_definition']
base = next(t for t in S['observed_tools'] if t['name'] == dd['name'])
ok('baseline readOnlyHint is true', base.get('annotations', {}).get('readOnlyHint'), True)
ok('drift readOnlyHint is false', dd.get('annotations', {}).get('readOnlyHint'), False)
diffs = []
for k in sorted(set(base) | set(dd)):
    if k == 'annotations':
        ba, da = base.get(k, {}), dd.get(k, {})
        for ak in sorted(set(ba) | set(da)):
            if jcs(ba.get(ak)) != jcs(da.get(ak)): diffs.append('annotations.' + ak)
    elif jcs(base.get(k)) != jcs(dd.get(k)):
        diffs.append(k)
ok('only differing field', diffs, ['annotations.readOnlyHint'])
ok('annotations key set unchanged', sorted(base.get('annotations', {})), sorted(dd.get('annotations', {})))
ok('drift digest differs from baseline digest', tool_digest(dd) != tool_digest(base), True)

pub = ed25519.Ed25519PublicKey.from_public_bytes(b64d(jwk['x']))

def axes(gate, token):
    a = {}
    hh, pp, ss = token.split('.')
    try:
        pub.verify(b64d(ss), (hh + '.' + pp).encode('ascii'))
        a['signature_valid'] = json.loads(b64d(hh)).get('kid') == jwk['kid']
    except InvalidSignature:
        a['signature_valid'] = False
    pb = b64d(pp)
    pl = json.loads(pb)
    no_floats(pl)
    a['canonical_bytes'] = jcs(pl).encode('utf-8') == pb
    a['subject_binds'] = pl['subject']['id'] == gate['subject_id']
    key = 'tool:' + gate['tool_name']  # names here are plain ASCII, v1 encoding is identity
    assert all(0x21 <= ord(c) <= 0x7E and c not in '%=' for c in gate['tool_name'])
    td = pl['scan']['toolDigests']
    a['tool_binds'] = key in td
    a['tool_digest_binds'] = (td[key] == gate['observed_tool_digest']) if a['tool_binds'] else 'not_evaluated'
    t = instant(gate['evaluation_time'])
    a['fresh'] = instant(pl['issuedAt']) <= t < instant(pl['expiresAt'])
    a['rely'] = all(a[k] is True for k in ['signature_valid', 'canonical_bytes', 'subject_binds', 'tool_binds', 'tool_digest_binds', 'fresh'])
    return a

AX = ['signature_valid', 'canonical_bytes', 'subject_binds', 'tool_binds', 'tool_digest_binds', 'fresh', 'rely']
print('\nvectors (axes recomputed, compared to expectation)')
for v in S['vectors']:
    token = jws if v['jws'] == 'reference' else v['jws']
    got = axes(v['gate'], token)
    for k in AX:
        ok(f'{v["name"]}: {k}', got[k], v['expect'][k])

print('\ngate digests and case shape')
by = {v['name']: v for v in S['vectors']}
ok('annotation-match gate digest is the baseline digest', by['annotation-match']['gate']['observed_tool_digest'], tool_digest(base))
ok('annotation-drift gate digest is the drift_definition digest', by['annotation-drift']['gate']['observed_tool_digest'], tool_digest(dd))
ok('unknown-tool name absent from served tools', by['unknown-tool']['gate']['tool_name'] in [t['name'] for t in S['observed_tools']], False)
for n in ['annotation-drift', 'unknown-tool', 'wrong-subject', 'past-expiry', 'tampered-payload']:
    e = by[n]['expect']
    ok(f'{n} fails exactly one axis', len([k for k in AX[:-1] if e[k] is False]), 1)

if live_path:
    print('\nlive tools/list fetched now (later drift is not a packet defect)')
    L = json.load(open(live_path, encoding='utf-8'))
    tools = L['result']['tools'] if 'result' in L else L
    for t in S['observed_tools']:
        lt = next((x for x in tools if x['name'] == t['name']), None)
        ok(f'live {t["name"]} digest equals pinned', lt and tool_digest(lt), tool_digest(t))

print('\nresult:', 'all checks passed' if fails == 0 else f'{fails} failed')
sys.exit(1 if fails else 0)
