"""Regression: timestamps must be compared as instants, not strings."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import aat

def rec(ts, rid, parent=None):
    r = {'record_id': rid, 'timestamp': ts, 'agent_id': 'urn:agent:t', 'agent_version': '1.0.0',
         'session_id': 's', 'action_type': 'lifecycle', 'action_detail': {'event': 'x'},
         'outcome': 'success', 'trust_level': 'L1', 'record_phase': 'concurrent',
         'parent_record_id': parent['record_id'] if parent else None,
         'prev_hash': aat.record_hash_hex(parent) if parent else None}
    return r

# same instant, different offsets: string order says regression, instant order says equal
a = rec('2026-09-11T20:00:00Z', 'r0')
b = rec('2026-09-11T21:00:00+01:00', 'r1', a)
assert '2026-09-11T21:00:00+01:00' > '2026-09-11T20:00:00Z'  # the string trap
assert not any('step 4' in f for f in aat.verify_chain([a, b])['findings']), 'equal instants flagged'

# later string, earlier instant: must be flagged
c = rec('2026-09-11T20:00:00Z', 'r0')
d = rec('2026-09-11T20:30:00+02:00', 'r1', c)   # 18:30Z, earlier
assert any('step 4' in f for f in aat.verify_chain([c, d])['findings']), 'regression missed'

# missing offset is invalid per 3.1
e = rec('2026-09-11T20:00:00', 'r0')
assert any('3.1' in f for f in aat.verify_chain([e, rec('2026-09-11T20:00:01Z', 'r1', e)])['findings'])
print('test_timestamps: ok')

# ---- RFC 3339 grammar boundary (not merely offset-aware ISO)
from rfc3339 import parse_rfc3339 as P
assert P('2026-09-11t20:00:00z') is not None, 'lowercase t/z is valid RFC 3339'
assert P('2026-09-11T20:00:00+0000') is None, '+0000 is not RFC 3339 time-numoffset'
assert P('2026-09-11T20:00:00+00') is None
assert P('2026-09-11T20:00:00+00:00:30') is None
assert P('2026-09-11T20:00:00') is None, 'offset is mandatory'
assert P('2026-09-11 20:00:00Z') is None, 'space separator is not RFC 3339'
assert P('2026-02-29T00:00:00Z') is None, '2026 is not a leap year'
assert P('2028-02-29T00:00:00Z') is not None
assert P('2026-09-11T23:59:60Z') is not None, 'leap second syntax is valid'
assert P('2026-09-11T23:59:59.999999Z') < P('2026-09-11T23:59:60Z') < P('2026-09-12T00:00:00Z'), 'leap second must be a distinct instant'
assert P('2026-09-11T23:59:60Z') != P('2026-09-12T00:00:00Z')
assert P('2026-09-11T23:59:60.5+00:00') < P('2026-09-12T00:00:00Z')
assert P('2026-09-11T23:59:60+01:00') < P('2026-09-11T23:00:00Z'), 'leap second at +01:00 is 22:59:60Z'
assert P('2026-09-11T20:00:00-00:00') == P('2026-09-11T20:00:00Z'), '-00:00 accepted, ordered as zero offset'
assert P('2026-09-11T20:00:00.123456789Z') is not None, 'secfrac is 1*DIGIT'
assert P('2026-09-11T00:00:00.1234561Z') < P('2026-09-11T00:00:00.1234569Z'), 'precision beyond 6 digits must order'
assert P('2026-09-11T00:00:00.1Z') == P('2026-09-11T00:00:00.100000000Z')
assert P('2026-09-11T00:00:00.999999999Z') < P('2026-09-11T00:00:01Z')
assert P('2026-09-11T20:00:00Z\n') is None, 'trailing newline is not RFC 3339'
assert P('\u0662\u0660\u0662\u0666-09-11T20:00:00Z') is None, 'non-ASCII digits are not DIGIT'
assert P('0000-01-01T00:00:00+23:59') is not None and P('9999-12-31T23:59:59-23:59') is not None, 'full year and offset range'
# the two false results the six-digit truncation produced
g = rec('2026-09-11T00:00:00.1234569Z', 'r0'); h2 = rec('2026-09-11T00:00:00.1234561Z', 'r1', g)
assert any('step 4' in x for x in aat.verify_chain([g, h2])['findings']), 'sub-microsecond regression missed'
# lowercase forms flow through verify_chain
f = rec('2026-09-11t20:00:00z', 'r0')
assert not any('3.1' in x for x in aat.verify_chain([f, rec('2026-09-11T20:00:01Z', 'r1', f)])['findings'])
print('test_timestamps (rfc3339 grammar): ok')

# ---- base64url strictness (6.2 step 5, RFC 4648 section 5)
from cryptography.hazmat.primitives.asymmetric import ec
k = ec.derive_private_key(0x1111111111111111111111111111111111111111111111111111111111111111, ec.SECP256R1())
r0 = rec('2026-09-11T20:00:00Z', 'r0'); r0['signature'] = aat.sign_record(r0, k)
assert aat.verify_signature(r0, k.public_key())
assert r0['signature'].endswith('==') and len(r0['signature']) == 88
bad = dict(r0, signature=r0['signature'].replace('_', '/').replace('-', '+'))
if bad['signature'] != r0['signature']:
    assert not aat.verify_signature(bad, k.public_key()), 'standard-alphabet characters must be rejected'
else:
    # this particular signature had no _ or -; force a non-alphabet character instead
    bad = dict(r0, signature='+' + r0['signature'][1:])
    assert not aat.verify_signature(bad, k.public_key())
assert not aat.verify_signature(dict(r0, signature=r0['signature'].rstrip('=')), k.public_key()), 'unpadded form is not accepted under the lab interpretation'
print('test base64url strictness: ok')
# ---- non-canonical pad bits: same 64 bytes, different last character
alias = r0['signature'][:85] + chr(ord(r0['signature'][85]) + 1) + '=='
import base64 as _b
try:
    same = _b.urlsafe_b64decode(alias) == _b.urlsafe_b64decode(r0['signature'])
except Exception:
    same = False
if same:
    assert not aat.verify_signature(dict(r0, signature=alias), k.public_key()), 'non-canonical pad bits must be rejected'
    print('test canonical pad bits: ok (alias case exercised)')
else:
    print('test canonical pad bits: alias not constructible for this signature; decode->re-encode identity check is in place')
