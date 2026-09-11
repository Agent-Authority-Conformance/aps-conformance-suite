"""Regression: expires_at compared as instants, not strings."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import odis

OAR = {'issuer': 'i', 'subject': 's', 'audience': 'a', 'grant_id': 'g', 'issued_at': '2026-01-01T00:00:00Z', 'expires_at': '2027-01-01T00:00:00Z'}

def parent(exp):
    return {'delegation_id': 'p', 'issuer': 'i', 'originating_authorization_ref': OAR,
            'granted_authorizations': ['a'], 'resource_indicators': ['r'],
            'constraints': {'m': 1}, 'expires_at': exp}

def child(p, exp):
    return {'delegation_id': 'c', 'issuer': 'i', 'originating_authorization_ref': OAR,
            'parent_delegation_ref': {'issuer': 'i', 'delegation_id': 'p', 'record_digest': odis.record_digest(p)},
            'granted_authorizations': ['a'], 'resource_indicators': ['r'], 'constraints': {'m': 1},
            'attenuation_profile_ref': {'uri': odis.LAB_PROFILE['uri'], 'digest': odis.LAB_PROFILE_DIGEST},
            'expires_at': exp}

p = parent('2026-09-11T21:00:00Z')
assert odis.validate_non_root(child(p, '2026-09-11T22:00:00+01:00'), [p])['result'] == 'pass'      # same instant
assert odis.validate_non_root(child(p, '2026-09-11T20:30:00-01:00'), [p])['check'] == 'expiry'    # 21:30Z, later
assert odis.validate_non_root(child(p, '2026-09-11T21:00:00'), [p])['check'] == 'expiry'          # no offset: indeterminate
print('test_timestamps: ok')

from rfc3339 import parse_rfc3339 as P
assert P('2026-09-11t21:00:00z') is not None
assert P('2026-09-11T21:00:00+0000') is None
assert odis.validate_non_root(child(p, '2026-09-11T21:00:00+0000'), [p])['check'] == 'expiry', 'malformed offset must be indeterminate, fail closed'
print('test_timestamps (rfc3339 grammar): ok')
assert P('2026-09-11T23:59:59.999999Z') < P('2026-09-11T23:59:60Z') < P('2026-09-12T00:00:00Z')
# ODIS expiry at the leap-second boundary: child expiring at :60 must not outlive a parent expiring at :59.999999
q = parent('2026-09-11T23:59:59.999999Z')
assert odis.validate_non_root(child(q, '2026-09-11T23:59:60Z'), [q])['check'] == 'expiry'
q2 = parent('2026-09-12T00:00:00Z')
assert odis.validate_non_root(child(q2, '2026-09-11T23:59:60Z'), [q2])['result'] == 'pass'
print('test_timestamps (leap second boundary): ok')

# ---- precision beyond microseconds (the false pass)
q3 = parent('2026-09-11T00:00:00.1234561Z')
assert odis.validate_non_root(child(q3, '2026-09-11T00:00:00.1234569Z'), [q3])['check'] == 'expiry', 'sub-microsecond containment missed'
# ---- booleans are not integers
c = child(p, '2026-09-11T20:00:00Z'); c['constraints'] = {'m': True}
assert odis.validate_non_root(c, [p])['check'] == 'attenuation', 'boolean constraint must be indeterminate'
assert odis.narrower_under_lab_profile({'granted_authorizations': [], 'resource_indicators': [], 'constraints': {'x': True}},
                                       {'granted_authorizations': [], 'resource_indicators': [], 'constraints': {'x': 1}})[0] is False
# ---- record shape: string originating_authorization_ref fails closed before any semantic check
c2 = child(p, '2026-09-11T20:00:00Z'); c2['originating_authorization_ref'] = 'urn:grant:string'
assert odis.validate_non_root(c2, [p])['check'] == 'record_shape'
print('test constraints/shape: ok')
