"""
From-scratch checker for the Delegation Record chain validation rules of
ODIS (cosai-oasis/ws4-odis RFCs/ODIS.md), section 6.3 and ODIS-L2-06.

Normative sentences implemented (quoted in fixtures):
  6.3  A verifier MUST resolve and digest-match every parent_delegation_ref
       ... and verify monotonic attenuation at every hop. A missing,
       unavailable, ambiguous, stale, revoked, or mismatched record MUST cause
       chain validation to fail closed.
  6.3  For a non-root record, the current granted_authorizations,
       resource_indicators, constraints, and expires_at MUST be equal to or
       narrower than the immediate parent under attenuation_profile_ref. An
       unresolved, ambiguous, cyclic, lossy, or indeterminate parent comparison
       MUST fail closed.
  6.3  expires_at <= parent.expires_at
  L2-06 Unknown, lossy, unsupported, or indeterminate comparisons MUST fail closed.

Timestamps: ODIS.md gives expires_at the type "timestamp" and does not fix a
serialization. The lab projection fixes it as RFC 3339 (section 5.6), parsed
with a section 5.6 syntax plus 5.7 range parser and compared as ordering keys (leap-second occurrence not validated).

Not implemented: issuer authentication, freshness, revocation state, root
originating_authorization_ref validation, carrier integrity protection. ODIS
leaves the carrier and the digest algorithm for record_digest to the
deployment; this checker uses SHA-256 over RFC 8785 JCS of the parent record
as a stand-in and says so in README.md.

JCS here covers objects, arrays, strings, integers, booleans and null only.
"""
import hashlib
from rfc3339 import parse_rfc3339  # lab projection: RFC 3339 5.6 syntax + 5.7 range, ordering key


# ---------------------------------------------------------------- JCS (subset)

def _s(x):
    out = ['"']
    for ch in x:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == '\\': out.append('\\\\')
        elif ch == '\n': out.append('\\n')
        elif ch == '\r': out.append('\\r')
        elif ch == '\t': out.append('\\t')
        elif ch == '\b': out.append('\\b')
        elif ch == '\f': out.append('\\f')
        elif o < 0x20: out.append('\\u%04x' % o)
        else: out.append(ch)
    out.append('"'); return ''.join(out)


def jcs(v) -> bytes:
    def ser(x):
        if x is None: return 'null'
        if x is True: return 'true'
        if x is False: return 'false'
        if isinstance(x, int): return str(x)
        if isinstance(x, float): raise ValueError('floats outside fixture domain')
        if isinstance(x, str): return _s(x)
        if isinstance(x, list): return '[' + ','.join(ser(i) for i in x) + ']'
        if isinstance(x, dict):
            return '{' + ','.join(_s(k) + ':' + ser(x[k]) for k in sorted(x, key=lambda k: k.encode('utf-16-be'))) + '}'
        raise TypeError(type(x))
    return ser(v).encode()


def record_digest(rec: dict) -> str:
    return 'sha256:' + hashlib.sha256(jcs(rec)).hexdigest()


OAR_REQUIRED = ('issuer', 'subject', 'audience', 'grant_id', 'issued_at', 'expires_at')

# ---------------------------------------------------------------- profiles

# The fixture attenuation profile. Pinned by URI + digest of its definition.
# Semantics: granted_authorizations and resource_indicators are string sets
# compared by set inclusion; constraints is an object whose integer members
# are compared child <= parent per member, and a member present in the parent
# must be present in the child (dropping a constraint widens).
LAB_PROFILE = {
    'uri': 'urn:lab:attenuation-profile:set-subset:v1',
    'rules': {
        'granted_authorizations': 'string set, child subset-or-equal of parent',
        'resource_indicators': 'string set, child subset-or-equal of parent',
        'constraints': 'object; each integer member child <= parent; parent members must be present in child',
    },
}
LAB_PROFILE_DIGEST = record_digest(LAB_PROFILE)
KNOWN_PROFILES = {(LAB_PROFILE['uri'], LAB_PROFILE_DIGEST): LAB_PROFILE}


def narrower_under_lab_profile(child: dict, parent: dict):
    """Returns (ok, reason). 'indeterminate' when a comparison cannot be made."""
    for f in ('granted_authorizations', 'resource_indicators'):
        c, p = child.get(f), parent.get(f)
        if not (isinstance(c, list) and isinstance(p, list)) or not all(isinstance(i, str) for i in c + p):
            return False, f'indeterminate: {f} is not a string set'
        if not set(c) <= set(p):
            return False, f'{f} is not a subset of parent'
    c, p = child.get('constraints'), parent.get('constraints')
    if not (isinstance(c, dict) and isinstance(p, dict)):
        return False, 'indeterminate: constraints not objects'
    for k, pv in p.items():
        if k not in c:
            return False, f'constraint {k} dropped in child (widening)'
        cv = c[k]
        # JSON number vs JSON boolean are distinct types; Python bool is an int
        # subclass, so isinstance(x, int) would accept true/false here.
        if not (type(cv) is int and type(pv) is int):
            return False, f'indeterminate: constraint {k} not comparable'
        if cv > pv:
            return False, f'constraint {k} looser than parent'
    return True, 'ok'


# ---------------------------------------------------------------- 6.3

def validate_non_root(child: dict, parents: list) -> dict:
    """Validate one non-root Delegation Record against the supplied parent set.
    Result: {'result': 'pass'|'fail_closed', 'reason': ..., 'check': ...}."""
    ref = child.get('parent_delegation_ref')
    if not isinstance(ref, dict):
        return _fc('6.3: non-root record without parent_delegation_ref', 'parent_ref')
    oar = child.get('originating_authorization_ref')
    if not (isinstance(oar, dict) and all(k in oar for k in OAR_REQUIRED)):
        return _fc('6.3: originating_authorization_ref MUST be an object carrying issuer, subject, audience, grant identifier or digest, issued_at, expires_at', 'record_shape')
    matches = [p for p in parents
               if p.get('issuer') == ref.get('issuer') and p.get('delegation_id') == ref.get('delegation_id')]
    if len(matches) != 1:
        return _fc('6.3: parent missing or ambiguous on resolution', 'parent_resolution')
    parent = matches[0]
    if record_digest(parent) != ref.get('record_digest'):
        return _fc('6.3: parent_delegation_ref.record_digest does not match resolved parent (mismatched record)', 'parent_digest')
    # expiry containment
    ce, pe = parse_rfc3339(child.get('expires_at')), parse_rfc3339(parent.get('expires_at'))
    if ce is None or pe is None:
        return _fc('6.3: expires_at not a valid timestamp; comparison indeterminate', 'expiry')
    if ce > pe:
        return _fc('6.3: expires_at exceeds parent.expires_at (child delegations cannot outlive parents)', 'expiry')
    # attenuation profile
    apr = child.get('attenuation_profile_ref')
    if not isinstance(apr, dict):
        return _fc('L2-06: attenuation_profile_ref absent (unsupported comparison)', 'profile')
    prof = KNOWN_PROFILES.get((apr.get('uri'), apr.get('digest')))
    if prof is None:
        return _fc('L2-06: attenuation_profile_ref unknown or unsupported by this verifier; comparison indeterminate', 'profile')
    ok, why = narrower_under_lab_profile(child, parent)
    if not ok:
        return _fc('6.3 / L2-06: ' + why, 'attenuation')
    return {'result': 'pass', 'reason': 'equal to or narrower than parent under attenuation_profile_ref', 'check': None}


def _fc(reason, check):
    return {'result': 'fail_closed', 'reason': reason, 'check': check}
