"""
Minimal from-scratch implementation of the parts of
draft-sharif-agent-audit-trail-03 that the fixtures exercise:

  6.1  prev_hash(N) = hex(SHA-256(JCS(record(N-1))))  over the COMPLETE stored
       previous record, including its signature field when present.
  6.2  signature = ECDSA P-256 over SHA-256(JCS(record without "signature")),
       IEEE P1363 r||s, base64url (RFC 4648 s5).
  6.3  chain verification steps 1, 2, 3, 4, 5, 6.
  4.2  decision+denied and decision+escalated MUST be pre_execution;
       delegation+denied MUST be pre_execution.

JCS (RFC 8785) is implemented here for the value domain the fixtures use:
objects, arrays, strings, integers, booleans and null. No floating point
values appear in any fixture, so the RFC 8785 number-serialization rules for
non-integers are deliberately not implemented. Strings are escaped per
RFC 8785 section 3.2.2.2. Object members are sorted by UTF-16 code units.

The ECDSA primitive comes from the `cryptography` package, with RFC 6979
deterministic signing so regeneration is byte-reproducible. No JCS library and
no code from any AAT implementation is used.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------- JCS

def _jcs_str(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_key(s: str):
    return s.encode('utf-16-be')


def jcs(value) -> bytes:
    def ser(v):
        if v is None:
            return 'null'
        if v is True:
            return 'true'
        if v is False:
            return 'false'
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            raise ValueError('floating point values are outside this fixture domain')
        if isinstance(v, str):
            return _jcs_str(v)
        if isinstance(v, list):
            return '[' + ','.join(ser(x) for x in v) + ']'
        if isinstance(v, dict):
            items = sorted(v.items(), key=lambda kv: _utf16_key(kv[0]))
            return '{' + ','.join(_jcs_str(k) + ':' + ser(x) for k, x in items) + '}'
        raise TypeError(type(v))
    return ser(value).encode('utf-8')


# ---------------------------------------------------------------- RFC 3339

from rfc3339 import parse_rfc3339  # RFC 3339 5.6 syntax + 5.7 range parser, returns an ordering key (3.1 timestamp)


_B64URL_64BYTES = __import__('re').compile(r'[A-Za-z0-9_-]{86}==')


# ---------------------------------------------------------------- 6.1 / 6.2

def record_hash_hex(record: dict) -> str:
    """6.1: hex(SHA-256(JCS(record))) over the complete record as stored."""
    return hashlib.sha256(jcs(record)).hexdigest()


def signing_preimage(record: dict) -> bytes:
    """6.2 step 1-2: the record with the signature member absent, JCS."""
    r = {k: v for k, v in record.items() if k != 'signature'}
    return jcs(r)


def sign_record(record: dict, private_key: ec.EllipticCurvePrivateKey,
                          preimage_override: bytes = None) -> str:
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    pre = preimage_override if preimage_override is not None else signing_preimage(record)
    digest = hashlib.sha256(pre).digest()
    der = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True))  # RFC 6979
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    # Lab interpretation: RFC 4648 section 5 base64url WITH padding, the RFC 4648
    # default. The draft cites section 5 and fixes the input at 64 bytes but does
    # not say "unpadded". See SCOPE.md.
    return base64.urlsafe_b64encode(raw).decode('ascii')


def verify_signature(record: dict, public_key: ec.EllipticCurvePublicKey) -> bool:
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    sig = record.get('signature')
    if not isinstance(sig, str):
        return False
    # Strict base64url per RFC 4648 section 5: URL-safe alphabet only, and the
    # padded canonical form for 64 input bytes is exactly 86 chars + "==".
    # Non-alphabet characters (including "+" and "/") are rejected.
    if not _B64URL_64BYTES.fullmatch(sig):
        return False
    raw = base64.urlsafe_b64decode(sig)
    if len(raw) != 64:
        return False
    # Canonical spelling only: the last character of the 86 encodes 4 data bits
    # plus 2 pad bits that MUST be zero. Reject aliases that decode to the same
    # bytes with non-zero pad bits by requiring decode -> re-encode identity.
    if base64.urlsafe_b64encode(raw).decode('ascii') != sig:
        return False
    r = int.from_bytes(raw[:32], 'big')
    s = int.from_bytes(raw[32:], 'big')
    digest = hashlib.sha256(signing_preimage(record)).digest()
    try:
        public_key.verify(encode_dss_signature(r, s), digest,
                          ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------- 4.2

PHASE_RULES = {
    ('decision', 'denied'): 'pre_execution',
    ('decision', 'escalated'): 'pre_execution',
    ('delegation', 'denied'): 'pre_execution',
}


def phase_violation(record: dict):
    want = PHASE_RULES.get((record.get('action_type'), record.get('outcome')))
    if want and record.get('record_phase') != want:
        return f"4.2: {record['action_type']}+{record['outcome']} requires record_phase={want}, got {record.get('record_phase')}"
    return None


# ---------------------------------------------------------------- 6.3

def verify_chain(records: list, public_key=None) -> dict:
    """Returns a structured report. Steps numbered as in 6.3."""
    findings = []
    ok = True
    if not records:
        return {'ok': False, 'findings': ['empty session']}
    g = records[0]
    if g.get('parent_record_id') is not None or g.get('prev_hash') is not None:
        ok = False
        findings.append('6.3 step 1: genesis parent_record_id and prev_hash must be null')
    for n in range(1, len(records)):
        prev, cur = records[n - 1], records[n]
        expected = record_hash_hex(prev)
        if cur.get('prev_hash') != expected:
            ok = False
            findings.append(f'6.3 step 2c: chain is broken at record {n} (prev_hash mismatch); trail MUST be flagged as tampered')
        if cur.get('parent_record_id') != prev.get('record_id'):
            ok = False
            findings.append(f'6.3 step 5: parent_record_id of record {n} != record_id of record {n-1}')
        tp, tc = parse_rfc3339(prev.get('timestamp')), parse_rfc3339(cur.get('timestamp'))
        if tp is None or tc is None:
            ok = False
            findings.append(f'3.1: timestamp on record {n-1 if tp is None else n} is not a valid RFC 3339 timestamp with UTC offset')
        elif tc < tp:
            ok = False
            findings.append(f'6.3 step 4: timestamp regression at record {n} (instants compared, not strings)')
    for n, rec in enumerate(records):
        if 'signature' in rec:
            if public_key is None:
                ok = False
                findings.append(f'6.3 step 3: record {n} carries a signature but no key was supplied')
            elif not verify_signature(rec, public_key):
                ok = False
                findings.append(f'6.3 step 3: signature on record {n} does not verify')
        pv = phase_violation(rec)
        if pv:
            ok = False
            findings.append(f'6.3 step 6 / record {n}: {pv}')
    return {'ok': ok, 'findings': findings}
