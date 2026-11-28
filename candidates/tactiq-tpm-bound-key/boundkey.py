"""Helpers for the bound-key presentation vectors (TQB-07 to TQB-16).

The evidence is a TPM2_Certify of a P-256 signing key by the registered AK over
a verifier's challenge, and a DPoP proof (RFC 9449) signed by that key over a
second challenge. Pure Python plus `cryptography`. No network, no TPM.
"""
import base64, hashlib, json, struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)
from cryptography.exceptions import InvalidSignature

import tpmq

TPM_ST_ATTEST_CERTIFY = 0x8017
SENSITIVE_DATA_ORIGIN = 1 << 5


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def ub64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def parse_certify(m: bytes):
    """TPMS_ATTEST of type certify: returns dict of the fields used here."""
    magic, typ = struct.unpack('>IH', m[0:6])
    o = 6
    o += 2 + struct.unpack('>H', m[o:o + 2])[0]                   # qualifiedSigner
    n = struct.unpack('>H', m[o:o + 2])[0]
    extra_off = o + 2
    extra = m[o + 2:o + 2 + n]; o += 2 + n
    o += 17 + 8                                                   # clockInfo, firmwareVersion
    n = struct.unpack('>H', m[o:o + 2])[0]
    name_off = o + 2
    name = m[o + 2:o + 2 + n]; o += 2 + n
    o += 2 + struct.unpack('>H', m[o:o + 2])[0]                   # qualifiedName
    if o != len(m):
        raise ValueError('trailing bytes in TPMS_ATTEST')
    return {'magic': magic, 'type': typ, 'extra': extra, 'extra_off': extra_off,
            'name': name, 'name_off': name_off}


def jwk_of(pub: bytes) -> dict:
    _, x, y, _ = tpmq.parse_public(pub)
    return {'crv': 'P-256', 'kty': 'EC', 'x': b64u(x), 'y': b64u(y)}


def jwk_of_key(sk) -> dict:
    n = sk.public_key().public_numbers()
    return {'crv': 'P-256', 'kty': 'EC',
            'x': b64u(n.x.to_bytes(32, 'big')), 'y': b64u(n.y.to_bytes(32, 'big'))}


def ec_thumbprint(jwk: dict) -> bytes:
    """RFC 7638 thumbprint of a P-256 JWK: what a grant carries as cnf.jkt."""
    canon = json.dumps({k: jwk[k] for k in ('crv', 'kty', 'x', 'y')},
                       separators=(',', ':'), sort_keys=True).encode()
    return hashlib.sha256(canon).digest()


def jws_verify(jwt: str):
    """Verify an ES256 compact JWS under the JWK in its own header.

    Returns (header, payload, signature_ok)."""
    h, p, s = jwt.split('.')
    hdr, pl = json.loads(ub64u(h)), json.loads(ub64u(p))
    jwk = hdr.get('jwk', {})
    raw = ub64u(s)
    ok = False
    if hdr.get('alg') == 'ES256' and len(raw) == 64:
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(ub64u(jwk['x']), 'big'), int.from_bytes(ub64u(jwk['y']), 'big'),
            ec.SECP256R1()).public_key()
        der = encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
        try:
            key.verify(der, f'{h}.{p}'.encode(), ec.ECDSA(hashes.SHA256()))
            ok = True
        except InvalidSignature:
            pass
    return hdr, pl, ok


def jws_sign(sk, header: dict, payload: dict) -> str:
    """Deterministic (RFC 6979) ES256 compact JWS."""
    si = b64u(json.dumps(header, separators=(',', ':')).encode()) + '.' + \
        b64u(json.dumps(payload, separators=(',', ':')).encode())
    r, s = decode_dss_signature(sk.sign(si.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    return si + '.' + b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
