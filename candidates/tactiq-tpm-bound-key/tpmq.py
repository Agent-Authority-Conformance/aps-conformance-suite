"""Parsing and verification helpers shared by gen.py and run.py.

Pure Python plus the `cryptography` package. No network access, no TPM.
"""
import base64, hashlib, json, struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)
from cryptography.exceptions import InvalidSignature

TPM_GENERATED = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
# TPMA_OBJECT bits
FIXED_TPM, FIXED_PARENT, RESTRICTED, SIGN = 1 << 1, 1 << 4, 1 << 16, 1 << 18


def thumbprint(x: bytes) -> bytes:
    """RFC 7638 thumbprint of an Ed25519 public key (OKP JWK)."""
    xb = base64.urlsafe_b64encode(x).rstrip(b'=').decode()
    jwk = json.dumps({'crv': 'Ed25519', 'kty': 'OKP', 'x': xb},
                     separators=(',', ':'), sort_keys=True).encode()
    return hashlib.sha256(jwk).digest()


def ed25519_x(seed_label: str) -> bytes:
    """Deterministic Ed25519 public key from a published label."""
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(seed_label.encode()).digest())
    return sk.public_key().public_bytes_raw()


def parse_public(b: bytes):
    """TPM2B_PUBLIC for an ECC P-256 key: returns (attributes, x, y, area)."""
    size = struct.unpack('>H', b[0:2])[0]
    area = b[2:2 + size]
    if len(area) != size or len(b) != size + 2:
        raise ValueError('TPM2B_PUBLIC size field does not match the file')
    typ, name_alg, attrs = struct.unpack('>HHI', area[0:8])
    if typ != 0x0023 or name_alg != 0x000B:
        raise ValueError('not an ECC key with SHA-256 name algorithm')
    o = 8
    o += 2 + struct.unpack('>H', area[o:o + 2])[0]          # authPolicy
    sym = struct.unpack('>H', area[o:o + 2])[0]; o += 2      # symmetric
    if sym != 0x0010:
        raise ValueError('symmetric not TPM_ALG_NULL')
    scheme = struct.unpack('>H', area[o:o + 2])[0]; o += 2
    if scheme != 0x0010:
        o += 2                                               # scheme hash
    curve, kdf = struct.unpack('>HH', area[o:o + 4]); o += 4
    if curve != 0x0003:
        raise ValueError('curve is not NIST P-256')
    if kdf != 0x0010:
        o += 2
    n = struct.unpack('>H', area[o:o + 2])[0]; x = area[o + 2:o + 2 + n]; o += 2 + n
    n = struct.unpack('>H', area[o:o + 2])[0]; y = area[o + 2:o + 2 + n]; o += 2 + n
    if o != len(area):
        raise ValueError('trailing bytes in the public area')
    return attrs, x, y, area


def name(pub: bytes) -> bytes:
    """TPM object name: nameAlg (SHA-256) || SHA-256(public area)."""
    _, _, _, area = parse_public(pub)
    return b'\x00\x0b' + hashlib.sha256(area).digest()


def parse_attest(m: bytes):
    """TPMS_ATTEST of type quote: returns dict of the fields used here."""
    magic, typ = struct.unpack('>IH', m[0:6])
    o = 6
    o += 2 + struct.unpack('>H', m[o:o + 2])[0]              # qualifiedSigner
    n = struct.unpack('>H', m[o:o + 2])[0]
    extra_off = o + 2; extra = m[o + 2:o + 2 + n]; o += 2 + n
    clock, reset, restart, safe = struct.unpack('>QIIB', m[o:o + 17]); o += 17
    o += 8                                                   # firmwareVersion
    cnt = struct.unpack('>I', m[o:o + 4])[0]; o += 4; sel = []
    for _ in range(cnt):
        alg, sz = struct.unpack('>HB', m[o:o + 3]); o += 3
        bits = m[o:o + sz]; o += sz
        if alg != 0x000B:
            raise ValueError('PCR bank is not SHA-256')
        sel += [i * 8 + j for i in range(sz) for j in range(8) if bits[i] >> j & 1]
    dlen = struct.unpack('>H', m[o:o + 2])[0]
    digest = m[o + 2:o + 2 + dlen]
    if o + 2 + dlen != len(m):
        raise ValueError('trailing bytes after pcrDigest')
    return {'magic': magic, 'type': typ, 'extra': extra, 'extra_off': extra_off,
            'reset': reset, 'clock': clock, 'sel': sel, 'pcr_digest': digest}


def parse_pcr(b: bytes, sel):
    """tpm2_quote -f values file (TPML_PCR_SELECTION + TPML_DIGEST lists).

    Returns {pcr: value}. Values are taken in selection order.
    """
    lists = struct.unpack('<I', b[132:136])[0]
    if len(b) != 136 + 532 * lists:
        raise ValueError('pcr file length does not match its digest lists')
    vals = []
    for i in range(lists):
        o = 136 + 532 * i
        n = struct.unpack('<I', b[o:o + 4])[0]
        for k in range(n):
            q = o + 4 + 66 * k
            size = struct.unpack('<H', b[q:q + 2])[0]
            vals.append(b[q + 2:q + 2 + size])
    if len(vals) != len(sel):
        raise ValueError('number of values differs from the signed selection')
    return dict(zip(sel, vals))


def write_pcr(template: bytes, sel, values) -> bytes:
    """Rewrite the values in a pcr file, keeping its layout."""
    b = bytearray(template)
    lists = struct.unpack('<I', b[132:136])[0]
    it = iter(values[i] for i in sel)
    for i in range(lists):
        o = 136 + 532 * i
        n = struct.unpack('<I', b[o:o + 4])[0]
        for k in range(n):
            q = o + 4 + 66 * k
            v = next(it)
            b[q:q + 2] = struct.pack('<H', len(v)); b[q + 2:q + 2 + len(v)] = v
    return bytes(b)


def verify_sig(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """TPMT_SIGNATURE ECDSA/SHA-256 over msg under a TPM2B_PUBLIC P-256 key."""
    alg, h = struct.unpack('>HH', sig[0:4])
    if alg != 0x0018 or h != 0x000B:
        return False
    o = 4
    n = struct.unpack('>H', sig[o:o + 2])[0]; r = sig[o + 2:o + 2 + n]; o += 2 + n
    n = struct.unpack('>H', sig[o:o + 2])[0]; s = sig[o + 2:o + 2 + n]; o += 2 + n
    if o != len(sig):
        return False
    _, x, y, _ = parse_public(pub)
    key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, 'big'), int.from_bytes(y, 'big'), ec.SECP256R1()).public_key()
    der = encode_dss_signature(int.from_bytes(r, 'big'), int.from_bytes(s, 'big'))
    try:
        key.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def p256_key(seed_label: str):
    d = int.from_bytes(hashlib.sha256(seed_label.encode()).digest(), 'big')
    d = d % (0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


def sign_tpmt(sk, msg: bytes) -> bytes:
    """Deterministic (RFC 6979) ECDSA/SHA-256 as a TPMT_SIGNATURE."""
    der = sk.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    rb, sb = r.to_bytes(32, 'big'), s.to_bytes(32, 'big')
    return struct.pack('>HHH', 0x0018, 0x000B, 32) + rb + struct.pack('>H', 32) + sb


def public_with_key(template: bytes, sk) -> bytes:
    """Copy of a TPM2B_PUBLIC with the point replaced by sk's public key."""
    _, x, y, area = parse_public(template)
    nums = sk.public_key().public_numbers()
    nx, ny = nums.x.to_bytes(32, 'big'), nums.y.to_bytes(32, 'big')
    tail = struct.pack('>H', 32) + x + struct.pack('>H', 32) + y
    assert area.endswith(tail)
    new = area[:-len(tail)] + struct.pack('>H', 32) + nx + struct.pack('>H', 32) + ny
    return struct.pack('>H', len(new)) + new
