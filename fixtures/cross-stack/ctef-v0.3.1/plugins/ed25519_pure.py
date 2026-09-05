"""Pure-Python Ed25519 verification, stdlib-only, Wycheproof-hardened.

Verification-only. Based on the public-domain reference at ed25519.cr.yp.to
(djb et al.), with the three decoding/verification constraints RFC 8032 requires
that the bare reference omits, so it rejects the Wycheproof invalid classes:

  1. Canonical point encoding: a decoded point must re-encode to the exact input
     bytes (rejects y >= p and the non-canonical identity/sign-bit encodings).
  2. Scalar range: S must satisfy 0 <= S < L (rejects the S, S+L, S+2L, S+4L,
     S+8L malleability family and S above the group order).
  3. y < p is implied by (1).

No third-party crypto dependency, so a conformance runner reproduces the check
with python3 alone. Slow by design; fine for one-shot conformance checking.
"""
from __future__ import annotations

import hashlib

b = 256
q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


d = (-121665 * _inv(121666)) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = (4 * _inv(5)) % q
Bx = _xrecover(By)
B = [Bx % q, By % q]


def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(0, b))


def _encodepoint(P) -> bytes:
    x, y = P
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(0, b - 1))
    if y >= q:                       # non-canonical y: reject (RFC 8032 §5.1.3)
        raise ValueError("non-canonical y")
    x = _xrecover(y)
    if x & 1 != _bit(s, b - 1):
        x = (q - x) % q          # reduce so x=0 with a set sign bit fails the canonical check below
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    if _encodepoint(P) != s:         # canonical-encoding check: reject all non-canonical encodings
        raise ValueError("non-canonical point encoding")
    return P


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff *signature* (64 bytes) is a valid, canonical Ed25519
    signature over *message* under *public_key* (32 bytes)."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    S = _decodeint(signature[32:])
    if S >= L:                       # RFC 8032 §5.1.7: reject non-reduced S (malleability)
        return False
    try:
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key)
    except (ValueError, IndexError):
        return False
    h = int.from_bytes(_H(signature[:32] + public_key + message), "little")
    return _scalarmult(B, S) == _edwards_add(R, _scalarmult(A, h))
