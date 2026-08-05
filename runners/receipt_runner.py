#!/usr/bin/env python3
"""Runner for agentlair-receipt-vectors-v1.

Implements the issuer's stated profile verbatim and nothing else:
  evaluation order  profile -> key_resolution -> signature -> receipt_id
  canonicalization  RFC 8785 JCS over the envelope with `signature` excluded
  signature         Ed25519 over utf8(canonical bytes), base64url unpadded
  receipt_id        "r1:" + b64url(SHA-256(utf8("agentlair-receipt/v1:" + JCS(body0))))
                    where body0 = envelope minus {receipt_id, signature}
  key resolution    did:key only, offline, multicodec 0xed01 + 32-byte Ed25519 key

Signature is evaluated BEFORE receipt_id deliberately, per the issuer's profile, so a
tampered id can never be masked by a bad signature.
"""
from __future__ import annotations
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for ch in s:
        if ch not in B58:
            raise ValueError("non-base58 character " + repr(ch))
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jcs(obj):
    """String-only v1 envelopes, so sort_keys over ASCII equals UTF-16 code unit order."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def resolve_did_key(did):
    if not did:
        return None, "SIGNER_DID_MISSING", "signer_did absent"
    if not did.startswith("did:key:z"):
        return None, "DID_URI_INVALID", "not a did:key multibase-z URI"
    try:
        raw = b58decode(did[len("did:key:z"):])
    except ValueError as e:
        return None, "DID_URI_INVALID", str(e)
    if len(raw) < 2 or raw[0] != 0xED or raw[1] != 0x01:
        got = raw[:2].hex() if len(raw) >= 2 else raw.hex()
        return None, "DID_URI_INVALID", "multicodec prefix " + got + ", expected ed01"
    key = raw[2:]
    if len(key) != 32:
        return None, "DID_URI_INVALID", "key length " + str(len(key)) + ", expected 32"
    return key, None, None


def verify(vec):
    r = dict(vec["receipt"])
    if "signature" not in r:
        return "invalid", "SIGNATURE_MISSING", "profile", ""
    pub, code, detail = resolve_did_key(r.get("signer_did", ""))
    if code:
        return "invalid", code, "key_resolution", detail
    signed = {k: v for k, v in r.items() if k != "signature"}
    canon = jcs(signed).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(b64url_decode(r["signature"]), canon)
    except (InvalidSignature, ValueError) as e:
        return "invalid", "SIGNATURE_INVALID", "signature", type(e).__name__
    body0 = {k: v for k, v in r.items() if k not in ("receipt_id", "signature")}
    want = "r1:" + b64url_nopad(
        hashlib.sha256(("agentlair-receipt/v1:" + jcs(body0)).encode("utf-8")).digest()
    )
    if want != r.get("receipt_id"):
        return "invalid", "RECEIPT_ID_MISMATCH", "receipt_id", "computed " + want
    return "valid", "OK", "", ""


def main(path):
    d = json.load(open(path, encoding="utf-8"))
    vecs = d["vectors"]
    base = dict(vecs[0]["receipt"])
    print("TRANSCRIPTION SELF-CHECK: fields differing from the valid vector")
    for v in vecs[1:]:
        diff = sorted(k for k in set(base) | set(v["receipt"])
                      if base.get(k) != v["receipt"].get(k))
        print("  %-42s %s" % (v["id"], diff if diff else "none (key order only)"))
    print()
    rows, fails = [], 0
    for v in vecs:
        res, code, stage, detail = verify(v)
        exp_res, exp_code = v["expected_result"], v.get("expected_reason")
        exp_stage = v.get("expected_failure_stage", "")
        match = (res == exp_res and code == exp_code
                 and (not exp_stage or stage == exp_stage))
        fails += (not match)
        rows.append((v["id"], res, code, stage, exp_res, exp_code, exp_stage, match, detail))
    print("%-42s %-8s %-20s %-15s %s" % ("vector", "got", "code", "stage", "match"))
    for i, r, c, s, er, ec, es, m, det in rows:
        print("%-42s %-8s %-20s %-15s %s" % (i, r, c, s if s else "-", "OK" if m else "MISMATCH"))
        if not m:
            print("%-42s expected %s/%s/%s   detail: %s" % ("", er, ec, es or "-", det))
    print("\nSUMMARY: %d/%d match expectation, %d failures" % (len(rows) - fails, len(rows), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
