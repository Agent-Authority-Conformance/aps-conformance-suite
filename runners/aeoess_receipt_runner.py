#!/usr/bin/env python3
"""Runner for aeoess-aps-receipt-vectors-v1.

Written fresh against the published profile. It imports nothing from the SDK that
emitted the vectors, so a passing positive is not the emitter agreeing with itself.
Every construction below is reimplemented from the profile text:

  evaluation order    schema -> receipt_id -> key_resolution -> signature, NO short-circuit
  canonicalization    RFC 8785 JCS over the relevant sub-object
  receipt_id          SHA-256(ASCII("APS-RECEIPT-ID-V1") || 0x00 ||
                              UTF8(JCS(receipt without receipt_id and signatures)))
  signature           Ed25519 over ASCII("APS-RECEIPT-SIG-V1") || 0x00 ||
                              UTF8(JCS({"receipt": receipt without signatures,
                                        "signer": {signer, key_id, alg}}))
                      value and public key are lowercase hex
  chain root          SHA-256(UTF8(JCS(chain))). Bare: no tag, no separator byte.
  integrity           receipt_len / receipt_sha256 over utf8 of the COMPACT JSON
                      serialization in the member order as published

Contrast with the agentlair profile in receipt_runner.py: there the signature is
evaluated before receipt_id and the run stops at the first failure, so a content
mutation reports one code. Here receipt_id comes first and nothing short-circuits,
so the same mutation reports two.
"""
from __future__ import annotations
import hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

RECEIPT_ID_TAG = b"APS-RECEIPT-ID-V1"
RECEIPT_SIG_TAG = b"APS-RECEIPT-SIG-V1"

RECEIPT_ALLOWED = ["profile", "receipt_id", "receipt_type", "issuer", "subject_agent",
                   "action_ref", "delegation_ref", "decision_ref", "issued_at",
                   "evidence_refs", "result", "prev", "signatures"]
RECEIPT_REQUIRED = ["profile", "receipt_id", "receipt_type", "issuer", "subject_agent",
                    "action_ref", "delegation_ref", "issued_at", "evidence_refs",
                    "result", "signatures"]
SIG_KEYS = ["signer", "key_id", "alg", "value"]
EVIDENCE_KEYS = ["artifact_type", "sha256"]


def jcs(obj) -> str:
    """RFC 8785 for the ASCII string-only bodies this corpus uses.

    Python sorts by Unicode code point and JCS sorts by UTF-16 code unit; the two
    agree for the Basic Multilingual Plane below U+D800, and every key and value
    here is ASCII. assert_ascii() below enforces that rather than assuming it.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compact(obj) -> str:
    """Compact serialization preserving the member order as published."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def assert_ascii(obj, path="$"):
    if isinstance(obj, str):
        if not obj.isascii():
            raise ValueError(f"{path}: non-ASCII, jcs() shortcut does not hold")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not k.isascii():
                raise ValueError(f"{path}: non-ASCII key")
            assert_ascii(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            assert_ascii(v, f"{path}[{i}]")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex(s, n):
    return isinstance(s, str) and len(s) == n and all(c in "0123456789abcdef" for c in s)


def validate(r) -> list[str]:
    """Closed-schema validation. Returns the literal error strings the profile lists."""
    errs = []
    for k in r:
        if k not in RECEIPT_ALLOWED:
            errs.append(f"ReceiptV1: unknown field {k}")
    for k in RECEIPT_REQUIRED:
        if k not in r:
            errs.append(f"ReceiptV1: missing field {k}")
    if errs:
        return errs
    if r["profile"] != "aps-receipt-v1":
        errs.append("ReceiptV1: profile")
    if not (r["receipt_type"] and r["issuer"] and r["subject_agent"] and r["delegation_ref"]):
        errs.append("ReceiptV1: empty identifier")
    if not is_hex(r["receipt_id"], 64):
        errs.append("ReceiptV1: receipt_id")
    if not is_hex(r["action_ref"], 64):
        errs.append("ReceiptV1: action_ref")
    if "decision_ref" in r and not is_hex(r["decision_ref"], 64):
        errs.append("ReceiptV1: decision_ref")
    if "prev" in r and not is_hex(r["prev"], 64):
        errs.append("ReceiptV1: prev")
    ts = r["issued_at"]
    ok_ts = (isinstance(ts, str) and len(ts) == 24 and ts[4] == ts[7] == "-"
             and ts[10] == "T" and ts[13] == ts[16] == ":" and ts[19] == "." and ts[23] == "Z")
    if not ok_ts:
        errs.append("ReceiptV1: issued_at")
    if not isinstance(r["result"], dict):
        errs.append("ReceiptV1: result")
    if not isinstance(r["evidence_refs"], list) or not isinstance(r["signatures"], list):
        errs.append("ReceiptV1: arrays")
        return errs
    seen = set()
    prev_key = None
    for ref in r["evidence_refs"]:
        if sorted(ref) != sorted(EVIDENCE_KEYS):
            errs.append("EvidenceRefV1: value")
            continue
        if not ref["artifact_type"] or not is_hex(ref["sha256"], 64):
            errs.append("EvidenceRefV1: value")
        key = (ref["artifact_type"].encode(), ref["sha256"].encode())
        if key in seen:
            errs.append("ReceiptV1: duplicate evidence_ref")
        seen.add(key)
        if prev_key is not None and prev_key >= key:
            errs.append("ReceiptV1: evidence_refs not sorted")
        prev_key = key
    seen_sig = set()
    prev_sig = None
    for p in r["signatures"]:
        if sorted(p) != sorted(SIG_KEYS):
            errs.append("ReceiptSignatureV1: value")
            continue
        if not p["signer"] or not p["key_id"] or p["alg"] != "Ed25519" or not is_hex(p["value"], 128):
            errs.append("ReceiptSignatureV1: value")
        key = (p["signer"].encode(), p["key_id"].encode())
        if key in seen_sig:
            errs.append("ReceiptV1: duplicate signature")
        seen_sig.add(key)
        if prev_sig is not None and prev_sig >= key:
            errs.append("ReceiptV1: signatures not sorted")
        prev_sig = key
    if not any(p.get("signer") == r["issuer"] for p in r["signatures"]):
        errs.append("ReceiptV1: issuer signature missing")
    return errs


def receipt_id_payload(r) -> bytes:
    body = {k: v for k, v in r.items() if k not in ("receipt_id", "signatures")}
    return RECEIPT_ID_TAG + b"\x00" + jcs(body).encode("utf-8")


def signature_payload(r, descriptor) -> bytes:
    form = {"receipt": {k: v for k, v in r.items() if k != "signatures"},
            "signer": descriptor}
    return RECEIPT_SIG_TAG + b"\x00" + jcs(form).encode("utf-8")


def verify(receipt, key_table):
    """Return (result, errors, stage, sig_detail). No short-circuit."""
    assert_ascii(receipt)
    schema_errs = validate(receipt)
    if schema_errs:
        return "invalid", schema_errs, "schema", []
    errors = []
    computed = sha256_hex(receipt_id_payload(receipt))
    if computed != receipt["receipt_id"]:
        errors.append("receipt_id_mismatch")
    sig_detail = []
    any_sig_bad = False
    for p in receipt["signatures"]:
        descriptor = {"signer": p["signer"], "key_id": p["key_id"], "alg": p["alg"]}
        pub = key_table.get((p["signer"], p["key_id"]))
        if pub is None:
            sig_detail.append((p["key_id"], False, "key_unresolved"))
            any_sig_bad = True
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
                bytes.fromhex(p["value"]), signature_payload(receipt, descriptor))
            sig_detail.append((p["key_id"], True, ""))
        except (InvalidSignature, ValueError) as e:
            sig_detail.append((p["key_id"], False, type(e).__name__))
            any_sig_bad = True
    if any_sig_bad:
        errors.append("signature_invalid")
    stage = "receipt_id" if "receipt_id_mismatch" in errors else ("signature" if any_sig_bad else "")
    return ("invalid" if errors else "valid"), errors, stage, sig_detail


def main(path):
    d = json.load(open(path, encoding="utf-8"))
    key_table = {(k["signer"], k["key_id"]): k["public_key_hex"] for k in d["profile"]["keys"]}
    vecs = d["vectors"]

    print("INTEGRITY SELF-CHECK: receipt_len / receipt_sha256 recomputed from the published bytes")
    integrity_fail = 0
    for v in vecs:
        s = compact(v["receipt"])
        n, h = len(s.encode("utf-8")), sha256_hex(s.encode("utf-8"))
        ok = (n == v["receipt_len"] and h == v["receipt_sha256"])
        integrity_fail += (not ok)
        print("  %-44s len=%-5d sha256=%s %s" % (v["id"], n, h[:16] + "...", "OK" if ok else "MISMATCH"))
        if not ok:
            print("  %-44s declared len=%s sha256=%s" % ("", v["receipt_len"], v["receipt_sha256"]))
    print()

    print("CHAIN ROOT RECOMPUTATION (bare SHA-256 over JCS of the chain array)")
    chain_fail = 0
    for v in vecs:
        if "delegation_chain" not in v:
            continue
        got = sha256_hex(jcs(v["delegation_chain"]).encode("utf-8"))
        ok = got == v["delegation_chain_root"]
        chain_fail += (not ok)
        print("  %-44s %s %s" % (v["id"], got, "OK" if ok else "MISMATCH declared " + v["delegation_chain_root"]))
    print()

    rows, fails = [], 0
    for v in vecs:
        res, errs, stage, sig_detail = verify(v["receipt"], key_table)
        exp_res = v["expected_result"]
        exp_errs = sorted(v.get("expected_errors", []))
        exp_stage = v.get("expected_failure_stage", "")
        match = (res == exp_res and sorted(errs) == exp_errs
                 and (not exp_stage or stage == exp_stage))
        fails += (not match)
        rows.append((v["id"], res, errs, stage, exp_res, exp_errs, exp_stage, match, sig_detail))

    print("%-44s %-8s %-12s %s" % ("vector", "got", "stage", "errors"))
    for i, r, e, s, er, ee, es, m, sd in rows:
        print("%-44s %-8s %-12s %-44s %s" % (i, r, s if s else "-", json.dumps(e), "OK" if m else "MISMATCH"))
        for kid, ok, why in sd:
            print("%-46ssig key_id=...%s valid=%s%s" % ("", kid[-12:], ok, " reason=" + why if why else ""))
        if not m:
            print("%-44s expected %s %s stage=%s" % ("", er, json.dumps(ee), es or "-"))
    total_fail = fails + integrity_fail + chain_fail
    print("\nSUMMARY: %d/%d vectors match expectation, %d integrity failures, %d chain-root failures, %d total failures"
          % (len(rows) - fails, len(rows), integrity_fail, chain_fail, total_fail))
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
