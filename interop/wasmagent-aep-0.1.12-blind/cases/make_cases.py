#!/usr/bin/env python3
"""Additional candidate cases and controls for missing combinations and checks
the 0.1.12 corpus does not isolate (following the cold-run record). Signed with a throwaway key generated here. Expected
outcomes are this author's reading of IMPLEMENTER.md, not corpus verdicts."""
import base64, copy, hashlib, json, sys
from pathlib import Path
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

corpus = Path(sys.argv[1]); out = Path(sys.argv[2]); out.mkdir(exist_ok=True)
base = json.loads((corpus / "valid/minimal-v05.json").read_text())
for k in ("signature", "dsse_envelope"): base.pop(k, None)
sk = Ed25519PrivateKey.generate()
pk_hex = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
(out / "extra-verify-key.hex").write_text(pk_hex + "\n")
PT = "application/vnd.in-toto+json"

def jcs(o): return rfc8785.dumps(o)
def pred(r): return {k: v for k, v in r.items() if k not in ("signature", "dsse_envelope")}
def pae(t, b): t = t.encode(); return b"DSSEv1 %d %s %d %s" % (len(t), t, len(b), b)

def sign(rec, keyid="extra-key-01", subjects=None, stmt_pred=None, digest=None):
    p = pred(rec) if stmt_pred is None else stmt_pred
    d = digest or hashlib.sha256(jcs(p)).hexdigest()
    subj = subjects or [{"name": "urn:wasmagent:run:" + rec["run_id"], "digest": {"sha256": d}}]
    stmt = {"_type": "https://in-toto.io/Statement/v1", "subject": subj,
            "predicateType": "https://wasmagent.dev/attestations/aep/v0.4", "predicate": p}
    body = jcs(stmt)
    sig = base64.b64encode(sk.sign(pae(PT, body))).decode()
    r = copy.deepcopy(rec)
    r["dsse_envelope"] = {"payloadType": PT, "payload": base64.b64encode(body).decode(),
                          "signatures": [{"keyid": keyid, "sig": sig}]}
    return r

cases = []
def add(name, rec, layer, expected, why):
    (out / f"{name}.json").write_text(json.dumps(rec, indent=1))
    cases.append({"path": f"{name}.json", "layer": layer, "expected": expected, "why": why})

add("X0-positive-control", sign(base), "authenticity", "dsse-valid", "control: correct profile, key extra-key-01 registered for this run only")
add("X1-unknown-keyid", sign(base, keyid="not-in-verifying-keys"), "authenticity", "invalid", "keyid absent from verifying_keys.by_keyid")
add("X2-subject-digest-wrong-predicate-right", sign(base, digest="0" * 64), "authenticity", "invalid", "statement predicate equals record, subject digest does not match it")
alt = pred(base); alt["created_at_ms"] = base["created_at_ms"] + 1
add("X3-predicate-differs-digest-consistent", sign(base, stmt_pred=alt), "authenticity", "invalid", "subject digest matches the statement predicate, but the predicate is not the record")
add("X3b-predicate-differs-digest-matches-record", sign(base, stmt_pred=alt, digest=hashlib.sha256(jcs(pred(base))).hexdigest()), "authenticity", "invalid", "subject digest matches the record, statement predicate is not the record: only the predicate binding check can catch it")
two = [{"name": "urn:wasmagent:run:" + base["run_id"], "digest": {"sha256": hashlib.sha256(jcs(pred(base))).hexdigest()}},
       {"name": "urn:wasmagent:run:other", "digest": {"sha256": "1" * 64}}]
add("X4-two-subjects", sign(base, subjects=two), "authenticity", "invalid", "IMPLEMENTER.md: the Statement carries exactly one subject")
c = copy.deepcopy(base); c.update({"run_attribution_backing_floor": "operator_asserted", "run_attribution_backing_observed": ["operator_asserted", "principal_key_signed"], "authorization_evidence_count": 1})
add("X5-count-below-observed-grades", c, "semantic", "invalid", "two distinct grades observed but count says one authorization")
c2 = copy.deepcopy(c); c2["authorization_evidence_count"] = 3
add("X6-count-with-floor-consistent", c2, "semantic", "valid", "count 3, two grades, floor is the weakest")
s = sign(base); s["signature"] = {"alg": "ed25519", "key_id": "extra-key-01", "sig": base64.b64encode(b"\x00" * 64).decode()}
add("X7-legacy-signature-not-derived", s, "authenticity", "invalid", "legacy signature field must derive from signatures[0]; here it differs")
(out / "cases.json").write_text(json.dumps({"extra_key_id": "extra-key-01", "cases": cases}, indent=1))
print(len(cases), "cases")
