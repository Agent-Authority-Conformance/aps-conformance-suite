#!/usr/bin/env python3
"""Independent AEP verifier (v2: vocabulary rule, empty observed), written from IMPLEMENTER.md, conformance/aep/README.md,
verifier-result-contract.md and schemas/aep/aep-record.schema.json of
@wasmagent/protocol 0.1.12. Imports no WasmAgent code.

Usage: aep_verify.py CORPUS_DIR PATHS_FILE OUT_JSON
PATHS_FILE lists corpus-relative fixture paths, one per line. Expected verdicts
are NOT read here. Grading is a separate step (grade.py)."""
import base64, hashlib, json, sys
from pathlib import Path

import jsonschema
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Profile constants, from IMPLEMENTER.md and the manifest dsse block.
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://wasmagent.dev/attestations/aep/v0.4"
SUBJECT_PREFIX = "urn:wasmagent:run:"
EXCLUDED = ("signature", "dsse_envelope")
# Total order from the run_attribution_backing_floor description, weakest first.
GRADE_ORDER = ["unknown", "operator_asserted", "principal_key_signed", "qualified_signature"]


def predicate(record):
    """The record with exactly signature and dsse_envelope removed."""
    return {k: v for k, v in record.items() if k not in EXCLUDED}


def jcs(obj):
    return rfc8785.dumps(obj)


def pred_hash(record):
    return hashlib.sha256(jcs(predicate(record))).hexdigest()


def b64decode_any(s):
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(s + pad)


def pae(payload_type, body):
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def load_fixture(path):
    text = path.read_text()
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return [json.loads(text)]


# ---------- L0 structural ----------
def structural(record, validator):
    errs = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
    return ("valid" if not errs else "invalid"), [e.message for e in errs][:5]


# ---------- L1 semantic ----------
def semantic(record):
    """Derived invariants stated in the schema descriptions:
    floor reported together with observed; floor in observed; floor equals the
    weakest observed grade (no round up); observed items unique; count, when
    present, cannot be smaller than the number of distinct grades observed."""
    v = []
    # Vocabulary rule (IMPLEMENTER.md names "vocabulary" as a semantic rule):
    # every grade-valued field must hold a value from the shared vocabulary.
    for f in ("attribution_backing", "run_attribution_backing_floor"):
        if f in record and record[f] not in GRADE_ORDER:
            v.append(f"{f}_outside_vocabulary")
    if isinstance(record.get("run_attribution_backing_observed"), list):
        if any(g not in GRADE_ORDER for g in record["run_attribution_backing_observed"]):
            v.append("observed_outside_vocabulary")
    floor = record.get("run_attribution_backing_floor")
    obs = record.get("run_attribution_backing_observed")
    count = record.get("authorization_evidence_count")
    if isinstance(obs, list) and len(obs) != len(set(map(json.dumps, obs))):
        v.append("observed_not_unique")
    if floor is not None:
        if not isinstance(obs, list) or not obs:
            v.append("floor_without_observed")
        else:
            if floor not in obs:
                v.append("floor_not_in_observed")
            known = [g for g in obs if g in GRADE_ORDER]
            if known and floor in GRADE_ORDER:
                weakest = min(known, key=GRADE_ORDER.index)
                if floor != weakest:
                    v.append("floor_not_weakest_observed")
    else:
        if isinstance(obs, list) and obs:
            # Absent floor = the producer emits no attribution_backing values.
            v.append("observed_without_floor")
        elif isinstance(obs, list) and not obs:
            # v2, from the corpus note on empty-observed.json (not stated in the
            # schema text): an empty observed set is an empty grading claim.
            v.append("empty_observed")
    if isinstance(count, int) and not isinstance(count, bool):
        if count < 0:
            v.append("negative_count")
        if isinstance(obs, list) and count < len(set(map(json.dumps, obs))):
            v.append("count_below_observed_grades")
    return ("valid" if not v else "invalid"), v


# ---------- L2 authenticity ----------
def authenticity(record, keys):
    env = record.get("dsse_envelope")
    legacy = record.get("signature")
    if env is None:
        if legacy is None:
            return "unsigned", []
        return "invalid", ["inline_signature_without_dsse (unsupported legacy)"]
    reasons = []
    if not isinstance(env, dict):
        return "invalid", ["envelope_not_object"]
    if env.get("payloadType") != PAYLOAD_TYPE:
        reasons.append("payload_type")
    sigs = env.get("signatures")
    if not isinstance(sigs, list) or len(sigs) != 1:
        return "invalid", reasons + ["signature_count"]
    sig = sigs[0]
    keyid = sig.get("keyid")
    if keyid not in keys:
        return "invalid", reasons + ["unknown_keyid"]
    try:
        body = b64decode_any(env.get("payload", ""))
        stmt = json.loads(body)
    except Exception:
        return "invalid", reasons + ["payload_decode"]
    if stmt.get("_type") != STATEMENT_TYPE:
        reasons.append("statement_type")
    if stmt.get("predicateType") != PREDICATE_TYPE:
        reasons.append("predicate_type")
    pred = predicate(record)
    want = hashlib.sha256(jcs(pred)).hexdigest()
    subj = stmt.get("subject")
    if not isinstance(subj, list) or len(subj) != 1:
        reasons.append("subject_count")
    else:
        s = subj[0]
        if s.get("name") != SUBJECT_PREFIX + str(record.get("run_id")):
            reasons.append("subject_name")
        if (s.get("digest") or {}).get("sha256") != want:
            reasons.append("subject_digest")
    try:
        if jcs(stmt.get("predicate")) != jcs(pred):
            reasons.append("predicate_not_record")
    except Exception:
        reasons.append("predicate_not_record")
    try:
        keys[keyid].verify(b64decode_any(sig.get("sig", "")), pae(env.get("payloadType", ""), body))
    except (InvalidSignature, Exception):
        reasons.append("signature")
    if isinstance(legacy, dict):
        if legacy.get("sig") != sig.get("sig") or legacy.get("key_id") != keyid:
            reasons.append("legacy_signature_not_derived_from_envelope")
    return ("dsse-valid" if not reasons else "invalid"), reasons


# ---------- L3 chain ----------
def chain(records):
    """not-present: no record carries a link. orphaned: the set starts with a link
    to a record outside it. broken: a present link does not match the previous
    record. partial: some later record lacks its link. intact: every later record
    links to its predecessor and the first carries none."""
    prevs = [r.get("prev_record_hash") for r in records]
    if all(p is None for p in prevs):
        return "not-present", []
    notes = []
    status = "intact"
    if prevs[0] is not None:
        status = "orphaned"
        notes.append("first_record_has_prev")
    for i in range(1, len(records)):
        p = prevs[i]
        if p is None:
            notes.append(f"missing_link_{i}")
            if status == "intact":
                status = "partial"
        elif p != pred_hash(records[i - 1]):
            notes.append(f"mismatch_{i}")
            status = "broken"
    if status == "orphaned" and any(n.startswith("mismatch") for n in notes):
        status = "broken"
    return status, notes


def worst(statuses, order):
    return max(statuses, key=order.index)


def main(corpus, paths_file, out):
    corpus = Path(corpus)
    pkg = corpus.parent.parent  # .../package
    schema = json.loads((pkg / "schemas/aep/aep-record.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    man = json.loads((corpus / "manifest.json").read_text())
    keys = {}
    for kid, rel in man["verifying_keys"]["by_keyid"].items():
        raw = bytes.fromhex((corpus / rel).read_text().strip())
        keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
    results = []
    for rel in [l.strip() for l in Path(paths_file).read_text().splitlines() if l.strip()]:
        recs = load_fixture(corpus / rel)
        st = [structural(r, validator) for r in recs]
        se = [semantic(r) for r in recs]
        au = [authenticity(r, keys) for r in recs]
        ch = chain(recs)
        results.append({
            "path": rel,
            "records": len(recs),
            "structural": worst([s for s, _ in st], ["valid", "invalid"]),
            "semantic": worst([s for s, _ in se], ["valid", "invalid"]),
            "authenticity": worst([a for a, _ in au], ["unsigned", "dsse-valid", "invalid"]) if len({a for a, _ in au}) == 1 or any(a == "invalid" for a, _ in au) else "mixed",
            "chain": ch[0],
            "detail": {
                "structural": [e for _, es in st for e in es],
                "semantic": [x for _, xs in se for x in xs],
                "authenticity": [x for _, xs in au for x in xs],
                "chain": ch[1],
            },
        })
    Path(out).write_text(json.dumps(results, indent=1, sort_keys=True))


if __name__ == "__main__":
    main(*sys.argv[1:4])
