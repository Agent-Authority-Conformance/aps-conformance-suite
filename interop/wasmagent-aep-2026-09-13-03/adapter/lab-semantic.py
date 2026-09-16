#!/usr/bin/env python3
"""LAB-SEMANTIC. Lab-authored recomputation of AEP record-semantic rules.

Shares no code with wasmagent-js or aep-core. Rules are taken from the pinned
schema's normative text, not from either implementation's behaviour.
Emits every violation found; never stops at the first.
"""
import json, os, sys

CORPUS = "../wasmagent-protocol/conformance/aep"
VOCAB = ["unknown", "operator_asserted", "principal_key_signed", "qualified_signature"]
RANK = {g: i for i, g in enumerate(VOCAB)}  # weakest..strongest, per schema line 420

def check(rec):
    v = []
    floor = rec.get("run_attribution_backing_floor")
    observed = rec.get("run_attribution_backing_observed")
    backing = rec.get("attribution_backing")
    count = rec.get("authorization_evidence_count")

    for g in ([backing] if backing is not None else []) + \
             ([floor] if floor is not None else []) + \
             (list(observed) if isinstance(observed, list) else []):
        if g not in RANK:
            v.append("SEM_UNKNOWN_GRADE")
            break

    if floor is not None and observed is None:
        v.append("SEM_FLOOR_WITHOUT_OBSERVED")
    if observed is not None and floor is None:
        v.append("SEM_OBSERVED_WITHOUT_FLOOR")
    if isinstance(observed, list) and len(observed) == 0:
        v.append("SEM_EMPTY_OBSERVED")
    if isinstance(observed, list) and len(observed) != len(set(observed)):
        v.append("SEM_DUPLICATE_OBSERVED")
    if isinstance(observed, list) and observed and floor is not None:
        if floor not in observed:
            v.append("SEM_FLOOR_NOT_OBSERVED")
        known = [g for g in observed if g in RANK]
        if known and floor in RANK and RANK[floor] != min(RANK[g] for g in known):
            v.append("SEM_FLOOR_NOT_WEAKEST")
    if isinstance(count, int) and count < 0:
        v.append("SEM_NEGATIVE_AUTH_EVIDENCE_COUNT")
    return v

man = json.load(open(os.path.join(CORPUS, "manifest.json")))
rows = []
for e in man["conformance_target"]:
    p = e["path"]
    raw = open(os.path.join(CORPUS, p)).read()
    if p.endswith(".jsonl"):
        recs = [json.loads(l) for l in raw.splitlines() if l.strip()]
    else:
        recs = [json.loads(raw)]
    viols = []
    for i, rec in enumerate(recs):
        for c in check(rec):
            tag = c if len(recs) == 1 else f"{c}@{i}"
            if tag not in viols:
                viols.append(tag)
    rows.append({
        "layer": "LAB-SEMANTIC", "fixture": p,
        "semantic_valid": len(viols) == 0, "violations": viols,
        "manifest_semantic": e.get("semantic"),
        "manifest_structural": e.get("structural"),
    })
json.dump(rows, open("../evidence/lab-semantic.json", "w"), indent=1)

agree = sum(1 for r in rows if r["semantic_valid"] == (r["manifest_semantic"] == "valid"))
print(f"fixtures={len(rows)} agree_with_manifest={agree}/{len(rows)}")
for r in rows:
    mark = "" if r["semantic_valid"] == (r["manifest_semantic"] == "valid") else "  <-- DISAGREE"
    print(f"  {r['fixture']:<52} lab_valid={str(r['semantic_valid']):<5} manifest={str(r['manifest_semantic']):<8} struct={str(r['manifest_structural']):<8} {','.join(r['violations'])}{mark}")
sys.exit(0 if agree == len(rows) else 1)
