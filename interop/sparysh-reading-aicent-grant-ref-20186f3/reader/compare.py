#!/usr/bin/env python3
"""Phase-2 comparison.  Reads out/phase1.json (never modified), the sealed
vectors and the blind-to-original id map; writes out/final.json.
usage: python3 -I compare.py <phase1.json> <vectors.json> <id-map.json> <final.json>
"""
import json
import sys

# Which phase-1 rules make up each named part in the candidate's expect_parts.
# Chosen after reading the sealed notes; this mapping is the only phase-2 judgement.
PART_MAP = {
    "GR-A01": {"value_and_assent": ["R1-reason-present", "R2-closed-set", "R3-no-granted", "R4-priority"],
               "computation_source": ["R7-computed-over-facts"]},
    "GR-A02": {"value": ["R1-reason-present", "R2-closed-set", "R3-no-granted", "R4-priority"],
               "boundary_call": ["R12-race-observation-vs-revocation"]},
}


def part_verdict(checks, rules):
    hs = [c["held"] for c in checks if c["rule"] in rules]
    if not hs:
        return "not scored"
    if any(h is False for h in hs):
        return "nonconformant"
    if any(h == "ambiguous" for h in hs):
        return "ambiguous"
    return "conformant"


def main(a):
    p1 = json.load(open(a[1], encoding="utf-8"))
    vec = {c["id"]: c for c in json.load(open(a[2], encoding="utf-8"))["cases"]}
    idmap = json.load(open(a[3], encoding="utf-8"))
    rows = []
    for r in p1["cases"]:
        oid = idmap[r["id"]]
        v = vec[oid]
        row = {"blind_id": r["id"], "original_id": oid, "candidate_rule": v["rule"],
               "verdict": r["verdict"], "expect": v["expect"],
               "result": "match" if r["verdict"] == v["expect"] else "diverge"}
        if "expect_parts" in v:
            pm = PART_MAP.get(oid, {})
            parts = {}
            for name, exp in sorted(v["expect_parts"].items()):
                got = part_verdict(r["checks"], pm.get(name, []))
                parts[name] = {"expect": exp, "reader": got, "rules": pm.get(name, []),
                               "result": "match" if got == exp else "diverge"}
            row["parts"] = parts
        rows.append(row)
    rows.sort(key=lambda x: x["original_id"])
    tally = {k: sum(1 for x in rows if x["verdict"] == k) for k in ("conformant", "nonconformant", "ambiguous")}
    agree = sum(1 for x in rows if x["result"] == "match")
    parts_div = [(x["original_id"], n) for x in rows for n, p in x.get("parts", {}).items() if p["result"] != "match"]
    doc = {"phase": 2, "phase1_sha256_input": None, "verdict_changes_from_phase1": [],
           "tally": tally, "verdict_agreement": f"{agree}/{len(rows)}",
           "part_divergences": parts_div, "cases": rows}
    import hashlib
    doc["phase1_sha256_input"] = hashlib.sha256(open(a[1], "rb").read()).hexdigest()
    with open(a[4], "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    print(json.dumps({"tally": tally, "verdict_agreement": doc["verdict_agreement"],
                      "part_divergences": parts_div}, sort_keys=True))
    for x in rows:
        print(x["original_id"], x["blind_id"], x["verdict"], x["expect"], x["result"],
              json.dumps(x.get("parts", ""), sort_keys=True) if "parts" in x else "")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
