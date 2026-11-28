#!/usr/bin/env python3
"""Phase 2: compare the frozen phase-1 verdicts with the candidate's expectations.

Reads out/phase1.json (never written here), the sealed vectors.json and the
blind-to-original id map. Writes out/final.json. No verdict is changed here:
any change after phase 1 is listed in CHANGES below and in out/changes.md.

Usage:
  python3 -B reader/compare.py --phase1 P1 --vectors V --idmap M --out FINAL
"""
import argparse
import hashlib
import json
import os

# Changes to phase-1 verdicts made in phase 2: blind id -> (new verdict, sentence, fault).
CHANGES = {}


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase1", required=True)
    ap.add_argument("--vectors", required=True)
    ap.add_argument("--idmap", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    p1 = json.load(open(a.phase1, encoding="utf-8"))
    vec = json.load(open(a.vectors, encoding="utf-8"))
    idmap = json.load(open(a.idmap, encoding="utf-8"))
    orig = {c["id"]: c for c in vec["cases"]}

    rows = []
    for c in p1["cases"]:
        bid = c["id"]
        oid = idmap[bid]
        o = orig[oid]
        final = CHANGES.get(bid, (c["verdict"],))[0]
        row = {
            "blind_id": bid, "original_id": oid, "candidate_rule": o["rule"],
            "phase1_verdict": c["verdict"], "final_verdict": final,
            "expect": o["expect"], "result": "match" if final == o["expect"] else "diverge",
        }
        if row["result"] == "diverge":
            # first differing condition: which of this run's readings gives the expected verdict
            row["readings_of_this_run"] = [{"reading": r["reading"], "verdict": r["verdict"],
                                            "agrees_with_expect": r["verdict"] == o["expect"]}
                                           for r in c["checks"]]
        if "expect_parts" in o or "ambiguous_detail" in c:
            row["parts"] = {
                "expect_parts": o.get("expect_parts"),
                "parts_of_this_run": c.get("ambiguous_detail", {}).get("parts_scored"),
                "same_part_names": sorted(set(o.get("expect_parts", {})) & set(c.get("ambiguous_detail", {}).get("parts_scored", {}))),
            }
        rows.append(row)
    rows.sort(key=lambda r: r["original_id"])
    verdicts = vec["verdicts"]
    doc = {
        "record": "final, after comparison with the candidate's expectations",
        "inputs": {"phase1": {"file": os.path.basename(a.phase1), "sha256": sha(a.phase1)},
                   "vectors": {"file": os.path.basename(a.vectors), "sha256": sha(a.vectors)},
                   "idmap": {"file": os.path.basename(a.idmap), "sha256": sha(a.idmap)}},
        "changes_after_phase1": {k: {"verdict": v[0], "sentence": v[1], "fault": v[2]} for k, v in CHANGES.items()},
        "cases": rows,
        "tally_phase1": {v: sum(1 for r in rows if r["phase1_verdict"] == v) for v in verdicts},
        "tally_final": {v: sum(1 for r in rows if r["final_verdict"] == v) for v in verdicts},
        "tally_expected": {v: sum(1 for r in rows if r["expect"] == v) for v in verdicts},
        "match": sum(1 for r in rows if r["result"] == "match"),
        "diverge": sum(1 for r in rows if r["result"] == "diverge"),
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    for r in rows:
        print("%s %s %-13s %-13s %s" % (r["original_id"], r["blind_id"], r["final_verdict"], r["expect"], r["result"]))
    print("match %d, diverge %d" % (doc["match"], doc["diverge"]))


if __name__ == "__main__":
    main()
