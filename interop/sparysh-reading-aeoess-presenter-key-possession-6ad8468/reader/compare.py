#!/usr/bin/env python3
"""Phase-2 comparison: map blind identifiers to the candidate's, compare verdicts.

Usage: python3 -I reader/compare.py <phase1.json> <vectors.json> <id-map.json> [<final.json>]
Prints one line per case and, with --detail, each case's title, basis and rules.
"""
import json
import sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
detail = "--detail" in sys.argv
p1 = json.load(open(args[0], encoding="utf-8"))
vec = json.load(open(args[1], encoding="utf-8"))
idmap = json.load(open(args[2], encoding="utf-8"))
final = json.load(open(args[3], encoding="utf-8")) if len(args) > 3 else None
orig = {c["id"]: c for c in vec["cases"]}
mine = {r["id"]: r for r in p1["results"]}
fin = {r["id"]: r for r in final["results"]} if final else {}
rows = []
for bid in sorted(idmap, key=lambda b: idmap[b]):
    oid = idmap[bid]
    c = orig[oid]
    v1 = mine[bid]["verdict"]
    vf = fin[bid]["verdict"] if fin else v1
    rows.append((oid, bid, v1, vf, c["expect"], "match" if vf == c["expect"] else "diverge"))
    print("%s %s phase1=%s final=%s expect=%s %s" % rows[-1])
    if detail:
        print("   title:", c.get("title"))
        print("   basis:", c.get("basis"))
        print("   rules:", c.get("rules"))
print("matches: %d of %d" % (sum(r[5] == "match" for r in rows), len(rows)))
