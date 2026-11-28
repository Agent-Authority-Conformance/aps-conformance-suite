#!/usr/bin/env python3
"""Compare a verifier result file to manifest.json expected verdicts. Usage: grade.py MANIFEST RESULTS"""
import json, sys
man = json.load(open(sys.argv[1])); res = {r["path"]: r for r in json.load(open(sys.argv[2]))}
layers = ["structural", "semantic", "authenticity", "chain"]
tot = {l: [0, 0] for l in layers}; mism = []
for t in man["conformance_target"]:
    r = res[t["path"]]
    for l in layers:
        if l not in t: continue
        exp = t[l]; got = r[l]; tot[l][1] += 1
        if exp == got: tot[l][0] += 1
        else: mism.append((t["path"], l, exp, got, r["detail"].get(l)))
for l in layers: print(f"{l}: {tot[l][0]}/{tot[l][1]}")
print("mismatches:", len(mism))
for m in mism: print(" ", m)
