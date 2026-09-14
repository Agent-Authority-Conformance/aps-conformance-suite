#!/usr/bin/env python3
"""Deterministic join of the three reproduced layer outputs into one per-fixture matrix.

Aggregation only. Makes no verification decision and introduces no semantic rule, so it
carries no authorship classification of its own. Fixture order follows the corpus
conformance_target order as carried through lab-semantic.json.
"""
import json

E = "../evidence/"
js = {r["fixture"]: r for r in json.load(open(E + "native-js.json")) if r["layer"] == "JS-NATIVE-RECORD"}
ch = {r["fixture"]: r for r in json.load(open(E + "native-js.json")) if r["layer"] == "JS-NATIVE-CHAIN"}
rs = {r["fixture"]: r for r in json.load(open(E + "native-rust.json"))}
lab = {r["fixture"]: r for r in json.load(open(E + "lab-semantic.json"))}

matrix = []
for p, l in lab.items():
    j = js.get(p); r = rs.get(p); c = ch.get(p)
    matrix.append({
        "fixture": p,
        "manifest": {"structural": l["manifest_structural"], "semantic": l["manifest_semantic"]},
        "JS_NATIVE_RECORD": None if not j else {"valid": j["valid"], "authenticity": j["authenticity"], "binding": j["binding"]},
        "RUST_NATIVE_DSSE": None if not r else r["result"],
        "JS_NATIVE_CHAIN": None if not c else {"valid": c.get("valid"), "status": c.get("status"), "brokenAt": c.get("brokenAt")},
        "LAB_SEMANTIC": {"semantic_valid": l["semantic_valid"], "violations": l["violations"]},
    })
json.dump(matrix, open(E + "consolidated-matrix.json", "w"), indent=1)
print(f"matrix rows={len(matrix)}")
