#!/usr/bin/env python3
"""Phase 2: key and claim checks against the sealed vectors, and the final verdicts.

Usage: python3 -I reader/phase2.py <blind cases.json> <vectors.json> <id-map.json> <rfc-dir> <out-dir>

Writes <out-dir>/final.json. Prints the key checks.
The final verdicts use the phase-1 checker unchanged (loaded from reader/checker.py),
with two choice points fixed by the axis definitions stated in the candidate's
CANDIDATE.md (see out/changes.md); the other choice points stay evaluated both ways.
"""
import hashlib
import importlib.util
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("checker", os.path.join(here, "checker.py"))
ck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ck)

blind_path, vec_path, map_path, rfc_dir, out_dir = sys.argv[1:6]
ck.verify_citations(rfc_dir)
ck.self_test()
blind = json.load(open(blind_path, encoding="utf-8"))
vec = json.load(open(vec_path, encoding="utf-8"))
idmap = json.load(open(map_path, encoding="utf-8"))
orig = {c["id"]: c for c in vec["cases"]}

checks = {}

# 0. The blind copy carries exactly the sealed inputs and outcomes.
same = {bid: (c["input"] == orig[idmap[bid]]["input"] and c["outcome"] == orig[idmap[bid]]["outcome"])
        for bid, c in ((c["id"], c) for c in blind["cases"])}
checks["K0_blind_equals_sealed"] = {"result": all(same.values()), "cases": len(same),
                                    "mismatches": sorted(b for b, v in same.items() if not v)}

# 1. Keys derived from keys.seed_rule.
keys = vec["keys"]
rule = keys["seed_rule"]
derived = {}
for label in sorted(k for k in keys if k != "seed_rule"):
    seed = hashlib.sha256(("aeoess-presenter-key-possession/" + label).encode("utf-8")).digest()
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    derived[label] = {"seed_b64url": ck.b64url_encode(seed), "x_derived": ck.b64url_encode(pub),
                      "x_in_block": keys[label].get("x"),
                      "matches": ck.b64url_encode(pub) == keys[label].get("x")}
checks["K1_keys_derive_from_seed_rule"] = {"seed_rule_as_stated": rule,
                                           "seed_rule_as_applied": "sha256(UTF-8('aeoess-presenter-key-possession/' + label)) as the 32-octet Ed25519 private key (RFC 8032 seed)",
                                           "result": all(d["matches"] for d in derived.values()),
                                           "keys": derived}

# 2. cnf.jkt against the thumbprint of each derived key.
tps = {label: ck.thumbprint_okp({"kty": "OKP", "crv": "Ed25519", "x": d["x_derived"]})[0]
       for label, d in derived.items()}
jkts = sorted({(c["input"].get("token_claims") or {}).get("cnf", {}).get("jkt") for c in vec["cases"]} - {None})
checks["K2_cnf_jkt_vs_derived_thumbprints"] = {
    "thumbprints": tps, "distinct_cnf_jkt_values": jkts,
    "jkt_to_key": {j: [l for l, t in tps.items() if t == j] for j in jkts},
    "cases_without_cnf": sorted(c["id"] for c in vec["cases"] if "cnf" not in (c["input"].get("token_claims") or {})),
    "result": all(any(t == j for t in tps.values()) for j in jkts)}

# 3. Every proof's jwk is one of the derived keys; 4. any d derives from a seed.
per_case, d_checks = {}, []
for c in vec["cases"]:
    dp = c["input"]["dpop"]
    try:
        hdr = ck.json_object_no_dups(ck.b64url_decode(dp.split(".")[0]))
        x = hdr.get("jwk", {}).get("x")
    except Exception as e:  # noqa: BLE001
        per_case[c["id"]] = "header not decodable: %s" % e
        continue
    per_case[c["id"]] = [l for l, d in derived.items() if d["x_derived"] == x] or "not a derived key"
    if "d" in hdr.get("jwk", {}):
        d = hdr["jwk"]["d"]
        d_checks.append({"case": c["id"], "d_matches_seed_of": [l for l, v in derived.items() if v["seed_b64url"] == d],
                         "d_public_key_equals_jwk_x": ck.b64url_encode(Ed25519PrivateKey.from_private_bytes(
                             ck.b64url_decode(d)).public_key().public_bytes(serialization.Encoding.Raw,
                                                                            serialization.PublicFormat.Raw)) == x})
checks["K3_every_proof_jwk_is_a_derived_key"] = {"result": all(isinstance(v, list) for v in per_case.values()),
                                                 "per_case": per_case}
checks["K4_private_d_derives_from_a_stated_seed"] = {"result": bool(d_checks) and all(x["d_matches_seed_of"] for x in d_checks),
                                                     "cases_with_d": d_checks}

# Final verdicts: C1 fixed to B and C5 fixed to A by CANDIDATE.md's axis definitions.
FIXED = {"C1_item3_axis": "B", "C5_freshness_axis": "A"}


def judge_final(facts, outcome, override=None):
    override = override or {}
    primary = dict(ck.PRIMARY, **FIXED)
    pv, pparts = ck.evaluate(facts, outcome, primary, override)
    by = {}
    for rd in ck.readings_all():
        if any(rd[k] != v for k, v in FIXED.items()):
            continue
        by["".join(rd[k] for k in sorted(rd))] = ck.evaluate(facts, outcome, rd, override)[0]
    vs = sorted(set(by.values()))
    if len(vs) == 1:
        return vs[0], pv, pparts, None
    flips = []
    for k in sorted(ck.CHOICES):
        if k in FIXED:
            continue
        v, p = ck.evaluate(facts, outcome, dict(primary, **{k: "B"}), override)
        if v != pv:
            flips.append({"choice": k, "reading_A": ck.CHOICES[k][0], "verdict_A": pv,
                          "reading_B": ck.CHOICES[k][1], "verdict_B": v,
                          "parts_that_change": sorted(n for n in p if p[n]["holds"] != pparts[n]["holds"])})
    return "ambiguous", pv, pparts, {"verdicts_over_remaining_readings": vs,
                                     "single_choices_that_flip_the_primary_verdict": flips,
                                     "verdict_by_reading": by, "readings_order": sorted(ck.CHOICES)}


results, base, facts_by = [], {}, {}
for c in blind["cases"]:
    f = ck.compute_facts(c["input"])
    facts_by[c["id"]] = f
    v, pv, parts, amb = judge_final(f, c["outcome"])
    base[c["id"]] = v
    o = orig[idmap[c["id"]]]
    results.append({"id": c["id"], "original_id": idmap[c["id"]], "verdict": v,
                    "verdict_under_primary_reading": pv, "expect": o["expect"],
                    "match": v == o["expect"], "parts_under_primary_reading": parts, "ambiguity": amb})
sens = {}
for r in ck.ALL_RULES:
    ch = []
    for c in blind["cases"]:
        v = judge_final(facts_by[c["id"]], c["outcome"], {r: lambda _v: True})[0]
        if v != base[c["id"]]:
            ch.append({"case": c["id"], "original_id": idmap[c["id"]], "from": base[c["id"]], "to": v})
    sens[r] = {"removed": ch, "no_case_depends_on_removal": not ch}
tally = {}
for r in results:
    tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
doc = {"fixed_readings": FIXED,
       "fixed_by": "CANDIDATE.md, 'The answer is read on four separate axes': proof_signature covers RFC 9449 4.3 items 2 to 7 (item 3 included); request_binding covers items 8 to 11 and section 11.1",
       "tally": tally, "matches": sum(r["match"] for r in results), "cases": len(results),
       "results": sorted(results, key=lambda r: r["original_id"]),
       "sensitivity_removed_under_final_readings": sens,
       "key_and_claim_checks": checks}
with open(os.path.join(out_dir, "final.json"), "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
    fh.write("\n")
print("tally:", json.dumps(tally, sort_keys=True), "matches:", doc["matches"], "of", doc["cases"])
for r in doc["results"]:
    print(r["original_id"], r["id"], r["verdict"], "expect", r["expect"], "match" if r["match"] else "DIVERGE")
for k in sorted(checks):
    print(k, "->", checks[k]["result"])
print(json.dumps({k: v for k, v in checks.items() if k != "K3_every_proof_jwk_is_a_derived_key"}, indent=1, sort_keys=True))
print("K3 per case:", json.dumps(checks["K3_every_proof_jwk_is_a_derived_key"]["per_case"], sort_keys=True))
for r, v in sens.items():
    print("sens(final) %s removed -> %s" % (r, [x["original_id"] for x in v["removed"]]))
