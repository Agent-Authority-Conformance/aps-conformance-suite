#!/usr/bin/env python3
"""Render markdown tables from out/phase1.json, out/phase1-sensitivity.json and out/final.json.
Usage: python3 -I reader/tables.py <out-dir>   (prints markdown)"""
import json, os, sys
o = sys.argv[1]
p1 = json.load(open(os.path.join(o, "phase1.json")))
se = json.load(open(os.path.join(o, "phase1-sensitivity.json")))
fi = json.load(open(os.path.join(o, "final.json")))
idm = {r["id"]: r["original_id"] for r in fi["results"]}
ph1 = {r["id"]: r for r in p1["results"]}
print("### Per-case table\n")
print("| Original | Blind | Phase 1 | Final | Expected | Final vs expected |")
print("|---|---|---|---|---|---|")
for r in fi["results"]:
    print("| %s | %s | %s | %s | %s | %s |" % (r["original_id"], r["id"], ph1[r["id"]]["verdict"], r["verdict"],
                                             r["expect"], "match" if r["match"] else "diverge"))
print("\n### Facts table\n")
print("Recomputed from the bytes of each case. `sig`: Ed25519 verification with the proof's own `jwk` (4.3 item 6). "
      "`jkt`: thumbprint computed from the proof `jwk` (RFC 7638, RFC 8037), shown as its first 8 characters, and whether it equals the token's `cnf.jkt` "
      "(`cOcBgQLw...` in every case that has one). `ath`: computed `ath` equals the proof's (4.3 item 12); the computed value is "
      "`%s` in every case. `now-iat`: seconds (4.3 item 11). `failing`: every condition of the checker that does not hold.\n"
      % p1["facts"]["B01"]["R12a_ath_matches"]["ath_computed"])
print("| Original | Blind | typ | alg | sig | private member | htm / method | htu (normalised) | nonce (server / proof) | now-iat | ath | jkt (computed / match) | scope ok | replay | failing |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
for r in fi["results"]:
    f = p1["facts"][r["id"]]
    def g(k, a):
        v = f[k].get(a)
        return "null" if v is None and a not in ("ath_in_proof", "cnf_jkt", "thumbprint_computed") else v
    tp = g("R12b_key_bound_matches", "thumbprint_computed")
    fail = [k.split("_")[0] for k, v in sorted(f.items()) if not v["holds"]]
    print("| %s | %s | %s | %s | %s | %s | %s / %s | %s | %s / %s | %s | %s | %s / %s | %s | %s | %s |" % (
        r["original_id"], r["id"], g("R04_typ", "typ"), g("R05_alg", "alg"),
        "verifies" if f["R06_signature"]["holds"] else "fails (%s)" % g("R06_signature", "reason"),
        ",".join(g("R07_no_private_key", "private_members")) or "none",
        g("R08_htm", "htm"), g("R08_htm", "method"),
        "equal" if f["R09_htu"]["holds"] else "%s vs %s" % (g("R09_htu", "htu_normalised"), g("R09_htu", "uri_normalised")),
        g("R10_nonce", "server_nonce"), g("R10_nonce", "nonce"),
        g("R11_iat_not_too_old", "now_minus_iat"),
        "absent" if g("R12a_ath_matches", "ath_in_proof") is None else ("equal" if f["R12a_ath_matches"]["holds"] else "differs: " + g("R12a_ath_matches", "ath_in_proof")[:8] + "..."),
        (tp or "")[:8] + "...", ("no cnf" if g("R12b_key_bound_matches", "cnf_jkt") is None else ("yes" if f["R12b_key_bound_matches"]["holds"] else "no")),
        "yes" if f["RS_scope_contains_required"]["holds"] else "no (%s)" % g("RS_scope_contains_required", "required_scope"),
        "yes" if g("R13_jti_not_replayed", "replay") else "no",
        ", ".join(fail) or "none"))
print("\n### Sensitivity table (phase 1, all four choice points evaluated both ways)\n")
print("| Rule | Cases whose verdict changes when the rule is removed | Cases whose verdict changes when the rule is inverted | Removal under final readings |")
print("|---|---|---|---|")
fs = fi["sensitivity_removed_under_final_readings"]
for k in sorted(x for x in se if not x.startswith("reading")):
    rem = ", ".join("%s (%s, %s->%s)" % (idm[c["case"]], c["case"], c["from"], c["to"]) for c in se[k]["removed"]) or "none"
    inv = ", ".join("%s" % idm[c["case"]] for c in se[k]["inverted"]) or "none"
    fr = ", ".join(c["original_id"] for c in fs[k]["removed"]) or "none"
    print("| %s | %s | %s | %s |" % (k, rem, inv, fr))
print("\nChoice points fixed one way for every case (phase 1):\n")
print("| Choice fixed | Cases whose verdict differs from the phase-1 verdict |")
print("|---|---|")
for k in sorted(x for x in se if x.startswith("reading")):
    print("| %s | %s |" % (k.replace("reading ", ""), ", ".join("%s (%s) -> %s" % (idm[c["case"]], c["case"], c["to"]) for c in se[k]["changed"]) or "none"))
