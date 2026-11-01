#!/usr/bin/env python3
"""Weaken or distort each rule in a plausible way and show that some case catches it.
Exit 0 when every mutant is killed."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check

def _value_part(i, o):
    exp = check.first_applicable(i)
    return "conformant" if o.get("reason") == exp else "nonconformant"

M = {
 "R-ORDER: drop priority, keep null split": ("R-ORDER", lambda i, o:
    "conformant" if (o.get("reason") is None) == (check.first_applicable(i) is None) else "nonconformant"),
 "R-ORDER: race boundary decided": ("R-ORDER", lambda i, o:
    _value_part(i, o) if i.get("race_boundary") else check.RULES["R-ORDER"](i, o)),
 "R-NOTDET: assent accepted": ("R-NOTDET", lambda i, o:
    "conformant" if o.get("reason") is None else check.RULES["R-NOTDET"](i, o)),
 "R-NOTDET: label computation decided": ("R-NOTDET", lambda i, o:
    ("conformant" if o.get("reason") == "authority_not_determined" else "nonconformant")
    if i.get("computed_over") == "label" else check.RULES["R-NOTDET"](i, o)),
 "R-CLOSED: any present value accepted": ("R-CLOSED", lambda i, o:
    "conformant" if "reason" in o else "nonconformant"),
 "R-CLOSED: reason optional": ("R-CLOSED", lambda i, o:
    "conformant" if o.get("reason") in (None,) + check.FIVE else "nonconformant"),
 "R-NULLOBS: backfill accepted": ("R-NULLOBS", lambda i, o: (
    "nonconformant" if (i.get("diagnostic_read") and not (i.get("relied_on_observation") or {}).get("fresh")
     and (o.get("grant_ref") or {}).get("expires_at_ms") is not None
     and o["grant_ref"]["expires_at_ms"] > i["grant_expires_at_ms"]) else "conformant")),
 "R-NULLOBS: renewal accepted": ("R-NULLOBS", lambda i, o: (
    "nonconformant" if (not (i.get("relied_on_observation") or {}).get("present")
     or not i["relied_on_observation"].get("fresh")) and (o.get("grant_ref") or {}).get("observation_as_of_ms") is not None
    else "conformant")),
 "R-NULLOBS: member must never be null": ("R-NULLOBS", lambda i, o:
    "nonconformant" if (o.get("grant_ref") or {}).get("observation_as_of_ms") is None else "conformant"),
 "R-GRANTREF: observation member optional": ("R-GRANTREF", lambda i, o: (
    "conformant" if isinstance(o.get("grant_ref"), dict)
    and all(m in o["grant_ref"] for m in ("grant", "evidence_id", "issued_at_ms", "expires_at_ms"))
    else "nonconformant")),
 "R-GRANTREF: structure only": ("R-GRANTREF", lambda i, o:
    "conformant" if isinstance(o.get("grant_ref"), dict) else "nonconformant"),
}

for _r in list(check.RULES):
    M[f"{_r}: always nonconformant"] = (_r, lambda i, o: "nonconformant")
    M[f"{_r}: always conformant"] = (_r, lambda i, o: "conformant")

def main():
    cases = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))["cases"]
    killed = 0
    for name, (rule, fn) in M.items():
        rules = dict(check.RULES); rules[rule] = fn
        hits = [c["id"] for c in cases if c["rule"] == rule and check.evaluate(c, rules) != c["expect"]]
        killed += bool(hits)
        print(("killed " if hits else "ALIVE  ") + f"{name:45} by {','.join(hits) or '-'}")
    print(f"{killed}/{len(M)} mutants killed")
    return 0 if killed == len(M) else 1

if __name__ == "__main__":
    sys.exit(main())
