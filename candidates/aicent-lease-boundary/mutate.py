#!/usr/bin/env python3
"""Weaken or distort each rule in a plausible way and show that some case catches it.
Exit 0 when every mutant is killed."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check

def _flip_declared(i, o):
    d = i.get("declared_boundary")
    if d == "fresh_at_instant":
        return "conformant" if o.get("reason") == "evidence_expired" else "nonconformant"
    if d == "expired_at_instant":
        return "conformant" if o.get("reason") is None else "nonconformant"
    return check.RULES["R-DECLARED"](i, o)

M = {
 "R-DECLARED: undeclared boundary decided inclusive": ("R-DECLARED", lambda i, o:
    ("conformant" if o.get("reason") is None else "nonconformant")
    if i.get("declared_boundary") is None else check.RULES["R-DECLARED"](i, o)),
 "R-DECLARED: declaration contradicts use": ("R-DECLARED", _flip_declared),
 "R-DECLARED: frame acceptance read as reliance": ("R-DECLARED", lambda i, o:
    ("conformant" if o.get("reason") is None else "nonconformant")
    if i.get("frame_accepted_at_equality") else check.RULES["R-DECLARED"](i, o)),
 "R-NOEXTEND: replay as fresh accepted": ("R-NOEXTEND", lambda i, o:
    "conformant" if (i["now_ms"] > i["lease_expiry_ms"] and o.get("reason") is None
     and (o.get("grant_ref") or {}).get("observation_as_of_ms") is not None)
    else check.RULES["R-NOEXTEND"](i, o)),
 "R-NOEXTEND: grace reinterpretation accepted": ("R-NOEXTEND", lambda i, o:
    "conformant" if (i["now_ms"] > i["lease_expiry_ms"] and i.get("grace_added")
     and o.get("reason") is None)
    else check.RULES["R-NOEXTEND"](i, o)),
 "R-MODE: cache rescues live mode": ("R-MODE", lambda i, o:
    "conformant" if (i["mode"] == "live" and i.get("organ_unreachable")
     and i.get("cache_fresh") and o.get("reason") is None)
    else check.RULES["R-MODE"](i, o)),
 "R-MODE: policy ignored in cached mode": ("R-MODE", lambda i, o:
    ("conformant" if o.get("reason") == "authority_not_determined" else "nonconformant")
    if (i["mode"] == "cached" and i.get("organ_unreachable") and i.get("cache_fresh"))
    else check.RULES["R-MODE"](i, o)),
 "R-MODE: cache age ignored": ("R-MODE", lambda i, o:
    check.RULES["R-MODE"]({**i, "cache_fresh": True}, o)
    if i["mode"] == "cached" else check.RULES["R-MODE"](i, o)),
 "R-WINDOW: default window assumed": ("R-WINDOW", lambda i, o:
    ("conformant" if o.get("reason") == "evidence_expired" else "nonconformant")
    if i["now_ms"] >= i["issued_at_ms"] + 120000 else check.RULES["R-WINDOW"](i, o)),
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
