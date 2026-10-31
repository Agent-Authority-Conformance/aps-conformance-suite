#!/usr/bin/env python3
"""Weaken each rule in a plausible way and show that some case catches it. Exit 0 when every mutant is killed."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check

M = {
 "R-ADMIT: admit anything": ("R-ADMIT", lambda i, o: "conformant"),
 "R-FTS: trust the receipt only": ("R-FTS", lambda i, o: "conformant" if o["receipt"]["operation_completed"] in (True, False) else "nonconformant"),
 "R-FTS: allow a mid-call stop": ("R-FTS", lambda i, o: "conformant" if o["receipt"]["operation_completed"] == o["observer"]["completed"] else "nonconformant"),
 "R-SAC: strictly after instead of at or after": ("R-SAC", lambda i, o: (lambda t: "ambiguous" if t is None else ("conformant" if o["receipt"]["checkpoint_id"] == t else "nonconformant"))(
     (sorted((ts, c) for c, ts in i["call"]["checkpoints"].items() if ts > i["t_observed"]) or [(None, None)])[0][1])),
 "R-SAC: no tail ambiguity": ("R-SAC", lambda i, o: "conformant" if o["receipt"]["operation_completed"] in (True, False) else "nonconformant"),
 "R-OBS: compare completion only": ("R-OBS", lambda i, o: "conformant" if o["receipt"]["operation_completed"] == o["observer"]["completed"] else "nonconformant"),
 "R-NOTDET: any PAUSE passes": ("R-NOTDET", lambda i, o: "conformant" if o.get("state") == "PAUSE" else "nonconformant"),
 "R-NOTDET: any state passes": ("R-NOTDET", lambda i, o: "conformant" if (o.get("receipt") or {}).get("determination") != "authority_revoked" else "nonconformant"),
 "R-INCOMPLETE: any set value passes": ("R-INCOMPLETE", lambda i, o: "conformant" if ((o.get("receipt") or {}).get("incomplete_check") or {}).get("reason") in check.INCOMPLETE_SET else "ambiguous"),
 "R-EXEMPT: exemption covers everything": ("R-EXEMPT", lambda i, o: "conformant"),
 "R-EXEMPT: not_determined coverable": ("R-EXEMPT", lambda i, o: "nonconformant" if (i["halt_cause"] == "authority_revoked" and o.get("state") == "RESUMED") else "conformant"),
 "R-RESTORE: verifier role optional": ("R-RESTORE", lambda i, o: "conformant" if (i["restore"]["evidence_list"] and i["restore"]["validity_window"]) == (o.get("state") == "RESUMED") else "nonconformant"),
 "R-ROLLBACK: failed rollback may resume": ("R-ROLLBACK", lambda i, o: "conformant"),
 "R-ONEWAY: regime ignored": ("R-ONEWAY", lambda i, o: "conformant"),
 "R-RECUR: resume is final": ("R-RECUR", lambda i, o: "conformant"),
 "R-WINDOW: closed window may resume": ("R-WINDOW", lambda i, o: "conformant"),
 "R-WINDOW: reason not recorded": ("R-WINDOW", lambda i, o: "conformant" if o.get("state") == "PAUSE" else "nonconformant"),
 "R-SPLIT: score admission only": ("R-SPLIT", lambda i, o: check.r_admit(i, o)),
 "R-SPLIT: score effects only": ("R-SPLIT", lambda i, o: check.r_fts(i, o)),
}

for _r in list(check.RULES):
    M[f"{_r}: always nonconformant"] = (_r, lambda i, o: "nonconformant")

def main():
    cases = json.load(open(os.path.join(HERE, "vectors.json")))["cases"]
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
