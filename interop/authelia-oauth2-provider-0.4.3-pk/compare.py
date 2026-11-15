"""Compare an implementation's answers with the candidate's reference axes.
Possession only: reference decision is accept iff proof_signature, key_binding and
request_binding are all True (authority is outside RFC 9449 and not evaluated).
For a reject, also checks that the reported axis is one that actually failed (R-DECISION reading).
Usage: python3 -I compare.py <candidate dir> vectors.json results.json"""
import json, sys
sys.path.insert(0, sys.argv[1])
import check  # noqa: E402

POSS = ("proof_signature", "key_binding", "request_binding")
doc = json.load(open(sys.argv[2]))
res = {r["id"]: r for r in json.load(open(sys.argv[3]))}
agree = differ = amb = nr = axis_ok = axis_bad = 0
for c in doc["cases"]:
    t = check.truth(c["input"])
    vals = [t[a] for a in POSS]
    ref = "reject" if any(v is False for v in vals) else ("ambiguous" if any(v == "ambiguous" for v in vals) else "accept")
    got = res[c["id"]]
    failing = [a for a in POSS if t[a] is False]
    if got["decision"] == "not_run":
        nr += 1
        print(f"SKIP {c['id']} {got['error']}")
        continue
    if ref == "ambiguous":
        tag, amb = "AMB ", amb + 1
    elif ref == got["decision"]:
        tag, agree = "ok  ", agree + 1
    else:
        tag, differ = "DIFF", differ + 1
    ax = ""
    if got["decision"] == "reject" and ref == "reject":
        if got.get("axis") in failing:
            axis_ok += 1; ax = "axis ok"
        else:
            axis_bad += 1; ax = "AXIS-DIFF"
    print(f"{tag} {c['id']} ref={ref:<6} impl={got['decision']:<6} ref_failing={','.join(failing) or '-':<32} impl_axis={got.get('axis','-'):<15} {ax}")
print(f"agree={agree} differ={differ} ambiguous={amb} not_run={nr} of {len(doc['cases'])}; reject axis named a failing axis: {axis_ok}, did not: {axis_bad}")
sys.exit(1 if differ or axis_bad else 0)
