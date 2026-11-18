#!/usr/bin/env python3
"""Offline rescoring of the saved r2.1 records with the r2.2 scoring code.
No server. Reads ../runs/*.json, recomputes every PR and RG window verdict with
r2.2 score_window and sample_errors, and re-judges the saved CX-09 body with
r2.2 judge_cx09. Exit 0 only if every saved verdict is reproduced."""
import glob, importlib.util, json, os, sys

HERE = os.path.dirname(__file__) or "."
RUNS = os.path.join(HERE, "..", "runs")


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


rp2, cx = load("rp2"), load("rp_cond2")
windows = same = errors = 0
for f in sorted(glob.glob(os.path.join(RUNS, "*.json"))):
    j = json.load(open(f))
    if "meta" not in j:
        continue
    m = j["meta"]
    for r in j["results"]:
        if "samples" not in r:
            continue
        windows += 1
        samples = [tuple(s) for s in r["samples"]]
        errors += len(rp2.sample_errors(samples))
        v, _, _ = rp2.score_window(samples, r["ack_end"], m["bound_s"], m["tolerance_s"], r["expected"])
        if v == r["verdict"]:
            same += 1
        else:
            print("MISMATCH", os.path.basename(f), r["case"], r["verdict"], v)
cxf = os.path.join(RUNS, "openfga-cx-r2-c1-cache.json")
row = [r for r in json.load(open(cxf))["results"] if r["case"] == "CX-09"][0]
body = json.loads(row["note"].split("body=", 1)[1])
cx09 = cx.judge_cx09(400, body)
print(f"windows {windows}, reproduced {same}, error samples {errors}")
print(f"saved CX-09 body re-judged: {cx09} (saved verdict {row['verdict']}, status 400 taken from the saved observed value)")
ok = windows == same and errors == 0 and cx09 == "ERROR400-names-current_time"
print("RESCORE", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
