#!/usr/bin/env python3
"""Summarize r2 result files into a Markdown table for RUNS.md. Read-only."""
import glob, json, os, sys

d = sys.argv[1] if len(sys.argv) > 1 else "out"
rows, tot = [], {"AGREE": 0, "DIFF": 0, "ERROR": 0, "RECORD": 0}
for f in sorted(glob.glob(f"{d}/*.json")):
    j = json.load(open(f))
    name = os.path.basename(f)
    if "meta" in j:
        m, res = j["meta"], j["results"]
        t = m["tally"]
        stale = {}
        for r in res:
            if r["case"][3:4] and r["scenario"] in ("PR", "RG") and r.get("last_stale_start_after_ack_s") is not None:
                key = r["scenario"]
                stale[key] = max(stale.get(key, 0), r["last_stale_start_after_ack_s"])
        gaps = [r["start_after_ack_s"] for r in res if r["scenario"] == "IM" and "start_after_ack_s" in r]
        proc = (m.get("server_process") or ["?"])[0]
        proc = " ".join(proc.split()[1:]).replace("--grpc-preshared-key rplabkey", "--grpc-preshared-key <local>")
        rows.append(f"| {name} | `{proc}` | {m['bound_s']} s, {m['bound_class']} | {m['tolerance_s']} s | "
                    f"{t['AGREE']} | {t['DIFF']} | {t['ERROR']} | {t['RECORD']} | "
                    f"{max(gaps) if gaps else '-'} | {stale.get('PR', 'none')} | {stale.get('RG', 'none')} |")
    else:
        t = {"AGREE": j["agree"], "DIFF": j["diff"], "ERROR": j.get("error", 0),
             "RECORD": sum(r["verdict"] == "RECORD" for r in j["results"])}
        rows.append(f"| {name} | same server as r2-c1 | n/a | n/a | {t['AGREE']} | {t['DIFF']} | {t['ERROR']} | {t['RECORD']} | - | - | - |")
    for k in tot:
        tot[k] += t[k]
print("| file | server process (as recorded by pgrep) | bound, class | tolerance | AGREE | DIFF | ERROR | RECORD | max IM start after ack (s) | last stale PR start after ack (s) | last stale RG start after ack (s) |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
print("\n".join(rows))
print(f"\nTotals: AGREE {tot['AGREE']}, DIFF {tot['DIFF']}, ERROR {tot['ERROR']}, RECORD {tot['RECORD']}")
