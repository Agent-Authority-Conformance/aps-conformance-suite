"""Re-execution of the HJS side's documented path over this corpus's ten distinct
canonical-bytes cases at 70d503f: hjs_jcs.py pinned at hjs-spec/hjs-05 bb6be62 over
jcs==0.2.1. The observation of record for this direction is the HJS report at the same
commit; this script confirms that the pinned files reproduce it.
Run: pip install jcs==0.2.1 && python3 rerun-hjs-over-aps.py > results-hjs-jcs-0.2.1-over-aps.json
"""
import hashlib, importlib.util, json, sys, urllib.request
PIN = "bb6be62fd28911c02ff31f61db8c023757ef2243"
HJS_JCS_SHA256 = "14d89acdd4bb0865da9012cec9b9f5910e4500b35f808375adbd05d43956ce7d"
APS_PIN = "70d503ffd5f29d84f2100731bd0511667e851131"
src = urllib.request.urlopen(f"https://raw.githubusercontent.com/hjs-spec/hjs-05/{PIN}/hjs_jcs.py").read()
if hashlib.sha256(src).hexdigest() != HJS_JCS_SHA256:
    sys.exit("hjs_jcs.py does not hash to the pinned value")
spec = importlib.util.spec_from_loader("hjs_jcs", loader=None); hjs_jcs = importlib.util.module_from_spec(spec); exec(src, hjs_jcs.__dict__)
import importlib.metadata as m
ours = {}
for f in ("canonical-bytes-jcs-v1.json", "canonical-bytes-jcs-v2.json"):
    d = json.loads(urllib.request.urlopen(f"https://raw.githubusercontent.com/Agent-Authority-Conformance/aps-conformance-suite/{APS_PIN}/fixtures/canonical-bytes/{f}").read())
    for v in d["vectors"]: ours[v["name"]] = v
out = {"witness": "hjs_jcs.py at bb6be62 over jcs", "jcs_version": m.version("jcs"), "aps_pin": APS_PIN, "cases": []}
ok = True
for n, v in ours.items():
    b = hjs_jcs.canonicalize_jcs(v["input"]); h = b.hex(); s = hjs_jcs.canonical_sha256(v["input"])
    bm, dm = h == v["canonical_bytes_hex"], s == v["canonical_sha256"]; ok = ok and bm and dm
    out["cases"].append({"name": n, "observed_bytes_hex": h, "observed_sha256": s, "bytes_match": bm, "digest_match": dm})
out["all_match"] = ok
print(json.dumps(out, indent=2)); sys.exit(0 if ok else 1)
