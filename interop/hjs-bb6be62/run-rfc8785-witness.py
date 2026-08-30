"""Independent witness for the HJS vector claims: Trail of Bits rfc8785 over the three
HJS vectors pinned at hjs-spec/hjs-05 bb6be62. No APS and no HJS code is imported.
Run: pip install rfc8785==0.1.4 && python3 run-rfc8785-witness.py > results-rfc8785-0.1.4.json
"""
import hashlib, json, sys, urllib.request
import rfc8785
PIN = "bb6be62fd28911c02ff31f61db8c023757ef2243"
URL = f"https://raw.githubusercontent.com/hjs-spec/hjs-05/{PIN}/fixtures/canonical-bytes/hjs-behavior-record-jcs-v1.json"
FIXTURE_SHA256 = "4f593700c1b25698906483171109c02f38b7e389454f49e2b7f4e0db80cda3f7"
raw = urllib.request.urlopen(URL).read()
got = hashlib.sha256(raw).hexdigest()
if got != FIXTURE_SHA256:
    sys.exit(f"fixture sha256 {got} != pinned {FIXTURE_SHA256}")
fx = json.loads(raw)
out = {"witness": "rfc8785 (Trail of Bits)", "python": sys.version.split()[0], "fixture_sha256": got, "cases": []}
ok = True
for v in fx["vectors"]:
    b = rfc8785.dumps(v["input"]); h = b.hex(); s = hashlib.sha256(b).hexdigest()
    bm, dm = h == v["canonical_bytes_hex"], s == v["canonical_sha256"]; ok = ok and bm and dm
    out["cases"].append({"name": v["name"], "observed_bytes_hex": h, "observed_sha256": s, "expected_bytes_hex": v["canonical_bytes_hex"], "expected_sha256": v["canonical_sha256"], "bytes_match": bm, "digest_match": dm, "length": len(b)})
out["all_match"] = ok
print(json.dumps(out, indent=2))
sys.exit(0 if ok else 1)
