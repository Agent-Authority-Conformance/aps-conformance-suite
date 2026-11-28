"""Thin harness: feed the v1-annotations packet to Probity's map_reader and compare.

Transport and comparison only. Every axis and digest comes from Probity code
(map_reader.evaluate, map_reader.capture_digest, map_reader.read_jws,
map_reader.tool_key). The key and issuer come from Probity's committed
selection.json. run_agentavow.selected_fixture is not used because its lock
pins the v1 packet; instead this harness checks the packet bytes against the
SHA-256 kenneives published in lab #155 comment 6150434388.
Usage: PYTHONPATH=<reader dir> python harness.py <reader dir> <vectors.json>
"""
import hashlib, json, subprocess, sys
from pathlib import Path

reader_dir, packet = Path(sys.argv[1]), Path(sys.argv[2])
from map_reader import capture_digest, decode_base64url, evaluate, read_jws, tool_key

STATED = "3fbe9b22750956623aba5657bcd647d0fcbe2fcc844e2af72011b07f0463a4b2"
raw = packet.read_bytes()
fixture = json.loads(raw)
selection = json.loads((reader_dir / "selection.json").read_bytes())
jwk, issuer = selection["jwk"], selection["issuer"]
jws = fixture["attestation"]["jws"]
payload, _, _ = read_jws(jws, jwk)
signed = payload["scan"]["toolDigests"]

definitions = [
    {"tool": t["name"],
     "matches": capture_digest(fixture["observed_tools"], t["name"]) == signed[tool_key(t["name"])]}
    for t in fixture["observed_tools"]
]
drift = fixture["drift_definition"]
drift_gate = next(v for v in fixture["vectors"] if v["name"] == "annotation-drift")["gate"]
drift_digest_matches_gate = capture_digest([drift], drift["name"]) == drift_gate["observed_tool_digest"]

results = []
for case in fixture["vectors"]:
    candidate = jws if case["jws"] == "reference" else case["jws"]
    actual = evaluate(candidate, jwk, issuer, case["gate"])
    matches = all(actual[axis] == value for axis, value in case["expect"].items())
    results.append({"name": case["name"], "axes": actual, "matches": matches})

payload_digest = hashlib.sha256(decode_base64url(jws.split(".")[1])).hexdigest()
reader_rev = subprocess.run(["git", "-C", str(reader_dir), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
report = {
    "harness": "aeoess thin harness over Probity map_reader (transport and comparison only)",
    "reader_revision": reader_rev,
    "map_reader_sha256": hashlib.sha256((reader_dir / "map_reader.py").read_bytes()).hexdigest(),
    "packet_sha256": hashlib.sha256(raw).hexdigest(),
    "packet_sha256_matches_stated": hashlib.sha256(raw).hexdigest() == STATED,
    "selection_key_kid": jwk["kid"],
    "definition_matches": definitions,
    "drift_definition_digest_matches_gate": drift_digest_matches_gate,
    "payload_sha256": payload_digest,
    "payload_digest_matches": payload_digest == fixture["attestation"]["payload_sha256"].removeprefix("sha256:"),
    "results": results,
}
report["passed"] = (report["packet_sha256_matches_stated"] and all(d["matches"] for d in definitions)
                    and drift_digest_matches_gate and report["payload_digest_matches"]
                    and all(r["matches"] for r in results))
print(json.dumps(report, indent=2, default=str))
raise SystemExit(0 if report["passed"] else 1)
