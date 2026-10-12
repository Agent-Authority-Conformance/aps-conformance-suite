"""Compare two published reader outputs with the vectors' recorded SDK output.

    python3 -I check-against-vectors.py VECTORS.json HS_RESULTS.json PROBITY_REPORT.json

Standard library only. Prints mismatches and exits 0. It decides nothing about
which outcome is correct.
"""
import hashlib, json, sys

PINS = {
    1: "9fce76dbf13de9749a2ef52c8dedecce08e4874da0203b39a7d941eb479b5ac5",
    2: "3547cb5167c818a6f739c38f4d83f4f7e5cd97d4282c798dba581350ab2c7a02",
    3: "1598f87559130cb0e7a2e4ca59e5d6a2a584b402149bc28baad30dd9eaa01df1",
}
raw = {}
for i in (1, 2, 3):
    raw[i] = open(sys.argv[i], "rb").read()
    got = hashlib.sha256(raw[i]).hexdigest()
    if got != PINS[i]:
        sys.exit("argument %d is not the pinned file (sha256 %s)" % (i, got))
vectors = {c["name"]: c["verification"] for c in json.loads(raw[1])["cases"]}
hs = json.loads(raw[2])["cases"]
probity = json.loads(raw[3])["cases"]
r1 = [c["name"] for c in hs
      if (c["reader"].get("state"), c["reader"].get("code"))
      != (vectors[c["name"]]["state"], vectors[c["name"]]["code"])]
r2 = [(c["name"], c["readerOutcome"], vectors[c["name"]]["state"]) for c in probity
      if c["readerOutcome"] != vectors[c["name"]]["state"]]
print("R1 cases %d, state and code differing from the vectors: %s" % (len(hs), r1 or "none"))
print("R2 cases %d, outcome differing from the vectors' state: %d" % (len(probity), len(r2)))
for name, theirs, ours in r2:
    print("  %s: R2 %s, vectors %s" % (name, theirs, ours))
