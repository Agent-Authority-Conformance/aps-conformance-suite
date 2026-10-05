# Recomputes the identifiers of the members that have no context with GNU coreutils sha256sum.
# This script only reads the manifest, invokes sha256sum on each receipt file and compares strings.
import json, subprocess, sys
m = json.load(open(sys.argv[1] + "/MANIFEST.json"))
ents = next(v for v in m.values() if isinstance(v, list) and v and isinstance(v[0], dict) and "file" in v[0])
ok = 0
for e in ents:
    if e.get("context"):
        print(f"{e['id']}  NOT COVERED (has a context)")
        continue
    h = subprocess.run(["sha256sum", sys.argv[1] + "/" + e["file"]], capture_output=True, text=True, check=True).stdout.split()[0]
    match = e["id"] == "v" + h[:16]
    ok += match
    print(f"{e['id']}  {h}  {'MATCH' if match else 'MISMATCH'}")
print(f"no-context identifiers matching: {ok}")
