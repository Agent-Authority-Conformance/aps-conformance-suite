"""Direction 1 runner: attenu-guard 0.6.0 canonicalization vs the pinned JCS bytes.

Requires: pip install attenu-guard==0.6.0. Run from this directory or the repo root.
Exits nonzero if the match set differs from the recorded result (5/10 distinct).
"""
import json, pathlib, sys

from attenu_guard.wire import _canonical_json  # the package's canonicalization step

HERE = pathlib.Path(__file__).resolve()
ROOT = next(p for p in HERE.parents if (p / "fixtures").is_dir())
FIX = ROOT / "fixtures" / "canonical-bytes"

EXPECTED_MATCH = {
    "float-tenth", "float-1e21-boundary", "negative-zero",
    "integer-above-2pow53", "nested-object-and-array",
}

def main() -> int:
    seen, matches, diverges = {}, set(), set()
    for f in ("canonical-bytes-jcs-v1.json", "canonical-bytes-jcs-v2.json"):
        for v in json.load(open(FIX / f))["vectors"]:
            jcs = bytes.fromhex(v["canonical_bytes_hex"])
            theirs = _canonical_json(v["input"])
            prev = seen.get(v["name"])
            if prev is not None and prev != (theirs == jcs):
                print(f"INCONSISTENT across files: {v['name']}")
                return 2
            seen[v["name"]] = theirs == jcs
            (matches if theirs == jcs else diverges).add(v["name"])
            if theirs != jcs:
                i = next((k for k in range(min(len(jcs), len(theirs)))
                          if jcs[k] != theirs[k]), min(len(jcs), len(theirs)))
                print(f"DIVERGE {v['name']}")
                print(f"  jcs   : {jcs[max(0, i-12):i+24]!r}")
                print(f"  attenu: {theirs[max(0, i-12):i+24]!r}")
    print(f"\ndistinct cases: {len(seen)}  byte-identical: {len(matches)}")
    for n in sorted(matches):
        print(f"  match {n}")
    if matches != EXPECTED_MATCH:
        print("RESULT DRIFTED from the recorded 5/10 match set")
        return 1
    print("RESULT MATCHES the recorded run")
    return 0

if __name__ == "__main__":
    sys.exit(main())
