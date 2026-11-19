#!/usr/bin/env bash
# Inputs for the outside reading of the aicent-lease-boundary candidate.
# Downloads exactly the pinned candidate files, checks their SHA-256, takes the
# draft from a supplied copy or the IETF archive, and writes a blind copy of the
# cases (basis, inputs and outcomes only) for the first phase.
# Run with bash, not sh:  bash aicent-lease-boundary-reading-1-fetch-inputs.sh
#
# Exit codes: 0 done; 1 a digest check failed; 2 the draft could not be obtained.
set -euo pipefail
export LC_ALL=C

LAB_COMMIT=0e0064bf2cc6b221bb0b22c893964e389fa7aa3d
RAW="https://raw.githubusercontent.com/Agent-Authority-Conformance/aps-conformance-suite/${LAB_COMMIT}/candidates/aicent-lease-boundary"
SHA_VECTORS=71735739303dcbc248e3939535d754c702d00109cb4c6f1b4a02316ff29d773c
SHA_CANDIDATE=076693695c6142dabe98046ca4c47bb80bee733309726316f5902a793d56ad6f
DRAFT=draft-li-rttp-iqa-addressing-02.txt
SHA_DRAFT=02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044
SEARCH_DIRS=". /mnt/user-data/uploads ${HOME}"

mkdir -p inputs/blind inputs/sealed inputs/draft

check() {  # check <file> <sha256>
  local got
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$got" != "$2" ]; then
    echo "SHA-256 MISMATCH for $1: got $got, expected $2. Stop and report." >&2
    exit 1
  fi
  echo "ok  $1"
}

# 1. The candidate's vectors and description, sealed until phase 1 is saved.
#    check.py and mutate.py are deliberately not downloaded.
curl -fsSL "$RAW/vectors.json" -o inputs/sealed/vectors.json
curl -fsSL "$RAW/CANDIDATE.md" -o inputs/sealed/CANDIDATE.md
check inputs/sealed/vectors.json "$SHA_VECTORS"
check inputs/sealed/CANDIDATE.md "$SHA_CANDIDATE"

# 2. The draft. A supplied copy is found by its digest, whatever the file is
#    called; otherwise the IETF archive. The digest decides, not the source.
found=""
for d in $SEARCH_DIRS; do
  [ -d "$d" ] || continue
  for f in "$d"/*.txt; do
    [ -f "$f" ] || continue
    case "$f" in */inputs/*) continue ;; esac
    if [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$SHA_DRAFT" ]; then
      cp "$f" "inputs/draft/$DRAFT"; found="supplied copy $f"; break 2
    fi
  done
done
if [ -z "$found" ]; then
  if curl -fsSL "https://www.ietf.org/archive/id/$DRAFT" -o "inputs/draft/$DRAFT" 2>/dev/null; then
    found="https://www.ietf.org/archive/id/$DRAFT"
  else
    rm -f "inputs/draft/$DRAFT"
    echo "$DRAFT could not be obtained. Upload it (https://www.ietf.org/archive/id/$DRAFT) to the working directory and run this script again." >&2
    exit 2
  fi
fi
check "inputs/draft/$DRAFT" "$SHA_DRAFT"
echo "draft read from: $found"

# 3. The blind copy: the representation rules and, per case, only basis,
#    input and outcome, under new identifiers in a fixed shuffled order.
#    rule, note, expect and expect_parts stay in the sealed file.
python3 -I - <<'PY'
import hashlib, json
src = json.load(open("inputs/sealed/vectors.json", encoding="utf-8"))
keep_top = ["label", "revision", "text_status", "readings", "absent_fields",
            "field_names", "sources", "verdicts"]
cases = sorted(src["cases"], key=lambda c: hashlib.sha256(c["id"].encode()).hexdigest())
blind, idmap = [], {}
for n, c in enumerate(cases, 1):
    bid = f"B{n:02d}"
    idmap[bid] = c["id"]
    blind.append({"id": bid, "basis": c["basis"], "input": c["input"], "outcome": c["outcome"]})
out = {k: src[k] for k in keep_top if k in src}
out["note_on_this_copy"] = ("blind copy made by the fetch script: per case only basis, input "
                            "and outcome; identifiers replaced; rule, note, expect and "
                            "expect_parts withheld until phase 1 is saved")
out["cases"] = blind
json.dump(out, open("inputs/blind/cases.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1, sort_keys=False)
json.dump(idmap, open("inputs/sealed/id-map.json", "w", encoding="utf-8"), indent=1)
print(f"blind copy: {len(blind)} cases")
PY

# 4. Digests of everything, and a copy of this script beside them.
cp "$0" inputs/ 2>/dev/null || true
( cd inputs && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "done: inputs/SHA256SUMS"
