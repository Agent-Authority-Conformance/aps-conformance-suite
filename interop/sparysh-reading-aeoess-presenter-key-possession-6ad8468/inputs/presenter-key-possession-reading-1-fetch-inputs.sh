#!/usr/bin/env bash
# Inputs for the outside reading of the aeoess-presenter-key-possession candidate.
# Downloads exactly the pinned candidate files, checks their SHA-256, takes the
# RFC texts from supplied copies or the RFC Editor, checks that Ed25519 is
# available, and writes a blind copy of the cases (inputs and outcomes only).
# Run with bash, not sh:  bash presenter-key-possession-reading-1-fetch-inputs.sh
#
# Exit codes: 0 done; 1 a digest or document check failed; 2 a required RFC text
# is missing; 3 the Python package `cryptography` is not available.
set -euo pipefail
export LC_ALL=C

LAB_COMMIT=6ad8468acfff6600356efb05e2a530366b1d9d96
RAW="https://raw.githubusercontent.com/Agent-Authority-Conformance/aps-conformance-suite/${LAB_COMMIT}/candidates/aeoess-presenter-key-possession"
SHA_VECTORS=7e108c346475fb6c213827f657c8a4feaa46e48d0f0b5f3e20f119d98296436f
SHA_CANDIDATE=e6562c79706903997574dc0c53d9e413d60dff46d88912b0650d330fa1034f5c
# RFC 9449 digest as pinned by the candidate (CANDIDATES.md index: sha256 3842c58e).
SHA_RFC9449=3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13
REQUIRED_RFCS="9449 7638 8037"
OPTIONAL_RFCS="7515 7517 7519 8032 3986 4648 2119 8174"
SEARCH_DIRS=". /mnt/user-data/uploads ${HOME}"

mkdir -p inputs/blind inputs/sealed inputs/rfc

check() {  # check <file> <sha256>
  local got
  got=$(sha256sum "$1" | cut -d' ' -f1)
  if [ "$got" != "$2" ]; then
    echo "SHA-256 MISMATCH for $1: got $got, expected $2. Stop and report." >&2
    exit 1
  fi
  echo "ok  $1"
}

is_rfc() {  # is_rfc <file> <number>: the RFC header names this number
  head -n 40 "$1" 2>/dev/null | grep -Eq "Request for Comments: $2([^0-9]|$)"
}

find_rfc() {  # find_rfc <number>: print the path of a supplied copy, if any
  local d f
  for d in $SEARCH_DIRS; do
    [ -d "$d" ] || continue
    for f in "$d"/*.txt; do
      [ -f "$f" ] || continue
      case "$f" in */inputs/*) continue ;; esac
      if is_rfc "$f" "$1"; then echo "$f"; return 0; fi
    done
  done
  return 1
}

# 1. The candidate's vectors and description, sealed until phase 1 is saved.
#    check.py, mutate.py and generate.py are deliberately not downloaded.
curl -fsSL "$RAW/vectors.json" -o inputs/sealed/vectors.json
curl -fsSL "$RAW/CANDIDATE.md" -o inputs/sealed/CANDIDATE.md
check inputs/sealed/vectors.json "$SHA_VECTORS"
check inputs/sealed/CANDIDATE.md "$SHA_CANDIDATE"

# 2. The blind copy: the representation statements and, per case, only input and
#    outcome, under new identifiers in a fixed shuffled order. title, basis,
#    rules, expect and the top-level keys block stay in the sealed file.
python3 -I - <<'PY'
import hashlib, json
src = json.load(open("inputs/sealed/vectors.json", encoding="utf-8"))
keep_top = ["label", "revision", "text_status", "readings", "now"]
cases = sorted(src["cases"], key=lambda c: hashlib.sha256(c["id"].encode()).hexdigest())
blind, idmap = [], {}
for n, c in enumerate(cases, 1):
    bid = f"B{n:02d}"
    idmap[bid] = c["id"]
    blind.append({"id": bid, "input": c["input"], "outcome": c["outcome"]})
out = {k: src[k] for k in keep_top if k in src}
out["note_on_this_copy"] = ("blind copy made by the fetch script: per case only input and "
                            "outcome; identifiers replaced; title, basis, rules and expect, "
                            "and the top-level keys block, withheld until phase 1 is saved")
out["cases"] = blind
json.dump(out, open("inputs/blind/cases.json", "w", encoding="utf-8"),
          ensure_ascii=False, indent=1, sort_keys=False)
json.dump(idmap, open("inputs/sealed/id-map.json", "w", encoding="utf-8"), indent=1)
print(f"blind copy: {len(blind)} cases")
PY

# 3. The RFC texts. A supplied copy is preferred (found by its header, whatever
#    the file is called), then the RFC Editor. RFC 9449 is checked against the
#    digest the candidate pins; for the others the digest is recorded.
for n in $REQUIRED_RFCS $OPTIONAL_RFCS; do
  dst="inputs/rfc/rfc$n.txt"
  src=""
  if src=$(find_rfc "$n"); then
    cp "$src" "$dst"
    echo "rfc$n read from: supplied copy $src"
  elif curl -fsSL "https://www.rfc-editor.org/rfc/rfc$n.txt" -o "$dst" 2>/dev/null && is_rfc "$dst" "$n"; then
    echo "rfc$n read from: https://www.rfc-editor.org/rfc/rfc$n.txt"
  else
    rm -f "$dst"
    case " $REQUIRED_RFCS " in
      *" $n "*)
        echo "RFC $n is required and could not be obtained. Upload rfc$n.txt (https://www.rfc-editor.org/rfc/rfc$n.txt) to the working directory and run this script again." >&2
        exit 2 ;;
      *) echo "rfc$n not supplied (optional)"; continue ;;
    esac
  fi
  if ! is_rfc "$dst" "$n"; then
    echo "inputs/rfc/rfc$n.txt does not carry the header of RFC $n. Stop and report." >&2
    exit 1
  fi
  if [ "$n" = 9449 ]; then
    check "$dst" "$SHA_RFC9449"
  else
    echo "recorded  $dst  $(sha256sum "$dst" | cut -d' ' -f1)"
  fi
done

# 4. Ed25519 for signature verification: the Python package `cryptography`.
probe='import cryptography; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey; print(cryptography.__version__)'
if ! ver=$(python3 -I -c "$probe" 2>/dev/null); then
  python3 -m pip install --quiet cryptography 2>/dev/null \
    || python3 -m pip install --quiet --break-system-packages cryptography 2>/dev/null || true
  if ! ver=$(python3 -I -c "$probe" 2>/dev/null); then
    echo "The Python package cryptography is not available and could not be installed. Stop and report." >&2
    exit 3
  fi
fi
echo "cryptography $ver"

# 5. Digests of everything, and a copy of this script beside them.
cp "$0" inputs/ 2>/dev/null || true
( cd inputs && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "done: inputs/SHA256SUMS"
