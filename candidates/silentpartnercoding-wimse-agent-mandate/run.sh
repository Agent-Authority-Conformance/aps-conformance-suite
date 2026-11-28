#!/bin/sh
# Check this candidate against its pinned source, then run the source's
# checker, regeneration and tests at that pin.
#
#   sh run.sh            needs git, python3 (3.10+) with venv, and shasum or sha256sum
#
# Network steps: the clone, and pip installing the pinned requirements.txt.
#
# The 36 files listed in CHECKSUMS.sha256 are byte copies of the source at the
# pin. Each is compared with the same path in that clone before anything runs.
# Written for this candidate: CANDIDATE.md, CHECKSUMS.sha256, run.sh.
# check.py, generate.py, tests/, keys/ and profile/ are used from the clone.
set -eu
PIN=52653c2d1f3622baa4d3c3c5ddebd9f5b12557ca
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi

git clone -q https://github.com/Silentpartnercoding/wimse-agent-mandate-vectors "$WORK/src"
git -C "$WORK/src" checkout -q "$PIN"
cd "$WORK/src"

echo "== candidate bytes equal the source at $PIN"
grep -v '^#' "$HERE/CHECKSUMS.sha256" | $SUM -c --quiet -
(cd "$HERE" && grep -v '^#' CHECKSUMS.sha256 | $SUM -c --quiet -)
echo "ok: $(grep -vc '^#' "$HERE/CHECKSUMS.sha256") files"

python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q -r requirements.txt
PY="$WORK/venv/bin/python"

echo "== check.py: every case against its expected result"
"$PY" check.py

echo "== regeneration: generate.py rebuilds every case file byte for byte"
"$PY" generate.py "$WORK/regen" > /dev/null
for tree in cases keys profile; do
  if ! diff -qr "$WORK/regen/$tree" "$WORK/src/$tree"; then
    echo "FAIL: regenerated $tree differs from the published bytes"
    exit 1
  fi
done
if ! cmp -s "$WORK/regen/trust-anchors.json" "$WORK/src/trust-anchors.json"; then
  echo "FAIL: regenerated trust anchors differ from the published bytes"
  exit 1
fi
echo "ok: rebuild is byte-identical"

echo "== tests"
"$PY" -W ignore::ResourceWarning -m unittest discover -s tests
