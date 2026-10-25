#!/bin/sh
# Check this candidate against its pinned source, then run every verification
# step with network access refused.
#
#   sh run.sh            needs git, python3 (3.9+), and: pip install cryptography jsonschema jcs pytest
#
# The clone is the only network step. It fetches the generators, the reference
# verifiers and the public test keys at the pinned commit. Every file in this
# directory is compared byte for byte with the same path in that clone before
# anything runs, so the verifiers below check exactly the bytes published here.
set -eu
PIN=6bb462f578c12d339b8fa964a5b1d8f97dbffa68
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

git clone -q https://github.com/MoltyCel/aae-conformance-vectors "$WORK/src"
git -C "$WORK/src" checkout -q "$PIN"
cd "$WORK/src"

echo "== candidate bytes equal the source at $PIN"
grep -v '^#' "$HERE/CHECKSUMS.sha256" | shasum -a 256 -c --quiet -
(cd "$HERE" && grep -v '^#' CHECKSUMS.sha256 | shasum -a 256 -c --quiet -)
echo "ok: $(grep -vc '^#' "$HERE/CHECKSUMS.sha256") files"

off() { echo "\$ python3 $*"; python3 -I "$HERE/offline.py" "$@"; }

echo "== native, draft-kroehl-agentic-trust-aae-00"
off tools/validate_schema.py
off examples/python-verify.py
off -m pytest -q -p no:cacheprovider tests/
echo "== enforce, draft-kroehl-agentic-trust-aae-02"
off tools/validate_enforce_schema.py
off examples/enforce-verify.py
echo "== composition, draft-kroehl-agentic-trust-aae-00 with draft-yossif-psea-02"
off tools/validate_interop_schema.py
off examples/composition-verify.py
off tools/run_negative_controls.py
(cd interop/psea && shasum -a 256 -c psea-fixture-v0.sha256)

echo "== regeneration: every generator rebuilds its files byte for byte"
off tools/build_vectors.py > /dev/null
off tools/build_enforce_vectors.py > /dev/null
off tools/build_interop_psea.py > /dev/null
if [ -n "$(git status --porcelain)" ]; then
  git status --porcelain
  echo "FAIL: a rebuild differs from the published bytes"
  exit 1
fi
echo "ok: rebuild is byte-identical"
