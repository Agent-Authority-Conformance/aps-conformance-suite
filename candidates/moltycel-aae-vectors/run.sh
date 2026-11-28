#!/bin/sh
# Check this candidate against its pinned source, then run each verification
# step through offline.py.
#
#   sh run.sh            needs git, python3 (3.9+), and: pip install cryptography jsonschema jcs pytest
#
# The clone is the only network step. It fetches the generators, the reference
# verifiers and the public test keys at the pinned commit.
#
# The 64 files listed in CHECKSUMS.sha256 are byte copies of the source at the
# pin. Each is compared with the same path in that clone before anything runs.
# Written for this candidate: CANDIDATE.md, CHECKSUMS.sha256, offline.py, run.sh.
# NOTICE is changed from the source's NOTICE.
#
# offline.py installs an audit hook in the interpreter that runs each
# verification step. Socket and name-lookup calls from that interpreter are
# refused. Child processes are not covered.
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
