#!/usr/bin/env bash
# Reproduce this run from scratch.
#
# Clones the external candidate at its pinned head SHA into a scratch directory,
# verifies both pinned digests, drops the lab harness into the checkout, and runs
# the vectors under both decode modes.
#
# Exits non-zero if either digest fails. The harness exit code is not masked, so a
# canonical-byte mismatch also exits non-zero. That exit code is a mechanism for
# surfacing a mismatch, not a verdict about the external project.
set -euo pipefail

EXT_REPO="https://github.com/kuangmi-bit/a2a-go.git"
EXT_SHA="411e3e81e21318c14a9cd3f2a2999eb2fb96e396"
EXT_FILE="a2acrypto/canonical.go"
EXT_FILE_SHA256="fc3848074fe68d77df4e00fcd82cbab3a2f5961ca2ea8abbf509575d00cf3bec"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="${APS_FIXTURE:-$HERE/../../fixtures/canonical-bytes/canonical-bytes-jcs-v2.json}"
FIXTURE_SHA256="9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

echo "go: $(go version)"

# 1. Fixture digest.
actual_fixture="$(shasum -a 256 "$FIXTURE" | awk '{print $1}')"
if [ "$actual_fixture" != "$FIXTURE_SHA256" ]; then
  echo "FIXTURE DIGEST MISMATCH" >&2
  echo "  expected $FIXTURE_SHA256" >&2
  echo "  actual   $actual_fixture" >&2
  exit 2
fi
echo "fixture digest ok: $actual_fixture"

# 2. Scratch clone at the pinned head SHA, outside any repository of ours.
git clone --quiet "$EXT_REPO" "$SCRATCH/a2a-go"
git -C "$SCRATCH/a2a-go" fetch --quiet origin feat/pull-event-queue
git -C "$SCRATCH/a2a-go" checkout --quiet "$EXT_SHA"
head_sha="$(git -C "$SCRATCH/a2a-go" rev-parse HEAD)"
if [ "$head_sha" != "$EXT_SHA" ]; then
  echo "HEAD SHA MISMATCH: expected $EXT_SHA, got $head_sha" >&2
  exit 2
fi
echo "head sha ok: $head_sha"

# 3. Target file digest at that SHA.
actual_file="$(shasum -a 256 "$SCRATCH/a2a-go/$EXT_FILE" | awk '{print $1}')"
if [ "$actual_file" != "$EXT_FILE_SHA256" ]; then
  echo "TARGET FILE DIGEST MISMATCH" >&2
  echo "  expected $EXT_FILE_SHA256" >&2
  echo "  actual   $actual_file" >&2
  exit 2
fi
echo "target file digest ok: $actual_file"

# 4. Drop the lab harness in and run both decode modes. jcsMarshal is unexported,
#    so the harness has to live inside the package.
cp "$HERE/aps_jcs_vectors_test.go" "$SCRATCH/a2a-go/a2acrypto/aps_jcs_vectors_test.go"
cd "$SCRATCH/a2a-go"
APS_VECTORS="$FIXTURE" APS_OUT="${APS_OUT:-$SCRATCH}" \
  go test ./a2acrypto/ -run TestAPSCanonicalBytesVectors -v
