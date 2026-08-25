#!/usr/bin/env bash
# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce the APS RFC 8785 canonical-bytes observation against the external
# head pinned below. Clones outside this repository. Nothing from the external
# checkout is copied back in.
#
# Exit status: non-zero if the fixture digest does not match, or if either
# decode mode reported a mismatch. Both modes always run to completion and
# results.json is always written before a non-zero exit.

set -u

PIN_SHA="ea003f9afb3312d88cc06fc7f38a98d1627beeb4"
PIN_REPO="https://github.com/kuangmi-bit/a2a-go.git"
FIXTURE_SHA256="9502d72102b10f083ce91529e025e4a9c8a18881c5a9ec8f9ac46b1c0e48f593"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITE_ROOT="$(cd "$HERE/../.." && pwd)"
FIXTURE="${APS_FIXTURE:-$SUITE_ROOT/fixtures/canonical-bytes/canonical-bytes-jcs-v2.json}"
WORK="${APS_WORK:-$(mktemp -d)}"

echo "fixture: $FIXTURE"
if command -v shasum >/dev/null 2>&1; then
  GOT="$(shasum -a 256 "$FIXTURE" | awk '{print $1}')"
else
  GOT="$(sha256sum "$FIXTURE" | awk '{print $1}')"
fi
echo "fixture sha256: $GOT"
if [ "$GOT" != "$FIXTURE_SHA256" ]; then
  echo "STOP: fixture digest does not match the pinned value $FIXTURE_SHA256" >&2
  exit 2
fi

CLONE="$WORK/a2a-go"
rm -rf "$CLONE"
git clone --quiet "$PIN_REPO" "$CLONE" || { echo "STOP: clone failed" >&2; exit 3; }
git -C "$CLONE" fetch --quiet origin "$PIN_SHA" 2>/dev/null || true
git -C "$CLONE" checkout --quiet "$PIN_SHA" || { echo "STOP: checkout of $PIN_SHA failed" >&2; exit 3; }
HEAD_NOW="$(git -C "$CLONE" rev-parse HEAD)"
echo "external head: $HEAD_NOW"
if [ "$HEAD_NOW" != "$PIN_SHA" ]; then
  echo "STOP: checkout is not at the pinned head" >&2
  exit 3
fi

if command -v shasum >/dev/null 2>&1; then
  echo "canonical.go sha256: $(shasum -a 256 "$CLONE/a2acrypto/canonical.go" | awk '{print $1}')"
else
  echo "canonical.go sha256: $(sha256sum "$CLONE/a2acrypto/canonical.go" | awk '{print $1}')"
fi
echo "canonical.go lines: $(wc -l < "$CLONE/a2acrypto/canonical.go" | tr -d ' ')"
go version

cp "$HERE/aps_jcs_vectors_test.go" "$CLONE/a2acrypto/aps_jcs_vectors_test.go"

OUT_PRIMARY="$WORK/primary.json"
OUT_SECONDARY="$WORK/secondary.json"

# Both modes run to completion. Neither status is masked and neither aborts the other.
echo "=== primary_usenumber ==="
( cd "$CLONE" && APS_MODE=primary_usenumber APS_FIXTURE="$FIXTURE" APS_OUT="$OUT_PRIMARY" \
    go test ./a2acrypto/ -run TestAPSCanonicalBytesVectors -v )
STATUS_PRIMARY=$?

echo "=== secondary_float64 ==="
( cd "$CLONE" && APS_MODE=secondary_float64 APS_FIXTURE="$FIXTURE" APS_OUT="$OUT_SECONDARY" \
    go test ./a2acrypto/ -run TestAPSCanonicalBytesVectors -v )
STATUS_SECONDARY=$?

echo "primary exit: $STATUS_PRIMARY"
echo "secondary exit: $STATUS_SECONDARY"
echo "per-mode results: $OUT_PRIMARY $OUT_SECONDARY"

if [ "$STATUS_PRIMARY" -ne 0 ] || [ "$STATUS_SECONDARY" -ne 0 ]; then
  exit 1
fi
exit 0
