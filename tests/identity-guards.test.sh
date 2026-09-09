#!/usr/bin/env bash
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Offline regression for the two identity checks in scripts/run-all.sh.
#
# WHAT IT GUARDS. Those checks answer two different questions and the runner
# used to answer neither. Package availability or version says WHICH
# DISTRIBUTION is installed; a fixture digest says WHICH INPUT BYTES are
# exercised. Before they existed, two families reading the same relative path
# from the same distribution at different revisions were indistinguishable, and
# the runner would have printed PASS for one while executing the other's
# vectors. This test is the thing that fails if either check is weakened.
#
# WHY IT IS NOT A MOCK. The identity logic is not reimplemented here. The block
# between the BEGIN IDENTITY HELPERS and END IDENTITY HELPERS markers is
# extracted out of scripts/run-all.sh at run time and sourced, so what executes
# is the production bytes. If a helper is moved outside the markers it silently
# leaves the regression, so the marker extraction itself is asserted first.
#
# The synthetic distribution is a real one as far as the runner is concerned: a
# package directory plus a .dist-info with METADATA, on PYTHONPATH. The runner
# resolves it through importlib.util.find_spec and reads its version through
# importlib.metadata, which are the same calls it makes against a pip install.
# Nothing here reaches the network, PyPI, a host-installed attenu_guard, or any
# path outside the temporary directory.
#
# WHAT IS STUBBED, and why that is honest. run/skip/not_run are the runner's
# reporting sink, not its identity logic. The test supplies its own sink so it
# can assert on which one was called AND on the reason text; `run` still
# executes the command it is handed, so reaching the verifier is observed
# through a sentinel file rather than inferred from a label.
#
# Four branches, each proved on its own:
#   1 version match     expected version installed        -> verifier reached
#   2 version mismatch  wrong version installed           -> SKIPPED, not reached
#   3 digest match      fixture digest matches            -> verifier reached
#   4 digest mismatch   fixture bytes differ, rest valid  -> SKIPPED, not reached
#
# Run: bash tests/identity-guards.test.sh
# Exit 0 when every branch reaches its expected sink for its expected reason.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$REPO_ROOT/scripts/run-all.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASSES=0
FAILURES=0
check() { # description, condition already evaluated by the caller as 0/1
  if [ "$2" -eq 0 ]; then
    PASSES=$((PASSES+1)); echo "  ok   $1"
  else
    FAILURES=$((FAILURES+1)); echo "  FAIL $1"
    [ -n "${3:-}" ] && echo "       $3"
  fi
}

# ---------------------------------------------------------------- extraction
extract_helpers() { # out_file
  awk '/^# BEGIN IDENTITY HELPERS/{f=1;next} /^# END IDENTITY HELPERS/{f=0} f' "$RUNNER" > "$1"
}
HELPERS="$TMP/helpers.sh"
extract_helpers "$HELPERS"
for fn in ag_resolve ag_expected check_pkg_version ag_fixture_case ag_version_case; do
  if ! grep -q "^${fn}() {" "$HELPERS"; then
    echo "FAIL: $fn is not inside the IDENTITY HELPERS markers in scripts/run-all.sh" >&2
    echo "      The regression cannot exercise a helper it cannot extract." >&2
    exit 1
  fi
done

# ------------------------------------------------- the synthetic distribution
# A package the runner can find_spec, and a .dist-info the runner can read a
# version from. build_dist VERSION VECTOR_BYTES_FILE -> prints the site dir.
build_dist() { # version vectors_source_file
  # Declared separately: under `set -u`, referring to `ver` inside the same
  # `local` statement that declares it reads an unset local, not the argument.
  local ver="$1"
  local src="$2"
  local site="$TMP/site-$ver-$RANDOM"
  mkdir -p "$site/idreg_pkg/vectors/regression"
  : > "$site/idreg_pkg/__init__.py"
  cp "$src" "$site/idreg_pkg/vectors/regression/vectors_v1.json"
  mkdir -p "$site/idreg_dist-$ver.dist-info"
  cat > "$site/idreg_dist-$ver.dist-info/METADATA" <<META
Metadata-Version: 2.1
Name: idreg-dist
Version: $ver
META
  echo "Wheel-Version: 1.0" > "$site/idreg_dist-$ver.dist-info/WHEEL"
  echo "$site"
}

# The vectors the fixture branches use, and their real digest.
GOOD="$TMP/vectors-good.json"
printf '%s\n' '{"suite":"identity-guard-regression","revision":"v1","cases":[{"id":"R-01"}]}' > "$GOOD"
GOOD_SHA="$(shasum -a 256 "$GOOD" | awk '{print $1}')"
BAD="$TMP/vectors-bad.json"
printf '%s\n' '{"suite":"identity-guard-regression","revision":"v2","cases":[{"id":"R-01"},{"id":"R-02"}]}' > "$BAD"
BAD_SHA="$(shasum -a 256 "$BAD" | awk '{print $1}')"

# ------------------------------------------------------- the synthetic verifier
# Writes an unambiguous sentinel, so "the verifier ran" is observed and not
# inferred from a status label.
SENTINEL="$TMP/sentinel"
VERIFIER="$TMP/verifier.py"
cat > "$VERIFIER" <<'PY'
import os, sys
open(os.environ["IDREG_SENTINEL"], "a").write("REACHED %s\n" % (sys.argv[1] if len(sys.argv) > 1 else "-"))
PY

# --------------------------------------------------------- synthetic registry
# Test data in the production schema. The helpers that read it are production.
write_registry() { # expected_sha expected_version
  cat > "$TMP/prereqs.json" <<JSON
{
  "\$comment": "synthetic registry for tests/identity-guards.test.sh; never shipped",
  "version": 1,
  "families": [
    {
      "id": "idreg-fixture",
      "label": "regtest:idreg fixture family",
      "script": "$VERIFIER",
      "identity": "fixture_digest",
      "vectors": {
        "package": "idreg_pkg",
        "relpath": "vectors/regression/vectors_v1.json",
        "sha256": "$1"
      }
    },
    {
      "id": "idreg-version",
      "label": "regtest:idreg version family",
      "scripts": ["$VERIFIER"],
      "identity": "package_version",
      "package": { "module": "idreg_pkg", "distribution": "idreg-dist", "version": "$2" }
    }
  ]
}
JSON
}

# ------------------------------------------------------------- the sink stubs
# These replace the runner's reporting sink, never its identity logic.
LAST_SINK=""; LAST_LABEL=""; LAST_REASON=""
run()     { LAST_SINK="run";     LAST_LABEL="$1"; LAST_REASON=""; shift; "$@" >/dev/null 2>&1; }
skip()    { LAST_SINK="skip";    LAST_LABEL="$1"; LAST_REASON="$2"; }
not_run() { LAST_SINK="not_run"; LAST_LABEL="$1"; LAST_REASON="$2"; }
# Dependency preconditions are a different concern and are satisfied so that a
# missing rfc8785 on the host cannot mask an identity result.
check_py_pin() { return 0; }
check_py_mod() { return 0; }

PREREQS="$TMP/prereqs.json"
# shellcheck disable=SC1090
. "$HELPERS"

reset() { LAST_SINK=""; LAST_LABEL=""; LAST_REASON=""; : > "$SENTINEL"; }
sentinel_reached() { [ -s "$SENTINEL" ]; }
export IDREG_SENTINEL="$SENTINEL"

echo "identity-guards.test.sh"
echo "  runner   : $RUNNER"
echo "  helpers  : extracted between the IDENTITY HELPERS markers, $(wc -l < "$HELPERS" | tr -d ' ') lines"
echo "  good sha : $GOOD_SHA"
echo "  bad sha  : $BAD_SHA"
echo

# ------------------------------------------------------- 1. version match
echo "branch 1: version match, verifier must be reached"
write_registry "$GOOD_SHA" "1.2.3"
SITE="$(build_dist 1.2.3 "$GOOD")"
reset
export PYTHONPATH="$SITE"; ag_version_case idreg-version; unset PYTHONPATH
check "sink is run"            "$([ "$LAST_SINK" = "run" ] && echo 0 || echo 1)" "sink=$LAST_SINK reason=$LAST_REASON"
check "verifier was reached"   "$(sentinel_reached && echo 0 || echo 1)"
check "label names the version" "$(grep -q '1\.2\.3' <<<"$LAST_LABEL" && echo 0 || echo 1)" "label=$LAST_LABEL"

# ------------------------------------------------------- 2. version mismatch
echo "branch 2: version mismatch, verifier must NOT be reached"
write_registry "$GOOD_SHA" "1.2.3"
SITE="$(build_dist 9.9.9 "$GOOD")"
reset
export PYTHONPATH="$SITE"; ag_version_case idreg-version; unset PYTHONPATH
check "sink is skip"                 "$([ "$LAST_SINK" = "skip" ] && echo 0 || echo 1)" "sink=$LAST_SINK"
check "verifier was NOT reached"     "$(sentinel_reached && echo 1 || echo 0)"
check "reason is version identity"   "$(grep -q 'version identity' <<<"$LAST_REASON" && echo 0 || echo 1)" "reason=$LAST_REASON"
check "reason names expected 1.2.3"  "$(grep -q 'idreg-dist==1\.2\.3' <<<"$LAST_REASON" && echo 0 || echo 1)" "reason=$LAST_REASON"
check "reason names installed 9.9.9" "$(grep -q 'idreg-dist==9\.9\.9' <<<"$LAST_REASON" && echo 0 || echo 1)" "reason=$LAST_REASON"

# ------------------------------------------------------- 3. digest match
echo "branch 3: digest match, verifier must be reached"
write_registry "$GOOD_SHA" "1.2.3"
SITE="$(build_dist 1.2.3 "$GOOD")"
reset
export PYTHONPATH="$SITE"; ag_fixture_case idreg-fixture; unset PYTHONPATH
check "sink is run"                "$([ "$LAST_SINK" = "run" ] && echo 0 || echo 1)" "sink=$LAST_SINK reason=$LAST_REASON"
check "verifier was reached"       "$(sentinel_reached && echo 0 || echo 1)"
check "label carries the digest"   "$(grep -q "$GOOD_SHA" <<<"$LAST_LABEL" && echo 0 || echo 1)" "label=$LAST_LABEL"

# ------------------------------------------------------- 4. digest mismatch
# Everything else is valid: same package name, same version, same relative path.
# Only the bytes differ.
echo "branch 4: digest mismatch, verifier must NOT be reached"
write_registry "$GOOD_SHA" "1.2.3"
SITE="$(build_dist 1.2.3 "$BAD")"
reset
export PYTHONPATH="$SITE"; ag_fixture_case idreg-fixture; unset PYTHONPATH
check "sink is skip"                 "$([ "$LAST_SINK" = "skip" ] && echo 0 || echo 1)" "sink=$LAST_SINK"
check "verifier was NOT reached"     "$(sentinel_reached && echo 1 || echo 0)"
check "reason is fixture identity"   "$(grep -q 'fixture identity' <<<"$LAST_REASON" && echo 0 || echo 1)" "reason=$LAST_REASON"
check "reason names expected digest" "$(grep -q "expected $GOOD_SHA" <<<"$LAST_REASON" && echo 0 || echo 1)" "reason=$LAST_REASON"
check "reason names observed digest" "$(grep -q "observed $BAD_SHA" <<<"$LAST_REASON" && echo 0 || echo 1)" "reason=$LAST_REASON"

echo
if [ "$FAILURES" -gt 0 ]; then
  echo "FAILED: $FAILURES check(s) failed, $PASSES passed"
  exit 1
fi
echo "PASSED: $PASSES checks, four branches, verifier reached twice and refused twice"
