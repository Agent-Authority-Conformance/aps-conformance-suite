#!/bin/sh
# Regression check for run.sh. A clean copy of this directory must pass, and each altered copy must fail
# with the expected message. A copy that cannot be set up counts as a failure of this check.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
fail=0
try() {
  T=$(mktemp -d) || { echo "FAIL: $1 (no temp dir)"; fail=1; return; }
  if ! cp -R "$HERE/." "$T/rec" || ! (cd "$T/rec" && sh -c "$3"); then
    echo "FAIL: $1 (setup)"; fail=1; rm -rf "$T"; return
  fi
  if sh "$T/rec/run.sh" >"$T/out.log" 2>&1; then got=0; else got=1; fi
  if [ "$got" != "$2" ]; then
    echo "FAIL: $1 (exit $got, expected $2)"; fail=1
  elif [ -n "$4" ] && ! grep -q -- "$4" "$T/out.log"; then
    echo "FAIL: $1 (exit $got as expected, but no \"$4\" in the output)"; fail=1
  else
    echo "ok: $1"
  fi
  rm -rf "$T"
}
try "unchanged record passes" 0 ":" "^9/9$"
try "changed frozen result fails" 1 "python3 -I -c 'p=\"results/run-2.json\"; s=open(p).read(); open(p, \"w\").write(s.replace(\":\", \";\", 1))'" "differ"
try "failed candidate expectation fails" 1 "python3 -I -c 'import json; p=\"cases/cases.json\"; d=json.load(open(p)); d[\"cases\"][0][\"expected\"]=\"__wrong__\"; json.dump(d, open(p, \"w\"))'" "^FAIL "
try "verifier exiting before output fails" 1 "printf 'raise SystemExit(3)\n' > verifier/aep_verify_v2.py" ""
exit $fail
