#!/bin/sh
# Regression check for run.sh. A clean copy of this directory must pass, and each altered copy must fail.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
fail=0
try() {
  T=$(mktemp -d)
  cp -R "$HERE/." "$T/rec"
  (cd "$T/rec" && sh -c "$3")
  if sh "$T/rec/run.sh" >"$T/out.log" 2>&1; then got=0; else got=1; fi
  if [ "$got" = "$2" ]; then echo "ok: $1"; else echo "FAIL: $1 (exit $got, expected $2)"; fail=1; fi
  rm -rf "$T"
}
try "unchanged record passes" 0 ":"
try "changed frozen result fails" 1 "printf ' ' >> results/run-2.json"
try "failed candidate expectation fails" 1 "python3 -I -c 'import json; p=\"cases/cases.json\"; d=json.load(open(p)); d[\"cases\"][0][\"expected\"]=\"__wrong__\"; json.dump(d, open(p, \"w\"))'"
try "verifier exiting before output fails" 1 "printf 'raise SystemExit(3)\n' > verifier/aep_verify_v2.py"
exit $fail
