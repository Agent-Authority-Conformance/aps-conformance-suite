#!/usr/bin/env bash
# Negative controls for run_vectors.py. Usage: ./self_test.sh <vectors-dir> <manifest.sha256>
# Each control must give the stated exit code. The pinned corpus itself must give 0.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; VEC="$1"; MAN="$2"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
check() { # name expected-exit vectors-dir manifest
  python3 -I "$HERE/run_vectors.py" "$3" "$4" > "$T/out.txt" 2>&1; got=$?
  if [ "$got" = "$2" ]; then echo "ok   $1 exit $got"; else echo "FAIL $1 exit $got, expected $2"; tail -3 "$T/out.txt"; fail=1; fi
}
check "pinned corpus" 0 "$VEC" "$MAN"
mkdir "$T/empty"; check "empty corpus" 2 "$T/empty" "$MAN"
: > "$T/empty.sha256"; check "empty manifest" 2 "$VEC" "$T/empty.sha256"
mkdir "$T/drop"; cp "$VEC"/[0-9][0-9]-*.json "$T/drop/"; rm "$(ls "$T/drop"/*.json | head -1)"; check "missing vector" 2 "$T/drop" "$MAN"
# a wrong expected code: change one vector, re-pin the manifest, the run must report the mismatch
mkdir "$T/flip"; cp "$VEC"/[0-9][0-9]-*.json "$T/flip/"; f="$(ls "$T/flip"/*.json | tail -1)"
python3 -I -c "import json,sys;p=sys.argv[1];d=json.load(open(p));d['expected_error_code']='not_a_real_code';json.dump(d,open(p,'w'),indent=2)" "$f"
check "edited vector, old manifest" 2 "$T/flip" "$MAN"
(cd "$T/flip" && shasum -a 256 [0-9][0-9]-*.json > "$T/flip.sha256"); check "wrong expected code" 1 "$T/flip" "$T/flip.sha256"
# a vector that cannot be parsed counts as a failure, not a pass
mkdir "$T/bad"; cp "$VEC"/[0-9][0-9]-*.json "$T/bad/"; f="$(ls "$T/bad"/*.json | head -1)"; printf '{"not": "a vector"' > "$f"
(cd "$T/bad" && shasum -a 256 [0-9][0-9]-*.json > "$T/bad.sha256"); check "unparseable vector" 1 "$T/bad" "$T/bad.sha256"
# an unsupported signature version is a mismatch, never a match
mkdir "$T/sv"; cp "$VEC"/[0-9][0-9]-*.json "$T/sv/"; f="$(ls "$T/sv"/*.json | head -1)"
python3 -I -c "import json,sys;p=sys.argv[1];d=json.load(open(p));d['inputs']['leaf']['sig_version']=4;json.dump(d,open(p,'w'),indent=2)" "$f"
(cd "$T/sv" && shasum -a 256 [0-9][0-9]-*.json > "$T/sv.sha256"); check "unsupported sig_version" 1 "$T/sv" "$T/sv.sha256"
exit $fail
