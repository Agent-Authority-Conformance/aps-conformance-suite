#!/usr/bin/env bash
# Re-run this reading from fetched inputs and compare every output with out/.
# Run from this directory after: bash inputs/fetch-inputs.sh
set -uo pipefail
PY=${PY:-python3}
F=fetched
mkdir -p rerun
run() { echo "\$ $*"; "$@"; echo "[exit $?]"; echo; }
run $PY -I -c "import sys; sys.path.insert(0,'reader'); import ceg_reader_pass1 as R; R.main('$F/inputs/cases.json','$F/inputs/keys.json','rerun/answers-pass1.json')"
run $PY -I -c "import sys; sys.path.insert(0,'reader'); import ceg_reader_pass2 as R; R.main('$F/inputs/cases.json','$F/inputs/keys.json','rerun/answers-pass2.json')"
run $PY -I -c "import sys; sys.path.insert(0,'reader'); import ceg_reader_pass3 as R; R.main('$F/inputs/cases.json','$F/inputs/keys.json','rerun/answers-pass3.json')"
run $PY -I reader/compare.py rerun/answers-pass2.json $F/sealed/expected.json $F/inputs/cases.json rerun/comparison-pass2.json
run $PY -I reader/compare.py rerun/answers-pass3.json $F/sealed/expected.json $F/inputs/cases.json rerun/comparison-pass3.json
run env PYTHONPATH=reader $PY -B reader/b1_check.py $F/draft/draft-moore-scitt-ciris-ceg-03.txt
for f in answers-pass1.json answers-pass2.json answers-pass3.json comparison-pass2.json comparison-pass3.json; do
  run cmp rerun/$f out/$f
done
