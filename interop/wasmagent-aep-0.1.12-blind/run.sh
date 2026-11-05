#!/bin/sh
# Reproduce both runs and the candidate cases against @wasmagent/protocol 0.1.12.
# Needs python3 with jsonschema, rfc8785, cryptography, and npm (for npm pack only, no install scripts).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
cd "$WORK"
npm pack @wasmagent/protocol@0.1.12 --ignore-scripts >/dev/null 2>&1
echo "30b3c2cd8534246684e5851b1557a21e921d242d9a1acabc2336d591ea9af90e  wasmagent-protocol-0.1.12.tgz" | shasum -a 256 -c -
tar -xzf wasmagent-protocol-0.1.12.tgz
C="$WORK/package/conformance/aep"
python3 -I "$HERE/verifier/aep_verify_v1_blind.py" "$C" "$HERE/paths.txt" "$WORK/blind-run-1.json"
python3 -I "$HERE/verifier/aep_verify_v2.py" "$C" "$HERE/paths.txt" "$WORK/run-2.json"
cmp "$WORK/blind-run-1.json" "$HERE/results/blind-run-1.json"
echo "blind run 1 reproduced byte for byte"
cmp "$WORK/run-2.json" "$HERE/results/run-2.json"
echo "run 2 reproduced byte for byte"
python3 -I "$HERE/verifier/grade.py" "$C/manifest.json" "$WORK/run-2.json"
python3 -I "$HERE/cases/run_cases.py" "$C" "$HERE/cases"
