#!/usr/bin/env bash
# Fetch the inputs of this run into ./fetched and check them against inputs/SHA256SUMS.
# Run from the directory that holds this run record.
set -euo pipefail
LAB=https://raw.githubusercontent.com/Agent-Authority-Conformance/aps-conformance-suite/7a8b3927e715a92cec447f3ceba84b45d6ac535d/candidates/cirisai-ceg-rows
DRAFT=https://raw.githubusercontent.com/CIRISAI/CIRISConstitution/be06d3ba7103c844abc4d4a3fd1ab1abaa592f56/ietf/draft-moore-scitt-ciris-ceg-03.txt
mkdir -p fetched/inputs fetched/sealed fetched/draft
for f in cases.json keys.json family_model.json; do curl -fsSL "$LAB/inputs/$f" -o "fetched/inputs/$f"; done
curl -fsSL "$LAB/expected.json" -o fetched/sealed/expected.json
curl -fsSL "$LAB/CANDIDATE.md" -o fetched/sealed/CANDIDATE.md
curl -fsSL "$DRAFT" -o fetched/draft/draft-moore-scitt-ciris-ceg-03.txt
(cd fetched && sha256sum -c ../inputs/SHA256SUMS)
