#!/usr/bin/env bash
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Runs every documented entrypoint of this repository in one pass and prints one
# line per runner.
#
# WHY THIS EXISTS. No single documented command runs the whole set. `npm test`
# is the hermetic default gate and deliberately excludes the schema-parity
# validators and the cross-stack families (.github/workflows/tests.yml says so
# in both jobs' comments). `npm run verify:cross-stack` covers the cross-stack
# registry and nothing else. The repository-hygiene workflow's checks live only
# as inline shell in YAML. The interop reproductions live only in
# interop/*/SOURCE.md and need third-party packages this repository does not
# depend on. A reviewer asking "what does the suite actually execute" therefore
# had to read four files; this runs all four sources and reports.
#
# STATUS VOCABULARY, and why four states and not two:
#   PASS     the command ran and exited 0
#   FAILED   the command ran and exited nonzero
#   SKIPPED  a documented precondition is absent (a package this repository does
#            not depend on, a tool not present on this host). NOT a pass. The
#            missing precondition is named on the line.
#   NOT_RUN  the entry is declared here but no command was resolved for it
# A missing dependency is never converted into a pass. The exit code of this
# script is nonzero if any runner FAILED; SKIPPED and NOT_RUN are reported and
# counted separately so that a run with skips can never be read as a clean run.
#
# This script does not mutate the tree. Generators (npm run readme:inventory,
# the generate-*.ts / generate_*.py files) are excluded by name for that reason,
# and so are the pure aggregates (`npm test`, `npm run verify:cross-stack`,
# `cross-stack:oracle-safety-check:verify`) whose leaves are all run directly.
#
# Run: bash scripts/run-all.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0; FAIL=0; SKIP=0; NOTRUN=0
declare -a LINES=()

emit() { # name status code note
  LINES+=("$(printf '%-52s %-8s exit=%-4s pass=%d fail=%d skip=%d %s' \
    "$1" "$2" "$3" "$4" "$5" "$6" "${7:-}")")
}

run() { # name command...
  local name="$1"; shift
  echo "--- RUN $name : $*"
  "$@"
  local code=$?
  if [ $code -eq 0 ]; then
    PASS=$((PASS+1)); emit "$name" PASS "$code" 1 0 0
  else
    FAIL=$((FAIL+1)); emit "$name" FAILED "$code" 0 1 0
  fi
  echo "--- END $name : exit=$code"
  echo
}

skip() { # name reason
  echo "--- SKIP $1 : $2"
  SKIP=$((SKIP+1)); emit "$1" SKIPPED "-" 0 0 1 "($2)"
  echo
}

have_py() { python3 -c "import $1" >/dev/null 2>&1; }
have_bin() { command -v "$1" >/dev/null 2>&1; }

echo "run-all.sh: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo: $REPO_ROOT"
echo "HEAD: $(git rev-parse HEAD 2>/dev/null || echo '?')"
echo "node: $(node -v 2>/dev/null || echo absent)  npm: $(npm -v 2>/dev/null || echo absent)  python3: $(python3 -V 2>&1 || echo absent)"
echo

# ---------------------------------------------------------------- 1. npm scripts
# Source: package.json "scripts". Excluded: the aggregates whose leaves are all
# run below, and readme:inventory which writes to the tree.
NPM_SCRIPTS=(
  typecheck
  test:digest-integrity
  test:manifest-integrity
  test:cross-stack-registry
  test:readme-inventory
  verify
  test:fail-loud
  test:canonical-bytes
  verify:envoys-rfc9421
  verify:a2a-1496-negative-paths
  verify:sk-function-invocation
  verify:aae-envelope
  verify:two-wrapper-attribution
  verify:accountability-record
  verify:read-fidelity-receipt
  verify:receipt-decision-relation
  verify:receipt-decision-relation:flip
  test:layered-gate-mutation
  crossrun:canonical-bytes
  test:cross-stack-wiring
  typecheck:cross-stack
  verify:oracle-safety-check
  verify:oracle-safety-check-consistency
  verify:oracle-safety-check-flips
  cross-stack:aat-amdal:verify
  cross-stack:argentum-action-ref-v1v2:verify
  cross-stack:action-ref-v1-negatives:verify
  cross-stack:nobulex-bilateral-v0:verify
  cross-stack:oracle-safety-check:falsify
  cross-stack:receipts-aeoess:verify
  cross-stack:receipts-amdal:verify
  cross-stack:ctef-v0.3.1:verify
  cross-stack:token-exchange-attenuation-v0:verify
)
echo "================ 1. package.json scripts (${#NPM_SCRIPTS[@]}) ================"
if [ ! -d node_modules ]; then
  for s in "${NPM_SCRIPTS[@]}"; do skip "npm:$s" "node_modules absent; run npm ci --include=dev"; done
else
  for s in "${NPM_SCRIPTS[@]}"; do
    if ! node -e 'const s=require("./package.json").scripts||{};process.exit(s[process.argv[1]]?0:1)' "$s"; then
      NOTRUN=$((NOTRUN+1)); emit "npm:$s" NOT_RUN "-" 0 0 0 "(no such script in package.json)"
      continue
    fi
    run "npm:$s" npm run --silent "$s"
  done
fi

# --------------------------------- 2. workflow-only commands (tests.yml)
echo "================ 2. .github/workflows/tests.yml schema-parity ================"
if have_py jsonschema && have_py cryptography; then
  run "wf:tests.yml accountability-record/validate.py" python3 fixtures/accountability-record/validate.py
  run "wf:tests.yml read-fidelity-receipt/validate.py" python3 fixtures/read-fidelity-receipt/validate.py
else
  skip "wf:tests.yml accountability-record/validate.py" "python jsonschema/cryptography absent"
  skip "wf:tests.yml read-fidelity-receipt/validate.py" "python jsonschema/cryptography absent"
fi

# --------------------------- 2b. the other language runners README.md names
# README.md: "Runners exist for TypeScript (runners/ts), Go (runners/go) and
# Python (runners/python plus the receipt and AAT runners under runners/)."
echo "================ 2b. Go and Python runners (README.md) ================"
if have_bin go; then
  run "runners/go: go run ." bash -c 'cd runners/go && go run .'
  run "runners/go: go test ./..." bash -c 'cd runners/go && go test ./...'
else
  skip "runners/go: go run ."      "go toolchain absent"
  skip "runners/go: go test ./..." "go toolchain absent"
fi
# runners/python/verify.py is a declared stub: it prints "not yet implemented"
# and exits 0. Exit 0 from a runner that asserts nothing is the single most
# dangerous line an aggregate like this can print, so it is NOT_RUN by name and
# never enters the PASS count.
NOTRUN=$((NOTRUN+1)); emit "runners/python/verify.py" NOT_RUN "-" 0 0 0 "(declared stub: prints not-yet-implemented and exits 0; asserts nothing)"
echo "--- NOT_RUN runners/python/verify.py : declared stub"
echo
if python3 -c 'import pytest' >/dev/null 2>&1; then
  run "tests/test_aat_runner.py (pytest)" python3 -m pytest -q tests/test_aat_runner.py
else
  skip "tests/test_aat_runner.py (pytest)" "pytest absent; no documented command names this file either"
fi

# ------------------------- 3. workflow-only commands (repository-hygiene.yml)
echo "================ 3. .github/workflows/repository-hygiene.yml ================"
hyg_abs() {
  hits=$(git ls-files -z | grep -zv -E '^\.github/workflows/repository-hygiene\.yml$' \
    | xargs -0 grep -n -E '/Users/|/home/' /dev/null 2>/dev/null \
    | sed 's|/Users/agent/workspace||g' | grep -E '/Users/|/home/' || true)
  [ -z "$hits" ] || { printf '%s\n' "$hits" | sed 's/^/  /'; return 1; }
  echo "ok: no absolute local paths"
}
hyg_secret() {
  hits=$(git ls-files | grep -E '(^|/)\.env($|\.)|\.(pem|key|p12|pfx|jks|keystore)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)$' || true)
  [ -z "$hits" ] || { printf '%s\n' "$hits" | sed 's/^/  /'; return 1; }
  echo "ok: no secret-shaped files"
}
hyg_deps() {
  hits=$(git ls-files | grep -E '(^|/)(node_modules|dist)/' || true)
  [ -z "$hits" ] || { printf '%s\n' "$hits" | head -50 | sed 's/^/  /'; return 1; }
  echo "ok: no committed node_modules or dist"
}
hyg_crlf() {
  files=$(git ls-files 'fixtures/**' 'interop/**' 'cross-impl-receipts/**')
  hits=""
  if [ -n "$files" ]; then
    hits=$(printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -l -U -P $'\r' 2>/dev/null || true)
  fi
  [ -z "$hits" ] || { printf '%s\n' "$hits" | sed 's/^/  /'; return 1; }
  echo "ok: no CRLF in pinned evidence"
}
run "wf:hygiene Absolute local paths" hyg_abs
run "wf:hygiene Secret-shaped files"  hyg_secret
run "wf:hygiene Committed deps/build output" hyg_deps
# grep -P is a GNU extension; BSD grep on macOS does not have it. Skipping is the
# honest result on such a host: the check did not run.
if echo x | grep -q -P 'x' 2>/dev/null; then
  run "wf:hygiene CRLF in pinned evidence" hyg_crlf
else
  skip "wf:hygiene CRLF in pinned evidence" "grep -P unavailable on this host"
fi

# ------------------------------- 4. interop/*/SOURCE.md reproductions
# Each of these is a documented reproduction of an external implementation's
# result. They depend on packages this repository does not depend on. Absent
# dependency is SKIPPED with the package named, never a pass.
echo "================ 4. interop/*/SOURCE.md reproductions ================"
if have_py rfc8785; then
  run "interop:hjs-bb6be62 run-rfc8785-witness.py" python3 interop/hjs-bb6be62/run-rfc8785-witness.py
else
  skip "interop:hjs-bb6be62 run-rfc8785-witness.py" "pip rfc8785==0.1.4 absent"
fi
if have_py jcs; then
  run "interop:hjs-bb6be62 rerun-hjs-over-aps.py" python3 interop/hjs-bb6be62/rerun-hjs-over-aps.py
else
  skip "interop:hjs-bb6be62 rerun-hjs-over-aps.py" "pip jcs==0.2.1 absent"
fi
# agent-passport-system is a dependency of this repository, but at the version
# package.json pins (6.0.0), not the 4.5.1 this witness's SOURCE.md names. A run
# under a different version is a different reproduction, so it is skipped with
# both versions on the line rather than passed off as the documented one.
# require.resolve is not the test: the package has an exports map and
# require.resolve throws ERR_PACKAGE_PATH_NOT_EXPORTED on it even when present.
APS_VER="$(node -e 'try{console.log(require("agent-passport-system/package.json").version)}catch(e){try{console.log(JSON.parse(require("fs").readFileSync("node_modules/agent-passport-system/package.json","utf8")).version)}catch(e2){console.log("absent")}}' 2>/dev/null)"
if [ "$APS_VER" = "4.5.1" ]; then
  run "interop:hjs-bb6be62 run-aps-witness.mjs" node interop/hjs-bb6be62/run-aps-witness.mjs
else
  skip "interop:hjs-bb6be62 run-aps-witness.mjs" "SOURCE.md pins agent-passport-system@4.5.1; installed is ${APS_VER}"
fi

# attenu-guard: every one of these imports the attenu_guard package, which
# SOURCE.md installs from PyPI into a throwaway venv. Absent package, absent run.
if have_py attenu_guard; then
  run "interop:attenu-guard-0.6.0 jcs-byte-diff.py"           python3 interop/attenu-guard-0.6.0/jcs-byte-diff.py
  run "interop:attenu-guard-0.6.0 cleanroom/verify_asor00.py" python3 interop/attenu-guard-0.6.0/cleanroom/verify_asor00.py
  run "interop:attenu-guard-0.6.1 jcs-byte-diff.py"           python3 interop/attenu-guard-0.6.1/jcs-byte-diff.py
  run "interop:attenu-guard-0.6.1 cleanroom/verify_asor00.py" python3 interop/attenu-guard-0.6.1/cleanroom/verify_asor00.py
else
  for e in "0.6.0 jcs-byte-diff.py" "0.6.0 cleanroom/verify_asor00.py" \
           "0.6.1 jcs-byte-diff.py" "0.6.1 cleanroom/verify_asor00.py"; do
    skip "interop:attenu-guard-$e" "python module attenu_guard absent (SOURCE.md: pip install attenu-guard)"
  done
fi
skip "interop:attenu-guard-0.8.0 (SOURCE.md)"          "SOURCE.md pins attenu-guard==0.8.0 from PyPI; not installed"
skip "interop:attenu-guard-0.11.0-bundles cleanroom"   "SOURCE.md pins attenu-guard==0.11.0 from PyPI; not installed"
skip "interop:attenu-guard-0.13.0-envelopes cleanroom" "SOURCE.md pins attenu_guard-0.13.0 wheel; not installed"
skip "interop:attenu-guard-0.15.0-envelopes cleanroom" "SOURCE.md pins attenu-guard==0.15.0 from PyPI; not installed"

# remora: imports the remora package from the counterparty's checkout.
if have_py remora; then
  run "interop:remora-edd8a4e remora_aps_mode_b.py" python3 interop/remora-edd8a4e/remora_aps_mode_b.py
else
  skip "interop:remora-edd8a4e remora_aps_mode_b.py" "python module remora absent (SOURCE.md: counterparty checkout)"
fi

# Reproductions whose documented command takes an external checkout as an
# argument. RUN.md / SOURCE.md gives the clone URL and pinned SHA; this host has
# no such clone, so the command cannot be formed. Not a failure of the suite and
# not a pass.
skip "interop:crypto-recompute-ctef-v0.3.1-a642c17 recompute.py"  "SOURCE.md command takes <family dir at a642c17f> <ed25519_test.json at 5722833c>; external checkout absent"
skip "interop:crypto-recompute-ctef-v0.3.1-a71b7329 recompute.py" "SOURCE.md command takes <family dir at a71b7329> <ed25519_test.json at 5722833c>; external checkout absent"
skip "interop:arpa-v0.9.5-1ec3008 recompute.py"                   "RUN.md command takes the agent-registry-protocol clone at 1ec3008; external checkout absent"
skip "interop:x402-receipts-debc94f recompute.py"                 "RUN.md command takes the x402-receipts clone at debc94f; external checkout absent"

# mcp-audit-gateway: SOURCE.md's command is run from the family directory and
# both inputs are committed there, so it can be formed here.
run "interop:mcp-audit-gateway-v0.6-cleanroom recompute.py" \
  bash -c 'cd interop/mcp-audit-gateway-v0.6-cleanroom-a0f14a0 && python3 recompute.py canonicalization.json checkpoint.json'

# cleanroom oracle-safety-check: corpus is committed in this repository.
# SOURCE.md pins cryptography==50.0.1; this host has a different version, which
# is recorded on the line rather than hidden.
if have_py rfc8785 && have_py cryptography; then
  run "interop:cleanroom-oracle-safety-check cleanroom_osc.py (cryptography $(python3 -c 'import cryptography;print(cryptography.__version__)'), SOURCE.md pins 50.0.1)" \
    python3 interop/cleanroom-oracle-safety-check-6e8b05b2/cleanroom_osc.py \
    fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1
else
  skip "interop:cleanroom-oracle-safety-check cleanroom_osc.py" "pip rfc8785==0.1.4 / cryptography==50.0.1 absent"
fi

for t in \
  "interop:ethers-oracle-safety-check-6e8b05b2|interop/ethers-oracle-safety-check-6e8b05b2/eip712-recompute.mjs" \
  "interop:ethers-oracle-safety-check-9b4ffee|interop/ethers-oracle-safety-check-9b4ffee/eip712-recompute.mjs" \
  ; do
  n="${t%%|*}"; f="${t##*|}"
  if node -e 'require.resolve("ethers")' >/dev/null 2>&1; then
    run "$n" node "$f" fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1
  else
    skip "$n" "npm ethers not installed (SOURCE.md reproduction dependency)"
  fi
done

# Reproductions documented in RUN.md / README.md rather than SOURCE.md. They are
# entrypoints all the same, and leaving them out of an inventory would say the
# suite runs less than it does.
MIH_OUT="$(mktemp -d)"
run "interop:mih-sato-composition-00 adapter/ts/run.ts" \
  bash -c "cd interop/mih-sato-composition-00 && OUT_DIR='$MIH_OUT' npx tsx adapter/ts/run.ts"
run "interop:mih-sato-composition-00 adapter/py/run.py" \
  bash -c "cd interop/mih-sato-composition-00 && OUT_DIR='$MIH_OUT' python3 adapter/py/run.py"
rm -rf "$MIH_OUT"
skip "interop:scitt-cose-vectors-ietf126 verifier/run.ts"       "README.md command takes VECTORS_DIR=./scitt-cose/test-vectors; external checkout absent"
skip "interop:scitt-cose-vectors-ietf126 verifier/selfattack.ts" "README.md command takes VECTORS_DIR=./scitt-cose/test-vectors; external checkout absent"
skip "interop:a2a-go-368-jcs run.sh"          "run.sh clones a2a-go at 411e3e81 and needs the go toolchain; network/toolchain absent"
skip "interop:a2a-go-368-jcs-ea003f9 run.sh"  "run.sh clones a2a-go at its pinned head and needs the go toolchain; network/toolchain absent"
skip "interop:ca2a-validity-window-d3db81c"   "RUN.md command clones agentrust-io/ca2a at d3db81c and runs its pytest; external checkout absent"
skip "interop:insight-oracle-safety-check-13bd3ed" "run-report.md records a counterparty run; no command in this tree"
skip "interop:ctef-v0.3.1-admissibility-checker-fd256bc4-run-aeoess" "SOURCE.md command is python3 checker.py inside the counterparty checkout at fd256bc4; absent"
skip "interop:ctef-v0.3.1-admissibility-giskard09-a642c17" "SOURCE.md records a counterparty run; no command in this tree"
skip "interop:aae-envelope moltycel-format crossverify.py" "build/crossverify scripts read the MoltyCel format drop; not wired to a documented standing command"

# ---------------------------------------------------------------- summary
echo "================ SUMMARY ================"
printf '%s\n' "${LINES[@]}"
echo
echo "runners=$(( PASS + FAIL + SKIP + NOTRUN )) PASS=$PASS FAILED=$FAIL SKIPPED=$SKIP NOT_RUN=$NOTRUN"
if [ "$FAIL" -gt 0 ]; then echo "result: FAILED"; exit 1; fi
if [ "$SKIP" -gt 0 ] || [ "$NOTRUN" -gt 0 ]; then echo "result: PASS WITH SKIPS (not a clean run)"; exit 0; fi
echo "result: PASS"
