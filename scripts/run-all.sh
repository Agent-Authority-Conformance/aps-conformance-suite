#!/usr/bin/env bash
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Runs every documented entrypoint of this repository in one pass and prints one
# line per runner.
#
# WHY THIS EXISTS. No single documented command runs the whole set. `npm test`
# is the hermetic default gate and .github/workflows/tests.yml says
# "Deliberately NOT in `npm test`" of both the schema-parity validators and the
# cross-stack families. `npm run verify:cross-stack` covers the cross-stack
# registry and nothing else. The repository-hygiene workflow's checks live only
# as inline shell in YAML. The Go runner is named in README.md and wired to no
# command. The interop reproductions live only in interop/*/SOURCE.md, RUN.md
# and README.md. A reviewer asking "what does the suite actually execute" had to
# read six files; this runs all six sources and reports.
#
# ---------------------------------------------------------------------------
# STATUS VOCABULARY. Four values, and no others. The suite has published this
# vocabulary and this file does not fork it.
#
#   PASS     the command ran and exited 0
#   FAILED   the command ran and exited nonzero
#   SKIPPED  a prerequisite was CHECKED and found missing. Every SKIPPED line
#            names the prerequisite that was checked and what the check saw.
#            There are no unconditional skips in this file: a skip is the result
#            of a test, never an assumption about the host.
#   NOT_RUN  no runnable command exists for this entry. Used for a family whose
#            directory holds a counterparty's run record and no script, and for
#            a declared stub.
#
# A missing prerequisite is never converted into a pass. The script exits
# nonzero if any runner FAILED. SKIPPED and NOT_RUN are counted separately, and
# a run carrying either prints "PASS WITH SKIPS (not a clean run)".
#
# ---------------------------------------------------------------------------
# VERSION PIN POLICY, uniform and without exception. A version named in a
# family's SOURCE.md, RUN.md or README.md is part of that reproduction's
# identity, so it is a prerequisite like any other. If the installed version
# differs from the pinned one, the runner is SKIPPED and BOTH versions appear on
# the line. Running under a different version produces a different reproduction,
# and labelling it PASS would attach the family's recorded result to bytes that
# never produced it.
#
# The earlier revision of this file applied that rule to
# agent-passport-system (pinned 4.5.1, installed 6.0.0, skipped) and not to
# cryptography (pinned 50.0.1, installed 49.0.0, run and reported PASS). One
# rule now, applied to both.
#
# ---------------------------------------------------------------------------
# EXIT CODES AND VECTOR TALLIES ARE DIFFERENT THINGS, and this file never prints
# one as the other.
#
#   exit=      the command's own exit status, read directly from `$?` on the
#              command itself. Never read through a pipe: `cmd | tail; echo $?`
#              reports tail's status, not the command's, and reading one that
#              way is how the earlier revision recorded runners/python/verify.py
#              as exiting 0 when it exits 2.
#   vectors=   the runner's OWN reported vector numbers, parsed out of its
#              output by scripts/run-all-tally.py, with the pattern that matched
#              named in src=. `vectors=na` means the runner reported no numbers,
#              which is a fact about the runner and is printed as such rather
#              than filled in from the exit code.
#
# ---------------------------------------------------------------------------
# This script does not mutate the tree. Generators (npm run readme:inventory,
# the generate-*.ts / generate_*.py files) are excluded by name for that reason,
# and so are the pure aggregates (`npm test`, `npm run verify:cross-stack`,
# `cross-stack:oracle-safety-check:verify`) whose leaves are all run directly.
#
# Run: bash scripts/run-all.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUTDIR="$(mktemp -d)"
trap 'rm -rf "$OUTDIR"' EXIT

PASS=0; FAIL=0; SKIP=0; NOTRUN=0
declare -a LINES=()

emit() { # name status exit vectors reason
  LINES+=("$(printf '%-52s %-8s exit=%-5s %-46s %s' "$1" "$2" "$3" "$4" "${5:-}")")
}

# run NAME CMD...  -- the exit status is read from the command itself.
run() {
  local name="$1"; shift
  local slug; slug="$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_')"
  local out="$OUTDIR/$slug.out"
  echo "--- RUN $name : $*"
  "$@" > "$out" 2>&1
  local code=$?              # the command's status, not a pipeline's
  cat "$out"
  local tally
  tally="$(python3 "$REPO_ROOT/scripts/run-all-tally.py" "$out" 2>/dev/null || echo 'vectors=na vpass=na vfail=na vskip=na src=error')"
  if [ $code -eq 0 ]; then
    PASS=$((PASS+1)); emit "$name" PASS "$code" "$tally"
  else
    FAIL=$((FAIL+1)); emit "$name" FAILED "$code" "$tally"
  fi
  echo "--- END $name : exit=$code  $tally"
  echo
}

# skip NAME REASON -- only ever called after a prerequisite check has run.
skip() {
  echo "--- SKIP $1 : $2"
  SKIP=$((SKIP+1)); emit "$1" SKIPPED "-" "vectors=na vpass=na vfail=na vskip=na src=none" "prereq: $2"
  echo
}

# not_run NAME REASON -- no runnable command exists for this entry.
not_run() {
  echo "--- NOT_RUN $1 : $2"
  NOTRUN=$((NOTRUN+1)); emit "$1" NOT_RUN "-" "vectors=na vpass=na vfail=na vskip=na src=none" "$2"
  echo
}

# ------------------------------------------------------- prerequisite checks
# Each returns 0 when the prerequisite is present and prints nothing; on absence
# it returns 1 and prints what the check saw, which becomes the skip reason.

have_bin() { command -v "$1" >/dev/null 2>&1; }

check_bin() { # cmd
  if command -v "$1" >/dev/null 2>&1; then return 0; fi
  echo "command \`$1\` not on PATH (checked with command -v)"; return 1
}

check_py_mod() { # module
  if python3 -c "import $1" >/dev/null 2>&1; then return 0; fi
  echo "python module \`$1\` not importable (checked with python3 -c 'import $1')"; return 1
}

check_py_pin() { # module pinned_version
  local mod="$1" pin="$2" got
  if ! python3 -c "import $mod" >/dev/null 2>&1; then
    echo "python module \`$mod\` not importable; the family pins $mod==$pin"; return 1
  fi
  got="$(python3 -c "import $mod,sys; sys.stdout.write(getattr($mod,'__version__','unknown'))" 2>/dev/null)"
  if [ "$got" = "$pin" ]; then return 0; fi
  echo "version pin: the family pins $mod==$pin, installed is $mod==$got"; return 1
}

check_node_pin() { # package pinned_version
  local pkg="$1" pin="$2" got
  got="$(node -e '
    const fs=require("fs"),p=process.argv[1];
    try{process.stdout.write(JSON.parse(fs.readFileSync("node_modules/"+p+"/package.json","utf8")).version)}
    catch(e){process.stdout.write("absent")}' "$pkg" 2>/dev/null)"
  if [ "$got" = "absent" ]; then
    echo "npm package \`$pkg\` not installed; the family pins $pkg@$pin"; return 1
  fi
  if [ "$got" = "$pin" ]; then return 0; fi
  echo "version pin: the family pins $pkg@$pin, installed is $pkg@$got"; return 1
}

check_node_pkg() { # package
  local got
  got="$(node -e '
    const fs=require("fs"),p=process.argv[1];
    try{JSON.parse(fs.readFileSync("node_modules/"+p+"/package.json","utf8"));process.stdout.write("ok")}
    catch(e){process.stdout.write("absent")}' "$1" 2>/dev/null)"
  [ "$got" = "ok" ] && return 0
  echo "npm package \`$1\` not installed under node_modules/ (checked by reading its package.json)"; return 1
}

check_path() { # path what
  if [ -e "$1" ]; then return 0; fi
  echo "$2 not present at \`$1\` (checked with test -e)"; return 1
}

check_grep_p() {
  if echo x | grep -q -P 'x' 2>/dev/null; then return 0; fi
  echo "grep -P unsupported on this host (checked with echo x | grep -q -P x); BSD grep has no PCRE"; return 1
}

echo "run-all.sh: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo: $REPO_ROOT"
echo "HEAD: $(git rev-parse HEAD 2>/dev/null || echo '?')"
echo "node: $(node -v 2>/dev/null || echo absent)  npm: $(npm -v 2>/dev/null || echo absent)  python3: $(python3 -V 2>&1 || echo absent)  go: $(go version 2>/dev/null || echo absent)"
echo

# ---------------------------------------------------------------- 1. npm scripts
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
if ! r="$(check_path node_modules 'dev dependencies')"; then
  for s in "${NPM_SCRIPTS[@]}"; do skip "npm:$s" "$r; run npm ci --include=dev"; done
else
  for s in "${NPM_SCRIPTS[@]}"; do
    if ! node -e 'const s=require("./package.json").scripts||{};process.exit(s[process.argv[1]]?0:1)' "$s"; then
      not_run "npm:$s" "no such script in package.json"
      continue
    fi
    run "npm:$s" npm run --silent "$s"
  done
fi

# --------------------------------- 2. workflow-only commands (tests.yml)
echo "================ 2. .github/workflows/tests.yml schema-parity ================"
# tests.yml pins these two: python -m pip install jsonschema==4.26.0 cryptography==49.0.0
PARITY_OK=1; PARITY_R=""
if ! PARITY_R="$(check_py_pin jsonschema 4.26.0)"; then PARITY_OK=0; fi
if [ "$PARITY_OK" -eq 1 ] && ! PARITY_R="$(check_py_pin cryptography 49.0.0)"; then PARITY_OK=0; fi
if [ "$PARITY_OK" -eq 1 ]; then
  run "wf:tests.yml accountability-record/validate.py" python3 fixtures/accountability-record/validate.py
  run "wf:tests.yml read-fidelity-receipt/validate.py" python3 fixtures/read-fidelity-receipt/validate.py
else
  skip "wf:tests.yml accountability-record/validate.py" "$PARITY_R"
  skip "wf:tests.yml read-fidelity-receipt/validate.py" "$PARITY_R"
fi

# --------------------------- 2b. the other language runners README.md names
echo "================ 2b. Go and Python runners (README.md line 89) ================"
if r="$(check_bin go)"; then
  run "runners/go: go run ."      bash -c 'cd runners/go && go run .'
  run "runners/go: go test ./..." bash -c 'cd runners/go && go test ./...'
else
  skip "runners/go: go run ."      "$r"
  skip "runners/go: go test ./..." "$r"
fi
# runners/python/verify.py is a declared stub. Its docstring says "Status: stub,
# not yet implemented. Do not run." and it exits 2. NOT_RUN is the label for an
# entry with no runnable command; it is not SKIPPED, because no prerequisite is
# missing, and it is not FAILED, because exiting 2 is the stub working.
not_run "runners/python/verify.py" "declared stub (docstring: \"Status: stub, not yet implemented. Do not run.\"); exits 2 by design, asserts nothing"
if r="$(check_py_mod pytest)"; then
  run "tests/test_aat_runner.py (pytest)" python3 -m pytest -q tests/test_aat_runner.py
else
  skip "tests/test_aat_runner.py (pytest)" "$r"
fi

# ------------------------- 3. workflow-only commands (repository-hygiene.yml)
echo "================ 3. .github/workflows/repository-hygiene.yml ================"
# The absolute-path pattern is ASSEMBLED AT RUNTIME rather than written out.
# Writing it out is what broke the previous revision: this file is tracked, the
# workflow scans every tracked file except repository-hygiene.yml, and a literal
# home-directory prefix inside the transcription made the transcription fail on
# itself. Commit cb97451 carried exactly that defect and would have failed the
# repository-hygiene job on CI. Assembling the pattern keeps the check faithful
# to the workflow without adding this file to the workflow's exclusion list,
# which would have weakened the check to hide the problem.
HYG_U="$(printf '/%s/' Users)"
HYG_H="$(printf '/%s/' home)"
HYG_PAT="${HYG_U}|${HYG_H}"
HYG_STRIP="${HYG_U}agent/workspace"
hyg_abs() {
  hits=$(git ls-files -z | grep -zv -E '^\.github/workflows/repository-hygiene\.yml$' \
    | xargs -0 grep -n -E "$HYG_PAT" /dev/null 2>/dev/null \
    | sed "s|$HYG_STRIP||g" | grep -E "$HYG_PAT" || true)
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
if r="$(check_grep_p)"; then
  run "wf:hygiene CRLF in pinned evidence" hyg_crlf
else
  skip "wf:hygiene CRLF in pinned evidence" "$r"
fi

# ------------------------ 4. interop reproductions (SOURCE.md / RUN.md / README.md)
echo "================ 4. interop reproductions ================"

# hjs-bb6be62. SOURCE.md pins rfc8785==0.1.4, jcs==0.2.1 and
# agent-passport-system@4.5.1, one per witness.
if r="$(check_py_pin rfc8785 0.1.4)"; then
  run "interop:hjs-bb6be62 run-rfc8785-witness.py" python3 interop/hjs-bb6be62/run-rfc8785-witness.py
else
  skip "interop:hjs-bb6be62 run-rfc8785-witness.py" "$r"
fi
if r="$(check_py_pin jcs 0.2.1)"; then
  run "interop:hjs-bb6be62 rerun-hjs-over-aps.py" python3 interop/hjs-bb6be62/rerun-hjs-over-aps.py
else
  skip "interop:hjs-bb6be62 rerun-hjs-over-aps.py" "$r"
fi
if r="$(check_node_pin agent-passport-system 4.5.1)"; then
  run "interop:hjs-bb6be62 run-aps-witness.mjs" node interop/hjs-bb6be62/run-aps-witness.mjs
else
  skip "interop:hjs-bb6be62 run-aps-witness.mjs" "$r"
fi

# attenu-guard. The cleanroom verifiers are stdlib plus rfc8785 (and cryptography
# for the envelope ones) and take the vectors JSON as argv[1]. That file ships
# inside the attenu_guard distribution, not in this tree, so the prerequisite
# that is actually checked is the module and the vectors path resolved from it.
ag_vectors() { # relative path inside the package
  python3 - "$1" <<'PY' 2>/dev/null
import importlib.util, os, sys
spec = importlib.util.find_spec('attenu_guard')
if not spec or not spec.submodule_search_locations:
    sys.exit(1)
p = os.path.join(list(spec.submodule_search_locations)[0], sys.argv[1])
print(p if os.path.exists(p) else '', end='')
PY
}
ag_case() { # label relpath script needs_crypto
  local label="$1" rel="$2" script="$3" needs_crypto="$4" r vec
  if ! r="$(check_py_pin rfc8785 0.1.4)"; then skip "$label" "$r"; return; fi
  if [ "$needs_crypto" = "yes" ] && ! r="$(check_py_mod cryptography)"; then skip "$label" "$r"; return; fi
  if ! r="$(check_py_mod attenu_guard)"; then
    skip "$label" "$r; the vectors file \`$rel\` ships inside that distribution"
    return
  fi
  vec="$(ag_vectors "$rel")"
  if [ -z "$vec" ]; then
    skip "$label" "attenu_guard is importable but carries no \`$rel\` (checked by resolving the package path)"
    return
  fi
  run "$label" python3 "$script" "$vec"
}
ag_case "interop:attenu-guard-0.11.0-bundles cleanroom" \
        "vectors/bundles/bundle_vectors_v1.json" \
        "interop/attenu-guard-0.11.0-bundles/cleanroom/verify_bundle_v1.py" no
ag_case "interop:attenu-guard-0.13.0-envelopes cleanroom" \
        "vectors/envelopes/envelope_vectors_v1.json" \
        "interop/attenu-guard-0.13.0-envelopes/cleanroom/verify_envelope_v1.py" yes
ag_case "interop:attenu-guard-0.15.0-envelopes cleanroom" \
        "vectors/envelopes/envelope_vectors_v1.json" \
        "interop/attenu-guard-0.15.0-envelopes/cleanroom/verify_envelope_v1.py" yes
for v in 0.6.0 0.6.1; do
  for s in jcs-byte-diff.py cleanroom/verify_asor00.py; do
    lbl="interop:attenu-guard-$v $s"
    if [ ! -f "interop/attenu-guard-$v/$s" ]; then
      not_run "$lbl" "no such file in this tree"
    elif r="$(check_py_mod attenu_guard)"; then
      run "$lbl" python3 "interop/attenu-guard-$v/$s"
    else
      skip "$lbl" "$r (the script imports it at module scope)"
    fi
  done
done
# 0.8.0 carries SOURCE.md and two results files and no script at all.
not_run "interop:attenu-guard-0.8.0" "the family directory holds SOURCE.md and two results files; no script exists in this tree (checked with find)"

# remora
if r="$(check_py_mod remora)"; then
  run "interop:remora-edd8a4e remora_aps_mode_b.py" python3 interop/remora-edd8a4e/remora_aps_mode_b.py
else
  skip "interop:remora-edd8a4e remora_aps_mode_b.py" "$r (SOURCE.md runs it inside the counterparty checkout)"
fi

# Reproductions whose documented command takes an external checkout. The
# prerequisite is that checkout at the path the family's RUN.md/SOURCE.md names,
# or the environment variable this script defines for the two that name none.
if r="$(check_path "${APS_CTEF_FAMILY_DIR:-/nonexistent}" 'the ctef family dir at a642c17f (set APS_CTEF_FAMILY_DIR)')"; then
  if r2="$(check_path "${APS_CTEF_ED25519_JSON:-/nonexistent}" 'ed25519_test.json at 5722833c (set APS_CTEF_ED25519_JSON)')"; then
    run "interop:crypto-recompute-ctef-v0.3.1-a642c17 recompute.py" \
      python3 interop/crypto-recompute-ctef-v0.3.1-a642c17/recompute.py "$APS_CTEF_FAMILY_DIR" "$APS_CTEF_ED25519_JSON"
  else
    skip "interop:crypto-recompute-ctef-v0.3.1-a642c17 recompute.py" "$r2"
  fi
else
  skip "interop:crypto-recompute-ctef-v0.3.1-a642c17 recompute.py" "$r"
fi
if r="$(check_path "${APS_CTEF_FAMILY_DIR_A71:-/nonexistent}" 'the ctef family dir at a71b7329 (set APS_CTEF_FAMILY_DIR_A71)')"; then
  if r2="$(check_path "${APS_CTEF_ED25519_JSON:-/nonexistent}" 'ed25519_test.json at 5722833c (set APS_CTEF_ED25519_JSON)')"; then
    run "interop:crypto-recompute-ctef-v0.3.1-a71b7329 recompute.py" \
      python3 interop/crypto-recompute-ctef-v0.3.1-a71b7329/recompute.py "$APS_CTEF_FAMILY_DIR_A71" "$APS_CTEF_ED25519_JSON"
  else
    skip "interop:crypto-recompute-ctef-v0.3.1-a71b7329 recompute.py" "$r2"
  fi
else
  skip "interop:crypto-recompute-ctef-v0.3.1-a71b7329 recompute.py" "$r"
fi
# An external checkout is only the prerequisite when it IS the pinned checkout.
# `test -e` on the path is not that test: this host carries stale leftovers at
# all three of these paths (no .git, a node_modules or a .venv and nothing else)
# and the previous revision of this check reported one of them as a PASS. The
# check is now a git HEAD comparison against the pinned SHA plus the input the
# documented command actually reads.
check_checkout() { # dir pinned_sha needed_path description
  local d="$1" pin="$2" need="$3" desc="$4" head
  if [ ! -d "$d/.git" ]; then
    echo "$desc: no git checkout at \`$d\` (checked with test -d $d/.git)"; return 1
  fi
  head="$(git -C "$d" rev-parse HEAD 2>/dev/null)"
  if [ "$head" != "$pin" ]; then
    echo "$desc: \`$d\` is at ${head:-unknown}, the pin is $pin"; return 1
  fi
  if [ -n "$need" ] && [ ! -e "$d/$need" ]; then
    echo "$desc: \`$d\` is at the pin but carries no \`$need\`"; return 1
  fi
  return 0
}
if r="$(check_checkout /tmp/arpa-v095-repro 1ec3008effc00f3ccbac26769f5528d97d065c9b scripts/requirements.txt 'the agent-registry-protocol clone RUN.md pins at 1ec3008')"; then
  run "interop:arpa-v0.9.5-1ec3008 recompute.py" python3 interop/arpa-v0.9.5-1ec3008/recompute.py /tmp/arpa-v095-repro
else
  skip "interop:arpa-v0.9.5-1ec3008 recompute.py" "$r"
fi
if r="$(check_checkout /tmp/x402-receipts-repro debc94f39dfa9f62855c4602c1baafc9d61f4642 vectors 'the x402-receipts clone RUN.md pins at debc94f')"; then
  run "interop:x402-receipts-debc94f recompute.py" python3 interop/x402-receipts-debc94f/recompute.py /tmp/x402-receipts-repro
else
  skip "interop:x402-receipts-debc94f recompute.py" "$r"
fi
if r="$(check_checkout /tmp/ca2a-repro d3db81cd98a64074a74cbf976fdba5ecbbfaa6f7 tests/conformance/test_profile_conformance.py 'the agentrust-io/ca2a clone RUN.md pins at d3db81c')"; then
  if r2="$(check_py_mod pytest)"; then
    run "interop:ca2a-validity-window-d3db81c (pytest)" \
      bash -c 'cd /tmp/ca2a-repro && python3 -m pytest tests/conformance/test_profile_conformance.py -q'
  else
    skip "interop:ca2a-validity-window-d3db81c (pytest)" "$r2"
  fi
else
  skip "interop:ca2a-validity-window-d3db81c (pytest)" "$r"
fi

# mcp-audit-gateway: SOURCE.md's command runs from the family directory and both
# inputs are committed there.
if r="$(check_path interop/mcp-audit-gateway-v0.6-cleanroom-a0f14a0/canonicalization.json 'the committed canonicalization.json input')"; then
  run "interop:mcp-audit-gateway-v0.6-cleanroom recompute.py" \
    bash -c 'cd interop/mcp-audit-gateway-v0.6-cleanroom-a0f14a0 && python3 recompute.py canonicalization.json checkpoint.json'
else
  skip "interop:mcp-audit-gateway-v0.6-cleanroom recompute.py" "$r"
fi

# cleanroom oracle-safety-check: the corpus is committed here; its
# requirements.txt pins rfc8785==0.1.4 and cryptography==50.0.1.
CLR_OK=1; CLR_R=""
if ! CLR_R="$(check_py_pin rfc8785 0.1.4)"; then CLR_OK=0; fi
if [ "$CLR_OK" -eq 1 ] && ! CLR_R="$(check_py_pin cryptography 50.0.1)"; then CLR_OK=0; fi
if [ "$CLR_OK" -eq 1 ]; then
  run "interop:cleanroom-oracle-safety-check cleanroom_osc.py" \
    python3 interop/cleanroom-oracle-safety-check-6e8b05b2/cleanroom_osc.py \
    fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1
else
  skip "interop:cleanroom-oracle-safety-check cleanroom_osc.py" "$CLR_R"
fi

# ethers recomputations. Each family ships its own package.json naming the pin.
for t in \
  "interop:ethers-oracle-safety-check-6e8b05b2|interop/ethers-oracle-safety-check-6e8b05b2" \
  "interop:ethers-oracle-safety-check-9b4ffee|interop/ethers-oracle-safety-check-9b4ffee" \
  ; do
  n="${t%%|*}"; d="${t##*|}"
  pin="$(node -e '
    const fs=require("fs");
    try{const p=JSON.parse(fs.readFileSync(process.argv[1]+"/package.json","utf8"));
        process.stdout.write(((p.dependencies||{}).ethers||"unpinned").replace(/^[^0-9]*/,""))}
    catch(e){process.stdout.write("unpinned")}' "$d" 2>/dev/null)"
  if r="$(check_node_pin ethers "$pin")"; then
    run "$n eip712-recompute.mjs" node "$d/eip712-recompute.mjs" fixtures/cross-stack/oracle-safety-check/oracle-safety-check-v1
  else
    skip "$n eip712-recompute.mjs" "$r"
  fi
done

# mih-sato-composition-00: README.md documents two adapters and the corpus is
# committed here. OUT_DIR is redirected so the run does not write into the tree.
MIH_OUT="$OUTDIR/mih"
mkdir -p "$MIH_OUT"
if r="$(check_path interop/mih-sato-composition-00/corpus 'the committed cross-slot corpus')"; then
  run "interop:mih-sato-composition-00 adapter/ts/run.ts" \
    bash -c "cd interop/mih-sato-composition-00 && OUT_DIR='$MIH_OUT' npx tsx adapter/ts/run.ts"
  run "interop:mih-sato-composition-00 adapter/py/run.py" \
    bash -c "cd interop/mih-sato-composition-00 && OUT_DIR='$MIH_OUT' python3 adapter/py/run.py"
else
  skip "interop:mih-sato-composition-00 adapter/ts/run.ts" "$r"
  skip "interop:mih-sato-composition-00 adapter/py/run.py" "$r"
fi

# scitt-cose-vectors-ietf126: README.md's command names VECTORS_DIR.
SCITT_VEC="interop/scitt-cose-vectors-ietf126/scitt-cose/test-vectors"
for t in "verifier/run.ts" "verifier/selfattack.ts"; do
  if r="$(check_path "$SCITT_VEC" 'the scitt-cose test-vector checkout README.md names as VECTORS_DIR')"; then
    run "interop:scitt-cose-vectors-ietf126 $t" \
      bash -c "cd interop/scitt-cose-vectors-ietf126 && VECTORS_DIR=./scitt-cose/test-vectors OUT_DIR='$OUTDIR' npx tsx $t"
  else
    skip "interop:scitt-cose-vectors-ietf126 $t" "$r"
  fi
done

# a2a-go: run.sh clones the external repo at a pinned SHA and runs go test in it.
# Two prerequisites, both checked: the go toolchain, and reachability of the
# pinned remote (a read-only git ls-remote, no clone).
check_remote() { # url
  if git ls-remote --exit-code "$1" HEAD >/dev/null 2>&1; then return 0; fi
  echo "pinned remote \`$1\` unreachable (checked with git ls-remote --exit-code)"; return 1
}
for d in interop/a2a-go-368-jcs interop/a2a-go-368-jcs-ea003f9; do
  n="interop:$(basename "$d") run.sh"
  if ! r="$(check_bin go)"; then skip "$n" "$r"; continue; fi
  if ! r="$(check_remote https://github.com/kuangmi-bit/a2a-go.git)"; then skip "$n" "$r"; continue; fi
  run "$n" bash "$d/run.sh"
done

# aae-envelope moltycel-format crossverify scripts read a schema from a path the
# drop is unpacked to.
for t in "moltycel-format/crossverify.py" "moltycel-format/constraint-monotonicity/crossverify.py"; do
  n="interop:aae-envelope $t"
  if r="$(check_path /tmp/aae-moltycel/schema/vector-schema.json 'the MoltyCel format drop schema the script reads')"; then
    run "$n" python3 "interop/aae-envelope/$t"
  else
    skip "$n" "$r"
  fi
done

# Families that hold a counterparty's recorded run and no script of ours.
not_run "interop:insight-oracle-safety-check-13bd3ed" "the family directory holds run-report.md only; no script exists in this tree (checked with find)"
not_run "interop:ctef-v0.3.1-admissibility-checker-fd256bc4-run-aeoess" "the family directory holds SOURCE.md and a results file; SOURCE.md's \`python3 checker.py\` runs inside the counterparty checkout at fd256bc4, and no checker.py exists here"
not_run "interop:ctef-v0.3.1-admissibility-giskard09-a642c17" "the family directory holds SOURCE.md and a results file; no script exists in this tree"

# ---------------------------------------------------------------- summary
echo "================ SUMMARY ================"
echo "exit=    the command's own status, read directly from \$? on the command."
echo "vectors= the runner's OWN reported numbers, parsed from its output; na means the runner reported none."
echo
printf '%s\n' "${LINES[@]}"
echo
echo "runners=$(( PASS + FAIL + SKIP + NOTRUN )) PASS=$PASS FAILED=$FAIL SKIPPED=$SKIP NOT_RUN=$NOTRUN"
if [ "$FAIL" -gt 0 ]; then echo "result: FAILED"; exit 1; fi
if [ "$SKIP" -gt 0 ] || [ "$NOTRUN" -gt 0 ]; then echo "result: PASS WITH SKIPS (not a clean run)"; exit 0; fi
echo "result: PASS"
