#!/usr/bin/env bash
# Reproduction script for the wasmagent AEP layered run.
# Self-contained: clones the three component repos at the pinned SHAs into a scratch
# directory, places the lab-owned adapters, executes all four surfaces, preserves exit codes.
# Depends on no state outside this directory. Requires: git, bun, cargo, python3.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${1:-$(mktemp -d)}"
PROTOCOL_SHA=35320c567ba02ae30ba441f488952954dd66a4cc
JS_SHA=bb71077cbd13051c05e17195d11d16efd0d1c572
PROXY_SHA=4b4bde3b2e06eb62b7910cb3f379d75288cc4db1

echo "scratch: $WORK"
mkdir -p "$WORK/out" "$WORK/evidence"

clone_at() { # repo sha dir
  git clone -q "https://github.com/WasmAgent/$1.git" "$WORK/$3" || return 1
  git -C "$WORK/$3" checkout -q "$2" || return 1
  got=$(git -C "$WORK/$3" rev-parse HEAD)
  [ "$got" = "$2" ] || { echo "PIN MISMATCH $1: want $2 got $got"; return 1; }
  echo "pinned $1 @ $got"
}
clone_at wasmagent-protocol "$PROTOCOL_SHA" wasmagent-protocol || exit 2
clone_at wasmagent-js       "$JS_SHA"       wasmagent-js       || exit 2
clone_at wasmagent-proxy    "$PROXY_SHA"    wasmagent-proxy    || exit 2

# --- JS-NATIVE-RECORD and JS-NATIVE-CHAIN ---
mkdir -p "$WORK/adapter"
cp "$HERE/adapter/js-driver.ts" "$WORK/adapter/"
printf '{ "name": "aep-lab-adapter", "private": true, "type": "module" }\n' > "$WORK/adapter/package.json"
( cd "$WORK/adapter" && bun add @noble/ed25519@^3.1.0 zod@^3.23.0 >/dev/null 2>&1 )
ln -sfn "$WORK/adapter/node_modules" "$WORK/wasmagent-js/node_modules"
( cd "$WORK/adapter" && bun run js-driver.ts > "$WORK/evidence/native-js.json" )
JS_EXIT=$?; echo "JS_DRIVER_EXIT=$JS_EXIT"
cp "$WORK/evidence/native-js.json" "$WORK/out/" 2>/dev/null

# --- RUST-NATIVE-DSSE ---
cp "$HERE/adapter/lab-driver.rs" "$WORK/wasmagent-proxy/crates/aep-core/tests/lab_driver.rs"
mkdir -p "$WORK/evidence"
( cd "$WORK/wasmagent-proxy" && cargo test -p aep-core --test lab_driver -- --nocapture >"$WORK/out/rust.log" 2>&1 )
RUST_EXIT=$?; echo "CARGO_EXIT=$RUST_EXIT"
[ -f "$WORK/evidence/native-rust.json" ] && cp "$WORK/evidence/native-rust.json" "$WORK/out/native-rust.json"

# --- LAB-SEMANTIC ---
cp "$HERE/adapter/lab-semantic.py" "$WORK/adapter/"
mkdir -p "$WORK/evidence"
( cd "$WORK/adapter" && python3 lab-semantic.py )
SEM_EXIT=$?; echo "LAB_SEMANTIC_EXIT=$SEM_EXIT"
[ -f "$WORK/evidence/lab-semantic.json" ] && cp "$WORK/evidence/lab-semantic.json" "$WORK/out/"

# --- consolidated matrix (aggregation only, no verification decision) ---
cp "$HERE/adapter/build-matrix.py" "$WORK/adapter/"
( cd "$WORK/adapter" && python3 build-matrix.py )
MATRIX_EXIT=$?; echo "BUILD_MATRIX_EXIT=$MATRIX_EXIT"
[ -f "$WORK/evidence/consolidated-matrix.json" ] && cp "$WORK/evidence/consolidated-matrix.json" "$WORK/out/"

echo "outputs in $WORK/out"
echo "EXITS js=$JS_EXIT rust=$RUST_EXIT lab_semantic=$SEM_EXIT matrix=$MATRIX_EXIT"
[ "$JS_EXIT" -eq 0 ] && [ "$RUST_EXIT" -eq 0 ] && [ "$SEM_EXIT" -eq 0 ] && [ "$MATRIX_EXIT" -eq 0 ]
