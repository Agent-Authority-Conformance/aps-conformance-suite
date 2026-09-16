#!/usr/bin/env bash
# Reproduction script for the wasmagent AEP layered run.
# Clones the three component repos at the pinned SHAs into a scratch directory, places the
# lab-owned adapters, executes all four surfaces, preserves exit codes.
# Requires no pre-existing local checkout or state. Requires network access for
# repository, package, Rust crate and toolchain fetches not already available locally.
# Requires: git, bun, rustup, cargo, python3. The Rust surface is pinned by the proxy
# repository's rust-toolchain.toml, which only takes effect when cargo is a rustup proxy,
# so the run asserts the active toolchain rather than reporting it.
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
( cd "$WORK/adapter" && bun add --exact @noble/ed25519@3.1.0 zod@3.25.76 >/dev/null 2>&1 )
ln -sfn "$WORK/adapter/node_modules" "$WORK/wasmagent-js/node_modules"
( cd "$WORK/adapter" && bun run js-driver.ts > "$WORK/evidence/native-js.json" )
JS_EXIT=$?; echo "JS_DRIVER_EXIT=$JS_EXIT"
cp "$WORK/evidence/native-js.json" "$WORK/out/" 2>/dev/null

# --- RUST-NATIVE-DSSE ---
cp "$HERE/adapter/lab-driver.rs" "$WORK/wasmagent-proxy/crates/aep-core/tests/lab_driver.rs"
mkdir -p "$WORK/evidence"
PROXY_CARGO="$(cd "$WORK/wasmagent-proxy" && cargo --version 2>&1)"
PROXY_RUSTC="$(cd "$WORK/wasmagent-proxy" && rustc --version 2>&1)"
echo "proxy cargo: $PROXY_CARGO"
echo "proxy rustc: $PROXY_RUSTC"
case "$PROXY_CARGO" in
  "cargo 1.96.1 "*) ;;
  *) echo "RUST TOOLCHAIN MISMATCH: $PROXY_CARGO"; exit 2 ;;
esac
case "$PROXY_RUSTC" in
  "rustc 1.96.1 "*) ;;
  *) echo "RUST TOOLCHAIN MISMATCH: $PROXY_RUSTC"; exit 2 ;;
esac
( cd "$WORK/wasmagent-proxy" && cargo test --locked -p aep-core --test lab_driver -- --nocapture >"$WORK/out/rust.log" 2>&1 )
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

# --- verify the regenerated artifacts equal the committed evidence ---
# One gate, one purpose: a reproduction that silently differs from the record is a
# failure, never a repair. run.sh never writes into results/.
DIFF_EXIT=0
for f in native-js.json native-rust.json lab-semantic.json consolidated-matrix.json; do
  if [ ! -f "$WORK/out/$f" ]; then echo "MISSING regenerated $f"; DIFF_EXIT=1; continue; fi
  if ! cmp -s "$HERE/results/$f" "$WORK/out/$f"; then
    echo "DIFFERS from committed evidence: $f"
    echo "  committed   $(shasum -a 256 "$HERE/results/$f" | cut -d' ' -f1)"
    echo "  regenerated $(shasum -a 256 "$WORK/out/$f" | cut -d' ' -f1)"
    DIFF_EXIT=1
  else
    echo "matches committed evidence: $f"
  fi
done
echo "REGEN_DIFF_EXIT=$DIFF_EXIT"

echo "outputs in $WORK/out"
echo "EXITS js=$JS_EXIT rust=$RUST_EXIT lab_semantic=$SEM_EXIT matrix=$MATRIX_EXIT diff=$DIFF_EXIT"
[ "$JS_EXIT" -eq 0 ] && [ "$RUST_EXIT" -eq 0 ] && [ "$SEM_EXIT" -eq 0 ] && [ "$MATRIX_EXIT" -eq 0 ] && [ "$DIFF_EXIT" -eq 0 ]
