# Artifact handoff: environment observations

Observations from running the reproduction on macOS. Environment only.

- Platform: macOS 26.5 on arm64. The runner header line in `test-output.log` records
  `RUN  v4.1.10 /private/tmp/x402-receipts-repro`.

- macOS resolves `/tmp` through `/private/tmp`, so vitest records the rootdir as
  `/private/tmp/x402-receipts-repro` even though the run was started from
  `/tmp/x402-receipts-repro`.

- `npm ci` reports advisories on the restored dependency tree and exits 0. The advisory
  text is npm's own and is not reproduced here; no `npm audit fix` was run, because
  changing the dependency tree would change what was reproduced.

- The checkout's `.gitignore` lists `node_modules/` and `dist/`, so neither the dependency
  restore nor the build step modifies a tracked file. `git status --porcelain
  --untracked-files=no` inside the clone is empty after both steps.

- `npm run build` is required only to call the repository's exported `envelopeDigest` from
  outside its own test runner. The standard-library recomputation in `recompute.py` does
  not use `dist/` and does not import any repository code.

- `verifyReceipt` in the checkout is an async function. A driver that calls it without
  awaiting receives a Promise and reads `valid` as `undefined` rather than a verdict.

- `verifyInclusion` in the checkout takes the merkle root with the `0x` prefix removed.
  The checkout's own `test/vectors.test.ts` passes
  `receipt.anchor.batch_merkle_root.slice(2)`. Passing the prefixed value returns false for
  every leaf, including the leaf the proof is genuinely for.

- The five settlement and inclusion checks need no network access. Each vector carries its
  own `mockOnChain` block, which the checkout's own test assembles into a SettlementClient.
  The reproduction needs network access only for the initial clone and the `npm ci`
  dependency restore.

- Python 3.14.6 was used for `recompute.py`. It imports `json`, `hashlib`, `glob`, `os`,
  `re` and `sys`, all standard library, and no third-party package.
