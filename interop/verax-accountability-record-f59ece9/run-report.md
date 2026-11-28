# Run record: the Verax interop checker on the `accountability-record` family

Recorded for [#152](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/152). This file records a run published by @dogrucanemek-alt of his own checker over the APS-native `accountability-record` family at corpus `7b60349`, and a rerun of that checker by @aeoess.

| field | value |
|---|---|
| who ran it | @dogrucanemek-alt (Emek Can Doğru, Verax) |
| date | 2026-10-05, run started 2026-10-05T00:07:30Z per the runner's trace. Reported on #152 the same day |
| run mode | Mode B, alternate recomputation |
| implementation | `interop/aps-accountability-record-v0.1.0/verify.ts` at `verax-ai/verax` `f59ece93f0bc396aee9a373ff9db7f7f6200cb39`, SHA-256 `daf9e62252f5d4e9acbf1c0c8523049a2171bc7f0d32b5b3c0fc3cd3fd72aba3`, 160 lines. The file last changed in `f50c59b`. It imports `node:crypto` (SHA-256, Ed25519), `node:fs`, `node:path` and `canonical` from `@cedulon/core` 0.13.1, an RFC 8785 canonicalizer. It imports no code from this repository |
| author-produced or independent | author-produced. The runner wrote `verify.ts`, which decides each stage, and `@cedulon/core`, which builds the bytes the DIGEST and SIGNATURE stages hash and verify. Under `CONTRIBUTING.md` this record is not independent |
| relationship to the producer | third party. The runner did not author the vectors, the claim inputs or the APS implementation, and the vectors' author (@aeoess) did not write the checker |
| what the checker was written from | the family's README and schema, per the file's header comment |
| corpus reference | `7b603492dc13278d4af47b4b899e701a17f96d6d`. `fixtures/accountability-record/accountability-record-fixture-v1.json` SHA-256 `536a952ebade9c8bfc7e0437d943e5157361cd8bcde83c1983cc8d7d4c865d14`, schema SHA-256 `38c3c397627376c4b752309ee83777616efd66891aa6096291b7a7dc518bfc80`. No commit between `7b60349` and `0929f09` touches `fixtures/accountability-record/` |
| published output | the command output in the body of #152. A copy is in `outputs/reported-output.txt` |
| environment | Node.js v24.16.0 on Windows 11 (build 10.0.26200) |
| suspected defective vectors | none reported |

## Results per vector, as the runner reports them

12 of 12 as expected, checker exit 0. Every vector gets four stage results, in order SCHEMA, CANONICAL, DIGEST and SIGNATURE.

```
PASS     allow-executed-settled             -         SCHEMA=pass CANONICAL=pass DIGEST=pass SIGNATURE=pass
PASS     deny-no-settlement                 -         SCHEMA=pass CANONICAL=pass DIGEST=pass SIGNATURE=pass
PASS     halt                               -         SCHEMA=pass CANONICAL=pass DIGEST=pass SIGNATURE=pass
PASS     detached-payload                   -         SCHEMA=pass CANONICAL=pass DIGEST=skipped SIGNATURE=pass
PASS     negative-tampered-payload          DIGEST    SCHEMA=pass CANONICAL=pass DIGEST=fail SIGNATURE=pass
PASS     negative-wrong-key                 SIGNATURE SCHEMA=pass CANONICAL=pass DIGEST=pass SIGNATURE=fail
PASS     negative-schema-decision           SCHEMA    SCHEMA=fail CANONICAL=pass DIGEST=pass SIGNATURE=pass
PASS     negative-type-relabel              SCHEMA    SCHEMA=fail CANONICAL=pass DIGEST=pass SIGNATURE=fail
PASS     positive-deny-executed             -         SCHEMA=pass CANONICAL=pass DIGEST=pass SIGNATURE=pass
PASS     positive-collision-same-second-a   -         SCHEMA=pass CANONICAL=pass DIGEST=pass SIGNATURE=pass
PASS     positive-collision-same-second-b   -         SCHEMA=pass CANONICAL=pass DIGEST=pass SIGNATURE=pass
PASS     negative-sig-alg-lowercase         SCHEMA    SCHEMA=fail CANONICAL=pass DIGEST=pass SIGNATURE=pass
12/12 as expected
```

The third column is the first failing stage. A vector's outcome is `PASS` when its verification result equals `expected_verification` and, for a negative, the stage its `rejection_kind` names failed. `negative-type-relabel` declares a signature rejection and fails at SIGNATURE. It also breaks the `record_type` const, so SCHEMA is the first failing stage the checker reports, as the runner notes.

## What each stage checks

Read from `verify.ts` at the pinned commit.

- SCHEMA applies the schema's constraints by hand: allowed and required members, types, patterns, the two consts and the `decision` enum. The `date-time` and `uri` formats are checked with the checker's own regular expressions. No JSON Schema validator is used, and this record does not compare that code with the schema file.
- CANONICAL canonicalizes the record without `sig` and compares the bytes with the vector's `signing_input_bytes_hex`. It also compares the SHA-256 of the full record's canonical form with `canonical_sha256`.
- DIGEST compares the SHA-256 of the canonical `action` object with `action_digest.sha256`. When `action` is absent, the stage stays `skipped`. That is the case for `detached-payload`, so its payload commitment is not checked against any payload.
- SIGNATURE verifies Ed25519 over the canonical signing input under `keypair.publicKeyHex`.
- `action_ref` is checked against its pattern only. The schema says it MUST be recomputable from an inline `action`, and this checker does not recompute it.
- A negative vector is matched by the stage its `rejection_kind` names. The checker's vector type declares `expected_error_code`, but the checker never reads it, so the vectors' individual error codes are not compared.

The process exits 0 only when all twelve outcomes are `PASS`.

## What the checker takes from the fixture

The expected signing input bytes, the expected canonical digests and the verification key all come from the fixture file. A CANONICAL pass shows agreement with bytes the fixture publishes. A SIGNATURE pass shows the record verifies under the deterministic test key the fixture itself supplies.

## Reproduction of the published output

A rerun by @aeoess on 2026-10-09 (macOS 26.5 arm64, Node.js v24.11.1) from fresh clones at the pinned commits produced stdout byte for byte identical to the output published on #152. Checker exit 0, stderr empty. Both files have SHA-256 `8c96341a7e2877c0f2a1f728546a64ae3280cb359064574c6e6e5893b854b01e`.

```
git clone -q https://github.com/Agent-Authority-Conformance/aps-conformance-suite aps
git -C aps checkout -q 7b603492dc13278d4af47b4b899e701a17f96d6d
git clone -q https://github.com/verax-ai/verax verax
git -C verax checkout -q f59ece93f0bc396aee9a373ff9db7f7f6200cb39
cd verax
npm ci --silent
node --experimental-strip-types interop/aps-accountability-record-v0.1.0/verify.ts ../aps > ../rerun-output.txt
```

`npm ci` installed `@cedulon/core` 0.13.1 from the npm registry as the lockfile pins it. The published output was taken from the code block in the body of #152, from the line after the `node` command to the line before `+ echo`. The rerun output is in `outputs/rerun-output.txt`.

This is a Mode A, author-produced reproduction of the runner's record. @aeoess authored the vectors, so the rerun is not independent for any claim that reads them, and it uses the runner's checker rather than a second implementation. It shows the published output reproduces on a second operating system and Node.js version. It is not an audit of `@cedulon/core`.

## Earlier corpus revision

The runner's report says the promise this run fulfils named a run against the corpus at `4b9dbb0`. The run recorded here is against `7b60349`. The family's fixture file and schema differ between those two commits, and this record covers `7b60349` only.

## What this record does not establish

This record contains no run classified independent under `CONTRIBUTING.md`.

It does not establish that `action_ref` values derive from their actions, that the `detached-payload` commitment binds any payload, that negatives fail with their expected error codes, or that the hand-written schema checks are equivalent to the schema. It says nothing about Verax beyond this checker at this commit, and nothing about deployment, production use or adoption. The lab certifies nothing, and a merged record is not an endorsement of the implementation it names.
