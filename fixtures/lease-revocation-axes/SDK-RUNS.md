# SDK primitive run records

Date 2026-10-22. Runner aeoess, Codex under Tima's direction. Both records are
Mode A, author-produced. The runner authored the vectors and bridge. The model
was also authored here. No external or independent implementation is inferred.

## Pins and commands

Lab base 6207fe5d3fe9c0a2b759a10e7e572ee5587f4e81. The candidate source pin is
the commit containing these records. The vector SHA-256 and installed package
entry digest are recorded in each JSON file. Node v24.11.1, macOS arm64.

The suite lockfile pins agent-passport-system 7.1.0. Its package exports and
freshness implementation were inspected before the bridge was written. It has
explicit Date input, freshness in integer seconds and an exclusive expiry check.
Its chain verifier accepts explicit now and a resolveRevocation callback.
This is a limited capability inventory of the selected APIs, not an exhaustive
SDK audit. No missing feature was simulated to create a successful claim.

    npm ci --include=dev
    node fixtures/lease-revocation-axes/sdk-bridge.mjs --json
    # direct exit 0, records/sdk-7.1.0.json

A separate installation left the suite dependency and lockfile unchanged:

    npm install --ignore-scripts --no-audit --no-fund --prefix <isolated-dir> agent-passport-system@8.0.1
    APS_SDK_ROOT=<isolated-dir>/node_modules/agent-passport-system node fixtures/lease-revocation-axes/sdk-bridge.mjs --json
    # direct exit 0, records/sdk-8.0.1.json

The retained 8.0.1 install completed from local npm cache with --offline. An
initial online install also completed, after registry retries. Package version
and selected API behavior were checked against the actual installed package.
No credentials were read. Network is unnecessary during the bridge runs.

## Results and boundaries

Each package run matched 123 primitive checks: 41 original-evidence freshness
checks and 82 signed-chain evaluations under supplied resolver answers. A
separate signature mutation was rejected. The JSON records retain each supplied
answer and SDK state, plus the supported and unsupported claims.

These checks do not establish complete cached lease or live standing-read
modes, observation provenance, second-worker synchronization, or P1 dispatch
enforcement. Those mappings are explicitly not_supported. A callback supplied
by the bridge is not the SDK fetching current state from an authority. Original
evidence expiry and signed-chain validation are separate primitive observations,
not a secretly composed enforcement path. No live third-party system was run.

## Model record

records/model.json is the compact retained reference-model result. Its full
per-call results can be reproduced with:

    node --import tsx fixtures/lease-revocation-axes/verify.ts --json

The model run directly exited 0 with 44 case/profile runs, 164 calls, 492 axis
comparisons and eight exact mutation failure sets. Four further disposable
corpus mutations were rejected, each with direct exit 1, while the pristine
vectors stayed unchanged. These are author-produced model results.

Initial model validation caught two incomplete authored mutation failure sets.
Repeated use also extended expiry in timelines 04, 05, 07 and 08, not only 10.
A retained first live read also violates observation freshness in no-revocation
controls 01 and 09. The failure sets were corrected after inspecting those
causes. No baseline expected answer was changed to fit the model. The retrieval
mutation was refined to renew only after a successful source read, so an
unavailable source no longer acts as renewal. The final exact failure sets are
retained in vectors.json and records/model.json.

A first tsx CLI invocation was blocked by sandbox IPC permissions before case
execution. The permission-enabled runs and node --import tsx runs completed.
Neither launcher failure is a model or SDK result.

Files covered by SHA256SUMS.txt are immutable for this record. Corrections to a
covered record must be appended in CLARIFICATIONS.md, preserving the original.
A later independent run is appended separately and does not replace these.
