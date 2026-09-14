# wasmagent AEP, layered run against the component tuple published for `aep-certified-2026-09-13-03`

A layered run record with independent native-verifier observations and a lab-authored semantic
recomputation. Date 2026-09-14. Context `Agent-Authority-Conformance/aps-conformance-suite#92`.

## Target and provenance

Component pins, read from `conformance/aep/certified-target.json` on `WasmAgent/wasmagent-protocol`
`origin/main` at commit `639a6117` (merged as `228db753`), not from an issue comment:

    target_id          aep-certified-2026-09-13-03
    certified_at       2026-09-13T13:33:08Z
    gate_c_run_id      34760116414
    protocol           35320c567ba02ae30ba441f488952954dd66a4cc
    js                 bb71077cbd13051c05e17195d11d16efd0d1c572
    proxy              4b4bde3b2e06eb62b7910cb3f379d75288cc4db1
    trace              5820bf811302a1e202b762792cac6ef44e833ad6
    signing_profile_id aep-dsse-ed25519-decoded-body-v1

The provenance anchor is unresolved and this record makes no reproduction claim. At the pinned
protocol SHA `35320c56`, `conformance/aep/certified-target.json` still contains the `-02` record,
naming a different protocol SHA, trace SHA and Gate C run. The `-03` manifest appears only on a
later protocol commit. The open question on #92 is whether the intended anchor is the `-03` tuple
plus the commit that publishes that manifest. Until that is answered this is a run against the
component tuple published for `-03`. That is why this directory is named
`wasmagent-aep-2026-09-13-03` rather than after the certification id.

Corpus identity was checked rather than assumed. `git diff 35320c56 origin/main -- conformance/aep/`
touches only `README.md` and `certified-target.json`. Every fixture and `manifest.json` are
byte-identical at the pinned SHA and on `origin/main`.

Scope: native verifier execution is JS and Rust only. `trace-pipeline` is recorded as the current
Python consumer and is not treated as a third native verifier. The pinned `manifest.json` states the
same, that `expected_python` is a corpus slot for an official standalone `wasmagent-py` SDK and that
no such SDK exists.

## Verification split

- `JS-NATIVE-RECORD` / authenticity and binding over the upstream fixtures; runner: aeoess;
  Mode A; independent; implementation: `@wasmagent/aep` 2.9.0 at `bb71077c`.
- `JS-NATIVE-CHAIN` / inter-record hash-chain assurance state; runner: aeoess; Mode A;
  independent; implementation: `@wasmagent/aep` 2.9.0 at `bb71077c`.
- `RUST-NATIVE-DSSE` / DSSE acceptance or rejection; runner: aeoess; Mode A; independent;
  implementation: `aep-core` at `4b4bde3b`.
- `LAB-SEMANTIC` / record-semantic verdict over the upstream fixtures; runner: aeoess; Mode B;
  author-produced; implementation: `adapter/lab-semantic.py`, authored by the runner. Authorship
  relationship preventing an independent label: the harness itself decides the claimed semantic
  result, so under `CONTRIBUTING.md` it is part of the recomputation implementation rather than a
  thin transport.
- No independent record exists for `LAB-SEMANTIC`; that layer is queued in `docs/OPEN-RUNS.md`.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a
family-level verdict.

## Reproduction

    ./run.sh [scratch-dir]

Clones the three component repos at the pinned SHAs, aborts on any pin mismatch, installs the two
JS dependencies, places the lab-owned adapters, runs all four surfaces and preserves exit codes.
Requires `git`, `bun`, `cargo`, `python3`. Depends on no state outside this directory.

Environment of the recorded run: bun 1.3.11, cargo 1.95.0 (f2d3ce0bd 2026-03-21), python 3.14.6.
Exit codes: `js-driver.ts` 0, `cargo test -p aep-core --test lab_driver` 0, `lab-semantic.py` 0,
`run.sh` 0. Re-executed from a clean scratch clone, the three result files reproduced
byte-identically to the copies in `results/`.

## Surfaces and what each can establish

`JS-NATIVE-RECORD`. `verifyAEPRecordDetailed`. Establishes `authenticity` in
`dsse-valid | unsigned | invalid | not-checked` and `binding` in
`exact | legacy-normalized | not-applicable | invalid`. Does not establish record-semantic
conformance.

`JS-NATIVE-CHAIN`. `verifyAEPChain`. Establishes `status` in
`intact | not-present | partial | orphaned | broken`. Its own source states that `valid` alone
cannot distinguish an intact chain from an absent one.

`RUST-NATIVE-DSSE`. `aep_core::verify_record_dsse`, public signature `Result<(), &'static str>`.
Establishes DSSE acceptance or rejection. Carries no typed failure contract. The pinned crate
exposes no public chain verifier, so `JS-NATIVE-CHAIN` has no Rust counterpart at this pin. Recorded
as an interface asymmetry, not a Rust gap.

`LAB-SEMANTIC`. `adapter/lab-semantic.py`, written for this run in Python, sharing no code with
either native implementation. Rules taken from the normative text of
`schemas/aep/aep-record.schema.json`: the total order
`unknown < operator_asserted < principal_key_signed < qualified_signature`, the floor must not round
up, the floor must equal the weakest grade across the declared set, and the floor is reported
together with observed and never instead of it. Eight lab-owned codes:

    SEM_FLOOR_WITHOUT_OBSERVED        SEM_OBSERVED_WITHOUT_FLOOR
    SEM_EMPTY_OBSERVED                SEM_FLOOR_NOT_OBSERVED
    SEM_FLOOR_NOT_WEAKEST             SEM_UNKNOWN_GRADE
    SEM_DUPLICATE_OBSERVED            SEM_NEGATIVE_AUTH_EVIDENCE_COUNT

All violations are emitted per fixture. The checker never stops at the first.

## Results

Twenty-eight fixtures, the full `conformance_target` list in the pinned manifest.

- Lab-authored semantic recomputation agrees with all 28 corpus semantic targets.
- All published JS chain states reproduce. `intact-3` and `intact-dsse-3` intact, `partial-last`
  and `partial-middle` partial, `singleton-with-prev` orphaned, `broken-middle` broken at index 1,
  `missing-all` not-present.
- Both native verifiers agree on accept and reject across the 9 DSSE fixtures exercised.
- The cross-language pair holds in both directions. Rust accepts `dsse/js-signed-v05.json` and JS
  accepts `dsse/rust-signed-v05.json`, recomputed here rather than taken from upstream CI.
- The semantic verdict is not recoverable from either native record surface and was recomputed by
  the lab-authored checker.

Two fixtures produce more than one lab violation. `floor-not-observed` yields
`SEM_FLOOR_NOT_OBSERVED` and `SEM_FLOOR_NOT_WEAKEST`, and `empty-observed` yields
`SEM_OBSERVED_WITHOUT_FLOOR` and `SEM_EMPTY_OBSERVED`.

Three of the nine semantic negatives are also `structural: invalid` in the manifest:
`unknown-attribution-grade`, `duplicate-observed-grade` and
`negative-authorization-evidence-count`. The lab-authored recomputation found the corresponding
semantic violation on each. Both facts are recorded per fixture and no execution order is imposed.

On the valid side the claim is narrow. Every corpus fixture carrying `semantic: valid` produced no
lab semantic violation. Nothing is claimed about completeness beyond the published target.

## Findings

F1. Layer separation is necessary rather than cosmetic. The matrix contains semantically invalid but
authenticity-neutral records, and semantically valid but authenticity-invalid records. Read down the
`JS-NATIVE-RECORD` column across the twelve `valid` and `invalid-semantic` fixtures and every row is
identical, `unsigned` / `not-applicable`, while `LAB-SEMANTIC` separates three valid from nine
invalid across seven distinct codes. Read across the seven DSSE negatives and the lab reports
`valid`, because those are semantically sound records with broken signatures. No single native result
answers whether a fixture is conformant.

F2. `not-checked` and `unsigned` describe different kinds of state. For the nine fixtures whose
semantic verdict is invalid, the corpus manifest records `authenticity: not-checked`. When those same
records are passed directly to the pinned JS authenticity API, `verifyAEPRecordDetailed` returns
`authenticity: unsigned`. These are not logically contradictory. `not-checked` describes the
conformance pipeline's decision not to evaluate authenticity after an earlier semantic failure.
`unsigned` describes what the native authenticity verifier observes when it is nevertheless invoked
on the record. The manifest and the native API therefore use the authenticity field to describe
evaluation state and record state respectively, and a consumer cannot substitute one for the other
without also knowing whether the authenticity layer was executed. The meaning of `not-checked`
depends on execution sequencing, and the direct verifier API has no representation for "not
invoked". This is not read as nine verifier failures and not as an upstream defect.

Consequence for the lab: preserve both facts separately rather than normalising one into the other.
As explanatory notation for this record only, and not proposed as an upstream schema change:

    expected_authenticity:        not-checked
    native_authenticity_observed: unsigned
    native_authenticity_invoked:  true

F3. The two native result contracts differ, and neither is a superset. JS exposes coarse typed
authenticity and binding fields plus typed chain states. Across the seven negative DSSE fixtures
exercised here, those typed fields distinguish exactly two outcomes, `(invalid, invalid)` for five
and `(invalid, not-applicable)` for two. Rust distinguishes seven, one per failure reason, but
delivers them as `&'static str` rather than as a typed public contract, and the pinned crate has no
public chain verifier. Scoped to this corpus and these seven negatives, not stated as a global
property of either implementation.

## Target-profile note

`packages/aep/src/canonical.ts` states that AEP uses sorted-key `JSON.stringify` with a recursive
lexicographic key sort, explicitly not RFC 8785 / JCS, and documents the acknowledged divergences on
some floats, large integers and non-ASCII strings. The lab adapter followed the target profile. This
run does not treat divergence from APS/JCS as an AEP conformance failure. It is a protocol-profile
fact.

## Artifacts

    results/native-js.json            JS-NATIVE-RECORD and JS-NATIVE-CHAIN
    results/native-rust.json          RUST-NATIVE-DSSE
    results/lab-semantic.json         LAB-SEMANTIC
    results/consolidated-matrix.json  all four layers per fixture
    adapter/js-driver.ts              JS-NATIVE-RECORD, JS-NATIVE-CHAIN
    adapter/lab-driver.rs             RUST-NATIVE-DSSE, placed into the pinned crate by run.sh
    adapter/lab-semantic.py           LAB-SEMANTIC
    run.sh                            reproduction
    CHECKSUMS.sha256                  sha256 of every file in this directory

## What this record does not establish

No broad AEP conformant or non-conformant verdict. No Python native verifier was exercised and none
is claimed. No capture-completeness claim. No claim that the `-03` certification was reproduced,
pending the provenance-anchor question on #92. The `LAB-SEMANTIC` layer is author-produced and is
not an independent record. Findings are scoped to the fixtures and failure paths actually exercised.

The run did not produce a single pass or fail verdict for AEP, and that is the useful result. Across
the pinned target, cryptographic authenticity, semantic conformance and chain assurance are
observably different properties. The native verifier surfaces establish different subsets of those
properties, and the lab-authored recomputation is what makes the semantic layer visible.
