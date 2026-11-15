# Candidate: icam-temporal-derivation (candidate package v0.3)

## Submitter
Nika Novak — ICAM / aiclavis. Submitted for publication review only after a pull request is opened; no independent implementation validation is claimed.

## Normative target and source
Individual, experimental, **Informational** Internet-Draft `draft-li-rttp-iqa-addressing-02`, published 2026-11-01, §§6.1, 6.3, 7.2, https://datatracker.ietf.org/doc/html/draft-li-rttp-iqa-addressing-02. The published draft text is pinned by the source-family SHA-256 `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` (TXT copy, as recorded by the aicent-lease-boundary candidate); this package has not separately retrieved and hashed that TXT copy. This is **not an IETF standard** and is not working-group consensus. The target is explicitly pinned to revision 02; updated drafts can change the interpretation.

## Version identifiers
`v0.3` describes the submitted candidate package/documentation revision; `0.2.0-prepublication` in `vectors.json` identifies the vector set revision. These are separate identifiers; none of the 24 cases' inputs or expected outputs have been changed in the review correction.

## License
Original ICAM materials, prepared for contribution under Apache-2.0. Submission requires a signed-off commit (`git commit -s`) and all laboratory publication conditions. The original draft is not reproduced.

## Bounded question
Does an implementation derive lease freshness from the **authenticated expiry** and an independently sampled verifier clock, rather than trusting a supplied derived/advisory state label? Existing candidate `aicent-lease-boundary` assumes `at_boundary` and tests answer semantics; this complements it without editing its 15 fixtures.

The advisory flag `supplied_boundary_classification` **is not an IQA wire field**. It is deliberately a test-harness input for negative controls. Its misuse is an ICAM proposed robustness failure pattern, **not by itself a specified RTTP/IQA nonconformance class**. Because no external implementation adapter is included, this pack tests the reference oracle and its authored expectations, not the question above against an actual implementation.

## Two separate layers
1. `DERIVE`: §6.1 lease reliance (`fresh`, `expired`, or at exact equality without declared convention `boundary_undetermined` as an **interpretive** result). A deployment may declare equality fresh or expired; §6.1 says implementations SHOULD declare.
2. `WIRE_TIME_GATE`: §7.2 step 2 only. The envelope time gate rejects when `lease_expiry < verifier_now`; it **passes at equality irrespective of the reliance convention**. Passing this isolated time gate does not mean the frame's HMAC, structure, identity, standing, or authority has passed verification.

All times are integral Unix seconds. §7.2 defines `lease_expiry` as unsigned 64-bit big-endian. Fixture clock values are independently supplied, not collected from a trusted runtime. `insufficient_input` / `invalid_convention` are **local test preconditions**, not normative refusal reason strings.

## Equality boundary classification
Four §6.1 equality cases (`TD-B02`, `TD-B05`, `TD-N03`, `TD-N04`) are `convention_specific`, not unconditional normative requirements. At the exact expiry instant, the reliance result follows the deployment's declared `boundary_convention` under §6.1. Under §7.2 step 2, the separately tested envelope time gate passes equality regardless of that convention. The case-status change is metadata only, not a new protocol response.

## Inventory
24 author-produced cases: 18 prior cases retained by ID and expected outcome, plus 4 wire-time-gate cases (TD-W01–04) and 2 nondefault-window cases (TD-B07–08). See `vectors.json`: case status and source basis are explicit for each record.

## How to run
```sh
python3 -I check.py vectors.json
python3 -I mutate.py
python3 -I metamorphic.py
```
All Python-standard-library, offline. The mutation check does not prove independent spec correctness. The metamorphic test changes a non-authoritative advisory input, demanding invariant time conclusions.

## Evidence and limitations
- The ICAM author-produced Mode B fixture-consistency run yielded 24/24 agreements, 8/8 caught mutations and 120/120 invariance checks. `RUN_REPORT.txt` is preserved as a historical receipt of that original run, including its original case-status labels.
- ShaoBao Li / Aicent separately reproduced the ICAM harness and wrote a different oracle-level runner (`icam_runner.py`) deriving rules from the pinned draft rather than the ICAM oracle. Their author-produced Mode B runner reports 24/24 matching expectations and 6/6 distinct mutations killed; see https://iqa.org/conformance/icam-runner/ . These are separately attributed runs, not independent test-vector creation or actual-runtime certification.
- No actual IQA runtime under test, authenticated 128-byte frame, HMAC verification, actual trusted-clock sampling, or independent scientific assessment. The Aicent runner's external oracle-level verification does not change these limitations.
- §6.3 is contextual support for evaluation at time of use. No task-execution or halt enforcement is tested.
- `TD-B07` and `TD-B08` catch an improper hard-coded 120-second lease cap but do not test recalculation of expiry from issuance time, because no issuance timestamp is supplied.
- Does not test clock drift, source authenticity, synchronization, multi-step policy, revocation, or authorization.
- Precondition outcomes and undeclared-boundary interpretations are **not** claims that a runtime must emit these codes.
- `time_gate_pass` cannot be described as an accepted frame.
- One laboratory candidate can be published without independent replication; publication is not admission to a reviewed corpus.

## Interface and provenance boundary
The test harness consumes `verifier_now_unix_s` as an explicit fixture value; it does not inspect a verifier runtime clock. Likewise, `lease_expiry_unix_s` is a fixture value, not verified bytes extracted from a signed frame. A future implementation-under-test adapter must establish both provenance guarantees before these vectors may support an implementation claim. `supplied_boundary_classification` is an intentionally adversarial harness hint and must not be mistaken for an IQA wire field.

All expectations are generated by the submitting ICAM oracle. The `normative` case tag denotes an interpretation of the source rule at that input, not an independently established conformance certification. Four equality cases now have the narrower `convention_specific` tag; the original `RUN_REPORT.txt` is retained without rewriting the original run's output.
