# SDK runs: lifecycle-evidence-and-record

Every vector in this family was run against the published npm
`agent-passport-system` 7.1.0 and the published PyPI `agent-passport-system`
4.1.0. Neither is a local source checkout.

- **Canonicalization, every vector, both SDKs.** `verify.ts` recomputes each
  case's pinned RFC 8785 (JCS) input digest through npm `canonicalizeJCS`, and
  `verify.py` recomputes the same pins through PyPI `canonicalize_jcs`. All 12
  vectors pass in both.
- **Behaviour, per group.** `not_supported` in both packages for both groups.
  The retention group has the nearest thing to a surface and the run below is
  the reason it is still recorded as not supported: `isRetentionExpired` is a
  ceiling and LC-G-005 needs a floor.

Nothing in draft-pidlisnyi-aps-03 asks either SDK for these behaviours, so
`not_supported` is an absence of a named surface, not a defect report and not a
conformance verdict.

Both blocks below are the verbatim stdout of the two probe scripts.

## Reproducing

    npm ci --include=dev
    node fixtures/lifecycle-evidence-and-record/sdk-probe.mjs

    python3 -m venv /path/to/venv
    /path/to/venv/bin/pip install "agent-passport-system==4.1.0"
    /path/to/venv/bin/python fixtures/lifecycle-evidence-and-record/sdk_probe.py

## npm agent-passport-system 7.1.0

```
agent-passport-system (npm) 7.1.0, 1179 exports

group retention_restriction: isRetentionExpired
  The package's RetentionPolicy declares maxRetentionMs, documented in
  dist/src/types/data-lifecycle.d.ts as "Max retention in milliseconds", with
  onExpiry one of delete, quarantine, renegotiate. That is a ceiling: data must
  not be kept longer than the policy allows. LC-G-005 is a floor: a record must
  not be destroyed before its duty runs out. The probe maps the vector's
  retention_years onto maxRetentionMs so the call can be made at all, and prints
  what came back next to the fixture's own verdict. They are not the same
  question and the two columns are not offered as agreeing.

  LC-G-005-a  fixture: restricted/retention_trigger_not_reached
    isRetentionExpired: not called, the SDK policy has no trigger-not-yet-occurred state
  LC-G-005-b  fixture: restricted/retention_duty_unexpired
    isRetentionExpired(trigger=2024-09-20T00:00:00Z, maxRetentionMs=189216000000): false
    reads as: the ceiling has not passed, so the policy permits keeping
    what LC-G-005 needs instead: whether destroying is permitted yet
  LC-G-005-c  fixture: valid/retention_duty_elapsed
    isRetentionExpired(trigger=2019-09-20T00:00:00Z, maxRetentionMs=189216000000): true
    reads as: the ceiling has passed, so the policy says destroy
    what LC-G-005 needs instead: whether destroying is permitted yet
  LC-G-005-d  fixture: restricted/external_hold_active
    isRetentionExpired(trigger=2019-09-20T00:00:00Z, maxRetentionMs=189216000000): true
    reads as: the ceiling has passed, so the policy says destroy
    what LC-G-005 needs instead: whether destroying is permitted yet
  LC-G-005-e  fixture: valid/retention_duty_elapsed
    isRetentionExpired(trigger=2019-09-20T00:00:00Z, maxRetentionMs=189216000000): true
    reads as: the ceiling has passed, so the policy says destroy
    what LC-G-005 needs instead: whether destroying is permitted yet
  LC-G-005-f  fixture: valid/evidence_survives_authority_end
    isRetentionExpired(trigger=2024-09-20T00:00:00Z, maxRetentionMs=189216000000): false
    reads as: the ceiling has not passed, so the policy permits keeping
    what LC-G-005 needs instead: whether destroying is permitted yet

  verdict for the group: not_supported. The call runs, but it answers the
  opposite question and takes no external hold, so no vector in this group has
  an SDK behavioural result. No export takes a minimum retention duty, a
  retention trigger event, or a set of composable holds:
    a minimum retention duty (a floor, not a ceiling): not_supported
    a retention trigger event distinct from the record instant: not_supported
    composable external holds released independently: not_supported

group receipt_immutability:
  a query distinguishing what a receipt decided at its decision instant from what is true now: not_supported
  a later record that references a prior receipt as a correction or supersession: not_supported
  distinguishing new-information from void-from-inception as reasons on a later record: not_supported

  The package does hash and chain receipts (hashReceiptForChain,
  canonicalizeReceiptForId, canonicalizeReceiptForSig), which is the machinery a
  bytes-unchanged check would sit on, and this fixture's LC-G-006-f is that
  check expressed as a vector. What it does not have is any notion of two
  different questions being asked of one receipt, which is what the group is about.
```

## PyPI agent-passport-system 4.1.0

```
agent-passport-system (PyPI) 4.1.0, 744 public names across 124 modules

group retention_restriction: not_supported
  needed: a retention duty as a floor: a record must not be destroyed before its duty runs out
  reason: the Python package has no retention surface of any kind. The npm package's isRetentionExpired has no Python counterpart at 4.1.0, and that call is a ceiling rather than a floor in any case, so this group has no SDK behavioural result in either language.
group receipt_immutability: not_supported
  needed: a query distinguishing what a receipt decided at its decision instant from what is true now
  reason: the package canonicalizes and hashes receipts, which is the machinery a bytes-unchanged check sits on, but has no notion of two different questions being asked of one receipt and no later-record reason vocabulary.

canonicalization: supported. agent_passport.canonical.canonicalize_jcs is what verify.py uses to recompute every case's pinned RFC 8785 input digest, so every vector in this family does have one PyPI SDK result.
```

## Reading the retention block

The two columns are not the same question and the probe says so on every line.

`RetentionPolicy.maxRetentionMs` is documented in the installed package's
`dist/src/types/data-lifecycle.d.ts` as "Max retention in milliseconds", with
`onExpiry` one of `delete`, `quarantine`, `renegotiate`. That is a data
minimization ceiling: do not keep this longer than allowed. LC-G-005 is a
preservation floor: do not destroy this before the duty runs out. The two point
in opposite directions, and on `LC-G-005-b` that shows plainly. The SDK returns
`false`, meaning the ceiling has not been reached and keeping is still
permitted. The fixture returns `restricted`, meaning destroying is not yet
permitted. A `false` from the SDK is not evidence for the fixture's verdict and
this file does not record it as such.

`isRetentionExpired` also reads the process clock rather than taking an
evaluation instant, so the probe cannot pin time the way the vectors do. Every
vector's `evaluated_at` is 2026-09-20 and the probe necessarily runs later, so
a `true` in the block above is evidence about the trigger date against the run
date and nothing finer. That is a second, independent reason this group has no
usable SDK behavioural result, and it is recorded rather than worked around.

`LC-G-005-a` is not passed to the call at all. The vector's retention trigger
has not occurred, and `RetentionPolicy` has no state for a clock that has not
started: its input is a single access timestamp. Skipping the call is the honest
option. Passing `null` or the evaluation instant would be inventing an input.

## Per-group summary

| group | vectors | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|---|
| retention_restriction | 6 | not_supported. `isRetentionExpired` runs but answers the opposite question, takes no external hold, has no trigger state, and reads the process clock | not_supported, no retention surface exists in the package |
| receipt_immutability | 6 | not_supported. Receipt hashing and canonicalization exist, two questions over one receipt do not | not_supported |
| all 12, canonicalization only | 12 | pass, `canonicalizeJCS` | pass, `canonicalize_jcs` |

This is an author-produced record, not an independent one, under
`CONTRIBUTING.md`'s admission rules: the same author wrote the vectors, the
probes and this file.
