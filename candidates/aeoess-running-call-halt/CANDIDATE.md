# Candidate: aeoess-running-call-halt

Cases for what a runtime does when authority is revoked, expires or cannot be determined while a
call is already running, and for when a halted chain may resume. Each case gives what was true and
one outcome an implementation produced, and states whether that outcome satisfies the source text
and which rule decides. This is a candidate under `docs/CANDIDATES.md`. It is not a reviewed
fixture and adds nothing to the lab's schema, failure classes or verifier behavior.

The lab's `lease-revocation-axes` family scores whether a new call is admitted after revocation.
These cases cover what that family does not: a call admitted before the halt, which must either
finish or stop at a checkpoint under a contract declared before the run.

## Submitter

Tymofii Pidlisnyi (Agent Passport System).

## Normative target

Every source is proposed text, not agreed text. The cases are candidate cases against that text.

- `spec`: "NTI × LGD transition-contract spec, v0.1.4" by Xinghua Zhao, sent as an attachment to
  public-agentprotocol on 2026-10-30
  (https://lists.w3.org/Archives/Public/public-agentprotocol/2026Oct/0108.html, file
  `att-0108/nti-transition-contract-spec-v0.1.4.md`), sha256
  `83d88a70237aedb6bffdb446b8bd8e3e4df41291d2c178f33367a6e10d8fc763` as retrieved. Its section 0.1
  says "Not agreed", and section 2.4 says the same of `resume_basis`. Section 0.2 says the release
  fingerprint is registered outside the file. That record was not located, so the sha256 above is
  of the retrieved copy. Sections 2.1 to 2.4 are used. Section 1.1 says no conformance test may be
  written against it until its five values are listed, so no case uses it.
- `m0108`: Xinghua Zhao, public-agentprotocol 2026Oct/0108, 2026-10-30. The two finish-or-stop
  contracts (FINISH_THEN_STOP, STOP_AT_CHECKPOINT), the four separately scored questions and the
  registry failure modes.
- `m0090`: Larry Lewis, public-agentprotocol 2026Oct/0090, 2026-10-29. A tryLater answer is
  recorded as received, a timeout is recorded separately, and admission of a later call is scored
  apart from the effects of a call already admitted.
- `m0088`: Xinghua Zhao, public-agentprotocol 2026Oct/0088, 2026-10-29. The `incomplete_check`
  block and its reason set.

Two later messages were read against the cases. No case rests on them, and the limitations below
say where they bear on a case.

- `m0109`: ShaoBao Li, public-agentprotocol 2026Oct/0109, 2026-10-30. The `incomplete_check`
  reasons map onto authority not determined, the wire value set stays closed at five, and a PAUSE
  with no receipt attached is still a well-formed record.
- `m1031`: Xinghua Zhao's reply of 2026-10-31 on public-agentprotocol, quoted in full in
  2026Oct/0121 and 0122. It accepts m0090's two refinements and m0109's constraint, and states
  that a receipt saying PAUSE(authority_not_determined) always carries its `incomplete_check`
  reason.

Each case lists the sources it rests on in `basis`.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`, `mutate.py`. No files are
copied from the sources. Rule descriptions quote single sentences.

## License

Apache 2.0, the license of this repository. The spec's section 0.5 licenses its normative text,
sections 1 to 6, under CC BY 4.0 "so that others may implement it and write conformance tests
against it", with attribution naming the document and its release fingerprint. This candidate
names the document, its version and the sha256 of the retrieved copy. It reuses no theory text
and no code from the spec's reference implementation.

## What the cases test

Thirty-four cases. Identifiers and times are illustrative.

| ids | rule | what is tested | basis |
|---|---|---|---|
| RC-01, RC-02 | R-ADMIT | a new call after the halt is known is refused | m0090, m0108 Q1 |
| RC-03 to RC-05 | R-FTS | an admitted non-interruptible call finishes, and its receipt does not claim it stopped | m0108, spec 2.1 |
| RC-06 to RC-08 | R-SAC | an admitted checkpointable call stops at the first checkpoint at or after the halt is known, including the equality edge. RC-08 has no checkpoint after the halt, which the text does not cover | m0108 |
| RC-09, RC-10 | R-OBS | the receipt agrees with an independent observer on completion and checkpoint | m0108 Q4 |
| RC-11 to RC-13, RC-28 | R-NOTDET | an unreachable registry or stale root ends in PAUSE with authority not determined, never ACTIVE and never reported as revoked. RC-28 is ambiguous, see limitations | m0108, m0088 |
| RC-14 to RC-16 | R-INCOMPLETE | a tryLater answer is recorded as tryLater, a timeout is not recorded as tryLater. RC-16 is ambiguous, see limitations | m0088, m0090 |
| RC-17 to RC-19 | R-EXEMPT | an exemption cannot resume a chain halted by revocation or by undetermined authority, and can resume one halted by a policy violation | spec 2.4 |
| RC-20, RC-21 | R-RESTORE | a restore condition missing an item keeps the chain in PAUSE with a receipt naming the gap | spec 2.3, 2.4 |
| RC-22, RC-25 | R-ROLLBACK | a rollback whose target fails its integrity check stays in ROLLBACK | spec 2.2 |
| RC-23, RC-26 | R-ONEWAY | a revocation in a regime declared irreversible never resumes, a suspension in a regime that provides suspension may | spec 2.3, 2.4 |
| RC-24, RC-27 | R-RECUR | a second trigger after RESUMED sends the chain back to PAUSE | spec 2.3 |
| RC-29, RC-30, RC-33 | R-WINDOW | a validity window that closes first keeps the chain in PAUSE with window closure recorded as the reason | spec 2.3 |
| RC-31, RC-32, RC-34 | R-SPLIT | one run scores admission of the new call and the effects of the admitted call, each with its own verdict in `expect_parts` | m0090, m0108 Q1 Q2 |

Reading rules, stated in `vectors.json`: receipt and observer values are final, read after every
call in the case has ended. An outcome lists the fields its rule reads, and a field the rule reads
that is missing from a listed receipt means the receipt does not carry it. Outcome field names are
this candidate's own representation, since the sources name values, not fields. The resume cases
state `trigger_present: false`.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` judges each case's `outcome`, compares the verdict with `expect`, and for the R-SPLIT
cases compares the two partial verdicts with `expect_parts`. To test a runtime, give it each case's
input, replace `outcome` with what it produced, and run `check.py`. `mutate.py` weakens one rule of
`check.py` at a time, including a version of every rule that always answers nonconformant, and
fails unless some case catches each change.

At the revision submitted, the submitter's runs on Python 3 printed `34/34 agree` and
`32/32 mutants killed`, each with exit 0. These show that the checker agrees with the expected
results and that every rule has a case depending on it, in both directions. They say nothing about
any runtime.

## Evidence

No runtime has been run against these cases.

The expected results were reviewed before submission. A separate model session, given only the
four sources and the case inputs without the expected results, judged 28 cases. Its verdicts
matched 26. For RC-26 it found that the case mixed a revocation into a suspension regime, and the
case was changed to a suspension. For RC-28 it found that m0108 and m0088 classify a stale root
differently, and the expectation was changed to `ambiguous`. After that review, RC-29 to RC-34 were
added for rules it found untested, RC-14's input was corrected and the resume cases gained
`trigger_present`. The same session then judged those 8 cases without expected results and matched
all 8. That review is a reading of the sources by a session working for the submitter. It is
author-produced and is not a run.

## Known limitations

- All sources are proposals on a mailing list. The spec's section 0.3 treats silence as acceptance
  between its two named sides only, which carries no weight here. A revised release needs a new
  revision of this candidate.
- RC-28: m0108 lists stale_root among the modes that report authority not determined. m0088 calls a
  check against a stale root a completed check that carries its own determination. Both reject
  ACTIVE, which RC-13 tests.
- RC-16: m0090 says a timeout is recorded separately, and m1031 accepts that it is never
  inferred, which RC-15 tests. m0088's reason set (tryLater, not_authoritative, internal_error)
  still has no value for a missing answer.
- RC-11 is scored on state and determination, the fields R-NOTDET reads. m1031 adds that a receipt
  saying PAUSE(authority_not_determined) always carries its `incomplete_check` reason. RC-11's
  receipt carries none, and no case tests that requirement, because the reason set has no value
  for an unreachable registry either. RC-28 has the same gap.
- No case requires a receipt for a PAUSE to be well formed, which fits m0109. RC-13 has no receipt
  and is scored on its ACTIVE state.
- RC-08: no source says what STOP_AT_CHECKPOINT does when no checkpoint follows the halt.
- STOP_AT_CHECKPOINT stops a call partway, while spec 2.1 says PAUSE happens "between atomic tool
  calls, never mid-call". The two fit only if a checkpoint counts as a tool-call boundary, which
  no source states.
- RC-29, RC-30 and RC-33 depend on the spec's OPEN-4. If escalation of a closed window is
  specified later, their expected PAUSE may change.
- RC-26's suspension rests on the eIDAS mapping in spec 2.3. Spec 2.1 lists only expiry,
  revocation and anomaly as registered triggers.
- In every case the halt takes effect and is seen at the same instant, so no case separates
  `t_effective` from `t_observed`.
- Not covered: presence of the tier-1 receipt fields, the timestamp source (OPEN-3) and signatures
  (OPEN-5), the rollback target being the last checkpoint, `resume_basis` as a closed set, the
  spec section 3 rule that a present trigger outranks a present restore and that a receipt names
  the root it was decided against, a mutated field changing `receipt_id`, recurrence without
  credit from an earlier resume, and the rule that the runtime does not read the observer during
  the run.
- The checker encodes one reading of the sources. A correction from their authors overrides it.
