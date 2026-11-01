# Candidate: aeoess-running-call-halt

Cases for what a runtime does when authority is revoked, expires or cannot be determined while a
call is already running. Each case gives what was true and one outcome a runtime could produce, and
states whether that outcome satisfies the source text and which rule decides. This is a candidate
under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's schema,
failure classes or verifier behavior.

The lab's `lease-revocation-axes` family scores whether a new call is admitted after revocation.
These cases cover what that family does not: a call admitted before the halt, which must either
finish or stop at a checkpoint under a contract declared before the run.

The scope is the first test family on the chair's agenda in public-agentprotocol 2026Oct/0123:
stopping semantics, independent observations of the resource, PAUSE receipts, and admission of a
new call scored separately.

## Submitter

Tymofii Pidlisnyi (Agent Passport System).

## Normative target

Every source is proposed text, not agreed text. The cases are candidate cases against that text.

- `spec`: "NTI × LGD transition-contract spec, v0.1.4" by Xinghua Zhao, sent as an attachment to
  public-agentprotocol on 2026-10-30
  (https://lists.w3.org/Archives/Public/public-agentprotocol/2026Oct/0108.html, file
  `att-0108/nti-transition-contract-spec-v0.1.4.md`), sha256
  `83d88a70237aedb6bffdb446b8bd8e3e4df41291d2c178f33367a6e10d8fc763` as retrieved. Its section 0.1
  says "Not agreed". Section 0.2 says the release fingerprint is registered outside the file. That
  record was not located, so the sha256 above is of the retrieved copy. Section 2.1 is used.
  Section 1.1 says no conformance test may be written against it until its five values are listed,
  so no case uses it.
- `m0108`: Xinghua Zhao, public-agentprotocol 2026Oct/0108, 2026-10-30. The two finish-or-stop
  contracts (FINISH_THEN_STOP, STOP_AT_CHECKPOINT), the four separately scored questions and the
  registry failure modes.
- `m0090`: Larry Lewis, public-agentprotocol 2026Oct/0090, 2026-10-29. A tryLater answer is
  recorded as received, a timeout is recorded separately, and admission of a later call is scored
  apart from the effects of a call already admitted.
- `m0088`: Xinghua Zhao, public-agentprotocol 2026Oct/0088, 2026-10-29. The `incomplete_check`
  block and its reason set.
- `m1031`: Xinghua Zhao's reply of 2026-10-31 on public-agentprotocol, quoted in full in
  2026Oct/0121 and 0122. It accepts m0090's two refinements and the constraint in 0109, and states
  that a receipt saying PAUSE(authority_not_determined) always carries its `incomplete_check`
  reason.

ShaoBao Li's 2026Oct/0109 was also read. It keeps the wire value set closed at five and says a
PAUSE with no receipt attached is still a well-formed record. No case requires a receipt for a
PAUSE to be well formed.

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

Twenty-four cases: 7 conformant, 13 nonconformant and 4 `ambiguous`. Identifiers and times are
illustrative.

| ids | rule | what is tested | basis |
|---|---|---|---|
| RC-01, RC-02 | R-ADMIT | a new call after the halt is known is refused. DENIED is the decision name in m0108 Q1, not one of spec 1.1's unlisted values | m0090, m0108 Q1 |
| RC-03 to RC-05 | R-FTS | an admitted non-interruptible call finishes, and its receipt does not claim it stopped | m0108, spec 2.1 |
| RC-06 to RC-08 | R-SAC | an admitted checkpointable call stops at the first checkpoint at or after the halt is known, including the equality edge. RC-08 has no checkpoint after the halt, which the text does not cover | m0108 |
| RC-09, RC-10 | R-OBS | the receipt agrees with an independent observer on completion and checkpoint | m0108 Q4 |
| RC-11 to RC-13, RC-28, RC-35, RC-36 | R-NOTDET | an unreachable registry or stale root ends in PAUSE with authority not determined, never ACTIVE and never reported as revoked, and for an unreachable registry the receipt carries an `incomplete_check` block that infers no answer | m0108, m0088, m0090, m1031 |
| RC-14 to RC-16, RC-37, RC-38 | R-INCOMPLETE | an answer that arrived is recorded as that answer, and a timeout is recorded separately, never as tryLater | m0088, m0090, m1031 |
| RC-31, RC-32, RC-34 | R-SPLIT | one run scores admission of the new call and the effects of the admitted call separately | m0090, m0108 Q1 Q2 |

R-NOTDET, R-INCOMPLETE and R-SPLIT score each case in named parts, listed in `expect_parts`, so a
case can show which part of an outcome holds and which does not. A case is nonconformant when any
part is, ambiguous when no part is nonconformant and one is ambiguous, and conformant when every
part is. RC-16, RC-28 and RC-35 are ambiguous in one part only.

Reading rules, stated in `vectors.json`: receipt and observer values are final, read after every
call in the case has ended. An outcome lists the fields its rule reads, and a field the rule reads
that is missing from a listed receipt means the receipt does not carry it. Outcome field names are
this candidate's own representation, since the sources name values, not fields.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` judges each case's `outcome`, compares the verdict with `expect` and the parts with
`expect_parts`. To test a runtime, give it each case's input, replace `outcome` with what it
produced, and run `check.py`. `mutate.py` weakens one rule of `check.py` at a time, including a
version of every rule that always answers nonconformant, and fails unless some case catches each
change.

At the revision submitted, the submitter's runs on Python 3 printed `24/24 agree` and
`21/21 mutants killed`, each with exit 0. These show that the checker agrees with the expected
results and that every rule has a case depending on it, in both directions. They say nothing about
any runtime, and they do not show that the expected results are the right reading of the sources.

## Evidence

No runtime has been run against these cases.

Revision 1 had 34 cases and was reviewed before submission by a separate model session, given only
the four sources then used and the case inputs without the expected results. It matched 26 of 28
cases in the first round and all 8 in the second, after corrections. Revision 2 followed two
further reviews by separate model sessions against all five sources and 0123. Both found that
RC-11 accepted a receipt without the `incomplete_check` block m1031 requires. Revision 2 changes
RC-11 to nonconformant, adds RC-35 to RC-38, scores the receipt cases in parts, and narrows the
scope to the chair's first family. Its changes were not reviewed blind. All of these reviews were
done by sessions working for the submitter. They are author-produced and are not runs.

## Known limitations

- All sources are proposals on a mailing list. A revised release needs a new revision of this
  candidate.
- RC-28: 0108 lists stale_root among the modes that report authority not determined, m0088 calls a
  check against a stale root a completed check that carries its own determination, and m1031 says
  every authority_not_determined receipt carries an `incomplete_check` reason. The PAUSE state is
  scored, the determination is not. RC-13 rests on 0108, "No mode stays ACTIVE".
- RC-16 and RC-35: recording a missing answer separately is agreed in m0090 and m1031, but no
  source names its value, and m0088's reason set (tryLater, not_authoritative, internal_error) has
  none. `no_response` in RC-35 is this candidate's label. m0088's own row gave tryLater for an
  unreachable registry, which m0090 and m1031 replaced.
- RC-08: no source says what STOP_AT_CHECKPOINT does when no checkpoint follows the halt.
- STOP_AT_CHECKPOINT stops a call partway, while spec 2.1 says PAUSE happens "between atomic tool
  calls, never mid-call". The two fit only if a checkpoint counts as a tool-call boundary, which
  no source states.
- R-OBS compares the receipt with the observer after the run. It does not test m0108's condition
  that the runtime cannot read the observer during the run.
- In every case the halt takes effect and is seen at the same instant, so no case separates
  `t_effective` from `t_observed`.
- Not covered: presence of the tier-1 receipt fields, the timestamp source (OPEN-3) and signatures
  (OPEN-5).
- Not in this revision: exemption, restore conditions, rollback, one-way regimes, recurrence and
  closed validity windows. Revision 1 had cases for them. They return, if at all, as a separate
  revision after the first family is reviewed.
- The checker encodes one reading of the sources. A correction from their authors overrides it.
