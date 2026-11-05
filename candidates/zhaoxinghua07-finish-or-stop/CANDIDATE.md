# Candidate: zhaoxinghua07-finish-or-stop

Cases for two fail-closed behaviors at the boundary of delegated authority: what
a verifier owes when a capability token arrives with no signature and no
attestation, and what an executor owes when a required quorum is not met. Each
case gives the facts and one response an implementation could produce, and
states whether that response satisfies the source text and which rule decides.
This is a candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and
adds nothing to the lab's schema, failure classes or verifier behavior.

The expected behaviors of these two cases are **proposed candidate tests**, not
requirements established by the pinned specification. The NTI x LGD
transition-contract spec v0.1.4 does not define either behavior these cases
test (rejecting unsigned capability tokens, or blocking dispatch when the
required quorum is missing); it is cited only as the context of the proposal.
The expected behavior instead comes from two sources:

1. the pinned Rust regression tests in the upstream NTI-1 spec repository
   (`conformance/rust/nti_regressions.rs` at commit
   `9193f5bdae54a5fe3768c6a705cc24efe631f88f`, tests
   `unsigned_capability_cannot_grant_authority` and
   `required_quorum_blocks_dispatch_when_one_module_is_available`), which check
   decisions and execution counts; and
2. the submitter's 2026-11-03 written input on the public list, recorded at
   2026Nov/0021 and quoted verbatim at 2026Nov/0022, which stated the expected
   values in advance before this candidate was drafted.

The reason strings used in the cases (`unsigned_token_no_attested_capability`,
`quorum_unmet`) are candidate-defined values: the Rust tests do not establish
reason strings, and `check.py` does not validate them.

## Submitter

Xinghua Zhao (Steven Zhao), independent researcher, ORCID 0009-0001-0512-1237.
Mail: zhaoxinghua07@126.com — GitHub: zhaoxinghua09-cell.

## Normative target

- `spec`: NTI x LGD transition-contract spec v0.1.4 (proposed, draft for
  comment), https://github.com/zhaoxinghua09-cell/nti-lgd-transition-contract at
  commit 0b9303a (main), sha256
  `83d88a70237aedb6bffdb446b8bd8e3e4df41291d2c178f33367a6e10d8fc763` of the
  retrieved copy (27477 bytes) — byte-identical to the list attachment
  2026Oct/att-0108 that the lab's published records pin. Cited as context only:
  this specification does not define either behavior these cases test, and no
  case cites it as basis.
- `nti_regressions.rs`: https://github.com/abisheakp197/nti-spec at commit
  9193f5bdae54a5fe3768c6a705cc24efe631f88f, file
  `conformance/rust/nti_regressions.rs`
  ([permanent link](https://github.com/abisheakp197/nti-spec/blob/9193f5bdae54a5fe3768c6a705cc24efe631f88f/conformance/rust/nti_regressions.rs)),
  tests
  `unsigned_capability_cannot_grant_authority` and
  `required_quorum_blocks_dispatch_when_one_module_is_available` (introduced by
  merged PR #24; CI on the merge commit reports 9/9 checks successful,
  https://github.com/abisheakp197/nti-spec/actions). These tests check
  decisions and execution counts; they do not establish the reason strings used
  in this candidate.
- List record: public-agentprotocol 2026Oct/0108; the two vectors and their
  expected behaviors were proposed in the submitter's 2026-11-03 written input
  (recorded at [2026Nov/0021](https://lists.w3.org/Archives/Public/public-agentprotocol/2026Nov/0021.html)
  and quoted verbatim at
  [2026Nov/0022](https://lists.w3.org/Archives/Public/public-agentprotocol/2026Nov/0022.html)),
  and the NTI author formally requested a lab run of them in
  [2026Nov/0023](https://lists.w3.org/Archives/Public/public-agentprotocol/2026Nov/0023.html).

Rule descriptions state the rule in the submitter's own words. Each case lists
the sources it rests on in `basis`.

Note on pins: two texts of this spec revision briefly coexisted. The W3C list
attachment of 2026-10-30 (att-0108, 27477 bytes, sha256 `83d88a70...`) is the
copy the lab's published records pin; an earlier mirror text (commit 679b6e4,
sha256 `a0d40175...`) diverged from it by wrapping plus three substantive
deletions (a §2.4 status sentence, part of the OPEN-1 row, and a §7 citation
clause) that were not version-bumped under the spec's own §0.2 rule. The
mirror was aligned back to the released bytes in commit 0b9303a on 2026-11-04,
so the pinned digest is now reproducible from the mirror end to end; a
correction and the alignment notice were posted on the list the same day. The
checker and mutation test below are pinned to behavior, not to a byte hash.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors.json`, `check.py`,
`mutate.py`. No files are copied from the sources. ZX-D01 and ZX-Q01 are the two
vectors proposed on the list (quoted in 2026Nov/0022); ZX-E01, ZX-E02, ZX-E03,
ZX-E04 and the two contrast cases were written for this candidate.

## License

Apache 2.0, the license of this repository. The transition-contract spec is
CC BY 4.0; this candidate reuses no text from it beyond short phrases for
identification, names the commit and the sha256 of the retrieved copy, and adds
no code from any implementation.

## What the cases test

Eight cases: 4 conformant, 4 nonconformant. Identifiers are illustrative; the
`ed25519:`/`nti1:` strings in ZX-D02 are placeholders, not keys.

| ids | rule | what is tested | basis |
|---|---|---|---|
| ZX-D01, ZX-E01, ZX-E03, ZX-D02 | R-UNSIGNED | a capability token that carries no attestation (ZX-D01 and the other unsigned cases carry no signature either): denying fail-closed with a `unsigned_token_no_attested_capability` reason (a candidate-defined value) and zero executions is what the rule owes (D01, the invited vector); returning ALLOW infers a pass from an unattested token and is not (E01, the failure mode the vector locks out); a denial that still lets the action execute is not a fail-closed denial (E03); a signed, attested token may be honored, so the rule is about absence of attestation, not refusal in general (D02) | nti_regressions.rs, list_record |
| ZX-Q01, ZX-E02, ZX-E04, ZX-Q02 | R-QUORUM | quorum set to 2 with only 1 eligible module available: the operation must present the blocked state with zero executions and a `quorum_unmet` reason (a candidate-defined value) (Q01, the invited vector); the single eligible module executing once breaks the quorum guarantee and is not (E02, the failure mode the vector locks out); an allow, even with zero executions, does not carry the blocked record the rule owes (E04); with 2 eligible modules executing is what the rule owes, so the rule is about an unmet quorum, not execution in general (Q02) | nti_regressions.rs, list_record |

Reading rules are stated in `vectors.json`: an outcome is read as the record it
presents; an absent key is not the same as an explicit null; outcome field names
are this candidate's own representation, since the source names values and
rules, not a JSON binding.

## How to run

```
python3 -I check.py vectors.json
python3 -I mutate.py
```

`check.py` recomputes each case's verdict from its input and outcome, compares
the verdict with `expect`. To test an implementation, give it each case's input,
replace `outcome` with the response it produced, and run `check.py`. `mutate.py`
weakens or distorts one rule of `check.py` at a time, including a version of
every rule family that always answers nonconformant and one that always answers
conformant, and fails unless some case catches each change.

At the revision submitted, the submitter's runs on Python 3 printed `8/8 agree`
and `6/6 mutants killed`, each with exit 0. These show that the checker agrees
with the expected results and that every rule has a case depending on it, in
both directions. They say nothing about any implementation, and they do not show
that the expected results are the right reading of the source.

## Evidence

The two failure classes are encoded as pinned Rust regressions in the upstream
NTI-1 spec repository (`conformance/rust/nti_regressions.rs` at commit
9193f5bdae54), and CI on that merge commit reports 9/9 checks successful,
including the two dedicated jobs "Original baseline must reproduce both defects"
and "Candidate core fix and regression controls"
(https://github.com/abisheakp197/nti-spec/actions). An NTI-1 run of these
vectors has been requested (2026Nov/0023); it has not been agreed or scheduled
by the lab, and no run has been performed. A reference implementation for a
future Mode A run has been named by the NTI author (2026Nov/0023):
https://github.com/abisheakp197/Neutral-Trust-Infrastructure. The submitter's
runs of `check.py` and `mutate.py` are author-produced and are not runs against
any implementation.

## Known limitations

- The vectors are candidate material; publication review does not establish
  technical correctness and no conformance result is claimed for any
  implementation.
- The expected verdicts encode the submitter's position as stated on the list
  (deny fail-closed; stay blocked); an independent runner may dispute via the
  lab's dispute record.
- The source is one spec at one revision. A revised spec needs a new revision of
  this candidate.
- Sibling record: the lab candidate aeoess-running-call-halt already covers the
  finish-or-stop family from the spec side; this candidate adds the two invited
  vectors as executable cases plus contrast cases, and does not overlap its
  file set.

## DCO

Commits in this pull request carry the sign-off actually recorded in the
repository, `Signed-off-by: Xinghua Zhao (Steven Zhao)
<zhaoxinghua09-cell@users.noreply.github.com>` (as in commit 91f9d90); new
commits to this candidate carry the same sign-off.
