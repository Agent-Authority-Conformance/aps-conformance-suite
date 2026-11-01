# Clarifications, 2026-11-01

Two positive vectors in this family no longer match the readings their sources now give.
The original vectors.json, results.json, run.mjs, README.md and SOURCE.md remain unchanged as
historical records. Their expected passes for 0003 and 0002 are not evidence of compatibility
with the corrected profile.

## 0003-empty-scope

This positive recomputes an `action_ref` for `scope: ""`. The argentum-core spec now carries an
erratum dated 2026-08-25 for the tag `action-ref-v1.0`, which this family targets. The tag's
`scope` row says both "Free-form non-empty string" and "Pass `""` if not applicable", and the
erratum gives the effective reading as `scope` non-empty with no `""` exception
(https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md). PR #48 made the
same change on `main` on 2026-08-15.
Under that reading an empty scope is outside the input domain and is rejected before any
digest, so 0003 should not be a positive.

The recorded run still passes because this repository pins `agent-passport-system` 7.1.0,
whose `computeExternalActionRefV1` accepts an empty scope. From 8.0.0 (commit 0fb8bb5,
2026-10-02) the same function rejects it with `OUT_OF_PROFILE_DOMAIN`, and the SDK's own
`conformance/action-ref-v1` vector av-007 now expects that rejection. Running this family
against SDK 8.0.0 or later fails on 0003.

## 0002-unicode-fields

This positive uses non-ASCII values. The tag `action-ref-v1.0` allows them. argentum-core
`main` added an ASCII-only domain rule on 2026-07-29, and SDK 8.0.0 or later rejects non-ASCII
`agent_id`, `action_type` and `scope` with `OUT_OF_PROFILE_DOMAIN`. 0002 is a correct positive
for the tag and out of profile for the current text and SDK.

## What follows

A revision that targets the current profile would move 0003 and 0002 to domain negatives
rejected before hashing, and needs the SDK path to run on 8.0.0 or later. That revision and the
repository's SDK pin are separate changes. The upstream copy at
giskard09/argentum-core `examples/conformance/recompute-drift-v1/` carries the same two
positives.

## Revision 2, added 2026-11-01

`revision-2/` targets argentum-core `docs/spec/action-ref.md` at `main` 96931c9. Its runner adds a
domain gate before hashing (ASCII-only `agent_id`, `action_type` and `scope`, non-empty `scope`),
keeps 0001, 0004 and 0005 as positives and the nine drift negatives unchanged, and carries 0002
and 0003 as `dom-0002-unicode-fields` and `dom-0003-empty-scope`, which both paths must reject
before any digest. The repository's `cross-stack:action-ref-v1-negatives:verify` script now runs
revision 2 against `agent-passport-system` 8.0.1. The revision 1 runner and record above remain
unchanged and reproduce only with 7.1.0 installed.

## Target pin of revision 2, added 2026-11-01

`revision-2/README.md`, `revision-2/vectors.json` (`target` and both `spec_stable_ref` values),
`revision-2/run.mjs`, `revision-2/results.json` and the paragraph above name argentum-core
`main` 96931c9 as the text revision 2 targets. That pin does not carry the rules revision 2
applies. 96931c9 is the commit of 2026-05-23 that the spec's own header still names as "Latest
commit". At 96931c9 the `scope` row still says "Pass `""` if not applicable", and the paragraph on
input shapes is a safe band with no rejection rule, so a reader of that revision finds no basis
for either domain negative.

The rules revision 2 applies (ASCII-only `agent_id`, `action_type` and `scope`, non-empty
`scope`, `OUT_OF_PROFILE_DOMAIN` before any digest) are in `docs/spec/action-ref.md` as last
changed at 623ee0a (2026-10-06), byte-identical at `main` d39821e (2026-11-01), sha256
`d07007090ef360d21e4dafb353b82800a4040051ec828b2daea6c8d55b7b4c91`. Read revision 2's target as
that text. The vectors, digests, expected stages and recorded results are unchanged, and the
files listed above remain as published.

The upstream copy at argentum-core `examples/conformance/recompute-drift-v1/` now holds the
positives 0001, 0004 and 0005 and the nine drift negatives. PR #153 removed `0002-unicode-fields`
there (merged 2026-11-01, d39821e).
