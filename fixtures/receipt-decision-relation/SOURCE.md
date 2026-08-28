# receipt-decision-relation

Conformance vectors for the cross-document relation between an APS receipt and
the decision it references.

## What this family proves

A receipt carries `decision_ref`, a digest of the decision it was issued under.
Verifying the receipt on its own establishes nothing about that decision: the
receipt is internally consistent and correctly signed whether or not the
decision a verifier happens to be holding is the right one, and whether or not
that decision's authority had already lapsed when the receipt was issued. Two
failure classes live in the gap, and a conformant verifier must reject both.

**`DECISION_REF_MISMATCH`, substitution.** The supplied decision is not the one
the receipt references. Unchecked, a receipt issued under decision A can be
presented alongside an unrelated decision B chosen for its convenient validity
window. The check is a recomputation: the reference is rebuilt from the full
decision evidence and the receipt's own `action_ref` and must equal
`receipt.decision_ref` exactly.

**`VALID_UNTIL_NOT_LATER`, temporal.** The decision's `valid_until` does not
fall strictly after the receipt's `issued_at`. Equality fails as well as
inversion: a window that closes at the instant the receipt is issued left no
interval in which the receipt rested on live authority. Both vectors 2 and 3
exist because equality is the boundary a `>=` reads as acceptable and a `>` does
not, and the corpus should force that distinction rather than assume it.

Ordering matters and is part of the property. Binding is settled **before** the
temporal comparison, because a validity window read off a decision that does not
belong to this receipt is not evidence about this receipt at all.

## Scope

This family exercises receipt/decision relation verification only. It does not
exercise dispatch-time enforcement: consumption of receipt_id, single-use,
revocation or time recheck at dispatch, or spend reservation are
enforcement-boundary obligations and are not tested here.

`verify.ts` additionally assumes the pinned artifacts have already passed their
standalone structural and signature checks. Those were asserted with the SDK at
generation time, before any file was written, and are listed under
*Generation-time assertions* below. The verifier's verdicts are therefore
**relation verdicts**, not full receipt-verification verdicts.

## Vectors

`receipt-decision-relation-v1/`

| file | expected | failure name |
|---|---|---|
| `pass.json` | accept | `PASS` |
| `temporal-equal.json` | reject | `VALID_UNTIL_NOT_LATER` |
| `temporal-earlier.json` | reject | `VALID_UNTIL_NOT_LATER` |
| `substitution.json` | reject | `DECISION_REF_MISMATCH` |
| `temporal-equal.flipped.json` | accept | `PASS` |
| `temporal-earlier.flipped.json` | accept | `PASS` |
| `substitution.flipped.json` | accept | `PASS` |

All seven share `issued_at` `2026-08-28T12:00:00.000Z`. `temporal-equal` sets
`valid_until` to that same instant, `temporal-earlier` to
`2026-08-28T11:59:59.999Z`, and every accepting vector to
`2026-08-28T12:30:00.000Z`.

`substitution.json` carries the receipt, decision **B** as
`provided_decision_evidence`, and a provenance block holding decision **A**
(`correct_decision_evidence`), `correct_decision_ref` and
`provided_decision_ref`. A reviewer can establish from that one file that
hash(A) equals `receipt.decision_ref` and hash(B) does not. B is itself a
complete permit whose own temporal relation passes, so the binding is the only
thing wrong with the pair.

### Failure names

`PASS`, `DECISION_REF_MISMATCH` and `VALID_UNTIL_NOT_LATER` are family-level
conformance semantics describing an observable classification. They are not an
SDK enum. `verify.ts` neither imports nor copies an SDK identifier as authority;
an implementation in any language that reaches the same classification conforms,
whatever it calls its internal error codes.

### Flipped counterparts

Correcting a temporal vector in place would prove nothing. `valid_until` is
inside the decision output, so changing it changes the decision digest, which
breaks the binding. A naive in-place fix still rejects, just for a different
reason. So each corrected counterpart is generated and pinned rather than
derived at test time:

- `temporal-equal.flipped.json`, `temporal-earlier.flipped.json`: the decision
  with `valid_until` moved strictly later, **and** the receipt rebuilt and
  re-signed against it with the same burned test key. Genuinely valid end to end.
- `substitution.flipped.json`: the **same receipt, byte for byte unmodified**,
  supplied with decision A. The receipt was never the defect, so it is not
  touched.

`npm run verify:receipt-decision-relation:flip` requires `PASS` on all three,
which is what shows each corrected artifact is genuinely valid rather than
differently invalid.

## Generation provenance

- SDK repository: `agent-passport-system`, checked out as a sibling of this repo
- Commit: `79d936c80555679c1d19abaed70da9dfa07fe5ee`
  ("feat(receipt-core): public strict serialized-input path for receipt verification")
- Command, run from the repository root:

```
npx tsx fixtures/receipt-decision-relation/generate.ts
```

Every artifact is SDK-produced: real Ed25519 signatures, real receipt ids, real
digests. No JSON under `receipt-decision-relation-v1/` is hand written or hand
edited. Keys, identifiers, timestamps and payloads are pinned constants derived
from documented literals, with no clock read and no randomness, so a re-run on
the same commit reproduces byte-identical files.

The issuer key is a burned test key: the SHA-256 of the literal
`aps-conformance/receipt-decision-relation-v1/issuer-ed25519-seed`, used as the
Ed25519 seed. Its public half is recorded in each vector's provenance block.

`generate.ts` is a provenance record and a regeneration tool. It is **not** part
of `npm test`, and nothing on the test path imports the SDK.

### Generation-time assertions

Nine assertions through `verifyReceiptWithDecisionV1` run before any file is
written; a failure aborts with nothing on disk.

- `pass`, `temporal-equal.flipped`, `temporal-earlier.flipped`: composite valid,
  no errors
- `temporal-equal`, `temporal-earlier`: invalid with exactly
  `['valid_until_not_after_issued_at']`
- `substitution` receipt with A, valid; the same receipt with B, invalid with
  exactly `['decision_ref_mismatch']`; B against a receipt that *does* reference
  it, valid, which is what establishes that B's rejection is a binding failure
  and nothing else
- every vector's receipt independently valid (`receipt.valid`) whatever the
  relation verdict, so a "reject" cannot be hiding a malformed receipt

### File digests

```
ae4ff4ce8cd3a94fd95af2a14aa26f88f7d976753fa9b509b34aa596ebacce74  pass.json
2730ff8e6884b1b4b56e450b233e7393d1af59fdf0e728d0d7248f42b1127afe  temporal-equal.json
4fc125c62451de06b0205e95928bd911b0171743adc701b70363135944fcb966  temporal-earlier.json
fb93520fa9cc6a7bf576b57f6c80316749a605ee0f785cda34b69f0398ef7dd5  substitution.json
a387199a46e9f8ca80808fc0f9eb0741f506de964aa536c3eaef7aab350f8604  temporal-equal.flipped.json
afbd9765545232b41b0ba77bd4008dc7987b0c78fd4ac20a412318ea9f17ab3f  temporal-earlier.flipped.json
7edda5ce72d5158020a2f613dde0367cc93158c36d7807b733609fbe6c584e23  substitution.flipped.json
```

## The construction, for reimplementation without the SDK

`verify.ts` recomputes `decision_ref` from scratch. It imports nothing from the
SDK: JCS and SHA-256 come from this family's own `lib.ts`, over Node's stdlib
crypto. Agreement with the pinned digests is therefore evidence about the
construction rather than an artifact of shared code, which is the whole reason
the family exists.

Domain separation is the tag, one NUL byte, then the RFC 8785 canonical form:

```
tagged(tag, canonical) := tag || 0x00 || canonical
digest(tag, value)     := SHA-256( tagged(tag, JCS(value)) )   -- lowercase hex
```

Tags, transcribed from `src/v2/receipt-core/decision-ref.ts` at commit 79d936c:

| constant | value | source |
|---|---|---|
| `DECISION_REF_TAG` | `APS-DECISION-REF-V1` | `decision-ref.ts:9` |
| authority component | `APS-DECISION-AUTHORITY-V1` | `decision-ref.ts:11` |
| policy component | `APS-DECISION-POLICY-V1` | `decision-ref.ts:12` |
| context component | `APS-DECISION-CONTEXT-V1` | `decision-ref.ts:13` |
| output component | `APS-DECISION-OUTPUT-V1` | `decision-ref.ts:14` |

`tagged` is `decision-ref.ts:18`, the SHA-256 hex helper `decision-ref.ts:19`,
and the component digest `decision-ref.ts:22-24`.

The reference is a digest over a six-member object and no others
(`decision-ref.ts:78-98`, validated at `decision-ref.ts:26-37`):

```
input := {
  "profile":             "aps-decision-ref-v1",
  "action_ref":          <from the RECEIPT>,
  "authority_state_ref": digest(APS-DECISION-AUTHORITY-V1, authority_state),
  "policy_ref":          digest(APS-DECISION-POLICY-V1,    policy_input),
  "context_ref":         digest(APS-DECISION-CONTEXT-V1,   decision_context),
  "decision_output_ref": digest(APS-DECISION-OUTPUT-V1,    normalize(decision_output))
}
decision_ref := SHA-256( "APS-DECISION-REF-V1" || 0x00 || JCS(input) )
```

`action_ref` comes from the **receipt**, never from the decision evidence
(`composite.ts:20`, `composite.ts:106-112`). A decision built for a different
action therefore cannot bind, and a caller cannot quietly supply an `action_ref`
that disagrees with the receipt being checked.

### Normalize before hashing

The output component is hashed **after** normalization
(`decision-ref.ts:44-76`, applied at `decision-ref.ts:88`). `decision_output` is
a closed five-member object (`profile`, `verdict`, `effective_authority_ref`,
`constraints`, `valid_until`), and `constraints` is NFC-normalized, then
de-duplicated, then ordered by Unicode code point
(`decision-ref.ts:68-74`). The sequence matters: two constraints differing only
by Unicode composition are the same constraint, and de-duplicating before
normalizing would keep both.

The pinned vectors store `constraints` **out of order** on purpose. A verifier
that skips normalization computes a different digest and fails `pass.json`, so
the step is observable rather than assumed.

### The temporal comparison

`valid_until` and `issued_at` are both exact UTC milliseconds
(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`, round-tripped through `Date`
so a well-shaped non-instant is rejected; `receipt.ts:25-29`). They are compared
as **instants**, never as strings, and the required relation is strict:
`valid_until > issued_at` (`composite.ts:135`).

## Running

```
npm run verify:receipt-decision-relation
npm run verify:receipt-decision-relation:flip
```

Both are wired into `npm test`. Either exits nonzero on any disagreement between
a vector's stated expectation and the independently computed classification, on
a required vector missing from the corpus, or on a provenance digest that does
not recompute.

Provenance digests are **audit outputs**. `verify.ts` never reads one as an input
to a classification; it recomputes them from the evidence in the file and fails
if they disagree.
