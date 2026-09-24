# lifecycle-expiry-and-renewal

Fifteen candidate vectors for three expiry and renewal lifecycle cases: telling a grant
that reached its planned end from one somebody ended early for cause, telling a renewal
that reissues from one that extends, and telling a caretaker's mandate to keep things
running from a mandate to decide how long it holds the job.

Every vector here is **candidate against proposed text**. None of them is a conformance
claim about draft-pidlisnyi-aps-03, about the Agent Passport System SDKs, or about
anything else.

## What this tests

| field | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| model document | `AUTHORITY-LIFECYCLE.md`, version 0.1.2-draft, commit `7796e22` or later |
| case document | `CASES.md`, commit `2bf5c7e`, section **Expiry and renewal** |
| cases | LC-I-007, LC-I-008, LC-I-009 |
| principal invariants | L10 (expiry is not revocation), L3 (reauthorization creates new authority) |
| status of that text | L10 and L3 are **proposed** as lifecycle distinctions. No published specification carries which of the two endings happened |
| label on every vector | `candidate_against_proposed` |

Every vector carries its CASES.md case id in its own id, for example
`LC-I-007-c-later-expiry-does-not-rewrite-the-earlier-record`.

## The `ending` field is the point

Every outcome in this family carries `ending`, which is `null`, `"expiry"` or
`"revocation"`. L10 says:

> "Both stop authority from being used. Expiry says the grant reached its planned end.
> Revocation says someone with authority ended it early."

A boolean validity check loses exactly that. On the three vectors where a grant has ended,
the declared `defective-boundary-boolean-validity` returns the **same verdict** as the
reference boundary and a different `ending`. `verify.ts` checks that claim rather than
asserting it, and prints the result of the check on every run.

## Verdict vocabulary

`valid`, `invalid`, `not_established`, `not_yet_effective`, `suspended`, `restricted`.

`LC-I-007-d` and `LC-I-009-e` are the family's two `not_established` vectors, and both are
there for the same wording rule: a claim nobody with standing made establishes neither
that the artifact ended nor that it did not. Neither is `invalid`.

Later findings never rewrite earlier receipts.
`LC-I-007-c-later-expiry-does-not-rewrite-the-earlier-record` is that rule made
executable: a grant ended early for cause whose declared end then passes keeps
`ending: "revocation"`, and the SDK's own `EXPIRED` answer sits next to it, not instead of
it.

## Layout

```
mint.ts                 builds chain.json, byte for byte, from published seed labels
chain.json              9 delegation chains, 9 signed lifecycle records, 5 action refs
harness.ts              the reference boundary and its two declared defective controls
vectors.json            15 vectors, their expected outcomes and the declared fail sets
verify.ts               the TypeScript run, wired into `npm test`
verify_python_sdk.py    the Python run, manual, not in the Node-only CI gate
CHECKSUMS.sha256        digests of every file above
```

## Determinism

Every Ed25519 key is derived from a published seed label,
`aps-conformance-suite:lifecycle-expiry-and-renewal:<label>`, hashed with SHA-256.
Timestamps, nonces and payloads are pinned constants, and no wall clock is read. Canonical
bytes are RFC 8785 JCS via the SDK's own `canonicalizeJCS`.

```
npx tsx fixtures/lifecycle-expiry-and-renewal/mint.ts
git diff --exit-code fixtures/lifecycle-expiry-and-renewal/chain.json
```

must produce no diff. Each vector is presented to a freshly constructed boundary.

## What the SDK decides and what this fixture decides

| step | decided by | how |
|---|---|---|
| chain shape, signatures, the time facet, revocation state | the SDK | `verifyAuthorityDelegationChain` / `verify_authority_delegation_chain` |
| whether an identifier binds its content (`ID_MISMATCH`) | the SDK | same call |
| parent-to-child narrowing (`SCOPE_WIDENING`, `TIME_WIDENING`) | the SDK | same call |
| scope membership | the TypeScript SDK | `isPurposePermitted`. The Python SDK has no equivalent and the Python runner records `not_supported` |
| which ending happened, its ground and its actor | **this fixture** | `harness.ts` |
| lifecycle standing to end an artifact early | **this fixture** | the signed standing registry in `chain.json` |
| renewal, supersession, and evidence keyed to a superseded identifier | **this fixture** | `harness.ts` |
| an interim or caretaking mandate | **this fixture** | `harness.ts` |

Two SDK answers worth naming, both recorded in `chain.json` under
`mint_time_sdk_observations` rather than asserted here:

- `LC-I-007-c`: the grant was ended early for cause and its declared end has also passed.
  The SDK reports `EXPIRED`, because draft-03 section 3.3 runs the current-validity phase
  before the revocation phase. The lifecycle `ending` stays `revocation`.
- `LC-I-008-d`: the attempt to extend an artifact in place returns `ID_MISMATCH`. draft-03
  derives `delegation_id` from the content, so a later `not_after` is a different
  artifact. Extend-in-place is not expressible, and that is the finding.

## The two negative controls

| control | its defect | declared fail set |
|---|---|---|
| `defective-boundary-boolean-validity` | records a boolean and no ending, cause or actor | `LC-I-007-a`, `-b`, `-c` |
| `defective-boundary-renewal-extends-identity` | reads "renewed" as the same authority with a later end date | `LC-I-008-a`, `-b`, `-c` |

**The negative control a naive implementation passes wrongly** is the boolean-validity
boundary on `LC-I-007-a`, `-b` and `-c`. On all three it returns the same verdict the
reference boundary returns. A checker comparing only `verdict` passes it on every vector
in the family. Only `ending` (and, on `-b` and `-c`, the recorded cause and actor)
separates a grant that ran out from one a party with standing cut off for a named reason.
`verify.ts` asserts that property explicitly at the end of the run.

`defective-boundary-boolean-validity`'s flag scopes to the `ending_kind` rule only, which
is why it matches on `LC-I-008-b` and `LC-I-009-d` even though those carry an `ending`.
The control is declared for LC-I-007 and nothing else.

## Sources

- **LC-I-007.** [22 CFR 51.62, via Cornell LII](https://www.law.cornell.edu/cfr/text/22/51.62):
  "The Department may revoke or limit a passport when:", one of whose named grounds is
  "The passport was illegally, fraudulently or erroneously obtained from the Department."
  Revocation on stated grounds and a printed expiration date are structurally separate
  mechanisms there. The fixture takes the *shape* (a named ground, a named actor, a
  separate trigger) and makes no claim about what the regulation requires of anything
  other than passports.
- **LC-I-008.** [Let's Encrypt](https://letsencrypt.org/how-it-works/): "Renewing a
  certificate at a later time means repeating the issuance process over again - performing
  domain validation and then requesting a new certificate."
- **LC-I-009.** [Universi Dominici Gregis, Vatican](https://www.vatican.va/content/john-paul-ii/en/apost_constitutions/documents/hf_jp-ii_apc_22021996_universi-dominici-gregis.html):
  "During the vacancy of the Apostolic See, the government of the Church is entrusted to
  the College of Cardinals solely for the dispatch of ordinary business and of matters
  which cannot be postponed." One governing model's answer for one office. The fixture
  reads one recorded instrument and makes no claim that the mechanism generalizes. Office
  vacancy stays open in `OPEN-QUESTIONS.md`.

Nothing here says that a legal doctrine applies to AI agents.

## Verification split

- reference boundary behaviour over all 15 vectors / the lifecycle verdicts and the
  `ending` field; `npm run verify:lifecycle-expiry-and-renewal`; Mode A; author-produced;
  `harness.ts` in this repository. Author-produced because the same author wrote the
  vectors, the expected outcomes and the boundary whose behaviour is being checked.
- chain state, identifier binding, parent narrowing and revocation state on every vector;
  `npm run verify:lifecycle-expiry-and-renewal`; Mode A; author-produced;
  `agent-passport-system` 7.1.0 (npm). Author-produced because the vectors and the SDK
  share an author, even though the harness only transports inputs into the SDK and
  compares its output.
- scope membership on every vector; `npm run verify:lifecycle-expiry-and-renewal`; Mode A;
  author-produced; `agent-passport-system` 7.1.0 `isPurposePermitted`. Same authorship
  relationship as the entry above.
- chain state, identifier binding and parent narrowing recomputed in a second language;
  `python fixtures/lifecycle-expiry-and-renewal/verify_python_sdk.py`; Mode B;
  author-produced; `agent-passport-system` 4.1.0 (PyPI). Author-produced because the
  Python SDK shares an author with the vectors.
- the lifecycle verdicts recomputed against a separately written port; `python
  fixtures/lifecycle-expiry-and-renewal/verify_python_sdk.py`; Mode B; author-produced;
  the rule port in `verify_python_sdk.py`. Author-produced because the port and
  `harness.ts` were written by the same author in the same session.
- determinism of `chain.json`; `npx tsx fixtures/lifecycle-expiry-and-renewal/mint.ts &&
  git diff --exit-code`; Mode A; author-produced; `mint.ts` in this repository. Same
  authorship relationship.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## What a pass establishes

That this fixture's reference boundary, run over records the pinned SDKs verify, returns
the recorded verdict and `ending` on each of the fifteen record sets, that two named
defective boundaries diverge on exactly the vectors declared for them, that the
boolean-validity boundary differs from the reference boundary in the `ending` field and
not in the verdict, and that a second implementation in a second language reaches the same
answers.

## Does not claim

- That the `ending` field, the standing registry or the renewal record are the right
  shapes, or the only reasonable ones.
- That draft-pidlisnyi-aps-03 states any of this. It does not.
- That either SDK is non-conformant.
- Anything about what a law, regulation or canon requires of AI agents.

## Where the proposed text was too vague to test

1. **L10 distinguishes the two endings and no record shape carries which happened.**
   draft-03 has no `ending` field, no ground and no actor. The `revocation_notice` record
   and the `ending` field are this fixture's invention.
2. **Phase order makes the earlier ending invisible to the SDK.** draft-03 section 3.3
   runs the current-validity phase before the revocation phase, so a grant ended early for
   cause that later reaches its declared end reports `EXPIRED`. Neither text says which of
   the two an evidence record should carry. This fixture keeps the earlier record, and
   says here that that is a choice.
3. **"Lifecycle standing" is named and never operationalized.** AUTHORITY-LIFECYCLE.md
   lists it as a concept: who may suspend, revoke, replace or reaffirm, which "is not
   always the issuer". Nothing says how a verifier establishes it. The signed standing
   registry is invented here.
4. **There is no renewal operation at all.** No supersession link, no way to say a new
   artifact replaces an old one, and no rule for evidence keyed to a superseded
   identifier. LC-I-008 needs all three and all three are invented.
5. **Whether extend-in-place should exist is unaddressed.** It cannot exist in draft-03
   because `delegation_id` binds the content. Whether that is a deliberate decision worth
   stating as a rule, or a consequence nobody has written down, is not in either document.
6. **LC-I-009 sits on an open question.** Office vacancy and succession, and an interim
   holder's own scope and duration, are listed as open in `OPEN-QUESTIONS.md`. The vectors
   here read one recorded instrument and decide nothing general. `LC-I-009-d` (an
   extension record from the party with standing is still not a fresh grant) is the one
   place the family leans on L3 rather than on the instrument, and L3's "new grant" half
   is itself marked **proposed**.

## Related fixtures in this repository

`issuance-refusal-expiry` already makes the narrower point that draft-03 chain
verification returns a different failure code for an expired member than for a revoked
one, at the code level. This family does not repeat that. What it adds is the record
layer: which ending happened, on whose standing, on what ground, and what a verifier
returns when the two overlap. `ancestor-revocation-chain` and `sponsor-handover` are the
other neighbours.

## Running it

```
npm ci --include=dev
npm run verify:lifecycle-expiry-and-renewal

python3 -m venv /tmp/pyenv
/tmp/pyenv/bin/pip install agent-passport-system==4.1.0
/tmp/pyenv/bin/python fixtures/lifecycle-expiry-and-renewal/verify_python_sdk.py
```

Both exit 0 on success. Neither touches the network.
