# lifecycle-subdelegation-edges

Candidate vectors for three subdelegation edges in the proposed authority
lifecycle model. Thirteen vectors, three named verification policies, two
reference SDKs.

**Every vector here is `candidate_against_proposed`.** Nothing in this family
is a conformance claim about draft-pidlisnyi-aps-03 or about any published
specification. Draft-03 states no rule for any of the three questions below.
Where a reference SDK decides one of them anyway, which it does for two of the
three, this README records that as observed implementation behavior at a pinned
version and nothing more.

## The proposed text under test

| what | value |
|---|---|
| repository | `aeoess/agent-authority-lifecycle` |
| commit | `2bf5c7e` |
| earliest commit carrying these concepts | `7796e22` |
| documents | `AUTHORITY-LIFECYCLE.md` 0.1.2-draft, `CASES.md` 0.2-draft, `OPEN-QUESTIONS.md` |

Named text, restated in `vectors.json` under `proposed_text.named_text`:
the `Authority path and dependency`, `Expiry or exhaustion`, `Status
observation`, `Notice` and `Evidence` concepts, invariants L1, L5, L7 and L10,
and the three `CASES.md` cases below.

## The three cases

| case id | question | proposed-text status before this family |
|---|---|---|
| `LC-H-007` | Does a child's own declared validity period have to nest inside its parent's? | Named in `CASES.md` as a question none of L1-L12 states a rule for. |
| `LC-H-008` | Is exhausting a chain's declared maximum subdelegation depth its own named failure, or a variant of expiry or revocation? | Named in `CASES.md`. L5 is the nearest invariant and does not cover it. |
| `LC-H-009` | What does a verifier return for a child minted after an ancestor's revocation was recorded at the source but before it was visible to the issuer? | `CASES.md` candidate tier, honestly labelled hypothetical. |

`LC-H-009` is a hypothetical in `CASES.md` with no external source, and it
stays one here. This family makes no claim that any legal doctrine, standard or
incident describes the propagation-window shape. The vectors exercise what a
verifier returns from records, which is a question that does not need an
external source to be decidable.

## Verdict vocabulary

Only these appear in a recorded result: `valid`, `invalid`, `not established`,
`not yet effective`, `suspended`, `restricted`. The distinction that does work
here is `invalid` against `not established`: a revoked ancestor makes a chain
invalid, and an unusable status answer would leave it not established. No
vector in this family reaches `not established` through the reference policy,
and the vocabulary is in the type so that a future vector cannot introduce one
without saying so.

## Files

| file | what it is |
|---|---|
| `mint.py` | Regenerates `chains.json` byte for byte from published seed labels. No secret material. |
| `chains.json` | Six pinned chains, the two issuance refusals the SDK raised, the issuer's status observation for LC-H-009 and the two instants that bracket its propagation window. |
| `vectors.json` | Thirteen vectors with their expected block and, per vector, what each defective policy does. |
| `harness.ts` | The three policies and the record writer. |
| `verify.ts` | npm runner. |
| `verify.py` | PyPI runner. Not a port of the TypeScript output: the three policies and the record digests are computed again. |
| `sdk-probe.mjs`, `sdk_probe.py` | Which of this family's claims each SDK exposes an API for. |
| `CHECKSUMS.sha256` | Pins `vectors.json` and `chains.json`. |

Regenerate and run:

    python3 fixtures/lifecycle-subdelegation-edges/mint.py   # git diff should be empty
    npm run verify:lifecycle-subdelegation-edges
    python3 fixtures/lifecycle-subdelegation-edges/verify.py

## Determinism

Every Ed25519 key is derived by SHA-256 over a published label of the form
`aps-conformance-suite:sde:<label>`, listed in `mint.py`. Every delegation
nonce is supplied rather than generated, which the Python SDK documents as the
path that keeps issuance deterministic. Canonical bytes are RFC 8785 JCS, and
the two boundary-record digests the LC-H-009 vectors check are pinned in
`vectors.json`. There is no network access, no wall-clock read and no random
source anywhere in the family: every instant comes from a vector.

## The three policies

`reference` is the SDK's own chain verifier, called once per vector. The other
two are deliberately defective and each differs from it along exactly one
declared axis, so a divergence is attributable to that axis and to nothing
else.

- **`per-artifact-only`** checks each presented record on its own and never
  compares two of them. The three checks it runs are the per-certificate checks
  a widely used base path algorithm specifies: the signature verifies under the
  resolved key, the record's own validity period includes the verification
  instant, and the record is not revoked at that instant. It performs no parent
  linkage check, no facet comparison and no depth accounting.
- **`issuer-attestation-trusting`** runs the reference checks except that a
  member the fixture holds a pinned issuer observation for takes its status
  from that observation rather than from the answer available at the boundary.

A vector marked `negative_control` is one at least one defective policy gets
wrong, and `verify.ts` and `verify.py` both check that rather than taking the
label on trust.

`agrees` in a vector's `policy_expected` block means the policy reached the
reference verdict **and** named the same reason at the same index. That
distinction earns its keep at `LC-H-007-d` and `LC-H-008-d`, where the
per-artifact policy reaches `invalid` for a reason that has nothing to do with
what is actually wrong with the chain.

## Sources

Every claim about an external document below was fetched in the session that
built this family and is quoted verbatim at forty words or fewer. The
translation into agent terms is ours. Neither source says anything about AI
agents, and nothing here claims either one applies to them.

**RFC 5280**, *Internet X.509 Public Key Infrastructure Certificate and CRL
Profile*, May 2008. Fetched from `https://www.rfc-editor.org/rfc/rfc5280.txt`.

- Section 6.1.3, item (a)(2), the per-certificate check the `per-artifact-only`
  policy is shaped on: "The certificate validity period includes the current
  time." The algorithm runs this against the current time for each certificate
  individually. It has no step comparing a certificate's stated validity period
  against its issuer's.
- Section 4.2.1.9, on `pathLenConstraint`: "it gives the maximum number of
  non-self-issued intermediate certificates that may follow this certificate in
  a valid certification path." The constraint is carried on an ancestor, which
  is why `LC-H-008-b` is a property of the chain's shape and not of the deepest
  record's own contents.

No source is cited for `LC-H-009`. It is a hypothetical and is labelled one.

This family cites no fixture, repository or open question of this project's own
as an external source. `CASES.md` and `AUTHORITY-LIFECYCLE.md` are named as the
proposed text under test, which is what `candidate_against_proposed` means.

## What the SDKs decide, and what they do not

Two of the three questions turn out to be decided by both reference SDKs
already, which the `CASES.md` text does not claim either way:

- A child's validity period **is** compared against its parent's, at issuance
  and at verification. The issuer refuses with `TIME_WIDENING` and the chain
  verifier reports `TIME_WIDENING` at the child's index. The base path
  algorithm RFC 5280 specifies does not do this, and `LC-H-007-c` is the vector
  that separates the two behaviors.
- Declared maximum depth **is** enforced across the whole chain, with
  `DEPTH_EXHAUSTED` as its own code, reported before any status answer is
  consulted. `LC-H-008-d` is the vector that shows it does not collapse into
  revocation.

The third is decided the way the case proposes, through ordinary ancestor
revocation: a child minted inside the propagation window is invalid once the
revocation is established, and the issuer's contemporaneous good-faith record
does not change that.

## Verification split

One entry per distinct verification claim.
Format: `layer / claim; runner; Mode A | Mode B; author-produced | independent; implementation`.

- chain verdicts, thirteen vectors / the reference policy's verdict and reason
  for each vector; `fixtures/lifecycle-subdelegation-edges/verify.ts`; Mode A;
  author-produced; npm `agent-passport-system` 7.1.0. Author-produced because
  the vectors, the harness and this runner were all written in the same lab,
  and no party outside it reviewed them.
- chain verdicts, thirteen vectors / the same claim recomputed against a second
  implementation; `fixtures/lifecycle-subdelegation-edges/verify.py`; Mode B;
  author-produced; PyPI `agent-passport-system` 4.1.0. Author-produced for the
  same reason: this lab wrote the runner and the vectors, and the two SDKs
  share an author.
- issuance refusals, two vectors / the code the SDK's child issuer raised when
  asked to mint each non-conforming child; `fixtures/lifecycle-subdelegation-edges/mint.py`;
  Mode A; author-produced; PyPI `agent-passport-system` 4.1.0. The refusals are
  pinned in `chains.json` and read back by both runners.
- defective-policy behavior, six vectors / that each declared fail set is a set
  a defective policy actually gets wrong; both runners; Mode A;
  author-produced; the policies in `harness.ts` and `verify.py`, which this lab
  wrote. This is a property of the fixture, not of either SDK.
- record continuity, one vector / that the later finding's record names the
  earlier record by digest and the earlier record's bytes are unchanged; both
  runners; Mode B; author-produced; the RFC 8785 canonicalizer vendored at
  `runners/ts/canonicalize.ts` and its Python mirror in `verify.py`. The two
  digests agree across the two implementations.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## Where the proposed text was too vague to test

Four things the model names that this family could not turn into a vector, with
what would have to be settled first.

1. **Which code a verifier should report when two structural failures are both
   present.** `LC-H-008-d` pins that the reference SDKs report
   `DEPTH_EXHAUSTED` rather than `REVOKED`, because the facet comparison runs
   before the status check. The proposed text says nothing about ordering, so
   that vector records an implementation's phase order and is not evidence that
   the order is the right one. A model that wanted a stable reason across
   implementations would have to say which failure is reported first, or
   require every applicable failure to be reported.

2. **What "the revocation is established" means at a particular boundary.**
   `LC-H-009-b` supplies the revocation as an answer the boundary receives,
   which sidesteps the question. The proposed text's `Status observation`
   concept names freshness and source, and its `Notice` concept names the gap
   between recording a transition and observing it, but nothing says what
   quality of answer makes a revocation established for a verifier that was not
   the one it was recorded at. Without that, a vector testing "the revocation
   exists at the source but this verifier cannot see it yet" would be testing
   the fixture's own stipulation.

3. **Whether the issuer's contemporaneous record has any effect at all.**
   `LC-H-009-c` establishes that it does not make the child's authority
   current. What it is for, beyond showing the issuer acted in good faith, is
   not stated. The wording rule that a later finding never rewrites an earlier
   receipt tells us the record survives. It does not tell us what a verifier or
   a relying party may do with it. `OPEN-QUESTIONS.md` marks the relying-party
   half of this as open and this family does not go past that line.

4. **Whether a depth constraint an ancestor declared may be tightened, but not
   loosened, by a descendant.** The SDKs report `DEPTH_WIDENING` for a child
   claiming more remaining hops than its parent, and the proposed text names no
   rule about it at all. There was no `CASES.md` case in this family's sections
   for it, so no vector was built. It is a gap worth a case rather than a gap
   in this family.
