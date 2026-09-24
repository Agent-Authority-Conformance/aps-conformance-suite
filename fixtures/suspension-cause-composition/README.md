# suspension-cause-composition: causes compose, releases are per cause, and a revocation during suspension still stands

Three concurrent lifecycle causes attach to one grant, from three different sources. A
regulator imposes a suspension. The firm's own compliance function imposes a second,
unrelated suspension. A court imposes a restriction. Each carries its own release. This
family asks what a verifier should return as those releases arrive, one at a time, from
the right source and from the wrong one.

Five claims, in the order the vectors exercise them:

1. more than one cause can stand on one grant at once, and the verdict names **which
   causes remain** rather than carrying a single state
2. releasing one cause does not release another, so the grant stays **suspended** while
   the second suspension stands and **restricted** once only the restriction is left
3. a release from a source the standing registry does not place over a cause does nothing
   to that cause, even when the record is genuine and its signature verifies
4. a release from a source that holds standing over a cause it did not impose **is**
   effective, because standing is not the same thing as authorship
5. after every cause has been released, a revocation recorded while the grant was
   suspended still makes the chain invalid, and an unresolvable revocation answer leaves
   it **not established** rather than exercisable

## Status: candidate against proposed text

Every vector in `vectors.json` carries `"status": "candidate_against_proposed"`, and both
runners refuse to run if any vector loses that label.

The proposed text is `aeoess/agent-authority-lifecycle` at commit
`5c1bf09ee29d517f2f19c9bb9212543a7c44b227`, in five places.

`AUTHORITY-LIFECYCLE.md`, section **Lifecycle concepts are separate**, subsection
**Authority lifecycle state**, entries **Suspension** and **External restriction**, quoted
in full:

> **Suspension.** Pauses or narrows the use of authority without permanently ending it.

> **External restriction.** A block from outside the grant chain, such as a sanction, a
> court order, or a legal hold that blocks a deletion. It can stop some effects while the
> grant itself stays valid.

Same section, subsection **Parties and standing**, entry **Lifecycle standing**, quoted in
full:

> **Lifecycle standing.** Who may suspend, revoke, replace or reaffirm an authority
> artifact. This is not always the issuer. An organization, a quorum, a successor, a court
> or a security function can have standing to change authority it never issued.

That document marks the whole grouping, including these three entries, **proposed**, and
says no public case tests them. Section **Invariants**, invariant **L8. Suspension is not
revocation**, supplies the verdict distinction this family is built around:

> Suspension stops the use of authority and of everything that depends on it, and can be
> lifted. Revocation is terminal for the artifact it names. A restricted state is
> different again and does not have to pause descendants.

L8 is marked **proposed** and says nothing about arity. An implementation that holds
exactly one suspension at a time conforms to every word of it. `OPEN-QUESTIONS.md` at the
same commit, section **Release from suspension**, is where the gap is named:

> Lifting one suspension should not clear another, bypass a revocation that happened while
> the agent was suspended, or recreate rights that changed in the meantime. Multiple
> suspension causes probably need to compose, with each one released separately. Not yet
> specified.

"Probably" and "not yet specified" are the words this family is a candidate against. Every
vector below is one reading of that paragraph made executable, and a different reading is
available for several of them. The section "Where the proposed text was too vague to test"
lists the places where the reading is doing work the text does not do.

### This is not a draft-03 conformance case

`draft-pidlisnyi-aps-03` states no suspension rule, no restriction rule, no release rule
and no lifecycle-standing rule. Searching the published plain text
(<https://www.ietf.org/archive/id/draft-pidlisnyi-aps-03.txt>, fetched for this fixture)
for `suspen` returns nothing outside the boilerplate, and `restrict` appears only in the
IETF Trust legal-provisions paragraph at line 65 and in an unrelated sandbox sentence at
line 1207. The closest thing the protocol has is the revocation resolver, and in both
reference SDKs its answer set is exactly three values:

    export type RevocationResolution = 'active' | 'revoked' | 'unknown';

There is nowhere in that type to put one cause, let alone a set of three. So no case here
is a draft-03 conformance case for the cause question.

Three vectors do touch draft-03, and each names that surface in its own
`draft_03_surface` member. `CR-02` rests on Section 3.3 chain verification, quoted at
lines 578-592 of the published plain text:

    578 3.3.  Chain Verification
    579
    580    A verifier processes a root-to-leaf chain in this order: closed
    581    schema and canonical values; delegation_id; historical signing-key
    582    resolution and signature; duplicate identifiers; root trust;
    583    parent_delegation_id; issuer-to-subject continuity; child issuance
    584    time; the seven facet comparisons in Section 3.2; current validity;
    585    and revocation state for every member.  A cycle, repeated identifier,
    586    broken parent link, or issuer discontinuity invalidates the chain.
    587
    588    Verification returns one of valid, invalid, indeterminate, or
    589    unsupported with a stable failure code.  An unavailable or stale
    590    revocation result is indeterminate.  An unsupported facet profile is
    591    unsupported.  Cryptographic or attenuation failure is invalid.  A
    592    caller MUST NOT collapse indeterminate or unsupported into valid.

`CR-13` uses "An unavailable or stale revocation result is indeterminate" from that same
block. `CR-12` rests on Section 3.5, lines 633-641:

    633 3.5.  Cascade Revocation
    634
    635    Any delegation MAY be revoked by its issuer.  Revocation MUST
    636    initiate a cascade to all transitive descendants; a cascade is
    637    complete only when the cascade-completion record of Section 3.5.1 has
    638    been emitted.  Revocation is irreversible.  Until that record is
    639    available, a verifier treats the cascade as incomplete.  The
    640    enforcement gateway MUST recheck revocation status at execution time,
    641    not only at approval time.

"Revocation is irreversible" is the load-bearing phrase for `CR-12`. Even in those three
cases the chain result is draft-03 and the mapping onto this family's verdict names is
not. That a release record does not reach the chain result at all is this fixture's
reading, not draft-03 text.

### The verdict names are not suite vocabulary

`exercisable`, `suspended`, `restricted`, `not_established` and `invalid`, and the
`cause_*` and `release_*` codes, are this family's own local labels. `CONTRIBUTING.md`
reserves failure-class names, record fields and verifier semantics to the maintainer, as
schema owner, and says a pull request is not the vehicle for minting them. This branch is
a candidate for discussion, so the names are a proposal to be decided or replaced, not a
taxonomy anyone should bind to.

## What the SDKs supply, and what this fixture supplies

Neither reference SDK has an API for a lifecycle cause. `sdk-support.ts` and
`sdk_support.py` print, per vector, what each SDK decided and what it declined, and their
output is the evidence for this table.

| concept | npm `agent-passport-system` 7.1.0 | PyPI `agent-passport-system` 4.1.0 |
|---|---|---|
| grant chain state at an instant | supported, `verifyAuthorityDelegationChain` | supported, `verify_authority_delegation_chain` |
| RFC 8785 canonical bytes of a record body | supported, `canonicalizeJCS` | supported, `canonicalize_jcs` |
| Ed25519 signature over those bytes | supported, `verify` | supported, `verify` |
| revoked state | supported, resolver answer `revoked`, failure code `REVOKED` | supported, same |
| unresolvable revocation state | supported, resolver answer `unknown`, code `REVOCATION_UNKNOWN`, chain state `indeterminate` | supported, same |
| a suspended or restricted state | `not_supported`: `RevocationResolution` is `'active' \| 'revoked' \| 'unknown'` and `AuthorityValidationState` is `valid`, `invalid`, `indeterminate`, `unsupported` | `not_supported`: same three resolver answers, same four states |
| more than one concurrent cause on one grant | `not_supported`: no cause object exists to hold one, so arity does not arise | `not_supported`: same |
| a release record, or when one takes effect | `not_supported`: no such record type and no such function | `not_supported`: same |
| lifecycle standing over a cause | `not_supported`: nothing on the authority-delegation surface resolves standing | `not_supported`: same |
| a verdict naming which causes remain | `not_supported`: the result carries `state`, `valid` and `failures`, with no cause member | `not_supported`: same |

The nearest named thing in either SDK is `StandingBasis`, which both export. It is a closed
list (`data_subject`, `third_party`, `regulator`, `court`, `internal_audit`, `insurer`,
`principal`) on the contestability receipt, and it says who may contest a decision. It is
not standing over a lifecycle cause, nothing in the authority-delegation surface consults
it, and this fixture does not use it. It is recorded here so a reader who greps for
"standing" and finds it does not mistake it for the concept under test.

So the gate in `harness.ts` calls the real SDK for the grant's chain state and for each
release record's signature over canonical bytes, and **implements the cause set, the cause
kinds, the standing registry, the release rules, the evaluation-instant comparison and the
five verdict names itself**. A pass is a result about this gate. It is not a conformance
result about either SDK, and neither SDK fails anything here by not having an API the
protocol does not define.

## Records

`chain.json` is minted by `mint.ts`, deterministically, from published seed labels:

    seed = SHA-256("aps-conformance-suite:scc:" + label)

which is the convention `docs/fixture-format.md` records for this suite. No secret
material is in the file: every private key regenerates from a label printed in
`chain.json` under `seed_labels`. `mint.ts` runs 41 mint-time assertions and refuses to
write `chain.json` if any fails.

Five identities: `scc-principal`, `scc-agent`, `scc-regulator`, `scc-firm-compliance`,
`scc-court`.

Two one-hop `AuthorityDelegationV1` chains, each with a time facet open over both
evaluation instants:

- **`GRANT`**, `principal -> agent`. The three causes attach to this grant.
- **`GRANT_CLEAN`**, the same shape with a different nonce and no cause. `CR-02` presents
  it as the positive control, so a run that failed every other case would still show the
  chain, the keys, the signatures and the time facet are sound.

Three causes, `record_type` `fixture:lifecycle-cause:v0`. **That is not an APS record type
and no SDK claims it.**

| label | `cause_id` | kind | imposed by | reason code |
|---|---|---|---|---|
| `REG` | `scc-cause-reg-suspension` | suspension | `scc-regulator` | `regulatory_suspension` |
| `FIRM` | `scc-cause-firm-investigation` | suspension | `scc-firm-compliance` | `internal_investigation` |
| `DECREE` | `scc-cause-decree-gate` | restriction | `scc-court` | `external_approval_gate` |

All three are imposed at the same instant, `T_IMPOSED`. Two are suspensions and one is a
restriction, because L8 separates those two states and this family needs both verdict
names to show the separation surviving a partial release.

The cause-standing registry, in `chain.json` under `cause_standing`:

| cause | sources holding standing |
|---|---|
| `REG` | `scc-regulator`, `scc-court` |
| `FIRM` | `scc-firm-compliance` |
| `DECREE` | `scc-court` |

The court's entry against `REG` is the whole of the superior-source case. The court did
not impose that cause and had no part in it, and the registry places it over that cause
anyway. Where a registry like this comes from, and who publishes it, is not something the
proposed text answers. See "Where the proposed text was too vague to test".

Eleven releases, `record_type` `fixture:cause-release:v0`, also not an APS record type.
Each canonicalizes under RFC 8785 with the SDK's own canonicalizer over a body carrying no
`record_id` and no `signature` member, its `record_id` is SHA-256 over those bytes, and
its `signature` is Ed25519 over the same bytes.

| release | releaser | names causes | released at | what makes it interesting |
|---|---|---|---|---|
| `REL_REG_BY_REGULATOR` | regulator | `REG` | `T_RELEASE_REG` | released by the source that imposed it |
| `REL_FIRM_BY_FIRM` | firm compliance | `FIRM` | `T_RELEASE_FIRM` | released by the source that imposed it |
| `REL_DECREE_BY_COURT` | court | `DECREE` | `T_RELEASE_DECREE` | released by the source that imposed it |
| `REL_FIRM_BY_REGULATOR` | regulator | `FIRM` | `T_RELEASE_FIRM` | **the negative control**, genuine record, no standing over that cause |
| `REL_REG_BY_COURT` | court | `REG` | `T_RELEASE_REG` | superior source, standing without authorship |
| `REL_REG_DECREE_BY_COURT` | court | `REG`, `DECREE` | `T_RELEASE_DECREE` | one record, two causes, standing over both |
| `REL_ALL_THREE_BY_COURT` | court | `REG`, `FIRM`, `DECREE` | `T_RELEASE_DECREE` | one record, three causes, standing over two |
| `REL_REG_FORGED` | regulator named | `REG` | `T_RELEASE_REG` | body names the regulator, signed with the firm's key |
| `REL_UNKNOWN_CAUSE` | court | a cause id not on this grant | `T_RELEASE_DECREE` | names nothing this grant carries |
| `REL_FIRM_EARLY` | firm compliance | `FIRM` | `T_GRANT_ISSUED` | dated before the cause it names was imposed |
| `REL_DECREE_LATE` | court | `DECREE` | `T_LATE_RELEASE` | after `T_EVAL` and before `T_LATER_EVAL` |

One clock, in `chain.json` under `clock`. Every evaluation instant, every imposition and
every release timestamp is one of its entries, and every vector names its instant by
label.

`chain.json` also carries `revocation_timeline_note`. It is an unsigned, descriptive
object, not a revocation record and not evidence that any revocation occurred. The
revocation a vector sees is the resolver answer the vector supplies, exactly as in
`fixtures/sponsor-handover`. The note exists so `CR-12`'s structural check can state, from
the file rather than from prose, that the revocation instant falls after every imposition
and before the earliest release that case presents.

## The gate

`harness.ts`, in two stages.

**Stage one, the SDK.** `verifyAuthorityDelegationChain` at the vector's evaluation
instant, with the vector's revocation answer. `invalid` stays `invalid`. `indeterminate`
and `unsupported` become `not_established`, on the reading that a verifier which could not
establish current authority has not made a claim against the grant. The cause question is
never reached when stage one does not return `valid`. No release record is presented to
the SDK at any point.

**Stage two, this fixture.** Each presented release is checked at the record level first,
in this order, and the first failing check rejects the whole record:

1. signature verifies under the key its `verification_method` points at, else
   `release_signature_unverified`
2. `verification_method` belongs to the `releaser` the body names, else
   `release_releaser_binding_mismatch`
3. `released_at` is at or before the evaluation instant, else
   `release_after_evaluation_instant`

A record that survives those three is then applied **per named cause**, independently:

1. the cause id is one this grant carries, else `cause_not_on_grant`
2. `released_at` is at or after that cause's `imposed_at`, else
   `release_precedes_imposition`
3. the standing registry places the releaser over that cause, else
   `releaser_without_standing`

Causes passing all three are released. This is why `REL_ALL_THREE_BY_COURT` clears exactly
two of the three causes it names: standing is decided per cause, not per record.

The remaining causes are then the grant's cause set minus everything released, sorted. If
the set is empty the verdict is `exercisable`. If anything remains and at least one
remaining cause is of kind `suspension`, the verdict is `suspended`. If anything remains
and all of it is of kind `restriction`, the verdict is `restricted`. In both cases the
result carries the remaining set, and every vector asserts it.

Nothing in this family is stateful across vectors. There is no ledger, no consumption and
no ordering between cases. `CR-15` and `CR-16` are two independent evaluations over one
set of records at two instants, not a sequence.

## Vectors

Sixteen cases in `vectors.json`. Each names its grant, its evaluation instant by clock
label, its revocation answer, and the releases presented.

| id | polarity | presents | expected verdict | remaining |
|---|---|---|---|---|
| `CR-01-three-causes-no-release-suspended` | negative | nothing | `suspended` | `DECREE FIRM REG` |
| `CR-02-no-cause-exercisable` | positive, control | nothing, on `GRANT_CLEAN` | `exercisable` | none |
| `CR-03-one-release-still-suspended` | negative | `REL_REG_BY_REGULATOR` | `suspended` | `DECREE FIRM` |
| `CR-04-two-releases-restricted` | negative | both suspension releases | `restricted` | `DECREE` |
| `CR-05-all-three-released-exercisable` | positive | all three proper releases | `exercisable` | none |
| `CR-06-release-without-standing-does-nothing` | negative, **control** | `REL_FIRM_BY_REGULATOR` | `suspended` | `DECREE FIRM REG` |
| `CR-07-superior-source-release-effective` | positive | `REL_REG_BY_COURT` | `suspended` | `DECREE FIRM` |
| `CR-08-one-record-two-causes-with-standing` | positive | `REL_REG_DECREE_BY_COURT` | `suspended` | `FIRM` |
| `CR-09-one-record-three-causes-partial-standing` | negative | `REL_ALL_THREE_BY_COURT` | `suspended` | `FIRM` |
| `CR-10-forged-release-does-nothing` | negative | `REL_REG_FORGED` | `suspended` | `DECREE FIRM REG` |
| `CR-11-release-of-unknown-cause-does-nothing` | negative | `REL_UNKNOWN_CAUSE` | `suspended` | `DECREE FIRM REG` |
| `CR-12-revocation-during-suspension-survives-full-release` | negative | all three, resolver `revoked` | `invalid` / chain / `REVOKED` at index 0 | none |
| `CR-13-unknown-revocation-after-full-release-not-established` | negative | all three, resolver `unknown` | `not_established` / chain / `REVOCATION_UNKNOWN` at index 0 | none |
| `CR-14-release-before-imposition-does-nothing` | negative | `REL_FIRM_EARLY` | `suspended` | `DECREE FIRM REG` |
| `CR-15-release-after-evaluation-instant-not-effective` | negative | two proper plus `REL_DECREE_LATE` at `T_EVAL` | `restricted` | `DECREE` |
| `CR-16-same-release-later-instant-effective` | positive | the same three at `T_LATER_EVAL` | `exercisable` | none |

`CR-07` is marked positive because the release under test is effective, and its verdict is
still `suspended`, because two other causes are untouched. That pair of facts in one
vector is the point of the case.

`CR-08` and `CR-09` reach the same verdict and the same remaining set from different
records, and both are kept. `CR-08` shows a single record clearing two causes, which is
what stops the composition rule from being read as "one release record, one cause".
`CR-09` shows that adding a third cause to that record changes nothing, because the court
holds no standing over the firm's cause. The reading being tested is that a release record
is not a list of assertions a verifier accepts wholesale.

`CR-12` and `CR-13` are the pair that keeps the wording honest. Both hold a fully released
cause set, and they reach different verdicts: a revoked grant is invalid, an unresolvable
revocation answer is not established. Neither is `exercisable`, and neither release record
is altered or invalidated by the chain result. The release records say what they said. The
chain result is a separate finding about the grant.

`CR-12` also carries `assert_revocation_within_suspension_window`, checked directly
against `chain.json` and not derived from any gate result: the revocation instant falls
after every imposition and before the earliest release the case presents. Without that
check, "a revocation that happened during suspension" would be narrative rather than a
property of the records.

### The negative control

`CR-06` is the vector a naive implementation passes wrongly. `REL_FIRM_BY_REGULATOR` is a
genuine, correctly signed record from a real source, naming a real cause that really is on
this grant, dated after that cause was imposed and before the evaluation instant. Every
check an implementation can run against the record alone succeeds. Only a standing
registry outside the record catches it. An implementation that treats "the signature
verifies and the cause exists" as sufficient clears the firm's suspension on the
regulator's say-so.

`N2-ignores-cause-standing` is that implementation, run against all sixteen cases, and it
fails exactly `CR-06` and `CR-09`.

### Negative control gates

Five gate configurations, all run against all sixteen cases, each with a declared failing
set checked in both directions: a declared failure that quietly starts passing fails the
run just as loudly as an undeclared failure.

| gate | flaw | declared failing set |
|---|---|---|
| `reference-gate` | none | empty |
| `N1-single-suspension-flag` | holds one boolean instead of a set, so any effective release clears everything | `CR-03`, `CR-04`, `CR-07`, `CR-08`, `CR-09`, `CR-15` |
| `N2-ignores-cause-standing` | accepts any release whose signature verifies, whoever signed it | `CR-06`, `CR-09` |
| `N3-release-clears-revocation` | treats a fully released grant as restored and stops reading the chain's revocation answer | `CR-12`, `CR-13` |
| `N4-standing-is-authorship` | only the source that imposed a cause may release it | `CR-07`, `CR-08`, `CR-09` |

`N1` is the representation mistake the family exists for: a single suspended flag cannot
hold three causes, so the first effective release looks like a full restoration. It is
right on ten of these sixteen cases and wrong on six, and the six are exactly the ones
where a cause survives a release.

`N4` is the reading an implementer is most likely to arrive at honestly, because "the
source that imposed it" is the obvious meaning of standing and the proposed text does not
rule it out. It is right on thirteen cases. The three it fails are the three where a court
releases a cause it did not impose. Whether `N4` is a defect at all depends on text that
does not exist yet, which is a finding about the text and not about `N4`.

## Running

Both runners are hermetic: they read `chain.json` and `vectors.json` from this directory
and make no network call.

TypeScript, against the pinned npm SDK, wired into `npm test`:

    npm ci --include=dev
    npm run verify:suspension-cause-composition

Expected final line:

    PASSED: reference-gate matched every case, N1, N2, N3 and N4 each failed exactly their declared set

Python, against the PyPI SDK, a manual run and not part of `npm test`, following the
convention `fixtures/sponsor-handover/validate.py` and
`fixtures/runtime-authority-denial-continuity/verify.py` already set for a Python side
kept out of the Node-only hermetic gate:

    python3 -m venv /tmp/aac-venv-composition
    /tmp/aac-venv-composition/bin/pip install agent-passport-system
    /tmp/aac-venv-composition/bin/python fixtures/suspension-cause-composition/validate.py

Expected final line:

    PASSED: reference-gate matched every case, N1, N2, N3 and N4 each failed exactly their declared set (python)

The per-SDK support records:

    npx tsx fixtures/suspension-cause-composition/sdk-support.ts
    /tmp/aac-venv-composition/bin/python fixtures/suspension-cause-composition/sdk_support.py

Regenerating the records gives the same bytes:

    npx tsx fixtures/suspension-cause-composition/mint.ts

`CHECKSUMS.sha256` pins every file in this directory except itself, and
`tests/digest-integrity.test.mjs` recomputes it inside `npm test`.

## Results

Both runners were executed locally, on one machine, on 2026-09-23, against npm
`agent-passport-system` 7.1.0 and PyPI `agent-passport-system` 4.1.0.

| gate | cases run | matched | declared fail set | observed fail set |
|---|---|---|---|---|
| `reference-gate` | 16 | 16/16 | none | none |
| `N1-single-suspension-flag` | 16 | 10/16 | `CR-03`, `CR-04`, `CR-07`, `CR-08`, `CR-09`, `CR-15` | same |
| `N2-ignores-cause-standing` | 16 | 14/16 | `CR-06`, `CR-09` | same |
| `N3-release-clears-revocation` | 16 | 14/16 | `CR-12`, `CR-13` | same |
| `N4-standing-is-authorship` | 16 | 13/16 | `CR-07`, `CR-08`, `CR-09` | same |

The two runners produced byte-identical output after removing the `(python)` suffix the
Python runner appends to its own summary lines. `CR-12`'s structural window check passed
under both. The per-vector SDK records from `sdk-support.ts` and `sdk_support.py` agree on
all sixteen vectors, for both the chain state and the release-record signature results,
after normalizing API names and boolean spelling.

## Verification split

One entry per distinct verification claim, in the form `layer / claim; runner; Mode;
authorship; implementation`, per `CONTRIBUTING.md`. This family is lab-authored rather
than ingested from an external system, so no entry here could be `independent`, and each
one states the authorship relationship that prevents it.

- **Record minting / `chain.json` regenerates byte for byte from its published seed
  labels; Tymofii Pidlisnyi; Mode A; author-produced; npm `agent-passport-system` 7.1.0
  via `mint.ts`.** Authorship relationship: the runner authored `mint.ts`, the seed labels
  and the records it checks.
- **Grant chain state / each vector's chain result at its evaluation instant; Tymofii
  Pidlisnyi; Mode A; author-produced; npm `agent-passport-system` 7.1.0 via `verify.ts`
  and `sdk-support.ts`.** Authorship relationship: the runner authored the vectors and the
  harness whose expectations the SDK result is compared against, though not the SDK.
- **Grant chain state / the same claim recomputed by the other reference SDK; Tymofii
  Pidlisnyi; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0 via `validate.py`
  and `sdk_support.py`.** Authorship relationship: same runner and same vector author as
  the Mode A entry above.
- **Release-record signature / each presented release's Ed25519 signature over its RFC
  8785 canonical bytes; Tymofii Pidlisnyi; Mode A; author-produced; npm
  `agent-passport-system` 7.1.0.** Authorship relationship: the runner minted the release
  records being checked.
- **Release-record signature / the same claim recomputed by the other reference SDK;
  Tymofii Pidlisnyi; Mode B; author-produced; PyPI `agent-passport-system` 4.1.0.**
  Authorship relationship: same runner, and the records were minted by the npm SDK under
  the same author.
- **Cause verdict / each vector's `exercisable`, `suspended`, `restricted`,
  `not_established` or `invalid` result, its code and its remaining cause set; Tymofii
  Pidlisnyi; Mode A; author-produced; this family's own `harness.ts`, with `validate.py`
  as a second implementation of the same rules.** Authorship relationship: the claimed
  semantic result is constructed by `harness.ts` and `validate.py`, both of which the
  runner wrote, so both are part of the recomputation implementation and not a thin
  harness. Neither reference SDK supplies this claim at all.
- **Structural window / the revocation instant falls after every imposition and before the
  earliest release `CR-12` presents; Tymofii Pidlisnyi; Mode A; author-produced;
  `verify.ts` and `validate.py` over `chain.json`.** Authorship relationship: the runner
  authored both the timestamps and the check.
- **Negative-control isolation / `N1`, `N2`, `N3` and `N4` each diverge on exactly their
  declared set; Tymofii Pidlisnyi; Mode A; author-produced; `harness.ts` and
  `validate.py`.** Authorship relationship: the runner authored the gates, their declared
  sets and the cases.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## External sources, and what they do and do not support

Two external documents were fetched while building this fixture. Neither of them
establishes the rule this family tests, and the fixture says so rather than borrowing
their authority. Neither is a claim that any legal doctrine applies to AI agents.

**FINRA Rule 8311(a)**, fetched at
<https://www.finra.org/rules-guidance/rulebooks/finra-rules/8311>:

> If a person is subject to a suspension, revocation, cancellation of registration, bar
> from association with a member (each a "sanction") or other disqualification

That sentence enumerates cause types that each carry one consequence. It does not say two
of them can attach at once, does not say they are released separately, and does not say
releasing one leaves another standing. Those are exactly this family's claims, so 8311(a)
is **not** a source for composition and is quoted here only to record that it was checked
and found not to support it. **Composition in this fixture is a design reading of the
proposed text, externally unsourced.**

**11 U.S.C. 1107(a)**, fetched at <https://www.law.cornell.edu/uscode/text/11/1107>:

> Subject to any limitations on a trustee serving in a case under this chapter, and to
> such limitations or conditions as the court prescribes, a debtor in possession shall
> have all the rights

That sentence places a court's prescribed conditions over powers the court did not create,
which is where the shape of `CR-07` comes from: a source can sit over an authority it had
no part in making. It does not say that such a source may lift a condition another party
imposed, and this fixture does not claim it does. `CR-07`'s outcome comes from the
standing registry in `chain.json`, which is a fixture-supplied object.

**RFC 8785**, fetched at <https://www.rfc-editor.org/rfc/rfc8785.txt>, is the
canonicalization every record here is signed over:

> This document describes the JSON Canonicalization Scheme (JCS).

## Where the proposed text was too vague to test

This is a finding of the family, not a defect in it. Each item below is a place where the
fixture had to choose, and a different choice would have produced a different, equally
defensible fixture.

**Nothing says where standing comes from.** The Lifecycle standing entry says who may act
on an artifact and lists the kinds of party that can hold it. It does not say what
establishes that a particular party holds standing over a particular cause, who publishes
that fact, or what a verifier consults. This fixture invents a `cause_standing` registry
in `chain.json` and treats it as authoritative. `CR-06`, `CR-07`, `CR-08` and `CR-09` all
turn on it entirely, which is four of the sixteen cases resting on an object the text does
not describe. `N4` exists because "the source that imposed it" is an equally available
reading of the same sentence, and until the text rules it out, `N4` is a reading rather
than a defect.

**Nothing says when a release takes effect.** The proposed text has a suspension that "can
be lifted" and an open question that says causes probably release separately. It says
nothing about the instant a release becomes effective, whether a release dated before its
cause was imposed is a nullity or an error, or whether a release recorded after an action
reaches back to that action. This fixture answers all three: `CR-14` makes an early
release a nullity, `CR-15` and `CR-16` make effect turn on the evaluation instant. All
three answers are constructions. The proposed document does distinguish a transition from
its observation elsewhere, under its `Status observation` and `Notice` entries, and the
suspension entries do not reach for that distinction at all.

**"Suspended or restricted" is not a verdict vocabulary anywhere.** draft-03 Section 3.3
returns `valid`, `invalid`, `indeterminate` or `unsupported`. The proposed text uses
"suspension" and "restriction" as state words in prose without saying whether either is a
verifier result, a fifth and sixth value, or a separate axis alongside the four. This
family mints two verdict names and a remaining-cause member, and both are choices. An
implementation that reported `indeterminate` for every case here would not obviously be
violating anything written down.

**Nothing says what wins when a cause and a revocation are both present.** `CR-12` and
`CR-13` put a revoked and an unresolvable grant next to a fully released cause set, and
this gate answers by evaluating the chain first. The `OPEN-QUESTIONS.md` paragraph says
lifting a suspension should not "bypass a revocation that happened while the agent was
suspended", which settles that case in the direction the gate takes. It does not settle
the reverse ordering, and no vector here presents a revoked grant with causes still
outstanding, because there is no text saying which of the two a verifier should report
first. That gap is real and this family deliberately does not paper over it.

**Precedence among causes is undefined, and the text says so.** The open question names
release from suspension as unspecified and does not raise ordering at all. Nothing here
depends on one cause outranking another, and the remaining set is reported sorted by
label, which is a presentation choice with no claim behind it.

## What a pass establishes

For the exact SDK revisions run, on one machine, a pass establishes that for this family's
own gate:

- three causes from three sources can stand on one grant at once, and the verdict reports
  which of them remain
- releasing the cause a regulator imposed leaves a firm's unrelated suspension standing,
  and the grant suspended
- releasing both suspensions while a restriction stands gives a verdict of restricted
  rather than suspended or exercisable, and names the restriction
- a genuine, correctly signed release from a source the standing registry does not place
  over a cause releases nothing, and an implementation that checks only the record admits
  it
- a release from a source holding standing over a cause it did not impose is effective,
  and an implementation reading standing as authorship rejects it
- one release record naming several causes clears exactly those the releaser holds
  standing over, and no others
- a release dated before its cause was imposed, or after the instant being evaluated,
  releases nothing at that instant, and the same record at a later instant does
- with every cause released, a revoked grant is invalid and an unresolvable revocation
  answer is not established, under distinct codes, and neither is exercisable
- the revocation instant in `CR-12` falls inside the suspension window as a property of
  the committed records, not as narrative

## Does not claim

A pass does **not** establish:

- that any of this is specified. draft-03 states no suspension, restriction, release or
  standing rule, and the proposed text marks its own entries `proposed` and its own open
  question unspecified
- that composition has external support. It does not. The best candidate source was
  fetched, quoted and found not to support it, and the "External sources" section above
  says so
- anything about a deployed gateway, MCP server or agent runtime. No protocol is spoken
  and no network call is made
- that either reference SDK conforms to or violates anything here. Both lack an API for
  the concept, which is `not_supported`, not a failure
- that `fixture:lifecycle-cause:v0` or `fixture:cause-release:v0` is, or should be, an APS
  record type. Both are fixture-local shapes with no standing
- that a cause-standing registry is the right mechanism, or that a registry lookup is
  where a real deployment would get standing from. The registry is this family's modelling
  choice and four vectors depend on it entirely
- that the cause kinds here are the right partition. Two suspensions and one restriction
  is the smallest set that exercises both verdict names, not a claim that lifecycle causes
  come in exactly two kinds
- that any precedence holds among causes. None is modelled and the proposed text defines
  none
- what happens to a cause set when the grant is revoked with causes still outstanding. No
  vector presents that state, and no text settles it
- anything about work in flight across a release boundary. Every vector is one evaluation
  at one instant, and nothing here models an operation that began before a release and
  finished after it
- that releasing every cause returns the grant to its pre-suspension shape. The family
  shows one thing that survives the release, a revocation, and says nothing about anything
  else that may have changed in the meantime
- that a release record is altered by a later finding. It is not. The chain result in
  `CR-12` is a separate record about the grant, and the release records still say exactly
  what they said
- that the verdict names or codes here will survive review as suite vocabulary. See "The
  verdict names are not suite vocabulary"
- that agreement between the two runners is independent corroboration. Both were written
  in this lab in one sitting by the same author, and the Verification split says so per
  layer
- anything about legal doctrine. Human agency and insolvency law have related
  distinctions, the proposed document says it does not assume they apply to AI agents, and
  neither does this fixture
