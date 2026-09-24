# `lifecycle-multiple-principals-and-conflict`

More than one principal with a claim on the same authority, and the ways those
claims conflict.

**92 vectors across 14 cases**, one concept per case, every one of them from the
"Multiple principals and conflict" section of `CASES.md` v0.2 in
`aeoess/agent-authority-lifecycle`. Every vector is
**`candidate_against_proposed`**. Nothing here tests draft-pidlisnyi-aps-03 or
any other published specification.

| Case | Concept | Question |
|---|---|---|
| LC-C-002 | `contested_seat` | Two live claims to one seat, with a default holder for the contested window, a hard deadline, and a supermajority that can flip the default |
| LC-C-005 | `competing_succession_sources` | Two independently valid sources naming different holders for one seat |
| LC-C-006 | `void_from_issuance_finding` | An ancestor invalid from issuance, discovered long after the fact |
| LC-C-011 | `concurrence_gate` | A gate needing two independent concurrences present together |
| LC-C-012 | `joint_objective_no_union` | Independently rooted chains coordinating without pooling scope |
| LC-C-016 | `asymmetric_threshold` | A threshold that differs by direction of the action |
| LC-C-018 | `unanimous_role_set` | An enumerated role set where silence blocks rather than consents |
| LC-C-020 | `ad_hoc_position` | A position created live by an eligibility rule, with no pre-named holder |
| LC-C-022 | `pending_ratification` | A revocation pending ratification, provisional throughout if denied |
| LC-C-029 | `per_contributor_caveat` | Per-contributor caveats on a shared coalition grant, checked per source |
| LC-C-031 | `standing_override` | A standing, cause-free override above a concurrently exercised grant |
| LC-H-001 | `divisible_grant_revocation` | A joint grant divisible by co-issuer contribution share |
| LC-H-002 | `instruction_precedence` | A named asymmetric default between contradictory co-signer instructions |
| LC-H-003 | `sequenced_revival_window` | A revival gated by a sequencing rule and a standing rescission window |

The fifteenth case in that section, **LC-C-009** (a legitimately confidential
succession order held by one custodian), is **not built here.** Its
record-level question, that an attestation from a sole custodian is what a
verifier has and that a missing, wrong-role or self-declared-role attestation
leaves the matter not established, is already tested vector for vector by
`fixtures/activation-not-established` (`AX-02` no attestation, `AX-03` honest
wrong role, `AX-04` self-declared role, `AX-06` unverifiable signature). Building
it again here would duplicate those vectors rather than add a question.

## Status

**candidate.** Each vector names the proposed text it exercises and the
`CASES.md` case id it comes from. The proposed text is in
`aeoess/agent-authority-lifecycle` at commit `7796e22` or later. A pass says the
reference boundary in `harness.ts` behaves as the vectors record and that the
SDK layers behave as recorded. It does not say the proposed text is right, and it
is not a conformance result for any implementation.

`CASES.md` marks all 14 cases **proposed**, and this fixture does not change
that.

## Proposed text under test

Every vector carries a `proposed_text` string naming the concept, invariant or
open question it exercises. The short form:

| Case | Proposed text |
|---|---|
| LC-C-002 | Principal, Lifecycle standing and Suspension concepts, plus `OPEN-QUESTIONS.md` "Office vacancy and succession" |
| LC-C-005 | **L5**, the Verifier trust policy concept, plus "Office vacancy and succession" |
| LC-C-006 | **L1**, the Issuance and Evidence concepts |
| LC-C-011 | **L5** and the Approval concept |
| LC-C-012 | **L5** |
| LC-C-016 | **L5** and the Authorization decision concept |
| LC-C-018 | the Approval concept and **L5** |
| LC-C-020 | Principal binding and Activation condition concepts, plus "Office vacancy and succession" |
| LC-C-022 | **L8**, plus `OPEN-QUESTIONS.md` "Release from suspension" |
| LC-C-029 | monotonic narrowing, Target binding and Action or capability binding concepts |
| LC-C-031 | **L11**, Delegated authority and Revocation concepts |
| LC-H-001 | **L1** |
| LC-H-002 | **L5** and the Authorization decision concept |
| LC-H-003 | **L3** and **L10** |

**L5** is named by five cases, and the point in four of them is that L5 is
**not** what they test. L5 forbids unioning scope across chains. LC-C-011 is the
opposite failure, refusing to act on one chain alone whatever its scope.
LC-C-012 is the case L5 leaves undescribed, chains coordinating legitimately
without pooling. LC-C-016 is a threshold that is not symmetric. LC-H-002 is two
instructions in direct conflict. Each vector's `proposed_text` states that
distinction rather than leaving it implied.

## Case sources

Each case in `CASES.md` rests on a human or institutional precedent. Five of the
fourteen have a source that was fetched while this fixture was built, quoted
below. **None of them says anything about AI agents.** The translation into agent
terms belongs to `CASES.md`, and a precedent is a source of cases rather than a
claim that a legal doctrine applies to AI agents.

- **LC-C-002.** US Constitution Amendment XXV Section 4,
  [Cornell LII](https://www.law.cornell.edu/constitution/amendmentxxv): "within
  twenty-one days after receipt of the latter written declaration, or, if
  Congress is not in session, within twenty-one days after Congress is required
  to assemble, determines by two-thirds vote of both Houses that the President is
  unable to discharge the powers and duties of his office". And the reversion:
  "otherwise, the President shall resume the powers and duties of his office".
  That second clause is why `LC-C-002-d` reverts to the challenged party rather
  than to whoever holds the seat.
- **LC-C-016.** 14 CFR §121.533,
  [Cornell LII](https://www.law.cornell.edu/cfr/text/14/121.533): "The pilot in
  command and the aircraft dispatcher are jointly responsible for the preflight
  planning, delay, and dispatch release of a flight in compliance with this
  chapter and operations specifications." And, on the stopping direction:
  "Cancelling or redispatching a flight if, in his opinion or the opinion of the
  pilot in command, the flight cannot operate or continue to operate safely as
  planned or released."
- **LC-H-001.** Maine Uniform Trust Code, 18-B M.R.S. §602(2),
  [legislature.maine.gov](https://legislature.maine.gov/statutes/18-B/title18-Bsec602.html):
  "each settlor may revoke or amend the trust with regard to the portion of the
  trust property attributable to that settlor's contribution". The same
  subsection also has a different rule for a different property class: "the trust
  may be revoked by either spouse acting alone but may be amended only by joint
  action of both spouses". That split between revocation and amendment is what
  `LC-H-001-e` and `-f` exercise.
- **LC-H-002.** UCC §4-403(a),
  [Cornell LII](https://www.law.cornell.edu/ucc/4/4-403): "If the signature of
  more than one person is required to draw on an account, any of these persons
  may stop payment or close the account."
- **LC-H-003.** 11 U.S.C. §524(c),
  [Cornell LII](https://www.law.cornell.edu/uscode/text/11/524): the agreement
  must have been made "before the granting of the discharge under section 727,
  1141, 1192, 1228, or 1328 of this title", and the debtor may rescind "at any
  time prior to discharge or within sixty days after such agreement is filed with
  the court, whichever occurs later". Those two clauses are the sequencing rule
  and the window `sequence-ignored` and `window-ignored` each drop.

For the other nine cases (LC-C-005, LC-C-006, LC-C-011, LC-C-012, LC-C-018,
LC-C-020, LC-C-029, LC-C-031, and the record-only half of LC-C-002) **no source
was fetched while this fixture was built**, so this README makes no claim about
their human analogs. Their vectors name only the `CASES.md` case id and the
proposed text they exercise, and the record-level question is the whole of what
is tested. `CASES.md` carries its own sources for them, and two of those are
flagged as needing rework in the lab's own review notes, so repeating them here
would be worse than silence.

## Setup

```
npm ci --include=dev
python3 -m venv /tmp/g2-venv
/tmp/g2-venv/bin/pip install 'agent-passport-system>=4.1,<5'
```

`mint.py` produces two kinds of record into `chain.json`.

**Ten `AuthorityDelegationV1` chains**, for the nine cases that rest on real
signed delegations:

| Chain | Shape | Used by |
|---|---|---|
| `TAINTED` | `dept -> deputy -> agent_t -> joint`, three hops | LC-C-006, the middle record is the one later found void |
| `SEAT_P` | `source_1 -> holder_p` | LC-C-005, one claimed succession source |
| `SEAT_Q` | `source_2 -> holder_q` | LC-C-005, the rival source, same seat |
| `UNIT_A` | `agency_a -> a_ops -> joint` | LC-C-012, one independently rooted chain |
| `UNIT_B` | `agency_b -> b_ops -> joint` | LC-C-012, the other, same leaf subject |
| `CONTRIB_X` | `nation_x -> coalition` | LC-C-029, one contributor's narrowed subset |
| `CONTRIB_Y` | `nation_y -> coalition` | LC-C-029, the other contributor's subset |
| `SHARE_A` | `settlor_a -> trustee` | LC-H-001, one co-settlor's contributed share |
| `SHARE_B` | `settlor_b -> trustee` | LC-H-001, the other share, same trustee |
| `PILOTAGE` | `master -> pilot` | LC-C-031, the concurrently exercised grant |

Three facts are readable off the bytes rather than asserted in prose. `UNIT_A`
and `UNIT_B` share the leaf subject and share no `delegation_id` and no parent,
so they are independently rooted chains held by one agent. `CONTRIB_X` and
`CONTRIB_Y` narrow to the **same** two-grant coalition subset, so the caveat
difference between them lives in the caveat records rather than in the delegated
scope. `SHARE_A` and `SHARE_B` carry disjoint scope prefixes into the same
trustee, so a revocation reaching one share is visible as a scope the trustee can
no longer exercise.

**Approval-gate material** for the six record-only cases: one Ed25519 public key
per named actor and one real signature per `(actor, gate subject)` pair over the
exact bytes `approvalSignContent` produces, which is `<request_id>:<subject>`. 25
signatures plus one deliberately tampered one, produced by advancing the final
hex digit of a real signature.

The runners **verify those signatures with the SDK** rather than trusting a
boolean in the vector, so "this confirmation's signature does not verify" is a
fact about bytes. Both SDKs produce byte-identical Ed25519 signatures over the
same content, confirmed in this session, so the gate material is not a
TypeScript-only artifact.

## Decision boundaries

`harness.ts` holds one reference boundary and **fourteen** defective ones. Each
drops exactly one part of the proposed text, so a divergence is attributable to
the part it dropped rather than to a blend of defects. Each runs against
**every** vector for the concepts it covers, not only the ones predicted to
diverge, so an undeclared divergence and a declared divergence that stops
happening are both loud.

| Boundary | What it drops | Diverges on |
|---|---|---|
| `reference` | nothing | none, it must match all 92 |
| `signature-suffices` | the multi-role gate. One signed affirmation from any known principal satisfies it. | `LC-C-011-b` to `-g`, `LC-C-018-b` to `-e` |
| `symmetric-threshold` | the direction axis. Uses the origination policy in every direction. | `LC-C-016-c`, `-d`, `-f` |
| `pooled-caveats` | per-source caveats. Forbids only where every contributor forbids. | `LC-C-029-b` |
| `objective-unions-scope` | the no-pooling reading of a joint objective. | `LC-C-012-b`, `-c` |
| `last-write-wins` | the named stop-beats-pay default. Takes the latest counted instruction. | `LC-H-002-c`, `-d` |
| `sequence-ignored` | the ordering rule for a revival. | `LC-H-003-b` |
| `window-ignored` | the standing rescission window. | `LC-H-003-c`, `-e` |
| `retroactive-finding` | the prospective-only reading of a later finding. | `LC-C-006-a` to `-e` |
| `revocation-channel-only` | the standing override. Only a revocation record ends a grant. | `LC-C-031-c`, `-e` |
| `finalize-on-initiation` | the state between initiation and ratification. | `LC-C-022-a`, `-c`, `-d`, `-e` |
| `indivisible-grant` | divisibility by contributed share. | `LC-H-001-b`, `-c`, `-d`, `-g` |
| `default-continues` | the reversion on deadline silence. | `LC-C-002-d` to `-g`, `-i` |
| `first-presented-wins` | the source priority requirement. | `LC-C-005-a` to `-d` |
| `pre-named-default-holder` | dissolution of an ad hoc position. | `LC-C-020-f` |

Several controls are written so they reach the reference answer where they
genuinely agree with it, rather than diverging on a positive vector because they
label the same answer differently. `signature-suffices` matches the reference
wherever every required role affirmed. `default-continues` matches it wherever
the supermajority was in fact recorded by the deadline. `objective-unions-scope`
checks the selected chain first. `revocation-channel-only` sits after the
standing and timing checks. The reason is that a control whose divergence set
includes the positives says nothing about which part of the proposed text it
dropped.

**`retroactive-finding` is the exception.** It diverges on all five LC-C-006
vectors including the one with no finding at all, because it applies the
relabelling before it looks at whether a finding exists. That is the defect, and
the fixture declares the full set rather than narrowing it artificially.

## Vectors

Verdicts come from the settled vocabulary only: `valid`, `invalid`,
`not_established`, `not_yet_effective`, `suspended`, `restricted`. `verify.ts`
fails the run if any expected verdict falls outside it, in any field. Codes are
fixture-local detail and are **not** proposed conformance vocabulary.

All 19 distinct record timestamps are RFC 3339 with millisecond precision and a
literal `Z`, asserted by the run, because the harness uses lexicographic string
comparison as a stand-in for chronological comparison and that holds only for
that exact shape.

The full table is `vectors.json`, one object per vector with its records,
expected result, SDK probes and declared control divergences. The distribution:

| Case | Vectors | Positive | Negative |
|---|---|---|---|
| LC-C-002 | 9 | 4 | 5 |
| LC-C-005 | 5 | 3 | 2 |
| LC-C-006 | 5 | 3 | 2 |
| LC-C-011 | 7 | 1 | 6 |
| LC-C-012 | 7 | 3 | 4 |
| LC-C-016 | 7 | 4 | 3 |
| LC-C-018 | 5 | 1 | 4 |
| LC-C-020 | 9 | 3 | 6 |
| LC-C-022 | 6 | 5 | 1 |
| LC-C-029 | 6 | 2 | 4 |
| LC-C-031 | 5 | 2 | 3 |
| LC-H-001 | 7 | 3 | 4 |
| LC-H-002 | 7 | 1 | 6 |
| LC-H-003 | 7 | 2 | 5 |

Each case has at least one vector marked in its description as the **negative
control target**, the one a naive implementation passes wrongly. Those are
`LC-C-011-f`, `LC-C-018-e`, `LC-C-002-d`, `LC-C-005-a`, `LC-C-006-e`,
`LC-C-012-b`, `LC-C-020-f`, `LC-C-022-a`, `LC-C-029-b`, `LC-C-031-c`,
`LC-H-001-b`, `LC-H-002-c` and `LC-H-003-b`.

Four verdicts do real work beyond `valid` and `invalid`:

- **`not_established`** for silence, a missing standing reference, an unnamed
  contributor, an incomplete priority rule and an unresolved dispute. Never for a
  recorded refusal.
- **`suspended`** for the challenged party inside a contest window
  (`LC-C-002-b`) and for a target pending ratification (`LC-C-022-a`).
- **`not_yet_effective`** for a revival inside its rescission window
  (`LC-H-003-c`) and for a position whose trigger has not opened
  (`LC-C-020-h`).
- **`restricted`** for a joint objective after one party withdraws
  (`LC-C-012-d`) and for a joint grant with some but not all shares revoked
  (`LC-H-001-b`).

## Determinism

- **Seed.** One published prefix,
  `aps-conformance-suite:lifecycle-multiple-principals-and-conflict:`, recorded in
  `chain.json` as `seed_prefix`. Every Ed25519 private key is
  `sha256(prefix + label)` for a label published in `mint.py`, so the file
  carries no secret material and anyone can regenerate it.
- **Nonces** are supplied, not generated, which the Python SDK documents as the
  path that keeps issuance deterministic.
- **`now`** is the fixed string `2026-09-20T12:00:00.000Z`, and each vector's
  own evaluation instant is a fixed string. No runner reads the clock, the
  network or any file outside its own directory.
- **Regeneration.** `python3 mint.py` rewrites `chain.json` and
  `python3 generate.py` rewrites `vectors.json`. Both leave `git diff` empty.
  Verified in this session by running each twice and diffing. The tampered
  signature is derived arithmetically from a real one, so it regenerates too.
- **Canonical bytes.** Both runners recompute the RFC 8785 JCS canonical form of
  all 14 signed delegation records with the SDK's own canonicalizer and print the
  SHA-256 of each. The 14 digests are byte-identical between npm
  `canonicalizeJCS` at 7.1.0 and PyPI `canonicalize_jcs` at 4.1.0.
- **Checksums.** `CHECKSUMS.sha256` pins `chain.json` and `vectors.json`. The
  suite's `npm run test:digest-integrity` gate recomputes them.

RFC 8785 is the [JSON Canonicalization Scheme
(JCS)](https://www.rfc-editor.org/rfc/rfc8785.html), whose abstract states:
"This specification defines how to create a canonical representation of JSON
data by building on the strict serialization methods for JSON primitives defined
by ECMAScript, constraining JSON data to the Internet JSON (I-JSON) subset, and
by using deterministic property sorting."

## TypeScript

```
npx tsx fixtures/lifecycle-multiple-principals-and-conflict/verify.ts
```

Wired into `npm test` as
`verify:lifecycle-multiple-principals-and-conflict`. Exit 0 when the reference
matches all 92 vectors, every control diverges on exactly its declared set, and
every supported npm probe matches. Exit 1 on any mismatch, 2 on a malformed
fixture.

Observed in this session: reference 92/92, 14 controls each on their declared
set, 86/86 npm probes, 25 minted signatures verify and 1 tampered signature does
not.

## Python

```
/tmp/g2-venv/bin/python fixtures/lifecycle-multiple-principals-and-conflict/verify_python_sdk.py
```

Not in `npm test`, the same convention
`fixtures/ancestor-revocation-chain/validate.py` and
`fixtures/runtime-authority-denial-continuity/verify.py` already follow for a
Python side kept out of the Node-only CI gate.

This runner does not reimplement the fourteen deciders. It reads the same two
files and calls the PyPI SDK for every layer that SDK exposes, printing
`not_supported` with a reason for every layer it does not. Observed in this
session: 72/72 supported PyPI probes, and the same 25-verify plus 1-tampered
signature result as the TypeScript side.

## What the SDKs do not support

Enumerated by the runs, not written by hand, so these lines cannot go stale.

| Layer | npm 7.1.0 | PyPI 4.1.0 |
|---|---|---|
| chain state | `verifyAuthorityDelegationChain` | `verify_authority_delegation_chain` |
| Ed25519 signature over approval content | `verify` and `approvalSignContent` | `verify`, over the same content bytes |
| RFC 8785 canonical bytes | `canonicalizeJCS` | `canonicalize_jcs` |
| multi-class threshold (LC-C-011, LC-C-018, and the all-mode direction of LC-C-016) | `evaluateThreshold` | **absent.** `dir(agent_passport)` matches only the unrelated `ThresholdDispute` and `request_human_approval`, asserted by the run. |
| a threshold that differs by direction of the action | **absent** | **absent** |
| a contested seat with a default holder, deadline and reversion | **absent** | **absent** |
| priority between two independently valid authority sources | **absent.** `resolveSuccessor` walks one charter's `successionOrder` and cannot see a rival source. | **absent** |
| a status distinct from revoked for a grant void from issuance | **absent** | **absent** |
| a signed joint objective binding chains without pooling scope | **absent** | **absent** |
| a position created live by an eligibility rule | **absent** | **absent** |
| a state between an initiated suspension and its ratification | **absent** | **absent** |
| a per-source caveat layered on a delegated subset | **absent** | **absent** |
| a standing, cause-free override | **absent** | **absent** |
| a grant divisible by co-issuer share | **absent.** `AuthorityDelegationV1` has exactly one issuer per record, so the object is not representable. | **absent**, same reason |
| a named asymmetric default between contradictory instructions | **absent** | **absent** |
| a targeted revival gated by sequence and a rescission window | **absent** | **absent** |

Three observations about `evaluateThreshold`, all produced by this session's
runs and recorded per vector in `vectors.json`:

1. It supplies the conjunction across key classes and the eligibility check on
   each signing key, and it contributes zero for a signature that does not verify
   over the supplied content. `LC-C-018-d` is decided by the SDK on that basis.
2. `ApprovalSignature` has **no decision member**, so a dissent and an
   affirmation are the same object to it. On `LC-C-011-e` and `LC-C-018-c` it
   answers `met: true` where the reference boundary answers `invalid`.
3. `MultiClassThresholdPolicy` has a collection timeout on the request but **no
   per-signature freshness bound**. On `LC-C-011-d` it answers `met: true` where
   the reference boundary answers `not_established`.

Items 2 and 3 are not SDK defects. They are places where the proposed text asks
for something the record shape does not carry, and they are recorded below.

## Verification split

One entry per verification claim, in the form
`layer / claim; runner; Mode; authorship; implementation`, per `CONTRIBUTING.md`.

- **Chain state / claim: the 10 chains verify as each `chain_state` probe
  records, including `TAINTED` reading `invalid`/`REVOKED@1` under a revoked
  middle record and `SHARE_A` reading `invalid`/`REVOKED@0` under its own**;
  runner: the lab, via
  `fixtures/lifecycle-multiple-principals-and-conflict/verify.ts`; Mode A;
  author-produced; implementation: `agent-passport-system` 7.1.0 (npm), 72/72
  chain probes. Authorship relationship preventing an independent label: the lab
  authored the vectors and the claim inputs, and the implementation is a
  reference SDK from the same project.
- **Chain state / same claim, recomputed by the Python reference SDK**; runner:
  the lab, via `verify_python_sdk.py`; Mode B; author-produced; implementation:
  `agent-passport-system` 4.1.0 (PyPI), 72/72 probes. Authorship relationship: as
  above. The two SDKs are separate implementations and the Python run supplies
  the substantive recomputation, but both are reference SDKs of the same project
  and the lab authored the vectors, so the record is not independent.
- **Approval signature authenticity / claim: 25 minted signatures verify under
  the key their actor is registered with, and the 1 tampered signature does
  not**; runner: the lab, via `verify.ts`; Mode A; author-produced;
  implementation: `verify` and `approvalSignContent` from `agent-passport-system`
  7.1.0 (npm), 26/26.
- **Approval signature authenticity / same claim, recomputed by the Python
  reference SDK**; runner: the lab, via `verify_python_sdk.py`; Mode B;
  author-produced; implementation: `verify` from `agent-passport-system` 4.1.0
  (PyPI), 26/26. Both SDKs produce byte-identical Ed25519 signatures over the
  same content.
- **Multi-class threshold / claim: `evaluateThreshold` answers `met` and the set
  of unsatisfied key classes as each gate vector records, over the minted
  signatures that vector names**; runner: the lab, via `verify.ts`; Mode A;
  author-produced; implementation: `agent-passport-system` 7.1.0 (npm), 14/14
  probes. Authorship relationship: as above, and the key-class requirements and
  eligible-key sets are the fixture's inputs rather than the SDK's.
- **RFC 8785 JCS canonical digest of the 14 signed delegation records / claim:
  the 14 SHA-256 digests are identical across both canonicalizers**; runner: the
  lab; Mode B; author-produced; implementation: `canonicalizeJCS` (npm 7.1.0)
  and `canonicalize_jcs` (PyPI 4.1.0), recomputed independently in each runner,
  14/14 identical.
- **Reference boundary verdicts, 92 vectors / claim: the verdict, code and
  per-case assertions each vector records**; runner: the lab, via `verify.ts`;
  Mode A; author-produced; implementation: `harness.ts`, which is this fixture
  rather than any implementation under test, so no independent classification is
  possible for this layer, 92/92.
- **Negative control divergence sets, 14 controls / claim: each control diverges
  on exactly the vectors it declares and on no others**; runner: the lab, via
  `verify.ts`; Mode A; author-produced; implementation: `harness.ts`, as above,
  14/14 controls over 99 control runs.
- **Absence of a PyPI multi-class threshold or charter API / claim: no such name
  exists at 4.1.0**; runner: the lab, via `verify_python_sdk.py`; Mode A;
  author-produced (author of the survey); implementation: `dir(agent_passport)`
  enumerated in the run and compared against the fixture's expected-absent list,
  so a later release that adds one fails the run.
- **Timestamp shape / claim: all 19 distinct record timestamps are RFC 3339 with
  millisecond precision and a literal `Z`, so the harness's string comparison is
  a chronological comparison**; runner: the lab, via `verify.ts`; Mode A;
  author-produced; implementation: `verify.ts`, 19/19.
- **Chain and gate minting determinism / claim: `mint.py` re-run reproduces
  `chain.json` byte for byte**; runner: the lab; Mode A; author-produced (author
  of the generator); implementation: `mint.py` against the committed
  `chain.json`, empty diff.
- **Vector generation determinism / claim: `generate.py` re-run reproduces
  `vectors.json` byte for byte**; runner: the lab; Mode A; author-produced;
  implementation: `generate.py` against the committed `vectors.json`, empty diff.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## What a pass establishes

For the exact SDK revisions run, a pass establishes that on the reference
boundary:

- a concurrence gate refuses on one authorized chain alone, refuses when two
  actors in one role affirm and the other role is silent, refuses when a more
  senior principal affirms in its place, and refuses when a confirmation's
  declared role differs from its actor's registered role
- a recorded refusal gives `invalid` and silence gives `not_established`, and the
  two are never collapsed
- an all-must-affirm role set of four blocks on one absent role, on one
  objecting role, on one role whose signature does not verify, and on a single
  lead authorizer's sign-off with no per-role record
- origination and continuation need both principals while cancellation and
  restriction need one, in both directions between the two principals, and a
  co-principal's contrary affirmation does not block a stop
- inside a contest window the default holder is `valid` and the challenged party
  is `suspended`, and past the deadline without a supermajority recorded **by**
  the deadline the seat reverts to the challenged party, under four separate ways
  of falling short (no votes, all votes late, one class short, one vote
  ineligible)
- two valid sources naming different holders leave the question
  `not_established` with no priority rule, resolve deterministically with one,
  resolve the same way whichever order they were presented in, and stay
  `not_established` under a rule that does not order every presented source
- a void-from-issuance finding makes the dependent chain `invalid` under a code
  that is not `REVOKED`, with no revocation record anywhere, leaves the earlier
  receipts byte-identical, and does nothing at all without a followable standing
  reference
- a signed joint objective binds its parties without widening any chain, so an
  action needing another party's grant is `invalid` under it, and one party's
  withdrawal leaves the objective `restricted` and the other party's own actions
  `valid`
- an ad hoc position's first holder is the first eligible claimant even when an
  ineligible actor claimed earlier, moves only through an accept-and-acknowledge
  record, and on the trigger closing is `invalid` with no holder and no reversion
- a relief pending ratification leaves the target `suspended`, becomes `invalid`
  only from the ratification instant, returns the target to `valid` on denial with
  the action characterised as provisional throughout and no record claiming a
  reversed revocation, and stays `suspended` when the ratifier has no standing
- the same action inside the same coalition subset is `invalid` under the
  contributor whose caveat forbids it and `valid` under the contributor whose
  caveat does not
- a standing override makes the delegate's action `invalid` with no revocation
  record and no cause required, and does nothing when recorded by a party the
  standing record does not name
- one co-issuer's revocation leaves the other co-issuer's share `valid` and the
  joint grant `restricted`, reaches only that issuer's share even when it names
  the whole grant, and reaches nothing at all from a non-contributor
- a stop from any one required signer controls over a contradictory pay from a
  co-signer whichever was recorded first, and a stop from outside the signer set
  leaves the item `not_established` rather than paid
- a revival is `invalid` when made after the termination even with the later
  timestamp, `not_yet_effective` inside its window, `invalid` on a rescission
  inside the window, and `valid` with the rescission `not_established` on one
  outside it, with the window end taken as the later of the termination and the
  filing plus the window
- all 14 signed records canonicalize identically under both SDKs' RFC 8785
  implementations, and 25 minted signatures verify under both while 1 tampered
  one verifies under neither
- the fourteen declared defective boundaries diverge on exactly the vectors the
  fixture predicts

## Does not claim

- That draft-pidlisnyi-aps-03 requires any of this. It does not. Every vector is
  `candidate_against_proposed`.
- That a legal doctrine applies to AI agents. The five quoted sources are sources
  of cases. None mentions AI agents, and this README makes no claim at all about
  the nine cases whose sources were not fetched here.
- That the reference boundary is the right design. It is one reading of the
  proposed text, and where the text is silent the reading is recorded below
  rather than presented as settled.
- That `evaluateThreshold` is defective. It computes a multi-class conjunction
  correctly. The gaps are in what `ApprovalSignature` carries, not in the
  arithmetic.
- That the fourteen codes and the concept names are conformance vocabulary. They
  are fixture-local. Failure-class names are decided by the maintainer, per
  `CONTRIBUTING.md`.
- That any run here is independent. Every record in the split is
  `author-produced` and says why.
- That LC-C-009 has no question worth testing. It has one, and
  `fixtures/activation-not-established` already tests it. See the note at the
  top.
- That LC-C-031's or LC-C-029's `CASES.md` sources hold up. Neither was fetched
  here, and the lab's own review notes flag LC-C-031's as needing a primary
  source. The record-level question is all these vectors test.

## Where the proposed text was too vague to test

Fourteen findings, recorded rather than resolved. The first is the family's
central one.

1. **Four of the six settled verdicts have no SDK representation.** Both SDKs'
   chain verifier returns `valid`, `invalid` or `indeterminate`.
   `not_established`, `not_yet_effective`, `suspended` and `restricted` exist
   only in this fixture's boundary, and a `resolveRevocation` answer of
   `"suspended"` becomes `indeterminate` under `REVOCATION_UNKNOWN` rather than a
   suspended state. Every vector in this family whose verdict is one of those
   four is therefore decided by `harness.ts` and not by any implementation under
   test, and the Verification split says so.
2. **Whether an unmet gate is `invalid` or `not_established`.** The **Approval**
   concept says an approval "is an input to authorization, with its own scope,
   expiry and use count", and says nothing about what an unmet requirement
   returns. `evaluateThreshold` answers `met: false` with no verdict name. This
   fixture chose `not_established` for silence and `invalid` for a recorded
   refusal, on the wording rule that missing evidence is not falsity. That choice
   is the fixture's.
3. **A refusal has no record shape.** `ApprovalSignature` has no decision
   member, and the proposed text names approval and withdrawal before dispatch
   but not a standing objection. So `LC-C-011-e` and `LC-C-018-c` model dissent
   with a fixture-local `decision` field, and the SDK answers `met: true` on
   both.
4. **Concurrence freshness has no bound.** `CASES.md` LC-C-011 requires both
   concurrences "present and fresh at the same moment" and names no bound. This
   fixture supplies 3600 seconds as a fixture parameter. Where the bound should
   come from, and whether it belongs to the gate, the approval or the verifier's
   trust policy, is not addressed.
5. **The direction names are the fixture's.** LC-C-016 distinguishes
   origination, continuation, cancellation and restriction. The proposed text has
   no direction axis at all, so those four names, and the decision that
   continuation shares origination's threshold, are inventions of this fixture.
6. **Who declares a contest's default holder.** LC-C-002 says a verifier needs a
   default holder for the contested window and does not say who may declare one,
   what happens when two records declare different ones, or what happens when the
   declared default holder is itself a party to the dispute. This fixture
   requires it in the contest record and returns `not_established` when absent.
7. **Void from issuance says nothing about effects already taken.** LC-C-006
   states outright that what happens to orders already executed is "a separate
   question the finding itself does not answer". This fixture asserts only that
   the earlier receipts are byte-identical after the finding. Whether those
   effects stand is untested, and it connects to `OPEN-QUESTIONS.md` "Work in
   flight".
8. **What makes a source priority rule authoritative.** LC-C-005 asks for "an
   explicit, checkable priority rule" without saying who issues it or how a
   verifier knows to trust it. This fixture takes it as a record in the set, which
   sidesteps the question rather than answering it. The **Verifier trust policy**
   concept is the nearest the model comes.
9. **`restricted` has no definition.** **L8** names a restricted state that "does
   not have to pause descendants" and does not say what a restricted grant
   authorizes. This fixture uses `restricted` for a joint objective after one
   withdrawal and for a joint grant with some shares reached, and decides actions
   from what survives. That is a reading, not the text.
10. **A one-party joint objective.** LC-C-012 says any party can withdraw
    "without invalidating the others" and does not say what becomes of an
    objective with one party left. This fixture returns `invalid` once fewer than
    two parties remain bound.
11. **An ad hoc position's dissolution and work in flight.** LC-C-020 says the
    position "should dissolve entirely, not revert to anyone". It says nothing
    about an action the holder had already authorized when the trigger closed.
    Untested here, and the same gap as `OPEN-QUESTIONS.md` "Work in flight".
12. **What a denied ratification leaves behind.** LC-C-022 requires the record to
    characterise the action as provisional throughout and does not say whether the
    target returns to `valid` or needs reaffirmation. This fixture returns `valid`
    from the denial instant. `OPEN-QUESTIONS.md` "Release from suspension" is the
    adjacent open question, and it is open.
13. **Whether a standing override ends the grant or only its exercise.**
    LC-C-031 says only the master's authority "was ever real at the root". This
    fixture returns `invalid` for the delegate's action and leaves the delegation
    record untouched, so whether the grant itself is ended, suspended or merely
    unexercisable is not decided by the text or by this fixture.
14. **The rescission window's boundary instant.** 11 U.S.C. §524(c) as quoted
    says "whichever occurs later" and does not settle whether the last instant is
    inside the window. The proposed text says nothing. This fixture treats the end
    as inclusive, so an evaluation exactly at the end is `not_yet_effective` and a
    rescission exactly at the end rescinds. Either convention would satisfy the
    text.

## Provenance

Built by the lab in one session against `CASES.md` v0.2 at commit `2bf5c7e`
and `AUTHORITY-LIFECYCLE.md` at `7796e22` or later. Both commits are reachable
from the public default branch of that repository. `chain.json` minted with PyPI `agent-passport-system` 4.1.0.
`vectors.json` generated by `generate.py`. Verified with npm
`agent-passport-system` 7.1.0 and PyPI 4.1.0. No network access in any runner.

Related fixtures, not duplicated here: on `main`,
`ancestor-revocation-chain` (L1), `sponsor-handover` (L2 and L4),
`single-chain-selection` (L5), `revocation-resolution-forward-compat` (L7),
`approval-single-use` and `cached-authorization-revocation` (L6),
`key-rotation-historical` (L9). From the lab's wave 2,
`chain-selection-no-union` (L5 and L11, the scope-union half of the question
LC-C-011 and LC-C-012 approach from the other side),
`activation-not-established` (which covers LC-C-009),
`authority-epoch-rollback`, `capability-binding-drift`,
`conflicting-status-sources` and `lifecycle-purpose-exhaustion`.
