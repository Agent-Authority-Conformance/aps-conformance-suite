# arap-reevaluation-context

Candidate cases against a proposed change to the AuthZEN Access Request
Approval Profile (ARAP): what Context a PEP sends when it re-evaluates after
approval. The change is openid/authzen pull request #745, a draft that waits
on the working group's decision on issue #663.

Every case here is a candidate against that proposed text. None of them is a
conformance claim about any AuthZEN implementation or about the Agent Passport
System. If the pull request changes or closes, the cases go with it. These
cases are kept apart from `fixtures/arap-binding`, which is pinned to the
earlier draft (#658 at `2e9412c`).

## Source

| field | value |
|---|---|
| repository | `openid/authzen` |
| pull request | #745 (draft, author mcguinness) |
| head read | `9bd238a0c7c1a97e1c812de56c31755a4cdf5b12` |
| applied locally to | `main` at `4deba63afa25e8a1d99f888a85cb64951ac83e37`, a clean local trial merge, not an upstream merge |
| file | `profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md` |
| file at the head, SHA-256 | `edd6316c922c5c6f4acef6e663bde8016d795602130202c317d55297df46e4ee` |
| file with #745 applied locally, SHA-256 | `f4a51e500faaf90bab4329851a9f71e46b17ad93dc65805fd7a9ff15f92f02a6` |
| status | **proposed, not merged** |

Line numbers cite the file with #745 applied locally to `main`. The pull request branches from an older
`main`, and `main` has since changed the re-evaluation example
(`83147c0`, which carries `project` again). The locally applied file holds
both changes. The text is paraphrased, not quoted at length. A case that stops
matching the source after an edit is a stale case, not a finding.

The rules under test:

- 822 to 824: the PEP builds re-evaluation Context by the rules of an
  ordinary Access Evaluation, keeps the approval unchanged, and presenting an
  approval must not remove members or substitute an approval-only object.
  Changes the ordinary rules make are allowed.
- 826: inputs the rules need must stay reachable. A PEP that cannot reach one
  cannot build the request and stops.
- 976 to 982: exact-match approval scope, and the PDP must not treat a bound
  member absent from the request as matching.

## What runs

The PDP side is the reference approval verifier from
`fixtures/arap-binding/harness.ts`, unchanged, in the lookup topology the
re-evaluation example uses (`approval.id` resolved from trusted state). This
family adds a minimal PEP model in `harness.ts`. A PEP has a list of ordinary
Context rules, each naming a member, the input it comes from, and an optional
condition, and the inputs it can reach at that moment. None of this is an
AuthZEN implementation. Nothing reads wall time.

The pull request's description proposes a test for 822 to 824: evaluate the
same operation without an approval and compare member sets. Each case runs
that comparison too.

| case | PEP | what happens | expected |
|---|---|---|---|
| R1 | ordinary rules | bound `project` kept, `time` refreshed | `approval_applies`, member sets equal |
| R2 | approval-only | the shape #663 reported, `project` dropped | `out_of_scope`, member sets differ |
| R3 | ordinary rules | the task's `project` changed | `out_of_scope`, member sets equal |
| R4 | ordinary rules | a later re-evaluation, `time` obtained fresh | `approval_applies` |
| R5 | ordinary rules | the input for `project` is unreachable | the PEP stops, nothing sent |
| R5b | approval-only | same unreachable input | a request is sent anyway, `out_of_scope` |
| R6 | ordinary rules | a conditional member the rules now omit, not bound | `approval_applies` |
| R7 | ordinary rules | the same conditional member, bound | `out_of_scope` |

R6 and R7 exercise the reason the pull request puts the obligation on the
construction path rather than on an inventory of the original members. An
ordinary rule may include a member only while a condition holds. Omitting it
is allowed, and when that member was bound the approval cannot apply.

## Negative controls

Each must fail exactly its declared set, checked in both directions.

- **present-only PDP**: the reference verifier with one change, a bound member
  absent from the request is skipped instead of compared. 982 rules this out.
  It fails R2, R5b and R7, each of which reaches the PDP with a bound member
  missing.
- **approval-only PEP**: swapped into every ordinary-rules case. It fails all
  six. In R3 and R7 the PDP returns `out_of_scope` either way, so the PDP
  outcome alone would not catch it. The member-set comparison does.
- **PEPs that drop or alter the approval**: four of them, one leaving the
  approval out, one changing its id, one rewriting `approved_until` in a copy,
  and one rewriting `approved_at` in place on the object it was handed. 822
  says the approval goes in unchanged. The runner keeps a pristine copy of the
  approval, compares the emitted approval with it, and passes the emitted
  approval to the PDP. Each fails the five ordinary-rules cases that send a
  request. Here the PDP resolves the approval by id from trusted state, so only
  the unchanged-approval check catches the two timestamp rewrites.
- **alternating PEP**: its first request carries a member no ordinary rule
  produces, and its later requests are clean. The member is unbound, so the
  PDP outcome does not change. It fails the same five cases because the runner
  calls the PEP once and runs the member-set test on the request it emitted.

Each run works on its own copies of the case's rules, inputs, approval and
ledger record. The ordinary construction the member-set test compares against
is built from those copies before the PEP runs.

## Reproduce

    python3 fixtures/arap-reevaluation-context/generate.py
    npx tsx fixtures/arap-reevaluation-context/verify.ts

`generate.py` writes `vectors.json` deterministically. `verify.ts` exits 0
when every case matches and each control fails exactly its declared set.
