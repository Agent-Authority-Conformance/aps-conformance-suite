# runtime-authority-denial-continuity

Candidate cases for two runtime-authority properties discussed in an open GitHub issue.
Nothing here is merged specification text, and nothing here is a conformance claim about
APS, MCP or any other protocol. The harness is protocol neutral. It models a generic
enforcement point in front of a generic resource store, with no APS types anywhere in it.

## Status

Candidate against discussion text in open issue #71. RavindraAnnam has since opened
[the runtime-authority proposal in #86](https://github.com/OWASP/www-project-agentic-skills-top-10/pull/86).
This fixture remains an input to that discussion. It has not been validated against
#86 and does not define its properties. If the proposed wording, boundary or identity
model changes, this fixture needs review against that text.

## Source

| field | value |
|---|---|
| repository | `OWASP/www-project-agentic-skills-top-10` |
| issue | #71 |
| status | open discussion, no merged specification |

Comments this fixture is built from, quoted for the exact claim each supports rather than
paraphrased wholesale:

| comment | author | what it supports here |
|---|---|---|
| [#issuecomment-5593939386](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5593939386) | RavindraAnnam | AUTHORITY_DENIED terminates the current authority path, suppresses automatic retry and fallback, and requires reauthorization before another path can attempt the same effect |
| [#issuecomment-5610341311](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5610341311) | RavindraAnnam | deny is an authorization-state transition, with no recovery through retry, fallback, alternate-tool selection, delegation or equivalent paths without a new authorization decision |
| [#issuecomment-5610348204](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5610348204) | RavindraAnnam | protected-effect identity is resource plus security-relevant state transition plus authorization domain, not the literal tool name, with the `delete_record(id=42)` versus `overwrite_record(id=42, empty)` example this fixture reuses directly |
| [#issuecomment-5595612289](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5595612289) | m13v | an effect decomposed into several individually legitimate writes never canonicalizes to the denied effect, so each hop clears a fresh authority decision, and a conformance case needs an effect that survives decomposition |
| [#issuecomment-5624800343](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5624800343) | m13v | the effect-equivalence oracle that decides two paths are the same effect is itself the bypass surface, and it is exactly the part left implementation neutral |
| [#issuecomment-5634265554](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5634265554) | RavindraAnnam | a denied protected effect remains denied until an explicit reauthorization bound to that denied effect and its authorization context, and an unrelated role change, token refresh or delegated grant must not satisfy that transition |
| [#issuecomment-5742545996](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5742545996) | RavindraAnnam | announcement of a separate compact conformance draft to follow the thread, referenced above under Status |

The full thread was read past these seven comments before this fixture was written, so
that nothing here contradicts a later turn in the discussion. Everything past
`5742545996`, if any, is a later reply and is not represented here.

## The two properties

**Property A, denial continuity.** After a deny on a protected effect, a retry, a
fallback, an alternate tool or a delegated call reaching the same protected effect under
the same authorization state is denied. It becomes eligible again only after a
reauthorization bound to that same effect and context changes the state. An unrelated
authorization-state change, such as a reauthorization of a different effect, must not
unlock it.

**Property B, decomposition boundary.** After a deny on a protected effect, a sequence of
individually permitted operations whose composition produces that same effect is denied
only when the implementation can identify the composed effect. An implementation that
cannot identify composed effects does not establish this property either way, and a
benign sequence of the same operation types that never composes the denied effect must
still be permitted, so the case also catches an implementation that over-blocks
decomposed writes on sight.

## Harness model

`harness.ts` is a synthetic enforcement point in front of a small in-memory resource
store. Nothing in it is an APS type, an APS receipt or an APS decision. It has:

- **Protected-effect identity.** `resource + transition + domain`, following comment
  5610348204 directly. `delete_record(id=42)` and `overwrite_record(id=42, empty)` both
  produce `{resource: "record:42", transition: "unavailable", domain: "records"}`.
- **A denial ledger** keyed by that identity plus context, holding a record for every
  active deny. A policy's `ledgerKey` function decides how tool identity does or does not
  fold into that key. This is the harness's one modeling choice for what counts as "the
  same path," and it is exactly what separates the reference gate from `fresh-path-control`.
- **An authorization state with an explicit generation**, advanced only by an explicit
  `reauthorize` call bound to one effect and one context. Nothing else in this harness
  advances it. There is no ambient credential refresh or unrelated grant event in these
  vectors, because comment 5634265554's point is that such events must not matter even
  when they exist, and the cleanest way to show that a mechanism is inert is to give it
  nothing to react to.
- **A resource store** with `content`, `flags`, `linked` and `available` fields per
  record, mutated by both direct tools (`delete_record`, `overwrite_record`) and
  decomposed writes (`set_content`, `set_flag`, `unlink_index`).
- **A delegate path**, modeled as an attempt whose tool identity is `delegate:<agent-id>`
  rather than a separate simulated agent. It reaches the same protected effect through a
  different named path, which is what these vectors need from it.
- **A composed-effect oracle**, used only by policies that declare
  `hasComposedEffectIdentification`. It recognizes one pattern. Content emptied, flagged
  `quarantined`, and unlinked from the index together read as the same `unavailable`
  effect a direct delete produces. This is one implementation's effect-interpretation
  choice, not a general algorithm, and the README's "Does not claim" section says so
  again below.

## Cases

Eight cases in `vectors.json`, six for Property A and two for Property B.

| case | property | covers |
|---|---|---|
| `A1-control-allowed-effect` | A | positive control, an unprotected effect proceeds |
| `A2-deny-then-identical-retry` | A | literal repeat of the denied tool and effect |
| `A3-deny-then-alias-tool` | A | `overwrite_record` after `delete_record` was denied, same effect |
| `A4-deny-then-delegate` | A | a delegated path reaching the same effect |
| `A5-reauthorization-bound-to-effect-permits` | A | explicit reauthorization of the denied effect and context lifts the deny |
| `A6-reauthorization-of-different-effect-does-not-unlock` | A | reauthorization of an unrelated effect leaves the original deny in place |
| `B1-decomposition-composes-denied-effect` | B | three individually permitted writes complete the denied effect |
| `B2-benign-sequence-does-not-compose` | B | the same three operation types applied so the denied effect is never completed |

Every A2 through B2 case begins with an explicit `deny` event. This harness does not model
a re-derivable policy underneath that deny. It is injected as ground truth, the same way
the cached-authorization-revocation family's `revoke_grant` event is injected rather than
derived, because what these two properties test is what happens after the deny, not why
the deny happened.

## Policies run by the harness

Three policies differ along two independent axes. One is how the denial ledger keys a
request, either canonical effect identity or that identity scoped additionally by tool.
The other is whether a composed-effect oracle is present.

- **reference-gate.** Canonical keying, oracle present. Runs against all nine cases and
  must match every one.
- **fresh-path-control (N1).** Tool-scoped keying, oracle present. Runs only against
  Property A's seven cases. Its one flaw is that it treats a different tool or a delegated
  path as an unrelated request, so it must fail exactly `A3-deny-then-alias-tool` and
  `A4-deny-then-delegate`, and pass the rest.
- **per-write-control (N2).** Canonical keying, oracle absent. Runs only against Property
  B's two cases. Its one flaw is evaluating each decomposed write only against its own
  narrow identity, never a composed one, so it must fail exactly
  `B1-decomposition-composes-denied-effect`, and pass `B2-benign-sequence-does-not-compose`.

N1 is not run against Property B, and N2 is not run against Property A. Each negative
control isolates one axis of the model. Running N1 against the decomposition cases would
mix its path-scoping defect into a property the fixture wants to attribute to the
composed-effect axis alone, and the reverse for N2. Both negative controls are still run
against every case on their assigned property, not only the ones predicted to fail, so an
undeclared failure or a declared failure that quietly starts passing would be visible in
either runner's output.

## Results

Both runners produced the same table.

| policy | cases run | matched | declared fail set | observed fail set |
|---|---|---|---|---|
| reference-gate | 9 (A + B) | 9/9 | none | none |
| fresh-path-control (N1) | 7 (A only) | 5/7 | `A3-deny-then-alias-tool`, `A4-deny-then-delegate` | same |
| per-write-control (N2) | 2 (B only) | 1/2 | `B1-decomposition-composes-denied-effect` | same |

Both runners also agree on final-state outcomes, including the expected mismatches
for A3/A4 under N1 and B1 under N2.

## Running

From the repository root, TypeScript:

    npm ci --include=dev
    npm run verify:runtime-authority-denial-continuity

It also runs in `npm test`, followed by the direct N1 harness regression
(`npm run test:runtime-authority-n1`). The regression checks two live tool-keyed
denials and rejected reauthorization without changing the candidate vector schema.
Expected final line from the fixture verifier:

    PASSED: reference-gate matched every case, N1 and N2 each failed exactly their declared set

Python, independently written from this README and `vectors.json`, not by porting
`harness.ts`, and with no third-party dependency:

    python3 fixtures/runtime-authority-denial-continuity/verify.py

This is a manual run, not part of `npm test`. The rest of this suite's `npm test` stays
Node only and runs on the Windows job, and this fixture follows that existing convention
rather than adding a Python dependency to the hermetic gate. It produces the same final
line, with `(python)` appended to the case count on its first line.

Both runners were run for this fixture and matched on every vector, every policy, and
every `final_state` check. Neither is a verdict on the other's language. Agreement between
two independently written implementations is what the family is for.

## What a pass establishes

For this reference model, at this revision, a pass establishes that:

- canonicalizing protected-effect identity across tool names and a delegated path is
  sufficient to make Property A hold in this model, and that a policy that instead scopes
  its ledger by tool name predictably fails exactly the aliasing and delegation cases
- an explicit reauthorization bound to the same effect and context is what this model
  needs to lift a deny, and that a reauthorization of an unrelated effect does not
- Property B holds only when the implementation declares and exercises a composed-effect
  oracle, and that a policy without one predictably allows a composed bypass while still
  correctly permitting a benign sequence of the same operation types

## What this does not claim

- **It does not solve semantic effect interpretation.** Property B's outcome depends
  entirely on the implementation's own effect oracle. Comment 5624800343 (in the Source
  table above) names that oracle as the actual bypass surface, and a later comment in the
  same thread,
  [#issuecomment-5679885267](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5679885267),
  restates it as an enforcement dependency rather than something the property itself
  resolves. This fixture's oracle recognizes one pattern over one toy resource model. It is
  not a claim about how to detect composed effects in general, and a real implementation's
  oracle can be wrong in ways this fixture cannot see.
- **A B1 failure is not a finding against a settled rule.** An implementation with no
  composed-effect identification fails B1 here. That records the capability as absent. It
  does not show the implementation breaks an agreed requirement, because #71 left effect
  interpretation open.
- **It does not test reservation generations, commit exclusivity, concurrency or
  partition behavior.** The same thread develops a second, separate cluster of properties
  around atomic authority conservation, reservation commit and reclaim exclusivity, and
  fail-closed behavior when current authority state cannot be established, running from
  comment 5679885267 above through
  [#issuecomment-5707273986](https://github.com/OWASP/www-project-agentic-skills-top-10/issues/71#issuecomment-5707273986).
  Those properties are not exercised here. This fixture's `generation` field exists only to
  make one denial record's authorization state legible, and no case in this family depends
  on concurrent or partitioned execution.
- **It is not RavindraAnnam's announced conformance draft**, and it does not define that
  draft's properties, wording or boundary. It is one reading of the discussion text that
  preceded it, produced independently of that draft's author.
- **It is author-produced, on one machine.** The vectors, the TypeScript harness and the
  Python runner were all written in this lab. Neither implementation was reviewed by a
  participant in the source thread, and no independent third party has run either of them.
  Agreement between the two runners here is agreement between two implementations from the
  same author, not independent corroboration.

## Boundary

A run of this family does not establish:

- anything about a real agent runtime, a real MCP server, a real tool-calling framework or
  any protocol. No protocol is spoken and no network call is made.
- that this harness's protected-effect identity model, `resource + transition + domain`,
  is the one a merged specification will adopt. It is the model comment 5610348204
  proposes, read as this fixture's own working definition.
- that `delete_record` and `overwrite_record` reaching the same effect, or the specific
  three-operation decomposition in `B1`, are exhaustive or representative of how aliasing
  or decomposition looks in a real system. They are the smallest cases this fixture could
  construct that still exercise each property.
- that the issue's discussion text is correct, complete, or will be adopted in this form
  by the eventual conformance draft.
