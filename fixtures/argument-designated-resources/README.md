# argument-designated-resources: resources named inside invocation arguments

**Status: candidate against proposed text. This is not a draft-04 conformance case.**
Every vector in `vectors.json` carries `status: "candidate_against_proposed"` and names
the proposed text it tests. `verify.ts` and `verify.py` both refuse to run if any vector
loses that label or names proposed text the file does not define.

A call names its target. Many calls also name other resources inside their arguments:
the destination of a copy, the output path of an export, a list of replicas. If the
enforcement point checks only the target, or lets the authority of the service that runs
the tool stand in for the caller's, a caller can get the service to act on a resource the
caller holds no authority over. That is the confused deputy (Hardy, 1988).

Hardy's compiler had two sources of authority, and both were legitimate. It wrote its own
statistics file under its own license and wrote debugging output to a file its caller
named. The fault was using the first authority for the second job. This family keeps both.
A tool here may write its own fixed resources under its own declared credential, and every
resource operand the caller supplies, as the trusted tool contract declares it, must be
authorized by a credential the caller selected for that operand. A data argument that
merely holds a resource-shaped string needs no authority over the named resource (ADR-06,
ADR-06b).

## Route

This is an ordinary lab-authored fixture under `fixtures/`, wired into `npm test` and CI
like the other lab families. It is not a submission under `docs/CANDIDATES.md` and makes
no use of that route's review allowance. The label `candidate_against_proposed` describes
the maturity of the text the vectors test, as it does in
[`capability-binding-drift`](../capability-binding-drift/). The README inventory is built
from `fixtures/manifest.json` and the cross-stack registry, so this family does not appear
in it, and the inventory generator was not changed.

## What this tests, and against which text

### The proposed profile

This family states the text it tests itself. **It is proposed here. It is not specified in
draft-pidlisnyi-aps-04 or in `AUTHORITY-LIFECYCLE.md`.** It is the caller-supplied-resource
profile, revision 0.2:

> For this family's caller-supplied-resource profile, the boundary identifies every
> resource operand that the trusted tool contract says will be accessed, and the operation
> required on that operand. It authorizes each operand using authority explicitly selected
> for that operand in this invocation. It does not substitute ambient service credentials
> or other credentials held by the requester. Supplied arguments the contract does not
> classify are refused under this profile, and so is a call that omits an operand the
> contract requires. Any service-owned effect uses a separately declared authority source
> and cannot be redirected by that exception to a resource the caller selects.

Two more subrules make the credential cases and ADR-11 testable:

> Under this profile a credential is resolved against trusted state, must be held by the
> authenticated requester, and must chain to an issuer the trusted issuer records give
> standing over the resource. A delegated credential needs a delegable parent held by its
> issuer and may be equal to that parent but no wider.

> When a decision is presented, the boundary admits only the exact call the decision
> names, including its authority selections.

In `vectors.json` each sentence group is one key of `proposed_text`, and every vector lists
the keys it tests:

| key | subrule |
|---|---|
| `csr-operands` | every resource operand the contract declares, with its operation |
| `csr-selected-authority` | the credential selected for that operand, and no other |
| `csr-closed-arguments` | unclassified arguments and missing required operands are refused |
| `csr-service-effects` | service-owned effects use their declared credential and cannot be redirected |
| `csr-holder-bound-credentials` | trusted resolution, holder, issuer standing, delegation, attenuation |
| `csr-exact-call` | the decided call and nothing else |
| `target-binding` | the motivating concept below, for vectors about which thing a name designates |

Revision 0.1 of this family stated a universal rule: every designated resource is checked
against the requester's authority and never the service's. That rule refuses Hardy's
statistics write. It survives here only as the defective policy
`caller-authority-for-service-effects`, which refuses ADR-14.

### The concept it refines

The **Target binding** concept is stated twice, in nearly the same words, and attaches no
rule in either place.

In [`AUTHORITY-LIFECYCLE.md` at commit `5c1bf09`](https://github.com/aeoess/agent-authority-lifecycle/blob/5c1bf09ee29d517f2f19c9bb9212543a7c44b227/AUTHORITY-LIFECYCLE.md#authority-and-dependencies),
section **Lifecycle concepts are separate > Authority and dependencies**, at commit
`5c1bf09ee29d517f2f19c9bb9212543a7c44b227` (version 0.1.2-draft, the commit
`capability-binding-drift` cites). The quoted entry is unchanged at
`57eb7421e3437d8d5fc372225dc49a9176c281f4`, the head read for this family. The two files
differ elsewhere.

> Target binding. Which resource, counterparty or object the authority applies to.
> Continuity of a name does not by itself establish continuity of the thing named.

The same document marks the entry **proposed** at the pinned commit.

In [draft-pidlisnyi-aps-04](https://www.ietf.org/archive/id/draft-pidlisnyi-aps-04.txt),
section 8.1, Concepts, lines 3634 to 3636:

> Target binding Which resource, counterparty or object the authority applies to.
> Continuity of a name does not on its own establish continuity of the thing named.

Target binding says which resource authority applies to. It does not say that one
invocation can designate several resources, where they sit, which credential covers each,
or how a service's own effects are kept apart from the caller's. The profile above is this
family's proposal for that gap.

### What else draft-04 says

Quotes are from draft-04 (text file sha256
`6912754a92ae82790568ca2169b9b74ab0a24e6aef485b3f0366eb7d1f2a1eb3`), with that file's line
numbers. Line breaks and the draft's double spacing after a full stop are collapsed. The
words are unchanged.

Section 5.1, Action Reference Computation, lines 2433 to 2436, on the call's target:

> target is the exact resource, tool, or endpoint against which the action will be
> dispatched; a profile MUST define its target string construction.

In draft-03 this sentence was in section 4.1, which is where `capability-binding-drift`
places it. In draft-04 section 4.1 is Faceted Authority Attenuation.

Section 9.2, The Exact Call, lines 6237 to 6241:

> At the next authorization boundary the boundary MUST compare the call it is about to
> admit against the action the approval names, and MUST NOT admit a call whose action
> reference differs from it. An argument changed after the decision produces a different
> action reference, so the comparison catches it without any separate argument-level rule.

and lines 6252 to 6253:

> It does not establish that the arguments mean what the requesting agent intended them to
> mean.

### Why this is not a draft-04 case

draft-04 scopes the call's `target` (5.1), binds the exact call (9.2) and names Target
binding as a concept (8.1). It states no rule for a second resource named inside the
arguments, and 9.2 says in its own words that the comparison does not establish what the
arguments mean. A call can match its approval exactly, have a covered target, and still
designate an uncovered resource in an argument. ADR-11 and ADR-11b lean on 9.2, and they
are labelled against `csr-exact-call`, because the call reference they use is this
family's own and is an analogue of an APS action reference, not one.

## Harness model

`harness.ts` is a synthetic enforcement point in front of a synthetic tool registry and an
in-memory resource store. Nothing in it is an APS type, an APS receipt or an APS decision,
and no network call is made.

### Trusted inputs

These are assumptions of the model, and `vectors.json` repeats them under `assumptions`.

- **The requester** (`party:alice`) is an assumed authenticated identity. Nothing proves
  possession of a key.
- **Tool contracts are trusted and honest.** Each tool performs exactly the accesses its
  program lists below. A dishonest or stale contract is outside v0, and no vector probes
  one.
- **Credentials and issuer records are trusted fixture-side state.** Each presentation
  carries `trusted_state.credentials`. A call names credentials by identifier only, so a
  caller cannot edit a credential's holder, issuer or scope. An identifier that is not in
  trusted state is a harness input error, and no vector carries one.
- **Resolution is lexical and pinned.** The boundary and the tool resolve identifiers with
  the same function, and nothing changes between admission and execution.

### Parties and credentials

`issuer_records` says who may issue root credentials over what. `party:store-admin` owns
`res:/store` and `party:svc-tools` owns `res:/svc`. `party:svc-tools` is also the service
identity every tool runs as. `party:bob` holds some delegable credentials and delegates to
Alice in the delegation cases. `party:mallory` holds a credential in ADR-10b and issues one
without standing in ADR-10g.

A credential is `{id, holder, issuer, resource, operations, delegable, parent}`. There are
two toy rights, `read` and `write`, and they are disjoint. Write does not imply read.

Every presentation's trusted state includes the service baseline, `cred:svc-home` (read and
write over all of `res:/svc`, Hardy's home-files license) and `cred:svc-stats-write` (write
over `res:/svc/stats`). ADR-03 adds `cred:svc-r2-write`, held by the service and issued by
the store owner.

### Tools

| tool | target | operands and data | program |
|---|---|---|---|
| `copy` | `src` | `src` resource read, `dst` resource write, `label` data, optional | read src, write its content to dst |
| `copy_audited` | `src` | `src` resource read, `dst` resource write. Service effect: write `res:/svc/stats` under `cred:svc-stats-write` | read src, write dst, then write `copy <src> -> <dst>` to `res:/svc/stats` |
| `copy_with_capability` | `src` | `src` resource read, `dst` capability write | read src, write it to the capability's resource |
| `export` | `src` | `src` resource read, `options.output.path` resource write, `options.output.format` data | read src, write `<format>:<content>` to the path |
| `normalize` | `src` | `src` resource read, `dst` resource write | read src, write it upper-cased to dst |
| `overwrite` | `target` | `target` resource write, `content` data | write the content string to target |
| `replicate` | `src` | `src` resource read, `dsts[]` resource write | read src, write it to each element of dsts in index order |

Every operand is required. `label` is optional data, and the other data arguments are
required. `target` is the operand that plays the part of draft-04's `target`. Only the
`target-only` defective policy reads it.

### Calls

A call is `{tool, requester, arguments, authority}`. `authority` maps a concrete operand
path, such as `dst` or `dsts[1]`, to the identifier of the credential selected for it. A
capability operand carries its credential in the argument itself, as
`{"capability": "<id>"}`, and its designated resource is that credential's resource. Each
presentation may carry a decision, `{call, call_ref}`, and an `inject_failure` path.

### Store and trace

`initial_store` holds `res:/store/r1` = `alpha`, `res:/store/r2` = `beta`, `res:/store/r3`
= `gamma`, `res:/svc/bill` = `billing-records` and `res:/svc/stats` = `none`. Every
presentation runs against a fresh copy.

When the boundary admits a call, the tool runs and every access it performs is recorded as
`{operation, resource, path, authority, holder}`. `resource` is the resolved identifier,
`path` is the argument path or `service_effects[i]`, and `authority` is the credential the
boundary admitted for that path, or `null` if the policy never checked that operand. A
refused call does not run, and its trace is empty.

Execution stops at the first access that cannot complete: an injected failure, an operand
the tool cannot resolve, or a read of an absent resource. The execution is then
`partial`, with `stopped_at` and `cause`. Accesses already performed stay in the store and
in the trace. Nothing is rolled back. Under the reference only ADR-05c is partial, by
injection. The other two causes appear only under defective policies that admit malformed
calls.

## Evaluation, reference boundary

The stages run in this order and the first refusal ends the evaluation.

1. **B, binding.** If a decision is presented and the call's call reference differs from
   it, refuse `call_does_not_match_decision`.
2. **V, validation.** Walk the argument tree (see "Argument paths"). A key outside the key
   grammar is refused `argument_key_invalid`. A node whose path the contract does not
   declare and that is not a container on the way to a declared path is refused
   `argument_designation_unknown`. Then, in sorted pattern order, a required pattern that
   is absent is refused `argument_operand_missing`.
3. **E, enumeration.** Every declared resource or capability node is a designation, in walk
   order. Data nodes are not.
4. For each designation in walk order:
   - **R, resolution.** A resource operand must be a string with a canonical identifier,
     else `argument_resource_identifier_invalid`. A capability operand must be exactly
     `{"capability": "<id>"}`, else the same reason.
   - **A, selection.** The credential is `authority[path]` for a resource operand, or the
     referenced credential for a capability operand. No selection for a resource operand
     is refused `argument_authority_not_selected`.
   - **C, credential.** The holder must be the requester, else
     `authority_not_held_by_requester`. Then the chain, from the credential to its root:
     a root's issuer must own a subtree covering the root's resource in `issuer_records`,
     else `authority_issuer_without_standing`. A delegated credential's parent must be
     held by its issuer, else `authority_issuer_without_standing`, must be delegable, else
     `authority_issuer_cannot_delegate`, and must cover the child's resource and every
     child operation, else `authority_exceeds_issuer_authority`.
   - **K, coverage.** The credential must cover the resolved resource and include the
     operation, else `argument_resource_not_authorized` with `path`, `resource` and
     `operation`.
5. **F, service effects.** Each declared service effect is checked with its declared
   credential, held by the tool's service identity, through C and K. A failure is
   `service_effect_not_authorized`. No reference vector fails here.
6. Admit with `all_designations_authorized`, then run the tool.

Only the selected credential is evaluated for an operand. The reference never searches the
requester's other credentials and never consults a service credential for a caller
operand. Both runners check this by mutation. They give the service a credential over all
of `res:/store`, remove every service credential the contracts do not declare, and give the
requester unselected credentials over everything, and require every reference outcome to
stay the same in all three.

### Argument paths

An argument key must match `[a-z][a-z0-9_]*`. A path is the keys joined by `.` with `[i]`
for an array element, for example `options.output.path` and `dsts[1]`. Because no valid key
contains `.`, `[` or `]`, a path has one reading. A refused invalid key is named as its
parent path followed by the key in brackets and JSON quotes, for example
`["options.output.path"]` in ADR-04c.

A contract is a table keyed by pattern, and a call's `authority` is a table keyed by path.
Both are looked up by own key only. A key the grammar allows can still be the name of a
property an implementation's objects inherit. In JavaScript that is `constructor`, the only
`Object.prototype` name the grammar admits. An undeclared `constructor` argument is
refused as unknown like any other (ADR-07e). `toString` is inherited too, but its capital
letter fails the grammar, so it is refused as an invalid key before any lookup (ADR-07f).

A contract pattern uses `[]` for any index, so `dsts[]` covers `dsts[0]` and `dsts[1]`.
The walk is depth first, with object keys in ascending code-unit order and array elements
in index order. A declared node is not entered, whatever its value. A container on the way
to a declared path is entered only if it has the type the contract implies. Otherwise the
operand beneath it counts as absent. An empty container at an undeclared path is still a
node and is refused (ADR-07b).

ADR-07 is a chosen closed-argument policy. Some APIs safely ignore extension data, and an
unknown field does not prove that a resource is designated. This profile refuses it
because the boundary cannot know what an unclassified argument does.

### Identifier grammar

These rules are a toy. They test lexical resolution only. Symbolic links, redirects, DNS
rebinding, mount changes and object replacement are not modelled, and nothing here says how
a real filesystem or URI scheme resolves names.

- **Namespace.** One scheme, `res:`, followed by `/` and one or more segments.
- **Case.** The scheme's four characters are ASCII case-insensitive. Each segment is
  ASCII-lowercased, A to Z only. This is a rule of this namespace, not a claim about URIs
  or filesystems in general.
- **Segments.** After lowercasing, a segment must match `[a-z0-9_-]+`. Nothing is
  percent-decoded and no Unicode normalization is applied, so `%` or any non-ASCII
  character makes the identifier malformed.
- **Traversal.** An empty segment or `.` is dropped. `..` removes the previous segment and
  makes the identifier malformed if there is none.
- **Alias table.** Empty. Two spellings name the same resource only through the case rule
  and the traversal rule.
- **Malformed.** A string that fails any rule, a string that ends with no segments, and
  any non-string value have no canonical identifier and are refused
  `argument_resource_identifier_invalid`.
- **Canonical form.** `res:/` followed by the segments joined by `/`.

So `RES:/Store/R2` resolves to `res:/store/r2`, `res:/store/r1/../r2` resolves to
`res:/store/r2`, and `res:/store/../../r2` has none.

**Covering.** A credential over E covers R when R equals E or begins with E followed by
`/`. A credential over `res:/store/r1` therefore covers `res:/store/r1/notes`. Subtree
covering is a choice of this family. Under exact-match covering, ADR-08's raw spelling
would be refused with or without resolution, and `no-canonicalization` would not admit it.

### Credential profile

The profile is holder-bound. ADR-10b refuses a credential held by someone else, and that
result says nothing about bearer tokens, which this profile does not model.

Issuer standing comes only from `issuer_records`. A credential cannot give itself standing
(ADR-10g). Delegation permission and exercise permission are separate. Bob may hold r2
write without being allowed to delegate it (ADR-10f). Non-amplification permits equality,
so a child equal to its delegable parent is valid (ADR-10e).

ADR-10c's child asserts all of r2 under a parent over `res:/store/r2/drafts`. This profile
rejects the over-broad child outright. A system that instead intersects the child with its
parent would also refuse the call, because the write to r2 lies outside the intersection.
The refusal reason would differ, the verdict would not.

There is no signature, key, expiry or revocation. A credential is a trusted record.

### Call reference

ADR-11 needs "the exact call" to mean something at the byte level. This family uses its own
reference over its own call object `{tool, requester, arguments, authority}`:

    call_ref = "sha256:" || lowercase-hex(SHA-256(ASCII("ADR-CALL-REF-V0") || 0x00 || UTF8(JCS(call))))

It follows the domain-separated digest style of draft-04 section 5.1. It is not an APS
`action_ref` and is not computed by any APS SDK. JCS here is RFC 8785 restricted to what the
family uses: strings of printable ASCII, booleans, null, arrays and objects. Both
implementations refuse a number rather than serialize one. The decision snapshot keeps the
decided call itself, and both runners recompute its reference.

## Vectors

Forty presentations. r1, r2 and r3 are `res:/store/r1`, `res:/store/r2` and
`res:/store/r3`. Credential names are shortened to their holder and scope.

| id | call and selection | expected | effect under the reference |
|---|---|---|---|
| ADR-01 | `copy(src=r1, dst=r2)`, r1 read and r2 write selected, matching decision | admitted | r1 read, r2 = alpha |
| ADR-02 | `copy(src=r1, dst=r2)`, Alice's r1 read-write selected for both | refused `argument_resource_not_authorized` `dst` r2 write | none |
| ADR-03 | as ADR-02, and the service holds r2 write | as ADR-02 | none |
| ADR-04 | `export`, `options.output.path=r2`, r1 read selected for it | refused `argument_resource_not_authorized` `options.output.path` r2 write | none |
| ADR-04b | as ADR-04, r2 write selected | admitted | r2 = csv:alpha |
| ADR-04c | `export` with one literal key `"options.output.path"` | refused `argument_key_invalid` `["options.output.path"]` | none |
| ADR-05 | `replicate(dsts=[r2, r3])`, r2 write selected for both | refused `argument_resource_not_authorized` `dsts[1]` r3 write | none, r2 not written |
| ADR-05b | as ADR-05, r3 write selected for `dsts[1]` | admitted | r2 = r3 = alpha |
| ADR-05c | as ADR-05b, failure injected at `dsts[1]` | admitted, partial at `dsts[1]` | r2 = alpha kept, r3 untouched |
| ADR-06 | `copy` with `label="res:/store/r3"` | admitted | r3 never touched |
| ADR-06b | `overwrite(target=r2, content="res:/store/r3")`, r2 write selected | admitted | r2 = the string res:/store/r3, r3 never read |
| ADR-06c | `copy(src=r3, dst=r2)`, r2 write selected for both | refused `argument_resource_not_authorized` `src` r3 read | none |
| ADR-07 | `copy` with `compression="gzip"` | refused `argument_designation_unknown` `compression` | none |
| ADR-07b | `copy` with `extra={}` | refused `argument_designation_unknown` `extra` | none |
| ADR-07c | `copy` without `dst` | refused `argument_operand_missing` `dst` | none |
| ADR-07d | `copy` with `dst={}` | refused `argument_resource_identifier_invalid` `dst` | none |
| ADR-07e | `copy` with `constructor={}` | refused `argument_designation_unknown` `constructor` | none |
| ADR-07f | `copy` with `toString={}` | refused `argument_key_invalid` `["toString"]` | none |
| ADR-08 | `copy(dst="res:/store/r1/../r2")`, r1 read-write selected | refused `argument_resource_not_authorized` `dst` r2 write | none |
| ADR-08b | `copy(dst="RES:/Store/R2")`, r2 write selected | admitted | r2 = alpha |
| ADR-08c | `copy(dst="res:/store/../../r2")` | refused `argument_resource_identifier_invalid` `dst` | none |
| ADR-09 | `overwrite(target=r2)`, r2 read selected | refused `argument_resource_not_authorized` `target` r2 write | none |
| ADR-10 | `copy_with_capability`, dst capability Alice r2 write | admitted | r2 = alpha |
| ADR-10b | dst capability held by Mallory | refused `authority_not_held_by_requester` `dst` | none |
| ADR-10c | dst capability for r2 delegated from Bob's drafts-only parent | refused `authority_exceeds_issuer_authority` `dst` | none |
| ADR-10d | dst capability Alice r2 read | refused `argument_resource_not_authorized` `dst` r2 write | none |
| ADR-10e | dst capability for r2 write delegated from Bob's equal, delegable parent | admitted | r2 = alpha |
| ADR-10f | as ADR-10e, Bob's parent not delegable | refused `authority_issuer_cannot_delegate` `dst` | none |
| ADR-10g | dst capability issued by Mallory as a root | refused `authority_issuer_without_standing` `dst` | none |
| ADR-11 | `copy(dst=r3)` with r3 write selected, decision names `dst=r2` | refused `call_does_not_match_decision` | none |
| ADR-11b | the decided call itself, same trusted state as ADR-11 | admitted | r2 = alpha |
| ADR-12 | `copy(dst=r2)`, Alice holds r2 read and r2 write, selects r2 read | refused `argument_resource_not_authorized` `dst` r2 write | none |
| ADR-12b | as ADR-12, selects r2 write | admitted | r2 = alpha |
| ADR-12c | as ADR-12, selects nothing for `dst` | refused `argument_authority_not_selected` `dst` | none |
| ADR-13 | `normalize(src=r2, dst=r2)`, Bob-delegated r2 read-write on src, root r2 read on dst | refused `argument_resource_not_authorized` `dst` r2 write | none |
| ADR-13b | as ADR-13 with the selections swapped back | admitted | r2 = BETA |
| ADR-13c | `normalize(src=r2, dst=r2)`, r2 write selected for both | refused `argument_resource_not_authorized` `src` r2 read | none |
| ADR-14 | `copy_audited(src=r1, dst=r2)` | admitted | r2 = alpha, and the service writes stats under its own credential |
| ADR-14b | `copy_audited(dst=res:/svc/bill)`, r2 write selected | refused `argument_resource_not_authorized` `dst` res:/svc/bill write | none |
| ADR-14c | `copy_audited(dst=res:/svc/stats)`, the service's stats credential selected | refused `authority_not_held_by_requester` `dst` | none |

Each vector's `differs_from` field names the one thing that separates it from its
neighbour, and `note` says why it matters. Every refused vector also names its
`forbidden_access`, the access that must not happen, or `null` where the refusal is a
policy refusal with no specific forbidden access (ADR-04c, ADR-07 to 07f, ADR-08c).

Pairs worth reading together:

- **ADR-02 and ADR-03** differ only in what the service holds, so the reference must give
  both the same outcome.
- **ADR-12, 12b and 12c** hold the trusted state fixed and change only the selection.
  Holding a covering credential is not enough.
- **ADR-13 and 13b** designate r2 twice, once for read and once for write, with two
  authority sources. Swapping the selections must not let the stronger source cover the
  other occurrence. ADR-13c shows that the second occurrence of a resource is checked for
  its own operation.
- **ADR-06b and ADR-06c** pass the same identifier by value and by reference. Only the
  reference needs authority over r3.
- **ADR-14, 14b and 14c** are Hardy's case. The service's own statistics write is
  admitted under its declared credential. A caller-chosen destination in the service's
  home is refused, and so is a caller selecting the service's statistics credential for its
  own destination.
- **ADR-11 and 11b** authorize both destinations, so only the binding check separates them.

Revision 0.1's identifiers are kept for every case that survived, except ADR-06, ADR-07,
ADR-08, ADR-08b and ADR-10, whose names changed to match the new model.

## Defective policies (negative controls)

`harness.ts` builds every policy from one evaluator and fourteen settings. The reference
uses the correct value of each. Every defective policy changes exactly one setting of one
stage, and every other stage keeps its reference behaviour. The tables do not hide a second
switch.

### Categories

Each runner classifies every defective outcome against the expected one, in this order:

| category | meaning |
|---|---|
| `unsafe_admission` | expected refused, the policy admitted, and the declared forbidden access appears in the trace. The unauthorized access really happened in the store |
| `admission_without_forbidden_access` | expected refused, the policy admitted, and no declared forbidden access happened. A policy refusal was skipped, but no unauthorized access to a named resource is shown |
| `false_refusal` | expected admitted, the policy refused |
| `wrong_diagnosis` | same verdict, different reason, path, resource or operation. A diagnostic defect, not a bypass |
| `wrong_effect` | same decision, different accesses, execution status or final store |
| `wrong_attribution` | same decision and the same accesses, but an access ran under a different recorded authority, usually `null` because the policy never checked that operand |

Each policy's declaration in `vectors.json` lists the vectors in each category, and both
runners require the observed set to equal the declared set in every category. A
`characteristic_cases` list names the vectors each policy was designed for.

The category is not the whole check for an admission the reference refuses. For each such
case, in both `unsafe_admission` and `admission_without_forbidden_access`, the declaration's
`defective_admissions` gives the complete outcome: the execution status, the ordered trace
with the authority and holder recorded for every access, and the store changes. They are
written by hand in `generate.ts`, as the reference expectations are, and are not computed
by `harness.ts`. Both runners require each such admission to equal its declared outcome
exactly. A defective tool that performed the forbidden access and also wrote the wrong
content, or one more access, fails. There are 47 of these declarations across 17 policies.

### The policies

| policy | stage | the one change | unsafe admission | other |
|---|---|---|---|---|
| `no-call-binding` | B | a presented decision is not compared | 11 | |
| `leaf-walk` | V | undeclared-path refusal and designation see only non-container values, as in revision 0.1 | | admission without forbidden access 07b, 07d, 07e |
| `open-schema` | V | an undeclared path is ignored | | admission without forbidden access 07, 07b, 07e |
| `no-required-check` | V | required operands are not checked | | admission without forbidden access 07c |
| `target-only` | E | only the operand at `target` is a designation | 02, 03, 04, 05, 08, 10b, 10c, 10d, 10f, 10g, 12, 12c, 13, 14b, 14c | admission without forbidden access 07d, 08c. Attribution 01, 04b, 05b, 05c, 06, 08b, 10, 10e, 11b, 12b, 13b, 14 |
| `shallow-args` | E | only top-level operands are designations, nothing inside an object or array | 04, 05 | attribution 04b, 05b, 05c |
| `shape-guessing` | E | a string beginning `res:` is a designation, read for data. A resource operand holding a non-string is skipped | | false refusal 06, 06b. Admission without forbidden access 07d |
| `dedup-by-resource` | E | a resource designated earlier in the walk is skipped | 13c | attribution 13b |
| `no-canonicalization` | R | coverage compares the raw string. The tool still resolves | 08 | false refusal 08b. Diagnosis 08c |
| `wallet-search` | A | a failed selection is replaced by any credential the requester holds | 12, 12c, 13 | |
| `pooled-selection` | A | a failed selection is replaced by any credential selected elsewhere in the call | 13 | |
| `deputy-authority` | A | a failed selection is replaced by any service credential | 03, 14b, 14c | |
| `holder-unchecked` | C | the holder is not compared with the requester | 10b, 14c | |
| `self-asserted-issuer` | C | a root's issuer is not checked against `issuer_records` | 10g | |
| `delegation-equals-exercise` | C | the parent's `delegable` flag is ignored | 10f | |
| `no-attenuation-check` | C | a child is not compared with its parent | 10c | |
| `strict-attenuation` | C | a child must be strictly narrower than its parent | | false refusal 10e |
| `resource-not-operation` | K | coverage ignores the operation. Chain attenuation is unchanged | 09, 10d, 12, 13, 13c | |
| `caller-authority-for-service-effects` | F | a service effect needs a caller-selected credential, revision 0.1's rule | | false refusal 14 |

No policy lands in `wrong_effect` on these vectors. The category is checked anyway, in both
directions, so a change that altered an effect without altering a decision would fail.

Notes on the sets:

- `target-only` keeps validation, so ADR-07 to 07c are refused correctly by it. It admits
  ADR-07d and ADR-08c, whose malformed destination it never examines, and the tool then
  stops at `dst` with `operand_unresolvable`. Twelve admitted vectors show
  `wrong_attribution`, because their destination ran with no checked authority. Checking
  the target alone misses 15 of the 27 refusals as real unauthorized accesses.
- `no-canonicalization` refuses ADR-08c for the wrong reason. That is a diagnostic defect.
  It does not reproduce an unauthorized access and is reported as `wrong_diagnosis`.
- `shape-guessing` refuses ADR-06 and 06b because it treats inert data as a read
  designation that nobody selected authority for.
- `wallet-search`, `pooled-selection` and `deputy-authority` differ only in where the
  substitute comes from. ADR-12 separates the wallet from the call's own selections, ADR-13
  is caught by both, and ADR-03 and 14b need the service.
- `dedup-by-resource` is caught by ADR-13c and not by ADR-13, because in ADR-13 the first
  occurrence in walk order (`dst`) is the one that fails.
- `leaf-walk` reproduces the empty-container bypass found in revision 0.1's harness
  (`extra: {}` and `dst: {}` were admitted). The reference now walks nodes, not leaves.

## Running

TypeScript, wired into `npm test` as its last step:

    npm ci --include=dev
    npm run verify:argument-designated-resources

Expected final line:

    PASSED: reference-boundary matched every presentation, every defective policy matched its declared categories

Python, standard library only:

    npm run verify:argument-designated-resources:py

or `python3 fixtures/argument-designated-resources/verify.py`. It is not in `npm test`,
because that gate also runs on the Windows job with Node only. It runs as its own step in
the `suite` job of `.github/workflows/tests.yml`, after the Python set up there, the same
way `verify:approval-authority-expiry:py` does. Expected final line, the same with
` (python)` appended.

Regenerating `vectors.json`:

    npm run generate:argument-designated-resources

## Determinism

`vectors.json` is produced by `generate.ts`. Every expected decision, execution, trace,
store change and forbidden access in it is written by hand in that file, and so is every
defective policy's category list and the full outcome of every defective admission. None is
computed by `harness.ts`. The generator imports
the harness for two things only: `canonicalizeResource`, to assert that every identifier in
trusted state is canonical, and `callRef`, to fill in each decision's call reference. There
is no clock, no randomness, no key and no network.

- `verify.ts` rebuilds the file with `generate.ts` in memory and requires it to equal the
  committed bytes.
- `verify.py` cannot run the TypeScript generator. It requires the committed bytes to equal
  their own re-serialization (`json.dumps(indent=2, ensure_ascii=False)` plus a newline).
  That is a formatting stability check, not an independent regeneration. It also checks
  that every identifier in trusted state is canonical under its own resolution and
  recomputes every decision's call reference with its own JCS and SHA-256.

No digest set is published for these files, for the reason `capability-binding-drift` gives:
a candidate against proposed text should stay editable while the text is argued about.

## Verification split

This family is lab-authored and protocol neutral, not an ingestion from an external
system, so `CONTRIBUTING.md` does not require this section. It is recorded in the same
format anyway.

- the 40 decisions, executions, traces and final stores, the three invariance mutations,
  the categories of 19 defective policies and the 47 declared defective-admission
  outcomes; runner aeoess; Mode A; author-produced,
  because this lab authored the profile, the vectors and both implementations,
  `harness.ts` with `verify.ts` and `verify.py`.
- decision call references over JCS bytes; runner aeoess; Mode B; author-produced, same
  relationship, with Node's `crypto` and `JSON.stringify` on one side and Python's
  `hashlib` and `json` on the other.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Results

Both runners were run locally, `verify.ts` under Node 24.11.1 with tsx 4.23.15 and
`verify.py` under Python 3.14.6 and Python 3.12. The reference boundary matched 40 of 40 on
decision, execution, trace and store under both, the 27 refused calls performed no access,
and the three invariance mutations changed nothing. Every defective policy matched its
declaration in every category under both, and each of the 47 defective admissions matched
its declared outcome. The complete outcome objects of all 20 policies on all 40
presentations, 800 in all, were exported from both implementations and compared equal. The
author reports writing the categories and the defective-admission outcomes before running
either runner against them. These are author-produced records, not independent ones.

## Where the proposed profile was too vague to test

The profile says what must be authorized and leaves these open. Each was decided here, and
a different decision gives different expected outcomes.

1. **Where designation comes from.** This family takes it from a trusted, honest contract.
   The profile does not say who authors the contract or why a boundary should trust it.
2. **Unclassified arguments.** Refusing them makes every contract change that adds an
   argument a refusal until the boundary's copy catches up (ADR-07, 07b).
3. **Identifier equivalence and covering.** The profile speaks of resources and arguments
   carry strings. ADR-08 to 08c depend entirely on the grammar and covering rule above.
4. **What selection looks like.** The profile requires authority selected per operand. This
   family uses an `authority` map keyed by path and an inline capability reference. Other
   encodings are possible.
5. **Delegation semantics.** Rejecting an over-broad child and intersecting it give the same
   verdict on ADR-10c and different reasons. The profile chooses rejection.
6. **Service effects.** The profile allows effects the contract declares. It does not say
   how a caller learns about them or limits them. A contract that declared an effect over
   a caller-chosen resource would defeat the exception, and v0 has no such contract.

## What a pass establishes

For this reference model, at this revision:

- a boundary that authorizes every declared operand with the credential selected for it,
  and runs declared service effects under their own credential, gives the expected decision
  on all 40 vectors, and the tool then performs exactly the expected accesses
- its outcomes do not depend on unselected credentials, whether the requester's or the
  service's
- a refused call touches nothing, an admitted call that fails part way keeps its earlier
  effects and says so, and each of 19 single-stage defects lands in exactly its declared
  categories, with every admission of a refused call performing exactly its declared
  accesses and leaving exactly its declared store

## What this family does not establish

- **No draft-04 conformance.** draft-04 states no such rule. Every vector is
  `candidate_against_proposed`.
- **No real tool, filesystem or resolver.** The store is an in-memory map. Resolution is
  lexical. Symbolic links, redirects, rebinding, mounts and object replacement are not
  modelled.
- **No dishonest or stale contracts.** The tool does what its contract says. A tool that
  touches resources its contract omits would pass every check here.
- **No runtime enforcement.** Nothing here says any gateway, MCP server or agent runtime
  does or does not check arguments.
- **No real capability system.** Credentials are trusted records. Nothing is signed,
  proven, expired or revoked, and the holder check assumes an authenticated requester.
  The results say nothing about bearer tokens.
- **No transactions.** ADR-05c shows that the profile governs authority, not atomicity.
- **No malformed or cyclic credential graphs.** Trusted state is well formed. A credential
  whose parent is missing, a chain that loops, an unknown credential identifier and chains
  deeper than two links are not runtime inputs here. A missing identifier is a harness
  input error, and a cycle is not detected. The delegation cases are a structural subset.
- **Stage labels are not validated.** A policy's `stage` and `change` text in
  `vectors.json` are descriptive. Neither runner checks them against what the policy does.
  `verify.ts` catches an edit to them only as byte drift from `generate.ts`, and `verify.py`
  does not catch it.
- **No claim that the profile is right.** It is proposed in this README.
- **Lab-authored and author-produced, with no independent run.** The profile, the vectors,
  `harness.ts`, `verify.ts` and `verify.py` were all written in this lab, in one session.
  Agreement between the two runners is agreement between two implementations by one
  author, and the same misreading of the profile could appear in both. Nobody outside the
  lab has reviewed or run either.

## Prior art

This family exercises a synthetic caller-supplied-resource profile motivated by the
confused deputy problem. Object capabilities can couple designation and authority, while
certificate and token mechanisms validate authority under their own chain, holder, caveat
and application rules. These cases do not run those mechanisms or establish their
conformance. The capability cases use the holder-bound model defined above. This family
claims no novelty. Each line was checked against the source at the URL given.

- Norm Hardy, "The Confused Deputy (or why capabilities might have been invented)", ACM
  SIGOPS Operating Systems Review 22(4), 36 to 38, October 1988, doi 10.1145/54289.871709.
  The compiler wrote `(SYSX)STAT` under its home-files license and wrote debugging output
  to a file its caller named, and a caller named `(SYSX)BILL`. In the author's words, "When
  it produces statistics it intends to use the authority granted by its home files
  license. When it produces its debugging output it intends to use authority from its
  invoker." The quotation is checked against the copy of the text on the author's own site,
  [cap-lore.com/CapTheory/ConfusedDeputy.html](http://cap-lore.com/CapTheory/ConfusedDeputy.html),
  fetched over http on 2026-10-27 because the https certificate does not match the host.
  The bibliographic details are the publication's, and the ACM copy was not retrieved.
- C. Ellison, B. Frantz, B. Lampson, R. Rivest, B. Thomas, T. Ylonen, "SPKI Certificate
  Theory", RFC 2693 (Experimental), September 1999.
  [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc2693.txt)
- A. Birgisson, J. G. Politz, U. Erlingsson, A. Taly, M. Vrable, M. Lentczner, "Macaroons:
  Cookies with Contextual Caveats for Decentralized Authorization in the Cloud", NDSS 2014.
  [ndss-symposium.org](https://www.ndss-symposium.org/ndss2014/programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/)
- W3C Credentials Community Group, "Authorization Capabilities (ZCAP)" v0.4.0, a Community
  Group draft whose capabilities name their `invocationTarget` and which describes holding
  capabilities in specific contexts "in order to avoid confused deputy and ambient
  authority problems".
  [w3c-ccg.github.io/zcap-spec](https://w3c-ccg.github.io/zcap-spec/v0.4.0/)
- "User Controlled Authorization Network (UCAN) Specification", version 1.0.0.
  [ucan-wg/spec README.md](https://raw.githubusercontent.com/ucan-wg/spec/main/README.md)
- "Biscuit, a bearer token with offline attenuation and decentralized verification".
  [biscuit-auth/biscuit SPECIFICATIONS.md](https://raw.githubusercontent.com/biscuit-auth/biscuit/main/SPECIFICATIONS.md)
- D. Hardt, "AAuth Protocol", draft-hardt-oauth-aauth-protocol-11, which states that its
  signed resource token "prevents confused deputy attacks" because "an attacker cannot
  substitute a different resource in the authorization flow". That addresses resource
  substitution in its own authorization flow and is cited here as related work.
  [Revision -11, appendix C.3.3](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-11#appendix-C.3.3)

## Credit

The question this family answers was raised by Alan Karp on the W3C AI Agent Protocol
Community Group list on 27 October 2026, in the thread "Four open questions on the Agentic
Web report":
[public-agentprotocol/2026Oct/0057](https://lists.w3.org/Archives/Public/public-agentprotocol/2026Oct/0057.html).
He wrote, "One thing that many certificate delegation systems get wrong is invocation, in
particular passing resource references as arguments," and said he had looked for an
example in the vectors and not found one. Alan did not design, review or endorse the profile or the
vectors.

## Provenance

`README.md`, `vectors.json`, `generate.ts`, `harness.ts`, `verify.ts` and `verify.py` are
authored for this suite. The neutral-harness pattern follows
[`runtime-authority-denial-continuity`](../runtime-authority-denial-continuity/). The
`candidate_against_proposed` labelling, the refuse-to-run check and the two-direction
negative-control check follow [`capability-binding-drift`](../capability-binding-drift/).
Revision 0.2 applies a hostile review of revision 0.1's plan and partial build. All code was
written in this lab.
