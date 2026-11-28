# Candidate: zhaoxinghua09-cell-53-byte-level

**Note on the directory name.** It records the first submission, which carried 53 cases. The
candidate now carries 113 cases in eight families. The name is not changed because the first commit
in this PR is already on record under it; the count lives here and in `summary.json`, not in the path.

Eight families on the byte level of action evidence: RFC 8785 canonical JSON, a Merkle root with
inclusion proofs, the two current action reference forms (v1 external, v2 dispatch), the draft-01
historical four-field form, the v2 object's own `profile` and non-empty string members, duplicate
member names in serialized JSON, nonce reuse inside a replay window, and recomputation on the
Section 4.1 side.
Each family has two implementations written separately in Python and Node that share no code, and
each case compares a computed byte string or a refusal code, not a narrative verdict. This is a
candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's
schema, failure classes or verifier behavior.

Why these bytes: two implementations that agree on a decision can still disagree on the bytes that
decision is signed over, and a receipt whose bytes disagree cannot be checked by the other
implementation at all.

## Submitter

Steven Zhao (Zhao Xinghua), zhaoxinghua09-cell.

## Normative target

- `spec-a`: RFC 8785 (JCS). Key order by UTF-16 code units, no insignificant whitespace,
  ECMAScript `Number::toString` for numbers, `\u00xx` lowercase hex for control characters,
  non-ASCII emitted raw.
- `spec-b`: draft-pidlisnyi-aps-04, retrieved 2026-11-28 from
  https://www.ietf.org/archive/id/draft-pidlisnyi-aps-04.txt, sha256 of the retrieved TXT
  re-encoded UTF-8 (720,711 B): `6912754a92ae82790568ca2169b9b74ab0a24e6aef485b3f0366eb7d1f2a1eb3`.
  Sections 4.1 (the `aps-action-ref-v2` input, eight members), 4.2 (the external four-field form and
  the `action-ref-v1-jcs-sha256` label) and the clause identifiers `REQ-4.1-1`, `REQ-4.1-2`,
  `REQ-4.1-4`, `REQ-4.1-7`, `REQ-4.1-8`, `REQ-4.1-9`, `REQ-4.2-2`, `REQ-4.2-3` are used. An
  Internet-Draft can change in a later revision.
- `spec-c`: RFC 6962 style domain separation for the Merkle tree (leaf `0x00`, node `0x01`), odd
  final position carried up rather than paired with itself.

Part of the v1 material is not authored here. The five positive and nine negative action-ref v1
cases are taken from the lab's own corpus, `fixtures/cross-stack/action-ref-v1-negatives/vectors.json`
at `79e9a7d4ff68a565fe0ca82261e23a0be434ec26`: the `action_ref`, `claimed_action_ref` values and the
declared failure stage are reused unchanged, so this candidate's contribution there is a third
implementation recomputing them, not new vectors.

The twelve Section 4.1 recomputation cases were likewise not authored from nothing: their expected
`payload_ref` and `action_ref` values were computed by the APS SDK (`computePayloadRefV1`,
`computeActionRefV2`, `dist/src/v2/action-reference/v2.js`) from this repo's install at
`79e9a7d4ff68a565fe0ca82261e23a0be434ec26`, and the two runners here reproduce them independently.
That makes three implementations agreeing on those byte strings, and the SDK is the source of the
expectation rather than the candidate.

## Source

Written for this candidate: `CANDIDATE.md`, `vectors/*.json`, `runners/*`, `CHECKSUMS.sha256`.
Runners are copied in so the directory runs without network access; the same files are at
`zhaoxinghua09-cell/lgd-passport` commit `2439366a9f988a994d094f8dfd84b59937892e4d` under
`zc/v2_candidates/`, with the vector files under `zc/vectors/`. That commit is the pinned source.
`runners/parity_check.py` runs both sides of every family and compares each case's computed value,
its reason string and the layer name where one exists.

## License

Apache 2.0, the license of the lab's repository and of the submitter's repository. The v1 values
reused from `79e9a7d4ff68a565fe0ca82261e23a0be434ec26` are data from a repository that declares
Apache 2.0; no text is quoted beyond short identifier strings. No text is copied from RFC 8785 or the
Internet-Draft.

## What the cases test

One hundred and thirteen cases in eight families. Each case states the input, the expected byte string or refusal
code, and the reason the rule decides that way.

| family | ids | rule | what is tested |
|---|---|---|---|
| jcs | 21 | RFC 8785, and draft `REQ-4.1-5`, `REQ-4.1-6` | key order by UTF-16 code units including the astral / `U+FFFD` split, integer vs `1.0`, `1e21` / `1e-6` / `1e-7`, `-0`, three-digit exponent form, short escapes, lowercase `\u001f`, raw non-ASCII, compact empty containers, two refusals (duplicate member name at top level, integer beyond 2^53-1), and five surrogate cases: a lone high, a lone low, a lone surrogate in a member name, a reversed pair, all four refused as `LONE_SURROGATE` rather than substituted, with a real pair accepted and emitted as the astral character |
| merkle | 12 | RFC 6962 style | empty root is 32 zero bytes, single leaf, two, three and five leaves with odd-carry, leaf order matters, `[a,a]` root differs from single leaf `a`, inclusion proofs for a middle and an edge leaf, empty proof for one leaf, tampered leaf against the original proof refused |
| action-ref | 25 | draft 4.1, 4.2 | v1 recomputation from the four-field preimage (5 positives byte-equal to the corpus) and 9 negatives: field-order drift, epoch-integer timestamp refused at the grammar gate before hashing, second and microsecond precision, `agent_id` case drift, `scope` and `action_type` drift. v2: 3 positives byte-equal to the SDK, sorted/NFC `scope_required`, lowercase hex, exact millisecond `issued_at`, a domain-stripped digest must not pass as a v2 ref, a v1 digest in a 4.1 slot refused, and same-agent-same-nonce-differing-only-in-`target` must produce different refs |
| dup-member | 12 | draft `REQ-4.1-4` | a hand-written scanner over the serialized text, not a JSON library: duplicate at top level, duplicate nested, `"a"` vs `"\u0061"`, `"\ud83d\ude00"` vs the literal astral character, key repeated three times, same key in *different* objects accepted, same key in sibling array elements accepted, key text inside a string value accepted, plus three structural refusals (trailing comma, missing colon, lone surrogate escape) that must fail as `NOT_JSON` rather than be read as "no duplicate" |
| nonce-replay | 12 | draft `REQ-4.1-9` | the pair key is `(agent_id, nonce)`, not the nonce alone: exact replay inside the window refused, `|Δ| == window` refused (closed on both ends), `|Δ| == window+1` accepted with `OUTSIDE_WINDOW`, same nonce under a different agent accepted, empty nonce, absent window and negative window refused, malformed ledger and ledger entry without `issued_at` refused, same nonce differing only in `target` refused, and one-of-two prior entries inside the window refused |
| recompute-41 | 12 | draft `REQ-4.1-7`, `REQ-4.1-8` | recompute `payload_ref` from the payload that would be dispatched and `action_ref` from the received Section 4.1 object, both **before** policy evaluation: match with an allowing policy dispatches, match with a denying policy is `POLICY_DENIED`, wrong `payload_ref` (including a domain-stripped one) stops at `ref-check` even though the policy would allow, wrong `action_ref` likewise, both wrong, absent payload, a v1 external-form digest presented as the 4.1 `action_ref`, and `nonce` / `scope_required` / `target` swapped after the ref was computed |
| actionref-historical | 6 | draft-01 section 4.1 historical form | camelCase members (`agentId` / `actionType` / `scopeRequired` / `timestamp`), each scope string NFC-normalized, scope list sorted by **Unicode code point** rather than UTF-16 code unit, JCS, sha256, no domain prefix. Four positives byte-equal to the corpus fixture `fixtures/actionref-canonical/actionref-canonical-fixture-v1.json` (single scope, unsorted multi-scope, NFD scope normalizing to NFC, astral scope ordering after a BMP-high string), and two negatives from the same file: a duplicated `scopeRequired` entry, and two scopes that collide only after NFC (`U+00E9` vs `e` + `U+0301`), both refused |
| actionref-v2-members | 13 | draft `REQ-4.1-1`, `REQ-4.1-2` | the v2 object's own fields, before any ref is computed: `profile` must equal the literal `aps-action-ref-v2` (refused for the v1 name, a case variant, an empty string, and an absent member), and every string member must be non-empty (`agent_id`, `action_type`, `target`, `payload_ref`, `issued_at`, `nonce`, and scope elements), plus an empty `scope_required` array. Expectations come from the draft sentence, not from an implementation: the SDK entry point computes a ref and performs none of these checks |

## Where this sits against the lab's own coverage table

`docs/ID-COVERAGE.md` in this repo (inspected at `b0bf645c`) records `REQ-4.2-2` and `REQ-4.2-3` as
NOT EXERCISED, and `REQ-4.1-9` as NOT EXERCISED while naming the two same-agent pairs that share a
nonce and differ only in `target`. `REQ-4.1-4` is NOT EXERCISED there as well, with the note that
nothing in the tree parses serialized JSON for duplicate member names. Those four clauses plus the
Section 4.1 half of `REQ-4.1-7` are where this candidate puts its cases. Whether the cases satisfy
the clauses is the maintainer's call; this candidate does not assert that they close them.

## How to run

```
python runners/jcs_check.py --vectors vectors/jcs.json
node   runners/jcs_check.mjs vectors/jcs.json --json
python runners/merkle_root.py
node   runners/merkle_root.mjs vectors/merkle.json --json
python runners/action_ref_dual.py
node   runners/action_ref_dual.mjs vectors/action-ref.json --json
python runners/dupmember_check.py --vectors vectors/dup-member.json
node   runners/dupmember_check.mjs vectors/dup-member.json --json
python runners/nonce_replay.py --vectors vectors/nonce-replay.json
node   runners/nonce_replay.mjs vectors/nonce-replay.json --json
python runners/recompute41.py --vectors vectors/recompute-41.json
node   runners/recompute41.mjs vectors/recompute-41.json --json
python runners/actionref_historical.py --vectors vectors/actionref-historical.json
node   runners/actionref_historical.mjs vectors/actionref-historical.json --json
python runners/actionref_v2_members.py --vectors vectors/actionref-v2-members.json
node   runners/actionref_v2_members.mjs vectors/actionref-v2-members.json --json
python runners/parity_check.py          # ZC_NODE may be set; otherwise `node` must be on PATH
```

`parity_check.py` also runs a negative control per family: it rewrites every `expect` to a value no
implementation can produce and requires the Node side to fail, so a comparator that always agrees is
visible.

## Evidence

Author-produced, Mode A, 2026-11-28, Windows 11 23H2, Node 22.23.2, Python 3.13. Both sides were
written by the submitter, so under the lab's run classification every result here is
author-produced, not independent:

```
jcs         py 16/16  js 16/16  same verdict 16/16  same reason 16/16  negative control caught
merkle      py 12/12  js 12/12  same verdict 12/12  same reason 12/12  negative control caught
actionref   py 25/25  js 25/25  same verdict 25/25  same reason 25/25  negative control caught
dupmember   py 12/12  js 12/12  same verdict 12/12  same reason 12/12  negative control caught
noncereplay py 12/12  js 12/12  same verdict 12/12  same reason 12/12  negative control caught
recompute41 py 12/12  js 12/12  same verdict 12/12  same reason 12/12  negative control caught
actionrefhist py 6/6  js 6/6  same verdict 6/6  same reason 6/6  negative control caught
actionrefv2m  py 13/13  js 13/13  same verdict 13/13  same reason 13/13  layer 13/13  negative control caught
```

The five v1 positives are byte-equal to the corpus values, the three v2 positives and the twelve
recompute expectations are byte-equal to SDK output. That agreement is with a foreign implementation
on the submitter's machine; it is not a run by the lab, and the lab has not reproduced it.

`actionref-v2-members` is the one family whose expectations are **not** taken from anything the
corpus or the SDK states: they come from two sentences of the draft (`REQ-4.1-1`, `REQ-4.1-2`), and
`docs/ID-COVERAGE.md` at `b0bf645c` records both as NOT EXERCISED. Two choices in it are the
submitter's reading, not the draft's words, and are flagged in the vector file itself:
refusing an empty `scope_required` array rests on the draft's MAY (a profile *may* permit an empty
array), and treating an empty scope element as an empty string field is an extension of "all string
fields MUST be non-empty". A reader who takes the MAY the other way should flip those two cases and
nothing else.

## Cross-check against the corpus

Beyond the cases here, three of this repo's own fixtures were read at `79e9a7d4` and used as an
outside expectation for the implementations in this directory:

- `fixtures/canonical-bytes/canonical-bytes-jcs-v1.json` and `-v2.json`: **18 of 18** cases reproduce
  byte-for-byte, including the `1e21` boundary, `-0`, and integers at 2^53 and 2^60 / 2^68. That
  agreement is with the expectations the corpus states, not with a decision: it is a string compare.
- `fixtures/actionref-canonical/actionref-canonical-fixture-v1.json`: **4 of 4** positives reproduce,
  plus the two negatives refuse as the file says they should. This is the `actionref-historical`
  family above.
- `fixtures/merkle-root-parity/vectors.json`: the six expected roots reproduce only under the
  construction that file's own `spec_section` states — leaf `sha256(0x00 || hex-of-leaf utf8)`, node
  `sha256(0x01 || left-hex utf8 || right-hex utf8)`, empty set `sha256("empty")`, leaves sorted by
  code point. Under the RFC 6962 style construction used in this candidate's `merkle` family — leaf
  `sha256(0x00 || raw 32 bytes)`, node `sha256(0x01 || left raw || right raw)` — **all six roots
  differ**. Both are internally consistent; they are different constructions that share the name.
  A receipt whose root was computed one way cannot be checked the other way, and this candidate does
  not claim the two are interchangeable.

## Known limitations

- No signatures. Digests only. A matching digest does not establish a valid signature, and nothing
  here says anything about Ed25519 verification or about a receipt's validity.
- The v1 timestamp gate is shape-only (`^\d{4}-...\.\d{3}Z$`, leap second 60 allowed) and does not
  check calendar validity, so `2026-02-30T00:00:00.000Z` would pass. The lab's own v1 validator is
  shape-only too; the candidate matches the source text's rule, not because that is safer.
- The dup-member scanner is a strict RFC 8259 reader: it accepts only what the grammar allows, so
  inputs valid in a looser dialect (comments, single quotes) come back `NOT_JSON`. Strings with lone
  surrogate escapes are `NOT_JSON` rather than `DUPLICATE_MEMBER`, because the scanner refuses before
  it compares names.
- The nonce case set defines the window as closed on both ends; an implementation with a half-open
  window would disagree on `|Δ| == window` and on that single case only.
- The recompute cases assume `payload_ref` is recomputed with the `APS-ACTION-PAYLOAD-V1\0` prefix and
  `action_ref` with `APS-ACTION-REF-V2\0` over the eight members, which is what the SDK does. Where
  the draft leaves the preimage implicit, this candidate follows the SDK.
- One incidental observation, offered as an observation and not as a defect claim: the SDK's
  `assertIJson` refuses integral numbers outside the 2^53-1 range (so `1.25e100` is rejected as
  "non-I-JSON number" although it is a finite double). The payloads in this candidate stay inside
  that range.
- No consistency proof between two Merkle roots; the root depends on leaf order, and an
  exchangeable root ordered by hash is a different construction, not mixed in.
- **Windows, one operational note for a reviewer.** On this machine Node 22.23.2 exits with
  `-1073740791` (`0xC0000409`) when the process's working directory is an ASCII path but any part of
  the *path passed to it* is non-ASCII — the same tree copied to `C:\aps89run` runs, the same tree
  under a Chinese directory name does not, and setting `TEMP` to an ASCII path does not help. Run
  `parity_check.py` from an ASCII working directory (`cd C:\` then the absolute script path). This is
  a property of the Node build here, not of the vectors.
- Three v2 refusals (`SCOPE_NOT_SORTED`, `SCOPE_NOT_NFC`, `HEX_CASE`) assert gates this candidate
  defines; if the draft states them differently, those three cases are wrong and the rest stand.
- Breadth is narrow on purpose: no lifecycle families, no lease families, no Kubernetes admission
  cases, no read-fidelity receipts. This does not claim to cover the corpus.
- Nothing here was run by the lab, and the submitter simulated no outsider. Independent (G5/G9 style)
  evidence is still absent, and this candidate must not be described as admitted, accepted,
  validated or certified.


