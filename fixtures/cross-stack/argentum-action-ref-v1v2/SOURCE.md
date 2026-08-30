# Provenance: argentum-action-ref-v1v2

## Upstream

- Repository: `giskard09/argentum-core` (https://github.com/giskard09/argentum-core), Apache 2.0.
- Pinned commit: `4aaa6eeb9748e4bc93d02a001705051938009ef1`, branch `main`. This is the third
  re-pin from the original `8bdee1feb0cbaa9e1cc0b0bcfa26df802e39ed12` — see "Re-pin" below for
  the full history. Verified as `HEAD == origin/main` on 2026-08-29 (no divergence, no
  local-only commits ahead of the pin).
- Files mirrored at that commit (SHA-256 of the bytes as vendored here):
  - `examples/conformance/action-ref-v1-domain-negative/action-ref-v1-domain-negative.fixture.json`
    — `5b1549added5b90e2fb53dd6f5514e7472256b3ecc4b1267d7f8f1aaf122aa86` (unchanged since the
    original pin — this file has never been touched by any re-pin's commit)
  - `examples/conformance/action-ref-v1-domain-negative/validate.py`
    — `a55feb385c25fd99fde76a7ac9581094a0d6925ae7dfb04494f570799a6e9f57`. **Not** byte-identical
    to argentum-core's copy at this commit (that copy is
    `168006446e7cb83750b8e36ea298938d08e1007ad7e6e9fa05f32a2e806a6ea4`) — this vendored copy
    still has argentum-core's dead `sys.path.insert` removed (per aeoess's non-blocking nit
    from the first review pass, fixed in `b557fca`), plus a new comment block (round 3, this
    re-pin) stating the modification per Apache License 2.0 §4(b) — this file is a modified
    copy of an Apache-2.0-licensed original, and the modification itself was previously
    undeclared in the file's own text (only in this document). Two intentional divergences
    from upstream now, both carried forward through every future re-pin.
  - `examples/conformance/action-ref-v2/action-ref-v2.fixture.json`
    — `02d244e205d86dcd24bdbdf5ef5ed1cab224c0d2deb2b8936ec5b910e7bc05c9`. Byte-identical to
    argentum-core's copy at this commit as of this re-pin (round 3 added the two newline
    `version_marker_negative_vectors` — `vm-neg-003`/`vm-neg-004` — upstream first, in
    `giskard09/argentum-core#73`, then re-pinned here rather than vendoring a local-only
    edit). The narrower `purpose` field from the previous re-pin (naming the live profile
    explicitly, ruling out aggregating results across profiles — see "Profile boundary"
    below) is unchanged.
  - `examples/conformance/action-ref-v2/validate.py`
    — `661195e102bd0839c14ad34e7efc8ad79e49c276a6ab09445176a12f74d4eb9c` (unchanged since the
    previous re-pin — `fullmatch` instead of `match`, profile-metadata and preimage-shape
    assertions)
  - Reference implementation (vendored here, at `plugins/agt_evidence_anchor/action_ref.py`
    within this directory, so `action-ref-v1-domain-negative/validate.py` resolves without
    cloning `argentum-core`) — `0eda0d12be1c6251fb150394c8d682b21b0db6b4344a45068e2f8b924dc45ef0`
    (unchanged since the previous re-pin). Exposes `compute_action_ref`,
    `compute_action_ref_v2`, `_validate_domain`, `OutOfProfileDomainError`.
    `action-ref-v2/validate.py` does not import this file — its digest logic and
    `action_ref_version()` grammar check are self-contained.
  - Normative spec (not vendored, cited): `docs/spec/action-ref.md` — the Domain
    paragraph (in the "Derivation" section) and the "Version negotiation" section.
    The scope-empty-string reversal this family's `av-003`/`av-007` vectors test is
    dated 2026-08-15 in the spec's changelog; a separate erratum note (dated
    2026-08-25) documents that the immutable `action-ref-v1.0` tag was never
    updated to match.
  - The fixture's top-level `generated_at: "2026-07-29"` is the date the file (all 10
    vectors as a set) was assembled — it is not the date each individual vector's
    expected result was decided. Two vectors have their own, later history: `av-007`
    (empty `scope`) had its `expect_valid` flipped from `true` to `false` on
    2026-08-15, and `epoch-ms-001` was added to the set on 2026-08-25. Treat
    `generated_at` as the family's assembly date, and each vector's own
    `description` field (which carries its individual date where one applies) as the
    source for that vector's history.

## Trigger

- [a2aproject/A2A#1628](https://github.com/a2aproject/A2A/issues/1628), comment by `aeoess`,
  2026-08-28T22:48:17Z: proposed this lab as the home for cross-running published `.well-known`
  vector sets, naming "the Argentum sets" alongside kenneives's CTEF vectors and
  douglasborthwick-crypto's Insumer `onchain_*` signals as candidates to "take one of these and
  put it through the lab end to end."
- A cold Mode A reproduction run against this repository was posted the same thread
  (2026-08-28T23:22:23Z, comment `5458781418`) ahead of this PR, per `docs/RUN-REPORT.md`.
  aeoess confirmed a real bug the run surfaced (hardcoded `$HOME/agent-passport-system` path in
  the AAE verifier) and fixed it same-day (`70d503f`), then invited this PR
  (comment `5458943621`, 2026-08-28T23:49:47Z).
- Direct prior contact: `giskard09/argentum-core#35`, opened by `aeoess` (as Pidlisnyi) on
  2026-07-29 and closed the same day — he reported that `compute_action_ref` hashed inputs the
  Domain paragraph said to reject. The fix (`_validate_domain`, `OutOfProfileDomainError`) and
  the `action-ref-v1-domain-negative` fixture set both came out of that report. This is the
  reason this family was chosen as the representative set over other Argentum corpora: `aeoess`
  already has hands-on history with exactly this failure class.

## Re-pin, round 1 (2026-08-29)

aeoess's second review pass on this PR found four issues, addressed in commit `30445e1`. One
of them — `action_ref_version()` checking only length and prefix instead of enforcing lowercase
hex grammar — turned out not to be specific to this vendored copy: the same function in
`giskard09/argentum-core`'s production reference implementation
(`plugins/agt_evidence_anchor/action_ref.py`) had the identical gap. Fixed there too
(`giskard09/argentum-core#69`, merged as `586299a`, suite 79/79 + 63/63 green before merge), so
the fix lands in the actual upstream implementation rather than only in a copy pasted into this
submission.

Re-pinning this PR to `586299a` — rather than leaving it at the original `8bdee1feb0c...` and
noting the divergence — keeps the claim in "Files mirrored at that commit" as true as this
submission can make it: every vendored file byte-identical to upstream at the cited commit,
with the one documented exception above
(`action-ref-v1-domain-negative/validate.py`, intentionally adapted, not byte-identical by
design). Only three of the five vendored files actually changed between the two commits
(`action-ref-v2.fixture.json`, `action-ref-v2/validate.py`, `action_ref.py`); the
`action-ref-v1-domain-negative/action-ref-v1-domain-negative.fixture.json` file is untouched and
keeps its original digest, noted per-file above.

## Re-pin, round 2 (2026-08-29)

A follow-up review pass by aeoess (after round 1 above) found a deeper instance of the same
length/prefix-only leniency in `action_ref_version()`: `re.match`'s pattern ends in `$`, which
matches at end-of-string OR immediately before a trailing newline, not strictly end-of-string —
so `'a' * 64 + '\n'` passed as v1, and `'v2:' + 'a' * 64 + '\n'` passed as v2, in both this PR's
vendored copy and the production implementation at `586299a`. `giskard09/argentum-core#70`
fixed it there with `fullmatch`, merged as `a9312c0` (suite 144/144 green before merge),
mirroring round 1's pattern of landing the grammar fix upstream rather than only in a copy.

The same review pass raised three further points, addressed in the same commit as the
`fullmatch` fix locally and reflected here: (1) `action-ref-v1-domain-negative/validate.py` now
asserts zero SHA-256 digests are computed during each rejected call, rather than only asserting
`OutOfProfileDomainError` is raised — the "check runs before any digest" claim was previously
prose, not enforced; (2) `action-ref-v2/validate.py` now asserts the fixture's declared
`hash_algo`/`preimage_format`/`domain_tag` against what the validator implements, and asserts
each preimage has exactly the four expected string keys, both checked before hashing; (3) the
"MUST still pass all v1 vectors" claim was corrected — see "Profile boundary" below.

Re-pinned to `a9312c0` for the same reason as round 1: every vendored file byte-identical to
upstream at the cited commit, with the one documented, intentional exception noted above.

## Re-pin, round 3 (2026-08-29)

aeoess's fourth review pass (review `5058939119`, `CHANGES_REQUESTED`) confirmed 5 of 6
independent mutations against the round-2 head still held, then found one still missing: the
`fullmatch` fix from round 2 landed, but the two vectors that actually exercise the
newline-vs-`match` failure mode it closes — a bare 64-hex v1 digest and a `v2:`-prefixed
digest, each with a trailing `\n` — were never added to `version_marker_negative_vectors`.
Mutating `fullmatch` back to `match` against the round-2 fixture left all 5 existing vectors
passing, so nothing in the family detected the regression the fix targets.

Added `vm-neg-003`/`vm-neg-004` upstream first (`giskard09/argentum-core#73`, merged as
`4aaa6ee`, suite green before merge — see the file hash above), then re-pinned this
submission to that commit, mirroring rounds 1 and 2's pattern of landing every fix in the
production repository rather than only in this vendored copy. Verified locally: reverting
`fullmatch` to `match` in this directory's `action-ref-v2/validate.py` makes exactly
`vm-neg-003`/`vm-neg-004` fail (5/7) while `fullmatch` restored passes all 7 — confirming
these two vectors, and only these two, anchor the fix.

The same review pass requested four further items, addressed in this re-pin: (1) a
`Verification split` section in README.md, required by `CONTRIBUTING.md` after `#49`,
attributing each verification claim to its actual runner and marking domain/grammar claims
`author-produced` rather than `independent` where aeoess originated the vectors or the
implementation under test; (2) the PR body, stale since round 2 (still read `Pinned at
8bdee1f…` and cited the old `reproduce_in_python` claim); (3) the "Profile boundary" section
below, correcting `0003-empty-scope`'s description — it is a historical fixture result under
wording the 2026-08-25 erratum has since resolved, not a currently-valid reading of the
frozen tag; (4) an Apache License 2.0 §4(b) modification notice added directly to
`action-ref-v1-domain-negative/validate.py` (previously the modification was documented only
here, not in the file itself), and a sentence separating this fixture's family-level
`generated_at` date from the later, per-vector history of `av-007` and `epoch-ms-001` (see
"How the digests were produced" below).

Re-pinned to `4aaa6ee` for the same reason as rounds 1 and 2: every vendored file
byte-identical to upstream at the cited commit, with the two documented, intentional
exceptions noted above.

## How the digests were produced

- All positive and negative expected outputs in both fixture files are computed with the
  reference implementation at the pinned commit (`compute_action_ref` for v1,
  `compute_action_ref_v2` for the domain-tagged variant), not invented or hand-typed. Each
  fixture file (not each vector — `reproduce_in_python` is a single top-level field per file,
  present in none of the 15 individual vector entries across both fixtures: 10 in
  `action-ref-v1-domain-negative.fixture.json`'s `vectors` array, 3 in
  `action-ref-v2.fixture.json`'s `vectors` array, plus the 2 in that same file's separate
  `version_marker_negative_vectors` array) carries the exact minimal procedure — RFC
  8785 JCS canonicalization + SHA-256, with the v2 variant prepending the domain tag
  (`mycelium.action-ref:v2:`) before hashing.
- The 10 domain-negative vectors assert rejection (an exception with a named reason), not a
  digest — the property under test is that the check runs before any digest is computed.
- The 3 v1/v2 vectors show the two derivations differ for these three pinned preimages;
  `arv2-001`'s preimage is the same worked example published in `docs/spec/action-ref.md`'s
  "Serialization — JCS" section, not a fixture-only value invented for this submission.
  `validate.py` additionally asserts the two underlying digests are unequal — a defensive
  invariant check, not a property these (or any normally-constructed) vectors can exercise: see
  Boundaries in README.md for why the branch can only fire on an actual SHA-256 collision.
- 4 additional version-marker negative vectors (`version_marker_negative_vectors` in
  `action-ref-v2.fixture.json`) assert that `action_ref_version()` rejects same-length strings
  that are not valid lowercase hex, or that carry trailing garbage after an otherwise-valid
  digest: `vm-neg-001`/`vm-neg-002` are an uppercase-hex string and a non-hex string, both 64
  characters (before this submission's review, `action_ref_version()` checked only length and
  the `v2:` prefix, so both would have been misread as valid v1 action_refs); `vm-neg-003`/
  `vm-neg-004` (added round 3) are a bare 64-hex v1 digest and a `v2:`-prefixed digest, each
  with a trailing `\n` — see the `fullmatch` note below for why these two specifically. The
  grammar is enforced with a regex requiring lowercase hex (`fullmatch`, not `match`), matching
  `docs/spec/action-ref.md`.
- `action-ref-v1-domain-negative/validate.py`'s rejection check is paired with an assertion that
  zero SHA-256 digests were computed during the rejected call (`hashlib.sha256` wrapped for the
  duration of each call to count invocations). "The check runs before any digest is computed"
  was previously a claim this file made in prose without anything enforcing it — a future
  regression that hashed first and rejected afterward would have passed every other check here.
- `action-ref-v2/validate.py` asserts the fixture's declared `hash_algo`/`preimage_format`/
  `domain_tag` match what the validator implements (fails loudly on a mismatch instead of
  silently validating against a different profile than the one declared), and asserts each
  vector's preimage has exactly the four expected string keys (`agent_id`, `action_type`,
  `scope`, `timestamp`) before hashing — neither was previously checked, so a fixture edited to
  a different tag or a preimage with an extra field would have validated identically. Verified
  both checks fire with two manual mutations (an added 5th preimage field, a wrong `domain_tag`)
  before this was committed.
- `action_ref_version()`, both here and in the vendored `action_ref.py`, uses `fullmatch`
  instead of `match`: a regex's trailing `$` matches at end-of-string OR immediately before a
  trailing newline, so `match` alone accepted a valid 64-hex digest with a trailing `\n`
  appended as though it were clean. `vm-neg-003`/`vm-neg-004` (round 3, upstream
  `giskard09/argentum-core#73`) are the vectors that exercise exactly this: reverting
  `fullmatch` to `match` makes both fail while `vm-neg-001`/`vm-neg-002` (which test the
  character-class check, not the anchoring) keep passing — confirmed locally before this
  re-pin. The upstream test suite
  (`plugins/agt_evidence_anchor/tests/test_action_ref.py`) also covers this fix.

## Profile boundary

The lab's own corpus already vendors an older Argentum family
(`runners/ts/sk-function-invocation/test-fixtures/argentum-core/`,
`recompute-drift-v1-positive`/`-negative`, pinned to `b4e03c2` and labeled
`spec_stable_ref: action-ref-v1.0`, fetched 2026-06-15) that predates this repository's
2026-07-29 Domain-paragraph enforcement. That family's `0002-unicode-fields` is a POSITIVE
case — a non-ASCII `agent_id` — and it stays one: this is a real historical profile
difference, valid under the frozen `action-ref-v1.0` tag's rules then and now, correctly
rejected by this submission's `nfc-001`/`nfc-002` only because those test the **live**,
Domain-enforced profile at the pinned commit.

`0003-empty-scope` is not the same kind of case, and is described differently here on
purpose. It is not "valid under the frozen tag's rules" — the tag's own 2026-08-25 erratum
(`docs/spec/action-ref.md`) gives non-empty `scope` with no `""` exception as the effective
reading for any consumer of `action-ref-v1.0`, including the frozen tag itself. `0003-empty-
scope`'s recorded PASS is a historical fixture result produced under the wording conflict
that erratum resolved, not a currently-valid alternate reading of the tag. This submission's
`av-007` (empty `scope`, rejected) is not in tension with it: both are consistent with the
tag's erratum-corrected reading, one as a stale artifact of when it was generated, the other
as a fresh vector against the corrected reading.

This is not a contradiction to reconcile — it is two different, both-correct profiles of the
same protocol at two different points in its history, and `action-ref-v2.fixture.json`'s
`purpose` field is written to say so explicitly rather than claim blanket compatibility. A
verifier running both families must report results per profile (e.g. "13/13 against the live
Domain-enforced profile at `<pin>`" and separately "N/M against the frozen `action-ref-v1.0`
profile") and must not aggregate the two into a single pass/fail count, since a single input can
correctly have opposite verdicts depending on which profile it's checked against.

## Independence

This family was assembled and submitted by the author of the upstream repository
(`giskard09`) — it is the author submitting their own vectors for the lab's independent
verification, not a third-party recomputation. Per `CONTRIBUTING.md`, independent verification
on the lab side (a clean-clone recompute against the pinned commit, before merge) is the
required step before an external-system vector family lands, and is expected to happen as part
of this PR's review rather than having been claimed here.

## Boundaries

- No signatures in this family — `action_ref` is a bare content-address, not an attestation.
- Only the Domain-rejection and v1/v2-domain-separation slices of the `action_ref` corpus are
  mirrored here; the upstream repository has additional fixture sets (scope semantics,
  cross-surface consistency) not included, to keep this submission small and legible.
- Deferred, not blocking: a non-ASCII `action_type` negative vector (only `agent_id` is covered
  today), and a representable duplicate-key case for the JCS canonicalizer (JSON with a
  duplicate key is not constructible from a Python dict, so this would need a raw-bytes fixture
  rather than the current `preimage` object shape).
- One known erratum on the historical tag `action-ref-v1.0` (git tag, not a branch): a
  scope-field wording conflict, resolved in the live spec (`docs/spec/action-ref.md`, dated
  2026-08-15) but the tag itself is left unedited by upstream policy — noted here so a verifier
  reading the tag directly is not surprised.

2026-08-30: outside run of the domain and version-grammar layers by rafaelasor at pull request #42 head 3127776 against Argentum 4aaa6ee (Python 3.14.6, Darwin arm64): action-ref-v1-domain-negative/validate.py rejected all 10 vectors as expected, exit 0; action-ref-v2/validate.py passed 7/7, exit 0; the four version_marker_negative_vectors, passed unchanged through the vendored action_ref_version, each raise ValueError. Classification under CONTRIBUTING.md: Mode A, independent; the runner authored neither the vectors, the claim inputs nor the implementation supplying the recomputation. Record: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/42#issuecomment-5467188281. The family merged from that head; its nine files are byte-identical after the rebase onto 8cf3ed0.
