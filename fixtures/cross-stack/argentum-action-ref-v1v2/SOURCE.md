# Provenance: argentum-action-ref-v1v2

## Upstream

- Repository: `giskard09/argentum-core` (https://github.com/giskard09/argentum-core), Apache 2.0.
- Pinned commit: `a9312c0b0e8a65dd0d8c8f002d55a767b0bf68c4`, branch `main`. This is the second
  re-pin from the original `8bdee1feb0cbaa9e1cc0b0bcfa26df802e39ed12` — see "Re-pin" below for
  the full history. Verified as `HEAD == origin/main` on 2026-08-29 (no divergence, no
  local-only commits ahead of the pin).
- Files mirrored at that commit (SHA-256 of the bytes as vendored here):
  - `examples/conformance/action-ref-v1-domain-negative/action-ref-v1-domain-negative.fixture.json`
    — `5b1549added5b90e2fb53dd6f5514e7472256b3ecc4b1267d7f8f1aaf122aa86` (unchanged since the
    original pin — this file has never been touched by any re-pin's commit)
  - `examples/conformance/action-ref-v1-domain-negative/validate.py`
    — `402510f88dc94b526e6742372bda6155daa8ee02a8816daa6d86850cb554ed88`. **Not** byte-identical
    to argentum-core's copy at this commit (that copy is
    `168006446e7cb83750b8e36ea298938d08e1007ad7e6e9fa05f32a2e806a6ea4`, changed at this pin by
    the same zero-hash assertion added below) — this vendored copy still has argentum-core's
    dead `sys.path.insert` removed (per aeoess's non-blocking nit from the first review pass,
    fixed in `b557fca`), the one intentional divergence from upstream, carried forward through
    both re-pins.
  - `examples/conformance/action-ref-v2/action-ref-v2.fixture.json`
    — `ef3287be43ae326e63346797650530591fac8580a06736c05f44b16014635c79` (changed at this pin —
    narrows the `purpose` field to name the live profile explicitly and rule out aggregating
    results across profiles, see "Profile boundary" below)
  - `examples/conformance/action-ref-v2/validate.py`
    — `661195e102bd0839c14ad34e7efc8ad79e49c276a6ab09445176a12f74d4eb9c` (changed at this pin —
    `fullmatch` instead of `match`, profile-metadata and preimage-shape assertions added)
  - Reference implementation (vendored here, at `plugins/agt_evidence_anchor/action_ref.py`
    within this directory, so `action-ref-v1-domain-negative/validate.py` resolves without
    cloning `argentum-core`) — `0eda0d12be1c6251fb150394c8d682b21b0db6b4344a45068e2f8b924dc45ef0`
    (changed at this pin — same `fullmatch` fix). Exposes `compute_action_ref`,
    `compute_action_ref_v2`, `_validate_domain`, `OutOfProfileDomainError`.
    `action-ref-v2/validate.py` does not import this file — its digest logic and
    `action_ref_version()` grammar check are self-contained.
  - Normative spec (not vendored, cited): `docs/spec/action-ref.md` — the Domain
    paragraph (in the "Derivation" section) and the "Version negotiation" section.
    The scope-empty-string reversal this family's `av-003`/`av-007` vectors test is
    dated 2026-08-15 in the spec's changelog; a separate erratum note (dated
    2026-08-25) documents that the immutable `action-ref-v1.0` tag was never
    updated to match.

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
- 2 additional version-marker negative vectors (`version_marker_negative_vectors` in
  `action-ref-v2.fixture.json`) assert that `action_ref_version()` rejects same-length strings
  that are not valid lowercase hex — an uppercase-hex string and a non-hex string, both 64
  characters. Before this submission's review, `action_ref_version()` checked only length and
  the `v2:` prefix, so both would have been misread as valid v1 action_refs; the grammar is now
  enforced with a regex requiring lowercase hex (`fullmatch`, not `match` — see below), matching
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
- `action_ref_version()`, both here and in the vendored `action_ref.py`, now uses `fullmatch`
  instead of `match`: a regex's trailing `$` matches at end-of-string OR immediately before a
  trailing newline, so `match` alone accepted a valid 64-hex digest with a trailing `\n`
  appended as though it were clean. Two more negative vectors were not added to the fixture for
  this specific case (the two already-empty `version_marker_negative_vectors` entries showed the
  grammar-enforcement mechanism; a third and fourth entry for the newline variant would test the
  same mechanism again, not a new property) — the fix and its behavior are covered by tests in
  the upstream repository instead (`plugins/agt_evidence_anchor/tests/test_action_ref.py`).

## Profile boundary

The lab's own corpus already vendors an older Argentum family
(`runners/ts/sk-function-invocation/test-fixtures/argentum-core/`,
`recompute-drift-v1-positive`/`-negative`, pinned to `b4e03c2` and labeled
`spec_stable_ref: action-ref-v1.0`, fetched 2026-06-15) that predates this repository's
2026-07-29 Domain-paragraph enforcement. That family's `0002-unicode-fields` and
`0003-empty-scope` are POSITIVE cases: a non-ASCII `agent_id` and an empty `scope` are both
valid under the frozen `action-ref-v1.0` tag's rules. This submission's `nfc-001`/`nfc-002`
(non-ASCII/surrogate-pair `agent_id`) and `av-007` (empty `scope`) vectors reject those same
shapes of input, because they test the **live** profile at the pinned commit, which enforces the
Domain paragraph the historical tag does not.

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
