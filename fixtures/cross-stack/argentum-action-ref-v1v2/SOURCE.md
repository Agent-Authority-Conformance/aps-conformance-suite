# Provenance: argentum-action-ref-v1v2

## Upstream

- Repository: `giskard09/argentum-core` (https://github.com/giskard09/argentum-core), Apache 2.0.
- Pinned commit: `586299a73145ef248dd855dde29dd8a079cf418b`, branch `main`. This is a re-pin from
  the original `8bdee1feb0cbaa9e1cc0b0bcfa26df802e39ed12` — see "Re-pin" below for why. Verified
  as `HEAD == origin/main` on 2026-08-29 (no divergence, no local-only commits ahead of the pin).
- Files mirrored at that commit (SHA-256 of the bytes as vendored here):
  - `examples/conformance/action-ref-v1-domain-negative/action-ref-v1-domain-negative.fixture.json`
    — `5b1549added5b90e2fb53dd6f5514e7472256b3ecc4b1267d7f8f1aaf122aa86` (unchanged since the
    original pin — this file was not touched by the re-pin's commit)
  - `examples/conformance/action-ref-v1-domain-negative/validate.py`
    — `c50bb37838bd8ba02e39d23b5daaff7e2212ad8acc233c45239b028b9e46f382`. **Not** byte-identical
    to argentum-core's copy at this commit (that copy is `901c492da2e5cdce2f4f68e82baf44e9db67f9aafd074638591ff1dd52eb0043`,
    unchanged since the original pin) — this vendored copy has argentum-core's dead
    `sys.path.insert` (resolves to the wrong directory given the documented `PYTHONPATH=.`
    invocation) removed, per aeoess's non-blocking nit from the first review pass (fixed in
    `b557fca`). Digest table entry corrected here to match; it previously cited
    argentum-core's unmodified hash by mistake.
  - `examples/conformance/action-ref-v2/action-ref-v2.fixture.json`
    — `10ad46c31892cbb2f45611dcac48438b75c55f6634dae7b8f800fd16d8885f7c` (changed by the re-pin —
    adds `version_marker_negative_vectors`, narrows the `purpose` field's collision wording)
  - `examples/conformance/action-ref-v2/validate.py`
    — `34f84244b6fae8c55dcc4957906a6f4d02fab5f105aaf1fd14c33858b33ef3c5` (changed by the re-pin —
    grammar-enforced `action_ref_version()`, fixed digest-equality comparison, new docstring)
  - Reference implementation (vendored here, at `plugins/agt_evidence_anchor/action_ref.py`
    within this directory, so `action-ref-v1-domain-negative/validate.py` resolves without
    cloning `argentum-core`) — `281feb31e8d365f21b348ee057d17b4e2ed51657308d32e861f561383e281944`
    (changed by the re-pin — same `action_ref_version()` grammar fix). Exposes
    `compute_action_ref`, `compute_action_ref_v2`, `_validate_domain`, `OutOfProfileDomainError`.
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

## Re-pin (2026-08-29)

aeoess's second review pass on this PR found four issues, addressed in commit `30445e1`. One
of them — `action_ref_version()` checking only length and prefix instead of enforcing lowercase
hex grammar — turned out not to be specific to this vendored copy: the same function in
`giskard09/argentum-core`'s production reference implementation
(`plugins/agt_evidence_anchor/action_ref.py`) had the identical gap. Fixed there too
(`giskard09/argentum-core#69`, merged as `586299a`, suite 79/79 + 63/63 green before merge), so
the fix lands in the actual upstream implementation rather than only in a copy pasted into this
submission.

Re-pinning this PR to `586299a` — rather than leaving it at the original `8bdee1feb0c...` and
noting the divergence — keeps the claim in "Files mirrored at that commit" literally true: every
vendored file byte-identical to upstream at the cited commit, not byte-identical to an older
commit plus a description of what changed since. Only three of the five vendored files actually
changed between the two commits (`action-ref-v2.fixture.json`, `action-ref-v2/validate.py`,
`action_ref.py`); the two `action-ref-v1-domain-negative/` files are untouched and keep their
original digests, noted per-file above.

## How the digests were produced

- All positive and negative expected outputs in both fixture files are computed with the
  reference implementation at the pinned commit (`compute_action_ref` for v1,
  `compute_action_ref_v2` for the domain-tagged variant), not invented or hand-typed. Each
  fixture file (not each vector — `reproduce_in_python` is a single top-level field per file,
  present in neither fixture's 13 individual vectors) carries the exact minimal procedure — RFC
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
  enforced with a regex requiring lowercase hex, matching `docs/spec/action-ref.md`.

## Independence

This family was assembled and submitted by the author of the upstream repository
(`giskard09`) — it is the author submitting their own vectors for the lab's independent
verification, not a third-party recomputation. Per `CONTRIBUTING.md`, independent verification
on the lab side (a clean-clone recompute against the pinned commit, before merge) is the
required step before an external-system vector family lands, and is expected to happen as part
of this PR's review rather than having been claimed here.

## Boundaries

- No signatures in this family — `action_ref` is a bare content-address, not an attestation.
- Only the Domain-rejection and v1/v2-collision slices of the `action_ref` corpus are mirrored
  here; the upstream repository has additional fixture sets (scope semantics, cross-surface
  consistency) not included, to keep this submission small and legible.
- One known erratum on the historical tag `action-ref-v1.0` (git tag, not a branch): a
  scope-field wording conflict, resolved in the live spec (`docs/spec/action-ref.md`, dated
  2026-08-15) but the tag itself is left unedited by upstream policy — noted here so a verifier
  reading the tag directly is not surprised.
