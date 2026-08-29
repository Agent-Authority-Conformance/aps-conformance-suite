# argentum-action-ref-v1v2: external-system vector family

Fifteen vectors from `giskard09/argentum-core`'s `action_ref` conformance corpus, mirrored here
at commit `8bdee1feb0cbaa9e1cc0b0bcfa26df802e39ed12` (branch `main`), following the invitation in
[a2aproject/A2A#1628](https://github.com/a2aproject/A2A/issues/1628) to put the Argentum sets
through the lab end to end.

- **10 domain-rejection vectors** (`action-ref-v1-domain-negative/`) — malformed timestamp
  grammar, non-ASCII/surrogate-pair `agent_id`, and empty scope, each expected to raise
  `OutOfProfileDomainError` with a named reason (`timestamp`, `agent_id`, `scope`) before any
  digest is computed. These vectors trace directly to
  [giskard09/argentum-core#35](https://github.com/giskard09/argentum-core/issues/35)
  (2026-07-29) — a bug report that the reference implementation hashed inputs the Domain
  paragraph said to reject. Both the fix and this fixture set came out of that report the same
  day.
- **3 domain-separation vectors + 2 version-marker negative vectors** (`action-ref-v2/`) — same
  preimage, two derivations (`action_ref_v1`: bare SHA-256; `action_ref_v2`: domain-tagged,
  `mycelium.action-ref:v2:` prepended and a `v2:` prefix on the result); the three pinned
  preimages show the two derivations differ. `arv2-001`'s preimage is the same worked example
  already published in `docs/spec/action-ref.md`'s "Serialization — JCS" section. `validate.py`
  also enforces `action_ref_version()`'s grammar (lowercase hex only, per spec) against two
  negative cases — a same-length uppercase-hex string and a same-length non-hex string, neither
  of which is a valid v1 or v2 action_ref and both of which must raise, not be misread by
  length/prefix alone.

## Recompute — no checkout of argentum-core needed

`validate.py`'s digest logic (JCS + SHA-256) and `action_ref_version()`'s grammar are
self-contained in this directory — no import from the vendored `action_ref.py` is needed to run
`action-ref-v2/validate.py`. `action-ref-v1-domain-negative/validate.py` does import the
vendored `plugins/agt_evidence_anchor/action_ref.py`, which is vendored in this directory
alongside the fixtures so it resolves without cloning `argentum-core`.

```bash
cd fixtures/cross-stack/argentum-action-ref-v1v2
PYTHONPATH=. python3 action-ref-v1-domain-negative/validate.py
PYTHONPATH=. python3 action-ref-v2/validate.py
```

Stdlib-only (`hashlib` + `json` + `re`), no network, no third-party packages.

## Verbatim recompute run (2026-08-29, against the pinned commit)

```
$ PYTHONPATH=. python3 action-ref-v1-domain-negative/validate.py
PASS adn-001 (rejected (timestamp))
PASS adn-002 (rejected (timestamp))
PASS adn-003 (rejected (timestamp))
PASS adn-004 (rejected (timestamp))
PASS adn-005 (rejected (timestamp))
PASS av-003 (rejected (scope))
PASS av-007 (rejected (scope))
PASS epoch-ms-001 (rejected (timestamp))
PASS nfc-001 (rejected (agent_id))
PASS nfc-002 (rejected (agent_id))

All 10 vectors PASSED

$ PYTHONPATH=. python3 action-ref-v2/validate.py
PASS arv2-001
PASS arv2-002
PASS arv2-003

PASS vm-neg-001 (rejected: uppercase hex, 64 chars — same length as a valid v1 digest but not lowercase, must raise ValueError, not be misread as v1)
PASS vm-neg-002 (rejected: non-hex characters, 64 chars — same length as a valid v1 digest but not hex, must raise ValueError, not be misread as v1)

All 5 vectors PASSED
```

## Boundaries

- `validate.py`'s digest-equality check (comparing the v1 digest against the v2 digest with its
  presentation prefix stripped) is a defensive invariant assertion, not something any vector in
  this file can actually exercise: `compute_v2` recomputes the v2 digest straight from the
  preimage, so a fixture whose stored `action_ref_v2` doesn't match what `compute_v2` produces
  fails on "v2 digest mismatch" before digest equality is ever compared. The only way to reach
  that branch is a real SHA-256 collision between the domain-tagged and bare digests of the same
  preimage — the assertion exists to catch that if it ever happens, and it is fine that no
  ordinary or adversarial vector can drive it.
- No signatures in this family — `action_ref` is a bare content-address, not an attestation.
  Nothing here exercises key resolution or a trust anchor.
- Only the Domain-rejection and v1/v2-collision slices of the corpus are included, to keep this
  family small and legible; the full `action_ref` spec has additional fixture sets in the same
  upstream repository not mirrored here.
- One known erratum on the historical tag `action-ref-v1.0`: a scope-field wording conflict,
  resolved in the live spec (`docs/spec/action-ref.md`, dated 2026-08-15) but left unedited on
  the tag by policy. See `SOURCE.md`.

Per the lab charter: this submission does not ask to be listed, endorsed, or described as
APS-validated. It is a record offered for independent verification, as CONTRIBUTING.md requires
for an external-system vector family.
