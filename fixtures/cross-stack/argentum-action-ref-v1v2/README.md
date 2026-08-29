# argentum-action-ref-v1v2: external-system vector family

Seventeen vectors from `giskard09/argentum-core`'s `action_ref` conformance corpus, mirrored
here at commit `4aaa6eeb9748e4bc93d02a001705051938009ef1` (branch `main`), following the
invitation in
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
- **3 domain-separation vectors + 4 version-marker negative vectors** (`action-ref-v2/`) — same
  preimage, two derivations (`action_ref_v1`: bare SHA-256; `action_ref_v2`: domain-tagged,
  `mycelium.action-ref:v2:` prepended and a `v2:` prefix on the result); the three pinned
  preimages show the two derivations differ. `arv2-001`'s preimage is the same worked example
  already published in `docs/spec/action-ref.md`'s "Serialization — JCS" section. `validate.py`
  also enforces `action_ref_version()`'s grammar (lowercase hex only, `fullmatch` not `match`,
  per spec) against four negative cases — a same-length uppercase-hex string, a same-length
  non-hex string, and a bare/`v2:`-prefixed valid digest each with a trailing newline (the
  `fullmatch`-vs-`match` case). None of the four is a valid v1 or v2 action_ref; all four must
  raise, not be misread by length or prefix alone. Before hashing anything, `validate.py` also
  checks the
  fixture's declared `hash_algo`/`preimage_format`/`domain_tag` against what it implements, and
  each preimage's exact key set — a fixture edited to a different tag or an extra field fails
  loudly instead of validating silently against the wrong profile.

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
PASS vm-neg-003 (rejected: bare 64-hex v1 digest with a trailing newline — fullmatch must reject it (a regex using match/search would accept it, treating the newline as trailing garbage after a valid match), so it must raise ValueError, not be misread as v1)
PASS vm-neg-004 (rejected: v2-prefixed digest with a trailing newline — same fullmatch-vs-match distinction as vm-neg-003, applied to the v2: prefix form, must raise ValueError, not be misread as v2)

All 7 vectors PASSED
```

## Verification split

One entry per verification claim: layer / claim; runner; Mode A | Mode B; author-produced | independent; implementation.

- action-ref-v2 digests (`jcs_payload`, `action_ref_v1`, `action_ref_v2`, 3 preimages); giskard09; Mode A; author-produced (author of the vectors and of argentum-core); `action-ref-v2/validate.py` at a9312c0, 3/3
- action-ref-v2 digests, same claim; aeoess; Mode B; independent; Python 3.14.6 stdlib `json` + `hashlib`, no argentum code, 9/9 values
- domain rejection verdict and field (10 vectors); giskard09; Mode A; author-produced (author of the implementation under test); `action-ref-v1-domain-negative/validate.py` with the zero-hash assertion at a9312c0, 10/10
- domain rejection verdict and field, same claim; aeoess; Mode B; author-produced (originator of eight of the ten vectors via argentum-core#35 and draft-etcheverry-action-ref#6); spec-derived checker from the Domain paragraph at a9312c0, no argentum code, 10/10
- `action_ref_version()` grammar (2 negative vectors plus the 2 newline vectors from round 3); giskard09; Mode A; author-produced (author of the implementation under test); `fullmatch` in `action-ref-v2/validate.py`
- `action_ref_version()` grammar, same claim; aeoess; Mode B; author-produced (the negative cases were supplied in review); spec regex, 4/4
- both validators end to end; aeoess; Mode A; author-produced (vector originator on the domain layer); CPython 3.12.13 and 3.14.6, macOS, 15/15

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

The outside run from the closing paragraph adds its own entries for the domain and grammar layers when it exists.

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
- Only the Domain-rejection and v1/v2-domain-separation slices of the corpus are included, to
  keep this family small and legible; the full `action_ref` spec has additional fixture sets in
  the same upstream repository not mirrored here.
- One known erratum on the historical tag `action-ref-v1.0`: a scope-field wording conflict,
  resolved in the live spec (`docs/spec/action-ref.md`, dated 2026-08-15) but left unedited on
  the tag by policy. See `SOURCE.md`.
- **Profile boundary, not a contradiction**: the lab's own corpus already vendors an older
  Argentum family (`runners/ts/sk-function-invocation/test-fixtures/argentum-core/`, pinned to
  the frozen `action-ref-v1.0` tag, predating this repository's Domain-paragraph enforcement)
  whose `0002-unicode-fields` is a genuine POSITIVE case under that tag's rules, then and now —
  this family's `nfc-001`/`nfc-002` reject the same input shape, correctly, only because they
  test the live post-Domain profile. `0003-empty-scope`'s recorded PASS is different in kind: it
  is a historical fixture result under a wording conflict the tag's own 2026-08-25 erratum has
  since resolved, not a currently-valid alternate reading — `av-007` (empty `scope`, rejected)
  is not in tension with it. Report results against each family separately; do not aggregate
  into one pass/fail count. Full explanation in `SOURCE.md`'s "Profile boundary" section.

Per the lab charter: this submission does not ask to be listed, endorsed, or described as
APS-validated. It is a record offered for independent verification, as CONTRIBUTING.md requires
for an external-system vector family.
