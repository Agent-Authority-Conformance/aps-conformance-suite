# attenu-guard 0.13.0: observer-envelope vectors (envelope_vectors_v1), three runners over one file

Artifact: `attenu_guard/vectors/envelopes/envelope_vectors_v1.json`, revision
`envelope_vectors_v1.1`, 18 cases, Ed25519 observer envelopes over committed ledger entries of
the same nine-entry ledger the bundle file uses. Announced by rafaelasor on a2aproject/A2A#1575
on 2026-09-03 (comment 5530281144) as shipped in attenu-guard 0.13.0 on PyPI and attenu-guard
0.8.0 on npm, byte-identical, sha256
`6a57d75ebec881d39d5a1805793a20f9a6d7bff021b70782dcb57c43b276df64`. This is the successor to
the bundle-level record at `interop/attenu-guard-0.11.0-bundles/`: same scope, same shape.

## Byte identity of the vector file across its published locations

| location | identity |
|---|---|
| PyPI wheel attenu_guard-0.13.0-py3-none-any.whl, sha256 87002b153105b007d111e7264e8133f0db4a6116276127fa0996ccd0cbf328dd, path `attenu_guard/vectors/envelopes/envelope_vectors_v1.json` | file sha256 6a57d75ebec881d39d5a1805793a20f9a6d7bff021b70782dcb57c43b276df64, git blob 112d5eca |
| attenu-io/attenu-guard tag v0.13.0, `src/attenu_guard/vectors/envelopes/` | blob 112d5eca, file sha256 6a57d75e |
| attenu-io/attenu-guard tag v0.13.0, `tests/vectors/envelopes/` | blob 112d5eca, file sha256 6a57d75e |
| attenu-io/attenu-guard-ts tag v0.8.0, `test/fixtures/vectors/envelopes/` | blob 112d5eca, file sha256 6a57d75e |

One object, four locations, 185227 bytes, and the sha256 the announcement names. The npm package
`attenu-guard` 0.8.0 (tarball sha256
640887a0daf147f233658a94527b2e72a3d7be711d126ca11ecab17e12ff3b75) ships no vector files: 128
entries, three of them JSON, all three `package.json`. The TypeScript side carries the vectors in
its repository only, as it did at 0.6.0. The package name on npm is `attenu-guard`, not
`attenu-guard-ts`; the latter is the repository name.

Rows 17 and 18, `reject_duplicate_subject` and `reject_unknown_alg`, are a v1.1 of the contract
and not a v0.1 amendment: they add the seventh named failure and the per-entry uniqueness rule
that a second envelope over one entry makes that entry process-asserted. `version` stays
`envelope_vectors_v1`, which is the compatibility contract; `revision` is `envelope_vectors_v1.1`.

## Direction 1: the author's runners (Mode A), Python and TypeScript

Python, from the downloaded wheel:

    python3 -m venv pkg && pkg/bin/pip install attenu_guard-0.13.0-py3-none-any.whl
    pkg/bin/python  (attenu_guard.evidence.verify_bundle(bundle, signer, witness_keys=...)
                     over vectors.load_envelope_vectors(), signer wrapped as
                     attenu_guard.wire.HS256TestSigner(secret, kid), and envelope_bytes
                     supplied from the case's raw_hex where it carries one)

Result (results-package-verify-envelopes.txt, verbatim): 18/18. Every verdict as declared, every
required {reason, seq, node} present at its declared position, and `expect_states` matched entry
by entry for all nine entries of every case.

TypeScript, the npm package, scored over the byte-identical copy of the same file:

    npm init -y && npm install attenu-guard@0.8.0
    node run.js <envelope_vectors_v1.json>   (verifyBundle(bundle, signer, {witnessKeys, envelopeBytes}))

Result (results-ts-verify-envelopes.txt, verbatim): 18/18, and the same failure set on every case
as the Python runner, position for position.

Two shape notes on the comparison, recorded because the README's scoring snippet does not mention
them and neither is a verdict difference. `report["envelopes"]["states"]` is keyed by integer while
`expect_states` is keyed by string, as JSON object keys always are, so a harness that compares them
directly reports a mismatch on every case; the runs above stringify the report's keys and compare
nothing else. `report["failure_details"]` entries carry `call_id` and `detail` beside
`{reason, seq, node}`, so each is projected to the triple before the presence check. Both notes are
printed in the results files themselves.

## Direction 2: clean-room verifier written from the README (Mode B)

`cleanroom/verify_envelope_v1.py`, written 2026-09-04 from `tests/vectors/README.md` at
attenu-io/attenu-guard v0.13.0 (sections "Observer envelope vectors", "The envelope", "The seven
named failures", "Scoring, and the two rules on where a failure may land") and the vector file's
own description field. No attenu_guard code was read or imported, Python or TypeScript: the file
was written and first run before the package was installed for direction 1. The bundle-level half
(chain hashes, anchor, authority, containment, execution binding) is carried unchanged from this
lab's own clean-room verifier for the bundle vectors,
`interop/attenu-guard-0.11.0-bundles/cleanroom/verify_bundle_v1.py`, written from the same
README's bundle sections. Dependencies: rfc8785 0.1.4, cryptography 50.0.1, hashlib, hmac.

    python3 -m venv cr && cr/bin/pip install -r cleanroom/requirements.txt
    cr/bin/python cleanroom/verify_envelope_v1.py <path to envelope_vectors_v1.json>

Result (results-cleanroom-verify-envelopes.txt, verbatim): 18 ok, 0 mismatches, exit 0. First run,
no adjustment after seeing the vectors' results. `canonical_hex` on `valid_jcs_reorder` was scored
on both halves: the row accepts, and the bytes the verifier canonicalized equal the row's
`canonical_hex`.

## Where the runners differ, recorded and not adjudicated

They do not differ. On all 18 cases the three runners agree on the verdict, on every reported
`{reason, seq, node}` including the permitted extras, and on the state of every entry. The extras
are the same in each: `reject_non_canonical` reports `envelope_bad_signature` beside the required
`envelope_non_canonical`, which the README names as permitted for a verifier that recomputes the
signing preimage, and `reject_rehashed_chain_anchored` reports the mismatch at seq 2 beside the
required one at seq 1, which the README names as an extra on a covered hop.

Two readings the clean-room had to choose, neither separated by any vector in this file:

- An envelope whose `v` or `typ` this build does not know stops that envelope's remaining checks.
  The README says such an envelope is `envelope_unknown_version` and does not say whether the
  member, subject, witness and signature checks still run. `reject_unknown_version` is signed
  correctly and is otherwise a valid envelope, so no vector separates a verifier that stops from
  one that continues: both report the same single failure. The author's runner reports the same
  single failure, so it is either stopping or finding nothing further.
- `witness_keys` is deployment input rather than attacker input, so the clean-room raises on a
  malformed row there, naming its `kid`, rather than folding it into a finding about the bundle.
  The README states that rule; no case in this file carries a malformed `witness_keys` row, so
  nothing here exercises it in either implementation.

## Verification split

- Author's runner over the author's vectors, Python (direction 1); runner: aeoess via the
  published PyPI wheel; Mode A; author-produced; implementation: attenu-guard 0.13.0.
- Author's runner over the author's vectors, TypeScript (direction 1); runner: aeoess via the
  published npm package; Mode A; author-produced; implementation: attenu-guard 0.8.0 on npm.
- Clean-room README-derived verifier over the author's vectors (direction 2); runner: aeoess;
  Mode B; author-produced; implementation: cleanroom/verify_envelope_v1.py, authored by the
  runner.
- No independent record exists for any of the three layers; all three are queued in
  docs/OPEN-RUNS.md.

## What this record does not establish

It does not verify attenu-guard's behaviour beyond these 18 cases: three runners agreeing on one
file is agreement on that file. It is not an adoption or endorsement claim by or about either
project, and nothing here is posted anywhere. It says nothing about the row the author's
announcement still marks open, that envelopes sit outside the anchor so a stripped array reads as
never having existed, which the vectors README carries under "Known limits of envelope v1" and
which the author states is a v2 question. The agreement between the Python and TypeScript runners
is agreement between two implementations by one author, not an independent recomputation.

## Not done here

The bundle-level record at `interop/attenu-guard-0.11.0-bundles/` was not re-run against 0.13.0;
whether the eight bundle cases still score as they did is a separate successor observation. The
token vectors were not re-run either.
