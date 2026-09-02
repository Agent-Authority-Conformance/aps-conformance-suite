# attenu-guard 0.11.0: bundle-level vectors (bundle_vectors_v1), two runners over one file

Artifact: `attenu_guard/vectors/bundles/bundle_vectors_v1.json`, eight cases, schema_version 2
evidence bundles with execution binding. Announced by rafaelasor on a2aproject/A2A#1575 on
2026-09-02 as the bundle-level rows shipped ahead of the envelope rows.

## Byte identity of the vector file across its three published locations

| location | identity |
|---|---|
| PyPI wheel attenu_guard-0.11.0-py3-none-any.whl, sha256 cae895475f116deb862295b6c8938f5e586f115ea20bdd6df2f6b2e38df880b0 | file sha256 90d7fa70eabe92cbfa4df04bad50ac78995b57e83812cc5671e1ba9de01619ce, git blob 7a78f025 |
| attenu-io/attenu-guard tag v0.11.0, src/attenu_guard/vectors/bundles/ and tests/vectors/bundles/ | blob 7a78f025 in both paths |
| attenu-io/attenu-guard-ts tag v0.6.0, test/fixtures/vectors/bundles/ | blob 7a78f025 |

One object, three locations. The npm package `attenu-guard` 0.6.0 (tarball sha256
9099da7270cda6e662a76ddf6ca08bd568bd8232970078cd1e47e76dd2377a13) ships no vector files; the
TypeScript side carries them in its repository only. The package name on npm is `attenu-guard`,
not `attenu-guard-ts`; the latter is the repository name.

## Direction 1: the author's runner (Mode A)

    python3 -m venv v && v/bin/pip install attenu-guard==0.11.0
    v/bin/python  (attenu_guard.evidence.verify_bundle over vectors.load_bundle_vectors(),
                   signer wrapped as attenu_guard.wire.HS256TestSigner(secret, kid))

Result (results-package-verify-bundles.txt, verbatim): 8/8; every required
{reason, seq, node} present; each accept/reject verdict as declared.

## Direction 2: clean-room verifier written from the README (Mode B)

`cleanroom/verify_bundle_v1.py`, written 2026-09-02 from tests/vectors/README.md at v0.11.0
(sections "Evidence bundle vectors" and "Verifying a bundle from the file alone") and the
vector file's own description field. No attenu_guard code read or imported. Dependencies:
rfc8785 0.1.4, hashlib, hmac.

    python3 -m venv cr && cr/bin/pip install -r cleanroom/requirements.txt
    cr/bin/python cleanroom/verify_bundle_v1.py <path to bundle_vectors_v1.json>

Result (results-cleanroom-verify-bundles.txt, verbatim): 8 ok, 0 mismatches, exit 0. Every
required failure reported at its declared position; first run, no adjustment after seeing
the vectors' results.

## Where the two runners differ, recorded and not adjudicated

Verdicts agree on all eight. The consequence sets (failures beyond the declared minimum,
which the scoring rule permits) differ in two cases:

- `reject_duplicate_call_id`: author's runner reports {duplicate_call_id@4/n1,
  outcome_without_allow@3/n0}. Clean-room reports those two plus params_mismatch@6/n1. The
  clean-room binds an outcome to the first allow that carried its call_id regardless of
  node; the author's runner binds within the node. The README's phrase "exactly one
  correctly-ordered outcome on the same node" admits both readings and no vector separates
  them: an outcome whose call_id was issued by an allow on a different node has no case.
- `reject_tampered_entry`: author's runner reports integrity@3/n0 plus integrity(anchor);
  clean-room reports integrity@3/n0 only. The author's runner recomputes the head and finds
  the anchor no longer commits to it; the clean-room compares the anchor to the stored last
  hash, which the tamper did not change.

Neither difference is a defect in either implementation under the published scoring rule.
They are the shape of the format's underspecified edges as of v0.11.0.

## Verification split

- Author's runner over the author's vectors (direction 1); runner: aeoess via the published
  package; Mode A; author-produced; implementation: attenu-guard 0.11.0.
- Clean-room README-derived verifier over the author's vectors (direction 2); runner: aeoess;
  Mode B; author-produced; implementation: cleanroom/verify_bundle_v1.py, authored by the
  runner.
- No independent record exists for either layer; both queued in docs/OPEN-RUNS.md.

## Not done here

The token-vector set also moved between 0.8.0 and 0.11.0 (reject_unsafe_integer,
valid_jcs_big_integer, valid_jcs_unmarked_header are new). The 0.8.0 record's clean-room -00
verifier was not re-run; that is a separate successor observation. The envelope rows
rafaelasor announced for a later drop are not in this file.
