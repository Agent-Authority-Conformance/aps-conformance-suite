# giskard09's report on issue #72, copied verbatim (his text, his codepoints, including an em dash)

## comment 5551733751, 2026-09-05T12:14:13Z

@kenneives — yes, happy to take this on, same terms as before: our implementation, our machine, built from the published vectors only (not looking at `admissibility.py`). Will implement the claim-model independently against the closed claim_type set + scope/composition/expiry rules, run it against the five fixtures at `a642c17`, and post pass/fail-closed + error code per fixture here once it's done. No timeline promise yet — will follow up on this thread when it's ready.

## comment 5551782874, 2026-09-05T12:21:49Z

@kenneives — independent claim-model checker built from scratch against the published vectors and fixture shapes only (SOURCE.md + fixtures/*.json/jwks.json — didn't look at `plugins/admissibility.py` or the rest of `plugins/`). Verified the five fixtures at `a642c17` byte-exact against the tree first (blob SHA match via `git hash-object`), then re-derived JCS canonical bytes/SHA-256 against each fixture's declared values before applying the claim model, before checking claim-type/scope/composition/expiry.

Results (5/5 match):
- positive-authority: pass
- negative-scope-violation: fail-closed / INVALID_CLAIM_SCOPE
- negative-composition-failure: fail-closed / INVALID_COMPOSITION
- negative-missing-claim-type: fail-closed / INVALID_CLAIM_SCOPE
- negative-expired: fail-closed / EXPIRED

Also ran a few adversarial cases beyond the five (tampered signature, out-of-set claim_type, valid multi-chain composition, boundary `expires_at == verification_time`) to check the checker isn't overfit to just the given vectors — all behaved as expected. Record sits with the lab now.

