# Candidate mapping: AAIF Identity and Trust WG #5, freshness and revocation

| field | value |
|---|---|
| proposal | [aaif/wg-identity-and-trust#5](https://github.com/aaif/wg-identity-and-trust/issues/5), "evidence-strength labels", revision 2 of 2026-08-28 |
| text read | issue body as of `updated_at` 2026-08-28T10:09:22Z, sha256 `bc0626addb02422f0a160bd1b08be095cd4d74b396c6925c87174dc466a29925` |
| section mapped | "A separate dimension: freshness and revocation", its three rules, and open question 5 |
| status | candidate mapping against a proposal, not an AAIF conformance claim |
| lab commit | `fec93192e844e6b94aec01cd4de579e65bec8bab` |

The proposal asks for a worked example that would validate the freshness dimension (open question 5, suggested next step 3). This record maps three existing lab families to the three freshness and revocation rules the proposal states. The families were written for other sources and are used here unchanged.

## Mapping

### Rule 1. "The verifier takes a revocation store and fails closed when it cannot answer."

Family: [`fixtures/revocation-resolution-forward-compat`](../../fixtures/revocation-resolution-forward-compat/)

- Direct case, `C19-13-resolver-throws`: the revocation lookup fails. Result `indeterminate`, code `REVOCATION_UNKNOWN`, never `valid`.
- Related candidate cases, `C19-03` to `C19-12`: the store does return something, but it is not a recognized revocation state (an unknown status string, null, a number, a boolean, an object, an array). The verifier refuses to round that into `valid` and returns `indeterminate` with `REVOCATION_UNKNOWN`. The proposal does not say an unrecognized answer is the same as no answer, so these are adjacent to the rule rather than a direct instance of it.
- Controls: `C19-01` (active, `valid`) shows the chain itself is sound, and `C19-02` (revoked, `invalid` with `REVOKED`) shows a real revocation is still reported as one.

What the positive verifier establishes: when revocation state cannot be established, the result is not valid, and it is kept apart from an actual revocation. This family has no deliberately wrong verifier. Its controls are the active and revoked cases.

### Rule 2. "It reports checks it did not perform rather than counting them as passes."

Family: [`fixtures/key-rotation-historical`](../../fixtures/key-rotation-historical/)

- `KRH-01`: a delegation signed with a key that was later retired, with evidence that it was signed before the retirement. Result `valid`.
- `KRH-05`: the same delegation and key with that evidence absent. The check that the key was authorized at signing time cannot be performed, so the result is `indeterminate`, not `valid`.
- Negative control `claim-trusting`: it accepts the issuer's own claimed signing time as if the check had been performed. It returns `valid` for `KRH-05` and fails exactly that vector.

What the positive verifier establishes: a check it could not perform is reported as not established. The evidence record in this family is a test profile made for the fixture. It is not a proposed format.

### Rule 3. "A verifier without freshness information says so rather than rounding up."

Family: [`fixtures/cached-authorization-revocation`](../../fixtures/cached-authorization-revocation/)

- `CAR-07` (request `r3`): an earlier authorization is cached, the authority is unreachable, and the cached decision is past its freshness limit. The call is denied with reason `freshness_not_establishable` and never reaches the tool.
- `CAR-09` (request `r3`): the authority is reachable but has no usable state for the grant, and the cached decision is past its freshness limit. The call is denied with reason `grant_state_unresolvable`.
- Negative control `stale-cache`: it serves the cached allow. It allows both calls with reason `cached_authorization_decision` and fails both vectors.

What the positive verifier establishes: when freshness cannot be established, the enforcement point says why and denies, instead of treating an older allow as current.

## Reproducing

From the lab commit above:

```sh
npm ci --include=dev
npm run verify:revocation-resolution-forward-compat
npm run verify:key-rotation-historical
npm run verify:cached-authorization-revocation
```

Recorded at that commit: C19 TypeScript 14/14 and Python 14/14, key-rotation-historical passed on both runners with `claim-trusting` failing exactly `KRH-05`, cached-authorization-revocation passed with `stale-cache` failing exactly its declared set, which includes `CAR-07` and `CAR-09`. The SDK-backed families ran against `agent-passport-system` 7.1.0 for TypeScript and the published `agent-passport-system` 4.0.0 for Python. cached-authorization-revocation runs the lab's own reference harness, not an SDK.

## Boundaries

- These vectors were not written for AAIF, and nothing here says the working group adopted any of this behavior.
- The mapping is one reading of revision 2. It can be wrong, and corrections go in the thread.
- Only the freshness and revocation dimension is mapped. Nothing here maps axis A, axis B, or the weakest-hop rule.
- The families keep their own status and sources. `cached-authorization-revocation` is a candidate family against proposed OWASP MCP Top 10 text, and the fail-closed rule for unrecognized revocation answers in `revocation-resolution-forward-compat` is a candidate rule that draft-pidlisnyi-aps-03 does not define in general.
