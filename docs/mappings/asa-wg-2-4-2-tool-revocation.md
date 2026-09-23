# Candidate mapping: ASA-WG AI Agent Specification 2.4.2, revocation after setup and unresolvable revocation status

| field | value |
|---|---|
| source | [appdefensealliance/ASA-WG](https://github.com/appdefensealliance/ASA-WG), `AI Profile/AI Agent Specification.md` |
| revision read | merge commit `e874cfa7f018af1355291f62c0bdaa4fa650dd16` (pull request #437), file sha256 `5e05da9b0cbe8840cb8e035405afa9816bc1341862547864d0a49aa99127e574` |
| section mapped | 2.4.2 Verifiable Tool Identity & Provenance, lines 635 to 653: the Test Procedure bullets (644 to 646) and the Verification bullets Allowlist / Registry Enforcement (650) and Fail Closed (653) |
| status | candidate mapping against text merged into `develop`, the working group's working branch, not yet Steering Committee approved `main`. Not an ASA-WG conformance claim |
| lab commit | `6261f97b6b54173e6b0fcc770e9b94381de58d20` |

Section 2.4.2 requires the Agent to "refuse unknown or revoked tools" (line 650) and to fail closed on a revoked tool rather than invoke it for a sensitive action (line 653). Its Test Procedure exercises a revoked tool identity (line 645) and a catalog change after pinning (line 646). This record maps one stated revocation requirement to a post-setup case the test procedure does not spell out, and one revocation-resolution case the section leaves unspecified. The families were written for other sources and are used here unchanged.

## Mapping

### Case A. A tool revoked after session establishment

Stated requirement: lines 650 and 653. Line 645 repeats the shadow-server attempt with a revoked tool identity, without saying whether the revocation happens before or after the session is established. The mid-session case in the procedure (line 646) changes a tool definition or schema, not revocation state.

Family: [`fixtures/cached-authorization-revocation`](../../fixtures/cached-authorization-revocation/)

- `CAR-02`: a grant is authorized, the cache is warmed, the grant is revoked, and the same credential is used again past the declared propagation limit on the retained session, after reconnecting, and on a second worker. Every call on the revoked credential is denied and the downstream test double records no attempt for any of them, while the independent grant in the same case still works.
- `CAR-03`: denial past the freshness limit and past the propagation limit, with no downstream attempt recorded for either.
- Controls: `CAR-01` (no revocation anywhere, the allow path works) and `CAR-04` (an independent grant still works after the other one is revoked).
- Boundary case `CAR-06`: the operation reaches the downstream double, the grant is then revoked, and a revocation error comes back at response time. The family counts this as not being enforcement evidence. It illustrates the failure shape line 653 is meant to prevent, a refusal that arrives only after the downstream operation has already run.
- Negative control `stale-cache`: it serves any cached allow it holds for the session. It fails exactly its declared set, which includes `CAR-02`, `CAR-03` and `CAR-04`.

What the reference harness establishes: an earlier successful check does not keep authorizing after the state behind it is revoked, and the denial lands before the downstream operation runs, on every reuse surface the family exercises.

What it does not establish about 2.4.2: the family revokes an authorization grant at an MCP server's enforcement point, not a tool identity at an Agent. The shared part is the failure shape, a check that passed at setup, a revocation after it, and a later sensitive call on the same session. The outcomes are determinate only because the family declares a propagation limit (5000 ms) and a freshness limit (2000 ms). Section 2.4.2 declares no such window, so a test of Case A against 2.4.2 needs one declared by the Agent or by the procedure.

### Case B. Revocation status cannot be established

Stated requirement: none directly. Line 651 requires the Agent to verify server identity and tool-catalog integrity at session establishment, and line 653 lists unknown, revoked, and post-pinning-altered tools as the fail-closed cases. The text does not say what the Agent does when it cannot establish whether a tool is currently revoked. This case maps to that gap, not to a stated rule.

Family: [`fixtures/revocation-resolution-forward-compat`](../../fixtures/revocation-resolution-forward-compat/)

- Direct case, `C19-13-resolver-throws`: the revocation lookup fails. Result `indeterminate`, code `REVOCATION_UNKNOWN`, never `valid`.
- Related candidate cases, `C19-03` to `C19-12` and `C19-14`: the lookup returns something that is not a recognized revocation state. The verifier does not round it into `valid`.
- Controls: `C19-01` (active, `valid`) shows the chain itself is sound, and `C19-02` (revoked, `invalid` with `REVOKED`) shows a real revocation is still reported as one.
- Related case in the other family, `CAR-07`: the authority is taken offline after warming, a cached allow is served inside the freshness limit, and the call past that limit is denied with reason `freshness_not_establishable` and never reaches the tool.

What the positive verifier establishes: "could not establish" is kept apart from both valid and revoked, and it does not authorize.

What it does not establish about 2.4.2: C19 verifies an `AuthorityDelegationV1` chain in the APS SDKs, not a tool identity or catalog. The fail-closed rule for unrecognized answers is a candidate rule in this lab that draft-pidlisnyi-aps-03 does not define in general. Nothing here says 2.4.2 intends Case B to fail closed. It is a case the text leaves open.

## Reproducing

From the lab commit above:

```sh
npm ci --include=dev
npm run verify:cached-authorization-revocation
npm run verify:revocation-resolution-forward-compat
python3 fixtures/revocation-resolution-forward-compat/validate.py
```

Recorded at that commit: cached-authorization-revocation passed, with `correct` matching every case and `stale-cache` failing exactly the declared set. C19 TypeScript 14/14 against `agent-passport-system` 7.1.0, and C19 Python 14/14 against the published `agent-passport-system` 4.1.0. cached-authorization-revocation runs the lab's own reference harness, not an SDK.

## Boundaries

- These vectors were not written for ASA-WG, and nothing here says the working group adopted any of this behavior.
- Neither family tests an Agent, an MCP server under test, or the ADA Malicious Reference Tool. They exercise a reference harness and the APS SDKs.
- The mapping is one reading of the text at `e874cfa7`. It can be wrong, and corrections go to the lab.
- Only lines 645, 650, 651 and 653 are read against. Nothing here maps allowlist enumeration, provenance surfacing, catalog tamper detection or transports.
- The families keep their own status and sources. `cached-authorization-revocation` is a candidate family against proposed OWASP MCP Top 10 text, and `revocation-resolution-forward-compat` is a candidate rule the APS draft does not define in general.
