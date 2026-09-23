# Candidate mapping: IBM ContextForge, stale authority and propagation (#6408, #6533)

| field | value |
|---|---|
| proposal | [IBM/mcp-context-forge#6408](https://github.com/IBM/mcp-context-forge/issues/6408), "Security Policy Engine and Generalization", and its inception task [#6533](https://github.com/IBM/mcp-context-forge/issues/6533) |
| text read | #6408 body as of `updated_at` 2026-09-21T14:25:05Z, sha256 `a22ace2a51568eddd4bb51c8839e6930aae3a7e81ab02881a536c4a5ff39b1ed`. #6533 body as of `updated_at` 2026-09-07T17:46:22Z, sha256 `99ab5b37b91e07a10c71ca07f10ceba27b8eec46e297f24e3897b0b15a958173` |
| code read | `IBM/mcp-context-forge` `main` at `380469fc2d50df599124b58c9ddea8ab2d739207`, and the pinned plugin framework `cpex` 0.1.3 |
| section mapped | #6408 User Story 2 scenarios "Policy change takes effect without restart" and "Policy engine unreachable", and the fail-closed design item in #6533 Scope |
| status | candidate mapping to ContextForge acceptance requirements. Not a ContextForge conformance claim, and not a proposal to replace CEL, Cedar or the engine #6533 selects |
| lab commit | `6261f97b6b54173e6b0fcc770e9b94381de58d20` |

Both issues are open. The User Story 2 scenarios describe the intended end state of the policy engine work, not behavior shipped by default today. This record maps one existing lab family to the stale-authority and propagation requirements in that text. The family was written for another source and is used here unchanged.

## Requirements

1. Policy change propagation. #6408 line 108: "new requests are evaluated against the updated policy within the configured propagation window".
2. Engine unavailable. #6408 line 120: "the gateway applies the configured fail-closed fallback (deny by default)".
3. Cached decisions. #6533 line 69 asks for fail-closed failure modes in which "cached decisions must never turn a denial into an allow". This record maps the stale-allow side of that item only. See Boundaries.

## Family

[`fixtures/cached-authorization-revocation`](../../fixtures/cached-authorization-revocation/)

### Requirement 1, propagation

- `CAR-02`: a grant is authorized and cached, then revoked. Past the declared propagation limit, the same credential is denied on the retained session, after reconnecting, and on a second worker, and the downstream test double records no attempt for any of those calls.
- `CAR-03`: denial past the freshness limit and again past the propagation limit, with no downstream attempt recorded for either.

The family declares both windows as parameters (propagation 5000 ms, freshness 2000 ms). The outcomes are determinate only because those limits are declared, which is the same role "the configured propagation window" plays in requirement 1.

### Requirement 2, engine unavailable

- `CAR-07`: the authority is taken offline after a prior allow. A cached allow is served inside the freshness limit. Past that limit the call is denied with reason `freshness_not_establishable`, and the downstream double records no attempt.

### Controls

- `CAR-01`: no revocation anywhere in the timeline. Unchanged authority keeps working.
- `CAR-04`: an independent grant, warmed before another grant is revoked, still performs its operation afterwards.
- Negative control `stale-cache`: it serves any cached allow it holds for the session. It fails exactly its declared set, which includes `CAR-02`, `CAR-03`, `CAR-04` and `CAR-07`.

Every denial above is read from the downstream double's own record (`downstream_reached`), not from what the enforcement point reports about itself. That is the evidence that the deny lands before the protected operation runs.

## What the code at `380469fc` shows

Read from source, not executed.

- The policy decision point is a plugin. The plugin framework is off by default (`mcpgateway/plugins/__init__.py:41`, `_PLUGINS_ENABLED = False`) and `UnifiedPDPPlugin` ships as `mode: "disabled"` (`plugins/config.yaml:1269`). Everything below applies only when an operator enables both.
- `PolicyDecisionPoint.check_access` returns a cached decision before evaluating any engine (`plugins/unified_pdp/pdp.py:161`) and caches every result, allow and deny (`pdp.py:185`, `plugins/unified_pdp/cache.py:219`). The default lifetime is 60 seconds (`plugins/unified_pdp/pdp_models.py:174`).
- `DecisionCache.invalidate` (`cache.py:261`) has no caller outside `cache.py`. A policy change does not evict cached decisions, so the time for a change to reach a cached request is bounded by cache lifetime rather than by an invalidation event.
- With Redis configured, a Redis hit repopulates the in-memory layer with a fresh full lifetime (`cache.py:211`). The oldest decision a worker can serve is then longer than `ttl_seconds`.
- An engine timeout or evaluation error yields the configured `default_decision` (`pdp.py:262` to `287`), which defaults to deny (`plugins/unified_pdp/unified_pdp.py:148`). Because the cache is consulted first, a cached allow is still served while the engine is unreachable, until it expires. That is the `CAR-07` shape.

## Reproducing

From the lab commit above:

```sh
npm ci --include=dev
npm run verify:cached-authorization-revocation
```

Recorded at that commit: `correct` matched every case and `stale-cache` failed exactly the declared set. The family runs the lab's own reference harness, not ContextForge and not an SDK.

## Boundaries

- ContextForge's current implementation uses a general policy-decision cache, while this family revokes an authorization grant. The mapping is to the stale-authority and propagation failure shape, not to identical state or cache semantics.
- Nothing here was run against ContextForge. The code observations are one reading of `380469fc` and can be wrong.
- The PDP path is opt-in on current `main`, and the User Story text describes the intended end state, not default shipped behavior.
- Requirement 3 has two sides. This family covers only a cached allow that outlives the authority behind it. The literal case in #6533, a cached denial served as an allow, has no vector in this lab and is not claimed here.
- Only the three requirements above are mapped. Nothing here maps authentication outsourcing, JWT trust mode, the Layer 1 and Layer 2 split, scope narrowing, latency, or the CoSAI hard constraints.
- `cached-authorization-revocation` keeps its own status and source. It is a candidate family against proposed OWASP MCP Top 10 text, and nothing here says ContextForge adopted any of it.
