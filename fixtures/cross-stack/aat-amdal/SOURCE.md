# AAT pair corpus (AgentLair x AEOESS weekly cadence)

Source: emailed by Pico Amdal (pico@amdal.dev), schema aat-pair-v1 as agreed 2026-06-11.
Bootstrap pair authored 2026-06-12T01:08:30Z; regular Wednesday drops begin 2026-06-17.
Issuer JWKS: https://agentlair.dev/.well-known/jwks.json (kid ab0502f7, Ed25519), fetched
live at ingestion; both signatures verified locally with an independent stdlib+cryptography
path. See ingestion-check-2026-06-12.json.

Pipeline finding from the bootstrap run: the live-half token (60m TTL) expired in transit
before ingestion (exp 02:06:01Z, ingested 02:1xZ). Signature checks are durable; window
status is not. Schema amendment proposed for v2: each vector carries verification_time,
the reference instant at which expected_result holds; runners evaluate the window against
that instant, signature checks stay live. Without it, live vectors rot and the corpus is
not replayable.

What this corpus does and does not cover: issuer signature validity and window semantics
for AAT bearer tokens at the APS verification boundary. It does not assert anything about
the bearer agent behavior, audit history accuracy, or APS receipt semantics.

Schema as of 2026-07-29: per-vector verification_time is mandatory. Every vector carries the
reference instant at which its expected_result holds, and runners evaluate both window bounds
against that instant. A file-level authored_at is metadata and is never used for window
evaluation. The subject is pinned per drop: all vectors in a drop carry one sub and one
al_name, recorded as an observation rather than enforced as a check.

Verification is automated by runners/aat_runner.py. Issuer JWKS URL and pinned kid live in
runners/issuers/, so a new issuer is a config entry rather than a new script.

Scope, restated for the automated corpus: it covers issuer signature validity and both window
bounds, and nothing else. It asserts nothing about the bearer agent, its audit history, or APS
receipt semantics. A run records what was executed against which bytes by which operator at
which time. It is not a conformance verdict about any implementation.
