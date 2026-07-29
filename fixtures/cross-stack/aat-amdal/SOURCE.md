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

Corpus repair, 2026-07-29. Three drops had been verified in correspondence and never landed
here: 2026-06-17, 2026-07-15 and 2026-07-22. All three are reconstructed from the issuer's
original emails, every token signature-verified before writing, and marked as reconstructed in
their own schema_note. The issuer's own same-day correction of the 2026-07-29 drop is ingested
alongside them; it was mailed 57 minutes after the first send and was never run at the time.

One token was repaired. Our local copy of aat-2026-06-24-expired had lost a single character
from al_nid at our write boundary, which left it parsing cleanly and failing only the signature.
The issuer's archive copy and his Sent copy were byte-identical to each other and verified, so
the loss was ours. He resent the bytes and the fixture now carries them.

Two integrity checks exist because of that. Every vector records the length and SHA-256 of its
compact token string, a convention agreed with the issuer so a transport corruption is one line
to spot rather than a thread. And al_nid is checked for multicodec well-formedness, which would
have localised the June loss without any signature verification at all.

Rotation history, corrected 2026-07-29 by the issuer against decoded tokens rather than declared
windows. The pre-expired half is the previous drop's live token from 2026-07-01 onward. Before
that it never was. The 2026-06-12 and 2026-06-17 drops both shipped a freshly minted sixty-second
companion as the expired half, minted seconds after the live one, so that was the original
behaviour rather than a break. A generator that reached back for the previous week's live token
did exist by 2026-06-17, and its own file proves it, but that file was never sent. So the correct
statement is not that the invariant broke twice. It is that the invariant was never on the path
that sent mail until 2026-07-01.

One consequence worth keeping. In the issuer's own archive the chain is unbroken at both seams
that are holes on the wire, so an invariant asserted over an archive can be satisfied by a chain
that was never transmitted. Assert the seam over sent bytes. The five seams the runner asserts,
2026-06-24 into 07-01 and then each week to 07-29, are anchored to wire fingerprints for the three
reconstructed drops and to our own ingests for the rest, one of which we know was corrupted on
write.

Wire anchoring. The 2026-06-17, 2026-07-15 and 2026-07-22 fixtures carry wire_provenance: the
issuer's message id, send time, and per-vector token_len and token_sha256 taken from his Sent
folder rather than his archive. Declared window fields in those three were normalised on
reconstruction and are NOT wire-faithful. Only the token bytes and their digests are.

Regression oracle. The lower-bound oracle is synthetic and lives at
fixtures/cross-stack/synthetic/. It replaced a reconstruction of the issuer's 2026-07-29 first
send, which he corrected 57 minutes later; publishing that would have pinned a mistake he had
already fixed. The synthetic key derives from a fixed published seed and verifies inline, so the
oracle cannot fail because of a third party's DNS.
