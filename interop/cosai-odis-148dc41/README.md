# ODIS Delegation Record chain validation (section 6.3, ODIS-L2-06): independent vectors

## Abstraction boundary, read first

ODIS requires an `attenuation_profile_ref` but defines no profile, and does
not fix the carrier or the digest algorithm behind `record_digest`. So these
vectors test the normative ODIS behavior **through a pinned lab projection**:
a lab attenuation profile and SHA-256 over RFC 8785 JCS as the record digest.

All five exact fixtures are lab-projection fixtures. What is
implementation-independent is the condition each one tests, not the bytes.

- `ODIS-ATT-02` (expiry containment) and `ODIS-ATT-04` (unknown profile fails
  closed) do not depend on the semantics of the lab projection for their
  expected condition, but their encoding still carries a lab `record_digest`
  and a lab `attenuation_profile_ref`, and a native driver must resolve the
  parent under its own carrier before it reaches either condition.
- `ODIS-ATT-01` (authorization widening) depends on the lab profile's subset
  rule. `ODIS-ATT-03` (parent digest mismatch) depends on the lab digest
  projection.

A real ODIS driver may have to translate each semantic condition into its own
supported profile and carrier rather than consume these exact bytes.

Four negative vectors and one positive control against the chain validation
rules of the ODIS contributor draft (cosai-oasis/ws4-odis, RFCs/ODIS.md),
pinned at the revision recorded in PROVENANCE.md. ODIS is an unapproved
contributor draft with no OASIS or CoSAI approval status (its own section
10.1); nothing here treats it as a standard.

| id | variant | rule | expected |
|---|---|---|---|
| `ODIS-ATT-00` | positive control | 6.3 narrower-or-equal under profile | pass (passes the checks this pack exercises; not ODIS conformance) |
| `ODIS-ATT-01` | negative | 6.3 granted_authorizations semantic subset, L2-06 | fail closed, attenuation |
| `ODIS-ATT-02` | negative | 6.3 expires_at <= parent.expires_at | fail closed, expiry |
| `ODIS-ATT-03` | negative | 6.3 parent record_digest must match resolved parent | fail closed, parent digest |
| `ODIS-ATT-04` | negative | L2-06 unknown or unsupported comparison MUST fail closed | fail closed, profile |

All five reproduce under the lab projection. `ODIS-ATT-04` tests the behavior
the text already fixes; it raises no question for the authors.

## Candidates against proposed text, kept apart

`candidates-proposed/` holds two cases that encode requirements proposed in
open issues #5 and #6 (both by szh, 2026-08-04, zero comments at pin time).
They are labelled `candidate_against_proposed`, are not run by the adapter,
carry an `expected_if_adopted` rather than an `expected`, and each states
what the pinned ODIS.md currently requires instead. They must not be read
as ODIS conformance cases.

## What ODIS leaves to the deployment, and what this checker assumes

- Carrier integrity protection for a Delegation Record and the digest
  algorithm behind `record_digest` are not fixed by ODIS.md. The checker uses
  SHA-256 over RFC 8785 JCS of the parent record as a stand-in and would need
  to be re-pointed at whatever carrier a real implementation uses.
- The attenuation profile is a lab fixture (`urn:lab:attenuation-profile:set-subset:v1`,
  pinned by digest in every fixture): string sets by inclusion, integer
  constraints child <= parent, dropped constraint counts as widening. ODIS
  requires a profile but defines none. Real profiles will differ; the four
  expected outcomes do not depend on the profile's contents beyond
  ATT-01 needing a subset rule of some kind.
- `expires_at` has type "timestamp" in ODIS.md with no fixed serialization.
  The lab projection fixes it as RFC 3339, parsed with the same section 5.6 syntax plus
  5.7 range parser as the AAT pack (leap-second occurrence not validated) and compared as instants. A malformed value is an
  indeterminate comparison and fails closed.
- `delegation_chain` entries in these fixtures use the lab's reference form,
  `{issuer, delegation_id, record_digest}`, the same triple as
  `parent_delegation_ref`. 6.3 permits an integrity-protected reference that
  supplies what is needed to verify lineage and attenuation; the exact shape
  is not fixed by ODIS.md and this is the lab's choice.
- `originating_authorization_ref` is carried as the 6.3 MUST object (issuer,
  subject, audience, grant_id, issued_at, expires_at) in every fixture, so
  the positive control is structurally valid under the pinned data model
  before any semantic check runs. The checker fails closed on a malformed one
  under check `record_shape`.
- Not exercised: issuer authentication, freshness, revocation, root
  originating_authorization_ref validation, max_depth, resource_indicators
  and constraints narrowing negatives (the profile covers them; only
  granted_authorizations is exercised as the widening axis).

## Re-run

    cd interop/cosai-odis-148dc41
    python3 adapter/py/run.py
    python3 adapter/py/test_timestamps.py

## Lab operating constraints

The lab certifies nothing and issues no conformance verdicts. Each vector
records the draft revision it targets and the sentence its expectation rests
on. This run was independently produced, not by the draft's authors.
