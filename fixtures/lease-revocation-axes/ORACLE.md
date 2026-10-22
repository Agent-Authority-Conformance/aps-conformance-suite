# Hand-reasoned oracle checkpoints

Revision 2, 2026-10-22. These are explicit author judgments under the declared
candidate profiles. They are not independent semantic validation. The associated
revision-2/oracle-checkpoints.json is authored separately from generate.py and
harness.ts. Verification compares its literal values to the implementation.
Both implementations and this table remain author-produced. Review can challenge
any premise below without accepting agreement between programs as its warrant.

Original evidence expires at 120000 ms. P1 requires unexpired, correctly bound
evidence, a current active observation and an allowed operation. The two endpoint
rules are alternatives, not conclusions attributed to W3C or another participant.

| Checkpoint | Truth | Evidence | Observation | Scoped authority | Current validity | Verification accepted | P1 | Dispatch |
|---|---|---|---|---|---|---|---|---|
| Cached, T=0, read | active | fresh | active at 0 | valid, bounded | valid | yes | permit | yes |
| Cached, T=119000 after revocation | revoked | fresh | active at 0 | valid, bounded | not established | yes | deny | no |
| Live, T=30000 after revocation | revoked | fresh | revoked at 30000 | revoked | revoked | no | deny | no |
| Live, T=30000, source down after revocation | revoked | fresh | none | not established | not established | no | deny | no |
| Live, T=121000, no diagnostic | revoked | expired | none | not established | not established | no | deny | no |
| Live, T=121000, diagnostic read | revoked | expired | revoked at 121000 | revoked, diagnostic | revoked | no | deny | no |
| Live, T=120000, inclusive endpoint | active | fresh | active at 120000 | valid | valid | yes | permit | yes |
| Live, T=120000, exclusive endpoint | active | expired | none | not established | not established | no | deny | no |
| Live, T=0, write | active | fresh | active at 0 | valid | valid | yes | deny | no |
| Live, request g2 with e1 for g1 | active g2 | fresh but mismatched | none | not established | not established | no | deny | no |
| Live, g2 after g1 revocation | active g2 | fresh | active at 30000 | valid | valid | yes | permit | yes |
| Live, T=30000, source down without revocation | active | fresh | none | not established | not established | no | deny | no |

Reasons

- At zero the original active observation is current and read is in scope.
- At 119000 the cached observation still meets the original lease, but it does
  not establish the present ledger state. P1 therefore refuses execution.
- An authoritative revoked observation establishes revocation even though the
  original evidence is still within its lease.
- An unavailable source supplies no current status. Unknown is not an observed
  revocation, and the active outage control has the same lack of knowledge.
- Expiry prevents acceptance and dispatch. A subsequent status read can establish
  current revocation without reissuing the evidence or extending its expiry.
- Equality at expiry is decided by the declared endpoint. Neither choice is
  inferred from the discussion.
- Valid authority for read does not permit write. Verification acceptance is a
  composite evidence check, not permission for every requested operation.
- Evidence naming another grant does not authorize the requested grant. This
  prerequisite is scored separately from the three axes. A diagnostic current
  status read would still not repair the binding or permit dispatch.
- Revoking one delegation does not revoke a different delegation for the same
  subject. The live g2 control remains permitted.

These checkpoints cover selected conditions. They do not establish every
possible expected value, real timing, source authenticity or SDK enforcement.
