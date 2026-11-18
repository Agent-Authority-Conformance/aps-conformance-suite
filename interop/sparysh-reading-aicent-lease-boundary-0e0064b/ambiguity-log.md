# Ambiguity log

Every place where the text of draft-li-rttp-iqa-addressing-02, as read in this run, admits more than one reading, or where this run's checker had to choose a mapping. Citation identifiers (C61-boundary etc.) are those of `reader/checker.py`; their text is in `out/phase1.json` under `citations`. Entries A1 to A14 were written in phase 1, before `inputs/sealed/` was opened.

## A1. The lease instant when the deployment declares expired_at_instant and the envelope accepted the frame (6.1, 7.2) — case B06

- Text: 6.1, "Whether the lease instant itself counts as fresh or as expired is a deployment convention; implementations SHOULD declare which boundary they use, and conformance material MAY test both." 7.2, step (2): "rejects the frame if lease_expiry is earlier than the current time"; the field table: lease_expiry is "the instant until which the answer counts as fresh (Section 6.1)".
- Reading (a): 6.1 governs. The declared convention (expired at the instant) applies to the answer; a frame that passed 7.2 step (2) can still be answered evidence_expired. `evidence_expired` is conformant.
- Reading (b): 7.2 fixes the boundary on the wire. A frame not rejected at equality has a lease that "counts as fresh", so the condition of evidence_expired ("The lease of the presented evidence has expired") does not hold. `evidence_expired` is nonconformant.
- Chosen: both readings kept; the verdict for B06 is `ambiguous`, with the part `reason` ambiguous. Why: 6.1 delegates the boundary to the deployment, while 7.2's procedure and table state a fixed boundary; neither sentence says which yields.
- Scope chosen: the conflict is applied only where the input states `frame_accepted_at_equality`. Cases B03, B11 and B15 state a declared convention and no envelope fact; the checker applies the declared convention to them. If the 7.2 procedure were taken to be in play for every receiver, B15 (declared expired, evidence_expired) would carry the same two readings as B06, and B03 (declared fresh, evidence_expired) would stay nonconformant under both.

- Phase-2 note: the candidate expects LB-D05 (B06) `conformant`, on the reading that "frame validity and reliance are different layers" (its note for LB-D05). That is reading (a). The phase-1 verdict is not changed; see `out/changes.md` and `findings/F01-boundary-layers.md`.

## A2. The lease instant with no declared convention (6.1, 7.2) — case B04

- Text: C61-boundary (above); C72-step2.
- Reading (a): with no declaration, the 7.2 verification procedure is the only fixed rule; at equality the frame is not rejected, the lease is fresh, and a permit (reason null) is conformant.
- Reading (b): the convention is the deployment's and was not declared; it may be expired at the instant, in which case a permit violates "an answer whose lease has expired MUST be refused" (6.2).
- Chosen: both readings kept; B04 is `ambiguous`, part `reason`. The missing declaration is a SHOULD (6.1) and is not scored as a failure by itself.

## A3. Cached-lease mode, lease fresh, organ unreachable, policy accepts lease-fresh evidence (6.2, 8.1, 9.2) — case B12

- Text: 6.2, "a policy that accepts lease-fresh evidence may admit it, with any exposure bounded by the lease itself." Against: 6.2, "In both modes ... an organ that cannot be reached MUST NOT be read as affirmative standing (Section 9.2)."; 8.1, "An unreachable source is refused under this value, never read as assent."; 9.2, "An endpoint that is unreachable, times out, or returns an error MUST NOT be read as affirmative standing".
- Reading (a): the specific sentence on cached-lease mode governs. Admission rests on the lease-fresh cached answer, checked "locally and offline", not on the organ's silence; a permit is conformant.
- Reading (b): the general rules govern in both modes; an unreachable organ at answer time requires a refusal with authority_not_determined; a permit is nonconformant.
- Chosen: (a). The sentence names this mode and this policy; the general rules are stated about reading the unreachable organ as standing, which the cached verifier does not do. Variant R10 inverted in `out/phase1-sensitivity.json` shows B12 is the only case this choice decides.

## A4. Whether a refusal is also allowed under a lease-fresh policy (6.2)

- Text: "may admit it". Reading (a): admitting is allowed and refusing with authority_not_determined is also allowed. Reading (b): the policy that accepts lease-fresh evidence admits.
- Chosen: (a); the checker allows `null` or `authority_not_determined` for B12's facts. No case presents a refusal under these facts, so no verdict depends on this choice.

## A5. Two refusal conditions at once: cached mode, lease expired, organ unreachable (6.2, 8.1) — case B07

- Text: 8.1, "it is the first value in the list whose condition applies (the priority order is part of this definition)". Both evidence_expired (lease expired) and authority_not_determined (organ could not be reached) apply.
- Reading (a): both apply; the first in the list, evidence_expired, is the reason. Reading (b): in cached mode the organ is not consulted, so only evidence_expired applies. Both readings give `evidence_expired`.
- Chosen: (a). The policy `lease_fresh` is not consulted, because 6.2 speaks of policy only for lease-fresh evidence.

## A6. The deployment window and the stated expiry (6.1) — cases B05, B14

- Text: "Current deployments use 120 seconds." and "Operators MAY configure other window lengths; the mechanism does not depend on this value."; 6.1 first paragraph: the answer states its own expiry in-band.
- Reading (a): freshness is the stated lease_expiry against the verifier's clock; a 300-second window is not expired at 299 seconds. Reading (b): a verifier may cap at 120 seconds from issuance.
- Chosen: (a). Variant R02 inverted shows B05 and B14 swap under (b).

## A7. A refusal whose condition does not hold (8.1) — cases B03, B05

- Text: 8.1, "it is the first value in the list whose condition applies"; "MUST NOT reinterpret an emitted value to mean something else".
- Reading (a): emitting evidence_expired when the lease has not expired is nonconformant. Reading (b): a refusal is never less safe than a permit, so any closed-set refusal is conformant.
- Chosen: (a). Variant R12 removed shows B03, B05 (and B06) change under (b).

## A8. Facts the input does not state

- The inputs carry only some facts: no binding information, no revocation information, no mode outside B02, B07, B08, B12, B13, no reachability for the lease-only cases.
- Reading (a): a fact not stated is not in play (no binding mismatch, no revocation, no mode rule). Reading (b): an unstated fact is unknown, and every case whose verdict would depend on it is ambiguous.
- Chosen: (a), consistent with the candidate's `absent_fields` rule for outcomes. This is a mapping chosen in this run.

## A9. Mapping of the candidate's input field names to conditions of the text

Each mapping below was chosen in this run; the text uses none of these names.

- `now_ms` → the verifier's own clock (C61-clock, C72-step2). The text uses Unix seconds; the cases use milliseconds. The checker compares the integers as given.
- `lease_expiry_ms` → the stated lease_expiry (C61-inband, C72-table).
- `issued_at_ms` → the issuance instant. The envelope of 7.2 has no such field. Used only in the R02 inverted variant.
- `grace_added: true` → the verifier extended the lease locally (C61-expired, "MUST NOT extend").
- `declared_boundary` → the declared convention of C61-boundary; `null` → not declared.
- `at_boundary: true` → the clock equals the lease instant.
- `frame_accepted_at_equality: true` → 7.2 step (2) did not reject the frame at equality.
- `mode` → `live` = live-standing-read mode, `cached` = cached-lease mode (6.2).
- `organ_unreachable` → "the organ cannot be reached" (6.2, 8.1, 9.2).
- `cache_fresh` → whether the cached answer's lease has expired (6.2, 6.1).
- `policy` → `current` = "a policy that demands a current observation"; `lease_fresh` = "a policy that accepts lease-fresh evidence" (6.2).
- Outcome `reason` → the refusal reason of 8.1, `null` = permit (C81-null); absent key = no reason reported (C81-without-reason).

## A10. The members a response must carry (8.1, 8.2)

- Text: 8.1, "a refusal reason MUST be computed over the authority facts the response carries"; section 2 defines *grant reference* by reference to Section 8.2. Section 8.2 is not referred to by 6.1, 6.2, 6.3 or 7.2 and was not read.
- Reading (a): the response carries a grant reference whose members are fixed by 8.2; the checker cannot score them. Reading (b): the in-scope text fixes no members beyond the reason.
- Chosen: the checker scores the presence of `reason` and of `grant_ref` only. `observation_as_of_ms` (800, 1050, 1250000, or null in B08) and the other members are not scored. Every case carries `reason` and `grant_ref`, so no verdict depends on these checks (R13, R15).

## A11. `lease_note` in B10

- The note states "lease treated as extended by a local grace period after issuance". The checker scores the extension from the input fact `grace_added`, not from the note string. B10 is nonconformant in the baseline (lease expired, permit). With R04 removed the grace period counts, the lease is fresh, and B10 becomes conformant; with R01 removed it also becomes conformant (`out/phase1-sensitivity.json`).

## A12. "expected to be refused" in live-standing-read mode (6.2) — cases B02, B08

- Text: "Every call in this mode is expected to be refused when the organ is unreachable, regardless of the age of any cached answer." The sentence carries no BCP 14 key word.
- Reading (a): the refusal is required, by the MUST NOT of 6.2 ("In both modes ...") and 9.2. Reading (b): "expected" is descriptive and the requirement is only the MUST NOT on reading silence as standing; a permit grounded on a fresh cache in live mode would then need a further argument.
- Chosen: (a). The live mode is defined as consulting the organ at each request, so a permit with the organ unreachable reads its absence as standing.

## A13. The mid-task sentence of 6.2 (not tested)

- Text: "the next verification answers authority_revoked or evidence_expired (Section 8.1)". With 8.1's priority, evidence_expired precedes authority_revoked when both apply. Reading (a): "or" names the two conditions, the priority decides. Reading (b): either is acceptable. No case tests this; the checker implements no rule for it.

## A14. Equality at millisecond resolution (7.2)

- 7.2 states lease_expiry in Unix seconds. `at_boundary` is taken as given; the checker does not test whether equality holds at second or millisecond resolution.

## A15 (phase 2). The parts of the undeclared-boundary case — LB-D04, blind B04

- The candidate scores LB-D04 in two parts: `answer_within_a_convention: conformant` and `declaration: ambiguous`. This run's checker scored the parts of the outcome (`reason member present`, `reason is null or in the closed set`, `reason`, `grant_ref member present`) and found `reason` ambiguous.
- Reading (a), the candidate's: both conventions are licensed by 6.1, so a permit at the instant lies inside one of them; what is open is the missing declaration.
- Reading (b), this run's: if the undeclared convention is expired at the instant, the permit violates "an answer whose lease has expired MUST be refused" (6.2); the open part is the reason itself.
- Both give the verdict `ambiguous`. The part names do not correspond one to one, and `declaration` is a fact of the input (`declared_boundary: null`), not a member of the outcome. Not changed; see `findings/F02-undeclared-boundary-parts.md`.
