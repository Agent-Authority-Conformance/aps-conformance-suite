# Ambiguity log — aicent-grant-ref, reading 1

Source: draft-li-rttp-iqa-addressing-02 (sha256 02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044).
Sections read: 8 (intro), 8.1, 8.2. Also read because 8.1/8.2 refer to them or use their terms:
- Section 2: the BCP 14 key-word paragraph (8.1 uses MUST / MUST NOT) and the terms *standing*, *standing read*, *trust lease*, *refusal reason*, *grant reference* (used by 8.1/8.2).
- Section 6 (6, 6.1, 6.2, 6.3, and 6.4 as it sits inside Section 6): 8.1 says a permit "may be relied on under the rules of Section 6"; 8.1 `evidence_expired` cites 6.1; 8.2 cites 6.3; "fresh" in 8.2 is the lease freshness of Section 6.
- RFC 2119 / RFC 8174 not opened: the key-word meanings were applied as commonly understood (MUST = absolute requirement); no case turned on a key-word subtlety.

State at the end of phase 1 is entries A01–A16. Entries added in phase 2, if any, are marked as such.

## Field mappings (candidate input/outcome names → conditions in the text)

| Candidate field | Mapped to | Text | Chosen? |
|---|---|---|---|
| `input.binding_mismatch` = true | condition of `evidence_binding_mismatch` | 8.1 "The presented evidence is bound to a different grant or subject than the one in the request." | direct |
| `input.evidence_expired` = true | condition of `evidence_expired` | 8.1 "The lease of the presented evidence has expired (Section 6.1)." | direct; see A08 |
| `input.authority` = `unreachable` | condition of `authority_not_determined` (first branch) | 8.1 "the organ or the authority source could not be reached" | chosen (A10) |
| `input.authority` = `stale_observation` | condition of `authority_not_determined` (second branch) | 8.1 "the only observation available predates the request" | chosen (A06, A10) |
| `input.authority` = `revoked` | condition of `authority_revoked` | 8.1 "The authority for the subject has been revoked." | direct |
| `input.authority` = `determined` | none of the authority conditions applies | — | chosen (A10) |
| `input.operation_permitted` = false | condition of `operation_not_permitted` | 8.1 | direct; "for reasons other than the four above" handled by the priority order |
| `input.computed_over` / `outcome.computed_over` | what the refusal was computed over | 8.1 last paragraph | chosen (A01) |
| `input.revoked_at_ms`, `input.race_boundary` | revocation instant near the invocation | 8.2 race paragraph | chosen (A02) |
| `input.relied_on_observation.{present,fresh,as_of_ms}` | "the observation the answer relied on", absent / not fresh / its as-of instant | 8.2 | direct; "fresh" per A08 |
| `input.diagnostic_read` | "a diagnostic or opportunistic read" / "a later, successful observation" | 8.2 | direct |
| `input.grant_expires_at_ms` | "grant expiry instant" | 8.2 member `expires_at_ms` | direct |
| `outcome.reason` | the refusal reason; JSON null = null; absent key = response does not carry it | 8, 8.1; candidate's `absent_fields` rule | direct |
| `outcome.grant_ref.*` | the five members of 8.2 | 8.2 | direct (names coincide) |

Required reason: computed only when the input carries all four of `binding_mismatch`, `evidence_expired`, `authority`, `operation_permitted`. For cases whose input lacks them (B08, B09, B11, B12, B14, B21–B24) the reason value is checked only against the closed set and for presence, not against facts (A11).

## Entries

### A01 — Refusal computed over a label: MUST vs "not a conformance target" (8.1) — affects B13
- Reading A: "a refusal reason MUST be computed over the authority facts the response carries". A refusal computed over an operator label violates a MUST, so it is nonconformant.
- Reading B: the next sentence says "A refusal computed over labels, opinions, or unrecorded context alone is not auditable, and producing one is not a conformance target of this section." That places such a refusal outside what 8.1 judges. 8.1 then assigns no verdict, and nothing in the vocabulary corresponds to "no verdict".
- In B13 the value emitted (`authority_not_determined`) is also the value the facts require (authority unreachable). A third party re-deriving from the facts gets the same value, so the auditability failure is only in the recorded basis.
- Chosen: `ambiguous`. The two sentences sit side by side and point to different verdicts. "alone" adds a third point: if the label is not the only input, neither sentence clearly applies.

### A02 — Revocation refusal whose stated observation predates the revocation (8.2 race paragraph) — affects B19
- The facts: authority revoked, `revoked_at_ms` 1101, `race_boundary` true. The outcome: `authority_revoked` with `observation_as_of_ms` 1100.
- Reading A: the race paragraph says the boundary "no protocol erases" and that the response owes "a legible record of it". A record showing observation at 1100 and a revocation refusal is that record, so it is conformant.
- Reading B: 8.2 defines `observation_as_of_ms` as "the as-of instant of the standing observation the answer relied on". An observation as of 1100 cannot show a revocation effective at 1101. Either the member misstates what the answer relied on, or the reason was not "computed over the authority facts the response carries" (8.1), so it is nonconformant.
- Chosen: `ambiguous`. The text gives no rule tying the observation instant to the revocation instant. It also does not say whether revocation knowledge must arrive through a standing observation.

### A03 — Refusal when no condition applies (8.1) — affects B06
- 8.1 says the reason is null "when there is no refusal". It does not say in so many words that a response MUST be a permit when no condition applies.
- Reading A: no refusal is admissible, so the reason must be null.
- Reading B: whether to refuse is outside 8.1 (6.2 leaves "whether an action proceeds" to the calling layer's policy). Then a refusal for policy reasons would be `operation_not_permitted` "for reasons other than the four above". But the input states `operation_permitted: true`, so that condition does not apply either.
- Chosen: nonconformant. Under both readings the emitted value's condition does not apply, and 8.1 requires "the first value in the list whose condition applies". This is recorded because the verdict rests on reading `operation_permitted: true` as "no policy forbids it". If the field meant only "the grant's scope covers the operation", Reading B would give `conformant`.

### A04 — Are all five grant-reference members required? (8.2) — affects B12, B14
- 8.2: "The grant reference is a structure with the following members". Only `observation_as_of_ms` is stated as nullable ("or null"). Nothing says a member may be omitted.
- Chosen: all five members are required. A missing `issued_at_ms` (B12) or `expires_at_ms` (B14) is nonconformant. The other reading (members optional) is not supported by any sentence, but the text has no explicit MUST for presence either.

### A05 — Absent `observation_as_of_ms` vs null (8.2) — affects B24
- The text allows a value "or null". It has no JSON binding, so absence is not defined by the text.
- Chosen: the candidate's `absent_fields` rule (an absent key is not an explicit null), with A04, so B24 is nonconformant. Without the candidate's representation rule, a binding that serialises null as omission would give `conformant`. The verdict depends on the representation rule, not on the draft.

### A06 — "the only observation available" when a later diagnostic read exists (8.1 vs 8.2) — affects B18
- 8.1 `authority_not_determined` applies when "the only observation available predates the request". In B18 a successful diagnostic read at 1150 is available at answer time, so literally the stale one is not the only observation available.
- 8.2: "diagnostic reads do not participate in authorisation and do not renew evidence"; the member stays null "even if a later, successful observation is available at answer time".
- Chosen: the diagnostic read does not count for authorisation, so `authority_not_determined` is required (input `authority: stale_observation`). B18 is nonconformant under either reading in any case, because its `observation_as_of_ms` 1150 fails the 8.2 null rule independently.

### A07 — 6.2 "answers authority_revoked or evidence_expired" vs 8.1 priority — affects B03, B05
- 6.2 says that when a lease expires mid-task "the next verification answers authority_revoked or evidence_expired". Read alone, this could suggest a free choice.
- Chosen: 8.1's priority order governs ("the priority order is part of this definition"). The 6.2 sentence pairs examples ("an employee whose authority has ended, a grant whose window has closed") with the two values; it does not choose between them for the same facts. With evidence expired and authority revoked, `evidence_expired` is required (B05 conformant, B03 nonconformant).

### A08 — Meaning of "fresh" / "expired" (8.1, 8.2 → 6.1)
- 8.2 uses "not fresh" without defining it in 8.2. Mapped to 6.1: an answer whose lease has not expired. 6.1 leaves the lease-instant boundary to "a deployment convention". All cases give freshness and expiry as booleans, so the boundary convention is not exercised and was not tested.

### A09 — Grant expiry earlier than grant issue (8.2) — data observation
- B01, B02, B03, B05, B09, B11, B15, B16, B18 carry `issued_at_ms` 1000 with `expires_at_ms` 900. 8.2 states no ordering between the two members, so the checker does not test it. Recorded only. Whether a grant that expires before it is issued is a well-formed record is not decided by the text.

### A10 — The `authority` enumeration
- The candidate's `authority` is a single enumeration (`determined`, `unreachable`, `stale_observation`, `revoked`). In the text, `authority_not_determined` precedes `authority_revoked`, and "revoked" presupposes the authority was determined. Because the enumeration is exclusive, no case can carry both, and the order between those two values is never tested by the cases.

### A11 — Reason value in 8.2-only cases
- B08, B09, B11 carry `authority_not_determined` with a relied-on observation that is present but not fresh. Whether a non-fresh relied-on observation is the 8.1 condition "the only observation available predates the request" depends on whether it predates the request, which the input does not state. These reasons were checked for closed-set membership and presence only.
- B21 is a permit (reason null) with no relied-on observation. Whether 6.2 / 8.1 allow a permit with no observation depends on the deployment mode, which the input does not state. Not scored.

### A12 — "MUST NOT reinterpret an emitted value" (8.1)
- Not separately implemented. Under the candidate's `readings` rule ("no case asks what the implementation intended"), a reinterpretation cannot be observed in a single outcome. Not attempted.

### A13 — `expires_at_ms` replaced by a diagnostic-read instant (8.2) — affects B08
- The no-backfill sentence names only the observation member. B08 puts the diagnostic read instant 1150 into `expires_at_ms` instead.
- Chosen: nonconformant on the member's own definition ("grant expiry instant"), since the input gives grant expiry 900. This does not need the backfill sentence. If `grant_expires_at_ms` in the input were not the grant's expiry as issued (for example, a renewed grant), the reading would change. The text says "do not renew evidence".

### A14 — The candidate's "an outcome lists the fields its rule reads"
- The per-case `rule` is withheld in the blind copy, so the checker cannot tell which outcome fields a case intends to test. It scores every field the outcome carries against every rule the input allows it to check.

### A15 — `observation_as_of_ms` in 8.1-only cases
- 8.1 cases do not carry `relied_on_observation`, so the 8.2 observation rule (R9/R10) is not applied to them. Their observation values (for example 800 in B01, alongside expired evidence) were not checked. Whether 800 is "fresh" cannot be decided from the input.

### A16 — Grant identifier and evidence identifier
- 8.2 `grant` "identifier of the grant as issued" and `evidence_id` "identifier of the evidence bound to it". In `evidence_binding_mismatch` cases (B02, B10, B15, B01), the evidence is bound to a different grant or subject, so which grant `grant` names, and whether `evidence_id` is "bound to it", is undefined. The checker tests presence only.

## Added in phase 2 (after the sealed files were opened)

### A17 — GR-A02 (B19): same part verdicts, different second reading
- The candidate's note puts the open question in which answer was owed at the boundary: `authority_revoked`, `authority_not_determined`, or a permit.
- The reader's A02 puts it in whether `observation_as_of_ms` 1100 is consistent with a revocation refusal for a revocation effective at 1101 (8.2 member definition; 8.1 "computed over the authority facts the response carries").
- Both score the value part conformant and the boundary part ambiguous. Neither reading was adopted over the other. The two together show that the boundary question has at least two independent axes: which value, and which observation instant the record states.

### A18 — GR-A01 (B13): part names
- The candidate names the first part `value_and_assent`. The reader has no separate "never read as assent" check for B13. The value check (R4) already requires `authority_not_determined` for an unreachable source, so a permit would fail R6. The assent property is therefore covered by R4/R6 in the reader, not by a rule of its own.
