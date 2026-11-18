# F01. The lease instant: does 7.2's acceptance at equality decide freshness?

Draft note to the author of draft-li-rttp-iqa-addressing-02. Not filed.

**Cases:** LB-D05 (blind B06). Under the further assumption that the 7.2 verification procedure is in play for every receiver, also LB-D02 (blind B15); this run's checker did not make that assumption, because LB-D02's input states no envelope fact.

**Sentences of the draft:**

- 6.1: "Whether the lease instant itself counts as fresh or as expired is a deployment convention; implementations SHOULD declare which boundary they use, and conformance material MAY test both."
- 7.2, field table: lease_expiry is "the instant until which the answer counts as fresh (Section 6.1)".
- 7.2, verification procedure: "(2) rejects the frame if lease_expiry is earlier than the current time, checked against the receiver's own clock (Section 6.1);"

**What was observed:** For the facts of LB-D05 (declared `expired_at_instant`, clock at the lease instant, frame accepted at equality, outcome `evidence_expired`), this run's checker found two readings. If 6.1 governs, the declared convention applies and `evidence_expired` is conformant. If 7.2 governs, a frame not rejected at equality has a lease that "counts as fresh", the condition of evidence_expired does not hold, and the outcome is nonconformant. This run's checker returned `ambiguous`; the candidate expects `conformant`, on the reading that frame validity and reliance are different layers. The minimal difference is the single condition "does acceptance under 7.2 step (2) make the lease fresh for the answer?". The text read in this run does not state the layering that the candidate's note relies on, and the 7.2 table ties lease_expiry to "counts as fresh" with a reference to 6.1.

**Where the fault may lie:** in the text, as read in this run: the two sentences can be read either way. This run's checker and the case each implement one consistent reading.

**Suggested change:** add one sentence to 7.2 step (2) or to 6.1, for example: "Step (2) is a floor for accepting the frame; a deployment that declares the lease instant expired refuses an answer read at that instant under Section 6.1 even though its frame was accepted."
