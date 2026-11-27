# F03. Cached-lease mode with the organ unreachable: may-admit against never-assent

Draft note to the author of draft-li-rttp-iqa-addressing-02. Not filed.

**Cases:** LB-M04 (blind B12), under these facts only: cached-lease mode, cached answer within its lease, organ unreachable, policy accepting lease-fresh evidence, outcome a permit.

**Sentences of the draft:**

- 6.2: "a policy that accepts lease-fresh evidence may admit it, with any exposure bounded by the lease itself."
- 6.2: "In both modes the following rules are normative: an answer whose lease has expired MUST be refused; and an organ that cannot be reached MUST NOT be read as affirmative standing (Section 9.2)."
- 8.1: "An unreachable source is refused under this value, never read as assent."
- 9.2: "An endpoint that is unreachable, times out, or returns an error MUST NOT be read as affirmative standing: absence of evidence is not evidence of compliance."

**What was observed:** this run's checker and the case agree (`conformant`). The agreement rests on a choice this run made (ambiguity log A3): that the sentence on cached-lease mode governs over the general rules, because the cached verifier admits on the lease-fresh answer and does not read the organ's silence as standing. Read literally, the 8.1 sentence "An unreachable source is refused under this value" applies in both modes and would require a refusal. In this run's sensitivity table, the variant that lets the general rules govern (R10 inverted) changes LB-M04 alone, to `nonconformant`. The candidate's known limitations state that the mode cases take the never-assent mapping as given.

**Suggested change:** qualify the 8.1 sentence, for example "In live-standing-read mode, and in cached-lease mode under a policy that demands a current observation, an unreachable source is refused under this value, never read as assent."
