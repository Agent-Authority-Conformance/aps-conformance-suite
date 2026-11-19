# F05. LB-D03 is also decided by the condition of evidence_expired

Draft note to the author of the candidate aicent-lease-boundary. Not filed.

**Cases:** LB-D03 (blind B03): declared `fresh_at_instant`, clock at the lease instant, outcome `evidence_expired`.

**Sentences of the draft:**

- 6.1: "Whether the lease instant itself counts as fresh or as expired is a deployment convention; implementations SHOULD declare which boundary they use, and conformance material MAY test both."
- 8.1: "*evidence_expired* — The lease of the presented evidence has expired (Section 6.1)."
- 8.1: "For a refusal, the reason is exactly one value from the following closed set, and it is the first value in the list whose condition applies (the priority order is part of this definition):"

**What was observed:** this run's checker and the case agree (`nonconformant`). The candidate's known limitations say the case "rests on a strict reading" of the SHOULD on declarations. This run's checker does not use a rule on declarations that contradict use. It takes the declared convention as fixing the fact (the lease is fresh at the instant) and finds that the condition of evidence_expired does not hold, so the reason is not the first value whose condition applies (rules R05 and R12; R05 inverted and R12 removed each change LB-D03 to `conformant`). On that ground, the verdict follows from a sentence of 8.1 and not only from the SHOULD of 6.1.

**Suggested change:** in the case note or the known limitations of LB-D03, name the 8.1 ground alongside the declaration argument, or state why the case is meant to rest on the declaration alone.
