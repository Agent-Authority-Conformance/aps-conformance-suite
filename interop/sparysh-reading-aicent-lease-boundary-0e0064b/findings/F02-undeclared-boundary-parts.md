# F02. The undeclared boundary: which part is open

Draft note to the author of draft-li-rttp-iqa-addressing-02. Not filed.

**Cases:** LB-D04 (blind B04): no declared convention, clock at the lease instant, outcome a permit (reason null).

**Sentences of the draft:**

- 6.1: "Whether the lease instant itself counts as fresh or as expired is a deployment convention; implementations SHOULD declare which boundary they use, and conformance material MAY test both."
- 6.2: "In both modes the following rules are normative: an answer whose lease has expired MUST be refused; and an organ that cannot be reached MUST NOT be read as affirmative standing (Section 9.2)."
- 7.2: "(2) rejects the frame if lease_expiry is earlier than the current time, checked against the receiver's own clock (Section 6.1);"

**What was observed:** this run's checker and the case both give `ambiguous`. They locate the open question differently. The case scores `answer_within_a_convention: conformant` and `declaration: ambiguous`. This run's checker scored the outcome's members and found the `reason` member ambiguous: under the reading that the undeclared convention is fresh at the instant (or that 7.2 step (2) supplies the default), the permit is conformant; under the reading that it is expired at the instant, the permit falls under the MUST of 6.2. `declaration` is a fact of the input (`declared_boundary: null`), not a member of the outcome, so this run's checker has no part with that name. The verdicts agree; the part names do not correspond one to one.

**Suggested change:** state in 6.1 what applies when no boundary is declared, for example "A deployment that declares no boundary is treated as counting the lease instant as fresh, the boundary of Section 7.2 step (2)", or state that behaviour at the instant without a declaration is not a conformance target.
