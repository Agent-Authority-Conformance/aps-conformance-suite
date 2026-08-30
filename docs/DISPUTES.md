# Disputes

A dispute is a claim that a vector in this corpus is wrong: that its recorded
bytes, digest, signature, or expected verdict does not follow from the normative
target it names.

This exists because the corpus can be the party that is wrong. A divergence
between an implementation and a vector is two parties computing different values
from the same inputs, and nothing about being the publisher makes this repository
the correct one. A run report that says "your vector is wrong" is the most useful
thing anyone sends.

## What a dispute is not

Not a bug report against an implementation. This lab issues no verdicts about
implementations, so it has no mechanism for filing one and would not know what to
do with it. If an implementation diverges from a vector and the vector is right,
that is a matter between you and that implementation's maintainers.

Not a severity assessment. A dispute is open or resolved. Ranking how bad a
disputed vector is would be a verdict about the implementations that rely on it,
which is the thing the lab does not do.

## Filing one

Open a [vector dispute issue](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/new?template=vector-dispute.yml).
The form asks for the vector or family, the corpus commit sha you read, what the
vector claims, what you computed, the exact command and its output, the normative
reference you are reading it against, and why you believe the expectation is
wrong.

The normative reference is the part that does the work. A dispute that says a
value is wrong without naming the document and revision it should follow from
cannot be resolved by anyone, including its author.

## How one is resolved

A dispute stays visible until it is resolved in public. Resolution is one of:

- **The vector is wrong.** A corrected vector is published. The old vector's bytes
  are not edited in place, because every record that observed them would silently
  start describing something else. The corrected vector is a new vector, and the
  records that observed the old one keep saying what they observed.
- **The vector is right.** The dispute record says what the reading turned on, so
  the next reader of the same normative text finds the answer instead of filing
  again.
- **The normative text is ambiguous.** Both readings are recorded, the vector says
  which one it pins, and the ambiguity is taken upstream to whoever owns the
  document.

Where the clarification comes from a draft revision authored by the lab
maintainer, the dispute record says so.

That last line is the conflict this lab has to disclose rather than manage. The
maintainer of this corpus also authors the individual Internet-Draft that several
of these vectors target. Resolving a dispute by pointing at a revision the same
person wrote is not neutral, and a reader has to be able to see when it happened.

## Open disputes

None open.

| dispute | vector or family | filed | normative reference | status |
|---|---|---|---|---|

A resolved dispute stays in this table with its resolution, because the record of
what was argued is worth more than a tidy table.
