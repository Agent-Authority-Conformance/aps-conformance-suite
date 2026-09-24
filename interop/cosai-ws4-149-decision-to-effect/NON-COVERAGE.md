# What a passing run does not establish

This corpus checks three narrow properties on the seam named on
cosai-oasis/ws4-secure-design-agentic-systems#149: exact call, non-bypassability
and effect verification. A case reproducing its expected verdict under this
checker, and a clean `run.py` verify, do not establish any of the following.

**Policy correctness.** `exact_call` checks that the dispatched call matches
what was authorized, and `effect_verified` checks that the reported effect
matches an independent read-back. Neither checks whether authorizing that call
in the first place was the right decision, or whether the effect it produced
was the correct postcondition under whatever policy governs the system. A
call can be exact, its effect can be verified, and the whole transaction can
still be a policy mistake. This corpus has nothing to say about that.

**Trustworthiness of the read-back source.** `effect_verified` compares the
tool's self-report against an independent read-back and trusts the read-back
as the arbiter. If the read-back source is itself compromised, colludes with
the tool, or is reading the wrong thing, a `pass` here reflects agreement
between two records, not ground truth. Establishing that the read-back source
is trustworthy is a separate concern this checker does not take on.

**Absence of bypass paths beyond the stated observation scope.** A `pass` on
`non_bypassability` requires an established observation-coverage premise, and
that premise is supplied by the verifier surface as context, never verified
recursively here (see PROVENANCE.md and the #189 asymmetric rule this corpus
reuses). The coverage premise is scoped: it says alternate paths within a
named scope were observed, not that no alternate path exists anywhere. A path
outside that scope is simply not something this checker looked at, in either
direction.

**Causation.** `effect_verified` establishes that the tool's self-report and
an independent read-back agree on the observed state after dispatch. It does
not establish that the action under test caused that state. The read-back
could agree by coincidence, because something else produced the same effect
around the same time, or because the "effect" being read back was already
true before the call ran. Agreement is not a causal claim.

**What a `non_bypassability` pass specifically is not.** A `pass` on this
property shows only that, within the stated observation scope, coverage was
established for the evaluated claim and no use of the protected credential
outside the governed path was observed. It is not a completeness proof. It
does not show that every possible alternate path was enumerated, tried, or
could have been observed by the evaluator. One observed bypass settles `fail`
on its own, while the absence of an observed bypass says nothing about paths
outside what was actually watched.

None of the above is a defect in the checker. It is the boundary of what
these three properties, and the evidence pairing they read, are built to
show. A verifier or a reader that treats a `pass` here as proof of any of the
five points above is reading past what the corpus checks.
