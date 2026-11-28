# Clarifications

Dated entries. Files listed in this record's SHA256SUMS.txt are not modified after the run. A later correction to one of them is recorded here. Earlier text and evidence remain unchanged.

## 2026-10-26: RESULTS.md, Determinism

The recorded run-output-rev3.json has SHA-256 f008756821a252b7a44ab11ccda446176ec943a41a27b31db5a0e471f89c2d93, as listed in SHA256SUMS.txt. The prefix 78824b82a07eccdb in RESULTS.md is incorrect.

## 2026-10-26: RESULTS.md and run-report.md, grant_ref

grant_ref is an object in all 176 revision 3 answers. Its member observation_as_of_ms is null when the decision used no observation, which includes every evidence_expired and evidence_binding_mismatch refusal. A diagnostic read after a rejection does not fill it.
