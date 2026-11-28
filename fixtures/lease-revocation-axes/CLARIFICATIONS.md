# Clarifications, 2026-10-22

The GPT implementation review identified gaps in the original candidate's worker
isolation, read provenance, post-expiry observation scoring and unsupported-mapping
handling. Revision 2 repairs these and adds a grant-binding control. It does not
retroactively strengthen the original record.

The original vectors.json, records/model.json, records/sdk-7.1.0.json,
records/sdk-8.0.1.json and SHA256SUMS.txt remain byte-identical. Their recorded
44 runs, 164 calls, 492 axis comparisons and eight mutant failure sets describe
revision 1 only. The sticky-unavailable mutant's original failure set does not
include repeated outage calls because revision 1 did not audit their reads.

Revision 2 files and records are under revision-2. Its additional per-call read
contract catches missing attempts even while the service remains down. These
are model-interface observations, not real network observations.

Historical author statements in SDK-RUNS.md about baseline expectations are
attributed statements about authoring, not a history proof derived from the
present source. The original one-line comment correction removes the contrary
claim that every mutant failure set preceded model execution.

Record immutability is repository policy with a digest gate. Digests detect
changes against their manifest and are not protection against rewriting both
files and manifest. Corrections to covered artifacts are appended separately.
