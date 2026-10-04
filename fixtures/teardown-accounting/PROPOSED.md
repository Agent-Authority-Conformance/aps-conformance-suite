# teardown-accounting: proposed text

This file is the proposed text the `teardown-accounting` family is a candidate
against. The family's runners pin the SHA-256 of these exact bytes, so an edit
here fails both runners until every case file's `proposed_text.sha256` is
updated with it.

**Status: candidate against this file.** This is not a conformance family, not
a draft requirement, and not part of the APS-native corpus.

## Provenance

Adapted from an unpublished maintainer draft of the teardown-completeness case
originally prepared for agent-authority-lifecycle. That repository is frozen, so
this lab file owns the candidate text.

The input shape and the eight author development cases follow the exploratory
prototype danyka-icam posted on Agent-Authority-Conformance/aps-conformance-suite#144
(`APS_LC_COMPLETENESS_BASIS_EXPLORATORY_v0.1.zip`, SHA-256
`8eb4690da88e832207dc20ddfeab75e5e2e5e4d7b4ef3323f8b28f7c72309b39`). The rules
and reason codes are the evaluator proposed on that issue.

## Published counterpart

`draft-pidlisnyi-aps-04`, Section 8.2.12, "L12. Completeness Is a Separate and
Stronger Claim", is the published text for the `not_established` side. Lines
4356 to 4359 of `https://www.ietf.org/archive/id/draft-pidlisnyi-aps-04.txt`
(SHA-256 of the fetched file
`6912754a92ae82790568ca2169b9b74ab0a24e6aef485b3f0366eb7d1f2a1eb3`):

> A claim that a set is complete MUST state the basis on which it is
> complete, and a verifier that cannot establish that basis MUST report
> not established with the coverage limb named, rather than reading the
> claim as covering the whole set.

Lines 4373 and 4374 of the same file say what that section leaves open:

> It does not define what basis is sufficient
> for a completeness claim.

This family does not settle that question. It fixes one candidate basis so that
its premises and the accounting check can be tested separately.

## The case

An authority epoch has a cutoff. Every declared sink accepts that epoch's
authority only through one admission boundary. The boundary keeps an
append-only sequence of the descendants it admitted and commits to that
sequence at the cutoff. A later observation says the boundary no longer admits
the epoch. A teardown processes descendants, and the operator claims the
teardown was complete.

A signed teardown list shows what was processed, not what had been accepted.
The case asks two separate questions. First, are the premises of one stated
basis present in the record? Missing premises leave the basis not established,
with the missing premise named. Second, under premises the case stipulates, does
the teardown account for every committed descendant? A committed descendant
missing from the teardown contradicts that narrower claim.

## Input schema

Whole-input validation runs before any rule. An input that fails validation is
a fixture error and receives no verdict. A runner reports every violation it
finds as a JSON Pointer (RFC 6901) to the offending location.

Definitions used below:

- **identifier**: a JSON string of length at least one. No character grammar
  and no normalization. Identifiers are compared exactly, code unit by code
  unit.
- **instant**: a JSON string matching
  `YYYY-MM-DDTHH:MM:SS[.fraction]OFFSET` where `T` is the uppercase letter T,
  the fraction is one or more digits, and `OFFSET` is either the uppercase
  letter `Z` or `+hh:mm` / `-hh:mm`. The offset is required. Year is 0001 to
  9999, month 01 to 12, day valid for that month and year in the proleptic
  Gregorian calendar, hour 00 to 23, minute 00 to 59, second 00 to 59 (a leap
  second `60` is rejected), offset hour 00 to 23 and offset minute 00 to 59.
  `-00:00` is accepted and denotes UTC. Lowercase `t` or `z`, a space
  separator, a missing offset, a missing seconds field, and any other deviation
  are errors. Instants are compared as points on the UTC time line after
  applying the offset, never as strings. Fractions are compared exactly, at
  whatever precision they are written.
- **integer**: a JSON number whose value is a whole number with magnitude at
  most 2^53 - 1. `true` and `false` are not integers.
- **map**: a JSON object whose member names are identifiers chosen by the
  input. A map's member set is open. Every other object below has a closed,
  exact member set: a missing member and an unknown member are both errors.

The input is an object with exactly these members:

| member | type | constraint |
|---|---|---|
| `stipulations` | array of identifiers | contains each of the three required stipulations below |
| `scope` | object | exactly `declared_sinks`, `epoch`, `boundary` |
| `scope.declared_sinks` | array of identifiers | non-empty, no identifier repeated |
| `scope.epoch` | identifier | |
| `scope.boundary` | identifier | |
| `sink_configurations` | map of sink identifier to configuration | |
| configuration | object | exactly `epoch` (identifier), `accepts_only_through` (identifier), `digest` (identifier) |
| `runtime_bindings` | map of sink identifier to binding | |
| binding | object | exactly `config_digest` (identifier), `from` (instant), `to` (instant) |
| `admissions` | array of admission | may be empty |
| admission | object | exactly `seq` (integer, at least 1), `descendant_id` (identifier) |
| `cutoff` | object | exactly `at` (instant), `committed_final_seq` (integer, at least 0), `committed_members` (array of identifiers) |
| `cutoff_ordering_evidence` | object or `null` | when an object, exactly `attestor` (identifier), `covers_from` (instant), `covers_to` (instant) |
| `stop_admitting` | object | exactly `boundary` (identifier), `epoch` (identifier), `admits_epoch` (boolean), `asserted_by` (identifier), `observed_at` (instant) |
| `teardown` | object | exactly `processed` (array of identifiers) |

The three required stipulations, as exact strings:

1. `sink configurations and runtime bindings are authentic`
2. `admission sequence is append only`
3. `distinct attestor identifiers denote distinct parties`

`admissions` lists the uniquely accepted descendants in first-acceptance order.
It is not a raw event log. A `descendant_id` that appears in two admissions is a
fixture error. A runner never deduplicates. If repeated admission events become
a legitimate input shape, the event sequence and the committed unique set need
separate members, so that teardown accounting is not defined by event
multiplicity.

Missing evidence is not malformed input. A declared sink may have no entry in
`sink_configurations` or `runtime_bindings`; that is decided by rule 1.
`cutoff_ordering_evidence` may be `null`; that is decided by rule 3. An entry
that is present must be fully well formed. A map entry for a sink outside the
declared set is validated and then not evaluated. An interval whose start is
after its end is well formed and simply contains no instant.

An empty admission sequence with `committed_final_seq` 0 and
`committed_members` `[]` is valid input.

## Rules

Applied in this order. The first rule that matches decides.

1. **Sink configuration and runtime binding.** For each declared sink, in the
   order of `scope.declared_sinks`: if the sink has no configuration, or the
   configuration's `epoch` differs from `scope.epoch`, or its
   `accepts_only_through` differs from `scope.boundary`, the result is
   `not_established` / `sink_configuration_not_established`. Otherwise, if the
   sink has no runtime binding, or the binding's `config_digest` differs from
   the configuration's `digest`, or the binding interval does not contain the
   cutoff (`from <= cutoff.at <= to`), the result is `not_established` /
   `runtime_binding_not_established`. Both checks for one sink run before the
   next sink.
2. **Stop admitting.** If `stop_admitting.boundary` differs from
   `scope.boundary`, or `stop_admitting.epoch` differs from `scope.epoch`, or
   `admits_epoch` is not `false`, or `observed_at` is not strictly after
   `cutoff.at`, the result is `not_established` /
   `stop_admitting_not_established`.
3. **Cutoff ordering.** If `cutoff_ordering_evidence` is `null`, or its interval
   does not contain the cutoff (`covers_from <= cutoff.at <= covers_to`), or the
   interval does not end strictly before the stop observation
   (`covers_to < stop_admitting.observed_at`), the result is `not_established` /
   `cutoff_ordering_not_established`. Otherwise, if `attestor` equals
   `stop_admitting.asserted_by`, the result is `not_established` /
   `cutoff_ordering_independence_not_established`.
4. **Accepted set committed.** With n the number of admissions: if the
   admission sequence numbers are not exactly 1, 2, ..., n in list order, or
   `committed_final_seq` is not n, or `committed_members` is not equal to the
   list of admission `descendant_id`s element by element (same length, then
   equal at every index), the result is `not_established` /
   `accepted_set_not_committed`. The comparison is over the arrays. It never
   joins either side into a string.
5. **Teardown accounts for the committed set.** If any admitted
   `descendant_id` is absent from `teardown.processed`, the result is `invalid`
   / `accepted_descendant_missing_from_teardown`.
6. Otherwise the result is `valid` /
   `teardown_accounts_for_accepted_set_under_stipulated_basis`.

Identifiers in `teardown.processed` that were not admitted do not affect the
result.

## Verdicts and reason codes

Verdicts: `valid`, `invalid`, `not_established`.

| reason | verdict | rule |
|---|---|---|
| `sink_configuration_not_established` | `not_established` | 1 |
| `runtime_binding_not_established` | `not_established` | 1 |
| `stop_admitting_not_established` | `not_established` | 2 |
| `cutoff_ordering_not_established` | `not_established` | 3 |
| `cutoff_ordering_independence_not_established` | `not_established` | 3 |
| `accepted_set_not_committed` | `not_established` | 4 |
| `accepted_descendant_missing_from_teardown` | `invalid` | 5 |
| `teardown_accounts_for_accepted_set_under_stipulated_basis` | `valid` | 6 |

## Negative control

`C1-ordering-taken-as-given` shares input validation and every check outside
rule 3 with the reference. When `cutoff_ordering_evidence` is present it skips
rule 3's interval check and attestor check entirely. When it is `null` it still
returns `not_established` / `cutoff_ordering_not_established`. It models a
verifier that reads a populated ordering field as establishing the ordering.

## What a result means, and what it does not

- `valid` means only that, under the listed stipulations, the teardown accounts
  for the committed accepted set. It is not a positive result for
  APS-LC-COMPLETENESS-BASIS and not evidence that this basis is normatively
  sufficient.
- `invalid` is scoped to this accounting check. It never means an authority
  chain or an artifact is invalid.
- Rules 1 to 4 are necessary conditions in this model, never sufficient ones.
- Rule 3 checks timestamp consistency and that two identifiers differ. The
  family stipulates that distinct identifiers denote distinct parties.
  Identifier inequality is not evidence of independence, and
  `cutoff_ordering_independence_not_established` reports only that the check
  failed.
- Nothing here establishes that admission actually stopped at the cutoff, that
  nothing was admitted between the cutoff and the stop observation, or anything
  about sinks outside the declared set.
- A `valid` result over an empty admission sequence does not establish that no
  descendant existed. It says only that the record commits to an empty set and
  the teardown has nothing in it to account for.
