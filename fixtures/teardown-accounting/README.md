# teardown-accounting

A candidate family for one question: does a teardown account for every
descendant a boundary had accepted at a cutoff, and which premises of one
stated basis does the record leave not established? Raised and scoped on
Agent-Authority-Conformance/aps-conformance-suite#144.

**Status: candidate against [`PROPOSED.md`](PROPOSED.md), this family's own
proposed text.** It is not a conformance family, not a draft requirement, and
not part of the APS-native corpus: it is not in `fixtures/manifest.json` and is
not counted there. Every case carries `label: "candidate_against_proposed"`.

## Class

Class 2 of `docs/fixture-format.md`, a family with a dedicated verifier. Its
claim is a verdict over an input, not a canonical-byte comparison, so the
generic runner does not check it, and it ships its own verifier wired into
`npm test` under its own script.

It is not class 4, which covers fixtures the repository generates with a
published generator and seed. The committed development cases are literal
inputs, and verification reads them without running a generator or using
randomness, time or network access. It is not class 3 either, since nothing
here is ingested from an external system.

## Why a separate family

The first proposal on #144 placed this as a seventh group of
`lifecycle-infrastructure-failure`. That family has one family-level proposed
text, pinned to a commit of aeoess/agent-authority-lifecycle, and its runners
check every case against it. That repository is frozen and its
`CONTRIBUTING.md` says runnable cases built from its material live in this
lab, so the teardown text cannot land there. A separate family owns its
proposed text in `PROPOSED.md` and leaves the existing family's 30 vectors, pin,
checksums, input digests and SDK run records untouched.

## What is tested

[`PROPOSED.md`](PROPOSED.md) is the whole definition: the input schema, six
rules applied in order with the first match deciding, eight reason codes, three
verdicts, the negative control, and the claim limits. In short:

1. each declared sink has a configuration accepting the epoch only through the
   boundary, and a runtime binding to that configuration across the cutoff
2. the stop admitting observation names the boundary and epoch, says the epoch
   is no longer admitted, and comes after the cutoff
3. ordering evidence exists, covers the cutoff, ends before the stop
   observation, and names an attestor other than the stop asserter
4. the cutoff commits to exactly the admission sequence, compared element by
   element
5. every committed descendant appears in the teardown, else `invalid`
6. otherwise `valid`

Rules 1 to 4 return `not_established` with the premise named. Whole-input
validation runs first, and a malformed input is a fixture error that receives
no verdict. A fixture-error case names the exact set of JSON Pointers the
validator must report, so a refusal for the wrong reason fails.

Case files for this candidate family must not contain duplicate JSON member
names after JSON string escape decoding. A file with a duplicate member is
malformed and is refused before any case is evaluated, as a failure of the
whole file that names the RFC 6901 pointer of the repeated member. This follows
the same fail-before-map principle that draft-pidlisnyi-aps-04 Section 5.1
applies to the action-reference input object, but here it is a rule of this
family's proposed input contract, not an APS requirement this family exercises.
This family does not exercise or satisfy any draft parser requirement. The
TypeScript runner scans the raw text before `JSON.parse`, and the Python runner
parses with an `object_pairs_hook` that keeps every member and checks the tree
before building any dict. Each runner also checks its detector directly
against the same literal strings.

### Negative control

`C1-ordering-taken-as-given` shares validation and every check outside rule 3
with the reference. With ordering evidence present it skips rule 3's interval
and attestor checks. With `null` evidence it still returns
`cutoff_ordering_not_established`. It runs against every case. On a
fixture-error case it must refuse identically. Elsewhere its observed fail set
must equal the declared fail set exactly: `TA-DEV-d`, `TA-DEV-g`, `TA-DEV-h`.

## Cases

27 author development cases in `dev-cases.json`.

| id | what it pins | expected |
|---|---|---|
| `TA-DEV-a` | positive control | `valid` |
| `TA-DEV-b` | sink-b runtime binding removed | `not_established` / `runtime_binding_not_established` |
| `TA-DEV-c` | ordering evidence `null` | `not_established` / `cutoff_ordering_not_established` |
| `TA-DEV-d` | ordering attested by the stop asserter | `not_established` / `cutoff_ordering_independence_not_established` |
| `TA-DEV-e` | an accepted descendant omitted from teardown | `invalid` / `accepted_descendant_missing_from_teardown` |
| `TA-DEV-f` | commitment disagrees with the admissions | `not_established` / `accepted_set_not_committed` |
| `TA-DEV-g` | ordering interval misses the cutoff | `not_established` / `cutoff_ordering_not_established` |
| `TA-DEV-h` | interval covers the cutoff, ends after the stop | `not_established` / `cutoff_ordering_not_established` |
| `TA-REG-01` | zero descendants, empty commitment, empty teardown | `valid` |
| `TA-REG-02` | `digest` and `config_digest` deleted for every sink | fixture error |
| `TA-REG-03` | empty strings for epoch and boundary fields | fixture error |
| `TA-REG-04` | `declared_sinks` empty | fixture error |
| `TA-REG-05` | `declared_sinks` repeats a sink | fixture error |
| `TA-REG-06` | `asserted_by` is the literal `__any__` | `valid`, reference and control |
| `TA-REG-07` | sink-b binding removed and `covers_from` not a time | fixture error, not a rule 1 verdict |
| `TA-REG-08` | `["a,b","c"]` committed against admissions `["a","b,c"]` | `not_established` / `accepted_set_not_committed` |
| `TA-REG-09` | a descendant repeated in admissions | fixture error |
| `TA-REG-10` | unknown top-level member | fixture error |
| `TA-REG-11` | unknown member in one sink configuration | fixture error |
| `TA-REG-12` | positive control with every instant in `+02:00` | `valid` |
| `TA-REG-13` | an instant with no offset | fixture error |
| `TA-REG-14` | `2026-02-30T11:00:00Z` | fixture error |
| `TA-REG-15` | `admits_epoch` as `0` | fixture error |
| `TA-REG-16` | `admits_epoch` as `"false"` | fixture error |
| `TA-REG-17` | no stipulations | fixture error |
| `TA-REG-18` | empty attestor identifier | fixture error |
| `TA-REG-19` | an admission `seq` given as `true` | fixture error |

`TA-REG-01` is `valid` because the record commits to an empty set and the
teardown has nothing in it to account for. It does not establish that no other
descendant existed.

Each runner also checks its sequence comparison directly: `["a,b","c"]` against
`["a","b,c"]` and `["a","b"]` against `["a,b"]` are unequal.

## Provenance

`dev-cases.json` carries `provenance: "author development cases, not
contributed vectors and not independent evidence"`. The same author wrote
`PROPOSED.md`, the cases, and both runners. `TA-DEV-a` to `TA-DEV-h` are the
eight cases proposed on #144, in the input shape of danyka-icam's exploratory
prototype posted there (ZIP SHA-256
`8eb4690da88e832207dc20ddfeab75e5e2e5e4d7b4ef3323f8b28f7c72309b39`). The
regressions `TA-REG-01` to `TA-REG-19` are this lab's.

`vectors.json` holds eight vectors contributed by danyka-icam in #151 and
added at merge commit `5d4b0672`, with their own `provenance` and
`proposed_text` pin. `generator.py` produces them as `REGENERATION.md`
describes. They use the same base input as the development cases, so they show
that the contract round-trips through the contributor's generator. They add no
new tested scenarios and are not independent evidence for the evaluator. They
never replace the dev cases. Both runners always run `dev-cases.json`, also
run `vectors.json` under the same checks, and fail when it is malformed. Each
runner checks the `PROPOSED.md` hash against the pin in every file it runs.
Neither runner executes `generator.py`.

Each case file pins PROPOSED.md by SHA-256. This candidate family carries no
historical digest set.

## Determinism

No randomness, no wall clock, no network, no seed. Every input is a literal.
Instants are parsed under the grammar in `PROPOSED.md` and compared as exact
UTC instants, never as strings. Neither runner uses a lenient date parser.

## Running

TypeScript, from the repository root. It runs in `npm test`:

    npm ci --include=dev
    npm run verify:teardown-accounting

Expected final line:

    teardown-accounting TypeScript: passed

Python, standard library only, written from `PROPOSED.md` rather than ported
from `harness.ts`. It is kept out of `npm test`, which stays Node only so it
runs on the Windows job, and runs as its own CI step in the `suite` job after
the pinned `actions/setup-python`:

    npm run verify:teardown-accounting:py

Expected final line:

    teardown-accounting Python: passed

Both runners accept `--results-only`, which prints one tab-separated line per
case (file, id, reference result, control result) and nothing else, so their
outputs can be compared with `diff`. Both accept `--dev-cases PATH` and
`--vectors PATH` to run against another copy of a case file.

## Verification split

`reference model and negative control / every case's expected verdict and
reason or refusal under the reference evaluator, and the control's observed
fail set equalling its declared fail set; runner
fixtures/teardown-accounting/verify.ts; Mode A; author-produced; implementation
fixtures/teardown-accounting/harness.ts.` Author-produced because the same
author wrote the proposed text, the cases, the harness and the runner.

`reference model and negative control / the same claim, recomputed by a second
implementation; runner fixtures/teardown-accounting/verify.py; Mode B;
author-produced; implementation fixtures/teardown-accounting/verify.py's own
validator and rules.` Author-produced for the same reason, although neither
implementation was ported from the other.

These records are attributed per layer. Merge of this family is not an
end-to-end verification or a family-level verdict.

## What this does not claim

- `valid` means only that, under the listed stipulations, the teardown accounts
  for the committed accepted set. It is not a positive result for
  APS-LC-COMPLETENESS-BASIS and not evidence that the basis is normatively
  sufficient.
- `invalid` is scoped to that accounting check. It never means an authority
  chain or artifact is invalid.
- Rules 1 to 4 are necessary conditions in this model, never sufficient ones.
- Rule 3 checks timestamp consistency and that two identifiers differ. The
  family stipulates that distinct identifiers denote distinct parties.
  Identifier inequality is not evidence of independence, and
  `cutoff_ordering_independence_not_established` reports only that the check
  failed.
- Nothing here establishes that admission actually stopped at the cutoff, or
  anything about sinks outside the declared set.
- The published counterpart for the `not_established` side is
  `draft-pidlisnyi-aps-04` Section 8.2.12, quoted in `PROPOSED.md`. That
  section does not define a sufficient basis, and neither does this family.
