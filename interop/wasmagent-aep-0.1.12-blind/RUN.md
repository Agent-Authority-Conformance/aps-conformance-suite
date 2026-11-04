# wasmagent AEP 0.1.12: a second verifier written from the published rules, first blind run

Run record, 2026-11-02 UTC. Context: `aeoess/agent-governance-vocabulary#177`, where the AEP maintainer pinned
`wasmagent-protocol` 0.1.12 for this run (comment 6568905497).

## Target

    package            @wasmagent/protocol 0.1.12 (npm pack, sha256 30b3c2cd...9af90e, registry integrity matches)
    certified target   aep-certified-2026-09-16-01 (conformance/aep/certified-target.json in the package)
    manifest           protocol_version 0.1.10, 33 current targets, historical/ not scored
    signing profile    aep-dsse-ed25519-decoded-body-v1

## How the verifier was written

From `conformance/aep/IMPLEMENTER.md`, `conformance/aep/README.md`, `conformance/aep/verifier-result-contract.md` and
`schemas/aep/aep-record.schema.json` only. It imports no WasmAgent code. Not read before the run: any WasmAgent source,
the `self-check` subcommand, `scripts/`, `adequacy/`, the cold-run reader in WasmAgent/wasmagent-protocol#261, and this
lab's own 2026-09 `interop/wasmagent-aep-2026-09-13-03/adapter/lab-semantic.py`. The manifest was read before the run
for fixture paths and verifying keys only. Results were written and hashed before any expected verdict was read.
Structural validation uses the `jsonschema` package (Draft 2020-12), canonical JSON uses `rfc8785`, signatures use
`cryptography` Ed25519.

## First blind run (`verifier/aep_verify_v1_blind.py`, `results/blind-run-1.json`, sha256 0637cc70...5a2f7b)

Every layer the manifest names: structural 33/33, semantic 31/33, authenticity 17/33, chain 7/9. 20 raw mismatches:

- 18 rows where the manifest gives `not-checked` (authenticity 16, chain 2) and the verifier evaluated the layer
  (`unsigned`, `not-present`). Under section 1 of the result contract these are an evaluation state against an outcome.
  They are listed because IMPLEMENTER.md asks for the raw list.
- `invalid-semantic/unknown-attribution-grade.json`, semantic: expected `invalid`, got `valid`. The verifier applied the
  vocabulary only through the floor ordering, so an out-of-vocabulary `attribution_backing` passed. A miss:
  IMPLEMENTER.md names vocabulary as a semantic rule.
- `invalid-semantic/empty-observed.json`, semantic: expected `invalid`, got `valid`. The verifier read "absent floor
  means no grading claim" as making an empty observed set consistent. The manifest note calls it an empty grading
  claim. The schema descriptions do not state that rule.

## Second run (`verifier/aep_verify_v2.py`, `results/run-2.json`)

The two fixes above, nothing else. Structural 33/33, semantic 33/33. The 18 evaluation-state rows are unchanged.

## Readings compared with the cold-run record (read after the blind run)

The cold-run record in aos-standard/catalog `docs/runs/wasmagent-aep-cold` at `4853cef` lists twelve readings, R1 to R12.
This verifier made the same reading for R1 to R3 and R5 to R11. It differed on R4 in the blind run (an empty observed set
without a floor passed, the cold run failed it) and on R12 (a sequence that mixes signed and unsigned records is reported
`mixed`, not `unsigned`). Its fourth finding, that every `*-resigned` fixture keeps the legacy `signature` field from the
original signing, shows here too: the verifier reports every failing check, and each re-signed fixture fails both its
intended check and the legacy-field check. `dsse/tampered-sig-only.json`, new since that record, fails on the signature
alone here.

## Candidate cases (`cases/`)

Nine additional cases, including controls, for missing combinations and checks the corpus does not isolate, signed with a throwaway key generated for this record
(`cases/extra-verify-key.hex`, key id `extra-key-01`, registered for this run only): X0 positive control, X1 unknown
keyid, X2 subject digest wrong with the predicate equal to the record, X3 predicate changed with a digest consistent with
it, X3b predicate changed with a digest that matches the record, X4 two subjects, X5 count below the number of observed
grades, X6 count and floor consistent, X7 legacy signature not derived from the envelope. Expected outcomes are this
author's reading of IMPLEMENTER.md, labelled candidate, not corpus verdicts. The v2 verifier agrees with all nine, which
shows only that the cases and this verifier match each other.

## Verification split

- structural / schema acceptance; aeoess; Mode B; author-produced; jsonschema over the canonical schema, driven by
  `aep_verify_v*.py`. The runner wrote the harness that decides the verdict.
- semantic / derived invariants; aeoess; Mode B; author-produced; `aep_verify_v*.py`. The runner wrote the
  recomputation.
- authenticity / DSSE profile and binding; aeoess; Mode B; author-produced; `aep_verify_v*.py` with `cryptography`
  Ed25519. The runner wrote the recomputation.
- chain / link states; aeoess; Mode B; author-produced; `aep_verify_v*.py`. The runner wrote the recomputation.
- candidate cases; aeoess; Mode B; author-produced; vectors and expected outcomes written by the runner.

These records are attributed per layer. Merge of this family is not an end-to-end verification or a family-level verdict.

## Reproduce

`./run.sh` packs the pinned tarball, checks its sha256, reruns both verifier versions and checks both result files byte
for byte, grades run 2, and reruns the candidate cases.

## Maintainer answers and known limits (2026-11-03)

- `mixed`: telleroutlook answered on vocabulary #177 (comment 6591027374) that `mixed` is not a value in
  `verifier-result-contract.md` section 3, and that the contract has no rule yet for combining authenticity results across
  the records of one file. In both verifier versions `mixed` is my own aggregation, outside the contract. Neither result
  file carries it, so no graded result depends on it.
- Canonical key order: both verifier versions canonicalize with the `rfc8785` Python package (0.1.4 where the runs were
  made, checked 2026-11-03), which sorts keys by UTF-16 code units as RFC 8785 section 3.2.3 requires. IMPLEMENTER.md
  in the 0.1.12 package describes code point order. After these runs the maintainers changed it to UTF-16 code units
  (WasmAgent/wasmagent-protocol#268, merged 2026-11-04 as `3ade5a1`) and closed #265. None of the 69 corpus documents or
  the 10 candidate case files has a non-ASCII or integer-like key, where these rules differ, so these runs do not show
  which rule the signed fixtures follow.

## Third-party material

`cases/X0` to `cases/X7` are modified copies of `valid/minimal-v05.json` from the `@wasmagent/protocol` 0.1.12 npm package (source repository WasmAgent/wasmagent-protocol), used under the Apache License, Version 2.0. `cases/make_cases.py` applies and records every change to that file. The package files listed in `paths.txt` are read from the package at run time and are not copied here. This repository's LICENSE carries the Apache License 2.0 text.


## Reproduction gate and reader limits (2026-11-04)

The wrapper now stops on either frozen-output mismatch, a failed candidate
expectation or a candidate-process error. The grading report remains diagnostic,
and its retained evaluation-state differences are described above. The case runner's
status controls whether its checks passed.

The preserved v1 and v2 readers and their original result files are unchanged.
They are not general verifier-contract conformance implementations. For example,
an envelope with a null signature entry or a decoded Statement that is an array
raises an exception rather than producing a layer outcome. The published corpus
and the recorded candidate cases do not exercise those malformed shapes.

Direct review probes accepted a correctly JCS-bound record containing Unicode
and integer-like property names and rejected a signature-valid statement whose
subject digest used code-point ordering. Those probes check the historical
reader's hashing choice. They are not additional agreed corpus verdicts.
