# priorseal-aps-payment-limit-d749d269

Interop record for the offline APS decision to PriorSeal execution comparison proposed in
lab issue #138 (from aeoess/agent-passport-system#163). It records runs of another
project's published pair. It is not a family, and it asserts nothing beyond the runs below.

## Pinned inputs

| input | pin |
|---|---|
| PriorSeal repository | `imokokok/PriorSeal` at `d749d2691c3e6be139de4020e7b27cdafca2c428` |
| pair directory | `examples/aps-priorseal-decision-binding-v1/` |
| `priorseal-inputs/payment-within-limit.json` | SHA-256 `c8dd05f412b3d1dd957f66deaf231a8becb9656e8bd1960ba88638cf9ad4c6da` |
| `priorseal-inputs/payment-over-limit.json` | SHA-256 `cb45a8378a5c9f1f7f2695c4d1fb5cbe344d9c840b799cf0ecb786e5ddf3c226` |
| `PAYMENT-LIMIT-REPORT.json` | SHA-256 `d2c1bea5f0acf0afe06c944376c5a471402ab5d48bf85ca267ed9b5876336ae4` |
| APS producer fixtures | `aeoess/agent-passport-system` at `948f99b85343bef2c6fa677c8543965caacfc087`, `fixtures/priorseal-decision-binding/` |
| reference time | `2026-09-19T10:05:00.000Z` |
| dependencies | `agent-passport-system` 6.0.1, `priorseal-sdk` 0.4.0, as pinned by the pair |

PriorSeal commit `b867ac5` later corrected verifier provenance wording in the pair's README
and run report. It does not change the pinned fixtures or report.

## What the pair contains

APS supplies a permit decision whose delegation carries a `spend.per_action` cap of
5,000,000,000,000,000 wei and whose request is an exact call of 1,000,000,000,000,000 wei.
PriorSeal binds that decision's `decision_ref` into a principal-signed exact-call
authorization and adds two separately signed synthetic execution observations.

- Within limit. The observation is 1,000,000,000,000,000 wei. PriorSeal reports `COMPLIANT`.
- Over limit. The observation is 6,000,000,000,000,000 wei. It exceeds the APS cap and it
  differs from the signed exact call. The APS decision and the authorization stay valid.
  PriorSeal reports `NON_COMPLIANT` with the single reason `TRANSACTION_VALUE_MISMATCH`.

The over-limit observation violates two separate conditions. PriorSeal's reason code names
only the exact-call mismatch. The cap comparison is a separate assertion in the pair's
report script, published as `aboveApsCap`. For that reason the claims are recorded
separately below, so neither result stands in for the other.

## Verification split

Claims, one entry each: `layer / claim; runner; Mode A | Mode B; author-produced | independent; implementation`.

1. APS evidence / receipts, decision and delegation verify under the pinned test keys at the
   reference time; aeoess; Mode A; author-produced; `verify-from-package-root.mjs` from
   `948f99b8` (SHA-256 `833b7de7563c26fbfe5d9a33b5935cebb3d68dad417c6f15ab3d84519d93a6f0`)
   over `agent-passport-system` 6.0.1. aeoess authored the APS fixtures and this verifier.
2. PriorSeal evidence / authorization and execution receipt signatures verify for both
   observations; aeoess; Mode A; independent; `priorseal-sdk` 0.4.0 through the pair's
   adapter, both authored by imokokok. aeoess authored neither these signed objects nor
   their verifier. The APS `decision_ref` is treated here only as signed payload data. Its
   semantic correlation to APS evidence is entry 3.
3. Correlation / the APS `decision_ref` and the PriorSeal authorization correlate
   (`DECISION_AUTHORIZATION_CORRELATED`); aeoess; Mode A; author-produced; the pair's
   adapter, authored by imokokok. The correlated APS decision evidence is a claim input
   authored by aeoess.
4. Exact call and observation agreement / the within-limit observation matches the signed
   call and the over-limit observation does not (`TRANSACTION_VALUE_MISMATCH`); aeoess;
   Mode A; independent; `priorseal-sdk` 0.4.0 compliance check, authored by imokokok.
   aeoess authored neither the authorization, the observations nor the check.
5. APS cap compliance / the within-limit observation is at or below the APS
   `spend.per_action` cap and the over-limit observation is above it; aeoess; Mode A;
   author-produced; the BigInt comparison in the pair's `payment-limit-report.mts`, authored
   by imokokok. The cap is a claim input from the APS fixtures, authored by aeoess.
6. Report reproduction / `npm run verify:payment-limit` regenerates
   `PAYMENT-LIMIT-REPORT.json` byte for byte; aeoess; Mode A; author-produced; the pair's
   report script, authored by imokokok. The report embeds SHA-256 digests of APS fixture
   files authored by aeoess. This entry records that the published report is the script's
   output. It adds no claim beyond entries 1 to 5.

These records are attributed per claim. Merging this interop record does not create an end-to-end verdict.

Layers 1, 3, 5 and 6 have no independent record here.

## Other observations, not records

- APS input identity. The 17 manifest-covered APS JSON files, `MANIFEST.sha256` and
  `README.md` in the pair are byte-identical to `948f99b8`. The pair's
  `verify-from-package-root.mjs` differs, because the pair generates it from a TypeScript
  port introduced in PriorSeal `705cb1c`. Entry 1 therefore runs the original script from
  `948f99b8`, not the pair's copy. See `results/04-aps-inputs-byte-compare.txt`.
- Earlier runs. aeoess reported a fresh-clone run on Node 24.11.1 in #163. imokokok
  reported running the original APS script and the generated port on Node 24.19.0 in #138.
  imokokok's run of entry 1 would be independent under `CONTRIBUTING.md`, since imokokok
  authored neither the APS fixtures nor the original verifier. It is not recorded here
  because its verbatim output is not published. It can be appended as its own record.
  The run below repeats aeoess's earlier run, so it is a reproduction by the same party,
  not additional independent evidence.

## Scope

Offline, synthetic observations at a fixed reference time. This record does not
establish independently observed chain execution, live APS currency, APS decision-level
single use, that any transaction was sent, or production use of either project.

## Run

| field | value |
|---|---|
| who ran it | aeoess |
| date | 2026-09-29 |
| run mode | Mode A, reproduction |
| implementation name | the PriorSeal pair's own verifiers, and the original APS verifier from `948f99b8` where stated |
| implementation repo and commit or version | `imokokok/PriorSeal` at `d749d2691c3e6be139de4020e7b27cdafca2c428`, `aeoess/agent-passport-system` at `948f99b85343bef2c6fa677c8543965caacfc087` |
| corpus reference | not applicable, no suite fixture was executed. Lab `main` was `df65bcbb9b00b471f9849f4f2d0ce2e770150e24` when this record was prepared |
| author-produced or independent | mixed by claim, see Verification split |
| environment | Ubuntu 24, Node.js v22.22.2, npm 10.9.7 |
| suspected defective vectors | none |
| procedure | clone `imokokok/PriorSeal`, check out `d749d269`, `npm ci` at the repository root and in the pair directory, then the commands below |

Commands were executed in an agent-assisted environment under the aeoess maintainer's
direction. For authorship classification, the runner is aeoess. Agent assistance does not
create independence.

Verbatim output is in `results/`:

| file | command | result |
|---|---|---|
| `01-test-aps-priorseal.txt` | `npm run test:aps-priorseal` | exit 0, producer verifier `ALL CHECKS PASSED`, 26 tests, 26 pass |
| `02-payment-limit-report-byte-compare.txt` | `npm run --silent verify:payment-limit`, then `cmp` against the committed report | exit 0, `cmp` exit 0, SHA-256 `d2c1bea5…` for both |
| `03-original-aps-verifier-948f99b8.txt` | original `verify-from-package-root.mjs` from `948f99b8` over the pair's `aps-inputs` | exit 0, `ALL CHECKS PASSED` |
| `04-aps-inputs-byte-compare.txt` | byte comparison of the pair's `aps-inputs` against `948f99b8` | 19 identical, 1 differs (`verify-from-package-root.mjs`) |

One environment note. The pair directory's own `npm test` fails if only the pair directory
is installed, because the adapter test imports PriorSeal's root `src/`, which needs the
root dependencies. Installing at the repository root first, as `test:aps-priorseal` does,
resolves it. This is a setup requirement, not a defect in the pair.
