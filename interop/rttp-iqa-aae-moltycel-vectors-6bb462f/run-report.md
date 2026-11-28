# Run report: independent run of moltycel-aae-vectors (AAE), 2026-11-04

**Operator:** ShaoBao Li (Lee) / [@Aicent-com](https://github.com/Aicent-com), repository maintained under the [@Aicent-Stack](https://github.com/Aicent-Stack) org. **Mode:** independent run, non-author-produced. **Exit status:** 0. **Suspected defective vectors:** none observed.

## Scope and method

Subject: the `moltycel-aae-vectors` candidate (PR #190), three vector sets targeting three published revisions of others' Internet-Drafts — native (15 vectors, draft-kroehl-agentic-trust-aae-00), enforce (26 vectors, draft-kroehl-agentic-trust-aae-02, enforce kernel 3.0), and composition (6 vectors, draft-kroehl-agentic-trust-aae-00 with draft-yossif-psea-02). Frozen inputs: the candidate's 64 files, each a byte copy of MoltyCel/aae-conformance-vectors at commit `6bb462f578c12d339b8fa964a5b1d8f97dbffa68`; `run.sh` compares every one against a fresh clone at that pin before executing anything.

Method: the candidate's own verification pipeline, executed unmodified — three schema validations, three shipped reference verifiers, the verifier unit tests, the PSEA fixture pin, and all three generators with a must-be-byte-identical regeneration gate. Every verification step runs under the candidate's `offline.py` audit hook, which refuses socket and name-lookup calls in the interpreting process. The clone is the only network step; verification itself is offline. We wrote no vectors, altered no verifier, and supplied no expected value.

Declared claim set: that the candidate's verification pipeline passes end-to-end, unmodified, on a second operator's host — nothing more. A run verifies the vectors, not the spec. The lab's separate `interop/aae-envelope` record is the lab's own and is not evidence for this candidate.

## Results

| Suite | Gate | Verification | Extra | Failures |
|---|---|---|---|---|
| native (aae-00, 15 vectors) | schema 15/15 | 15/15 (5 runtime, 10 structural) | unit tests 14/14 | 0 |
| enforce (aae-02, 26 vectors) | schema 26/26 | 26/26 (verdicts + core digests) | — | 0 |
| composition (aae-00 × psea-02, 6 vectors) | schema 6/6 | 6/6 (eight staged rows, row-by-row) | fixture pin OK | 0 |
| negative controls (composition) | — | 11/11 (mutated inputs, expected rows) | — | 0 |
| regeneration | — | 3/3 generators | working tree unchanged — rebuild byte-identical | 0 |
| **Total** | **47/47 schema** | **47/47 vectors** | **11/11 controls · 14/14 tests** | **0 · exit 0** |

## Instrumentation (executed, not asserted)

The byte gate runs before anything scores (any byte difference aborts the run); every verification step executes under the `offline.py` audit hook; the run ends with all three generators re-run and a `git status --porcelain` emptiness check (`ok: rebuild is byte-identical`); the third-party PSEA fixture is checksum-verified; and the console output of the entire session is captured whole as `run-output.txt` — nothing in the report is a paraphrase of a memory.

## Mutation battery

None. This candidate ships no mutation battery; its discriminating power is exercised through the 11 negative controls (mutated inputs with pinned expected rows) and pinned expected verdicts and rejection reasons on every vector. The operator added none: the claim recorded here is the candidate's own pipeline passing unmodified.

## Environment

Python 3.11.2, Debian GNU/Linux 12 (bookworm), kernel 6.1.0-53-amd64, x86_64; cryptography 50.0.2, jcs 0.2.1, jsonschema 4.26.0, jsonschema-specifications 2025.9.1, pytest 9.2.0. Recorded output sha256: `d33a484a643298e3054417bc9683c9be994a23326549fdc46dd357fbeac4bd80`. Wall-clock cost of the full run (clone, byte gate, all suites, unit tests, regeneration): under two minutes, dominated by the clone; verification is offline and fast.

## Findings raised and resolved

Findings on the corpus: none. Operator-side notes (environmental, not scoring): the run host required `python3.11-venv` to be installed before the virtual environment could be created, and the source archive's directory layout nests one `candidates/` level deeper than the checkout path `run.sh` assumes — both resolved before the run; neither touches any vector, verifier or expectation.

## Artifact and seal

The complete artifact (candidate + recorded run + environment record + manifest) is sealed by the operator's organ and archived at <https://iqa.org/conformance/files/aae-runner-20261104a.tar.gz> (SHA-256 `5dd92d2729c90932768a408f39c0a9bb2767c8b9194d1a52b774dfaf56d85695`), with a report page at <https://iqa.org/conformance/aae-runner/>. The seal is verifiable offline with `pip install "iqa-org[ed25519]==1.3.1"` and the bundle at <https://iqa.org/attestations/release-attestations.json>; organ AID `ba92fadd46a51caf25633e0f315c4ad10103b879d7397397362f89dc33817153`.
