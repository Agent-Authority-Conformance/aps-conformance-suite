# RTTP & IQA independent run over moltycel-aae-vectors (AAE) — non-author-produced

This directory records an independent, non-author-produced run of the `moltycel-aae-vectors`
candidate (merged upstream in PR #190): conformance vectors for the Agent Authorization Envelope, submitted by Lars Kroehl (MoltyCel, for CryptoKRI GmbH / MolTrust). The operator is ShaoBao Li (Lee) / @Aicent-com, not affiliated with MoltyCel / MolTrust / CryptoKRI, and wrote none of the vectors, generators, verifiers or expected values.

The candidate's own evidence table (in `candidates/moltycel-aae-vectors/CANDIDATE.md`) recorded two author-produced runs and the line "No independent run exists yet"; this record is filed to close exactly that gap. The runner here is the candidate's own shipped pipeline, executed unmodified, so the independence of this record rests on the operator rather than on an alternate implementation — the complement of the lab's other RTTP & IQA records (`interop/rttp-iqa-lra-runner-*`), where the implementation is independent and the operator is the author.

## Result

All suites green, exit 0: 64 candidate files byte-verified against the pinned source commit `6bb462f578c12d339b8fa964a5b1d8f97dbffa68` before anything ran; native set 15/15 (5 runtime, 10 structural) plus 14/14 verifier unit tests; enforce set 26/26 (verdicts plus recomputed core digests); composition set 6/6 row-by-row across the eight-stage ladder; 11/11 negative controls; and the regeneration gate rebuilt every vector byte-identically. No suspected defective vector was observed.

## Re-run

The runner is the candidate's own pipeline, already merged at `candidates/moltycel-aae-vectors/`. Its `run.sh` clones the source at the pinned commit (the only network step), byte-checks the 64 listed files, and runs every verification step under the `offline.py` audit hook, which refuses socket and name-lookup calls in the interpreting process (child processes are not covered, as the candidate itself states):

```
cd candidates/moltycel-aae-vectors
pip install cryptography jsonschema jcs pytest
sh run.sh
```

Expected output ends with `ok: rebuild is byte-identical` and exit status 0; the byte gate prints `ok: 64 files`. The full console output of the recorded run is preserved verbatim in `run-output.txt`.

## Files

- `run-report.md` — the run report (scope, method, results, findings)
- `PROVENANCE.md` — operator, mode, independence statement, environment
- `RESULTS.md` — per-vector results, transcribed from the recording
- `VECTOR-INVENTORY.md` — what the three vector sets and the negative controls contain
- `run-output.txt` — the complete console output of the recorded run, uncut
- `SHA256SUMS.txt` — digests of the accompanying files
