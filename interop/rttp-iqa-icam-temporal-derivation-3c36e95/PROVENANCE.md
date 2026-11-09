# Provenance

- Operator: ShaoBao Li (Lee) / @Aicent-com, Aicent Stack — RTTP CRI 27, IQA CRI 28.
- Mode: independent implementation over author-produced vectors (non-author-produced relative to the candidate; the operator authored the pinned draft `draft-li-rttp-iqa-addressing-02` but none of the candidate's vectors, checkers, oracles, or expected values).
- Candidate: `icam-temporal-derivation` by Nika Novak (ICAM / aiclavis), merged upstream in PR #218 (2026-11-08T17:06:55Z); corpus pinned at lab main `3c36e95`, frozen under `vendor/` and digest-gated against the candidate's own `CHECKSUMS.sha256` (6/6 before anything ran).
- Code as run: `icam_runner.py` in this directory (distinct implementation; the candidate's reference oracle is vendored frozen but never executed).
- Normative basis: draft-li-rttp-iqa-addressing-02, sections 6.1 and 7.2 (step 2), TXT sha256 `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044`.
- Environment: Windows, CPython 3.14, `python -I` isolated mode (see `ENVIRONMENT.txt`); standard library only, zero dependencies, no network access at run time.
- Output: `run-output.json` (machine-readable, deterministic, no timestamps) and `run-output.txt` (console, uncut).
- Independence: the runner re-derives every verdict from the published draft text; the candidate's input and result vocabulary is adopted only as the interface contract; the advisory `supplied_boundary_classification` input is never consulted.
- Certification: none. This is a run record, not a runtime certification and not a merge vote; the lab certifies nothing and maintainer decisions are separate from this record.
