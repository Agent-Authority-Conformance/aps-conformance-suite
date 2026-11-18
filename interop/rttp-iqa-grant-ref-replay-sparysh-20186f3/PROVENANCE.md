# Provenance

- Operator (replay): ShaoBao Li (Lee) / Aicent Stack — RTTP CRI 27, IQA CRI 28.
- Operator (replayed record): Andrii Sparysh (GitHub `andreysparish`), using an AI assistant; the record's checker (`reader/check_reader.py`) and comparison script (`reader/compare.py`) are his work, executed here as code-as-run.
- Mode: pipeline replay of a merged lab record — our pipeline executes the record's own checker and compares the outputs against the recorded bytes; the wrapper adds no verdict logic.
- Record classification (adopted verbatim from the lab): the replayed run was blind to the candidate's expected results; its semantic verdicts are labeled author-produced Mode B because Andrii wrote the checker — a reading record, not a certification, not an independent run.
- Source of record: `interop/sparysh-reading-aicent-grant-ref-20186f3` in Agent-Authority-Conformance/aps-conformance-suite, merged via PR #234 (2026-11-17T20:40:28Z, merge commit `dbf9c245ecca1636344dc7f2e23af7dd8844f58d`); corpus pinned at lab commit `20186f3ebc78de2f34e79a0b4bfe5f828599653b`, candidate `aicent-grant-ref` revision 1.
- Authorship relationships: the replay operator authored the pinned draft (`draft-li-rttp-iqa-addressing-02`) and the replayed family's vectors, checkers and expected values; the replayed record's author authored none of the candidate and none of the replay wrapper; the two sides share no employer or affiliation.
- Vendor: seven frozen files digest-gated before anything executes — the record's checker and comparison script (digests as published in the record's own run report), the pinned draft, the record's blind copy, and the candidate's sealed vectors, description and id-map (digests as pinned by the record's fetch manifest).
- Normative basis: draft-li-rttp-iqa-addressing-02, sections 8.1 and 8.2, TXT sha256 `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044`.
- Environment: Windows 11, CPython 3.14.2, `python -I` isolated mode (see `ENVIRONMENT.txt`); standard library only, zero dependencies, no network access at replay time.
- Output: `run-output.json` (machine-readable, deterministic, no timestamps, no paths) and `run-output.txt` (console, uncut).
- Certification: none. This is a replay record, not a runtime certification, not a merge vote, and not a judgment on the reading; the lab certifies nothing and maintainer decisions are separate from this record.
