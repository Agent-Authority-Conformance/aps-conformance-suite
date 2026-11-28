# Provenance

## Lab repository

- Repository: `Agent-Authority-Conformance/aps-conformance-suite`.
- Commit: `0e0064bf2cc6b221bb0b22c893964e389fa7aa3d`.
- Candidate: `aicent-lease-boundary`, revision 1.
- How fetched: by `inputs/aicent-lease-boundary-reading-1-fetch-inputs.sh`, which downloaded `candidates/aicent-lease-boundary/vectors.json` and `candidates/aicent-lease-boundary/CANDIDATE.md` from `raw.githubusercontent.com` at the pinned commit and checked each against a SHA-256 written in the script. Both checks printed `ok` (`logs/fetch.log`).
- When: 2026-11-18; `logs/fetch.log` was written at 08:22:18Z.

## Files read, with digests

| File | SHA-256 | When read |
|---|---|---|
| task description (the boundary set out below) | not part of the lab corpus | before setup |
| `inputs/aicent-lease-boundary-reading-1-fetch-inputs.sh` | `a840c8a4f5d370ebe8a19b58ab6db74a4a1e07eeda3995fb9dbc437e246e0447` | before setup |
| `inputs/draft/draft-li-rttp-iqa-addressing-02.txt` (sections listed below) | `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` | phase 1 |
| `inputs/blind/cases.json` | `9f94b748437c0544e5b02bf35fb14f99be80f88774f85e992387b2219a8c0e46` | phase 1 |
| `inputs/sealed/id-map.json` | `1410ed0293112ef7db1d498428e7fc4405fa5e4912865feccea129d10b5216ac` | phase 2 only |
| `inputs/sealed/vectors.json` | `71735739303dcbc248e3939535d754c702d00109cb4c6f1b4a02316ff29d773c` | phase 2 only |
| `inputs/sealed/CANDIDATE.md` | `076693695c6142dabe98046ca4c47bb80bee733309726316f5902a793d56ad6f` | phase 2 only |

The digests are those of `inputs/SHA256SUMS`, written by the fetch script. Only `inputs/SHA256SUMS` and the fetch script are kept in this directory.

## The draft

- Revision: `draft-li-rttp-iqa-addressing-02`; SHA-256 `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044`, checked by the fetch script (`ok`).
- How obtained, as the fetch log states it: `draft read from: https://www.ietf.org/archive/id/draft-li-rttp-iqa-addressing-02.txt`. No copy was supplied; the fetch script found no file with the draft's digest in the directories it searches and downloaded it from that URL.
- Sections read, in order:
  1. The heading lines of the whole draft (a `grep` for numbered headings), to locate the sections in scope. Only the heading lines were printed.
  2. 6.1 The Lease; 6.2 Answer Modes; 6.3 Evaluation at the Moment of Use (in scope). The same line range printed 6.4 Out of Scope, which 6.3 refers to ("the residual treatment of Section 6.4 apply").
  3. 7.2 The Attestation Envelope (iqa), up to the heading of 7.2.1 (in scope).
  4. 8.1 Refusal Reasons: referred to by 6.2 ("refuses the call with authority_not_determined (Section 8.1)"; "answers authority_revoked or evidence_expired (Section 8.1)") and by 6.3 ("MUST be answered as expired (Section 8.1)").
  5. 2 Conventions and Terminology: 6.1 to 6.3 and 7.2 use the BCP 14 key words and terms defined there (organ, standing, trust lease, refusal reason).
  6. 9.2 The iqa scheme: referred to by 6.2 ("MUST NOT be read as affirmative standing (Section 9.2)").
- Sections not read: the front matter and table of contents; 1; 3; 4 and all its subsections (4.4 is referred to by 7.2 for ROUTE_SHARD, which no case uses); 5 and all its subsections; the introductory text of 6 (before 6.1); the introductory text of 7; 7.1 and its subsections; 7.2.1; the introductory text of 8; 8.2 (defines the grant reference; not referred to by 6.1, 6.2, 6.3 or 7.2); 8.3; 8.4; the introductory text of 9; 9.1; 10; 11 and its subsections; 12 (referred to by 7.2 for a comparison of formats, which no case uses); 13; 14; 15; 16; and the documents [IQA-SPEC], [RFC2104], [FIPS180]. RFC 2119 and RFC 8174 were not read as documents; the key words were taken with the meaning section 2 assigns them by reference to BCP 14.

## Boundary as kept

- The phase-1 zip `sparysh-reading-aicent-lease-boundary-0e0064b-phase1.zip` was written at 2026-11-18T08:27:57Z, before any file under `inputs/sealed/` was opened. Its SHA-256 is `3cd457fb1c7a27c51aa11f478a08db1d3951bd6895e5333b32ad9f1761cb4c6b`. It is kept in `logs/`, with its digest in `logs/phase1-zip.sha256`. It contains `out/phase1.json`, `out/phase1-sensitivity.json`, `reader/checker.py`, `ambiguity-log.md` as it stood, `logs/transcript.log` and `logs/fetch.log` as they stood, `inputs/SHA256SUMS` and the fetch script.
- Not downloaded: the candidate's `check.py` and `mutate.py`.
- Not read: `check.py` and `mutate.py`; any other file of the lab repository (other candidates, including the `aicent-*` candidates and the `aicent-grant-ref` candidate named in `CANDIDATE.md`; `fixtures/`; `interop/`; `docs/`); the draft author's own pages, run records and mailing-list threads; any other implementation, checker or reading of the draft.
- `out/phase1.json` was not edited after the zip. Its SHA-256 is `0f73cf747351218369a395a138851b164dbd1ff0ffb97eaf4d279af075ba457f`; in phase 2, `cmp` found it identical to the copy inside the phase-1 zip (`logs/transcript.log`).
- No network request and no web search was made after setup.

## Events at the boundary

1. Before setup, these commands ran outside `logs/transcript.log`: creating the record directory, copying the fetch script into it, listing the user-data directory and its uploads directory (the uploads directory was empty), and printing the Python version, the operating system release and the kernel.
2. Each command of `logs/transcript.log` was run through a small logging wrapper that writes the command, its output and its exit code to that file. The wrapper is not part of the record and read no input of the run.
3. The `grep` for numbered headings printed the heading line of every section of the draft, including sections outside the four in scope. No body text was printed.
4. The line range printed for 6.1 to 6.3 also printed 6.4, which 6.3 refers to.
5. `mkdir -p out`, before the first checker run, ran outside the transcript.
6. Two commands that print parts of this run's own outputs ran outside the transcript: one in phase 1, printing the `ambiguous_detail` of the ambiguous cases from `out/phase1.json`; one in phase 2, printing the divergent and part-scored rows of `out/final.json`.
7. The citation check was tested on an altered copy of the draft in a temporary directory, which was then deleted (`logs/transcript.log`).
8. The re-run commands of `README.md` were tested in phase 2 from copies of the already fetched inputs placed in `rerun/inputs/`; their fetch step was not attempted, because no network request was made after setup. `rerun/` was then deleted.
9. One command in phase 2 contains a `sha256sum -c` call with a path that does not resolve from the record's directory; it ran with its output discarded and is followed in the same line by the check that did run (`logs/transcript.log`).
10. Not recorded in the transcript, as packaging: the commands that wrote the phase-1 zip, the zips saved after phase 2 and at the end, the copy of the phase-1 zip into `logs/` with its digest file, the insertion of `logs/transcript.log` into the "Commands" section of `run-report.md`, the generation of `SHA256SUMS.txt`, its `sha256sum -c` check, the check for `__pycache__` and `.pyc`, and the removal of the fetched inputs and of the working copy of the fetch script from the directory before packaging.
11. No file in the permitted set turned out to contain someone's reading or code rather than data or specification text.

## Authorship

- Carried out and checked by Andrii Sparysh (GitHub `andreysparish`), using an AI assistant.
- Andrii Sparysh authored none of the candidate, its vectors, its checker, the draft, or any claim input.
- He wrote the checker (`reader/checker.py`) and the comparison script (`reader/compare.py`), so every claim of this record is author-produced Mode B.
- The recomputation is written from the text of draft-li-rttp-iqa-addressing-02 (sections 6.1, 6.2, 6.3, 7.2, and 2, 6.4, 8.1, 9.2 where those refer to them) and from the blind copy of the cases (`basis`, `input`, `outcome`, and the representation rules).
- The checker verifies 27 citations of the draft at start-up.
- Judgements made in phase 2: the attribution of the LB-D05 divergence to the text (F01); the comparison of LB-D04's parts with `expect_parts` (F02, ambiguity log A15); the drafting of findings F01 to F05; the classification in the run report of suspected defective vectors. No verdict was changed.
