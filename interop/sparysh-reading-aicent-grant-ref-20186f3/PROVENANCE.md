# Provenance

## Lab repository

- Repository: `Agent-Authority-Conformance/aps-conformance-suite`
- Commit: `20186f3ebc78de2f34e79a0b4bfe5f828599653b`
- Candidate: `candidates/aicent-grant-ref`, revision 1
- Fetched by `inputs/aicent-grant-ref-reading-1-fetch-inputs.sh` from `raw.githubusercontent.com` at that commit, on 2026-11-16, about 15:24:50 UTC. The script was run twice: once to fetch, once more to capture its log. Both runs reported `ok` for all three digests and exited 0.

## Files read, with digests

| File | SHA-256 | When read |
|---|---|---|
| `inputs/draft/draft-li-rttp-iqa-addressing-02.txt` | `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` | phase 1 (sections listed below) |
| `inputs/blind/cases.json` | `86c9aa2c2f6151cd5f8ebcf33c01e08a4a19a3cdac7bdd9936fe00ddc0309205` | phase 1, all of it |
| `inputs/sealed/vectors.json` | `f1924f07be2b7dcf93c3832938bdb288f0f2868057fe8396c9c5b4935b71a303` | phase 2 only |
| `inputs/sealed/id-map.json` | `04a7f8df180f8841ba534950deec6d06f4dd8ed5cdaa9b139a850fafc7938141` | phase 2 only |
| `inputs/sealed/CANDIDATE.md` | `089091faec6d63e7515f8279b23495866c65438929353a5e7fb8d22daddda0a3` | phase 2 only, after the verdict comparison |
| fetch script | `60f283c0aa60e492ba1a9302ea82d1f80d19edc162aa4a6514d44514873048c8` | before setup |
| task description (the boundary set out below) | not part of the lab corpus | before setup |

## The draft

- Revision: draft-li-rttp-iqa-addressing-02, header date November 2026, "Expires 5 May 2027".
- Obtained: Andrii Sparysh supplied a downloaded copy, placed beside the fetch script. The script took it from there (`draft read from: draft-li-rttp-iqa-addressing-02.txt`) and checked it against the pinned SHA-256: ok. The script did not contact the IETF archive.
- Sections read, in order:
  1. A heading list of the whole draft (a `grep` of section-number lines) to locate 8.1 and 8.2. Only headings were displayed.
  2. Section 8 (intro), 8.1, 8.2, and the heading line of 8.3.
  3. Section 2, in full: the key-word paragraph (8.1 uses MUST / MUST NOT) and the terminology list (8.1/8.2 use *standing*, *standing read*, *trust lease*, *refusal reason*, *grant reference*).
  4. Section 6 with 6.1, 6.2, 6.3 and 6.4. 8.1 says a permit is relied on "under the rules of Section 6" and cites 6.1. 8.2 cites 6.3, and "fresh" is defined by the lease of Section 6. 6.4 was displayed because it falls inside Section 6 and is cited by 6.3. Nothing from it was used.
- RFC 2119 and RFC 8174 were not opened.
- Not read: Sections 1, 3, 4, 5, 7, 8.3 (body), 8.4, 9–16.

## Boundary as kept

- `inputs/sealed/` was not opened until the phase-1 zip was saved. The zip `sparysh-reading-aicent-grant-ref-20186f3-phase1.zip` (sha256 `e90ed087b5ba20491c10803fdacaa81ac78f793dc0a516a3bc6fd1fea2d67a01`) was written at 15:28:49 UTC. `id-map.json` and `vectors.json` were opened after that, then `CANDIDATE.md`. The zip is kept in this directory as `logs/sparysh-reading-aicent-grant-ref-20186f3-phase1.zip`.
- `check.py` and `mutate.py` were not downloaded or read. No other file of the lab repository was read: no other candidate, no `fixtures/` (including `fixtures/lease-revocation-axes`), no `interop/`, no `docs/`.
- No page on iqa.org, no run record of the author, no mailing-list thread, and no other implementation, checker or reading of the draft was read. No web search was made.
- `out/phase1.json` was not edited after the zip. Its digest `4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a` is the same in the zip, in this directory, and in the re-run transcript.

## Events at the boundary

1. The draft's heading list was displayed for the whole document (item 1 above). This showed section titles outside 8.1/8.2, but no body text.
2. The whole of Section 2 and all of Section 6, including 6.2 and 6.4, were read, not only the sentences 8.1/8.2 refer to. The reason is recorded above.
3. Before the phase-1 zip, the checker was edited once. After a first run, inversion variants that are not meaningful (for example, "require a value outside the closed set") were dropped from the sensitivity run. The phase-1 verdict output was identical before and after the edit (`4ec54b03…`); only the sensitivity file changed (`3d8f7351…` → `688a6822…`). The sealed files had not been opened at that point.
4. The blind `cases.json` carries the candidate's representation rules (`readings`, `absent_fields`, `field_names`) and `sources`. These are data and representation rules that the boundary of this run permits. No file read before phase 2 contained the candidate's reading of a case, or any code. Ordering rule 3 was not triggered.
5. The fetch script's text, read before setup, names the withheld fields (`rule`, `note`, `expect`, `expect_parts`) but no values.

## Authorship

- The run was carried out and checked by Andrii Sparysh (GitHub `andreysparish`), using an AI assistant. He authored none of the candidate, its vectors, its checker, the draft, or any claim input.
- He wrote the checker that supplies the recomputation, so under `CONTRIBUTING.md` every claim in this record is author-produced Mode B (`run-report.md`, "Labels per claim").
- The recomputation is `reader/check_reader.py`, written from the text of draft sections 8.1/8.2 (and the sections listed above) and the blind cases only. Every check in it cites a sentence of the draft, and the program verifies at start-up that each cited sentence occurs in the draft (20 citations).
- The candidate's checker (`check.py`) and mutation harness (`mutate.py`) were never obtained. The rule names, rule boundaries and sensitivity design of this run are this run's own. CANDIDATE.md, read after the comparison, uses different rule names (R-ORDER, R-NOTDET, R-NULLOBS, R-CLOSED, R-GRANTREF).
- The only phase-2 judgement is `PART_MAP` in `reader/compare.py`, which groups phase-1 rules into the candidate's named parts for the two ambiguous cases. It changes no phase-1 result.

## Changes made in review, before merge (2026-11-17)

These change no command, output, log or verdict of the run. `out/` and `logs/` are unchanged.

- `SHA256SUMS.txt`: the entry for `reader/__pycache__/check_reader.cpython-313.pyc` was removed. That file is a local interpreter cache, is not part of this directory as committed, and had been listed by mistake. The digests of every changed file were recomputed.
- Classification: the record was first labelled independent. Under `CONTRIBUTING.md` it is author-produced Mode B for every claim, because the runner wrote the checker that supplies the recomputation. `run-report.md`, `README.md` (section "Verification split") and this file were corrected.
- `findings/`: "the independent reading" and "the independent checker" now read "this run's reading" and "this run's checker", so that the prose does not stand in for a label.
