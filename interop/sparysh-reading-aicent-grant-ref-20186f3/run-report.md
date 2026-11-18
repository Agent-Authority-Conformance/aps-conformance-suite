# Run report

who ran it: Andrii Sparysh (GitHub `andreysparish`), using an AI assistant
date: 2026-11-16
run mode: B, alternate recomputation
implementation name: `reader/check_reader.py` (a reader of draft-li-rttp-iqa-addressing-02 §8.1–8.2, written by the runner for this run), with `reader/compare.py` for the comparison
implementation repository and version: this directory, `reader/`; `check_reader.py` sha256 `5eeb294a5e3cd039ff40e94581afc097ac9d1f1e290795a387af7eba405a02f2`; `compare.py` sha256 `1394a8ce0240aabc092e96f427c88cf4c09ab1b2d805f249a3aa75047d97e136`
corpus reference: `aps-conformance-suite` at `20186f3ebc78de2f34e79a0b4bfe5f828599653b`, candidate `aicent-grant-ref`, revision 1
environment: Python 3.13.18 (standard library only), Linux 6.18.44-fc-v470 x86_64, Ubuntu 24.04.5 LTS
author-produced or independent: author-produced, for every claim (see "Labels per claim"). Authorship relationship: the runner wrote `reader/check_reader.py`, which supplies the recomputation, and `reader/compare.py`. The runner authored none of the candidate, its vectors, its checker or the draft. The checker was written from the draft's text and a blind copy of the cases, and its phase-1 output was frozen before the expected verdicts were opened.
suspected defective vectors: none on verdict grounds. Data observations, which change no verdict in this reading, are in `findings/F03-cases-not-isolating-rules.md` (GR-C01, GR-C03, GR-N04 do not isolate one rule each; no case tests the observation-equals-relied-on rule) and `findings/F04-grant-times.md` (nine cases carry `issued_at_ms` 1000 > `expires_at_ms` 900).

## Labels per claim

The claims are the candidate's expected verdicts, grouped by the rules its CANDIDATE.md names, and the named parts of its two `ambiguous` cases. The runner for every claim is Andrii Sparysh.

| claim (candidate rule) | cases | mode | label | implementation |
|---|---|---|---|---|
| R-ORDER: the reason is the first value whose condition applies, null when none applies | GR-P01 to GR-P06, GR-P08, GR-P09 | Mode B | author-produced | `reader/check_reader.py` |
| R-NOTDET: an unreachable source or a predating observation ends in `authority_not_determined` | GR-P07, GR-N04 | Mode B | author-produced | `reader/check_reader.py` |
| R-NULLOBS: `observation_as_of_ms` is null when the relied-on observation is absent or not fresh | GR-N01 to GR-N03, GR-N05, GR-N06 | Mode B | author-produced | `reader/check_reader.py` |
| R-CLOSED: the refusal set is closed | GR-C01 to GR-C04 | Mode B | author-produced | `reader/check_reader.py` |
| R-GRANTREF: every response carries the five grant-reference members | GR-G01 to GR-G04 | Mode B | author-produced | `reader/check_reader.py` |
| `ambiguous` verdicts and their four named parts | GR-A01, GR-A02 | Mode B | author-produced | `reader/check_reader.py`; parts grouped by `PART_MAP` in `reader/compare.py` |

For every row, the authorship relationship is that the runner wrote the checker that supplies the result. The sensitivity table, the ambiguity log and the findings are this run's own analysis, not claims of the candidate.

## Per-vector result

| original | blind | reader verdict | expected | result |
|---|---|---|---|---|
| GR-A01 | B13 | ambiguous | ambiguous | match (parts: value_and_assent conformant = conformant; computation_source ambiguous = ambiguous) |
| GR-A02 | B19 | ambiguous | ambiguous | match (parts: value conformant = conformant; boundary_call ambiguous = ambiguous) |
| GR-C01 | B20 | nonconformant | nonconformant | match |
| GR-C02 | B16 | nonconformant | nonconformant | match |
| GR-C03 | B25 | nonconformant | nonconformant | match |
| GR-C04 | B17 | conformant | conformant | match |
| GR-G01 | B23 | conformant | conformant | match |
| GR-G02 | B24 | nonconformant | nonconformant | match |
| GR-G03 | B14 | nonconformant | nonconformant | match |
| GR-G04 | B12 | nonconformant | nonconformant | match |
| GR-N01 | B22 | conformant | conformant | match |
| GR-N02 | B21 | conformant | conformant | match |
| GR-N03 | B09 | nonconformant | nonconformant | match |
| GR-N04 | B18 | nonconformant | nonconformant | match |
| GR-N05 | B11 | conformant | conformant | match |
| GR-N06 | B08 | nonconformant | nonconformant | match |
| GR-P01 | B15 | conformant | conformant | match |
| GR-P02 | B01 | nonconformant | nonconformant | match |
| GR-P03 | B05 | conformant | conformant | match |
| GR-P04 | B03 | nonconformant | nonconformant | match |
| GR-P05 | B10 | conformant | conformant | match |
| GR-P06 | B02 | conformant | conformant | match |
| GR-P07 | B04 | conformant | conformant | match |
| GR-P08 | B07 | conformant | conformant | match |
| GR-P09 | B06 | nonconformant | nonconformant | match |

Verdicts equal: 25 of 25. Named parts equal: 4 of 4. For GR-A02 the parts are equal, but the alternative reading behind `boundary_call` differs from the candidate's note (ambiguity-log A17, finding F02).

Not attempted:
- Testing any implementation (none was supplied).
- Running the candidate's `check.py` / `mutate.py`, which were not obtained, by design.
- The 6.1 lease-instant boundary convention (no case carries instants for it).
- Value formats of `grant` / `evidence_id`.
- Pairwise rule removals in the sensitivity run.
- Opening RFC 2119 / RFC 8174.

## Verbatim commands and output

### 1. Fetch (first run)

```
$ bash aicent-grant-ref-reading-1-fetch-inputs.sh
ok  inputs/sealed/vectors.json
ok  inputs/sealed/CANDIDATE.md
ok  inputs/draft/draft-li-rttp-iqa-addressing-02.txt
draft read from: draft-li-rttp-iqa-addressing-02.txt
blind copy: 25 cases
done: inputs/SHA256SUMS
EXIT=0
```

### 2. Fetch (second run, log captured as `logs/fetch.log`)

```
$ bash aicent-grant-ref-reading-1-fetch-inputs.sh
ok  inputs/sealed/vectors.json
ok  inputs/sealed/CANDIDATE.md
ok  inputs/draft/draft-li-rttp-iqa-addressing-02.txt
draft read from: draft-li-rttp-iqa-addressing-02.txt
blind copy: 25 cases
done: inputs/SHA256SUMS
exit code: 0
```

### 3. Phase-1 production run (two runs, byte comparison), before the phase-1 zip

```
$ for i in 1 2; do python3 -I reader/check_reader.py inputs/draft/draft-li-rttp-iqa-addressing-02.txt inputs/blind/cases.json out/run$i-phase1.json --sensitivity out/run$i-sens.json; done
{"ambiguous": 2, "conformant": 11, "nonconformant": 12}
{"ambiguous": 2, "conformant": 11, "nonconformant": 12}
$ cmp out/run1-phase1.json out/run2-phase1.json && cmp out/run1-sens.json out/run2-sens.json && echo BYTE-IDENTICAL
BYTE-IDENTICAL
$ mv out/run1-phase1.json out/phase1.json; mv out/run1-sens.json out/phase1-sensitivity.json; sha256sum out/* reader/check_reader.py
688a6822a609d3e9a7e1a1d3426cc97c2bfec0f170622a14dcd36a38820beb50  out/phase1-sensitivity.json
4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a  out/phase1.json
4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a  out/run2-phase1.json
688a6822a609d3e9a7e1a1d3426cc97c2bfec0f170622a14dcd36a38820beb50  out/run2-sens.json
5eeb294a5e3cd039ff40e94581afc097ac9d1f1e290795a387af7eba405a02f2  reader/check_reader.py
```

### 4. Phase-1 zip

```
$ sha256sum sparysh-reading-aicent-grant-ref-20186f3-phase1.zip
e90ed087b5ba20491c10803fdacaa81ac78f793dc0a516a3bc6fd1fea2d67a01  sparysh-reading-aicent-grant-ref-20186f3-phase1.zip
$ date -u
Mon Nov 16 15:28:49 UTC 2026
```

### 5. Re-run and comparison transcript (`logs/transcript.log`)

```
$ python3 --version
Python 3.13.18
[exit 0]
$ uname -srm
Linux 6.18.44-fc-v470 x86_64
[exit 0]
$ grep PRETTY_NAME /etc/os-release
PRETTY_NAME="Ubuntu 24.04.5 LTS"
[exit 0]
$ sha256sum reader/check_reader.py reader/compare.py
5eeb294a5e3cd039ff40e94581afc097ac9d1f1e290795a387af7eba405a02f2  reader/check_reader.py
1394a8ce0240aabc092e96f427c88cf4c09ab1b2d805f249a3aa75047d97e136  reader/compare.py
[exit 0]
$ python3 -I reader/check_reader.py inputs/draft/draft-li-rttp-iqa-addressing-02.txt inputs/blind/cases.json rerun/phase1.run1.json --sensitivity rerun/sens.run1.json
{"ambiguous": 2, "conformant": 11, "nonconformant": 12}
[exit 0]
$ python3 -I reader/check_reader.py inputs/draft/draft-li-rttp-iqa-addressing-02.txt inputs/blind/cases.json rerun/phase1.run2.json --sensitivity rerun/sens.run2.json
{"ambiguous": 2, "conformant": 11, "nonconformant": 12}
[exit 0]
$ cmp rerun/phase1.run1.json rerun/phase1.run2.json
[exit 0]
$ cmp rerun/sens.run1.json rerun/sens.run2.json
[exit 0]
$ cmp rerun/phase1.run1.json out/phase1.json
[exit 0]
$ cmp rerun/sens.run1.json out/phase1-sensitivity.json
[exit 0]
$ sha256sum out/phase1.json out/phase1-sensitivity.json rerun/phase1.run1.json rerun/phase1.run2.json
4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a  out/phase1.json
688a6822a609d3e9a7e1a1d3426cc97c2bfec0f170622a14dcd36a38820beb50  out/phase1-sensitivity.json
4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a  rerun/phase1.run1.json
4ec54b036a9be76e72944623079c30c891cbdcc67bc90e220a68428c199d1a4a  rerun/phase1.run2.json
[exit 0]
$ python3 -I reader/compare.py out/phase1.json inputs/sealed/vectors.json inputs/sealed/id-map.json rerun/final.run1.json
{"part_divergences": [], "tally": {"ambiguous": 2, "conformant": 11, "nonconformant": 12}, "verdict_agreement": "25/25"}
GR-A01 B13 ambiguous ambiguous match {"computation_source": {"expect": "ambiguous", "reader": "ambiguous", "result": "match", "rules": ["R7-computed-over-facts"]}, "value_and_assent": {"expect": "conformant", "reader": "conformant", "result": "match", "rules": ["R1-reason-present", "R2-closed-set", "R3-no-granted", "R4-priority"]}}
GR-A02 B19 ambiguous ambiguous match {"boundary_call": {"expect": "ambiguous", "reader": "ambiguous", "result": "match", "rules": ["R12-race-observation-vs-revocation"]}, "value": {"expect": "conformant", "reader": "conformant", "result": "match", "rules": ["R1-reason-present", "R2-closed-set", "R3-no-granted", "R4-priority"]}}
GR-C01 B20 nonconformant nonconformant match 
GR-C02 B16 nonconformant nonconformant match 
GR-C03 B25 nonconformant nonconformant match 
GR-C04 B17 conformant conformant match 
GR-G01 B23 conformant conformant match 
GR-G02 B24 nonconformant nonconformant match 
GR-G03 B14 nonconformant nonconformant match 
GR-G04 B12 nonconformant nonconformant match 
GR-N01 B22 conformant conformant match 
GR-N02 B21 conformant conformant match 
GR-N03 B09 nonconformant nonconformant match 
GR-N04 B18 nonconformant nonconformant match 
GR-N05 B11 conformant conformant match 
GR-N06 B08 nonconformant nonconformant match 
GR-P01 B15 conformant conformant match 
GR-P02 B01 nonconformant nonconformant match 
GR-P03 B05 conformant conformant match 
GR-P04 B03 nonconformant nonconformant match 
GR-P05 B10 conformant conformant match 
GR-P06 B02 conformant conformant match 
GR-P07 B04 conformant conformant match 
GR-P08 B07 conformant conformant match 
GR-P09 B06 nonconformant nonconformant match 
[exit 0]
$ cmp rerun/final.run1.json out/final.json
[exit 0]
$ sha256sum out/final.json
e61ca93a1f01447a7234475e939b5cf5fd9edf0cab2f85f6b75b6e29b1149cc3  out/final.json
[exit 0]
```
