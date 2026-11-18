# Results — replay of sparysh-reading-aicent-grant-ref-20186f3

The replay executed the record's own checker (`reader/check_reader.py`) over the frozen blind copy and compared every produced output against the record's recorded bytes; the per-case rows below are transcribed from the record's own comparison output (`recorded/final.json`, sha256 `e61ca93a1f01447a7234475e939b5cf5fd9edf0cab2f85f6b75b6e29b1149cc3`). Every row matches the candidate's expected verdict: 25 of 25 verdicts and all four named parts of the two ambiguous cases.

Tally (reader): 11 conformant, 12 nonconformant, 2 ambiguous. Verdict agreement: 25/25. Named-part divergences: 0. Note kept from the record itself: for GR-A02 the parts are equal, but the alternative reading behind `boundary_call` differs from the candidate's note (ambiguity-log A17, finding F02).

| original | blind | rule | reader verdict | expected | result |
|---|---|---|---|---|---|
| GR-A01 | B13 | R-NOTDET | ambiguous | ambiguous | match |
| GR-A02 | B19 | R-ORDER | ambiguous | ambiguous | match |
| GR-C01 | B20 | R-CLOSED | nonconformant | nonconformant | match |
| GR-C02 | B16 | R-CLOSED | nonconformant | nonconformant | match |
| GR-C03 | B25 | R-CLOSED | nonconformant | nonconformant | match |
| GR-C04 | B17 | R-CLOSED | conformant | conformant | match |
| GR-G01 | B23 | R-GRANTREF | conformant | conformant | match |
| GR-G02 | B24 | R-GRANTREF | nonconformant | nonconformant | match |
| GR-G03 | B14 | R-GRANTREF | nonconformant | nonconformant | match |
| GR-G04 | B12 | R-GRANTREF | nonconformant | nonconformant | match |
| GR-N01 | B22 | R-NULLOBS | conformant | conformant | match |
| GR-N02 | B21 | R-NULLOBS | conformant | conformant | match |
| GR-N03 | B09 | R-NULLOBS | nonconformant | nonconformant | match |
| GR-N04 | B18 | R-NOTDET | nonconformant | nonconformant | match |
| GR-N05 | B11 | R-NULLOBS | conformant | conformant | match |
| GR-N06 | B08 | R-NULLOBS | nonconformant | nonconformant | match |
| GR-P01 | B15 | R-ORDER | conformant | conformant | match |
| GR-P02 | B01 | R-ORDER | nonconformant | nonconformant | match |
| GR-P03 | B05 | R-ORDER | conformant | conformant | match |
| GR-P04 | B03 | R-ORDER | nonconformant | nonconformant | match |
| GR-P05 | B10 | R-ORDER | conformant | conformant | match |
| GR-P06 | B02 | R-ORDER | conformant | conformant | match |
| GR-P07 | B04 | R-NOTDET | conformant | conformant | match |
| GR-P08 | B07 | R-ORDER | conformant | conformant | match |
| GR-P09 | B06 | R-ORDER | nonconformant | nonconformant | match |

## Named parts of the two ambiguous cases

| case | part | expected | reader | result | rules |
|---|---|---|---|---|---|
| GR-A01 | computation_source | ambiguous | ambiguous | match | R7-computed-over-facts |
| GR-A01 | value_and_assent | conformant | conformant | match | R1-reason-present, R2-closed-set, R3-no-granted, R4-priority |
| GR-A02 | boundary_call | ambiguous | ambiguous | match | R12-race-observation-vs-revocation |
| GR-A02 | value | conformant | conformant | match | R1-reason-present, R2-closed-set, R3-no-granted, R4-priority |

