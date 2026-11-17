# Results

Run of the outside reading of `aeoess-presenter-key-possession`, revision 1, at lab commit `6ad8468acfff6600356efb05e2a530366b1d9d96`.

## Tallies

| | conformant | nonconformant | ambiguous | matches with `expect` |
|---|---|---|---|---|
| Phase 1 (blind, `out/phase1.json`) | 5 | 19 | 4 | 25 of 28 |
| Final (`out/final.json`) | 5 | 21 | 2 | 27 of 28 |

Phase 1 `ambiguous`: B17 (PK-17), B26 (PK-26), B27 (PK-18), B28 (PK-28). Final `ambiguous`: B17 (PK-17), B27 (PK-18). The change between them is listed in `out/changes.md`. The one final divergence is PK-18: this run gives `ambiguous`, the candidate expects `nonconformant` (`findings/F01-pk18-jti-replay-requirement.md`).

### Per-case table

| Original | Blind | Phase 1 | Final | Expected | Final vs expected |
|---|---|---|---|---|---|
| PK-01 | B16 | conformant | conformant | conformant | match |
| PK-02 | B15 | nonconformant | nonconformant | nonconformant | match |
| PK-03 | B21 | conformant | conformant | conformant | match |
| PK-04 | B24 | nonconformant | nonconformant | nonconformant | match |
| PK-05 | B01 | nonconformant | nonconformant | nonconformant | match |
| PK-06 | B23 | conformant | conformant | conformant | match |
| PK-07 | B11 | nonconformant | nonconformant | nonconformant | match |
| PK-08 | B14 | nonconformant | nonconformant | nonconformant | match |
| PK-09 | B25 | nonconformant | nonconformant | nonconformant | match |
| PK-10 | B07 | nonconformant | nonconformant | nonconformant | match |
| PK-11 | B08 | nonconformant | nonconformant | nonconformant | match |
| PK-12 | B02 | nonconformant | nonconformant | nonconformant | match |
| PK-13 | B09 | conformant | conformant | conformant | match |
| PK-14 | B22 | nonconformant | nonconformant | nonconformant | match |
| PK-15 | B18 | nonconformant | nonconformant | nonconformant | match |
| PK-16 | B20 | nonconformant | nonconformant | nonconformant | match |
| PK-17 | B17 | ambiguous | ambiguous | ambiguous | match |
| PK-18 | B27 | ambiguous | ambiguous | nonconformant | diverge |
| PK-19 | B05 | nonconformant | nonconformant | nonconformant | match |
| PK-20 | B04 | conformant | conformant | conformant | match |
| PK-21 | B10 | nonconformant | nonconformant | nonconformant | match |
| PK-22 | B12 | nonconformant | nonconformant | nonconformant | match |
| PK-23 | B03 | nonconformant | nonconformant | nonconformant | match |
| PK-24 | B13 | nonconformant | nonconformant | nonconformant | match |
| PK-25 | B06 | nonconformant | nonconformant | nonconformant | match |
| PK-26 | B26 | ambiguous | nonconformant | nonconformant | match |
| PK-27 | B19 | nonconformant | nonconformant | nonconformant | match |
| PK-28 | B28 | ambiguous | nonconformant | nonconformant | match |

### Facts table

Recomputed from the bytes of each case. `sig`: Ed25519 verification with the proof's own `jwk` (4.3 item 6). `jkt`: thumbprint computed from the proof `jwk` (RFC 7638, RFC 8037), shown as its first 8 characters, and whether it equals the token's `cnf.jkt` (`cOcBgQLw...` in every case that has one). `ath`: computed `ath` equals the proof's (4.3 item 12); the computed value is `B5iTFvaDdm6GxikTB18xe4mvPqiDaY16c_oX4m6kAH0` in every case. `now-iat`: seconds (4.3 item 11). `failing`: every condition of the checker that does not hold.

| Original | Blind | typ | alg | sig | private member | htm / method | htu (normalised) | nonce (server / proof) | now-iat | ath | jkt (computed / match) | scope ok | replay | failing |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PK-01 | B16 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | none |
| PK-02 | B15 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | kApwaulV... / no | yes | no | R12b |
| PK-03 | B21 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | kApwaulV... / no | yes | no | R12b |
| PK-04 | B24 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | kApwaulV... / no | yes | no | R12b |
| PK-05 | B01 | dpop+jwt | EdDSA | fails (Ed25519 verification failed) | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R06 |
| PK-06 | B23 | dpop+jwt | EdDSA | fails (Ed25519 verification failed) | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R06 |
| PK-07 | B11 | dpop+jwt | EdDSA | verifies | d | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R07 |
| PK-08 | B14 | dpop+jwt | none | fails (alg 'none': no EdDSA verification applies) | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R05, R06 |
| PK-09 | B25 | JWT | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R04 |
| PK-10 | B07 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | differs: AZxmuuke... | cOcBgQLw... / yes | yes | no | R12a |
| PK-11 | B08 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / no cnf | yes | no | R12b |
| PK-12 | B02 | dpop+jwt | EdDSA | verifies | none | GET / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R08 |
| PK-13 | B09 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | none |
| PK-14 | B22 | dpop+jwt | EdDSA | verifies | none | POST / POST | https://api.example.test/refunds vs https://api.example.test/orders | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R09 |
| PK-15 | B18 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | n-2026-11-03 / n-old | 5 | equal | cOcBgQLw... / yes | yes | no | R10 |
| PK-16 | B20 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 600 | equal | cOcBgQLw... / yes | yes | no | R11 |
| PK-17 | B17 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | -20 | equal | cOcBgQLw... / yes | yes | no | R11f |
| PK-18 | B27 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | yes | R13 |
| PK-19 | B05 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | no (refunds:write) | no | RS |
| PK-20 | B04 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | no (refunds:write) | no | RS |
| PK-21 | B10 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | no (refunds:write) | no | RS |
| PK-22 | B12 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | equal | kApwaulV... / no | yes | no | R12b |
| PK-23 | B03 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | absent | cOcBgQLw... / yes | yes | no | R03b, R12a |
| PK-24 | B13 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | n-2026-11-03 / null | 5 | equal | cOcBgQLw... / yes | yes | no | R03c, R10 |
| PK-25 | B06 | dpop+jwt | EdDSA | fails (no signature to verify) | none | POST / POST | equal | null / null | 5 | equal | cOcBgQLw... / yes | yes | no | R02, R06 |
| PK-26 | B26 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | absent | cOcBgQLw... / yes | yes | no | R03b, R12a |
| PK-27 | B19 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | null / null | 5 | absent | cOcBgQLw... / yes | yes | no | R03b, R12a |
| PK-28 | B28 | dpop+jwt | EdDSA | verifies | none | POST / POST | equal | n-2026-11-03 / null | 5 | equal | cOcBgQLw... / yes | yes | no | R03c, R10 |

### Sensitivity table (phase 1, all four choice points evaluated both ways)

| Rule | Cases whose verdict changes when the rule is removed | Cases whose verdict changes when the rule is inverted | Removal under final readings |
|---|---|---|---|
| R01_single_header | none | PK-20, PK-13, PK-01, PK-17, PK-03, PK-04, PK-26, PK-18 | none |
| R02_well_formed_jwt | none | PK-20, PK-13, PK-01, PK-17, PK-03, PK-04, PK-26, PK-18 | none |
| R03a_claims_jti_htm_htu_iat | none | PK-20, PK-13, PK-01, PK-17, PK-03, PK-06, PK-26, PK-18, PK-28 | none |
| R03b_claim_ath | PK-26 (B26, ambiguous->conformant) | PK-20, PK-13, PK-21, PK-01, PK-17, PK-03, PK-06, PK-04, PK-26, PK-18, PK-28 | PK-26 |
| R03c_claim_nonce | none | PK-20, PK-13, PK-01, PK-17, PK-03, PK-06, PK-04, PK-26, PK-18 | none |
| R04_typ | PK-09 (B25, nonconformant->conformant) | PK-20, PK-13, PK-01, PK-17, PK-03, PK-04, PK-09, PK-26, PK-18 | PK-09 |
| R05_alg | none | PK-20, PK-13, PK-01, PK-17, PK-03, PK-04, PK-26, PK-18 | none |
| R06_signature | PK-05 (B01, nonconformant->conformant), PK-06 (B23, conformant->nonconformant) | PK-05, PK-20, PK-13, PK-01, PK-17, PK-03, PK-06, PK-04, PK-26, PK-18 | PK-05, PK-06 |
| R07_no_private_key | PK-07 (B11, nonconformant->conformant) | PK-20, PK-13, PK-07, PK-01, PK-17, PK-03, PK-04, PK-26, PK-18 | PK-07 |
| R08_htm | PK-12 (B02, nonconformant->conformant) | PK-12, PK-20, PK-13, PK-01, PK-17, PK-03, PK-06, PK-26, PK-18, PK-28 | PK-12 |
| R09_htu | PK-14 (B22, nonconformant->conformant) | PK-20, PK-13, PK-01, PK-17, PK-03, PK-14, PK-06, PK-26, PK-18, PK-28 | PK-14 |
| R10_nonce | PK-15 (B18, nonconformant->conformant) | PK-20, PK-13, PK-01, PK-17, PK-15, PK-03, PK-06, PK-04, PK-26, PK-18 | PK-15 |
| R11_iat_not_too_old | PK-16 (B20, nonconformant->conformant) | PK-20, PK-13, PK-01, PK-17, PK-16, PK-03, PK-06, PK-04, PK-26, PK-18 | PK-16 |
| R11f_iat_future | PK-17 (B17, ambiguous->conformant) | PK-20, PK-13, PK-01, PK-17, PK-03, PK-06, PK-04, PK-26, PK-18 | PK-17 |
| R12a_ath_matches | PK-10 (B07, nonconformant->conformant) | PK-20, PK-10, PK-13, PK-21, PK-01, PK-17, PK-06, PK-18, PK-28 | PK-10 |
| R12b_key_bound_matches | PK-11 (B08, nonconformant->conformant), PK-02 (B15, nonconformant->conformant), PK-03 (B21, conformant->nonconformant) | PK-20, PK-11, PK-13, PK-21, PK-02, PK-01, PK-17, PK-03, PK-06, PK-18, PK-28 | PK-11, PK-02, PK-03 |
| R13_jti_not_replayed | PK-18 (B27, ambiguous->conformant) | PK-20, PK-13, PK-01, PK-17, PK-03, PK-06, PK-04, PK-26, PK-18 | PK-18 |
| RS_scope_contains_required | PK-20 (B04, conformant->nonconformant), PK-19 (B05, nonconformant->conformant) | PK-20, PK-19, PK-13, PK-01, PK-17, PK-03, PK-06, PK-26, PK-18, PK-28 | PK-20, PK-19 |

Choice points fixed one way for every case (phase 1):

| Choice fixed | Cases whose verdict differs from the phase-1 verdict |
|---|---|
| C1_item3_axis fixed to A | PK-17 (B17) -> nonconformant, PK-26 (B26) -> conformant, PK-18 (B27) -> nonconformant, PK-28 (B28) -> nonconformant |
| C1_item3_axis fixed to B | PK-17 (B17) -> nonconformant, PK-26 (B26) -> nonconformant, PK-18 (B27) -> nonconformant, PK-28 (B28) -> nonconformant |
| C2_future_iat_null_skew fixed to A | PK-17 (B17) -> nonconformant, PK-26 (B26) -> conformant, PK-18 (B27) -> nonconformant, PK-28 (B28) -> nonconformant |
| C2_future_iat_null_skew fixed to B | PK-17 (B17) -> conformant, PK-26 (B26) -> conformant, PK-18 (B27) -> nonconformant, PK-28 (B28) -> nonconformant |
| C3_jti_replay fixed to A | PK-17 (B17) -> nonconformant, PK-26 (B26) -> conformant, PK-18 (B27) -> nonconformant, PK-28 (B28) -> nonconformant |
| C3_jti_replay fixed to B | PK-17 (B17) -> nonconformant, PK-26 (B26) -> conformant, PK-18 (B27) -> conformant, PK-28 (B28) -> nonconformant |
| C5_freshness_axis fixed to A | PK-17 (B17) -> nonconformant, PK-26 (B26) -> conformant, PK-18 (B27) -> nonconformant, PK-28 (B28) -> nonconformant |
| C5_freshness_axis fixed to B | PK-17 (B17) -> nonconformant, PK-26 (B26) -> conformant, PK-18 (B27) -> nonconformant, PK-28 (B28) -> conformant |

The "choice fixed" rows fix the named choice point for every case, leave the other choice points at reading A, and compare with the phase-1 verdict.

## Two-run byte-identity check

`reader/checker.py` was run twice on the same inputs, writing to `out/` and `logs/run2/`. `cmp` found both output files identical:

- `out/phase1.json` SHA-256 `2b0fe980cc2909e7fe21ae68644ac1ed4e3917796d561ec79543623cbc9b06ce` (both runs)
- `out/phase1-sensitivity.json` SHA-256 `0b724bd5d90938a578ef3dd7b13eb4bc91b2841af5a487e51860dc2b9b7d412a` (both runs)

`logs/run2/` was deleted after the comparison. The commands and their output are in `logs/transcript.log`.

## Start-up checks

- Citations: 54 RFC sentences, each found verbatim in the supplied text after whitespace normalisation (page header and footer lines of the older RFCs removed first).
- Self-tests from RFC examples: RFC 8037 A.3 thumbprint `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` recomputed: true. RFC 8037 A.4/A.5 Ed25519 JWS verifies: true. RFC 3986 6.2.3 example (`http://example.com:80` normalises to `http://example.com/`): true. RFC 3986 6.2.2 example pair compares equal: true.

## Phase-2 key and claim checks

Each is a separate result. Computed by `reader/phase2.py`; full values are in `out/final.json`, `key_and_claim_checks`.

| Check | Result | Detail |
|---|---|---|
| K0. The blind copy carries the sealed `input` and `outcome` of every case | holds | 28 cases, 0 mismatches |
| K1. Each key in `keys` derives from `keys.seed_rule` | holds | private key = SHA-256(UTF-8(`aeoess-presenter-key-possession/` + label)) used as the Ed25519 seed. `agent` gives `x` `s08tgBeilGl3TAZ94T3RwNKsACFVkcFMgJtjIJvDeaQ`, `attacker` gives `nSTCN36lL9LqVqNs0oheqNt0Z0WYUdarPXth1m5nwvg`. Both equal the block |
| K2. Token `cnf.jkt` against the thumbprint of each derived key | holds | thumbprint of `agent` `cOcBgQLwawngecIAW38DspRnV75EbcX0JwpOppcXZ6Q`, of `attacker` `kApwaulV5e2dstZEUjq7IumwhCwUtq9f6OguDXDfRCI`. The one `cnf.jkt` value in the cases equals the `agent` thumbprint. PK-11 has no `cnf` |
| K3. Every proof's `jwk` is one of the derived keys | holds | `attacker` key in PK-02, PK-03, PK-04 and PK-22. `agent` key in the other 24 cases |
| K4. A private `d` in a proof header derives from a stated seed | holds | one case, PK-07. Its `d` is the `agent` seed, and the public key derived from it equals that header's `x` |
| K5. PK-05/PK-06, "payload changed after signing" | holds | header and signature segment equal PK-01's. PK-01's signature verifies over PK-01's signing input and not over PK-05's |
| K6. PK-08, "`alg` none, empty signature" | holds | three segments, the third of length 0 |
| K7. PK-25, "DPoP value with two segments" | holds | two segments |
| K8. The "What the cases test" table in `CANDIDATE.md` against the recomputed facts | holds | the input column of every row matches the facts table above |

## Candidate claims not checked

- That `generate.py` reproduces `vectors.json` byte for byte: not attempted. `generate.py` was not downloaded, which the boundary of this run requires.
- That `check.py` prints `28/28 agree`: not attempted, because `check.py` was not obtained.
- That `mutate.py` prints `19/19 mutants killed`, that each mutant weakens one check, and which cases kill which mutants: not attempted, because `mutate.py` was not obtained. F03 compares the claim about PK-26 to PK-28 with this run's own sensitivity results only.
- That no implementation has been run against these cases: not checkable from the inputs.
- The digest pinned for RFC 9449 holds for the supplied copy. That copy is the one the candidate retrieved: not checkable beyond the digest.

## Limits of the checker

The places where a decision rests on something other than a derivation from the text:

- **Fixed values.**
  - The set of registered asymmetric JWS algorithms (`REGISTERED_ASYMMETRIC`). The IANA JOSE registry was not supplied.
  - "Supported by the application" is fixed to EdDSA over Ed25519. Any other `alg` also makes item 6 fail, which couples items 5 and 6 (A15).
  - The list of private JWK members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`).
  - The default ports, for `http` and `https` only.
- **String tests.**
  - `typ` == `dpop+jwt`.
  - `htm` == method, case-sensitive.
  - `nonce`, `ath` and `jkt` by string equality.
  - The scope check splits on single spaces and requires an exact element.
  - `seen_jti` matches on (normalised URI, `jti`).
- **Policy parameters taken from the input.** `accepted_algs`, `iat_window_s`, `future_skew_s`, `tracks_jti`, `seen_jti`, `server_nonce`, `now` and `required_scope`. The checker does not judge whether a 300 s window is "relatively brief" (11.1).
- **Mappings chosen in this run.**
  - The axis map: A1, A2, A6, A7.
  - What makes an accept or a rejection conformant: A8, A9.
  - Each axis judged on its own: A10.
  - The facts of a non-well-formed proof: A11.
  - A null `future_skew_s`: A3.
  - jti replay as a failed check: A4.
  - An unbound token failing item 12: A5. This one is not evaluated both ways.
  - The window bound is inclusive: A12.
  - A string stands for one DPoP header field: A19.
- **Parsing.**
  - The JSON of the segments is parsed with Python's `json`, with duplicate member names rejected. That parser also accepts `NaN` and `Infinity`, which RFC 7159 does not. No case uses them.
  - base64url decoding checks the alphabet and the absence of padding. It does not check canonical trailing bits.
- **URI normalisation.**
  - Only the parts of RFC 3986 6.2.2 and 6.2.3 that are implemented: case, percent-encoding, dot segments, empty path, and default port.
  - The cases exercise only query removal and a different path.
- **Not exercised by any case.** Item 1 (several header fields), Ed448, and algorithms other than EdDSA.

## Environment and time

- Python 3.13.18 (`python3 -I`). `cryptography` 50.0.1. Ubuntu 24.04.5 LTS, Linux 6.18.44 x86_64 (`Linux-6.18.44-fc-v553-x86_64-with-glibc2.39`).
- Wall-clock: setup began 2026-11-17T14:12:15Z. The phase-1 zip was written by 2026-11-17T14:19:08Z. The final outputs were complete at 2026-11-17T14:35:01Z.
