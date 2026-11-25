# Candidate: tactiq-tpm-bound-key

Vectors for presentation checks that compare identities alone cannot make: that the key a grant
is bound to is vouched for by a registered hardware attestation key, that the measured state in the
supplied quote equals the state the grant was issued against, and, in the second family, that the
bound key is a non-exportable key in that TPM, certified over a verifier's challenge, and that the
presenter proves possession of it over a second challenge. The evidence is real TPM 2.0 output from
one reference board (Infineon SLB9670). This is a candidate under
`docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's schema, failure
classes or verifier behavior.

## Submitter

Andrey Lazarev, TactiQ AI.

## Normative target

The L4 and L5 presentation tests of section 5.1 of the OWASP AIMM Pillar 2 working draft, in
particular the proof binding and presenting agent checks at L5 and the L4 sender-constraint
evidence: hardware key attestation of a non-exportable binding key, and a negative test that a
copy of the runtime, or any key material it can read, cannot produce a valid proof elsewhere.
Read on 2026-10-27 (first family) and 2026-11-25 (second family, by then in the draft's text).
The working draft is a shared document with no published revision.

This candidate narrows one line of `docs/mappings/owasp-aimm-pillar-2.md`, Remaining gaps:
"Proof that the presenter holds the bound key (L5). ASE-12 and the token exchange actor check
compare identities only." The first family binds a quote to a key and compares the quoted state
with a reference, with no proof of possession and no freshness. The second family asks the
presenter to sign a DPoP proof over the verifier's challenge with a key the registered AK
certified as non-exportable over another challenge of the verifier. It still checks records, not
a running authorization boundary, so it narrows the gap and does not close it.

The vectors build on ASE-12 in `fixtures/lifecycle-agent-side-events/`, which refuses a presenter
whose identity differs from the grant subject. That comparison is declared: a copy presenting
under the original's name passes it. TQB-03 and TQB-06 add the hardware evidence that turns it
into a check on the registered key and on the quoted state.

Record formats are not APS. They are TPM 2.0 structures (TCG TPM 2.0 Library, Part 2:
`TPMS_ATTEST`, `TPMT_SIGNATURE`, `TPM2B_PUBLIC`) as written by tpm2-tools, and the binding to a
grant is the RFC 7638 thumbprint that RFC 9449 (DPoP) carries as `cnf.jkt`.

## Source

- Repository: https://github.com/revenue7-eng/tactiq-os
- First family, commit `ce65daec5d5352c2d8bd65bd6a3a25b4a65d4bec`.
- Second family, commit `b033444fa8f4da41b9d08d0d5e43251cfc4fde99`.
- `source/` holds byte copies, listed in `CHECKSUMS.sha256`:

| here | source path |
|---|---|
| `source/ak.pub` | `measurements/tpm-quotes-dev-20261015/ak.pub` |
| `source/q15.msg`, `.sig`, `.pcr` | `measurements/tpm-quotes-dev-20261015/quote.msg`, `.sig`, `.pcr` |
| `source/q02.msg`, `.sig`, `.pcr` | `measurements/tpm-quotes-dev-20261002/cold.msg`, `.sig`, `.pcr` |

| `source/bk.pub` | `measurements/tpm-bound-key-dev-20261125/bind.pub` |
| `source/bk.certify.msg`, `.sig` | `measurements/tpm-bound-key-dev-20261125/certify.att`, `certify.sig` |
| `source/bk.pop.jwt` | `measurements/tpm-bound-key-dev-20261125/pop.jwt` |
| `source/xk.pub` | `measurements/tpm-bound-key-dev-20261125/exp.pub` |
| `source/xk.certify.msg`, `.sig` | `measurements/tpm-bound-key-dev-20261125/exp.att`, `exp.sig` |
| `source/n1.hex`, `n2.hex`, `n3.hex` | `measurements/tpm-bound-key-dev-20261125/n1.hex`, `n2.hex`, `n3.hex` |

  `ak.pub` is byte for byte the same in all three source directories.
- Written for this candidate: `CANDIDATE.md`, `CHECKSUMS.sha256`, `tpmq.py`, `boundkey.py`,
  `gen.py`, `run.py`. `derived/` and `vectors.json` are produced by `gen.py`.

The full evidence behind the second family, including the board console output, the negative
test on a software TPM with its raw output, and its own `check.py`, is in
`measurements/tpm-bound-key-dev-20261125/` at its pin.

The full evidence behind each quote, including the boot event log and IMA log that replay to
the quoted PCRs and their own `check.py`, is in the source directories at the pin. The AK
registration record and the EK certificate chain it was checked against are in
`l3-evidence-rc14.tar.gz` of the source repository's `v2.1.0-rc14` release.

## License

MIT, the license of the source repository. `LICENSE` is a copy of it. The files written for this
candidate are under the same license.

## What the vectors test

The evidence is two quotes from one Infineon SLB9670 TPM 2.0, signed by one restricted ECDSA
P-256 attestation key (AK) whose name is recorded in the signed AK registration record:

- `q15`: 2026-10-15, v2.1.0-rc14 development image, U-Boot 2026.10 loader. Its
  qualifying data is the RFC 7638 thumbprint of an Ed25519 workload key.
- `q02`: 2026-10-02, cold start, v2.1.0-rc13 development image, an earlier development loader.
  Its qualifying data is a run label. It is used only as a reference state.

PCR 0, 1, 4, 6 and 8 differ between the two. The reference in every vector is PCR 0 to 9.

The verifier in `run.py` applies five checks in order and reports the first that fails:

1. `ak_not_registered`: the presented AK's name differs from the registered name, or its
   attributes lack fixedTPM, fixedParent, restricted or sign.
2. `signature_invalid`: the quote does not verify under the presented AK, or is not a
   TPM-generated quote.
3. `pcr_digest_mismatch`: the PCR values do not reproduce the signed `pcrDigest`.
4. `key_not_bound`: the qualifying data is not the grant's `cnf.jkt`.
5. `state_mismatch`: a quoted PCR differs from the reference.

| vector | presentation | expected |
|---|---|---|
| TQB-01 | control: grant bound to the key the registered device quoted, state equal to the reference | accept |
| TQB-02 | grant bound to a key the device evidence does not name | `key_not_bound` |
| TQB-03 | simulated second device: the same quote bytes signed by a software AK derived from a published label, claiming the same attributes, not registered | `ak_not_registered` |
| TQB-04 | qualifying data rewritten to another key's thumbprint, original signature kept | `signature_invalid` |
| TQB-05 | PCR values edited to the older state to match an older reference, quote and signature kept | `pcr_digest_mismatch` |
| TQB-06 | same device and AK, measured boot state differs from the reference the grant was issued against | `state_mismatch` |

TQB-03 simulates the different-device case. Its AK is not from a second TPM: `gen.py` creates
it in software from a published label and gives its public area the same attributes as the
registered AK. The copy holds the grant, the key and a byte-identical quote, and fails only
because its AK is not the registered one. TQB-06 is the changed-state case on real data from
the same TPM.

Each check carries exactly one vector. Removing check 1, 2, 3, 4 or 5 from the verifier makes
TQB-03, TQB-04, TQB-05, TQB-02 or TQB-06 respectively give the wrong result, and no other vector
changes.

### Second family: TPM-certified bound key and proof of possession

The evidence was taken on 2026-11-25 on the same board and TPM, development image, slot B:

- `bk.pub`: a P-256 signing key created in the TPM under an owner-hierarchy primary, with
  fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth and sign, scheme ECDSA SHA-256 (ES256).
- `bk.certify.msg`, `.sig`: TPM2_Certify of that key by the registered AK, qualifying data the
  verifier's challenge `n1`.
- `bk.pop.jwt`: a DPoP proof (`typ dpop+jwt`, `alg ES256`, the key's JWK in the header, `nonce` the
  verifier's challenge `n2`). The signing input was built off the board; the TPM signed its SHA-256
  with the key.
- `xk.pub`, `xk.certify.*`: a second key on the same TPM created without fixedTPM and fixedParent,
  certified by the same AK over `n3`. Real data for the exportable-key refusal.

`run.py` applies nine checks in order and reports the first that fails:

1. `ak_not_registered`: as in the first family.
2. `certify_signature_invalid`: the certify does not verify under the presented AK, or is not a
   TPM-generated TPM2_Certify.
3. `certify_challenge_mismatch`: its qualifying data is not the verifier's certify challenge.
4. `key_not_certified`: the presented key's name is not the certified name.
5. `key_exportable`: the key lacks fixedTPM, fixedParent, sensitiveDataOrigin or sign, or is
   restricted.
6. `proof_signature_invalid`: the DPoP proof does not verify under the JWK in its header, or is not
   `typ dpop+jwt` with `alg ES256`.
7. `proof_key_not_certified_key`: that JWK is not the certified key.
8. `proof_challenge_mismatch`: the proof's `nonce` is not the verifier's proof challenge.
9. `key_not_bound`: the grant's `cnf.jkt` is not the RFC 7638 thumbprint of the certified key.

| vector | presentation | expected |
|---|---|---|
| TQB-07 | control: key certified by the registered AK over the certify challenge, DPoP proof by it over the proof challenge, grant bound to its thumbprint | accept |
| TQB-08 | real key without fixedTPM and fixedParent, honestly certified by the same AK over its own challenge | `key_exportable` |
| TQB-09 | the same certify bytes signed by the software AK of TQB-03 | `ak_not_registered` |
| TQB-10 | one byte of the certified name changed, AK signature kept | `certify_signature_invalid` |
| TQB-11 | the certify of TQB-07 presented to a verifier whose certify challenge was another value | `certify_challenge_mismatch` |
| TQB-12 | the certify of the board key presented with the public area of the other key from the same TPM | `key_not_certified` |
| TQB-13 | one claim of the DPoP payload changed, signature kept | `proof_signature_invalid` |
| TQB-14 | a valid DPoP proof over the right challenge from a software key derived from a published label, carrying its own JWK | `proof_key_not_certified_key` |
| TQB-15 | the DPoP proof of TQB-07 presented to a verifier whose proof challenge was another value | `proof_challenge_mismatch` |
| TQB-16 | evidence and proof valid, grant bound to the thumbprint of another key | `key_not_bound` |

Each check carries exactly one vector: removing check 1 to 9 from `evaluate_bound_key` makes
TQB-09, 10, 11, 12, 08, 13, 14, 15 or 16 respectively give the wrong result, and no other vector
changes. `tpm2_checkquote` does not apply to this family; `--tpm2-tools` cross-checks the first
family only.

The negative test the L4 text asks for, that a copy of the runtime or any key material it can
read cannot produce a valid proof elsewhere, is not a vector here: it needs a second TPM. It is in
the source record: every key file root on the board can read (`bind.pub`, the wrapped
`bind.priv`, the saved contexts), given to a software TPM, gives no signature; loading the wrapped
key under that TPM's primary is refused with `TPM_RC_INTEGRITY`. TQB-14 is the record-level
counterpart: a proof from any other key is refused.

## How to run

```
python3 run.py
python3 run.py --tpm2-tools
```

Needs Python 3 and `cryptography` (`gen.py` needs 43 or later for RFC 6979 signing). No network
access and no TPM. Expected last line of the first form:

```
PASSED: 16 vectors matched their expected results
```

The second form also runs `tpm2_checkquote` from tpm2-tools on every quote, as a second
implementation of the signature and PCR digest checks, and scores it: each vector states
`expected.tpm2_checkquote` (`verifies` for TQB-01, 02, 03 and 06, `fails` for TQB-04 and 05), and
a different result fails the run. `tpm2_checkquote` does not check registration, key binding or
the reference state. If it cannot run, the result is `NOT ESTABLISHED` with exit status 2.
Expected last line:

```
PASSED: 16 vectors matched their expected results (including tpm2_checkquote)
```

`python3 gen.py` regenerates `derived/` and `vectors.json` from `source/`. Derived keys come from
published labels under `seed_prefix` in `vectors.json`, and signatures use RFC 6979, so a second
run gives the same bytes. The private keys derived from those labels are test keys for these
vectors and nothing else.

## Evidence

- 2026-10-28, Andrey Lazarev, first revision, the six vectors of the first family, Mode A with
  `run.py` (`cryptography` 50.0.1) and Mode B with `tpm2_checkquote` (tpm2-tools 5.6), scored, for
  the signature and PCR digest claims: TQB-01, 02, 03 and 06 verify, TQB-04 and 05 fail, as
  expected. Author-produced: the submitter produced the source evidence, wrote the vectors and
  wrote the verifier.
- 2026-11-25, Andrey Lazarev, this revision, all sixteen vectors, Mode A with `run.py`
  (`cryptography` 41.0.7) and Mode B (tpm2-tools 5.6) for the first family. The removal of each
  check of the second family was run one at a time and changed exactly the vector named above.
  Author-produced, as above.

## Known limitations

First family (TQB-01 to TQB-06):

- The Ed25519 key in `cnf.jkt` was generated off the board, so nothing in this family shows that
  key cannot be copied. A quote over a thumbprint shows that the device vouched for the key at
  quote time, not that the key lives in the device. The second family closes this for its key.
- No proof of possession and no freshness: the thumbprint was fixed before the quote and was not a
  verifier's challenge, so a replayed old quote over the same key and state passes. The second
  family closes both for its key, and does not cover the measured state.

Second family (TQB-07 to TQB-16):

- No measured state: the certify binds the key to the TPM, not to a boot state. The key is not
  sealed to a PCR policy and signs in any state; a state check needs a quote as in the first
  family, and the two families are not joined in one presentation.
- The negative test against a copy uses a software TPM (swtpm) as the other TPM, not a second
  hardware TPM, and it is in the source record, not in these vectors.
- On the board itself, any process that can reach the TPM and the key files can use the key.
  Non-exportable here means it cannot be used on another TPM.
- The owner authorization of the board's TPM is empty, so root on the board can create keys under
  the owner hierarchy and can evict the AK.
- `iat` in the DPoP proof is the verifier's clock; the board has no trusted time. The verifier's
  challenges, not `iat`, carry freshness in these vectors.
- The key was created for this run in a temporary directory and is gone after the next boot.

Both families:

- The registered AK name is given to the verifier as trusted input. The registration record and
  its EK chain are in the source repository's rc14 release and are not re-verified here.
- One device, one registration made by the submitter on its own bench, development images only.
  Nothing here covers a release image or another board.
- The first measuring stage (SPL) is not itself authenticated, so the boot measurements start
  from an unverified root. A substituted first stage is not detected by these vectors.
- These vectors check records. They do not test a running authorization boundary.
