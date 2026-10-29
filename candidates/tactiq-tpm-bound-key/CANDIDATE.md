# Candidate: tactiq-tpm-bound-key

Vectors for two presentation checks that compare identities alone cannot make: that the key a
grant is bound to is vouched for by a registered hardware attestation key, and that the measured
state in the supplied quote equals the state the grant was issued against. The evidence is real
TPM 2.0 output from one reference board (Infineon SLB9670). This is a candidate under
`docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the lab's schema, failure
classes or verifier behavior.

## Submitter

Andrey Lazarev, TactiQ AI.

## Normative target

The L4 and L5 presentation tests of section 5.1 of the OWASP AIMM Pillar 2 working draft, as
read on 2026-10-27, in particular the proof binding and presenting agent checks at L5 and the
proposed L4 addition on non-exportable bound keys. The working draft is a shared document with
no published revision, and the L4 addition is a reviewer proposal, not accepted text.

This candidate narrows one line of `docs/mappings/owasp-aimm-pillar-2.md`, Remaining gaps:
"Proof that the presenter holds the bound key (L5). ASE-12 and the token exchange actor check
compare identities only." It does not close it. The vectors bind a quote to a key and compare
the quoted state with a reference. They do not require the presenter to prove it holds the
workload key, and with no freshness an old quote over the same key and state passes.

The vectors build on ASE-12 in `fixtures/lifecycle-agent-side-events/`, which refuses a presenter
whose identity differs from the grant subject. That comparison is declared: a copy presenting
under the original's name passes it. TQB-03 and TQB-06 add the hardware evidence that turns it
into a check on the registered key and on the quoted state.

Record formats are not APS. They are TPM 2.0 structures (TCG TPM 2.0 Library, Part 2:
`TPMS_ATTEST`, `TPMT_SIGNATURE`, `TPM2B_PUBLIC`) as written by tpm2-tools, and the binding to a
grant is the RFC 7638 thumbprint that RFC 9449 (DPoP) carries as `cnf.jkt`.

## Source

- Repository: https://github.com/revenue7-eng/tactiq-os
- Commit: `ce65daec5d5352c2d8bd65bd6a3a25b4a65d4bec`
- `source/` holds byte copies, listed in `CHECKSUMS.sha256`:

| here | source path |
|---|---|
| `source/ak.pub` | `measurements/tpm-quotes-dev-20261015/ak.pub` |
| `source/q15.msg`, `.sig`, `.pcr` | `measurements/tpm-quotes-dev-20261015/quote.msg`, `.sig`, `.pcr` |
| `source/q02.msg`, `.sig`, `.pcr` | `measurements/tpm-quotes-dev-20261002/cold.msg`, `.sig`, `.pcr` |

  `ak.pub` is byte for byte the same in both source directories.
- Written for this candidate: `CANDIDATE.md`, `CHECKSUMS.sha256`, `tpmq.py`, `gen.py`,
  `run.py`. `derived/` and `vectors.json` are produced by `gen.py`.

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

## How to run

```
python3 run.py
python3 run.py --tpm2-tools
```

Needs Python 3 and `cryptography` (`gen.py` needs 43 or later for RFC 6979 signing). No network
access and no TPM. Expected last line of the first form:

```
PASSED: 6 vectors matched their expected results
```

The second form also runs `tpm2_checkquote` from tpm2-tools on every quote, as a second
implementation of the signature and PCR digest checks, and scores it: each vector states
`expected.tpm2_checkquote` (`verifies` for TQB-01, 02, 03 and 06, `fails` for TQB-04 and 05), and
a different result fails the run. `tpm2_checkquote` does not check registration, key binding or
the reference state. If it cannot run, the result is `NOT ESTABLISHED` with exit status 2.
Expected last line:

```
PASSED: 6 vectors matched their expected results (including tpm2_checkquote)
```

`python3 gen.py` regenerates `derived/` and `vectors.json` from `source/`. Derived keys come from
published labels under `seed_prefix` in `vectors.json`, and signatures use RFC 6979, so a second
run gives the same bytes. The private keys derived from those labels are test keys for these
vectors and nothing else.

## Evidence

- 2026-10-28, Andrey Lazarev, this revision, all six vectors, Mode A with `run.py`
  (`cryptography` 50.0.1) and Mode B with `tpm2_checkquote` (tpm2-tools 5.6), scored, for the
  signature and PCR digest claims: TQB-01, 02, 03 and 06 verify, TQB-04 and 05 fail, as
  expected. Author-produced: the submitter produced the source evidence, wrote the vectors and
  wrote the verifier.

## Known limitations

- Only the AK is shown to be non-exportable. Its fixedTPM attribute is part of its name, and the
  registration record binds that name to the TPM's EK. The Ed25519 key in `cnf.jkt` was generated
  off the board, so nothing here shows that key cannot be copied. A quote over a thumbprint shows
  that the device vouched for the key at quote time, not that the key lives in the device.
- No proof of possession. The vectors compare `cnf.jkt` with the quote and never ask the
  presenter to sign with the workload key (for example a DPoP proof), so holding the grant and an
  old quote is enough to pass.
- The key is not sealed to a PCR policy. A changed state is detected by the verifier comparing
  the quote with the reference (TQB-06). The TPM does not refuse to use a key in a changed state.
- No freshness. The thumbprint was fixed before the quote and was not a verifier's challenge, so
  the time of the quote is not established by these vectors. A replayed old quote over the same
  key and the same state passes.
- The registered AK name is given to the verifier as trusted input. The registration record and
  its EK chain are in the source repository's rc14 release and are not re-verified here.
- One device, one registration made by the submitter on its own bench, development images only.
  The loader of `q02` is a development loader; which build the loader of `q15` is, is not
  recorded. Nothing here covers a release image or another board.
- The first measuring stage (SPL) is not itself authenticated, so the boot measurements start
  from an unverified root. A substituted first stage is not detected by these vectors.
- These vectors check records. They do not test a running authorization boundary.
