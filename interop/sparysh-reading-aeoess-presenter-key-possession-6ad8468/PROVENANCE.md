# Provenance

## Lab repository

- **Repository.** `Agent-Authority-Conformance/aps-conformance-suite`, commit `6ad8468acfff6600356efb05e2a530366b1d9d96`.
- **Candidate.** `aeoess-presenter-key-possession`, revision 1.
- **Files fetched.**
  - `vectors.json` and `CANDIDATE.md` were downloaded by the fetch script with `curl` from `https://raw.githubusercontent.com/Agent-Authority-Conformance/aps-conformance-suite/6ad8468acfff6600356efb05e2a530366b1d9d96/candidates/aeoess-presenter-key-possession/`.
  - The download was on 2026-11-17, around 14:12Z (`logs/fetch.log`).
  - Both matched the digests pinned in the script.
  - No other file of the repository was fetched.

## Files read, with digests

| File | SHA-256 | When read |
|---|---|---|
| task description (the boundary set out below) | not part of the lab corpus | before setup |
| `inputs/presenter-key-possession-reading-1-fetch-inputs.sh` | `6cf1862df75a5a6e942f0e27659e55ef92f064ad55484c6d4d49fa7e64995603` | before setup |
| `inputs/rfc/rfc7638.txt` | `98b29ab9652070e6a5fec748d43e221bbedc66b6b22e05903fb5366c04ef3110` | before setup (the supplied copy, identical digest), and phase 1 |
| `inputs/rfc/rfc8037.txt` | `f14347f9d8eead78ef6e7a1ea3d795d35d664033095a76a80fcd567904aaedaa` | before setup (the supplied copy, identical digest), and phase 1 |
| `inputs/blind/cases.json` | `7e8a902c8731493fd5f98fe58833749a23ace233d02f981fa53784a9e64b93ed` | phase 1 |
| `inputs/rfc/rfc9449.txt` | `3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13` | phase 1 |
| `inputs/rfc/rfc7515.txt` | `ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40` | phase 1 |
| `inputs/rfc/rfc7519.txt` | `fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248` | phase 1 |
| `inputs/rfc/rfc3986.txt` | `3102dae4b68cebe40337730312fcb612297b8928547267e8b3d1ee6002b2d683` | phase 1 |
| `inputs/SHA256SUMS` | as in `inputs/` | phase 1 |
| `inputs/sealed/CANDIDATE.md` | `e6562c79706903997574dc0c53d9e413d60dff46d88912b0650d330fa1034f5c` | phase 2 only |
| `inputs/sealed/id-map.json` | `11f0ef355543ced1b74018be7c47f3a7e3dce1a2caf884e1203d2c759d58df5c` | phase 2 only |
| `inputs/sealed/vectors.json`, `keys` block | `7e108c346475fb6c213827f657c8a4feaa46e48d0f0b5f3e20f119d98296436f` | phase 2 only |
| `inputs/sealed/vectors.json`, each case's `title`, `basis`, `rules` and `expect` | (same file) | phase 2 only, read together with the verdict comparison (`reader/compare.py --detail` printed them beside the comparison) |

## The RFCs

**How each was obtained** (`logs/fetch.log`):

- RFC 9449, 7638, 8037 and 7515: "supplied copy /mnt/user-data/uploads/rfcNNNN.txt". Andrii Sparysh supplied a downloaded copy of each.
- RFC 7517, 7519, 8032, 3986, 4648, 2119 and 8174: "read from: https://www.rfc-editor.org/rfc/rfcNNNN.txt". The fetch script fetched these.

**Revisions:** the published RFC texts. RFC 9449 is the September 2023 Proposed Standard, digest-checked against the candidate's pin. The other digests were recorded; see `VECTOR-INVENTORY.md`.

**Sections read, in order:**

1. RFC 9449 section headings (`grep` of the text), to locate the sections in scope.
2. RFC 9449 4.2, 4.3, 6.1, 7.1 and 11.1.
3. RFC 7519 section 7.2. 4.3 item 2 requires "a single and well-formed JWT", and JWT is RFC 7519's term.
4. RFC 7515 section 5.2. JWS validation, for the JWS signing input and the segment and duplicate-name rules that a JWT proof (RFC 9449 4.2, "signed (using JSON Web Signature (JWS) [RFC7515])") relies on.
5. RFC 3986 sections 6.2.2 and 6.2.3. The 4.3 SHOULD on normalisation before comparing `htu` names them.
6. RFC 3986 section 5.2.4. Section 6.2.2.3 refers to `remove_dot_segments` there.
7. RFC 7519 section 4, the sentence on duplicate claim names. This is part of JWT well-formedness.
8. RFC 7519 section 4.1.6 (`iat`) and section 2 (NumericDate). RFC 9449 4.2 defines `iat` by reference to "Section 4.1.6 of [RFC7519]".
9. RFC 7515 section 2 (Base64url Encoding). RFC 9449 4.2 `ath` refers to "Section 2 of [RFC7515]".
10. RFC 7638 and RFC 8037, in full, for the thumbprint of an Ed25519 key, the OKP members, and the Appendix A examples used as self-tests.

**Sections not read:**

- RFC 9449 1 to 3, 4.1, 5, 6.2, 7.2, 7.3, 8 to 10, 11.2 to 11.11, 12 and 13.
- RFC 7515, apart from sections 2 and 5.2.
- RFC 7519, apart from the parts listed above.
- RFC 3986, apart from sections 5.2.4, 6.2.2 and 6.2.3.
- RFC 7517, 8032, 4648, 2119 and 8174 in full. These were obtained but not opened.

**Used without a supplied text:**

- **IANA JOSE "JSON Web Signature and Encryption Algorithms" registry.** Used for the set of registered asymmetric algorithms in 4.3 item 5, as a fixed list.
- **RFC 9110.** Used for the HTTP method (exact, case-sensitive comparison) and the target URI, both referred to from 4.2 `htm` and `htu`.
- **RFC 6749, section 3.3.** Used for the space-delimited `scope`, which only the candidate's authority axis needs.
- **RFC 7159 / JSON.** Used for parsing the segments with Python's `json` module.
- **RFC 4648, section 5.** Used for the base64url alphabet, implemented from the definition quoted in RFC 7515 section 2.
- **RFC 8032.** Used for Ed25519 verification, through the `cryptography` package. The text was obtained but not read.

## Boundary as kept

- **The phase-1 zip.**
  - Written at 2026-11-17T14:19Z, before any file under `inputs/sealed/` was opened.
  - SHA-256 `e1127a677d67a0e480489ea541a5ec0db48e8838606bb56066f198b2d2e101d7`. The zip is kept as `logs/phase1.zip`, and its digest is in `logs/phase1-zip.sha256`.
  - It was also saved to `/mnt/user-data/outputs/` as `sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1.zip`.
- **Not downloaded or read.**
  - The candidate's `check.py`, `mutate.py` and `generate.py`.
  - Every other file of the lab repository, including other candidates (among them `tactiq-tpm-bound-key`), `docs/`, `fixtures/` and `interop/`.
  - The Agent Passport System and its SDKs or draft.
  - Any other DPoP implementation, test suite or vector set.
  - No JOSE, JWT or DPoP library was used.
- **After setup, no network request and no web search was made.**
- **`out/phase1.json` was not edited after the zip.** Its SHA-256 is `2b0fe980cc2909e7fe21ae68644ac1ed4e3917796d561ec79543623cbc9b06ce` in the zip and in this directory.

## Events at the boundary

1. **Placement of the supplied RFC copies.** The supplied RFC copies (9449, 7638, 8037, 7515) and the fetch script were placed in `/mnt/user-data/uploads/` under the names `rfcNNNN.txt` before setup, so that the script would find them by their headers. Their digests are unchanged.
2. **Optional RFCs fetched over the network.** The fetch script obtained the optional RFCs 7517, 7519, 8032, 3986, 4648, 2119 and 8174 from the RFC Editor during setup. This is the script's own behaviour, and it happened before the no-network rule took effect.
3. **Two phase-1 runs missing from the transcript.**
   - In phase 1, `reader/explore.py` (which decodes the blind cases for inspection) was first run once from a scratch location before being run again under the log. The logged run is in `logs/transcript.log`, and its output is in `logs/explore-blind.txt`.
   - A debug run of `reader/checker.py` wrote to a scratch directory before the logged runs. Neither unlogged run read anything outside the boundary.
   - The phase-1 checker had a self-test step added after the debug run. The logged runs are those of the version in `reader/`.
4. **Other lab files named in `CANDIDATE.md`.** `CANDIDATE.md` (phase 2) names `docs/mappings/owasp-aimm-pillar-2.md` and `tactiq-tpm-bound-key`. Neither was opened.
5. **Representation statements in the blind copy.** `inputs/blind/cases.json` carries the candidate's representation statements `text_status` and `readings`, which are permitted reading. No file read turned out to contain someone's code. No file read turned out to contain a reading other than these permitted statements.

## Authorship

- **Who.** The run was carried out and checked by Andrii Sparysh (GitHub `andreysparish`), using an AI assistant. He authored none of the candidate, its vectors, its generator, its checker, RFC 9449, or any claim input.
- **Classification.** He wrote the checker. Under `CONTRIBUTING.md`, Ed25519 signature validity under the embedded key is independent Mode B, because `cryptography` supplies that result. Every other claim is author-produced Mode B (`run-report.md`, "Labels per claim").
- **What the recomputation is written from.** It is written from the RFC texts listed above, the blind cases, and, in phase 2 only, the candidate's stated axis map.
- **Citations.** At start-up the checker verifies 54 cited sentences.
- **Candidate code.** The candidate's code was never obtained.
- **Judgements made in phase 2.**
  - Choice points A1 and A2 were fixed by `CANDIDATE.md`'s axis definitions (`out/changes.md`).
  - The divergence analysis was done, and findings F01 to F04 were drafted.
  - The phase-2 entry A20 was added to the ambiguity log.

## Changes made in review, before merge (2026-11-17)

- **What did not change.** No command, output, log or verdict of the run. `out/` and `logs/` are unchanged.
- **Classification.**
  - The record was first labelled independent as a whole. Under `CONTRIBUTING.md` it is now labelled per claim:
    - Ed25519 signature validity under the embedded key is independent Mode B;
    - every other claim is author-produced Mode B, because the runner wrote the checker that supplies it.
  - Corrected: `run-report.md` (field "author-produced or independent", new section "Labels per claim"), `README.md` (section "Verification split", formerly "Independence") and this file (section "Authorship", formerly "Independence").
  - `out/changes.md` still refers to the section by its earlier name.
- **Digests.** The digests of the changed files were recomputed in `SHA256SUMS.txt`.
