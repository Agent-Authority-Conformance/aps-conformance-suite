# Run report

- **who ran it:** Andrii Sparysh (GitHub `andreysparish`), using an AI assistant
- **date:** 2026-11-17
- **run mode:** B, alternate recomputation
- **implementation name, and its repository and version:** the checker in `reader/`, identified by the SHA-256 of each source file:
  - `reader/checker.py` SHA-256 `ab95f78651b6a4752b953aab12716eed37afbb450b4ab83add96709828b74578`
  - `reader/phase2.py` SHA-256 `a7b559e0bc52f462a4edf4b5cf234e848d58a4e919cce567ae74739b7296b63c`
  - `reader/compare.py` SHA-256 `c334946b80b2d756278d2cefb8da9123e077fb341847ce9c0adbaafdd3c8310a`
  - `reader/tables.py` SHA-256 `c15adbd9b727308f77117f03a2d90ee7776a7a257cc2bf66c106e7f6bb2a8922`
  - `reader/explore.py` SHA-256 `eafd642ff4a3a78fef12e0320d5e8d5a6acbf2b9618ac53eda9b4a08b9fdfa8e`
- **corpus reference:** `aps-conformance-suite` at `6ad8468acfff6600356efb05e2a530366b1d9d96`, candidate `aeoess-presenter-key-possession`, revision 1
- **environment:** Python 3.13.18, `cryptography` 50.0.1 (Ed25519 only), no other third-party package; Ubuntu 24.04.5 LTS, Linux 6.18.44 x86_64
- **author-produced or independent:** labelled per claim; see "Labels per claim".
  - Ed25519 signature validity under the public key embedded in each proof: independent.
  - Every other claim: author-produced. The authorship relationship is that the runner wrote the checker (`reader/checker.py`, `reader/phase2.py`) that supplies those results.
  - The runner authored none of the candidate, its vectors, its generator, its checker or RFC 9449. The checker was written from the RFC text and a blind copy of the cases, and its phase-1 output was frozen before the expected verdicts were opened.
- **suspected defective vectors:**
  - PK-18. Its expected `nonconformant` rests on reading RFC 9449 11.1 ("servers can store the jti value"; "would be declined") as a requirement. This run reads the text two ways and reports `ambiguous` (F01).
  - Data observations:
    - The axis-to-item map that decides PK-26 and PK-28 is stated only in `CANDIDATE.md` (F02).
    - Four conditions have no case that isolates them under this checker: items 1, 2 and 5, and item 3 for `jti`/`htm`/`htu`/`iat` and for `nonce` (F03).
    - PK-11's `basis` omits 4.3 item 12 (F04).

## Labels per claim

The runner for every claim is Andrii Sparysh.

| claim | cases | mode | label | implementation |
|---|---|---|---|---|
| Ed25519 signature validity under the public key in the proof's own `jwk` header (rule R06): 24 valid; PK-05 and PK-06 invalid | the 26 cases in which a verification call was made | Mode B | independent | `cryptography` 50.0.1, `Ed25519PublicKey.verify`. A thin harness in `reader/checker.py` passes it the first two segments of the compact JWT as received (the signing input, not reconstructed), the decoded third segment and the decoded `x`. |
| Signature fact for PK-08 (`alg` `none`) and PK-25 (two segments), decided before any verification call | PK-08, PK-25 | Mode B | author-produced | `reader/checker.py` |
| Header and form: single header, well-formed JWT, `typ`, `alg`, no private member in `jwk` (R01, R02, R04, R05, R07) | all 28 | Mode B | author-produced | `reader/checker.py` |
| Required claims (R03a to R03c) | all 28 | Mode B | author-produced | `reader/checker.py` |
| JWK thumbprint (RFC 7638, RFC 8037) against `cnf.jkt` (R12b) | all 28 | Mode B | author-produced | `reader/checker.py` |
| `ath` against the access token (R12a) | all 28 | Mode B | author-produced | `reader/checker.py` |
| `htm`, and `htu` with URI normalisation (R08, R09) | all 28 | Mode B | author-produced | `reader/checker.py` |
| Nonce, `iat` window, `jti` replay (R10, R11, R11f, R13) | all 28 | Mode B | author-produced | `reader/checker.py` |
| Scope contains `required_scope` (RS) | all 28 | Mode B | author-produced | `reader/checker.py` |
| Axis values, `decision`, `reject_axis` and the 28 verdicts | all 28 | Mode B | author-produced | `reader/checker.py`, `reader/phase2.py` |
| Key claims K1 to K8: derivation from `keys.seed_rule`, thumbprints of the derived keys, the key in each proof, PK-07's `d`, and the segment checks for PK-05, PK-06, PK-08 and PK-25 | as listed in `RESULTS.md` | Mode B | author-produced | `reader/phase2.py` |

The independent row establishes signature validity under the key embedded in each proof. It does not establish that the key is trusted or that it is bound to the token; that binding is the thumbprint row, which is author-produced.

For every author-produced row, the authorship relationship is that the runner wrote the checker that supplies the result. The sensitivity table, the ambiguity log and the findings are this run's own analysis, not claims of the candidate.

## Per-vector table

| Original | Blind | Phase 1 verdict | Final verdict | Expected | Final vs expected |
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

Phase 1: 25 of 28 match. Final: 27 of 28 match. The change between them is described in `out/changes.md`.

## Commands

Every command run in the record directory, verbatim, with its full output and exit code, copied from `logs/transcript.log`. The command that packaged this directory is not included.

````
$ date -u +%Y-%m-%dT%H:%M:%SZ; uname -srm; cat /etc/os-release | head -3; python3 --version
2026-11-17T14:12:15Z
Linux 6.18.44-fc-v553 x86_64
PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
Python 3.13.18
[exit 0]

$ bash presenter-key-possession-reading-1-fetch-inputs.sh 2>&1 | tee logs/fetch.log; exit ${PIPESTATUS[0]}
ok  inputs/sealed/vectors.json
ok  inputs/sealed/CANDIDATE.md
blind copy: 28 cases
rfc9449 read from: supplied copy /mnt/user-data/uploads/rfc9449.txt
ok  inputs/rfc/rfc9449.txt
rfc7638 read from: supplied copy /mnt/user-data/uploads/rfc7638.txt
recorded  inputs/rfc/rfc7638.txt  98b29ab9652070e6a5fec748d43e221bbedc66b6b22e05903fb5366c04ef3110
rfc8037 read from: supplied copy /mnt/user-data/uploads/rfc8037.txt
recorded  inputs/rfc/rfc8037.txt  f14347f9d8eead78ef6e7a1ea3d795d35d664033095a76a80fcd567904aaedaa
rfc7515 read from: supplied copy /mnt/user-data/uploads/rfc7515.txt
recorded  inputs/rfc/rfc7515.txt  ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40
rfc7517 read from: https://www.rfc-editor.org/rfc/rfc7517.txt
recorded  inputs/rfc/rfc7517.txt  681c19b92a85068716b7e89c5815aa821bd3f11c755ff1c641b40ae9851bb33c
rfc7519 read from: https://www.rfc-editor.org/rfc/rfc7519.txt
recorded  inputs/rfc/rfc7519.txt  fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248
rfc8032 read from: https://www.rfc-editor.org/rfc/rfc8032.txt
recorded  inputs/rfc/rfc8032.txt  ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3
rfc3986 read from: https://www.rfc-editor.org/rfc/rfc3986.txt
recorded  inputs/rfc/rfc3986.txt  3102dae4b68cebe40337730312fcb612297b8928547267e8b3d1ee6002b2d683
rfc4648 read from: https://www.rfc-editor.org/rfc/rfc4648.txt
recorded  inputs/rfc/rfc4648.txt  84e14418f795d503be5f34bf23ce4ebaa119e9ec7c9f667d8caeb111385b178f
rfc2119 read from: https://www.rfc-editor.org/rfc/rfc2119.txt
recorded  inputs/rfc/rfc2119.txt  3c2ceb7bfc84cd34720f4a5271338ab9d8280d34bdd1eb250c64306202f2ed8b
rfc8174 read from: https://www.rfc-editor.org/rfc/rfc8174.txt
recorded  inputs/rfc/rfc8174.txt  5ca0e2f90be0bc5928ee465f76518fee316dfa775aed885658a29a419cc293b7
cryptography 50.0.1
done: inputs/SHA256SUMS
[exit 0]

$ cat inputs/SHA256SUMS; wc -c inputs/blind/cases.json; python3 -I -c "import json;d=json.load(open(\"inputs/blind/cases.json\"));print(list(d));print(json.dumps({k:d[k] for k in d if k!=\"cases\"},indent=1))"
7e8a902c8731493fd5f98fe58833749a23ace233d02f981fa53784a9e64b93ed  ./blind/cases.json
6cf1862df75a5a6e942f0e27659e55ef92f064ad55484c6d4d49fa7e64995603  ./presenter-key-possession-reading-1-fetch-inputs.sh
3c2ceb7bfc84cd34720f4a5271338ab9d8280d34bdd1eb250c64306202f2ed8b  ./rfc/rfc2119.txt
3102dae4b68cebe40337730312fcb612297b8928547267e8b3d1ee6002b2d683  ./rfc/rfc3986.txt
84e14418f795d503be5f34bf23ce4ebaa119e9ec7c9f667d8caeb111385b178f  ./rfc/rfc4648.txt
ecbf84674118e62526511c1237e1deaa86aada86d25b247623a2a7e04ae62e40  ./rfc/rfc7515.txt
681c19b92a85068716b7e89c5815aa821bd3f11c755ff1c641b40ae9851bb33c  ./rfc/rfc7517.txt
fecd930e9ccf2276b95c0017c6c4ff5d09352e4bc3c7629946447894e0f97248  ./rfc/rfc7519.txt
98b29ab9652070e6a5fec748d43e221bbedc66b6b22e05903fb5366c04ef3110  ./rfc/rfc7638.txt
ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3  ./rfc/rfc8032.txt
f14347f9d8eead78ef6e7a1ea3d795d35d664033095a76a80fcd567904aaedaa  ./rfc/rfc8037.txt
5ca0e2f90be0bc5928ee465f76518fee316dfa775aed885658a29a419cc293b7  ./rfc/rfc8174.txt
3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13  ./rfc/rfc9449.txt
e6562c79706903997574dc0c53d9e413d60dff46d88912b0650d330fa1034f5c  ./sealed/CANDIDATE.md
11f0ef355543ced1b74018be7c47f3a7e3dce1a2caf884e1203d2c759d58df5c  ./sealed/id-map.json
7e108c346475fb6c213827f657c8a4feaa46e48d0f0b5f3e20f119d98296436f  ./sealed/vectors.json
35161 inputs/blind/cases.json
['label', 'revision', 'text_status', 'readings', 'now', 'note_on_this_copy', 'cases']
{
 "label": "aeoess-presenter-key-possession",
 "revision": 1,
 "text_status": "RFC 9449 is a published Proposed Standard. The scope check and the axis names are this candidate's representation, not RFC 9449 text",
 "readings": "an outcome is the verifier's answer for one request. Each axis is read on its own, whatever the other axes say",
 "now": 1793750400,
 "note_on_this_copy": "blind copy made by the fetch script: per case only input and outcome; identifiers replaced; title, basis, rules and expect, and the top-level keys block, withheld until phase 1 is saved"
}
[exit 0]

$ python3 -I reader/explore.py inputs/blind/cases.json > logs/explore-blind.txt; echo lines: $(wc -l < logs/explore-blind.txt)
lines: 112
[exit 0]

$ python3 -I reader/checker.py inputs/blind/cases.json inputs/rfc out
citations verified: 54
self-tests: {"3986-6.2.2-example": true, "3986-6.2.3-example": true, "8037-A.3-thumbprint": true, "8037-A.5-verify": true}
tally: {"ambiguous": 4, "conformant": 5, "nonconformant": 19}
B01 nonconformant (primary reading: nonconformant)
B02 nonconformant (primary reading: nonconformant)
B03 nonconformant (primary reading: nonconformant)
B04 conformant (primary reading: conformant)
B05 nonconformant (primary reading: nonconformant)
B06 nonconformant (primary reading: nonconformant)
B07 nonconformant (primary reading: nonconformant)
B08 nonconformant (primary reading: nonconformant)
B09 conformant (primary reading: conformant)
B10 nonconformant (primary reading: nonconformant)
B11 nonconformant (primary reading: nonconformant)
B12 nonconformant (primary reading: nonconformant)
B13 nonconformant (primary reading: nonconformant)
B14 nonconformant (primary reading: nonconformant)
B15 nonconformant (primary reading: nonconformant)
B16 conformant (primary reading: conformant)
B17 ambiguous (primary reading: nonconformant)
B18 nonconformant (primary reading: nonconformant)
B19 nonconformant (primary reading: nonconformant)
B20 nonconformant (primary reading: nonconformant)
B21 conformant (primary reading: conformant)
B22 nonconformant (primary reading: nonconformant)
B23 conformant (primary reading: conformant)
B24 nonconformant (primary reading: nonconformant)
B25 nonconformant (primary reading: nonconformant)
B26 ambiguous (primary reading: conformant)
B27 ambiguous (primary reading: nonconformant)
B28 ambiguous (primary reading: nonconformant)
[exit 0]

$ python3 -I reader/checker.py inputs/blind/cases.json inputs/rfc logs/run2 >/dev/null && cmp out/phase1.json logs/run2/phase1.json && cmp out/phase1-sensitivity.json logs/run2/phase1-sensitivity.json && echo byte-identical && sha256sum out/phase1.json logs/run2/phase1.json out/phase1-sensitivity.json logs/run2/phase1-sensitivity.json
byte-identical
2b0fe980cc2909e7fe21ae68644ac1ed4e3917796d561ec79543623cbc9b06ce  out/phase1.json
2b0fe980cc2909e7fe21ae68644ac1ed4e3917796d561ec79543623cbc9b06ce  logs/run2/phase1.json
0b724bd5d90938a578ef3dd7b13eb4bc91b2841af5a487e51860dc2b9b7d412a  out/phase1-sensitivity.json
0b724bd5d90938a578ef3dd7b13eb4bc91b2841af5a487e51860dc2b9b7d412a  logs/run2/phase1-sensitivity.json
[exit 0]

$ rm -rf logs/run2; mkdir -p /tmp/p1/sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1 && cp -r out reader ambiguity-log.md /tmp/p1/sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/ && mkdir -p /tmp/p1/sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/logs && cp logs/fetch.log logs/transcript.log logs/explore-blind.txt /tmp/p1/sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/logs/ && find /tmp/p1 -name __pycache__ -prune -exec rm -rf {} + ; cd /tmp/p1 && rm -f phase1.zip && TZ=UTC find . -exec touch -d 2026-11-17T00:00:00Z {} + && find sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1 -type f | LC_ALL=C sort | zip -X -q phase1.zip -@ && cp phase1.zip /mnt/user-data/outputs/sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1.zip && cd /mnt/user-data/working/run && cp /tmp/p1/phase1.zip logs/phase1.zip && (cd logs && sha256sum phase1.zip > phase1-zip.sha256 && cat phase1-zip.sha256) && unzip -l logs/phase1.zip && date -u +%Y-%m-%dT%H:%M:%SZ
e1127a677d67a0e480489ea541a5ec0db48e8838606bb56066f198b2d2e101d7  phase1.zip
Archive:  logs/phase1.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     8425  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/ambiguity-log.md
    12523  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/logs/explore-blind.txt
     1850  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/logs/fetch.log
     8073  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/logs/transcript.log
    20070  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/out/phase1-sensitivity.json
   174713  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/out/phase1.json
    35224  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/reader/checker.py
      982  2026-11-17 00:00   sparysh-reading-aeoess-presenter-key-possession-6ad8468-phase1/reader/explore.py
---------                     -------
   261860                     8 files
2026-11-17T14:19:08Z
[exit 0]

$ cat inputs/sealed/CANDIDATE.md; echo ====; cat inputs/sealed/id-map.json; echo ====; python3 -I -c "import json;d=json.load(open(\"inputs/sealed/vectors.json\"));print([k for k in d]);print(json.dumps(d[\"keys\"],indent=1))"
# Candidate: aeoess-presenter-key-possession

Cases for one question a verifier must answer before an agent's request goes through: does the
party presenting the token hold the key the token is bound to, for this request, now. Each case
gives a real signed DPoP proof, the access token it is presented with, the request, and one answer
a verifier could give. The case states whether that answer is conformant under the rules below
and which rule decides. Whether to accept or reject follows RFC 9449. Which axis a verifier reports
as failed is this candidate's representation, described under Normative target. This is a candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds
nothing to the lab's schema, failure classes or verifier behavior.

The answer is read on four separate axes, because each can fail while the others hold.

- `proof_signature`: the proof is a well-formed DPoP JWT and its signature verifies with the key
  in its own `jwk` header (RFC 9449 section 4.3, items 2 to 7).
- `key_binding`: that key is the key the access token is bound to (`cnf.jkt`, section 6.1), and
  the proof's `ath` is the hash of the presented token (section 4.3, item 12).
- `request_binding`: the proof was made for this method and URI, with the server's nonce, inside
  the accepted time window, and its `jti` was not seen before for this URI (items 8 to 11 and
  section 11.1).
- `authority`: the operation's required scope is in the token's scope.

A valid signature shows that someone holds a key. It does not show that the key is the one the
token is bound to, and possession of the bound key does not show authority for the operation. The
central cases are PK-02 to PK-04 and PK-22, a proof validly signed with the attacker's own key.
Accepting it fails RFC 9449 section 4.3 item 12. Refusing it for the wrong reason is nonconformant
only under this candidate's axis reporting, because RFC 9449 does not define the axes.

This candidate narrows one line of `docs/mappings/owasp-aimm-pillar-2.md`, Remaining gaps:
"Proof that the presenter holds the bound key (L5). ASE-12 and the token exchange actor check
compare identities only." It complements `tactiq-tpm-bound-key`, which binds a TPM quote to a
grant's key without requiring the presenter to prove it holds that key at request time.

## Submitter

Tymofii Pidlisnyi (Agent Passport System). Lab maintainer, so the expected results and the
checker are author-produced.

## Normative target

- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession (DPoP), Proposed Standard, September 2023.
  https://www.rfc-editor.org/rfc/rfc9449.txt, sha256
  `3842c58e1f6043389416023b9bb8d765048266024982fbbd90640e05943f4e13` of the retrieved TXT copy.
  Sections 4.2, 4.3, 6.1, 7.1 and 11.1 are used.
- RFC 7638 (JWK thumbprint) and RFC 8037 (Ed25519 JWK members) for the `jkt` computation.

The `authority` axis is not RFC 9449 text. RFC 9449 leaves authorization to the resource server.
The candidate represents it as the token's space separated `scope` containing the request's
`required_scope`, so possession and authority can fail separately.

The four axes, and the R-DECISION requirement that a reject name an axis that actually failed, are
also this candidate's representation. RFC 9449 section 7.1 says a rejection SHOULD carry an error
parameter, names `invalid_dpop_proof` for a proof that fails the section 4.3 checks, and shows
`invalid_token` for a failed key binding in its Figure 16. It does not split a rejection into
axes. PK-04, PK-21, PK-22 and PK-26 to PK-28 reject a request that should be rejected and are
nonconformant only on the reported axis, and their `basis` says so.

## Source

The cases are generated by `generate.py` from the rules above. Keys are Ed25519 test keys
derived from public seed labels (`keys.seed_rule` in `vectors.json`). Ed25519 signatures are
deterministic, so `generate.py` reproduces `vectors.json` byte for byte.

## License

Apache 2.0, the license of this repository. The candidate quotes no RFC text beyond section
and item numbers and short rule summaries.

## What the cases test

| Case | Input | Answer given | Expected |
|---|---|---|---|
| PK-01 | valid proof, bound key, fresh, in scope | accept | conformant |
| PK-02 | proof signed with the attacker's own key | accept, key reported bound | nonconformant |
| PK-03 | same | reject at key_binding | conformant |
| PK-04 | same | reject, signature reported invalid | nonconformant |
| PK-05, PK-06 | payload changed after signing | accept, reject at signature | nonconformant, conformant |
| PK-07 | private key inside the `jwk` header | accept | nonconformant |
| PK-08 | `alg` none, empty signature | accept | nonconformant |
| PK-09 | `typ` is not `dpop+jwt` | accept | nonconformant |
| PK-10 | same key, `ath` of another token | accept | nonconformant |
| PK-11 | bearer token without `cnf` | accept as bound | nonconformant |
| PK-12 | `htm` GET on a POST | accept | nonconformant |
| PK-13 | request URI differs only in its query | accept | conformant |
| PK-14 | `htu` names another path | accept | nonconformant |
| PK-15 | server nonce issued, proof carries another | accept | nonconformant |
| PK-16 | `iat` ten minutes old, 300 s window | accept | nonconformant |
| PK-17 | `iat` 20 s ahead, no future allowance declared | accept | ambiguous |
| PK-18 | `jti` already seen at this URI, server tracks `jti` | accept | nonconformant |
| PK-19, PK-20 | possession holds, scope lacks the operation | accept, reject at authority | nonconformant, conformant |
| PK-21 | same | reject, blamed on key binding | nonconformant |
| PK-22 | attacker's own key, axes reported correctly | reject naming the signature | nonconformant |
| PK-23 | proof without `ath`, presented with an access token | accept | nonconformant |
| PK-24 | server nonce issued, proof carries none | accept | nonconformant |
| PK-25 | DPoP value with two segments, not a JWT | accept | nonconformant |
| PK-26 | proof without `ath` | reject at key_binding, proof reported well formed | nonconformant |
| PK-27 | proof without `ath` | reject at signature, key reported bound | nonconformant |
| PK-28 | server nonce issued, proof carries none | reject at signature, request reported bound | nonconformant |

Rules: R-SIG, R-BIND, R-REQ and R-AUTH compare each axis of the answer with the axis recomputed
from the input. R-DECISION requires accept when every axis holds, and otherwise a reject that
names an axis that actually failed. It does not require an order among failing axes.

## How to run

```
python3 -I generate.py | cmp - vectors.json
python3 -I check.py vectors.json
python3 -I mutate.py vectors.json
```

`check.py` and `generate.py` need the `cryptography` package for Ed25519.

## Evidence

At this revision `generate.py` reproduces `vectors.json` byte for byte, `check.py` prints
`28/28 agree` and `mutate.py` prints `19/19 mutants killed`, each with exit 0. Each of the 19
mutants weakens one check (signature not verified, `cnf.jkt` not compared, `ath` not compared,
query not ignored, `jti` not tracked, scope not checked, any reject axis accepted, and others),
and at least one case changes its verdict under it. PK-23 and PK-24 are each caught by two
checks, a missing required claim and the `ath` or nonce comparison, so weakening one of those
checks does not change their verdicts. PK-26 to PK-28 report one axis wrongly at a time, and they
are the cases that kill the mutants for the required claims check, the missing `ath` and the
missing nonce. Like PK-04, PK-21 and PK-22, they are nonconformant only on the reported axis. This shows the checker agrees with the
expected results and that each rule has a case depending on it. It does not show that the
expected results are the only reading of RFC 9449, and no implementation has been run against
these cases.

## Known limitations

- The checker supports EdDSA over Ed25519 only. A proof with another registered algorithm is
  refused by local policy (`accepted_algs`), which section 4.3 item 5 allows. ES256 and other
  algorithms are not exercised.
- URI comparison strips query and fragment and compares scheme, authority and path exactly. RFC
  9449 section 4.3 item 9 defers to URI normalization rules that the cases do not exercise.
- The access token is an opaque string with its claims supplied beside it, as introspection
  would return them. Token signature validation is out of scope.
- `jti` replay is checked only when the case declares that the server tracks `jti`. Section 11.1
  says a server can do this and does not require it.
- PK-17 is ambiguous by design: section 11.1 lets a server accept a near-future `iat`, and the
  case declares no allowance.
- The `authority` axis and the axis names are this candidate's representation.
- Each case carries one DPoP value, so section 4.3 item 1 (more than one DPoP header) is not
  exercised.
- `jti` values are short test labels such as `p-0001`. Section 4.2 asks the client for a value
  with negligible collision probability, which a server cannot check, so no case tests it.
- PK-07 carries the agent's test private key in its `jwk` header. Like every key here it is
  derived from a public seed label and is not a credential.
- Expected results, checker and mutations are written by the lab maintainer. A run by an
  implementation, or an independent checker, would be a separate record.
====
{
 "B01": "PK-05",
 "B02": "PK-12",
 "B03": "PK-23",
 "B04": "PK-20",
 "B05": "PK-19",
 "B06": "PK-25",
 "B07": "PK-10",
 "B08": "PK-11",
 "B09": "PK-13",
 "B10": "PK-21",
 "B11": "PK-07",
 "B12": "PK-22",
 "B13": "PK-24",
 "B14": "PK-08",
 "B15": "PK-02",
 "B16": "PK-01",
 "B17": "PK-17",
 "B18": "PK-15",
 "B19": "PK-27",
 "B20": "PK-16",
 "B21": "PK-03",
 "B22": "PK-14",
 "B23": "PK-06",
 "B24": "PK-04",
 "B25": "PK-09",
 "B26": "PK-26",
 "B27": "PK-18",
 "B28": "PK-28"
}====
['label', 'revision', 'text_status', 'readings', 'now', 'keys', 'cases']
{
 "agent": {
  "crv": "Ed25519",
  "kty": "OKP",
  "x": "s08tgBeilGl3TAZ94T3RwNKsACFVkcFMgJtjIJvDeaQ"
 },
 "attacker": {
  "crv": "Ed25519",
  "kty": "OKP",
  "x": "nSTCN36lL9LqVqNs0oheqNt0Z0WYUdarPXth1m5nwvg"
 },
 "seed_rule": "Ed25519 private key = sha256('aeoess-presenter-key-possession/' + label), test keys only"
}
[exit 0]

$ python3 -I reader/compare.py out/phase1.json inputs/sealed/vectors.json inputs/sealed/id-map.json --detail
PK-01 B16 phase1=conformant final=conformant expect=conformant match
   title: Valid proof, bound key, fresh, in scope: accept
   basis: ['4.3', '6.1', '7.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-02 B15 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Attacker's own key, validly signed, accepted as bound
   basis: ['4.3 item 6', '4.3 item 12', '6.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-03 B21 phase1=conformant final=conformant expect=conformant match
   title: Attacker's own key, refused at key binding
   basis: ['4.3 item 6', '4.3 item 12', '6.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-04 B24 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Attacker's own key, refused but reported as a bad signature
   basis: ['4.3 item 6', '4.3 item 12', "axis reporting is this candidate's representation"]
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-05 B01 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Payload changed after signing, accepted
   basis: ['4.3 item 6']
   rules: ['R-SIG', 'R-DECISION']
PK-06 B23 phase1=conformant final=conformant expect=conformant match
   title: Payload changed after signing, refused at the signature
   basis: ['4.3 item 6']
   rules: ['R-SIG', 'R-DECISION']
PK-07 B11 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Private key inside the jwk header, accepted
   basis: ['4.3 item 7']
   rules: ['R-SIG', 'R-DECISION']
PK-08 B14 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: alg none with an empty signature, accepted
   basis: ['4.3 item 5']
   rules: ['R-SIG', 'R-DECISION']
PK-09 B25 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Wrong typ, accepted
   basis: ['4.3 item 4']
   rules: ['R-SIG', 'R-DECISION']
PK-10 B07 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Same key, proof made for another access token, accepted
   basis: ['4.3 item 12', '4.2 ath']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-11 B08 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Bearer token without cnf presented with a valid proof, accepted as bound
   basis: ['7.1', '6.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-12 B02 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Proof for GET presented on POST, accepted
   basis: ['4.3 item 8']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-13 B09 phase1=conformant final=conformant expect=conformant match
   title: htu differs only in its query, accepted
   basis: ['4.3 item 9']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-14 B22 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: htu names another path, accepted
   basis: ['4.3 item 9']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-15 B18 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Server issued a nonce, proof carries another, accepted
   basis: ['4.3 item 10']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-16 B20 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Proof created ten minutes ago with a 300 s window, accepted
   basis: ['4.3 item 11', '11.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-17 B17 phase1=ambiguous final=ambiguous expect=ambiguous match
   title: Proof dated 20 s ahead, no future skew declared, accepted
   basis: ['4.3 item 11', '11.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-18 B27 phase1=ambiguous final=ambiguous expect=nonconformant diverge
   title: Server tracks jti, proof jti already seen at this URI, accepted
   basis: ['11.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-19 B05 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Possession established, operation outside the token scope, accepted
   basis: ['7.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-20 B04 phase1=conformant final=conformant expect=conformant match
   title: Possession established, operation outside the token scope, refused for authority
   basis: ['7.1']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-21 B10 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Operation outside the token scope, refused but blamed on key binding
   basis: ['7.1', '6.1', "axis reporting is this candidate's representation"]
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-22 B12 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Attacker's own key, axes reported correctly, refusal names the signature
   basis: ['4.3 item 6', '4.3 item 12', "axis reporting is this candidate's representation"]
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-23 B03 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Proof without ath presented with an access token, accepted
   basis: ['4.2 ath', '4.3 item 3', '4.3 item 12']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-24 B13 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Server issued a nonce, proof carries none, accepted
   basis: ['4.2 nonce', '4.3 item 3', '4.3 item 10']
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-25 B06 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: DPoP value is not a single well-formed JWT, accepted
   basis: ['4.3 item 2']
   rules: ['R-SIG', 'R-DECISION']
PK-26 B26 phase1=ambiguous final=ambiguous expect=nonconformant diverge
   title: Proof without ath, reported well formed, refused at key binding
   basis: ['4.3 item 3', "axis reporting is this candidate's representation"]
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-27 B19 phase1=nonconformant final=nonconformant expect=nonconformant match
   title: Proof without ath, refused at the signature, key reported bound
   basis: ['4.3 item 12', "axis reporting is this candidate's representation"]
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
PK-28 B28 phase1=ambiguous final=ambiguous expect=nonconformant diverge
   title: Server issued a nonce, proof carries none, refused at the signature, request reported bound
   basis: ['4.3 item 10', "axis reporting is this candidate's representation"]
   rules: ['R-SIG', 'R-BIND', 'R-REQ', 'R-AUTH', 'R-DECISION']
matches: 25 of 28
[exit 0]

$ python3 -I reader/phase2.py inputs/blind/cases.json inputs/sealed/vectors.json inputs/sealed/id-map.json inputs/rfc out
tally: {"ambiguous": 2, "conformant": 5, "nonconformant": 21} matches: 27 of 28
PK-01 B16 conformant expect conformant match
PK-02 B15 nonconformant expect nonconformant match
PK-03 B21 conformant expect conformant match
PK-04 B24 nonconformant expect nonconformant match
PK-05 B01 nonconformant expect nonconformant match
PK-06 B23 conformant expect conformant match
PK-07 B11 nonconformant expect nonconformant match
PK-08 B14 nonconformant expect nonconformant match
PK-09 B25 nonconformant expect nonconformant match
PK-10 B07 nonconformant expect nonconformant match
PK-11 B08 nonconformant expect nonconformant match
PK-12 B02 nonconformant expect nonconformant match
PK-13 B09 conformant expect conformant match
PK-14 B22 nonconformant expect nonconformant match
PK-15 B18 nonconformant expect nonconformant match
PK-16 B20 nonconformant expect nonconformant match
PK-17 B17 ambiguous expect ambiguous match
PK-18 B27 ambiguous expect nonconformant DIVERGE
PK-19 B05 nonconformant expect nonconformant match
PK-20 B04 conformant expect conformant match
PK-21 B10 nonconformant expect nonconformant match
PK-22 B12 nonconformant expect nonconformant match
PK-23 B03 nonconformant expect nonconformant match
PK-24 B13 nonconformant expect nonconformant match
PK-25 B06 nonconformant expect nonconformant match
PK-26 B26 nonconformant expect nonconformant match
PK-27 B19 nonconformant expect nonconformant match
PK-28 B28 nonconformant expect nonconformant match
K0_blind_equals_sealed -> True
K1_keys_derive_from_seed_rule -> True
K2_cnf_jkt_vs_derived_thumbprints -> True
K3_every_proof_jwk_is_a_derived_key -> True
K4_private_d_derives_from_a_stated_seed -> True
{
 "K0_blind_equals_sealed": {
  "cases": 28,
  "mismatches": [],
  "result": true
 },
 "K1_keys_derive_from_seed_rule": {
  "keys": {
   "agent": {
    "matches": true,
    "seed_b64url": "3anwyr1NxkoK1Q48UUSOPeXJIVEACwdd7Zjza9RWMXI",
    "x_derived": "s08tgBeilGl3TAZ94T3RwNKsACFVkcFMgJtjIJvDeaQ",
    "x_in_block": "s08tgBeilGl3TAZ94T3RwNKsACFVkcFMgJtjIJvDeaQ"
   },
   "attacker": {
    "matches": true,
    "seed_b64url": "ci_Pi1fYLaYZ_F70NcTgQbreYbvvZHBBeg4NvCHwI-0",
    "x_derived": "nSTCN36lL9LqVqNs0oheqNt0Z0WYUdarPXth1m5nwvg",
    "x_in_block": "nSTCN36lL9LqVqNs0oheqNt0Z0WYUdarPXth1m5nwvg"
   }
  },
  "result": true,
  "seed_rule_as_applied": "sha256(UTF-8('aeoess-presenter-key-possession/' + label)) as the 32-octet Ed25519 private key (RFC 8032 seed)",
  "seed_rule_as_stated": "Ed25519 private key = sha256('aeoess-presenter-key-possession/' + label), test keys only"
 },
 "K2_cnf_jkt_vs_derived_thumbprints": {
  "cases_without_cnf": [
   "PK-11"
  ],
  "distinct_cnf_jkt_values": [
   "cOcBgQLwawngecIAW38DspRnV75EbcX0JwpOppcXZ6Q"
  ],
  "jkt_to_key": {
   "cOcBgQLwawngecIAW38DspRnV75EbcX0JwpOppcXZ6Q": [
    "agent"
   ]
  },
  "result": true,
  "thumbprints": {
   "agent": "cOcBgQLwawngecIAW38DspRnV75EbcX0JwpOppcXZ6Q",
   "attacker": "kApwaulV5e2dstZEUjq7IumwhCwUtq9f6OguDXDfRCI"
  }
 },
 "K4_private_d_derives_from_a_stated_seed": {
  "cases_with_d": [
   {
    "case": "PK-07",
    "d_matches_seed_of": [
     "agent"
    ],
    "d_public_key_equals_jwk_x": true
   }
  ],
  "result": true
 }
}
K3 per case: {"PK-01": ["agent"], "PK-02": ["attacker"], "PK-03": ["attacker"], "PK-04": ["attacker"], "PK-05": ["agent"], "PK-06": ["agent"], "PK-07": ["agent"], "PK-08": ["agent"], "PK-09": ["agent"], "PK-10": ["agent"], "PK-11": ["agent"], "PK-12": ["agent"], "PK-13": ["agent"], "PK-14": ["agent"], "PK-15": ["agent"], "PK-16": ["agent"], "PK-17": ["agent"], "PK-18": ["agent"], "PK-19": ["agent"], "PK-20": ["agent"], "PK-21": ["agent"], "PK-22": ["attacker"], "PK-23": ["agent"], "PK-24": ["agent"], "PK-25": ["agent"], "PK-26": ["agent"], "PK-27": ["agent"], "PK-28": ["agent"]}
sens(final) R01_single_header removed -> []
sens(final) R02_well_formed_jwt removed -> []
sens(final) R03a_claims_jti_htm_htu_iat removed -> []
sens(final) R03b_claim_ath removed -> ['PK-26']
sens(final) R03c_claim_nonce removed -> []
sens(final) R04_typ removed -> ['PK-09']
sens(final) R05_alg removed -> []
sens(final) R06_signature removed -> ['PK-05', 'PK-06']
sens(final) R07_no_private_key removed -> ['PK-07']
sens(final) R08_htm removed -> ['PK-12']
sens(final) R09_htu removed -> ['PK-14']
sens(final) R10_nonce removed -> ['PK-15']
sens(final) R11_iat_not_too_old removed -> ['PK-16']
sens(final) R11f_iat_future removed -> ['PK-17']
sens(final) R12a_ath_matches removed -> ['PK-10']
sens(final) R12b_key_bound_matches removed -> ['PK-11', 'PK-02', 'PK-03']
sens(final) R13_jti_not_replayed removed -> ['PK-18']
sens(final) RS_scope_contains_required removed -> ['PK-20', 'PK-19']
[exit 0]

$ python3 -I -c "
import json;d=json.load(open(\"inputs/blind/cases.json\"));c={x[\"id\"]:x for x in d[\"cases\"]}
print(\"B14 segments:\", [len(s) for s in c[\"B14\"][\"input\"][\"dpop\"].split(\".\")])
print(\"B06 segments:\", [len(s) for s in c[\"B06\"][\"input\"][\"dpop\"].split(\".\")])
"; python3 -I -c "import cryptography,sys,platform;print(sys.version);print(\"cryptography\",cryptography.__version__);print(platform.platform())"
B14 segments: [156, 184, 0]
B06 segments: [158, 184]
3.13.18 (main, Oct 26 2026, 14:08:19) [Clang 23.1.3 ]
cryptography 50.0.1
Linux-6.18.44-fc-v553-x86_64-with-glibc2.39
[exit 0]

$ python3 -I reader/tables.py out > logs/tables.md; wc -l logs/tables.md
103 logs/tables.md
[exit 0]

$ python3 -I reader/tables.py out > logs/tables.md; grep -c "None" logs/tables.md; tail -25 logs/tables.md
0
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
[exit 0]

$ python3 -I -c "
import json;d=json.load(open(\"inputs/blind/cases.json\"));c={x[\"id\"]:x[\"input\"][\"dpop\"].split(\".\") for x in d[\"cases\"]}
print(\"B01/B23 signature segment equals B16 (PK-01) signature segment:\", c[\"B01\"][2]==c[\"B16\"][2], c[\"B23\"][2]==c[\"B16\"][2])
print(\"B01/B23 header equals B16 header:\", c[\"B01\"][0]==c[\"B16\"][0])
"
B01/B23 signature segment equals B16 (PK-01) signature segment: True True
B01/B23 header equals B16 header: True
[exit 0]

$ sha256sum reader/checker.py reader/phase2.py reader/compare.py reader/tables.py reader/explore.py; sha256sum out/phase1.json out/phase1-sensitivity.json out/final.json; date -u +%Y-%m-%dT%H:%M:%SZ
ab95f78651b6a4752b953aab12716eed37afbb450b4ab83add96709828b74578  reader/checker.py
a7b559e0bc52f462a4edf4b5cf234e848d58a4e919cce567ae74739b7296b63c  reader/phase2.py
c334946b80b2d756278d2cefb8da9123e077fb341847ce9c0adbaafdd3c8310a  reader/compare.py
c15adbd9b727308f77117f03a2d90ee7776a7a257cc2bf66c106e7f6bb2a8922  reader/tables.py
eafd642ff4a3a78fef12e0320d5e8d5a6acbf2b9618ac53eda9b4a08b9fdfa8e  reader/explore.py
2b0fe980cc2909e7fe21ae68644ac1ed4e3917796d561ec79543623cbc9b06ce  out/phase1.json
0b724bd5d90938a578ef3dd7b13eb4bc91b2841af5a487e51860dc2b9b7d412a  out/phase1-sensitivity.json
c91bd0ab359f7831bd041fbb54e4f89c180e7fc1a1a0ca836f91875e9097801f  out/final.json
2026-11-17T14:35:01Z
[exit 0]

````
