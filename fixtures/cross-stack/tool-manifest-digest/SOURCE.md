# Provenance: tool-manifest-digest

External-system vector family: **AgentAvow tool-manifest-digest vectors, v0 and v1**,
ingested as signed, producer-owned fixtures. Nothing here reaches the network; every check
recomputes from the bytes in this directory with `node` alone. Proposed in lab issue
[#155](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/155) for
the boundary on
[aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177),
edge E1 in [#179](https://github.com/aeoess/agent-governance-vocabulary/pull/179). The
claim inventory and the per-claim standing below are the ones settled on #155.

## Pinned inputs

| input | pin |
|---|---|
| producer repository | `AgentAvow/AgentAvow` (formerly `agentgraph-co/agentgraph`; the old path redirects) |
| v0 directory | `docs/standards/tool-manifest-digest-vectors-v0/` at `4404df2c4176ca5390f1af5a2e63f069a503a01f` (2026-09-29); every file in `v0/` except `LICENSE` is that commit's byte for byte |
| v0 vector file | `tool-manifest-digest-v0-vectors.json`, SHA-256 `2f4632b03305471b3262109dce7db2cf71d029fe6d9ec85fe54e9bf5c82bb9df` |
| v1 directory | `docs/standards/tool-manifest-digest-vectors-v1/` at `36426cfd5152bba6a27766febfac8aaef47b6f34` (2026-10-01); every file in `v1/` except `LICENSE` is that commit's byte for byte |
| v1 vector file | `tool-manifest-digest-v1-vectors.json`, SHA-256 `488496079155830caf83593be0cafcb21367f72cd70ea363c2400f40eda72647` |
| `LICENSE` in `v0/` and `v1/` | Apache-2.0, added by the producer at `ca6b5551f71ce98aa47f43b7b15ad561bdcc2b7b` (2026-10-02), after both pins; the only file in either directory not taken from its pin. The producer's later README edits (consumer boundaries, a licence paragraph, the Probity CI note) are not copied |
| issuer | `did:web:agentgraph.co`; JWK pinned inside each vector file, kid-matched to the JWS header; `jwks_url` is informational and not on the verification path |
| v0 subject | `github:github/github-mcp-server`, attestation fetched once on 2026-09-29 |
| v1 subject | `mcp:https://mcp.deepwiki.com/mcp` (three tools), attestation and the server's `tools/list` fetched in the same minute on 2026-10-01 |
| digest profile (v1) | `agentavow.mcp-tool-definition.v1`: `sha256(JCS({profile, tool}))` over `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`; key `tool:<encoded name>` per the v1 README derivation |
| Probity reader | `probityai/agent-evidence-vectors`, `interop/agentavow-signed-map-v1/` (`map_reader.py`, `run_agentavow.py`), PR #43 head `c5622736366fcbb8a40d2ce6800bddcd1f1f7c2b`, merge `d759fb4db68a7fefcc91c2d3ad2a585471d6a53a`; `agent-evidence-vectors` 0.15.0 primitives |
| heldfast profile | `rufat325/heldfast`, `src/heldfast/profiles.py` at `ca5a872`, `tests/test_profile_agentavow.py` |
| APS-side consumer | `aeoess/agent-passport-system` `examples/interop/agentavow/` at `fd47f34` (v0); the v1 consumer code was not published as of 2026-10-02 |

## What a fixture is

Each vector file carries one real, pinned AgentAvow scan attestation: a compact JWS
(RFC 7515, EdDSA/Ed25519) whose payload is the RFC 8785 canonical bytes of the verdict
(issuer, subject, `issuedAt`, `expiresAt`, score, tier, findings and the tool digests).
A case supplies the gate's input and the expected value of every axis. `rely` is every axis
true. v1 additionally carries `observed_tools`, the served `tools/list`, so the digest
preimage is testable, and `key_encoding`, thirteen unsigned name-to-key pairs whose expected
keys were produced by the issuer's implementation.

| version | cases | axes | what each negative breaks |
|---|---|---|---|
| v0 | digest-match, digest-mismatch, past-expiry, wrong-subject, tampered-payload | signature_valid, canonical_bytes, subject_binds, digest_binds, fresh | one axis each |
| v1 | tool-match, unknown-tool, tool-drift, wrong-subject, past-expiry, tampered-payload | signature_valid, canonical_bytes, subject_binds, tool_binds, tool_digest_binds, fresh | one axis each; `tool_digest_binds` is `not_evaluated` when `tool_binds` is false |

`tampered-payload` raises the score after signing and re-canonicalizes, keeping the original
signature: canonical bytes still check, the signature does not. `tool-drift` adds one
sentence to a served description after the grade.

## Reproduce

`node v0/verify.mjs` and `node v1/verify.mjs`. Zero dependencies, Node 18+, nothing
fetched, exit non-zero on any failure. v0: 30 expected axis results plus six property
checks. v1: three per-tool digest recomputations and a tool-count check, thirteen key pairs,
42 expected axis results, seven property checks. `node v0/generate.mjs` and
`node v1/generate.mjs` rebuild each vector file from its `source.json`; both rebuilds are
byte-identical to the pinned files. Producer-run output is in `results/`
(`01-v0-verify.txt`, `02-v1-verify.txt`; Node v22.22.0, macOS arm64, 2026-10-05).

In CI the lab first runs `scripts/check-tool-manifest-digest-pins.mjs`, which checks both vector files against the SHA-256 pins above. The native verifiers do not check the `key_encoding` count and do not bind the unsigned `toolDigests` map to the signed payload, so the pin check protects the exact bytes admitted at this pin. It does not change the producer's verifiers. AgentAvow closed both gaps upstream at `cbd33844` (`v1/verify.mjs` now requires the thirteen pairs and binds the unsigned map to the signed one). That verifier is not part of this pin, and a later pin can pick it up.

## Claim inventory, v1 packet at `36426cf`

Inputs: the pinned attestation, the served `tools/list`, the thirteen name-to-key pairs.
Independence is recorded per claim, not once for the family. The table is the one settled
on #155; a `yes` says the implementation recomputes the claim, not that its run is
independent.

| # | Claim | Inputs checked | verify.mjs (ours, author) | Probity reader `d759fb4` | heldfast profile `ca5a872` | APS consumer (aeoess, author-produced) |
|---|---|---|---|---|---|---|
| C1 | Key encoding: each of the 13 names encodes to the stated `tool:` key | `key_encoding` | yes | yes | yes | yes |
| C2 | Per-tool digest derivation: each of the 3 served definitions recomputes to its signed digest | `observed_tools` vs `scan.toolDigests` | yes | yes | yes | yes |
| C3 | Canonical bytes: JCS of the decoded payload equals the signed payload bytes | JWS payload | yes | yes (payload digest) | no | yes |
| C4 | Signature: EdDSA verifies under the pinned JWK, kid-matched | JWS, JWK | yes | yes | no | yes |
| C5 | Case verdicts: the six axes per case for tool-match, unknown-tool, tool-drift, wrong-subject, past-expiry, tampered-payload, including `not_evaluated` for unknown-tool's digest axis | gate input per case | yes | yes | no | yes |
| C6 | Each negative fails exactly one axis | derived from C5 | yes | not as a separate assertion, I believe; @astrogilda can confirm | no | yes |

On C3 and C4 the maintainer's reading of the reader (#155): it verifies the Ed25519 JWS
under the selected, kid-matched key and compares the signature axis with each case's
expectation, and it compares the canonical bytes directly with the signed payload bytes.
C4 stays its own row even though the same run covers it. On C6 the maintainer confirmed
that the reader at `d759fb4` does not assert the property.

### Standing per claim

| claim | author-produced records | independent record |
|---|---|---|
| C1 | verify.mjs; Probity reader by astrogilda; heldfast by rufat325; APS consumer by aeoess | candidate: aeoess's run of the Probity reader, `results/03-aeoess-probity-reader-run/` |
| C2 | same four | same candidate |
| C3 | verify.mjs; Probity reader by astrogilda; APS consumer by aeoess | same candidate |
| C4 | same three | same candidate |
| C5 | same three | same candidate |
| C6 | verify.mjs; APS consumer by aeoess | candidate: aeoess's Mode A run of the unchanged native verifier, `results/04-aeoess-native-mode-a-run/` |
| v0 (all layers) | verify.mjs; APS consumer by aeoess | candidate: aeoess's Mode A run of the unchanged native verifier, `results/04-aeoess-native-mode-a-run/` |

"Candidate" is the maintainer's word on #155: a candidate record for the covered claims,
not a family admission. Whether it is accepted as the independent record for C1 to C5 is
decided on the PR, not by this file.

## Verification split

One entry per run per claim: `layer / claim; runner; Mode A | Mode B; author-produced |
independent; implementation`, each author-produced entry stating the authorship
relationship that keeps it from being independent.

### C1, key encoding

- C1 / the thirteen name-to-key pairs reproduce under the percent-encoding and length rules; kenneives; Mode A; author-produced; `v1/verify.mjs` over `node:crypto`. kenneives authored the vectors, the expected keys (produced by the issuer's own implementation) and the verifier.
- C1; astrogilda; Mode B; author-produced; Probity reader `map_reader.py` at `c5622736` (PR #43), `agent-evidence-vectors` 0.15.0 primitives, `recorded-run.json` in that PR; all thirteen pairs match. astrogilda authored the reader that supplies the recomputation.
- C1; rufat325; Mode B; author-produced; heldfast profile at `ca5a872`, `tests/test_profile_agentavow.py` against a local copy of the v1 vector file byte-identical to `36426cf`; thirteen pairs match by the author's statement in [`docs/TRANSPARENCY.md` at `321d44a`](https://github.com/rufat325/heldfast/blob/321d44aa8792ea48e23355a538c558d6be9130f4/docs/TRANSPARENCY.md#comparing-with-another-record). rufat325 authored the profile. The test is gated on `AGENTAVOW_VECTORS_DIR`, CI never runs it, and no verbatim output is published: an author's statement, not a published run. Verbatim: "heldfast reproduces the published digests and key encoding for the pinned fixture as of 2 October 2026. It makes no claim about AgentAvow's grades."
- C1; aeoess; Mode B; author-produced; APS-side consumer over the v1 packet at `36426cf`, 60 checks, all thirteen pairs including both cuts inside a `%XX` triplet ([comment](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-5944466430)). aeoess authored the consumer and the `agent-passport-system` 7.2.0 primitives it uses; the v1 consumer code was unpublished as of 2026-10-02, so this is the runner's report.
- C1; aeoess (Codex executing under aeoess's mandate, on aeoess's machine, 2026-10-05); Mode B; independent; Probity reader at `d759fb4` over the v1 packet at `36426cf`, `key_pair_matches` 13 of 13 in `results/03-aeoess-probity-reader-run/report.json`. aeoess authored neither the vectors nor the reader, and no semantic harness was written for the run. Recorded as the candidate independent record for C1; provenance notes below.

### C2, per-tool digest derivation

- C2 / the three signed `scan.toolDigests` recompute from `observed_tools` under the stated preimage, and the served count equals the signed count; kenneives; Mode A; author-produced; `v1/verify.mjs`. kenneives authored the vectors and the verifier.
- C2; astrogilda; Mode B; author-produced; Probity reader at `c5622736`; three served-definition digests match. astrogilda authored the reader.
- C2; rufat325; Mode B; author-produced; heldfast profile at `ca5a872`, its own implementation of `agentavow.mcp-tool-definition.v1` with no AgentAvow file copied; three digests match by the author's statement, same limits as under C1. rufat325 authored the profile.
- C2; aeoess; Mode B; author-produced; APS-side consumer, three tool digests match; same relationship as under C1.
- C2; aeoess (Codex under aeoess's mandate); Mode B; independent; Probity reader at `d759fb4`, `definition_matches` 3 of 3 in `results/03-…/report.json`. Candidate independent record for C2.

### C3, canonical bytes

- C3 / `jcs(payload)` equals the signed payload bytes; kenneives; Mode A; author-produced; `v1/verify.mjs`. kenneives authored the vectors and the verifier.
- C3; astrogilda; Mode B; author-produced; Probity reader at `c5622736`; the canonical bytes are compared with the signed payload bytes and the payload digest is recorded. astrogilda authored the reader.
- C3; aeoess; Mode B; author-produced; APS-side consumer. Same relationship as under C1.
- C3; aeoess (Codex under aeoess's mandate); Mode B; independent; Probity reader at `d759fb4`, `payload_digest_matches: true`, `payload_sha256` `5e159675e62845bd5411932a1f970ed08bb0ea768043cb898a8c2656bfd000fa`, and `canonical_bytes: true` on all six cases in `results/03-…/report.json`. Candidate independent record for C3.
- heldfast does not check this claim.

### C4, signature

- C4 / the Ed25519 signature verifies under the pinned JWK, kid-matched to the JWS header; kenneives; Mode A; author-produced; `v1/verify.mjs` over `node:crypto`. kenneives authored the vectors and the verifier.
- C4; astrogilda; Mode B; author-produced; Probity reader at `c5622736`; it verifies the Ed25519 JWS under the key it selects on its own side (`selection.json`), kid-matched, and compares the signature axis with each case's expectation. astrogilda authored the reader.
- C4; aeoess; Mode B; author-produced; APS-side consumer. Same relationship as under C1.
- C4; aeoess (Codex under aeoess's mandate); Mode B; independent; Probity reader at `d759fb4`, `signature_valid` true on five cases and false on `tampered-payload`, each equal to its expectation, in `results/03-…/report.json`. Candidate independent record for C4. The key came from the reader's own selection, which the run's provenance records as "key authority supplied by consumer selection".
- heldfast does not check this claim.

### C5, case verdicts

- C5 / the six axes for each of the six cases, including `tool_digest_binds = not_evaluated` for `unknown-tool`; kenneives; Mode A; author-produced; `v1/verify.mjs`. kenneives authored the vectors and the verifier.
- C5; astrogilda; Mode B; author-produced; Probity reader at `c5622736`; six case verdicts match, `rely` included. astrogilda authored the reader. The reader adds an `issuer_binds` axis of its own; that axis is not a claim of this family.
- C5; aeoess; Mode B; author-produced; APS-side consumer, six cases match. Same relationship as under C1.
- C5; aeoess (Codex under aeoess's mandate); Mode B; independent; Probity reader at `d759fb4`, `results[*].matches` true for all six cases in `results/03-…/report.json`, with `unknown-tool` reporting `tool_digest_binds: "not_evaluated"`. Candidate independent record for C5.
- heldfast does not check this claim.

### C6, each negative fails exactly one axis

- C6 / every negative case fails exactly one axis; kenneives; Mode A; author-produced; `v1/verify.mjs` (the "every negative fails exactly one axis" property check). kenneives authored the vectors and the verifier.
- C6; aeoess; Mode B; author-produced; APS-side consumer, each negative failing exactly its own axis. aeoess authored the consumer.
- The Probity reader at `d759fb4` does not assert the property; deriving it from the reader's per-axis output in a runner-written step would make the runner's code decide the claimed result, so the run in `results/03` is not a record for C6 and is not labeled as one. heldfast does not check it.

- C6; aeoess (Codex executing under aeoess's mandate, on aeoess's machine, 2026-10-07); Mode A; independent; unchanged `v1/verify.mjs`, "every negative fails exactly one axis" ok in `results/04-aeoess-native-mode-a-run/v1-verify.txt`, exit 0. aeoess authored neither the vectors nor the verifier, and no runner-written code decides the result. It is an independently operated run of the producer's verifier, not an independent implementation. Candidate independent record for C6.

C6 is independently recomputable, so it lands only with an independent record, and the Mode A run above is that record. An independent implementation record (the reader asserting the property, or a new pinned Probity run) would be appended, not substituted.

Whichever implementation recomputes it, the count excludes the aggregate `rely` result and
keeps `not_evaluated` distinct from a failure. `verify.mjs` already counts that way: its
check drops the `rely` entry and counts only axes equal to `false`, so `not_evaluated` is
not a failure, and it finds one failing axis on each of the five v1 negatives (four in v0).

### v0, manifest-digest binding at `4404df2c`

v0 is one claim family (whole-server binding by `scan.toolManifestDigest`; five cases, five
axes, 30 axis results) and is recorded separately from the v1 inventory, as stated on #155.
Its layers are the v0 counterparts of C3, C4, C5 and C6 plus the `digest_binds` axis; the
runs on record are:

- v0 signature and canonical bytes / the Ed25519 signature verifies under the pinned key and `jcs(payload)` equals the payload bytes; kenneives; Mode A; author-produced; `v0/verify.mjs` over `node:crypto`. kenneives authored the vectors and the verifier.
- v0 gate verdicts / `subject_binds`, `digest_binds`, `fresh` and `rely` for the five cases, each negative failing exactly one axis; kenneives; Mode A; author-produced; `v0/verify.mjs`. Same relationship.
- v0, both layers; aeoess; Mode B; author-produced; APS-side consumer at `agent-passport-system@fd47f34` `examples/interop/agentavow/`, reading the v0 vector file at `4404df2c` unchanged, 30 of 30 expected axis results, each negative failing exactly its own axis ([comment](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-5914989949)). aeoess authored the consumer and the 7.2.0 primitives it uses. The runner's own label: a second implementation, run by the consuming project; a reproduction, not an independent verification record.
- v0, both layers; aeoess (Codex executing under aeoess's mandate, on aeoess's machine, 2026-10-07); Mode A; independent; unchanged `v0/verify.mjs`, 30 axis results and six property checks ok in `results/04-aeoess-native-mode-a-run/v0-verify.txt`, exit 0. aeoess authored neither the vectors nor the verifier, and no runner-written code decides the result. It is an independently operated run of the producer's verifier, not an independent implementation. Candidate independent record for v0. Neither the Probity reader nor the heldfast profile reads v0, so no independent implementation record exists for it.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## The run in `results/03-aeoess-probity-reader-run/`

Published by aeoess on #155
([comment 6000216036](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/155#issuecomment-6000216036),
2026-10-05) as the raw report and a run-provenance record. Both files are the fenced JSON
blocks of that comment, taken verbatim, each with one trailing LF.

| field | value |
|---|---|
| who ran it | Tymofii Pidlisnyi (@aeoess); executed by Codex under his mandate on his machine, macOS 26.5 (25F71) arm64 |
| date | 2026-10-05 |
| mode | Mode B for the AgentAvow-origin claims recomputed by the Probity reader |
| implementation | Probity reader at `d759fb4db68a7fefcc91c2d3ad2a585471d6a53a`, `interop/agentavow-signed-map-v1/` (`run_agentavow.py`, `map_reader.py`), with the reader's own 76-test suite passing first |
| inputs | the v1 packet fetched by the reader's `fetch_fixture.py` at `36426cf`, SHA-256 `48849607…` checked by the reader |
| interpreter | Python 3.12.13; the reader's README asks for 3.13, so this is a different runtime from the one the reader states. For comparison only: the producer's own CI runs the same reader at `d759fb4` on 3.13; that run is producer-operated and counts for nothing here |
| report | `report.json`, SHA-256 `3cf419993ca3cc6de48c9d185abb981d6c02b0742d4dace72b0c90187d03f619`, which equals the hash the runner reported. Computed here over the comment's fenced block plus one trailing LF; without the LF the digest differs, so the trailing LF is part of the report bytes |
| provenance | `provenance.json`, SHA-256 `a5eace45d1229ab9a5a2cb98f0f40a105ac4cda137cb75a916d357750ede9ace` (this family's own digest of the block as published; the runner reported no hash for it) |
| operator strings | `report.json` says `Probity-operated reproduction` and `same Probity operator` because the reader writes that text itself; the strings do not describe this execution. `provenance.json` identifies the actual runner. The raw output is kept unchanged, as the runner asked |
| result | 13 of 13 key pairs, 3 of 3 definition digests, payload digest match, 6 of 6 case verdicts, `passed: true`; 76 reader tests passed |
| commands | in `provenance.json`, path-normalized transcriptions of the ones that ran (`$ROOT` stands for the reproduction directory) |
| limits the runner states | not a family admission or public record; no AgentAvow native verifier executed; no full audit of the reader's shared `run_vectors.py` (its JCS helpers inspected, pinned hash checked by the published runner); no runtime effects, production signing trust or operator adoption established; no heldfast run; clean git status before and after |

The reader's `issuer_binds` axis appears in the report; it is the reader's own and is not
a claim of this family.

## The run in `results/04-aeoess-native-mode-a-run/`

A Mode A run of the unchanged native verifiers `v0/verify.mjs` and `v1/verify.mjs` over the pinned vector files, operated by aeoess and executed by Codex under his mandate on his machine (macOS arm64, node v24.11.1), 2026-10-07. Both runs exit 0 with empty stderr. `v0-verify.txt` and `v1-verify.txt` are the verbatim stdout, `provenance.json` states the runner, inputs, label basis and limits, and `SHA256SUMS.txt` covers the other four files. Same machine and maintainer as the run in `results/03`. It covers v0 and the native C6 assertion and claims nothing about the verifiers' coverage beyond what they print.

## Claim ceiling

`rely=true` establishes exactly this: at `evaluation_time`, the named issuer had signed a
static-analysis grade for this server, the grade covered a tool of this name, the
definition the gate was served for that tool is the one the scan graded, and signature,
subject and window all check. It establishes nothing about runtime behavior, nothing about
what the tool does when invoked, nothing about other tools on the server, and nothing
about definitions the scan did not observe.

For v0 the same ceiling applies with "this subject over this tool-definition digest" in
place of the tool clause; a behavioral axis is a separate artifact with its own ceiling.

## Boundaries

- The subject is a repo or server, not a tool. In v0 the attestation carries no tool name,
  so a gate authorizing one tool has nothing to bind to and reports that binding as
  `not_evaluated`. v1 adds the binding as the separate `tool_binds` axis.
- `scan.toolManifestDigest` is a fold over the per-tool digests, not a per-tool metadata pin.
  It has a different preimage from an APS `capabilityMetadataDigest`, and neither is evidence
  for the other (`false_analog`). The v1 gate does not use it.
- Whether a gate proceeds on `rely=true` is a separately versioned admission policy, not
  part of this family.
- The `tool:` key's length rule truncates to 96 characters plus a 64-bit hash suffix; no
  injectivity is claimed for truncated keys.
- Ingestion only. Axis names, case names and the digest profile label are AgentAvow's
  vocabulary, presented as an external system's; this is not a proposal to add names to
  this suite's taxonomy. The family touches no suite verifier or schema; it adds the
  registry entry in `fixtures/cross-stack/index.json`, one `package.json` script (which runs the lab pin check `scripts/check-tool-manifest-digest-pins.mjs` first), and the
  generated README inventory row, as family registration requires.
- Per CONTRIBUTING, a merge means the fixtures verified as deterministic, in scope and
  correctly labeled, not an endorsement, adoption or partnership by APS or the lab.

## Licence

`v0/` and `v1/` are Apache-2.0 under the `LICENSE` file in each, as the producer published
them at `ca6b5551`; `NOTICE` records the copy. The rest of this directory is contributed
under the repository's Apache-2.0 terms. The signed attestations inside the vector files
were issued by AgentAvow and are published for verification; the private signing key is
not part of this contribution.
