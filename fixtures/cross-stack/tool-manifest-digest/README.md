# tool-manifest-digest — AgentAvow signed tool-definition digests (external-system ingestion)

Signed **AgentAvow** scan attestations for the boundary on
[aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177)
(edge E1 in [#179](https://github.com/aeoess/agent-governance-vocabulary/pull/179)):
tool-safety evidence consumed by a pre-execution gate, bound by the digest of the tool
definition the scan graded. Proposed and inventoried on lab issue
[#155](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/155).

Each attestation is a compact JWS (RFC 7515, EdDSA/Ed25519) whose payload is the RFC 8785
canonical bytes of the verdict. A gate supplies what it holds about the call it is about to
authorize (subject, tool name, the digest it computed from the definition it was served, and
a pinned evaluation time) and reports each axis separately. `rely` is all axes.

- `v0/` — one digest for the whole server (`scan.toolManifestDigest`); five cases, five axes.
- `v1/` — one digest per served tool, keyed by tool name (`scan.toolDigests`); six cases, six
  axes; the per-tool digest preimage and the key encoding are under test.

## Reproduce (no network, no dependencies)

```console
$ node v0/verify.mjs
$ node v1/verify.mjs
```

Node 18+. Exit 0 iff every check passes. Verbatim output of the producer's own run is in
`results/01-v0-verify.txt` and `results/02-v1-verify.txt`. `node v0/generate.mjs` and
`node v1/generate.mjs` rebuild each vector file from its `source.json`, byte-identical to
the pinned files; v1 refuses to build if any served definition does not recompute to its
signed digest. In CI the family runs as `npm run cross-stack:tool-manifest-digest:verify`,
declared in `fixtures/cross-stack/index.json`.

## Claims and their standing

The v1 packet carries six claims, C1 to C6, inventoried on #155 and recorded per claim in
`SOURCE.md`. In short:

| claim | what it says | independent record |
|---|---|---|
| C1 | the 13 names encode to the stated `tool:` keys | candidate: `results/03-aeoess-probity-reader-run/` |
| C2 | the 3 served definitions recompute to their signed digests | same candidate |
| C3 | JCS of the payload equals the signed payload bytes | same candidate |
| C4 | the EdDSA signature verifies under the pinned, kid-matched JWK | same candidate |
| C5 | the six axes per case, `not_evaluated` included | same candidate |
| C6 | each negative fails exactly one axis | **none; pending** |

`results/03` is a run of Probity's reader (written by astrogilda) at `d759fb4`, made by
aeoess, who authored neither the vectors nor the reader; it is a candidate independent
record for C1 to C5. C6 has only author-produced records, because the pinned reader does
not assert the property, and stays pending on one of the three routes `SOURCE.md` lists.
v0 has only author-produced records and is recorded separately. Every other run on record
(the producer's `verify.mjs`, Probity's reader by its author, heldfast's profile by its
author, the APS-side consumer by its author) is author-produced.

## What the verifiers check

| check | claim |
|-------|-------|
| **signature_valid** | Ed25519 verifies under the JWK pinned in the file (kid-matched to the JWS header) |
| **canonical_bytes** | `jcs(JSON.parse(payload))` equals the payload bytes |
| **subject_binds** | the attestation's subject is the repo or server the gate names |
| **digest_binds** (v0) | the signed manifest digest equals the digest the gate observed |
| **tool_binds** / **tool_digest_binds** (v1) | the scan observed a tool of that name, and its signed digest equals the digest the gate computed from the definition it was served; `not_evaluated` when the tool is unknown |
| **fresh** | `evaluation_time` is inside `[issuedAt, expiresAt)` |
| **preimage** (v1) | all three signed per-tool digests recompute from the served `tools/list` under the stated derivation; thirteen name-to-key pairs exercise the key encoding |
| **one axis per negative** | every negative case fails exactly one axis, and the verifier asserts it (C6; asserted by `verify.mjs` only) |

## Layout

```
tool-manifest-digest/
├── v0/                      README, source.json, generate.mjs, verify.mjs, vector file, LICENSE
├── v1/                      README, source.json, generate.mjs, verify.mjs, vector file, LICENSE
├── results/
│   ├── 01-v0-verify.txt     verbatim producer run (author-produced)
│   ├── 02-v1-verify.txt     verbatim producer run (author-produced)
│   └── 03-aeoess-probity-reader-run/
│                            report.json (raw, unchanged), provenance.json, SHA256SUMS.txt
├── SOURCE.md                pins, claim inventory, per-claim verification split, the run
│                            record, claim ceiling, boundaries
├── NOTICE                   where the copied files come from and their terms
└── .gitattributes           vector files are -text so signed bytes survive checkout
```

A merge is not an APS or lab endorsement, and opening the family does not decide
admission; see this repo's CONTRIBUTING.
