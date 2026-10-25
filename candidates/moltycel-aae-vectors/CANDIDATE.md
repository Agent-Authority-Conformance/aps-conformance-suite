# Candidate: moltycel-aae-vectors

Conformance vectors for the Agent Authorization Envelope (AAE), an Internet-Draft for
delegated authority of autonomous agents. The vectors are in AAE's own format and terms. This
is a candidate under `docs/CANDIDATES.md`. It is not a reviewed fixture and adds nothing to the
lab's schema, failure classes or verifier behavior.

## Submitter

Lars Kroehl, MoltyCel, for CryptoKRI GmbH, Zurich (MolTrust). Contact: lars@moltrust.ch.

## Normative target

Each vector set was built against one published revision. Each vector names that revision in
its own `section_ref`.

| set | path here | vectors | target |
|---|---|---|---|
| native | `vectors/` | 15 | [draft-kroehl-agentic-trust-aae-00](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/00/) |
| composition | `interop/psea/vectors/` | 6 | [draft-kroehl-agentic-trust-aae-00](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/00/) with [draft-yossif-psea-02](https://datatracker.ietf.org/doc/draft-yossif-psea/02/) |
| enforce | `vectors/enforce/` | 26 | [draft-kroehl-agentic-trust-aae-02](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/02/), enforce kernel 3.0 |

Revision -01 changed no field, no verification step and no normative requirement.

## Source

- Repository: https://github.com/MoltyCel/aae-conformance-vectors
- Commit: `6bb462f578c12d339b8fa964a5b1d8f97dbffa68` (vector set version 1.4.0 plus the
  unreleased verifier changes listed in its README; no vector or expected result changed
  after 1.4.0)
- Every file here is a byte copy of the same path at that commit. `CHECKSUMS.sha256` lists all
  64 of them, and `run.sh` compares each one with a fresh clone before it runs anything.

Not copied: the generators (`tools/`), the reference verifiers (`examples/`), the verifier unit
tests (`tests/`) and the test key files (`testkeys/*.json`). The test key files hold the private
Ed25519 components and are published in the source repository at the pin. This directory holds
no private key material. The public DID documents the verifiers resolve against are copied under
`testkeys/did-documents/`.

## License

Apache License 2.0, the license of the source repository. `interop/psea/psea-fixture-v0.json`
is third-party material under the MIT License from
[yuthent/psea-spec](https://github.com/yuthent/psea-spec) at commit
`08e16444c139eb5aa0095686e51af336bf21f16a`. `NOTICE` carries its copyright and permission
notice.

## What the vectors test

**Native, 15.** One AAE as a compact EdDSA JWS plus a context object, expected `ACCEPT` or
`REJECT` at a numbered step of the nine-step verification algorithm in §5. Delegation:
`06`–`10` and `15` (valid chain of depth 2, action superset, relaxed numeric constraint, depth
over `max_depth`, cycle, currency mismatch). Revocation: `04` (revocation endpoint answers
HTTP 503) and `11` (an ancestor of a valid child is revoked). The rest cover validity window,
replay, signing authority, unknown required constraint and the `cty` header. Each vector also
states `verification_mode`: `structural` when the documents decide the result, `runtime` when
it needs a clock, a revocation answer or consumed-id state, which the context object supplies.

**Composition, 6.** One AAE paired with one PSEA proof over the same action. The expected
result is eight staged rows (`aae_native`, `action_linkage`, `principal_linkage`,
`evidence_satisfaction`, `freshness`, `decision`, `admission`, `outcome`), not one verdict.
`interop/psea/negative-controls.json` holds 11 mutated inputs with their expected rows.

**Enforce, 26.** A mandate plus a transaction, or a record plus an authority proof. Expected
`PERMIT`, `DENY` or `PENDING`, or `RATIFIED` / `REJECTED`, together with the core digest a
conforming implementation must recompute from the input alone. Coverage: type form and
`action_binding` (10), the closed constraint language (8), the verdict vocabulary (3),
ratification and its guards (5).

The formats are defined in `schema/`, one closed schema per set.

## How to run

```
pip install cryptography jsonschema jcs pytest
sh run.sh
```

`run.sh` clones the source at the pinned commit, checks every file here against it byte for
byte, and then runs each step through `offline.py`, which refuses every socket and name lookup.
The steps: three schema validations, three reference verifiers (15/15, 26/26, 6/6 row by row),
the 11 negative controls, the verifier unit tests, the PSEA fixture pin, and all three
generators, after which the clone must be unchanged. The clone is the only network access.
Lab CI does not execute any of this.

## Requirements of CONTRIBUTING.md, one by one

A candidate needs only the DCO sign-off and the license terms. The vector requirements below
apply to the reviewed corpus.

1. **Deterministic.** The generators use no clock, no randomness and no network. They sign
   with committed test keys, and Ed25519 signing is deterministic (RFC 8032). The keys were
   generated once at random by `tools/genkeys.py` and committed. No seed is recorded. The last
   step of `run.sh` regenerates every vector and fails on any byte difference.
2. **Canonical bytes under RFC 8785.** Every digest in the set is computed over JCS. The JWS
   payloads are not in JCS form.
   - Enforce: every core, mandate, transaction and action digest is SHA-256 over a domain tag
     plus the JCS form of the object. `examples/enforce-verify.py` imports `jcs` without a
     fallback and checks that a key-reordered input gives the same digest.
   - Composition: the action digest that joins both profiles is SHA-256 over the JCS form of
     the action payload. The generator refuses to run if its own JCS output differs from the
     form recorded in the PSEA fixture.
   - JWS: the payload of each AAE is compact JSON in the generator's key order, not JCS.
     Across the 25 distinct native JWS all headers are JCS and no payload is; the 16
     composition JWS have 10 of 16 headers and none of 16 payloads in JCS form. The signature
     covers the published bytes as RFC 7515 defines them. A verifier that re-serializes the
     decoded payload under JCS before checking would get a different signing input.
3. **Recomputable from the bytes up, without network.** DID resolution is offline against
   `testkeys/did-documents/`. Every runtime fact the documents cannot carry (current time,
   revocation answers by AAE id, consumed ids, the ancestor chain) is in the vector's
   `input.context`. `run.sh` runs every verification step with network access refused. Only
   one verifier per set exists here, and it is ours (see Evidence).
4. **No new fields, failure classes or verifier semantics.** This pull request changes only
   this directory and its row in the `docs/CANDIDATES.md` index. The vectors use AAE's own
   schemas and reason codes inside this directory. They are not expressed in the lab's
   schema, and nothing here proposes a lab name.
5. **Generation included.** The three generators are at the pinned commit
   (`tools/build_vectors.py`, `tools/build_enforce_vectors.py`, `tools/build_interop_psea.py`),
   and `run.sh` runs them and compares the result. They are linked, not copied. They read the
   test keys, which are published in the source repository at the pin.
6. **One concern.** One candidate directory and one index row.

## Revocation reasons and the lab's vocabulary

AAE reports a revocation status that cannot be determined as its own rejection reason,
`revocation_status_indeterminate` at step 8, apart from `revoked` at step 8 and
`ancestor_revoked` at step 9. The AAE result itself has two values, `ACCEPT` and `REJECT`; the
distinction lives in the reason and the step. The lab's terms at main
`7141c6167acfdd5288ec7cc1ca8d2ba9207b3390` compare as follows.

| AAE (vector) | lab value | where in the lab |
|---|---|---|
| `REJECT`, step 8, `revocation_status_indeterminate` (`04`, endpoint answers 503) | state `indeterminate`, failure code `REVOCATION_UNKNOWN` | `fixtures/revocation-resolution-forward-compat`, case `C19-13-resolver-throws` |
| same | authority axis: `current_validity` `not_established` | `fixtures/lease-revocation-axes` revision 2, source outage (`LRA-03`, `LRA-07`) |
| same | no value: the action decision is `permit` or `deny` only | `fixtures/lease-revocation-axes` revision 2, action record |
| `REJECT`, step 9, `ancestor_revoked` (`11`) | state `invalid`, failure code `REVOKED` | `fixtures/revocation-resolution-forward-compat`, case `C19-02-revoked-control` |

The first and last rows are mappings onto existing values. For the action record of
lease-revocation-axes no value exists in revision 2. A refusal reason for that record was
proposed for revision 3 on public-agentprotocol on 24 October 2026
([message](https://lists.w3.org/Archives/Public/public-agentprotocol/2026Oct/0029.html)).
This candidate waits for revision 3 and does not introduce a class of its own.

The lab's `interop/aae-envelope` holds four chain-envelope vectors that APS wrote in AAE's
shape and decides with the APS verifier through an adapter. That record is the lab's own and
covers its own vectors. It is not evidence for this candidate.

## Evidence

| run | candidate revision | claims | mode | authorship | link |
|---|---|---|---|---|---|
| Lars Kroehl, 2026-10-25, `run.sh` | source `6bb462f` | all 47 vectors, 11 negative controls, schema validation, byte-identical regeneration, offline | Mode A | author-produced: the runner wrote the vectors, the generators and the verifiers | output in the pull request body |
| MolTrust, 2026-09-05, enforce set against a second implementation | enforce set 1.4.0 (same vector bytes) | the 26 enforce verdicts and core digests | Mode B | author-produced: the same author wrote both implementations | [vectors/enforce/RESULTS.md at the pin](https://github.com/MoltyCel/aae-conformance-vectors/blob/6bb462f578c12d339b8fa964a5b1d8f97dbffa68/vectors/enforce/RESULTS.md) |

No independent run exists yet.

The six composition vectors carry `"status": "confirmed"` in the source. That status records
the PSEA author's confirmation of the two join tables, as stated in each vector's
`join_who.status`. It is not a run of these vectors and is not listed as evidence.

## Known limitations

- Only author-produced runs, and one reference verifier per set. Both enforce implementations
  come from the same author.
- The JWS payloads are not in JCS form (requirement 2).
- The test keys are committed, not derived from a recorded seed (requirement 1).
- Native vectors state where a verifier must stop, not a full trace. Two verifiers that stop at
  the same step for different reasons are told apart only by `rejection_reason`.
- `04` covers one failure of the revocation lookup, HTTP 503. Timeouts, malformed answers and
  unknown status values are not vectored. An undeterminable revocation status for an ancestor
  in a chain is not vectored either.
- The composition rows depend on a principal table that is supplied, not derived (see the
  source's `interop/psea/README.md`). The set makes no claim about PSEA conformance.
- The enforce digests depend on the domain tags and kernel version each vector names. A
  kernel on other tags computes other digests over the same input.

## Record

- Publication: published, from the merge of this pull request.
- Evidence: the entries above.
- Disputes: none.
