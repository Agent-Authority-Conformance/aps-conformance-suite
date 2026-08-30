# Fixture format

This repository holds four classes of artifact. They have different formats,
different admission rules and different meanings, and reading one as another is
the most common way to misread the corpus. An earlier version of this document
described a single JSON shape and listed four categories, at a time when the
corpus had four; it now has more, and most of them are not that shape.

## The four classes

### 1. APS-native vector files

Declared in `fixtures/manifest.json`, one entry per file, each with a category, a
path, a `canonical_sha256` over the file bytes and a `vector_count`. These are
the vectors this repository authors and maintains against Agent Passport System.
`runners/ts/manifest-integrity.test.ts` holds the manifest to the files, and
`npm run verify` is the generic runner over them.

The common shape:

```jsonc
{
  "version": "v1",
  "spec":     "RFC 8785 JSON Canonicalization Scheme",
  "spec_ref": "https://www.rfc-editor.org/rfc/rfc8785",
  "seed_input":      "aps-canonicalize-fixture-v1",
  "seed_sha256_hex": "<64 hex>",
  "keypair":         { "publicKeyHex": "<64 hex>" },
  "generated_at":    "2026-04-26",
  "vectors":         [ { "name": "...", "description": "...", "input": {} } ]
}
```

A vector carries at minimum `name`, `description` and `input`. A vector that
pins bytes adds `canonical_bytes_hex` and `canonical_sha256`. A vector that pins
a signature adds `ed25519_signature_over_canonical_hex` and
`ed25519_pubkey_hex`. Not every family carries all of these: a scenario family
carries none of them, and that is not a defect in the file.

### 2. Families with a dedicated verifier

Some families are not checked by the generic runner because their claim is not
a canonical-byte comparison. They ship their own verifier, documented with the
family and wired into `npm test` under its own script. `read-fidelity-receipt`,
`accountability-record` and `receipt-decision-relation` are of this class. The
family's own README or `SOURCE.md` states what the verifier decides and what it
deliberately does not.

### 3. External-system families

Under `fixtures/cross-stack/`. These are families ingested from an external
system or source. The family document separately records provenance and the
authorship relationships relevant to each verification claim. They are not
APS-native vectors and are not counted in `fixtures/manifest.json`.

Every such family carries a `SOURCE.md` with its provenance, the pins it was
ingested at, and a **Verification split**: one entry per distinct verification
claim, each carrying Mode A or Mode B and author-produced or independent, per
`CONTRIBUTING.md`. Merging one of these is an admission of evidence, not a
verdict on the counterparty's implementation.

### 4. Lab-authored regression fixtures

Deterministic fixtures this repository generates for its own regression
purposes, with a published generator and seed. They are not ingestions from an
external system and are not governed by the family admission rule.
`fixtures/cross-stack/synthetic/` is of this class, and its `SOURCE.md` says so;
its location under `cross-stack/` is historical and the path is kept to avoid
breaking existing references.

Class 3 and class 4 are told apart by `fixtures/cross-stack/index.json`, which is
a reviewed declaration, not an inference from where a directory sits.

## What is not a fixture

`interop/` holds run records: observations of some implementation at an exact
revision, with a runner, a mode and an authorship label. A run record is
evidence about a run, not a vector, and it is never counted as one.
`cross-impl-receipts/` holds mirrored receipts from another implementation,
pinned per upstream revision.

## Deterministic keypairs

An APS-native family that uses this repository's deterministic test-key
convention derives its Ed25519 keypair from the SHA-256 of its `seed_input`:

```
seed        = SHA-256(seed_input)   // 32 bytes
private key = seed                  // RFC 8032 Ed25519 seed
public key  = Ed25519 public derivation of seed
```

An implementation under test reproduces the keypair from `seed_input`, which is
what makes signature verification deterministic across languages. No secret
material is in the fixture: the public key is published and the private key is
reproducible from the published seed, which is exactly why these keys are for
test vectors and nothing else.
