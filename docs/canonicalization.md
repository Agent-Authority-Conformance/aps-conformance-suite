# Canonicalization rules

This document is the canonical-byte contract for the `canonical-bytes` fixture
family. It is not a statement about the corpus as a whole. Most families in this
repository are not canonicalization vectors: they carry receipts, delegations,
scenario descriptions or ingested external artifacts, and each family's own
document says what it pins.

## The contract

`canonical-bytes` vectors pin RFC 8785 JSON Canonicalization Scheme output. Each
vector carries an `input`, the canonical form as `canonical_bytes_hex`, and the
SHA-256 of those bytes as `canonical_sha256`.

An implementation reading a vector's `input` and producing canonical bytes whose
UTF-8 hex differs from `canonical_bytes_hex` diverges from the vector. Where a
vector also carries `ed25519_signature_over_canonical_hex` and
`ed25519_pubkey_hex`, a verification that returns false against the canonical
bytes diverges from the vector.

Divergence is a recorded observation, not a verdict. The corpus can be the party
that is wrong, and `docs/DISPUTES.md` is where that is argued.

## RFC 8785, as these vectors pin it

1. `null` is `null`. There is no `undefined` value in JSON or RFC 8785. This
   family contains no `undefined` input and makes no claim about how an API
   handles values outside JSON.
2. Booleans are `true` or `false`.
3. Numbers use ECMAScript `Number::toString`, the shortest decimal that round
   trips. `Infinity` and `NaN` are rejected. Serialization follows the binary64
   value, not the caller's spelling, so an integer above 2^53 emits the double it
   parsed to. `2.0` and `2` are the same binary64 value and both emit `2`.
4. Strings are serialized with the JSON string escaping rules.
5. Arrays preserve order and are never sorted.
6. Object member names are sorted by their **UTF-16 code units**, per RFC 8785
   section 3.2.3. This is not code-point order: an astral character sorts by its
   lead surrogate, so a key at U+1D306 (lead unit 0xD834) sorts before a key at
   U+FF61. The `astral-key-ordering` vector pins exactly that case.
7. Member names are emitted as given and are never Unicode-normalized. An NFD key
   stays NFD and is a different key from its NFC form. The
   `nfd-key-used-as-given` vector pins that.
8. `null` object values are preserved, not stripped.

Keys are not restricted to ASCII. An earlier version of this document said they
must be, which contradicted the vectors in this family: two of them carry
non-ASCII keys on purpose, because non-ASCII key ordering and non-ASCII output
are where implementations most often diverge.

## Cross-implementation runs

`fixtures/canonical-bytes/crossrun/` holds runners in four languages that report
where a canonicalizer's bytes and SHA-256 agree or differ from these vectors, and
`fixtures/canonical-bytes/README.md` documents how to add another. A result there
is a byte diff on the pinned cases, not a verdict on the implementation.

## Path canonicalization, instruction-provenance only

The `instruction-provenance` family adds path canonicalization on top of JCS.
This rule belongs to that family and to no other. The instruction-provenance
vectors pin the following expectations from InstructionProvenanceReceipt v0.2
section 5.1:

1. Reject an empty path.
2. Reject percent-encoded paths.
3. Resolve to absolute, relative to the declared `working_root`.
4. Reject a path outside `working_root`.
5. Strip a leading `./` and a trailing `/`.
6. Reject any `..` segment.
7. Normalize Unicode to NFC.
8. Apply the case mode, lowercasing when `filesystem_mode` is `case-insensitive`.
9. Replace operating-system separators with a forward slash.

Symlinks are preserved as separate entries carrying `is_symlink: true` and are
not dereferenced.
