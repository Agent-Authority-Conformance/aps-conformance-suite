# HJS-Core-1 behavior-record digest path and the pinned JCS byte contract, both directions

Cross-run agreed by email between Yuqiang Wang (HJS Foundation, author of
draft-wang-hjs-accountability) and aeoess (maintainer of this corpus), 2026-08-28 to
2026-08-29. Each side pinned its inputs and implementation, ran the other side's vectors
through its own RFC 8785 path, and recorded per-case bytes and digests. This family is a
set of attributed run records. It confers no conformance verdict on HJS, on
agent-passport-system, or on this corpus, and asserts nothing beyond the pinned cases.

## Counterparty artifacts, pinned, held by reference

Repository hjs-spec/hjs-05 at commit bb6be62fd28911c02ff31f61db8c023757ef2243
(2026-08-29). Nothing from that repository is copied into this corpus: no license file
was found at the pinned commit (conventional root location checked), so the files are linked and hashed, and the runners
here fetch them at the pin and refuse to run if the bytes do not match.

| file | sha256 at bb6be62 |
|---|---|
| fixtures/canonical-bytes/hjs-behavior-record-jcs-v1.json (three HJS-Core-1 behavior records; input rule: canonicalize the entire input member, omit nothing, retain nulls; digest rule: SHA-256 over the canonical UTF-8 bytes, lowercase hex without the sha256: tag) | 4f593700c1b25698906483171109c02f38b7e389454f49e2b7f4e0db80cda3f7 |
| hjs_jcs.py (implementation; jcs==0.2.1 per the repository's requirements) | 14d89acdd4bb0865da9012cec9b9f5910e4500b35f808375adbd05d43956ce7d |
| reports/interop/aps-jcs-cross-run-2026-08.md (the HJS side's report of its run over this corpus) | 5b059b1b5dc7d1d7343e8e8737d1ac9ca3c774a62e30ba81c91047319a109c38 |
| fixtures/external/aps/aps-canonical-bytes-70d503f-distinct.json (the HJS side's copy of this corpus's ten distinct cases) | checked field by field against this corpus at 70d503f: all ten inputs, canonical_bytes_hex and canonical_sha256 identical |

Link: https://github.com/hjs-spec/hjs-05/tree/bb6be62fd28911c02ff31f61db8c023757ef2243

This corpus's side: fixtures/canonical-bytes/canonical-bytes-jcs-v1.json and
canonical-bytes-jcs-v2.json at 70d503ffd5f29d84f2100731bd0511667e851131 (v2 repeats
v1's eight cases unchanged; ten distinct cases). Implementation for the APS witness:
agent-passport-system 4.5.1, canonicalizeJCS, Node v24.11.1.

## Direction 1: HJS path over this corpus's ten cases

Observation of record: the HJS report at bb6be62. Its current run, hjs_jcs.py over
jcs==0.2.1, matches all ten cases at both the byte and the digest level. The same
report preserves the HJS side's own earlier observation: the previous canonicalizer
(canonicaljson==2.0.0, the path imported by app.py before this commit) matched six of
ten, with four divergent cases (small-exponent-vs-decimal, astral-key-ordering,
integer-2pow60-inside-int64, integer-2pow68-above-int64) and three recorded causes
(Python exponent rendering, code-point rather than UTF-16 key order, arbitrary-precision
integers). That 6/10 is the HJS side's recorded pre-fix observation. This corpus did not
run canonicaljson==2.0.0 and does not reproduce that number; it is cited from the report.

Re-execution by this corpus: rerun-hjs-over-aps.py fetches hjs_jcs.py at the pin,
checks its hash, and runs it over jcs==0.2.1 against the ten cases at 70d503f. Output
in results-hjs-jcs-0.2.1-over-aps.json: 10 of 10 at bytes and digest, exit 0. This
confirms that the pinned files reproduce the reported observation; it is not a second
witness for the HJS claims.

What hjs_jcs.py does on this path, from the pinned source: canonicalize_jcs returns
jcs.canonicalize(value) unchanged, and canonical_sha256 hashes those bytes. The
validation function is not invoked on this corpus's inputs (they are not HJS records),
and it modifies nothing when it is. The harness therefore only invokes an independently
authored primitive and compares its output.

## Direction 2: this corpus's implementations over the three HJS vectors

Two runners, kept separate because they have different relationships to the parties.

APS implementation witness, run-aps-witness.mjs: agent-passport-system 4.5.1
canonicalizeJCS on Node v24.11.1 over the three vectors fetched at the pin. Output in
results-aps-4.5.1.json.

| case | length | observed sha256 | bytes | digest |
|---|---:|---|---|---|
| hjs-core1-minimal-behavior-record | 153 | ff438b247159ad77180afef645c6f3bc307cd4fd6aab5797ae9237c02878158b | match | match |
| hjs-core1-draft05-tool-call | 1138 | bdcc830a1d2dd8c334163b7fcbaad4584a7b7612e001050945dc3a954525d4c7 | match | match |
| hjs-core1-unicode-null-and-array-boundaries | 448 | aa893876066d7cc054f9bf735abc13f8eca3759ea23adc9a88764d831e52e442 | match | match |

Independent witness, run-rfc8785-witness.py: rfc8785 0.1.4 (Trail of Bits) on Python
3.14, no APS and no HJS code imported, same three vectors. Output in
results-rfc8785-0.1.4.json: same three byte strings and digests, 3 of 3, exit 0.

Every results file carries the observed bytes as hex and the observed digest per case
next to the expected values, so a reader can diff bytes rather than trust a label.

## Verification split

- HJS vector claims (bytes and digests of the three HJS-Core-1 records at bb6be62);
  runner: rfc8785 0.1.4 via run-rfc8785-witness.py; Mode B; independent; implementation:
  rfc8785 (Trail of Bits). The runner authored neither the vectors nor the primitive.
- HJS vector claims (same three records); runner: aeoess via run-aps-witness.mjs; Mode B;
  author-produced; implementation: agent-passport-system 4.5.1 canonicalizeJCS. Authorship
  relationship: aeoess maintains both the implementation and this corpus. Relative to HJS
  this is an outside implementation, which is what the row records; it does not make the
  row independent under this corpus's definition.
- This corpus's canonical-bytes claims (ten distinct cases at 70d503f); runner: Yuqiang
  Wang, as recorded in the HJS report at bb6be62; Mode B; independent; implementation:
  jcs 0.2.1 through hjs_jcs.py, a thin call-through that invokes the primitive and
  compares its output (see Direction 1). The runner authored neither the vectors nor the
  primitive. rerun-hjs-over-aps.py is an aeoess re-execution of the pinned HJS path
  confirming that the referenced files reproduce the reported 10 of 10; it is not a
  second independent record.
- HJS pre-fix observation (6 of 10 under canonicaljson==2.0.0); not a record of this
  corpus; cited from the HJS report only.

Because the externally originated recomputable claims (the three HJS vectors) carry an
independent record in this family, no entry is added to docs/OPEN-RUNS.md.

These records are attributed per layer. Merge of this family is not an end-to-end
verification or a family-level verdict.

## Re-run

    pip install rfc8785==0.1.4 && python3 interop/hjs-bb6be62/run-rfc8785-witness.py
    pip install jcs==0.2.1     && python3 interop/hjs-bb6be62/rerun-hjs-over-aps.py
    npm install agent-passport-system@4.5.1 && node interop/hjs-bb6be62/run-aps-witness.mjs

Each runner exits 0 only when every case matches, and exits 2 before running if a
fetched counterparty file does not hash to its pinned value.
