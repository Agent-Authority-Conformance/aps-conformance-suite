# Adding to the corpus

There are four lanes into this repository. They are different kinds of
contribution with different review, and picking the wrong one is the usual reason
a pull request stalls. An earlier version of this document described only the
first lane and said every vector flows from the upstream Agent Passport System
repository, which was true when the corpus was one family's vectors and is not
true now.

Read `CONTRIBUTING.md` first for what does not land by pull request at all.

## Lane 1: a vector in an existing APS-native family

1. Add or change the vector upstream, in `agent-passport-system`, and regenerate
   the fixture with that repository's generator. Where the upstream family has
   a generator, regenerate the fixture with that generator. Do not hand-edit
   pinned canonical bytes, digests or signatures.
2. Confirm it passes upstream before it comes here.
3. Copy the regenerated file into `fixtures/<category>/`, preserving its bytes.
4. Update its entry in `fixtures/manifest.json`: the `canonical_sha256` over the
   file bytes, the `vector_count`, and the `totals` block. Recompute these; do
   not type them. `npm run test:manifest-integrity` will tell you if the
   declaration and the files disagree.
5. Run `npm test` from the repository root.

## Lane 2: a new APS-native family

Everything in lane 1, plus:

1. A new entry in `fixtures/manifest.json`, and a `vector_count` that matches.
2. Either the generic runner covers the family, or the family ships its own
   verifier wired into `npm test` under its own script, with a README saying what
   the verifier decides and what it does not.
3. A note in `well-known/aps-test-vectors.json` if the family belongs in the
   published reference set. That set is selective; it is what to cite, not an
   index of everything here.

A new family name is conformance vocabulary. Read the section in
`CONTRIBUTING.md` on what does not land by pull request before proposing one.

## Lane 3: an external-system family

A family ingested from an external system or source, landing under
`fixtures/cross-stack/`. Individual vector, claim-input and implementation
authorship is recorded separately in the family's provenance and Verification
split. These are not APS-native vectors and are never added to
`fixtures/manifest.json`.

Required with the family:

1. A `SOURCE.md` naming the counterparty, how the artifacts were obtained, and
   the exact revisions they are pinned to.
2. A **Verification split**: one entry per distinct verification claim, each
   carrying Mode A or Mode B and author-produced or independent, using the single
   definition in `CONTRIBUTING.md`, plus the authorship relationship for every
   author-produced entry.
3. An entry in `fixtures/cross-stack/index.json` declaring the family's kind.
   That file is a reviewed declaration; the classification is not inferred from
   where the directory sits.

Merging an external family admits evidence. It is not a verdict on the
counterparty's implementation and it is not an end-to-end verification.

## Lane 4: a run record

An observation of some implementation at an exact revision, landing under
`interop/<implementation>-<target>-<pin>/`. This is not a vector and is never
counted as one.

`docs/RUN-REPORT.md` has the required fields and the two run modes. The two that
are most often missing: a named person or handle for who ran it, and the commit
sha of this repository the run was made against. A record states its Mode and its
authorship label, and it stays pinned to the revision actually run: a later
revision becomes a new record rather than an edit to this one.

## Versioning

A fixture file's `version` field is the format version of that file, not a
version of the corpus. Changing pinned bytes in place invalidates every claim
recorded against them, so a corrected vector is a new vector or a new file, and
the record that observed the old one keeps saying what it observed.
