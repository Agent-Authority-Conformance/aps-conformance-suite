# Corpus releases

A release is an immutable snapshot of this repository at one commit, published so
a reader can reconstruct exactly what the corpus claimed on a given day.

No release has been cut. This document is the format, so that when one is cut it
records the things a reader would otherwise have to reconstruct by hand, and so
that the shape is agreed before there is a release to argue about.

## What a release is

A commit sha, and a record of what was true at it. Nothing is regenerated at
release time and no vector is edited to make a release tidy. A release that
disagrees with its commit is a defect in the release, not in the commit.

## What a release is not

Not a certification, and not a verdict on any implementation. A release says what
the corpus held and what had been observed against it. It does not say that any
implementation is conformant, because the lab issues no conformance verdicts and
a release is the least appropriate place to start.

Not a claim of completeness. The open-runs queue and the open disputes are part
of the record precisely so a release cannot be read as a finished picture.

## Release record template

```markdown
# Release <tag>

Commit: <full sha>
Date: <YYYY-MM-DD>

## Normative targets

One line per target document with its exact revision, and the families that
target it.

| document | revision | families |
|---|---|---|

## APS-native corpus

fixtures/manifest.json SHA-256: <64 hex>
Files: <n>   Vectors: <n>

Both numbers are the manifest's own totals, which
runners/ts/manifest-integrity.test.ts holds to the files at this commit.

## External-system families

One line per family with the upstream revision it is pinned to. A family whose
pin cannot be stated is not released; it is a gap and is listed under known
limitations.

| family | counterparty | pinned revision |
|---|---|---|

## Interop run records

One line per record, with the implementation and revision observed and the
corpus commit the run was made against.

| record | implementation and revision | corpus revision observed |
|---|---|---|

## Open independent runs at this commit

The contents of docs/OPEN-RUNS.md at this commit, copied in full. It is a work
queue of layers that landed with author-produced evidence and have no
independent follow-up record. It is not a completeness status and not a
certification gap.

## Open disputes at this commit

The open rows of docs/DISPUTES.md at this commit, copied in full. "None open" is
itself a statement worth recording.

## Known limitations

What this release does not cover, in plain sentences. A limitation named here is
worth more than a passing check, because it is the thing a reader would
otherwise assume was covered.

## No verdict

This release is a snapshot of published vectors, verifier adapters and
attributed run records at one commit. It certifies nothing. It issues no
implementation-level or family-level conformance verdict. A passing run recorded
here is an observation at exact pins, by a named runner, under a stated mode and
authorship label. A merge is not a verdict.
```

## Reconstructing a release

Everything above is derivable from the commit, which is the point: given the
tag, a reader can check the manifest digest, re-read the pins, and re-run the
gate. If a value in a release record cannot be reproduced from its commit, the
record is wrong and is corrected by a dated erratum rather than by an edit that
makes the disagreement disappear.
