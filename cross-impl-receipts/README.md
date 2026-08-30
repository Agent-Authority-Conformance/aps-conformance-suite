# cross-impl-receipts

Verifier receipts produced by the
[`arian-gogani/nobulex`](https://github.com/arian-gogani/nobulex) implementation,
mirrored here so a reader can check cross-implementation evidence from two
repositories without asking either maintainer to re-run anything.

Each record here is pinned to one upstream revision. A later upstream revision
becomes a new record; it does not overwrite an earlier one. This is the same rule
the lab applies to run records: a published record stays at the revision actually
observed, so a citation of it keeps meaning what it meant.

## Frozen legacy snapshot, at the root of this directory

`aps-byte-match-receipt.json`, `ctef-byte-match-receipt.json` and
`ctef-vectors.json` are the snapshot taken at upstream commit
`d68fcee827bf946414ab0669146403827bf59f51` on 2026-05-02.

| file | SHA-256 |
|---|---|
| `aps-byte-match-receipt.json` | `a4d63359574a7408cac8dd3c132586cff611535c4c8f074ed3556a61cf165443` |
| `ctef-byte-match-receipt.json` | `2e8afc85080ed64fe539c913410f2343d10cba8c5b17f61cc8a7d19e4fa11216` |
| `ctef-vectors.json` | `b655d1b3e7aeccb8b75517c1efc46d2dbf6759dea07581a1b39d4ab59baa7046` |

These three files predate the dated-snapshot layout below and are kept at their
original paths on purpose. Their public paths may already be cited, and moving
them to make the directory tidy would break those citations to no reader's
benefit. They are frozen: never re-fetched, never reformatted, never modified
again. A change upstream produces a new dated snapshot and leaves these alone.

## Dated snapshots

`snapshots/<YYYY-MM-DD>-<upstream-sha7>/` holds one snapshot per observed
upstream revision: the three receipt files as fetched, a `CHECKSUMS` file with
their SHA-256 digests, and a `PROVENANCE.md` naming the upstream repository,
branch, full commit sha and fetch time.

Nothing in an existing snapshot directory is ever modified. That is the whole
mechanism: a snapshot is an observation at one revision, and observations
accumulate.

## Editorial role

None. These are mirrored bytes. They are not reformatted, re-pretty-printed or
cleaned up here, and any divergence from the upstream revision a record pins is
a bug in the mirror.

## Snapshot mechanism

`.github/workflows/sync-cross-impl-receipts.yml` polls upstream daily at 00:00
UTC, and on a change writes a new dated snapshot directory and opens a pull
request; it never modifies an existing path and never auto-merges. The daily
cadence is a public commitment, agreed with `@arian-gogani` in
[A2A#1786](https://github.com/a2aproject/A2A/issues/1786) and named in CTEF
section A as daily-poll synchronization.

## Verify a record locally

Each record pins a revision, so it is checked against that revision rather than
against whatever upstream `main` holds today. For the frozen legacy snapshot:

```bash
for f in aps-byte-match-receipt.json ctef-byte-match-receipt.json ctef-vectors.json; do
  diff -q \
    <(curl -fsSL "https://raw.githubusercontent.com/arian-gogani/nobulex/d68fcee827bf946414ab0669146403827bf59f51/$f") \
    "$f" \
    && echo "OK $f" || echo "DIVERGED $f"
done
```

Run from inside this directory. For a dated snapshot, use the commit sha in its
`PROVENANCE.md` and run the same loop inside that directory. A divergence against
the pinned revision is a bug in the mirror. A difference against upstream `main`
is not: it means upstream has moved, which is what the next snapshot records.
