# Provenance

## Pack source

| item | value |
|---|---|
| repository | emiliaprotocol/emilia-protocol |
| pull request | 521, "Ship Authority Brain, Scan 0.3.9, composition conformance, and receipts preprint" |
| pull request state | merged 2026-08-06T06:02:15Z, author FutureEnterprises |
| commit read | 30916c802dcb60251f6af5e0999912a6306117c3, dated 2026-08-05T05:51:09Z |
| merge commit | 89686520a3cb305a9d462aa1fa85294e242c49a0 |
| fetch date | 2026-08-18 |

The commit read is the one the composition draft names. It is a pull-request
branch object: the pull request was squash-merged, so the merge commit has a
single parent and 30916c80 is not an ancestor of it or of main. Both commits are
recorded above so either can be resolved. The bytes in corpus/ are from
30916c802dcb60251f6af5e0999912a6306117c3.

## Manifest pin, and its verification

The pack's cross-slot manifest pins the composition revision by digest:

| pinned item | revision | pinned sha256 | verified against datatracker |
|---|---|---|---|
| composition | draft-mih-sato-agent-accountability-composition-00 | `3649831a2908fdee5cf11015965d24711f67e89bffdce193220d2bd50925919f` | yes |
| profiled WHAT | draft-mih-scitt-agent-action-capsule-02 | `493428486c85e03624bc1d90e8265b072b98265b93b7bd50d55824688a1802d8` | yes |

Both were fetched from datatracker.ietf.org on 2026-08-18 at the pinned revision
and hashed. Both equal the manifest's pinned values.

The manifest pins -00. The current revision of that draft is -01. This directory
records a run against the -00 pin, which is what the manifest carries.

## Published checksums

The pack ships CHECKSUMS.sha256 in each pack directory, covering manifest.json,
bundle.json, report.emilia-js.json and external-report.template.json. All eight
entries verify against the copies in corpus/. Verify with:

    cd corpus/examples/composition/cross-slot-conformance-v1 && shasum -a 256 -c CHECKSUMS.sha256
    cd corpus/examples/composition/caid-aec-aeb-capsule-v1 && shasum -a 256 -c CHECKSUMS.sha256

SHA256SUMS.txt in this directory covers every file here, including the runners,
the tests and the README files that the pack's own checksum files do not list.

## Input digests

Per-file SHA-256 for every corpus file is tabulated in VECTOR-INVENTORY.md.
SHA256SUMS.txt covers the whole directory.

## Independence

This run was independently produced. The adapters in adapter/ were written from
the published bytes and the pack's mechanism document, by a party that is not the
pack's author. No upstream code was copied, and no shared library is used by both
sides: the adapters depend on Node builtins and the Python standard library only.
