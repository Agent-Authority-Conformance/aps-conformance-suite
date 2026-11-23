# Sealed artifact record — interop/rttp-iqa-lease-boundary-replay-sparysh-0e0064b

This file is the repository-side record of the current sealed artifact for the pipeline replay of `sparysh-reading-aicent-lease-boundary-0e0064b` (lab PR #238, merged 2026-11-23). It is deliberately **not** a member of the sealed tarball: a sealed archive cannot carry its own digest-derived address, because any byte changed inside the archive changes the very digest the address is derived from. The sealed bytes live in the tarball; this file records where they are and how they resolve. It is written at seal time, before the seal wave is committed — the sealing step precedes every commit and pull request.

## Current cut (generation b, 2026-11-24)

- Reason: one abbreviated digest suffix in `PROVENANCE.md` corrected (the human-readable tail of the `CANDIDATE.md` vendor pin, `07669369…56ad` → `07669369…ad6f`, matching the full pinned digest); no case, verdict, tally, pin value or recorded byte changed. Self-audit before the lab PR caught it (the run234 CRLF-direction lesson applied to a digest transcription).
- Artifact: `lease-boundary-replay-sparysh-20261124b.tar.gz` (60,169 bytes)
- SHA-256: `6e8d16e1081956f71579fae596fe486fcb68b7d5e4be80ede5d495d41d7f4631`
- Dual addresses: `rttp://6e8d16e1.conformance.iqa` · `iqa://6e8d16e1081956f71579fae596fe486f.forge.iqa`
- Resolvers: <https://rttp.com/open/> · <https://iqa.org/open/>
- Report page: <https://iqa.org/conformance/lease-boundary-replay-sparysh/>
- Page digest (SEAL display block excluded), generation b: `8b0f919c0a96a7c2e0e7f0ee60f691e07a0bb2a12851caa7a0f2cb3097b4c1b1`
- Site tarball: `lease-boundary-replay-sparysh-site-20261124c.tar.gz` (13,109 bytes) — SHA-256 `6a010a02c42c8db4601f852bdfd1bba3425dca52fce8dd59c5b567e02acb88c3`
- Page address pair (generation b): `rttp://8b0f919c.site.iqa` · `iqa://8b0f919c0a96a7c2e0e7f0ee60f691e0.forge.iqa`

## Generation a (first seal, 2026-11-24, superseded by generation b)

- Artifact: `lease-boundary-replay-sparysh-20261124a.tar.gz` (60,210 bytes)
- SHA-256: `d286892febd54b501aad9e6e69e7957b96ebb17f55326ee78aacbd18eb0e5fb6`
- Dual addresses: `rttp://d286892f.conformance.iqa` · `iqa://d286892febd54b501aad9e6e69e7957b.forge.iqa`
- Page digest (SEAL display block excluded), generation a: `0ff06e926cf4588f65002abf33dd71f619c081282946496faa575c6843c144f4`
- Site tarball: `lease-boundary-replay-sparysh-site-20261124b.tar.gz` (12,993 bytes) — SHA-256 `454a0bc1ac772493fe237e855e4cbc2297bc0d714892baf948a1d11eb14fd22b`
- Page address pair (generation a): `rttp://0ff06e92.site.iqa` · `iqa://0ff06e926cf4588f65002abf33dd71f6.forge.iqa`

## Ledger and registration

- Ledger: `attestations/release-attestations.json`, dual-station identical (194 records, station SHA-256 `cdb80e981ede670021233a390822de0b649d204acea3bcd68e903cd361f4b390`)
- Records appended by generation a: `2026-11-24-lease-boundary-replay-sparysh` (sealed-run, artifact) and `2026-11-24-lease-boundary-replay-sparysh-page` (site-freeze, first publication of the report page)
- Records appended by generation b: `2026-11-24-lease-boundary-replay-sparysh-digest-suffix-fix` (sealed-run, supersedes the generation-a record) and `2026-11-24-lease-boundary-replay-sparysh-page-digest-suffix-fix` (site-freeze, supersedes the generation-a page record)
- Organ registration (generation b): subject `iqa://6e8d16e1081956f71579fae596fe486f.forge.iqa` — standing `radiant`, organ `forge` (production 66 → 67 subjects, backup `production.json.bak-20261124b-pre66`); the generation-a subject registration remains on the ledger, append-only
- Wayback pins: report page capture `20261123165838` (generation a); the generation-b capture lands via the weekly submit window (the same-URL save request was deduplicated by the archive minutes after the first capture, twice attempted)

The wrapper committed alongside this record is the one extended for this replay: this record's comparison output uses the `match`/`diverge`/`tally_final` summary schema, named through the profile's optional `summary_keys`; the wrapper's default schema is unchanged and the grant-ref replay reproduces byte for byte under the extended wrapper (verified before sealing).

The full per-cut table (every cut's size, SHA-256 and derived address pair) lives on the report page, which is the canonical display layer for the sealing discipline.
