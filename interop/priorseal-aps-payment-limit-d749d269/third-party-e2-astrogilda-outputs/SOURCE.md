# Copies of the outputs of @astrogilda's E2 run

Exact copies of the two output files that `third-party-e2-astrogilda.md` cites by hash, kept here so the record does not depend on another repository staying available. `third-party-e2-astrogilda.md` is unchanged by this directory.

| file | SHA-256 | bytes | source |
|---|---|---|---|
| `RESULTS.json` | `80e1adbb4c0e97fd2a9a7a8d2c290e9f225fd37793324f72b49198861861a8cd` | 26983 | `probityai/agent-evidence-vectors` at `00f5acab880bffc5ee8fe124f3a015d3ed970514`, `interop/aps-priorseal-e2-2026-09-30/RESULTS.json` |
| `NEGATIVES.json` | `cb43bd4409e30dad465ea0e445668e9b8282914a62beecaecf88099fd1141829` | 6506 | same commit, `interop/aps-priorseal-e2-2026-09-30/NEGATIVES.json` |

Both files were fetched from that commit on 2026-10-01 and hashed after download. They are the runner's work, under that repository's Apache-2.0 license.

The runner's own CI produced the same two hashes in seven `e2-reproduction` artifacts, from workflow runs 36773384654, 36773475427, 36776622460, 36776629545, 36778628682 and 36778635765 on branch `interop/aps-priorseal-e2-2026-09-30` (heads `ad2c3fd1`, `57a770fb`, `b2f57da8`) and run 36828238003 on `main` at `a430a9cf`. Those artifacts expire 14 days after each run. They are listed as provenance only and are not stored here.

These copies add no claim. What the run establishes and what it does not is stated in `third-party-e2-astrogilda.md`.
