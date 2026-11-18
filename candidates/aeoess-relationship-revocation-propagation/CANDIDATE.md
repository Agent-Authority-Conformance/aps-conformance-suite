# Candidate: aeoess-relationship-revocation-propagation

## Submitter

Tymofii Pidlisnyi (Agent Passport System)

## Normative target

There is no single normative text. Each case reads the consistency documentation of the implementation it runs against, pinned below. Where a bound is our reading rather than a number the project states, it is labelled that way in `vectors.json` and `RUNS.md`. The cases are a candidate interpretation of those texts. They are not requirements those projects have adopted.

| implementation | text | pin | sha256 |
|---|---|---|---|
| OpenFGA v1.22.1 | `docs-site/interacting/consistency.mdx`, and `openfga run --help` for the cache flags | openfga/openfga.dev `8e460255093d9922fa19cd63d3a69b799ea4114e` (docs-next) | `cb27a274af7ef8204b7d12dbbc0b3e0bdd41926b5226c4c0159bc589366ac8e1` |
| SpiceDB v1.57.1 | `app/spicedb/concepts/read-after-write/page.mdx` | authzed/docs `278ac404f05ccde6a741a7cf7af674a58fb610f9` | `355e650cbaa46284b962c010b68c20ff078519fb74a50dbd8d1e0f5681c5091a` |
| SpiceDB v1.57.1 | `app/spicedb/concepts/consistency/page.mdx` | authzed/docs `278ac404f05ccde6a741a7cf7af674a58fb610f9` | `080aa232224e2943265d5cfcf7e3efc3310a9d102965d0566fd5718c9ea97331` |
| Permify v1.7.6 | `docs/operations/snap-tokens.mdx` | Permify/permify `18fcfdda52fdc93bef7b8de43474d26173e9d23f` | `cb20a3fa6ae955106365c8f8a6a6ff0a48125c0a37b2907d5118a42f7707863c` |

## Source

Cases and harness written by the submitter, 2026-11-18. Server binaries are the public release archives for the versions above, each checked against the checksums file published with its release.

## License

Apache 2.0.

## What the cases test

When access depends on a chain of relationships, revoking any one of them should remove the access. A user can view a document because the user is in a group, the group can view a folder, and the document is in that folder. Each relationship is removed in turn and the document check and lookup are observed.

- **Immediate (IM).** After the revoke is acknowledged, the next request uses the strongest read the implementation names and must deny. The document must be absent from the next lookup. A re-grant must be visible the same way. Default-mode caches are warmed first on the same chain.
- **Propagation (PR).** On a separate chain, default-mode caches are warmed, the relationship is revoked, and only default-mode reads follow. A stale allow before the bound is recorded. Every request that starts at or after the bound plus a 0.5 s tolerance must deny.
- **Recovery (RG).** On a third chain, a deny is cached in the default mode, the relationship is restored, and only default-mode reads follow, under the same rule.
- **Conditional expiry (CX, OpenFGA only).** A grant with a CEL expiry condition on the folder relationship. With the check cache on, an allow cached for one `current_time` must not answer a later one. A request without `current_time` must get HTTP 400 naming the missing parameter.

Responses are validated before scoring. An error, an unknown value or a missing field is recorded as ERROR and never counts as a deny.

This tests relationship-based authorization. It does not mint or validate signed delegation between agents, and it does not invoke a protected operation or observe its effect. It may inform the AIMM Pillar 2 remaining gap "descendant use after parent revocation beyond the propagation limit, in one case", but it does not close that gap.

## How to run

Start the server with the flags listed in `RUNS.md`, then run, for example:

```
python3 -I harness-r2.2/rp2.py openfga c1 --bound 10 --tolerance 0.5 --bound-class configured-setting --out out
python3 -I harness-r2.2/rp_cond2.py c1 --out out
python3 -I harness-r2.2/selftest.py
python3 -I harness-r2.2/rescore.py
```

The recorded runs used `harness/` (r2.1), kept unchanged. `harness-r2.2/` fixes three failure paths found after the runs and scores valid samples the same way (`CLARIFICATIONS.md`). `harness/run_all.sh` is the historical driver and uses the submitter's scratch paths. `selftest.py` needs no server. It checks that malformed, error and transport failures cannot pass as denials in any bound class, that a stale answer past the bound is reported, that the CX-09 oracle reads only the error message, and that output directories are created before any server work. `rescore.py` reproduces the saved verdicts offline.

## Evidence

See `RUNS.md`. Author-produced Mode A, 2026-11-18, harness r2.1 (`rp2.py` sha256 `e6e1055a2e2e0070334757b655736d3910ceff80f8cb21c9c8bb49349f57f264`, `rp_cond2.py` sha256 `0d175942a5b0c25d0c676f10552b8718c3627db196e9a08d468bcc60fd9835ce`). Nine result files, one per server configuration (OpenFGA 3, SpiceDB 4, Permify 2), and one for the conditional cases on the OpenFGA c1 server: 289 scored case instances agree, 0 differ, 0 errors, 108 recorded observations. In every configuration the strongest read returned the post-change answer on the first request after the change. In the default mode, OpenFGA with 10 s cache TTLs served the pre-change answer for up to 9.47 s, and SpiceDB for up to 4.43 s at a 5 s quantization interval and 20.01 s at 20 s. Permify without a snap token served no stale answer in the sampled requests. No stale answer was observed in the sampled requests beyond the declared bound plus the 0.5 s tolerance. r2.1 `selftest.py` exit 0. After the runs, r2.2 offline rescoring reproduced all 108 saved window verdicts and the CX-09 verdict (`checks-r2.2/rescore.txt`, exit 0).

## Revision history

r2.1 (this candidate). Earlier local revisions were not published. r1 could count a malformed response as a deny, scored the default mode only once after the window, ran its strongest-mode checks after the default-mode poll and did not check that warm-ups succeeded. r2.0 confirmed the check and lookup warm-ups one after the other. SpiceDB default reads are not monotonic, so one precondition failed there, and r2.1 confirms them together. Only r2.1 results are reported here. r2.2 (2026-11-18, after a second review) changes the harness only: poll errors become ERROR in every bound class instead of being recorded or crashing the scorer, CX-09 reads only the error message, and output directories are created up front. The r2.1 records were not rerun. See `CLARIFICATIONS.md`.

## Known limitations

- Single node, one client, local loopback. No replicas, follower reads or distributed datastores. The SpiceDB consistency page warns that `fully_consistent` may miss a just-committed write on CockroachDB. CockroachDB was not run.
- Requests are sequential. No revoke races an in-flight check.
- Sampling is every 0.25 s for a finite horizon. A clean window is "no stale answer observed in the sampled requests", not proof for all times.
- The OpenFGA bound with caches on is the configured cache TTL, read from the flag text. How the query and iterator caches compose is our reading. `cache-controller-ttl` is a minimum interval between invalidation attempts, not a maximum delay, so the controller configuration is scored against its 60 s TTL and the earlier recovery it produces is only recorded.
- In the OpenFGA cache-controller configuration, the propagation and recovery polls interleave ListObjects requests, and the flag text says ListObjects can trigger invalidation sooner than Check. A check-only poll may see a longer stale window under that configuration.
- SpiceDB `minimize_latency` reads were not monotonic in one run (deny three times, then listed), so warm-ups confirm the check and the lookup together before a change is made.
- The SpiceDB bound is the quantization interval times (1 + max staleness 0.1), our reading of the two flags the read-after-write page names. SpiceDB does not state that number.
- The Permify bound of 0 s reads its text on requests without a snap token for a single node with sequential requests. It is not a distributed guarantee.
- All runs are author-produced Mode A. They are not independent and do not establish conformance for any of the three implementations.
