# Runs: aeoess-relationship-revocation-propagation r2.1

All runs are author-produced, Mode A. The submitter wrote the cases and the harness and ran the three implementations from their public release binaries. They are not independent records and do not establish conformance for any implementation.

## Environment

- macOS 26.5, arm64, Python 3.14.6, local loopback, one client, single server process per run.
- OpenFGA v1.22.1 (tag commit 44054f5), `openfga_1.22.1_darwin_arm64.tar.gz` sha256 `4d64ccd3ead676e3b13154bb32372421f3cd4735eda0211f5d0b7d244c689b90`.
- SpiceDB v1.57.1 (tag commit 7074da7), `spicedb_1.57.1_darwin_arm64.tar.gz` sha256 `42e5026ad728ba5b08e87d59a5c4b4284e10e76c3cad4b26fd805d41f95fca2c`.
- Permify v1.7.6 (tag commit 81819b8), `permify_1.7.6_darwin_all.tar.gz` sha256 `f02176736e1c6f9a2fede69e430b925e8ec8b8cf91e65317ea85be3542bc4e3c`.
- Each archive matched the checksums file published with its release. That checks correspondence with the release, not signatures.
- PostgreSQL 17.5, two local clusters (ports 55432 for SpiceDB, 55433 for Permify), trust auth on loopback. `spicedb datastore migrate head` exit 0. Permify migrated itself on start.
- `rplabkey` in the SpiceDB command line and harness is a throwaway preshared key for a loopback server.

## Commands and exits

`harness/run_all.sh` started each server, ran the harness, and stopped the server. `runs/driver.log` holds every command and its direct exit code. Harness hashes at launch are in `runs/harness-sha256-at-launch.txt` and in each result file (`meta.harness_sha256`). Each result file keeps every request with its monotonic start and end time, status and response body (10,161 requests in total).

| step | exit |
|---|---|
| `python3 -I selftest.py rp2.py` (no server) | 0 |
| OpenFGA r2-c0-nocache | 0 |
| OpenFGA r2-c1-cache-ttl10 | 0 |
| OpenFGA conditional cases on the r2-c1 server (`rp_cond2.py`) | 0 |
| OpenFGA r2-c2-ttl60-controller10 | 0 |
| SpiceDB r2-s0-memory | 0 |
| `spicedb datastore migrate head` | 0 |
| SpiceDB r2-s1-postgres-q5 | 0 |
| SpiceDB r2-s2-postgres-q20 | 0 |
| SpiceDB r2-s3-postgres-fullrelcache | 0 |
| Permify r2-m0-memory | 0 |
| Permify r2-p1-postgres | 0 |

## Results

The last two columns give the start time, after the acknowledged change, of the last stale answer seen in the default mode (an allow after a revoke in PR, a deny after a re-grant in RG). "none" means no stale answer was seen in the sampled requests.

| file | server process (as recorded by pgrep) | bound, class | tolerance | AGREE | DIFF | ERROR | RECORD | max IM start after ack (s) | last stale PR start after ack (s) | last stale RG start after ack (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| openfga-cx-r2-c1-cache.json | same server as r2-c1 | n/a | n/a | 10 | 0 | 0 | 0 | - | - | - |
| openfga-r2-c0-nocache.json | `../ofga/openfga run --datastore-engine memory --playground-enabled=false --metrics-enabled=false` | 0.0 s, documented | 0.5 s | 27 | 0 | 0 | 12 | 0.004 | none | none |
| openfga-r2-c1-cache-ttl10.json | `../ofga/openfga run --datastore-engine memory --playground-enabled=false --metrics-enabled=false --check-query-cache-enabled --check-iterator-cache-enabled --list-objects-iterator-cache-enabled` | 10.0 s, configured-setting | 0.5 s | 27 | 0 | 0 | 12 | 0.0031 | 9.4688 | 9.4561 |
| openfga-r2-c2-ttl60-controller10.json | `../ofga/openfga run --datastore-engine memory --playground-enabled=false --metrics-enabled=false --check-query-cache-enabled --check-iterator-cache-enabled --list-objects-iterator-cache-enabled --check-query-cache-ttl 60s --check-iterator-cache-ttl 60s --list-objects-iterator-cache-ttl 60s --cache-controller-enabled --cache-controller-ttl 10s` | 60.0 s, configured-setting | 0.5 s | 27 | 0 | 0 | 12 | 0.0028 | 0.0001 | 0.0001 |
| permify-r2-m0-memory.json | `../pmf/permify serve --distributed-port 5099 --meter-enabled=false --database-engine memory` | 0.0 s, documented | 0.5 s | 27 | 0 | 0 | 12 | 0.0035 | none | none |
| permify-r2-p1-postgres.json | `../pmf/permify serve --distributed-port 5099 --meter-enabled=false --database-engine postgres --database-uri postgres://postgres@127.0.0.1:55433/postgres?sslmode=disable` | 0.0 s, documented | 0.5 s | 27 | 0 | 0 | 12 | 0.0025 | none | none |
| spicedb-r2-s0-memory.json | `../sdb/spicedb serve --grpc-preshared-key <local> --http-enabled --metrics-enabled=false --telemetry-endpoint= --datastore-engine memory` | 5.5 s, submitter-derived | 0.5 s | 36 | 0 | 0 | 12 | 0.003 | 4.4066 | 4.4059 |
| spicedb-r2-s1-postgres-q5.json | `../sdb/spicedb serve --grpc-preshared-key <local> --http-enabled --metrics-enabled=false --telemetry-endpoint= --datastore-engine postgres --datastore-conn-uri postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable` | 5.5 s, submitter-derived | 0.5 s | 36 | 0 | 0 | 12 | 0.0136 | 4.4255 | 4.4199 |
| spicedb-r2-s2-postgres-q20.json | `../sdb/spicedb serve --grpc-preshared-key <local> --http-enabled --metrics-enabled=false --telemetry-endpoint= --datastore-engine postgres --datastore-conn-uri postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable --datastore-revision-quantization-interval 20s` | 22.0 s, submitter-derived | 0.5 s | 36 | 0 | 0 | 12 | 0.0097 | 19.0802 | 20.0066 |
| spicedb-r2-s3-postgres-fullrelcache.json | `../sdb/spicedb serve --grpc-preshared-key <local> --http-enabled --metrics-enabled=false --telemetry-endpoint= --datastore-engine postgres --datastore-conn-uri postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable --experimental-full-relation-cache=enabled --experimental-full-relation-cache-materialize-threshold 1` | 5.5 s, submitter-derived | 0.5 s | 36 | 0 | 0 | 12 | 0.0152 | 4.1871 | 4.4296 |

Totals: AGREE 289, DIFF 0, ERROR 0, RECORD 108

The totals count scored case instances across ten result files from nine server configurations. They are not distinct tests.

## Observations

- Strongest-mode reads (OpenFGA HIGHER_CONSISTENCY, SpiceDB fully_consistent and at_least_as_fresh, Permify with the write's snap token) returned the post-change answer on the first request after each acknowledged change in every configuration. The largest gap between acknowledgement and that request's start was 0.0152 s.
- OpenFGA with caches on and 10 s TTLs: the default mode kept serving the pre-change answer for up to 9.47 s after the change, for revokes and for re-grants (a cached deny is also kept). No stale answer was seen after 10.5 s.
- OpenFGA with 60 s TTLs and the cache controller at 10 s: a stale answer was seen only on the first request after the change. The polls interleave ListObjects requests, which the flag text says can trigger invalidation sooner. The earlier check-only local revision saw stale allows for about 10 s in this configuration. Neither result is a statement about a maximum delay.
- SpiceDB minimize_latency: stale answers up to 4.43 s after the change at a 5 s quantization interval (memory, Postgres, and Postgres with the experimental full relation cache), and up to 20.01 s at 20 s. Before each change the harness waits until the default mode shows the current state for both check and lookup three times in a row. Reaching that took up to about 5 s at 5 s and about 20 s at 20 s.
- Permify without a snap token: no stale answer in the sampled requests, on memory or Postgres.
- OpenFGA conditional expiry with caches on: all ten cases agree. The missing `current_time` request got HTTP 400 `validation_error` naming `current_time`.

## Reproduce

Start a server with the flags in the table, then run `python3 -I harness/rp2.py <impl> <label> --bound <s> --tolerance 0.5 --bound-class <class>`. Exit 0 means no DIFF and no ERROR. `python3 -I harness/summarize.py runs` rebuilds the table from the result files.
