# Clarifications

## 2026-11-18, r2.2 harness after a second review

A review of this candidate at commit ea89d94 found three defects in the r2.1 harness. None of them occurs in the recorded runs, and the r2.1 records are unchanged. `harness/` (r2.1) and `runs/` are kept as run. The fixes are in `harness-r2.2/`.

1. Poll errors. In r2.1 a poll request that fails returns a sample with no timestamps. In the observational bound class the window was recorded without checking for errors, so repeated HTTP 500 responses could give exit 0 with no ERROR row. In the timed bound classes the scorer compared the missing timestamps and stopped with a TypeError before saving results. r2.2 checks every sample for ERROR, MALFORMED, indeterminate or a missing timestamp before any comparison, in every bound class. It also saves partial results and exits 2 if a run stops early. None of the nine recorded runs used the observational class, and no recorded poll sample is an error (`checks-r2.2/rescore.txt`).
2. CX-09 oracle. r2.1 searched the whole serialized response for `current_time`, so an unrelated HTTP 400 with `current_time` in another field could pass. r2.2 requires HTTP 400, code `validation_error`, and `current_time` in the `message` field. The recorded CX-09 body (`code` `validation_error`, message naming the missing `current_time` parameter) passes the r2.2 oracle.
3. Output directory. Neither r2.1 harness created its output directory, so a standalone run from a fresh checkout could finish its server work and then fail to save. r2.2 creates the directory and checks that it can write before contacting any server. `harness/run_all.sh` is the historical driver and uses the submitter's scratch paths.

Copy corrections in the same change. `vectors.json` now describes the warm-ups as they ran in r2.1, with check and lookup confirmed together three times in a row. `RUNS.md` now says the raw request log is in the nine rp2.py result files only, not in the conditional result. The evidence summary now names the acceptance rule: no stale answer observed in the sampled requests beyond the declared bound plus the 0.5 s tolerance.

Checks, all without a server, attributed to this revision and not to the recorded runs:

- `python3 -I harness-r2.2/selftest.py` exit 0 (`checks-r2.2/selftest-r2.2.txt`). New probes cover HTTP 500, malformed bodies and transport failures during polling in the observational and configured-setting classes, an unwritable output path, a genuine empty SpiceDB stream, and the CX-09 oracle with a decoy field.
- `python3 -I harness-r2.2/selftest.py harness/rp2.py` exit 1 (`checks-r2.2/selftest-r2.2-against-r2.1-rp2.txt`). The same probes fail against the r2.1 rp2.py, which shows they detect the defects.
- `python3 -I harness-r2.2/rescore.py` exit 0 (`checks-r2.2/rescore.txt`). 108 of 108 saved window verdicts reproduced with the r2.2 scorer, 0 error samples, saved CX-09 body passes the r2.2 oracle.

No server was run for r2.2. No new server behavior is claimed.
