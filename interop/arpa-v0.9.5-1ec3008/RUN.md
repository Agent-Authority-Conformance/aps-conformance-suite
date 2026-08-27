# ARPA v0.9.5 release-gate reproduction at pinned 1ec3008

## Purpose

Reproduction of the release gate `make release-check-all` published by
sankarshanmukhopadhyay/agent-registry-protocol, all eight of its targets, and independent
recomputation of the nine authority-evaluation conformance vectors from the specification
text, at pinned SHA 1ec3008effc00f3ccbac26769f5528d97d065c9b, which is tag v0.9.5.

## Environment

- macOS 26.5, arm64
- Python 3.12.13 (`.venv/bin/python --version` output: `Python 3.12.13`), venv created inside
  the clone
- Python 3.14.6 (`python3 --version` output: `Python 3.14.6`) is the machine default and was
  used for `recompute.py`, which is standard library only
- Node v24.11.1 (`node --version` output: `v24.11.1`)
- npm 11.6.2 (`npm --version` output: `11.6.2`)
- GNU Make 3.81
- Python dependencies restored from the checkout's own `scripts/requirements.txt` into the
  venv: fastapi 0.141.1, httpx 0.28.1, jsonschema 4.26.0, pytest 8.4.2, PyYAML 6.0.3,
  referencing 0.37.0, uvicorn 0.52.4
- TypeScript dependencies restored by the Makefile's own project-local `npm install` inside
  `typescript/`

## Commands

    $ rm -rf /tmp/arpa-v095-repro
    $ git clone https://github.com/sankarshanmukhopadhyay/agent-registry-protocol.git /tmp/arpa-v095-repro
    exit=0
    $ git -C /tmp/arpa-v095-repro checkout 1ec3008effc00f3ccbac26769f5528d97d065c9b
    exit=0
    $ git -C /tmp/arpa-v095-repro rev-parse HEAD
    1ec3008effc00f3ccbac26769f5528d97d065c9b

    $ cd /tmp/arpa-v095-repro
    $ /opt/homebrew/bin/python3.12 -m venv .venv
    exit=0
    $ .venv/bin/python -m pip install -r scripts/requirements.txt
    exit=0
    $ cd typescript && npm install --ignore-scripts --no-audit --no-fund
    exit=0

    $ export PATH="/tmp/arpa-v095-repro/.venv/bin:$PATH"
    $ make release-check-all > /tmp/arpa-v095-repro/release-check-all.log 2>&1; echo "exit=$?"
    exit=0

    $ python3 recompute.py /tmp/arpa-v095-repro > recompute-output.log 2>&1; echo "exit=$?"
    exit=0

`make setup` was not run. Its recipe is `python3 -m pip install -r scripts/requirements.txt`
with no venv, which installs outside the clone. The venv above is the project-local
substitute, and the `npm install` line is the Makefile's own recipe inside `typescript/`.

## Result

Exit code of the documented release gate command: 0

The eight targets, with each tally line verbatim from release-check-all.log:

    target             tally line, verbatim                                                                                exit
    validate           validate_examples.py: 44/44 OK                                                                      0
                       validate_test_vectors.py: 12/12 OK
                       validate_extended_vectors.py: 14/14 OK
                       validate_artifacts.py: schemas, registries and YAML parsed successfully
                       validate_repository.py: flagship baseline and local Markdown links OK
                       validate_licensing.py: artifact-specific licensing map OK
                       validate_candidate.py: mapping complete; 13 projection vectors and 15 historical vectors present
                       validate_historical_resolution.py: 15/15 historical vectors passed
                       validate_a2a_interoperability.py: 18/18 OK
    test               12 passed, 1 warning in 0.45s                                                                       0
    interop            interoperability: 7/7 checks passed                                                                 0
    candidate          candidate-program: 15/15 checks passed                                                              0
    report             /private/tmp/arpa-v095-repro/conformance/reports/reference-implementation-report.json               0
    typescript-check   TypeScript conformance: 12/12 vectors passed                                                        0
                       TypeScript historical resolution: 15/15 vectors passed
                       TypeScript A2A adapter checks: 5/5 passed
                       node:test block: tests 13, pass 13, fail 0
    cross-runtime      Cross-runtime equivalence: 27/27 checks (12/12 deterministic; 15/15 historical)                      0
    network-interop    TypeScript network interoperability: 7/7 checks passed                                              0

Every target passed on the first run, so no target was run individually afterwards. No target
attempted an address outside loopback: `scripts/run_typescript_network_interop.py` binds
127.0.0.1 on two ephemeral ports and starts both servers against them, so nothing was skipped
and nothing was faked.

The 27/27 figure is two comparisons of different kinds, summed. The 12 deterministic checks
take one `TV-*.json` vector each: the Python outcome is computed in process by the script
importing the repository's own `scripts/reference_evaluator`, the TypeScript outcome is read
from `artifacts/typescript/conformance-report.json`, and a check counts as equivalent only
when the Python outcome, the TypeScript outcome and the vector's own expected outcome are all
the same value, so the comparison is three-way and not two-way. Both sides were regenerated
during this run before the comparison ran, the TypeScript report by `npm run conformance`
under the typescript-check target. The 15 historical checks compare two report files written
earlier in the same run, `artifacts/historical-resolution/evidence-bundle.json` from the
Python validator and `artifacts/typescript/historical-resolution-report.json` from the
TypeScript one, on two fields each, `reconstruction_status` and `historical_effect`, and
require both to record `passed` true.

The nine authority-evaluation vectors recomputed from the specification text, verbatim from
recompute-output.log. `recompute.py` computes every outcome from the vector input alone in a
first pass and reads each vector's own `expected_outcome` from disk only in a second pass:

    vector     spec section  expected               recomputed             match
    TV-B-01    28.2          allow                  allow                  yes
    TV-B-02    28.2          deny                   deny                   yes
    TV-B-03    28.2          indeterminate          indeterminate          yes
    TV-C-01    28.2          allow                  allow                  yes
    TV-C-02    28.2          allow_with_conditions  allow_with_conditions  yes
    TV-C-03    28.2          deny                   deny                   yes
    TV-D-01    28.2          allow                  allow                  yes
    TV-D-02    28.2          deny                   deny                   yes
    TV-D-03    28.2          deny                   deny                   yes

Nine attempted, nine matching. TV-A-01, TV-A-02 and TV-A-03 were not attempted: their `check`
field is `identifier_resolution` rather than `authority_evaluation`. The rules `recompute.py`
implements are transcribed from spec/agent-registry-protocol-v0.9.0.md section 28.2 at the
pinned SHA, steps 3, 4, 5, 8, 10, 11, 12 and 16 and that section's closing rule; steps 1, 2,
6, 7, 9, 13, 14, 15 and 17 are not implemented because the TV vectors supply an already
resolved single envelope with no delegation lineage, no assurance claims and no named
relying-party policy.

Every target above runs the repository's own code and vectors outside its CI. No second
implementation of ARPA was written. The nine authority-evaluation vectors were recomputed from
the specification text alone in recompute.py, which imports no repository code; that covers
nine of the corpus's 72 vectors and one of the eight gate targets.

## Scope

This artifact covers ARPA v0.9.5 only. It does not characterize unreleased corpora or claims
present only on the repository's later main branch. It records that the v0.9.5 release gate
(make release-check-all) passes at the pinned SHA in an environment outside the repository's
CI. It makes no statement about APS and grades no APS artifact. Case definitions and expected
outcomes are the repository's own, referenced by path at the pinned SHA and not quoted here.

### Not tested, outside this pinned release

The repository's main branch, after this tag, describes additional hardening material that is
not part of v0.9.5 and was not run.
