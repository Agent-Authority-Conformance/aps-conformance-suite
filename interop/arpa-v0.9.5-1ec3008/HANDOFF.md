# Artifact handoff: environment observations

Observations from running the reproduction on macOS. Environment only.

- Platform: macOS 26.5 on arm64. The `report` target prints an absolute path, and
  `release-check-all.log` records it as `/private/tmp/arpa-v095-repro/...` even though the run
  was started from `/tmp/arpa-v095-repro`, because macOS resolves `/tmp` through `/private/tmp`.

- The Makefile's `setup` target is `python3 -m pip install -r scripts/requirements.txt` with no
  venv, so running it would install seven packages outside the clone. It was not run. A
  `python3.12` venv was created inside the clone instead, and `PATH` was prefixed with
  `.venv/bin` so that the `python3` the Makefile recipes name resolves to it.

- Python 3.12 rather than the machine default 3.14 was used for the gate. `scripts/requirements.txt`
  states no interpreter constraint and the repository carries no `pyproject.toml`, `setup.py` or
  `setup.cfg`, so the choice is this environment's, not the repository's.

- `npm ci` is not available for the TypeScript track: `typescript/` carries no
  `package-lock.json`. The Makefile's own `typescript-check` recipe runs
  `npm install --ignore-scripts --no-audit --no-fund` inside `typescript/`, which is
  project-local, and that is what ran. It reported `added 1 package in 2s`.

- The `test` target emits one warning, a Starlette deprecation notice that `httpx` is
  deprecated with `starlette.testclient`. It is a warning and not a failure; the tally line is
  `12 passed, 1 warning in 0.45s`.

- The gate writes evidence into the working tree as it runs. After the run, seven tracked files
  are modified inside the clone: two under `artifacts/candidate-specification/`, two under
  `artifacts/interoperability/`, two under `artifacts/typescript/`, and
  `conformance/reports/reference-implementation-report.json`. Two further report files that the
  gate rewrites, `artifacts/typescript/historical-resolution-report.json` and
  `artifacts/historical-resolution/evidence-bundle.json`, come back byte-identical to their
  committed versions and so do not appear as modified.

- Network access is needed for the initial clone and for the `npm install` dependency restore.
  The `network-interop` target needs none: `scripts/run_typescript_network_interop.py` obtains
  two ephemeral ports with `socket.bind(('127.0.0.1', 0))` and starts a local uvicorn process
  and the TypeScript server against `http://127.0.0.1:<port>`.

- `recompute.py` was run with Python 3.14.6. It imports `glob`, `json`, `os`, `sys` and
  `datetime`, all standard library, and no third-party package and no repository module. It is
  run from the artifact directory and takes the checkout path as its one argument.
