# Artifact handoff: environment observations

Observations from running the reproduction on macOS. Environment only.

- Platform: macOS 26.5 on arm64. The pytest header line in `pytest-output.log` records
  `platform darwin -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0`.

- A bare `import ca2a` fails on macOS, both outside and inside the pytest rootdir:

      $ python -c "import ca2a"
      ModuleNotFoundError: No module named 'ca2a'

  This matches the behaviour recorded on Linux. The installed distribution is named
  `ca2a-runtime` and the importable package is `ca2a_runtime`; a bare `import ca2a` is
  not the package's import name on either platform, so the failure is not macOS specific.

- The editable install resolves the package inside the checkout:
  `/private/tmp/ca2a-repro/src/ca2a_runtime/__init__.py`.

- macOS resolves `/tmp` through `/private/tmp`, so pytest records
  `rootdir: /private/tmp/ca2a-repro` and `configfile: pyproject.toml` even though the run
  was started from `/tmp/ca2a-repro`.

- The run emits one warning, recorded in `pytest-output.log`:
  `PytestConfigWarning: Unknown config option: asyncio_mode`. It is raised by pytest 9.1.1
  reading the checkout's own pytest configuration and is unrelated to the platform.

- The reproduction needs no network access after the clone and the pip install step.
