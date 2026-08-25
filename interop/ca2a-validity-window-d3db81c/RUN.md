# ca2a conformance profile reproduction at pinned d3db81cd

## Purpose

Reproduction of the ca2a conformance profile, including the validity-window cases
ACTION-012, ACTION-013 and DELEG-007 through DELEG-009, at pinned SHA
d3db81cd98a64074a74cbf976fdba5ecbbfaa6f7.

## Environment

- macOS 26.5, arm64
- Python 3.14.6 (`python -V` output: `Python 3.14.6`)
- ca2a-runtime 0.2.1, editable install from the pinned checkout
- pytest 9.1.1

## Commands

    $ rm -rf /tmp/ca2a-repro
    $ git clone https://github.com/agentrust-io/ca2a.git /tmp/ca2a-repro
    $ cd /tmp/ca2a-repro
    $ git checkout d3db81cd98a64074a74cbf976fdba5ecbbfaa6f7
    $ git rev-parse HEAD
    d3db81cd98a64074a74cbf976fdba5ecbbfaa6f7

    $ python3 -m venv /tmp/ca2a-repro/.venv
    $ source /tmp/ca2a-repro/.venv/bin/activate
    $ pip install -e /tmp/ca2a-repro pytest

    $ cd /tmp/ca2a-repro
    $ python -m pytest tests/conformance/test_profile_conformance.py -v > /tmp/ca2a-repro/pytest-output.log 2>&1; echo "exit=$?"
    exit=0

## Result

Exit code: 0

The five validity-window cases, verbatim from pytest-output.log:

    tests/conformance/test_profile_conformance.py::test_deleg_007_expired_credential_rejected PASSED [ 17%]
    tests/conformance/test_profile_conformance.py::test_deleg_008_not_yet_valid_credential_rejected PASSED [ 19%]
    tests/conformance/test_profile_conformance.py::test_deleg_009_chain_within_validity_window_accepted PASSED [ 21%]
    tests/conformance/test_profile_conformance.py::test_action_012_expired_delegation_credential_is_provenance_invalid PASSED [ 84%]
    tests/conformance/test_profile_conformance.py::test_action_013_not_yet_valid_delegation_credential_is_provenance_invalid PASSED [ 86%]

The final tally line, verbatim from pytest-output.log:

    ======================== 46 passed, 1 warning in 1.35s =========================

The log carries 46 PASSED lines and 0 FAILED lines.

## Scope

This artifact records that ca2a's own conformance profile passes at the pinned SHA in an
environment outside the ca2a CI. It makes no statement about APS and grades no APS
artifact. Case definitions are ca2a's own: tests/conformance/README.md rows ACTION-012 and
ACTION-013, and the ca2a CHANGELOG.md entry for the delegation credential validity window
added by PR #110, referenced by path at the pinned SHA and not quoted here.
