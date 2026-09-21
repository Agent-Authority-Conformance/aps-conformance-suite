#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python runner for the action-result-binding family.

It runs the pinned agent-passport-system 4.0.0 for Python over each case on the one
receipt surface that release has, `validate_receipt_stage_v1`, and holds it to what
vectors.json records under `sdk_py.validate_receipt_stage_v1`.

It also checks the second half of the sdk_py block: that this release really has no
counterpart to the TypeScript `verifyReceiptWithDecisionV1`. That claim is executable
here rather than asserted in prose, so a future Python release that adds a composite
verifier makes this runner fail instead of leaving a stale `not_implemented` on disk.

The `draft03` and `replay_policy` blocks are printed for the reader and are not
asserted: they come from the published text and from a third party's report.

The prev comparison of section 5.3.3 line 1104 is not implemented here and is not an
SDK result on either side. See verify.ts for the one labelled harness line.

This is a MANUAL run, not part of `npm test`, for the same reason C19's validate.py is:
the Python CI job keeps SDK dependencies out. Run it against an interpreter that has the
released agent-passport-system 4.0.0 installed, which in practice means a dedicated
virtualenv rather than a system python3 that may carry an editable install of an
unreleased checkout:

    PY=/path/to/venv-aps-py-4.0.0/bin/python
    "$PY" fixtures/action-result-binding/validate.py

This runner refuses to report on any other version.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import sys
from pathlib import Path

from agent_passport.receipt_core import validate_receipt_stage_v1

HERE = Path(__file__).resolve().parent

# The sdk_py block in vectors.json is a record of one pinned release. Reporting it as
# agreement under a different release would make the record say something it never
# established, so the version is checked before anything is run.
PINNED_PYTHON_SDK = "4.0.0"

_installed = importlib.metadata.version("agent-passport-system")
if _installed != PINNED_PYTHON_SDK:
    print(
        f"agent-passport-system {_installed} is installed; vectors.json records "
        f"{PINNED_PYTHON_SDK}. Run this against the pinned release.",
        file=sys.stderr,
    )
    sys.exit(2)

# The names a composite receipt/decision verifier would plausibly carry in this SDK.
# If any of them ever resolves, the not_implemented record in vectors.json is stale.
COMPOSITE_CANDIDATE_NAMES = (
    "verify_receipt_with_decision_v1",
    "verify_receipt_with_decision",
    "VerifyReceiptWithDecisionV1",
)


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def composite_verifier_present() -> list[str]:
    """Names of any composite receipt/decision verifier this release exposes."""
    found = []
    for module_name in ("agent_passport", "agent_passport.receipt_core"):
        module = importlib.import_module(module_name)
        for candidate in COMPOSITE_CANDIDATE_NAMES:
            if hasattr(module, candidate):
                found.append(f"{module_name}.{candidate}")
    return found


chain = read_json("chain.json")
vectors = read_json("vectors.json")

boundary = chain["identities"]["enforcement_boundary"]

passed = 0
failed_ids: list[str] = []

for vector in vectors["cases"]:
    record = chain["cases"].get(vector["case"])
    if record is None:
        print(f"FAIL {vector['id']}: chain.json has no case named {vector['case']}", file=sys.stderr)
        failed_ids.append(vector["id"])
        continue

    result = validate_receipt_stage_v1(record, boundary_identity=boundary)
    observed = {
        "status": result["status"],
        "boundary_identity": result["boundary_identity"],
        "stage": result["stage"],
        "failures": result["failures"],
    }

    recorded = vector["sdk_py"]["validate_receipt_stage_v1"]
    problems = [
        f"{key}: recorded {json.dumps(recorded[key], sort_keys=True)}, "
        f"observed {json.dumps(observed[key], sort_keys=True)}"
        for key in observed
        if json.dumps(recorded[key], sort_keys=True) != json.dumps(observed[key], sort_keys=True)
    ]

    composite_record = vector["sdk_py"]["composite_decision_verifier"]
    if composite_record["result"] != "not_implemented":
        problems.append(
            "composite_decision_verifier: vectors.json records "
            f"{composite_record['result']!r}; this runner only knows how to check "
            "not_implemented"
        )

    if problems:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        failed_ids.append(vector["id"])
    else:
        passed += 1
        print(f"PASS {vector['id']}")

    codes = [failure["code"] for failure in observed["failures"]]
    sections = "; ".join(vector["draft03"]["sections"])
    note = vector["replay_policy"]["note"]
    print(f"  draft03                              {vector['draft03']['outcome']}  [{sections}]")
    print(
        f"  sdk_py validate_receipt_stage_v1     status={observed['status']} "
        f"boundary_identity={observed['boundary_identity']} "
        f"stage={json.dumps(observed['stage'])} failures={json.dumps(codes)}"
    )
    print("  sdk_py composite verifier            not_implemented in agent-passport-system 4.0.0 for Python")
    print(
        f"  sdk_ts                               run npm run verify:action-result-binding "
        f"separately; two TypeScript surfaces are recorded there"
    )
    print(
        f"  replay_policy (reported, not run)    {vector['replay_policy']['outcome']}"
        + (f" ({note})" if note else "")
    )
    print(f"  classification                       {vector['classification']}")

present = composite_verifier_present()
if present:
    print(
        "FAIL composite verifier record is stale: this Python release exposes "
        + ", ".join(present)
        + ". vectors.json records not_implemented for every case.",
        file=sys.stderr,
    )
    failed_ids.append("composite-verifier-absence")
else:
    print("PASS composite-verifier-absence: no verify_receipt_with_decision counterpart in this release")

total = len(vectors["cases"]) + 1
print(f"action-result-binding Python: {passed + (0 if present else 1)}/{total} passed")
sys.exit(1 if failed_ids else 0)
