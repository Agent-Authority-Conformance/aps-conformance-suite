#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python runner for the action-result-binding family.

It runs the pinned agent-passport-system 4.0.0 for Python over each case on the one
receipt surface that release has, `validate_receipt_stage_v1`, and holds it to what
vectors.json records under `sdk_py.validate_receipt_stage_v1`.

It also exercises three things that surface does not reach on its own:

  the three chain receipts (intent, permit decision, deny decision), each with its
  receipt_id recomputed, its signatures verified over the section 5.2 signature payload
  and its stage validated, held to what vectors.json records under `chain_receipts`

  case 2's own receipt_id and boundary signature, which the stage surface skips because
  it fails that record on its schema first

  which decision's evidence each case is checked against, recomputed through the Python
  `build_decision_ref_v1` over that record's own action_ref and the named decision
  evidence, and held to the same `decision_ref_binding` values verify.ts is held to. This
  is HARNESS EVIDENCE, not a Python composite verifier result. The pinned release has no
  counterpart to verifyReceiptWithDecisionV1 and that record stays not_implemented; what
  this adds is the same digest recomputation on the Python side, so the digests
  vectors.json pins are not a statement of one implementation alone

  the second half of the sdk_py block: that this release really has no counterpart to
  the TypeScript `verifyReceiptWithDecisionV1`. That claim is executable here rather
  than asserted in prose. The probe imports every module in the installed
  `agent_passport` package and looks for any callable whose name contains both "receipt"
  and "decision" together with "verify" or "check". A release that adds a composite
  verifier under a name of that shape makes this runner fail instead of leaving a stale
  `not_implemented` on disk; a release that adds one under a name outside that shape
  would not be caught here.

The `draft03` and `replay_policy` blocks are printed for the reader and are not
asserted: one comes from the published text, the other is this suite's own derivation
from a third party's stated rules.

The prev comparison of section 5.3.3 lines 1104 to 1105 is not implemented here and is
not an SDK result on either side. See verify.ts for the one labelled harness line. The
decision_ref recomputation described above is likewise not an SDK verdict on either side:
it is the digest builder run directly, and it is labelled harness evidence wherever it
appears.

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
import pkgutil
import sys
from pathlib import Path

import agent_passport
from agent_passport import verify
from agent_passport.receipt_core import (
    build_decision_ref_v1,
    compute_receipt_id_v1,
    receipt_signature_payload_v1,
    validate_receipt_stage_v1,
)

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


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True)


def composite_verifier_present() -> list[str]:
    """Names of any composite receipt/decision verifier this release exposes.

    Every module in the installed agent_passport package is imported and every callable
    it binds is considered. A name qualifies when it contains "receipt" and "decision"
    and either "verify" or "check". That shape, not a fixed list of names, is what this
    probe covers; a verifier named outside it is not found here.
    """
    modules = [agent_passport]
    for info in pkgutil.walk_packages(agent_passport.__path__, agent_passport.__name__ + "."):
        try:
            modules.append(importlib.import_module(info.name))
        except Exception as exc:  # a module this release cannot import cannot expose one
            print(f"  note: {info.name} did not import ({exc})", file=sys.stderr)

    found: list[str] = []
    for module in modules:
        for name, obj in vars(module).items():
            if not callable(obj):
                continue
            low = name.lower()
            if "receipt" in low and "decision" in low and ("verify" in low or "check" in low):
                qualified = f"{module.__name__}.{name}"
                if qualified not in found:
                    found.append(qualified)
    return sorted(found)


def observed_signatures(record, keys) -> list[dict]:
    out = []
    for signature in record["signatures"]:
        descriptor = {
            "signer": signature["signer"],
            "key_id": signature["key_id"],
            "alg": signature["alg"],
        }
        key = keys.get(signature["key_id"])
        out.append(
            {
                "signer": signature["signer"],
                "key_id": signature["key_id"],
                "verified": bool(
                    key is not None
                    and verify(receipt_signature_payload_v1(record, descriptor), signature["value"], key)
                ),
            }
        )
    return out


chain = read_json("chain.json")
vectors = read_json("vectors.json")

boundary = chain["identities"]["enforcement_boundary"]
keys = chain["verification_keys"]

print(
    "MATCH means observed SDK behavior equals the recorded expectation. "
    "It is not a conformance verdict."
)

passed = 0
failed_ids: list[str] = []

# ---------------------------------------------------------------------------
# The three chain receipts. The cases below are all action-result records; the intent
# and the two decisions they hang off are exercised here, on the same three surfaces,
# so a regression in them fails this runner rather than passing unnoticed.
# ---------------------------------------------------------------------------

receipt_checks = len(vectors["chain_receipts"]["expected"])
receipts_matched = 0

for expected in vectors["chain_receipts"]["expected"]:
    record = chain["receipts"].get(expected["receipt"])
    problems: list[str] = []

    if record is None:
        problems.append(f"chain.json has no receipt named {expected['receipt']}")
    else:
        if record["receipt_type"] != expected["receipt_type"]:
            problems.append(
                f"receipt_type: recorded {expected['receipt_type']!r}, "
                f"observed {record['receipt_type']!r}"
            )

        id_recomputed = compute_receipt_id_v1(record) == record["receipt_id"]
        if id_recomputed != expected["receipt_id_recomputed"]:
            problems.append(
                f"receipt_id_recomputed: recorded {expected['receipt_id_recomputed']}, "
                f"observed {id_recomputed}"
            )

        signatures = observed_signatures(record, keys)
        if canonical(signatures) != canonical(expected["signatures"]):
            problems.append(
                f"signatures: recorded {canonical(expected['signatures'])}, "
                f"observed {canonical(signatures)}"
            )

        stage = validate_receipt_stage_v1(record, boundary_identity=boundary)
        stage_observed = {
            "status": stage["status"],
            "boundary_identity": stage["boundary_identity"],
            "stage": stage["stage"],
            "failures": stage["failures"],
        }
        problems.extend(
            f"stage {key}: recorded {canonical(expected['stage'][key])}, "
            f"observed {canonical(stage_observed[key])}"
            for key in stage_observed
            if canonical(expected["stage"][key]) != canonical(stage_observed[key])
        )

    if problems:
        print(f"FAIL chain receipt {expected['receipt']}", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        failed_ids.append(f"chain receipt {expected['receipt']}")
    else:
        receipts_matched += 1
        print(f"MATCH chain receipt {expected['receipt']}")

print(f"action-result-binding Python chain receipts: {receipts_matched}/{receipt_checks} matched")

# ---------------------------------------------------------------------------
# The cases.
# ---------------------------------------------------------------------------

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
        f"{key}: recorded {canonical(recorded[key])}, observed {canonical(observed[key])}"
        for key in observed
        if canonical(recorded[key]) != canonical(observed[key])
    ]

    composite_record = vector["sdk_py"]["composite_decision_verifier"]
    if composite_record["result"] != "not_implemented":
        problems.append(
            "composite_decision_verifier: vectors.json records "
            f"{composite_record['result']!r}; this runner only knows how to check "
            "not_implemented"
        )

    # Which decision's evidence this case is checked against, recomputed on the Python
    # side. HARNESS EVIDENCE, not a Python composite verifier result: this release has no
    # composite verifier, and the sub-block above still records not_implemented. What runs
    # here is build_decision_ref_v1 over this record's own action_ref and the evidence the
    # case names, the same inputs verify.ts gives buildDecisionRefV1, held to the same
    # pinned digest. Agreement means the two SDKs' digest builders agree on these inputs;
    # it is not a verdict on any record.
    binding_line = None
    binding = vector.get("decision_ref_binding")
    if binding is not None:
        evidence = chain["decision_evidence"].get(vector["decision_evidence"])
        if evidence is None:
            problems.append(
                f"decision_ref_binding: chain.json has no decision evidence named "
                f"{vector['decision_evidence']}"
            )
        elif binding["evidence"] != vector["decision_evidence"]:
            problems.append(
                f"decision_ref_binding.evidence: records {binding['evidence']!r} but the "
                f"case reads {vector['decision_evidence']!r}"
            )
        else:
            recomputed = build_decision_ref_v1(
                action_ref=record["action_ref"],
                authority_state=evidence["authority_state"],
                policy_input=evidence["policy_input"],
                decision_context=evidence["decision_context"],
                decision_output=evidence["decision_output"],
            )["decision_ref"]
            binding_observed = {
                "recomputed_from_permit_evidence": recomputed,
                "equals_record_decision_ref": recomputed == record["decision_ref"],
                "equals_permit_decision_ref": recomputed == chain["decision_refs"]["permit"],
                "record_decision_ref_is_deny": record["decision_ref"] == chain["decision_refs"]["deny"],
            }
            problems.extend(
                f"decision_ref_binding {key}: recorded {canonical(binding[key])}, "
                f"observed {canonical(binding_observed[key])}"
                for key in binding_observed
                if canonical(binding[key]) != canonical(binding_observed[key])
            )
            binding_line = (
                f"evidence={vector['decision_evidence']} recomputed={recomputed} "
                f"equals_record_decision_ref={binding_observed['equals_record_decision_ref']}"
            )

    # Case 2's own sealing. The stage surface fails that record on its schema before any
    # signature is verified, so without this the one thing the section 5.2 sealing path
    # exists to produce would never be exercised by either runner.
    sealed = vector.get("sealed_signature_check")
    if sealed is not None:
        id_recomputed = compute_receipt_id_v1(record) == record["receipt_id"]
        if id_recomputed != sealed["receipt_id_recomputed"]:
            problems.append(
                f"sealed_signature_check receipt_id_recomputed: recorded "
                f"{sealed['receipt_id_recomputed']}, observed {id_recomputed}"
            )
        signatures = observed_signatures(record, keys)
        if canonical(signatures) != canonical(sealed["signatures"]):
            problems.append(
                f"sealed_signature_check signatures: recorded {canonical(sealed['signatures'])}, "
                f"observed {canonical(signatures)}"
            )

    if problems:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        failed_ids.append(vector["id"])
    else:
        passed += 1
        print(f"MATCH {vector['id']}")

    codes = [failure["code"] for failure in observed["failures"]]
    sections = "; ".join(vector["draft03"]["sections"])
    replay = vector["replay_policy"]
    replay_value = replay["outcome"] if replay["status"] == "derived" else replay["status"]
    print(f"  draft03                              {vector['draft03']['outcome']}  [{sections}]")
    print(
        f"  sdk_py validate_receipt_stage_v1     status={observed['status']} "
        f"boundary_identity={observed['boundary_identity']} "
        f"stage={json.dumps(observed['stage'])} failures={json.dumps(codes)}"
    )
    print("  sdk_py composite verifier            not_implemented in agent-passport-system 4.0.0 for Python")
    if binding_line is not None:
        print(f"  decision_ref binding (harness, not SDK verdict) {binding_line}")
    print(
        f"  sdk_ts                               run npm run verify:action-result-binding "
        f"separately; two TypeScript surfaces are recorded there"
    )
    print(f"  replay_policy (derived from stated rules, not run) {replay_value}")
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
    print(
        "MATCH composite-verifier-absence: no callable in the installed agent_passport "
        "package names a receipt and a decision together with verify or check"
    )

total = len(vectors["cases"]) + receipt_checks + 1
matched = passed + receipts_matched + (0 if present else 1)
print(f"action-result-binding Python: {matched}/{total} matched")
sys.exit(1 if failed_ids else 0)
