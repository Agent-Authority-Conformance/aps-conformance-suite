#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Reference runner for the key-rotation-historical fixture, Python side.
# Exercises draft-pidlisnyi-aps-03 section 2.4: a resolver MUST select the
# key version authorized at the artifact's issued_at, not the key current at
# verification time. See verify.ts for the full model description; this
# runner follows the same two-policy, both-directions pattern as
# fixtures/runtime-authority-denial-continuity.

import json
import sys
from pathlib import Path

from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("delegations.json")
vectors = read_json("vectors.json")

if (
    fixture.get("_placeholder")
    or not isinstance(fixture.get("now"), str)
    or not isinstance(fixture.get("rotation_boundary"), str)
    or not isinstance(fixture.get("keys"), dict)
    or "K1" not in fixture["keys"]
    or "K2" not in fixture["keys"]
    or not isinstance(fixture.get("records"), dict)
):
    print(
        "key-rotation-historical delegations.json is still a placeholder. Mint the five "
        "root delegations with the SDK before running.",
        file=sys.stderr,
    )
    sys.exit(2)


def historical_resolver(_issuer, verification_method, issued_at):
    if verification_method != fixture["verification_method"]:
        return {"outcome": "not_found"}
    return fixture["keys"]["K1"] if issued_at < fixture["rotation_boundary"] else fixture["keys"]["K2"]


def current_key_only_resolver(_issuer, verification_method, _issued_at):
    if verification_method != fixture["verification_method"]:
        return {"outcome": "not_found"}
    return fixture["keys"]["K2"]


def actual_failure(result):
    first = result.failures[0] if result.failures else None
    return {
        "code": first.code if first is not None else None,
        "index": first.index if first is not None else None,
    }


def matches(result, expected):
    failure = actual_failure(result)
    return (
        result.state == expected["state"]
        and (result.state == "valid") == (expected["state"] == "valid")
        and failure["code"] == expected["failure_code"]
        and failure["index"] == expected["failure_index"]
        and (expected["failure_code"] is not None or len(result.failures) == 0)
    )


def run_one(case_id, resolve_verification_key):
    vector = next(c for c in vectors["cases"] if c["id"] == case_id)
    record = fixture["records"][vector["record"]]
    return verify_authority_delegation_chain(
        [record],
        now=fixture["now"],
        resolve_verification_key=resolve_verification_key,
        trust_root=lambda _root: True,
        resolve_revocation=lambda _delegation: "active",
    )


def run_policy(policy, resolve_verification_key):
    observed_fail_ids = []
    matched = 0
    print(f"policy: {policy['name']}")
    for case_id in policy["runs_against"]:
        vector = next(c for c in vectors["cases"] if c["id"] == case_id)
        result = run_one(case_id, resolve_verification_key)
        if matches(result, vector["expected"]):
            matched += 1
            print(f"  MATCH    {case_id}  state={result.state}")
        else:
            observed_fail_ids.append(case_id)
            failure = actual_failure(result)
            print(f"  MISMATCH {case_id}", file=sys.stderr)
            print(f"             expected: {json.dumps(vector['expected'], sort_keys=True)}", file=sys.stderr)
            print(
                "             actual:   "
                + json.dumps(
                    {"state": result.state, "failure_code": failure["code"], "failure_index": failure["index"]},
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
    return matched, len(policy["runs_against"]), observed_fail_ids


ok = True

historical_matched, historical_total, _ = run_policy(vectors["policies"]["historical"], historical_resolver)
if historical_matched != historical_total:
    ok = False
    print(f"FAIL historical-key-resolution matched {historical_matched}/{historical_total}, expected all", file=sys.stderr)
else:
    print(f"ok   historical-key-resolution matched all {historical_total} cases")

current_matched, current_total, observed_current_fail = run_policy(
    vectors["policies"]["current_key_only"], current_key_only_resolver
)
declared_current_fail = sorted(vectors["policies"]["current_key_only"]["expected_fail_ids"])
observed_current_fail = sorted(observed_current_fail)
if declared_current_fail != observed_current_fail:
    ok = False
    print(
        f"FAIL current-key-only declared fail set {declared_current_fail}, observed {observed_current_fail}",
        file=sys.stderr,
    )
else:
    print(f"ok   current-key-only failed exactly the declared set: {declared_current_fail}")

# KRH-05: run and record the observed result. Not scored pass/fail: this
# vector documents a gap between draft-03 section 2.4's evidentiary
# requirement and what the reference SDKs' resolver surface can express.
gap_vector = next(c for c in vectors["cases"] if c["id"] == "KRH-05-indeterminate-boundary-no-evidence")
gap_result = run_one(gap_vector["id"], historical_resolver)
gap_failure = actual_failure(gap_result)
gap_observed = {"state": gap_result.state, "failure_code": gap_failure["code"], "failure_index": gap_failure["index"]}
gap_observed_matches_recorded = gap_observed == gap_vector["observed"]
gap_diverges_from_draft = gap_observed != gap_vector["draft_required"]
print(f"gap  {gap_vector['id']}  observed={json.dumps(gap_observed, sort_keys=True)} draft_required={json.dumps(gap_vector['draft_required'], sort_keys=True)}")
if not gap_vector.get("known_sdk_gap") or not gap_observed_matches_recorded or not gap_diverges_from_draft:
    ok = False
    print(
        "FAIL KRH-05 gap bookkeeping: expected known_sdk_gap true, observed result matching the recorded "
        "observed field, and observed diverging from draft_required",
        file=sys.stderr,
    )
else:
    print("ok   KRH-05 observed result matches the recorded known_sdk_gap, and diverges from draft_required as documented")

print(
    "PASSED: historical-key-resolution matched every vector, current-key-only failed exactly the declared set"
    if ok
    else "FAILED"
)
sys.exit(0 if ok else 1)
