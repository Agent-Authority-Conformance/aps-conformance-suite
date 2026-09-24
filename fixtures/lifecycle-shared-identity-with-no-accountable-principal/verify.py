#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Independent Python runner for the
# lifecycle-shared-identity-with-no-accountable-principal candidate family.
#
# Written from README.md and vectors.json rather than ported from harness.ts.
# The accountability rule here is a sequence of guard clauses over pre-filtered
# lists rather than the flag-parameterized function the TypeScript harness uses,
# so the two implementations agreeing is evidence about the rules.
#
# The only third-party import is the published PyPI agent-passport-system, for
# its RFC 8785 (JCS) canonicalization primitive.
#
# Run: /path/to/venv/bin/python \
#        fixtures/lifecycle-shared-identity-with-no-accountable-principal/verify.py
#
# Exit 0 on success, 1 on any failure.

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_passport.canonical import canonicalize_jcs

HERE = Path(__file__).resolve().parent
VOCABULARY = {"valid", "invalid", "not_established", "not_yet_effective", "suspended", "restricted"}
ANOMALIES = {"not_applicable", "on_enumerated_list", "off_enumerated_list"}

problems: list[str] = []


def fail(message: str) -> None:
    problems.append(message)
    print(f"  FAIL {message}", file=sys.stderr)


def at(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc)


def anomaly_for(inp: dict) -> str:
    if inp["identity"]["kind"] != "privileged_unscoped":
        return "not_applicable"
    on_list = inp["action"]["task"] in inp["privileged_task_list"]
    return "on_enumerated_list" if on_list else "off_enumerated_list"


def accountability(inp: dict, *, check_interval: bool, check_multiplicity: bool) -> tuple[str, str]:
    if inp["identity"]["kind"] == "individual":
        return "valid", "individual_identity_bound"

    with_standing = [c for c in inp["checkouts"] if c["signer_has_standing"]]
    action_at = at(inp["action"]["at"])
    if check_interval:
        covering = [c for c in with_standing if at(c["from"]) <= action_at <= at(c["to"])]
    else:
        covering = list(with_standing)

    if len(covering) == 1:
        return "valid", "individual_bound_by_checkout"
    if len(covering) > 1:
        if check_multiplicity:
            return "not_established", "overlapping_checkouts"
        return "valid", "individual_bound_by_checkout"
    if with_standing:
        return "not_established", "no_checkout_covers_the_action"

    attributions = inp["attribution_records"]
    if not attributions:
        return "not_established", "shared_identity_attribution_pending_or_external"
    referencing = [a for a in attributions if a["references_record_sha256"] == inp["record_sha256"]]
    if not referencing:
        return "not_established", "attribution_does_not_reference_the_record"
    if not any(a["signer_has_standing"] for a in referencing):
        return "not_established", "attribution_without_standing"
    return "valid", "attribution_established_by_later_record"


def reference(inp: dict) -> tuple[str, str, str, str]:
    verdict, reason = accountability(inp, check_interval=True, check_multiplicity=True)
    return inp["chain_state"], verdict, reason, anomaly_for(inp)


def n1_authenticated_is_accountable(inp: dict) -> tuple[str, str, str, str]:
    authorized = inp["chain_state"] == "valid"
    return (
        inp["chain_state"],
        "valid" if authorized else "not_established",
        "individual_identity_bound" if authorized else "shared_identity_attribution_pending_or_external",
        anomaly_for(inp),
    )


def n2_shared_flag_only(inp: dict) -> tuple[str, str, str, str]:
    verdict, reason = accountability(inp, check_interval=False, check_multiplicity=False)
    return inp["chain_state"], verdict, reason, anomaly_for(inp)


CONTROLS = {
    "N1-authenticated-is-accountable": n1_authenticated_is_accountable,
    "N2-shared-flag-only": n2_shared_flag_only,
}


def expected_tuple(case: dict) -> tuple[str, str, str, str]:
    e = case["expected"]
    return e["authority_verdict"], e["accountability_verdict"], e["reason"], e["anomaly"]


def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text())
    pinned = json.loads((HERE / "input-digests.json").read_text())["inputs"]
    cases = vectors["cases"]

    print(f"{vectors['family']}: {len(cases)} cases, Python runner")

    if vectors["status"] != "candidate_against_proposed":
        fail(f"family status is {vectors['status']!r}")
    if not vectors.get("proposed_text", {}).get("commit"):
        fail("family does not name the proposed text it is a candidate against")

    ids = set()
    for case in cases:
        if case["id"] in ids:
            fail(f"{case['id']}: duplicate vector id")
        ids.add(case["id"])
        if case["label"] != "candidate_against_proposed":
            fail(f"{case['id']}: label is {case['label']!r}")
        if not case["id"].startswith(case["case_id"]):
            fail(f"{case['id']}: vector id does not carry its CASES.md case id")
        if not case.get("proposed_text", {}).get("sections"):
            fail(f"{case['id']}: names no proposed text")
        for field in ("authority_verdict", "accountability_verdict"):
            if case["expected"][field] not in VOCABULARY:
                fail(f"{case['id']}: {field} {case['expected'][field]!r} is outside the settled vocabulary")
        if case["expected"]["anomaly"] not in ANOMALIES:
            fail(f"{case['id']}: unknown anomaly value {case['expected']['anomaly']!r}")
    print(f"  ok   labelling: {len(cases)} cases carry candidate_against_proposed and name their proposed text")

    for case in cases:
        digest = hashlib.sha256(canonicalize_jcs(case["input"]).encode("utf-8")).hexdigest()
        if pinned.get(case["id"]) is None:
            fail(f"{case['id']}: no pinned input digest")
        elif digest != pinned[case["id"]]:
            fail(f"{case['id']}: input digest {digest} does not match pinned {pinned[case['id']]}")
    if len(pinned) != len(cases):
        fail(f"input-digests.json pins {len(pinned)} inputs for {len(cases)} cases")
    print(f"  ok   canonical bytes: {len(cases)}/{len(cases)} JCS input digests match, via PyPI canonicalize_jcs")

    if not all(c["input"]["chain_state"] == "valid" for c in cases):
        fail("a case in this family has a chain that is not valid, which is not what the section is about")
    diverging = [
        c
        for c in cases
        if c["expected"]["authority_verdict"] == "valid"
        and c["expected"]["accountability_verdict"] == "not_established"
    ]
    if not diverging:
        fail("no case pairs a valid chain with accountability not_established, so the two axes never diverge")
    print(
        f"  ok   axis separation: all {len(cases)} chains valid, {len(diverging)} cases pair a valid chain "
        f"with accountability not_established"
    )

    matched = 0
    for case in cases:
        got = reference(case["input"])
        want = expected_tuple(case)
        if got != want:
            fail(f"{case['id']}: reference gave {'/'.join(got)}, expected {'/'.join(want)}")
        else:
            matched += 1
    print(f"  ok   reference model: {matched}/{len(cases)} matched")

    for control in vectors["policies"]["negative_controls"]:
        run = CONTROLS.get(control["id"])
        if run is None:
            fail(f"{control['id']}: no control by that id in this runner")
            continue
        observed = [c["id"] for c in cases if run(c["input"]) != expected_tuple(c)]
        declared = sorted(control["declared_fail_set"])
        if sorted(observed) != declared:
            fail(f"{control['id']}: declared fail set {declared}, observed {sorted(observed)}")
        else:
            print(
                f"  ok   {control['id']}: ran all {len(cases)} cases, "
                f"failed exactly {len(declared)} declared ({', '.join(declared)})"
            )
        if not declared:
            fail(f"{control['id']}: a negative control with an empty declared fail set is not a control")
        if len(declared) == len(cases):
            fail(f"{control['id']}: a control that fails every case has no passing baseline and isolates nothing")

    if problems:
        print(f"\nlifecycle-shared-identity Python: FAILED, {len(problems)} problem(s)", file=sys.stderr)
        return 1
    print(f"\nlifecycle-shared-identity Python: {len(cases)}/{len(cases)} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
