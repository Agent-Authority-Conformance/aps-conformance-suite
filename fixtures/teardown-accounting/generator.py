#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

PROPOSED_PATH = "fixtures/teardown-accounting/PROPOSED.md"
PROPOSED_SHA256 = "5d9a398bee5f675e95298ae1e1ba1af11068a30e8ba8a7151b5a2f371edf3a0d"

STIPULATIONS = [
    "sink configurations and runtime bindings are authentic",
    "admission sequence is append only",
    "distinct attestor identifiers denote distinct parties",
]

def base_input():
    return {
        "stipulations": list(STIPULATIONS),
        "scope": {
            "declared_sinks": ["sink-a", "sink-b"],
            "epoch": "E0",
            "boundary": "M",
        },
        "sink_configurations": {
            "sink-a": {
                "epoch": "E0",
                "accepts_only_through": "M",
                "digest": "cfg-a-v1",
            },
            "sink-b": {
                "epoch": "E0",
                "accepts_only_through": "M",
                "digest": "cfg-b-v1",
            },
        },
        "runtime_bindings": {
            "sink-a": {
                "config_digest": "cfg-a-v1",
                "from": "2026-09-20T09:00:00Z",
                "to": "2026-09-20T13:00:00Z",
            },
            "sink-b": {
                "config_digest": "cfg-b-v1",
                "from": "2026-09-20T09:00:00Z",
                "to": "2026-09-20T13:00:00Z",
            },
        },
        "admissions": [
            {"seq": 1, "descendant_id": "d1"},
            {"seq": 2, "descendant_id": "d2"},
            {"seq": 3, "descendant_id": "d3"},
        ],
        "cutoff": {
            "at": "2026-09-20T11:00:00Z",
            "committed_final_seq": 3,
            "committed_members": ["d1", "d2", "d3"],
        },
        "cutoff_ordering_evidence": {
            "attestor": "time-witness-b",
            "covers_from": "2026-09-20T10:59:00Z",
            "covers_to": "2026-09-20T11:01:00Z",
        },
        "stop_admitting": {
            "boundary": "M",
            "epoch": "E0",
            "admits_epoch": False,
            "asserted_by": "boundary-operator-a",
            "observed_at": "2026-09-20T11:05:00Z",
        },
        "teardown": {"processed": ["d1", "d2", "d3"]},
    }

def case(cid, title, inp, verdict, reason):
    return {
        "id": cid,
        "group": "teardown_accounting",
        "label": "candidate_against_proposed",
        "title": title,
        "input": inp,
        "expected": {"verdict": verdict, "reason": reason},
    }

def build():
    cases = []

    x = base_input()
    cases.append(case(
        "TA-ICAM-01", "Positive control", x,
        "valid", "teardown_accounts_for_accepted_set_under_stipulated_basis"
    ))

    x = base_input()
    del x["runtime_bindings"]["sink-b"]
    cases.append(case(
        "TA-ICAM-02", "Runtime binding for sink-b removed", x,
        "not_established", "runtime_binding_not_established"
    ))

    x = base_input()
    x["cutoff_ordering_evidence"] = None
    cases.append(case(
        "TA-ICAM-03", "Cutoff ordering evidence absent", x,
        "not_established", "cutoff_ordering_not_established"
    ))

    x = base_input()
    x["cutoff_ordering_evidence"]["attestor"] = x["stop_admitting"]["asserted_by"]
    cases.append(case(
        "TA-ICAM-04", "Ordering attested by stop asserter", x,
        "not_established", "cutoff_ordering_independence_not_established"
    ))

    x = base_input()
    x["cutoff_ordering_evidence"]["covers_from"] = "2026-09-20T11:01:00Z"
    x["cutoff_ordering_evidence"]["covers_to"] = "2026-09-20T11:02:00Z"
    cases.append(case(
        "TA-ICAM-05", "Ordering interval misses cutoff", x,
        "not_established", "cutoff_ordering_not_established"
    ))

    x = base_input()
    x["cutoff_ordering_evidence"]["covers_to"] = "2026-09-20T11:06:00Z"
    cases.append(case(
        "TA-ICAM-06", "Ordering interval ends after stop observation", x,
        "not_established", "cutoff_ordering_not_established"
    ))

    x = base_input()
    x["teardown"]["processed"] = ["d1", "d2"]
    cases.append(case(
        "TA-ICAM-07", "Accepted descendant omitted from teardown", x,
        "invalid", "accepted_descendant_missing_from_teardown"
    ))

    x = base_input()
    x["cutoff"]["committed_members"] = ["d1", "d2"]
    cases.append(case(
        "TA-ICAM-08", "Commitment disagrees with admissions", x,
        "not_established", "accepted_set_not_committed"
    ))

    return {
        "family": "teardown-accounting",
        "status": "candidate_against_proposed",
        "provenance": "ICAM/danyka-icam contributed vectors generated deterministically from the exploratory #144 generator lineage; generator revision and regeneration command are supplied beside this file.",
        "proposed_text": {
            "path": PROPOSED_PATH,
            "sha256": PROPOSED_SHA256,
        },
        "negative_control": {
            "id": "C1-ordering-taken-as-given",
            "defect": "Shares validation and every check outside rule 3 with the reference. Null ordering evidence still returns cutoff_ordering_not_established; present ordering evidence is taken as given, skipping the interval check and the attestor check.",
            "declared_fail_set": ["TA-ICAM-04", "TA-ICAM-05", "TA-ICAM-06"],
        },
        "cases": cases,
    }

def main():
    out = Path(__file__).with_name("vectors.json")
    doc = build()
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(out)
    print(hashlib.sha256(out.read_bytes()).hexdigest())

if __name__ == "__main__":
    main()
