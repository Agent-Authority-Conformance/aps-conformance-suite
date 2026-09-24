#!/usr/bin/env python3

import json
import sys
from pathlib import Path

from agent_passport.v2.authority_revocation import (
    InMemoryAuthorityRevocationStore,
    record_authority_revocation,
    verify_authority_revocation,
)

HERE = Path(__file__).resolve().parent


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("fixture.json")
vectors = read_json("vectors.json")

if fixture.get("_placeholder") or "records" not in fixture or "target_delegation" not in fixture:
    print(
        "authority-revocation-record fixture.json is still a placeholder. Run mint.py first.",
        file=sys.stderr,
    )
    sys.exit(2)

delegation = fixture["target_delegation"]
entries = fixture["key_resolver"]["entries"]


def resolve_verification_key(controller, verification_method, at):
    for entry in entries:
        if entry["controller"] == controller and entry["verification_method"] == verification_method:
            if at < entry["key_valid_from"]:
                return {"outcome": "not_found"}
            return entry["public_key_hex"]
    return {"outcome": "not_found"}


passed = 0
total = 0

print("authority-revocation-record Part A: record verification")
for vector in vectors["part_a_record_verification"]["cases"]:
    total += 1
    result = verify_authority_revocation(
        fixture["records"][vector["record"]],
        delegation,
        resolve_verification_key=resolve_verification_key,
    )
    actual = {
        "state": result.state,
        "valid": result.valid,
        "failures": [{"code": item.code, "message": item.message} for item in result.failures],
    }
    expected = vector["expected"]
    ok = actual == expected

    if ok:
        passed += 1
        codes = ",".join(item["code"] for item in actual["failures"]) or "-"
        print(f"PASS {vector['id']} state={actual['state']} failures={codes}")
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print("  expected: " + json.dumps(expected, sort_keys=True), file=sys.stderr)
        print("  actual:   " + json.dumps(actual, sort_keys=True), file=sys.stderr)

print()
print("authority-revocation-record Part B: store first-wins")
store = None
for vector in vectors["part_b_store_first_wins"]["cases"]:
    total += 1
    if vector["store"] == "fresh" or store is None:
        store = InMemoryAuthorityRevocationStore()
    outcome = record_authority_revocation(
        store,
        delegation,
        fixture["records"][vector["offer"]],
        resolve_verification_key=resolve_verification_key,
    )
    stored_id = outcome.stored["revocation_id"] if outcome.stored is not None else None
    actual = {
        "recorded": outcome.recorded,
        "inserted": outcome.inserted,
        "stored_revocation_id": stored_id,
    }
    expected = vector["expected"]
    expected_id = fixture["records"][expected["stored_record"]]["revocation_id"]
    ok = (
        actual["recorded"] == expected["recorded"]
        and actual["inserted"] == expected["inserted"]
        and actual["stored_revocation_id"] == expected_id
    )

    if ok:
        passed += 1
        print(
            f"PASS {vector['id']} recorded={actual['recorded']} "
            f"inserted={actual['inserted']} stored={actual['stored_revocation_id']}"
        )
    else:
        print(f"FAIL {vector['id']}", file=sys.stderr)
        print(
            "  expected: "
            + json.dumps(
                {
                    "recorded": expected["recorded"],
                    "inserted": expected["inserted"],
                    "stored_revocation_id": expected_id,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        print("  actual:   " + json.dumps(actual, sort_keys=True), file=sys.stderr)

print()
print(f"authority-revocation-record Python: {passed}/{total} passed")
sys.exit(0 if passed == total else 1)
