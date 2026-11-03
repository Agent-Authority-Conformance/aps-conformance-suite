#!/usr/bin/env python3
"""Checker for the zhaoxinghua07-finish-or-stop candidate vectors.

Recomputes each case's verdict from its input and outcome, compares the verdict
with the pre-declared `expect`, and prints an agree/total line.

Usage: python3 -I check.py vectors.json
"""

import json
import sys


def is_unattested(token):
    # A token with no attestation carries no attested capability, whatever its
    # signature field claims; an absent key reads as no attestation.
    return token.get("attestation") is None


def verdict_unsigned(case):
    token = case["input"]["capability_token"]
    outcome = case["outcome"]
    denied = outcome.get("decision") == "DENY"
    # A fail-closed denial means the action did not execute either.
    clean_denial = denied and outcome.get("executions_performed", 0) == 0
    if is_unattested(token):
        return "conformant" if clean_denial else "nonconformant"
    # A signed, attested token may be honored; denying it without cause is not.
    return "conformant" if not denied else "nonconformant"


def verdict_quorum(case):
    required = case["input"]["quorum"]["required"]
    eligible = len(case["input"]["eligible_modules"])
    executed = (
        case["outcome"].get("decision") == "EXECUTED"
        or case["outcome"].get("executions_performed", 0) > 0
    )
    if eligible >= required:
        return "conformant" if executed else "nonconformant"
    # Quorum unmet: the operation must present the blocked state with zero
    # executions; an allow, even with zero executions, does not.
    blocked = (
        case["outcome"].get("decision") == "BLOCKED"
        and case["outcome"].get("executions_performed", 0) == 0
    )
    return "conformant" if blocked else "nonconformant"


RULES = {
    "R-UNSIGNED": verdict_unsigned,
    "R-QUORUM": verdict_quorum,
}


def main():
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    total = 0
    agree = 0
    for case in doc["cases"]:
        total += 1
        verdict = RULES[case["rule"]](case)
        ok = verdict == case["expect"]
        agree += ok
        print("%s: %s (expect %s) %s" % (
            case["id"], verdict, case["expect"], "ok" if ok else "MISMATCH"))
    print("%d/%d agree" % (agree, total))
    sys.exit(0 if agree == total else 1)


if __name__ == "__main__":
    main()
