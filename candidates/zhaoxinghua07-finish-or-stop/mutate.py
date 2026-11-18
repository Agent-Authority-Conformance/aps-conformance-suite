#!/usr/bin/env python3
"""Mutation test for the zhaoxinghua07-finish-or-stop checker.

Each mutant weakens or distorts one rule of check.py at a time - including a
version that always answers conformant and one that always answers
nonconformant - and the run fails unless at least one case catches every
mutant.

Usage: python3 -I mutate.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def load_cases():
    with open(os.path.join(HERE, "vectors.json"), encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def mutant_always_conformant(case):
    return "conformant"


def mutant_always_nonconformant(case):
    return "nonconformant"


def mutant_unsigned_ignores_signature(case):
    # Treats every token as signed: only the outcome shape decides.
    denied = case["outcome"].get("decision") == "DENY"
    return "conformant" if not denied else "nonconformant"


def mutant_unsigned_inverted(case):
    if case["rule"] != "R-UNSIGNED":
        return case["expect"]  # does not apply to other rules' cases
    verdict = check.verdict_unsigned(case)
    return "nonconformant" if verdict == "conformant" else "conformant"


def mutant_quorum_ignores_quorum(case):
    # Treats quorum as always met: only the outcome shape decides.
    executed = (
        case["outcome"].get("decision") == "EXECUTED"
        or case["outcome"].get("executions_performed", 0) > 0
    )
    return "conformant" if executed else "nonconformant"


def mutant_quorum_inverted(case):
    if case["rule"] != "R-QUORUM":
        return case["expect"]  # does not apply to other rules' cases
    verdict = check.verdict_quorum(case)
    return "nonconformant" if verdict == "conformant" else "conformant"


MUTANTS = [
    ("always-conformant", mutant_always_conformant),
    ("always-nonconformant", mutant_always_nonconformant),
    ("unsigned-ignores-signature", mutant_unsigned_ignores_signature),
    ("unsigned-inverted", mutant_unsigned_inverted),
    ("quorum-ignores-quorum", mutant_quorum_ignores_quorum),
    ("quorum-inverted", mutant_quorum_inverted),
]


def main():
    cases = load_cases()
    killed = 0
    for name, fn in MUTANTS:
        caught = any(fn(c) != c["expect"] for c in cases)
        killed += caught
        print("%s: %s" % (name, "killed" if caught else "SURVIVED"))
    print("%d/%d mutants killed" % (killed, len(MUTANTS)))
    sys.exit(0 if killed == len(MUTANTS) else 1)


if __name__ == "__main__":
    main()
