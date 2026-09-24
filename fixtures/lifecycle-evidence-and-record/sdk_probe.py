#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Records what the published PyPI `agent-passport-system` package offers for the
# two groups in this family. It reports, it does not judge: nothing in
# draft-pidlisnyi-aps-03 asks the SDK for either behaviour, so `not_supported`
# is an absence of a named surface, not a defect report.
#
# The probe walks every importable module in the package and collects every
# public name, so an absence is an absence across the whole package.
#
# Run: /path/to/venv/bin/python fixtures/lifecycle-evidence-and-record/sdk_probe.py
# Exit 0 always.

from __future__ import annotations

import importlib
import importlib.metadata
import pkgutil
import re
import sys

import agent_passport


def all_public_names() -> tuple[list[str], int]:
    modules: list[str] = []

    def walk(package, depth: int = 0) -> None:
        if depth > 4:
            return
        for info in pkgutil.iter_modules(package.__path__):
            full = f"{package.__name__}.{info.name}"
            modules.append(full)
            if info.ispkg:
                try:
                    walk(importlib.import_module(full), depth + 1)
                except Exception:
                    pass

    walk(agent_passport)
    names: set[str] = set()
    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        names.update(a for a in dir(module) if not a.startswith("_"))
    return sorted(names), len(modules)


PROBES = [
    (
        "retention_restriction",
        "a retention duty as a floor: a record must not be destroyed before its duty runs out",
        r"retention|preserv|legal_hold|external_hold|purge",
        "the Python package has no retention surface of any kind. The npm package's isRetentionExpired has no "
        "Python counterpart at 4.1.0, and that call is a ceiling rather than a floor in any case, so this group has "
        "no SDK behavioural result in either language.",
    ),
    (
        "receipt_immutability",
        "a query distinguishing what a receipt decided at its decision instant from what is true now",
        r"decision_time|as_of_decision|historical_verdict|supersedes_receipt|corrects_receipt|void_from_inception",
        "the package canonicalizes and hashes receipts, which is the machinery a bytes-unchanged check sits on, but "
        "has no notion of two different questions being asked of one receipt and no later-record reason vocabulary.",
    ),
]


def main() -> int:
    version = importlib.metadata.version("agent-passport-system")
    names, module_count = all_public_names()
    print(f"agent-passport-system (PyPI) {version}, {len(names)} public names across {module_count} modules")
    print("")
    for group, concept, pattern, reason in PROBES:
        hits = [n for n in names if re.search(pattern, n, re.IGNORECASE)]
        print(f"group {group}: {'not_supported' if not hits else 'present: ' + ', '.join(hits)}")
        print(f"  needed: {concept}")
        print(f"  reason: {reason}")
    print("")
    print(
        "canonicalization: supported. agent_passport.canonical.canonicalize_jcs is what verify.py uses to recompute "
        "every case's pinned RFC 8785 input digest, so every vector in this family does have one PyPI SDK result."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
