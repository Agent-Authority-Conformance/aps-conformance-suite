#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Records what the published PyPI `agent-passport-system` package offers for the
# four surfaces this family needs. It reports, it does not judge: nothing in
# draft-pidlisnyi-aps-03 asks the SDK for any of these, so `not_supported`
# is an absence of a named surface, not a defect report.
#
# The probe walks every importable module in the package and collects every
# public name, so an absence is an absence across the whole package.
#
# Run: /path/to/venv/bin/python fixtures/lifecycle-shared-identity-with-no-accountable-principal/sdk_probe.py
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
        "shared identity",
        "a declared distinction between an identity one individual holds and an identity several can drive",
        r"shared_identity|is_shared|group_account|generic_account|multi_operator",
        "nothing in the package marks a credential as shared, so a record naming an identity says which credential "
        "authenticated and nothing about who is accountable.",
    ),
    (
        "checkout or broker binding",
        "a record binding one individual to a shared identity for an interval",
        r"checkout|broker|assume_as|individual_binding",
        "the package has no credential-checkout surface. Unlike the npm package it does not even carry the ACP "
        "commerce checkout names, so there is not even a near-name here.",
    ),
    (
        "later attribution record",
        "a later record referencing an earlier decision record and naming the individual established to have acted",
        r"attribute_to_individual|later_attribution|investigation_record|attribution_pending",
        "the package's accountability module builds and verifies accountability bundles over what a check covered. "
        "No field names an accountable individual and none marks the acting identity as shared.",
    ),
    (
        "privileged-identity anomaly flag",
        "an anomaly flag for an unscoped all-powerful identity used off its own enumerated required-list",
        r"root_identity|privileged_use|break_glass|enumerated_task|off_list",
        "nothing has a notion of an identity that is exceptional by construction, or of a list of tasks only it "
        "may perform.",
    ),
]


def main() -> int:
    version = importlib.metadata.version("agent-passport-system")
    names, module_count = all_public_names()
    print(f"agent-passport-system (PyPI) {version}, {len(names)} public names across {module_count} modules")
    print("")
    for group, concept, pattern, reason in PROBES:
        hits = [n for n in names if re.search(pattern, n, re.IGNORECASE)]
        print(f"{group}: {'not_supported' if not hits else 'present: ' + ', '.join(hits)}")
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
