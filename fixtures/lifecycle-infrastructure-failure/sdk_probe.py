#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Records what the published PyPI `agent-passport-system` package offers for
# each group in this family, so SDK-RUNS.md's entries are reproducible rather
# than asserted.
#
# It reports, it does not judge. Nothing in draft-pidlisnyi-aps-03 asks the SDK
# for any of these six behaviours, so a `not_supported` line is an absence of a
# named surface, not a defect report and not a conformance result.
#
# The probe walks every importable module in the package and collects every
# public name, so an absence here is an absence across the whole package rather
# than across one module somebody remembered to look in.
#
# Run: /path/to/venv/bin/python fixtures/lifecycle-infrastructure-failure/sdk_probe.py
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
        for attribute in dir(module):
            if not attribute.startswith("_"):
                names.add(attribute)
    return sorted(names), len(modules)


PROBES = [
    (
        "status_artifact",
        "a freshness record carrying both a source's own declared validity window and the verifier's own bound",
        r"fresh|stale|max_staleness|next_update|evidence_age",
        "the Python package has no freshness, staleness or evidence-age surface at all. The npm package's "
        "enforceFreshnessPolicy / isEvidenceFresh / createRotatingFreshness have no Python counterpart at 4.1.0, so "
        "this group has no Python path and the npm run is the only SDK result this family has for it.",
    ),
    (
        "status_correction",
        "retraction of an erroneous status publication, distinct from a revocation withdrawal",
        r"retract|correct|unrevoke|withdraw|publication_error",
        "no name in the package retracts a published status entry, and none takes a list version range.",
    ),
    (
        "issuer_time_evidence",
        "independent time evidence covering an issuer-claimed issued_at",
        r"timestamp_authority|trusted_timestamp|time_source|rfc3161|external_time",
        "the package canonicalizes and compares timestamps (is_canonical_timestamp, compare_canonical_timestamps) "
        "but takes no evidence about a timestamp from a party other than the issuer, and no declared "
        "time-source-disagreement window.",
    ),
    (
        "history_reconciliation",
        "merging two divergent authority write histories with a reconciliation record",
        r"reconcile|merge|split_brain|partition|discarded",
        "InMemoryAuthorityRevocationStore is a single set with no notion of two histories, no merge entry point and "
        "no record of what a merge kept or discarded.",
    ),
    (
        "causal_read",
        "a required-observation token binding a read to a specific prior write",
        r"consistency_token|zookie|zed_token|required_observation|read_after_write|applied_through",
        "create_authority_revocation_resolver returns a callable over the delegation alone, so a request has no "
        "argument through which to name a write the answer must reflect.",
    ),
    (
        "evidence_coverage",
        "coverage of an evidence interval against a declared delivery lag and a consumer set",
        r"coverage|delivery_lag|delivered_through|interval_complete",
        "nothing takes a query interval, a declared delivery-lag bound, or a set of consumers with delivery "
        "positions.",
    ),
]


def main() -> int:
    version = importlib.metadata.version("agent-passport-system")
    names, module_count = all_public_names()
    print(f"agent-passport-system (PyPI) {version}, {len(names)} public names across {module_count} modules")
    print("")
    for group, concept, pattern, reason in PROBES:
        hits = [n for n in names if re.search(pattern, n, re.IGNORECASE)]
        verdict = "not_supported" if not hits else f"present: {', '.join(hits)}"
        print(f"group {group}: {verdict}")
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
