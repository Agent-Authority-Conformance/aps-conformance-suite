#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Mode B adapter: APS conformance vectors executed against REMORA's own code.

**This is a NEW adapter, not the one described in the 2026-08-28 run report.**
That adapter (SHA-256 700593e5c3a41cc...) could not be located on the machine
that produced the report, so it is not reused here and its results are not
carried forward. This file was written from the report's method description and
carries its own hash. Anything it reports is a fresh run against fresh pins.

Mode B means the APS SDK computes nothing on REMORA's behalf. Every value is
produced by REMORA's own implementations, imported directly:

- ``remora.enforcement.result_envelope._canonical_bytes`` for the deterministic
  JSON that REMORA has always produced;
- ``remora.interop.jcs.canonicalise`` for the RFC 8785 form added in response to
  the report.

Two canonicalisers are run deliberately. The first reproduces the divergences
the report found; the second shows which of them are closed. Reporting only the
second would hide what changed, and reporting only the first would hide the
work.

Usage, from a clean checkout of the conformance suite with REMORA importable:

    APS_SUITE=/path/to/aps-conformance-suite \\
    PYTHONPATH=/path/to/REMORA-research \\
    python remora_aps_mode_b.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

SUITE = Path(os.environ.get("APS_SUITE", ".")).resolve()

CANONICAL_FIXTURES = (
    "fixtures/canonical-bytes/canonical-bytes-jcs-v1.json",
    "fixtures/canonical-bytes/canonical-bytes-jcs-v2.json",
)
#: REMORA failure codes and the APS reason classes they correspond to. Written
#: down even though the delegation family is not re-run in this pass, because
#: the earlier run used a mapping and did not publish one, and an unpublished
#: mapping makes a 4/4 unauditable: a reader cannot tell whether the decisions
#: matched or whether the mapping was drawn to make them match.
REASON_MAP: dict[str, str] = {
    "scope_exceeds_delegation": "SCOPE_WIDENING",
    "scope_widened_at_link": "SCOPE_WIDENING",
    "delegation_link_expired": "DELEGATION_EXPIRED",
    "envelope_expired": "DELEGATION_EXPIRED",
    "revoked_kid_at_link": "DELEGATION_REVOKED",
    "unknown_or_revoked_kid_at_link": "DELEGATION_REVOKED",
}


def load(rel: str) -> Any:
    return json.loads((SUITE / rel).read_text(encoding="utf-8"))


# --- family 1: canonical bytes ----------------------------------------------


def canonical_family() -> dict[str, Any]:
    """Every vector through both canonicalisers, byte-compared to the fixture."""

    from remora.enforcement.result_envelope import _canonical_bytes
    from remora.interop.jcs import NotCanonicalisable, canonicalise

    results: list[dict[str, Any]] = []
    for rel in CANONICAL_FIXTURES:
        fixture = load(rel)
        for vector in fixture["vectors"]:
            expected = bytes.fromhex(vector["canonical_bytes_hex"])
            row: dict[str, Any] = {
                "fixture": Path(rel).name,
                "vector": vector["name"],
                "expected_sha256": vector["canonical_sha256"],
            }

            legacy, _media = _canonical_bytes(vector["input"])
            row["legacy_match"] = legacy == expected
            row["legacy_sha256"] = hashlib.sha256(legacy).hexdigest()

            try:
                produced = canonicalise(vector["input"])
                row["jcs_match"] = produced == expected
                row["jcs_sha256"] = hashlib.sha256(produced).hexdigest()
                row["jcs_refused"] = False
            except NotCanonicalisable as exc:
                row["jcs_match"] = False
                row["jcs_refused"] = True
                row["jcs_refusal"] = str(exc)

            results.append(row)

    return {
        "family": "canonical-bytes",
        "n_vectors": len(results),
        "legacy_byte_identical": sum(1 for r in results if r["legacy_match"]),
        "jcs_byte_identical": sum(1 for r in results if r["jcs_match"]),
        "jcs_refused": sum(1 for r in results if r.get("jcs_refused")),
        "vectors": results,
    }


def main() -> int:
    if not SUITE.exists():
        print(f"APS_SUITE not found: {SUITE}", file=sys.stderr)
        return 2

    report: dict[str, Any] = {
        "adapter": "remora_aps_mode_b.py",
        "adapter_note": (
            "New adapter. Not the one described in the 2026-08-28 run report; "
            "that file could not be located and its results are not reused."
        ),
        "mode": "B",
        "families": [canonical_family()],
        "not_rerun": [
            {
                "family": "aae-delegation-semantics",
                "reason": (
                    "The 2026-08-28 run reported 4/4 here, but the semantic mapping "
                    "it used was never published: APS DID-bound links were "
                    "represented through REMORA's link-key registry and "
                    "mandate.actions through opaque scope strings. Re-deriving that "
                    "mapping would produce a different mapping and therefore a "
                    "result that cannot be compared to the earlier one. A mapping "
                    "drawn after seeing the expected answers is not evidence."
                ),
            },
            {
                "family": "ed25519-kat",
                "reason": (
                    "The report's 29 known-answer tests were not located as a "
                    "single fixture family at this suite revision, and are not "
                    "claimed here."
                ),
            },
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
