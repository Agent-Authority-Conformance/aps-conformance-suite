#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# SDK support probe for the lifecycle-purpose-exhaustion family, PyPI side.
#
# Claims 1 to 5 are the single-use track's. Claims 6 to 11 are the bounds
# track's, folded in when the two builds were reconciled into one family.
#
# It reports, for each claim this family makes, whether the pinned PyPI SDK
# exposes an API that decides it. A not_supported line is a statement about
# this SDK's surface at this version, not a conformance verdict, and nothing
# here is simulated to fill one in. SDK-RUNS.md records the output verbatim.
#
# Run: python3 fixtures/lifecycle-purpose-exhaustion/sdk_probe.py

import agent_passport as ap
import agent_passport.crypto as crypto
from agent_passport import receipt_core
from agent_passport.v2 import authority_delegation as adl

MODULES = (adl, ap, crypto, receipt_core)

CLAIMS = [
    [
        "1. chain verdict for a presented chain at the event's instant",
        "verify_authority_delegation_chain"
    ],
    [
        "2. an exhaustion ledger keyed to a grant, carried across an ordered event list",
        None
    ],
    [
        "3. a second presentation of a single-use grant reaching artifacts issued out of it",
        None
    ],
    [
        "4. an exhaustion state distinguishable from revoked and from expired in a recorded result",
        None
    ],
    [
        "5. a refusal to undo an exhaustion, and standing checked separately from reversibility",
        None
    ],
    [
        "6. purpose membership for a requested purpose against a grant's allowed purposes",
        "is_purpose_permitted"
    ],
    [
        "7. a completion record's signature and stage validity",
        "verify_receipt_v1"
    ],
    [
        "8. cumulative spend across a delegation subtree, reserved then settled",
        "InMemoryAuthorityBudgetLedger"
    ],
    [
        "9. a detached signature over canonical JCS bytes, for a principal-signed bound",
        "canonicalize_jcs"
    ],
    [
        "10. a purpose bound reached, established from a fulfillment record",
        None
    ],
    [
        "11. a use-count bound reached, established from the boundary's own admissions",
        None
    ]
]


def resolve(name):
    if name is None:
        return None
    for module in MODULES:
        candidate = getattr(module, name, None)
        if callable(candidate):
            return candidate
    return None


supported = 0
for claim, api in CLAIMS:
    ok = resolve(api) is not None
    supported += 1 if ok else 0
    print(f"{'supported   ' if ok else 'not_supported'}  {claim}")
    print(f"                 api: {api or 'none in this SDK'}")

print(f"lifecycle-purpose-exhaustion PyPI probe: {supported}/{len(CLAIMS)} claims have an API")
