#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# SDK support probe for the lifecycle-organization-events family, PyPI side.
#
# It reports, for each claim this family makes, whether the pinned PyPI SDK
# exposes an API that decides it. A not_supported line is a statement about
# this SDK's surface at this version, not a conformance verdict, and nothing
# here is simulated to fill one in. SDK-RUNS.md records the output verbatim.
#
# Run: python3 fixtures/lifecycle-organization-events/sdk_probe.py

import agent_passport as ap
import agent_passport.crypto as crypto
from agent_passport.v2 import authority_delegation as adl

MODULES = (adl, ap, crypto)

CLAIMS = [
    [
        "1. chain verdict for a presented chain under the vector's revocation answers",
        "verify_authority_delegation_chain"
    ],
    [
        "2. issuer refusal to mint a successor grant outside the successor's own scope",
        "issue_sub_authority_delegation"
    ],
    [
        "3. detached Ed25519 verification of an external record's canonical bytes",
        "verify"
    ],
    [
        "4. principal binding reported separately from chain validity",
        None
    ],
    [
        "5. attestor standing evaluated against a verifier trust policy",
        None
    ],
    [
        "6. an external restriction that narrows scope without revoking, reported as restricted",
        None
    ],
    [
        "7. a third-party consent gate keyed to an exact target and operation",
        None
    ],
    [
        "8. an in-flight acceptance boundary for a submitted order",
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

print(f"lifecycle-organization-events PyPI probe: {supported}/{len(CLAIMS)} claims have an API")
