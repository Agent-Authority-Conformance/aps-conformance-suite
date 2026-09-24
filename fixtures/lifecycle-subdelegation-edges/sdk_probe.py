#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# SDK support probe for the lifecycle-subdelegation-edges family, PyPI side.
#
# It reports, for each claim this family makes, whether the pinned PyPI SDK
# exposes an API that decides it. A not_supported line is a statement about
# this SDK's surface at this version, not a conformance verdict, and nothing
# here is simulated to fill one in. SDK-RUNS.md records the output verbatim.
#
# Run: python3 fixtures/lifecycle-subdelegation-edges/sdk_probe.py

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
        "2. a child's declared validity period compared against its parent's at verification time",
        "verify_authority_delegation_chain"
    ],
    [
        "3. a chain's declared maximum subdelegation depth enforced across the whole chain",
        "verify_authority_delegation_chain"
    ],
    [
        "4. issuer refusal to mint a child outside its parent's window or past its declared depth",
        "issue_sub_authority_delegation"
    ],
    [
        "5. a per-artifact-only verification mode, for the negative control",
        None
    ],
    [
        "6. taking a member's status from a pinned issuer observation, for the negative control",
        None
    ],
    [
        "7. a boundary record naming the earlier record it follows by digest",
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

print(f"lifecycle-subdelegation-edges PyPI probe: {supported}/{len(CLAIMS)} claims have an API")
