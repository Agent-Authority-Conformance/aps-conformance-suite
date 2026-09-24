// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// SDK support probe for the lifecycle-organization-events family, npm side.
//
// It reports, for each claim this family makes, whether the pinned npm SDK
// exposes an API that decides it. A not_supported line is a statement about
// this SDK's surface at this version, not a conformance verdict, and nothing
// here is simulated to fill one in. SDK-RUNS.md records the output verbatim.
//
// Run: node fixtures/lifecycle-organization-events/sdk-probe.mjs

import * as sdk from 'agent-passport-system'

const CLAIMS = [
  [
    "1. chain verdict for a presented chain under the vector's revocation answers",
    "verifyAuthorityDelegationChain"
  ],
  [
    "2. issuer refusal to mint a successor grant outside the successor's own scope",
    "issueSubAuthorityDelegation"
  ],
  [
    "3. detached Ed25519 verification of an external record's canonical bytes",
    "verify"
  ],
  [
    "4. principal binding reported separately from chain validity",
    null
  ],
  [
    "5. attestor standing evaluated against a verifier trust policy",
    null
  ],
  [
    "6. an external restriction that narrows scope without revoking, reported as restricted",
    null
  ],
  [
    "7. a third-party consent gate keyed to an exact target and operation",
    null
  ],
  [
    "8. an in-flight acceptance boundary for a submitted order",
    null
  ]
]

let supported = 0
for (const [claim, api] of CLAIMS) {
  const ok = api !== null && typeof sdk[api] === 'function'
  if (ok) supported += 1
  console.log(`${ok ? 'supported   ' : 'not_supported'}  ${claim}`)
  console.log(`                 api: ${api ?? 'none in this SDK'}`)
}
console.log(`lifecycle-organization-events npm probe: ${supported}/${CLAIMS.length} claims have an API`)
