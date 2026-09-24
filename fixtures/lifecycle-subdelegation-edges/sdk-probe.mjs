// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// SDK support probe for the lifecycle-subdelegation-edges family, npm side.
//
// It reports, for each claim this family makes, whether the pinned npm SDK
// exposes an API that decides it. A not_supported line is a statement about
// this SDK's surface at this version, not a conformance verdict, and nothing
// here is simulated to fill one in. SDK-RUNS.md records the output verbatim.
//
// Run: node fixtures/lifecycle-subdelegation-edges/sdk-probe.mjs

import * as sdk from 'agent-passport-system'

const CLAIMS = [
  [
    "1. chain verdict for a presented chain under the vector's revocation answers",
    "verifyAuthorityDelegationChain"
  ],
  [
    "2. a child's declared validity period compared against its parent's at verification time",
    "verifyAuthorityDelegationChain"
  ],
  [
    "3. a chain's declared maximum subdelegation depth enforced across the whole chain",
    "verifyAuthorityDelegationChain"
  ],
  [
    "4. issuer refusal to mint a child outside its parent's window or past its declared depth",
    "issueSubAuthorityDelegation"
  ],
  [
    "5. a per-artifact-only verification mode, for the negative control",
    null
  ],
  [
    "6. taking a member's status from a pinned issuer observation, for the negative control",
    null
  ],
  [
    "7. a boundary record naming the earlier record it follows by digest",
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
console.log(`lifecycle-subdelegation-edges npm probe: ${supported}/${CLAIMS.length} claims have an API`)
