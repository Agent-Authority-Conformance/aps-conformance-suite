// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// SDK support probe for the lifecycle-purpose-exhaustion family, npm side.
//
// Claims 1 to 5 are the single-use track's. Claims 6 to 11 are the bounds
// track's, folded in when the two builds were reconciled into one family.
//
// It reports, for each claim this family makes, whether the pinned npm SDK
// exposes an API that decides it. A not_supported line is a statement about
// this SDK's surface at this version, not a conformance verdict, and nothing
// here is simulated to fill one in. SDK-RUNS.md records the output verbatim.
//
// Run: node fixtures/lifecycle-purpose-exhaustion/sdk-probe.mjs

import * as sdk from 'agent-passport-system'

const CLAIMS = [
  [
    "1. chain verdict for a presented chain at the event's instant",
    "verifyAuthorityDelegationChain"
  ],
  [
    "2. an exhaustion ledger keyed to a grant, carried across an ordered event list",
    null
  ],
  [
    "3. a second presentation of a single-use grant reaching artifacts issued out of it",
    null
  ],
  [
    "4. an exhaustion state distinguishable from revoked and from expired in a recorded result",
    null
  ],
  [
    "5. a refusal to undo an exhaustion, and standing checked separately from reversibility",
    null
  ],
  [
    "6. purpose membership for a requested purpose against a grant's allowed purposes",
    "isPurposePermitted"
  ],
  [
    "7. a completion record's signature and stage validity",
    "verifyReceiptV1"
  ],
  [
    "8. cumulative spend across a delegation subtree, reserved then settled",
    "InMemoryAuthorityBudgetLedger"
  ],
  [
    "9. a detached signature over canonical JCS bytes, for a principal-signed bound",
    "canonicalizeJCS"
  ],
  [
    "10. a purpose bound reached, established from a fulfillment record",
    null
  ],
  [
    "11. a use-count bound reached, established from the boundary's own admissions",
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
console.log(`lifecycle-purpose-exhaustion npm probe: ${supported}/${CLAIMS.length} claims have an API`)
