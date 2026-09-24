// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records which APIs the npm reference SDK actually exposes for this family.
// Prints one line per probe: supported, or not_supported with the reason. No
// assertions about behaviour, only reachability.
//
//     node fixtures/lifecycle-policy-change/sdk-probe.mjs

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// The package does not export ./package.json, so the version is read from the
// installed tree rather than required.
const here = path.dirname(fileURLToPath(import.meta.url))
const version = JSON.parse(
  fs.readFileSync(path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version
const sdk = await import('agent-passport-system')

const PROBES = [
  ['policy version registry, create', 'createPolicyVersion'],
  ['policy version registry, resolve at instant', 'resolvePolicyVersionAt'],
  ['operative pointer, issue', 'issueOperativePolicyPointer'],
  ['operative pointer, resolve', 'resolveOperativePolicyPointer'],
  ['policy rollback, classify', 'classifyPolicyRollback'],
  ['decision record, render against pinned version', 'renderDecisionAgainstPolicyVersion'],
  ['decision record, read pinned policy version', 'policyVersionOfDecision'],
  ['policy bundle, create', 'createPolicyBundle'],
  ['policy bundle, verify', 'verifyPolicyBundle'],
  ['policy chain, verify', 'verifyPolicyChain'],
  ['policy receipt, create', 'createPolicyReceipt'],
  ['policy decision, verify', 'verifyPolicyDecision'],
  ['scope version hash, compute', 'computeScopeVersionHash'],
  ['scope version match, verify', 'verifyScopeVersionMatch'],
  ['authority chain, verify', 'verifyAuthorityDelegationChain'],
  ['authority delegation, issue root', 'issueAuthorityDelegation'],
  ['RFC 8785 JCS canonical bytes', 'canonicalizeJCS'],
  ['Ed25519 verify', 'verify'],
]

console.log(`agent-passport-system@${version} (npm, TypeScript reference SDK)`)
let notSupported = 0
for (const [label, name] of PROBES) {
  if (typeof sdk[name] === 'function') {
    console.log(`  supported      ${label.padEnd(46)} ${name}`)
  } else {
    notSupported += 1
    console.log(`  not_supported  ${label.padEnd(46)} ${name}: not exported from the package root`)
  }
}
console.log('')
console.log(
  `${PROBES.length - notSupported}/${PROBES.length} supported. The policy-version, operative-pointer, rollback-classification`,
)
console.log(
  'and decision-rendering steps this family decides are implemented in harness.ts, not by the SDK. See README.',
)
