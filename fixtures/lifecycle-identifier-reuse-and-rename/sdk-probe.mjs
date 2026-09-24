// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records which APIs the npm reference SDK actually exposes for this family.
// Prints one line per probe: supported, or not_supported with the reason. No
// assertions about behaviour, only reachability.
//
//     node fixtures/lifecycle-identifier-reuse-and-rename/sdk-probe.mjs

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
  ['external identifier binding, issue', 'issueIdentifierBinding'],
  ['external identifier binding, verify', 'verifyIdentifierBinding'],
  ['external identifier controller, resolve at instant', 'resolveIdentifierControllerAt'],
  ['external identifier continuity, verify', 'verifyIdentifierContinuity'],
  ['identifier retention record, issue', 'issueIdentifierRetention'],
  ['namespace claim, create', 'createNamespaceClaim'],
  ['namespace claim, verify', 'verifyNamespaceClaim'],
  ['DID document, create', 'createDIDDocument'],
  ['public key from DID', 'publicKeyFromDID'],
  ['identity rotation log, verify', 'verifyRotationLog'],
  ['unbind event, verify', 'verifyUnbindEvent'],
  ['bound wallet, verify', 'verifyBoundWallet'],
  ['authority chain, verify', 'verifyAuthorityDelegationChain'],
  ['authority delegation, issue root', 'issueAuthorityDelegation'],
  ['RFC 8785 JCS canonical bytes', 'canonicalizeJCS'],
  ['Ed25519 verify', 'verify'],
]

console.log(`agent-passport-system@${version} (npm, TypeScript reference SDK)`)
let notSupported = 0
for (const [label, name] of PROBES) {
  if (typeof sdk[name] === 'function') {
    console.log(`  supported      ${label.padEnd(50)} ${name}`)
  } else {
    notSupported += 1
    console.log(`  not_supported  ${label.padEnd(50)} ${name}: not exported from the package root`)
  }
}
console.log('')
console.log(`${PROBES.length - notSupported}/${PROBES.length} supported. No exported API takes an external identifier`)
console.log('and an instant and answers who controls it, so the dependency, pin, binding, conflict,')
console.log('lapse and continuity-gap steps are implemented in harness.ts, not by the SDK. See README.')
