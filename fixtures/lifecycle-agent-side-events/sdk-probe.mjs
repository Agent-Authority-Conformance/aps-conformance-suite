// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records which APIs the npm reference SDK actually exposes for this family.
// Prints one line per probe: supported, or not_supported with the reason. No
// assertions about behaviour, only reachability.
//
//     node fixtures/lifecycle-agent-side-events/sdk-probe.mjs

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
  ['presenter is the grant subject, verify', 'verifyPresenterIsSubject'],
  ['replay cache, consume a presented credential', 'consumePresentedCredential'],
  ['replay cache, lost-record refusal window', 'replayCacheLossWindow'],
  ['executor lifecycle record, issue', 'issueExecutorLifecycleRecord'],
  ['executor availability at an instant, resolve', 'resolveExecutorAvailabilityAt'],
  ['capability consent record, issue', 'issueCapabilityConsent'],
  ['capability consent at an instant, resolve', 'resolveCapabilityConsentAt'],
  ['self-asserted authority claim, classify', 'classifyAuthorityClaim'],
  ['approval, verify', 'verifyApproval'],
  ['authority revocation, issue', 'issueAuthorityRevocation'],
  ['authority revocation, verify', 'verifyAuthorityRevocation'],
  ['authority revocation resolver, create', 'createAuthorityRevocationResolver'],
  ['inference session, verify', 'verifyInferenceSession'],
  ['runtime attestation, verify', 'verifyRuntimeAttestation'],
  ['behavioral memory object, verify', 'verifyBehavioralMemoryObject'],
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
console.log(`${PROBES.length - notSupported}/${PROBES.length} supported. The presenter binding, the consumption`)
console.log('record and its loss rule, the executor lifecycle lookup and the capability consent step are')
console.log('implemented in harness.ts, not by the SDK. See README.')
