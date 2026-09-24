// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records what the published npm `agent-passport-system` package offers for this
// family, so SDK-RUNS.md's entries are reproducible rather than asserted.
//
// It reports, it does not judge. Nothing in draft-pidlisnyi-aps-03 asks the SDK
// for any of this, so a `not_supported` line is an absence of a named surface,
// not a defect report and not a conformance result.
//
// The package does have an accountability surface, and this probe looks at it
// rather than around it: it constructs an accountability ScopeOfClaim and prints
// its fields, so a reader can see what that record does and does not carry about
// which individual acted.
//
// Run: node fixtures/lifecycle-shared-identity-with-no-accountable-principal/sdk-probe.mjs
// Exit 0 always.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import * as aps from 'agent-passport-system'

const HERE = dirname(fileURLToPath(import.meta.url))
const version = JSON.parse(
  readFileSync(join(HERE, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version
const exported = Object.keys(aps).sort()

console.log(`agent-passport-system (npm) ${version}, ${exported.length} exports`)
console.log('')

// --- what the package's accountability surface actually is ------------------

console.log('accountability surface present in the package:')
const accountabilityNames = exported.filter(n => /accountab|scopeOfClaim|attribution/i.test(n))
for (const n of accountabilityNames) console.log(`  ${n}`)
console.log('')

console.log('ATTRIBUTION_ROLES:', JSON.stringify(aps.ATTRIBUTION_ROLES))
console.log('ATTRIBUTION_AXIS_TAGS:', JSON.stringify(aps.ATTRIBUTION_AXIS_TAGS))
console.log('')

// --- the three things this family needs -------------------------------------

const probes = [
  {
    need: 'a declared distinction between an identity one individual holds and an identity several can drive',
    pattern: /(sharedIdentity|isSharedCredential|groupAccount|genericAccount|multiOperator)/i,
    note:
      'nothing in the package marks a credential as shared. An identity is an identity, and a record naming it says which credential authenticated, which is the fact LC-I-010 says is not the same fact as who is accountable.',
  },
  {
    need: 'a checkout or broker record binding one individual to a shared identity for an interval',
    pattern: /(checkOutIdentity|identityCheckout|brokerCredential|assumeAs|individualBinding)/i,
    note:
      'the package exports createCheckout, updateCheckout, completeCheckout and cancelCheckout, which are the ACP commerce checkout, a purchase flow. They are not credential checkout and they bind no individual to a shared identity.',
  },
  {
    need: 'a later attribution record that references an earlier decision record and names the individual established to have acted',
    pattern: /(attributeToIndividual|laterAttribution|investigationRecord|attributionPending)/i,
    note:
      'the attribution surface the package does have (aggregateAttributionPrimitives, ATTRIBUTION_ROLES, ATTRIBUTION_AXIS_TAGS) attributes contribution across compute, data and protocol axes between systems. It is a different sense of the word from which person was at the keyboard.',
  },
  {
    need: 'an anomaly flag for an unscoped all-powerful identity used off its own enumerated required-list',
    pattern: /(rootIdentity|privilegedUse|breakGlass|enumeratedTaskList|offListUse)/i,
    note:
      'nothing in the package has a notion of an identity that is exceptional by construction, or of a list of tasks only it may perform.',
  },
]

for (const p of probes) {
  const hits = exported.filter(n => p.pattern.test(n))
  console.log(`${hits.length === 0 ? 'not_supported' : `present: ${hits.join(', ')}`}`)
  console.log(`  needed: ${p.need}`)
  console.log(`  note:   ${p.note}`)
}
console.log('')

// --- what an accountability record from the package carries -----------------

console.log('What the package\'s own accountability record carries, constructed and printed:')
try {
  const scope = aps.buildRevocationEnforcementScopeOfClaim()
  console.log(`  buildRevocationEnforcementScopeOfClaim() -> ${JSON.stringify(scope)}`)
  console.log('  Read the field names: this is a scope of claim over what a check covered.')
  console.log('  No field on it names an accountable individual, and none says the acting')
  console.log('  identity was shared, so a consumer of this record cannot tell LC-I-010-a')
  console.log('  from LC-I-010-b.')
} catch (err) {
  console.log(`  buildRevocationEnforcementScopeOfClaim() threw: ${err.message}`)
}
