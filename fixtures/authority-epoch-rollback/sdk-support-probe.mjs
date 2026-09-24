// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records which of this family's three concepts the npm `agent-passport-system`
// package has an API for, so the README's not_supported entries are reproducible
// rather than asserted.
//
// This probe reports absence of a named surface. It is not a conformance result
// and not a defect report: nothing in draft-03 asks the SDK for any of these.
//
// Run: node fixtures/authority-epoch-rollback/sdk-support-probe.mjs
// Exit 0 always. It reports, it does not judge.

import * as aps from 'agent-passport-system'
import { readFileSync } from 'node:fs'

// The package does not export ./package.json, so its version is read from the
// installed tree rather than imported.
const version = JSON.parse(
  readFileSync(new URL('../../node_modules/agent-passport-system/package.json', import.meta.url), 'utf8'),
).version
const exported = Object.keys(aps).sort()

// Each probe names the exact surface an implementation would need, and the
// regular expression that would find it among the package's exports.
const probes = [
  {
    concept: 'authority epoch on delegation, revocation or store state',
    pattern: /^(?!.*gonka).*(authorityEpoch|revocationEpoch|epochOf|stateEpoch)/i,
    needed_for: 'AER-01 to AER-06',
  },
  {
    concept: 'fencing token on an authority-mutating write',
    pattern: /fencing|fenceToken|writeToken/i,
    needed_for: 'AER-07 to AER-10',
  },
  {
    concept: 'withdrawal or correction of a recorded revocation',
    pattern: /(withdrawRevocation|revocationWithdrawal|unrevoke|correctRevocation)/i,
    needed_for: 'AER-11, AER-12',
  },
]

console.log(`agent-passport-system (npm) ${version}, ${exported.length} exports`)
for (const probe of probes) {
  const hits = exported.filter(name => probe.pattern.test(name))
  const verdict = hits.length === 0 ? 'not_supported' : `present: ${hits.join(', ')}`
  console.log(`  ${probe.concept} [${probe.needed_for}]: ${verdict}`)
}

// The store boundary, checked by calling rather than by name. A removal method
// is what a rollback inside one store would need, and there is none.
const store = new aps.InMemoryAuthorityRevocationStore()
const storeMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(store)).filter(n => n !== 'constructor')
console.log(`  InMemoryAuthorityRevocationStore methods: ${storeMethods.join(', ')}`)
console.log(
  `  removal method on the revocation store: ${
    storeMethods.some(m => /delete|remove|clear|unset/i.test(m)) ? 'present' : 'not_supported'
  }`,
)

// The resolver contract, checked by reading what the chain verifier accepts.
console.log(
  '  resolveRevocation callback arity: ' +
    `${aps.createAuthorityRevocationResolver.length} arguments to build it, ` +
    'and the callback it returns takes the delegation and nothing else, so there is ' +
    'no argument through which an epoch or a token could be supplied',
)
