// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Records which APIs the TypeScript reference SDK actually exposes at runtime for the
// concepts this family needs. Prints one line per probe: supported or not_supported
// with the reason. No network access, no assertions about behaviour, only reachability.
//
//   node fixtures/capability-binding-drift/sdk-probe.mjs

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// The package does not export ./package.json as a subpath, so its version is read
// from the installed tree the same way mint.ts reads it.
const here = path.dirname(fileURLToPath(import.meta.url))
const version = JSON.parse(
  fs.readFileSync(path.join(here, '..', '..', 'node_modules', 'agent-passport-system', 'package.json'), 'utf8'),
).version

const root = await import('agent-passport-system')
let core = {}
try {
  core = await import('agent-passport-system/core')
} catch {
  core = {}
}

const PROBES = [
  ['tool registry entry, create', 'createToolRegistryEntry'],
  ['tool registry entry, verify', 'verifyToolIntegrity'],
  ['tool manifest, create', 'createToolManifest'],
  ['tool manifest, verify', 'verifyToolManifest'],
  ['tool manifest, revise', 'reviseToolManifest'],
  ['tool manifest, re-approve', 'reapproveToolManifest'],
  ['namespace claim, create', 'createNamespaceClaim'],
  ['namespace claim, verify', 'verifyNamespaceClaim'],
  ['authority chain, verify', 'verifyAuthorityDelegationChain'],
  ['authority delegation, issue root', 'issueAuthorityDelegation'],
  ['action reference v2, compute', 'computeActionRefV2'],
  ['RFC 8785 JCS canonical bytes', 'canonicalizeJCS'],
]

console.log(`agent-passport-system@${version} (npm, TypeScript reference SDK)`)
let notSupported = 0
for (const [label, name] of PROBES) {
  const where = typeof root[name] === 'function'
    ? 'package root'
    : typeof core[name] === 'function'
      ? 'agent-passport-system/core'
      : null
  if (where === null) {
    notSupported += 1
    console.log(`  not_supported  ${label.padEnd(36)} ${name}: not exported from the package root or from ./core`)
  } else {
    console.log(`  supported      ${label.padEnd(36)} ${name}: ${where}`)
  }
}

console.log('')
console.log('No API in this SDK decides whether an action through a tool is established')
console.log('under a grant that pins that tool. That boundary is this family\'s own code.')
console.log(`probes: ${PROBES.length}, not_supported: ${notSupported}`)
