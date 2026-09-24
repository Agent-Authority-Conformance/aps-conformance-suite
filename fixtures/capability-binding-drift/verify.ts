// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runs the eight capability-binding-drift presentations against harness.ts's reference
// boundary and its declared defective negative control, over chain.json's real,
// agent-passport-system-signed grants and tool registry entries. No network access.
//
// This is evidence about this family's own reference boundary, not an SDK conformance
// result. See README "What a pass establishes" and "Does not claim".

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AuthorityDelegationV1, ToolRegistryEntry } from 'agent-passport-system'

import {
  CapabilityBindingBoundary,
  makeDefectiveBoundary,
  makeReferenceBoundary,
  type Outcome,
} from './harness.js'

const here = path.dirname(fileURLToPath(import.meta.url))

function readJson<T>(name: string): T {
  return JSON.parse(fs.readFileSync(path.join(here, name), 'utf8')) as T
}

type GrantName = 'pinned' | 'impl_pin_only' | 'unpinned'
type EntryName = 'v1' | 'v2' | 'v1_other_attestor'
type Revision = 'v1' | 'v2'

interface ChainFixture {
  _placeholder?: boolean
  now: string
  metadata_digest_domain: string
  identities: Record<string, string>
  verification_keys: Record<string, string>
  attestor_keys: Record<string, string>
  tool: {
    name: string
    trusted_attestor: string
    implementations: Record<Revision, string>
    implementation_digests: Record<Revision, string>
    metadata: Record<Revision, unknown>
    metadata_digests: Record<Revision, string>
  }
  delegations: Record<GrantName, AuthorityDelegationV1>
  registry_entries: Record<EntryName, ToolRegistryEntry>
  action: { input: { scope_required: string[] }; action_ref: string }
}

interface Presentation {
  id: string
  status: string
  tests_proposed_text: string[]
  differs_from: string | null
  grant: GrantName
  registry_entry: EntryName
  current_implementation: Revision
  current_metadata: Revision
  requested_tool: string
  now: string
  revocation: 'active' | 'revoked' | 'unknown'
  expected: { verdict: string; reason: string; detail?: string }
}

interface Vectors {
  profile: string
  status: string
  proposed_text: Record<string, { commit: string; concept: string }>
  declared_defective_fail_set: string[]
  presentations: Presentation[]
}

const fixture = readJson<ChainFixture>('chain.json')
const vectors = readJson<Vectors>('vectors.json')

if (
  fixture._placeholder ||
  typeof fixture.now !== 'string' ||
  !fixture.delegations?.pinned ||
  !fixture.registry_entries?.v1 ||
  Object.keys(fixture.verification_keys ?? {}).length === 0
) {
  console.error(
    'capability-binding-drift chain.json is not minted. Run ' +
    '`npx tsx fixtures/capability-binding-drift/mint.ts` first.',
  )
  process.exit(2)
}

// Every vector must be labelled and must name proposed text this file can find.
for (const presentation of vectors.presentations) {
  if (presentation.status !== 'candidate_against_proposed') {
    console.error(`capability-binding-drift: ${presentation.id} is not labelled candidate_against_proposed`)
    process.exit(2)
  }
  if (!Array.isArray(presentation.tests_proposed_text) || presentation.tests_proposed_text.length === 0) {
    console.error(`capability-binding-drift: ${presentation.id} names no proposed text`)
    process.exit(2)
  }
  for (const key of presentation.tests_proposed_text) {
    if (!vectors.proposed_text[key]) {
      console.error(`capability-binding-drift: ${presentation.id} names unknown proposed text "${key}"`)
      process.exit(2)
    }
  }
}

const boundaryOptions = {
  resolveDelegationVerificationKey: (_issuer: string, method: string) =>
    fixture.verification_keys[method] ?? null,
  resolveTrustedAttestorKey: (toolName: string) =>
    toolName === fixture.tool.name ? fixture.attestor_keys[fixture.tool.trusted_attestor] : undefined,
  trustRoot: () => true,
  metadataDigestDomain: fixture.metadata_digest_domain,
}

function runBoundary(boundary: CapabilityBindingBoundary): Map<string, Outcome> {
  const results = new Map<string, Outcome>()
  for (const presentation of vectors.presentations) {
    const outcome = boundary.admit({
      label: presentation.id,
      grant: fixture.delegations[presentation.grant],
      registryEntry: fixture.registry_entries[presentation.registry_entry],
      currentImplementation: fixture.tool.implementations[presentation.current_implementation],
      currentMetadata: fixture.tool.metadata[presentation.current_metadata],
      requestedToolName: presentation.requested_tool,
      requestedScopeRequired: fixture.action.input.scope_required,
      now: presentation.now,
      resolveRevocation: () => presentation.revocation,
    })
    results.set(presentation.id, outcome)
  }
  return results
}

function matches(actual: Outcome, expected: Presentation['expected']): boolean {
  if (actual.verdict !== expected.verdict) return false
  if (actual.reason !== expected.reason) return false
  if (expected.detail !== undefined && actual.detail !== expected.detail) return false
  return true
}

const referenceBoundary = makeReferenceBoundary(boundaryOptions)
const defectiveBoundary = makeDefectiveBoundary(boundaryOptions)

const referenceResults = runBoundary(referenceBoundary)
const defectiveResults = runBoundary(defectiveBoundary)

console.log(`capability-binding-drift: ${vectors.presentations.length} presentations, status ${vectors.status}`)
console.log('')
console.log('boundary: reference-boundary')

let referenceMatched = 0
for (const presentation of vectors.presentations) {
  const actual = referenceResults.get(presentation.id)!
  const ok = matches(actual, presentation.expected)
  if (ok) referenceMatched += 1
  console.log(`  ${ok ? 'MATCH' : 'MISMATCH'} ${presentation.id}  verdict=${actual.verdict} reason=${actual.reason}`)
  if (!ok) {
    console.log(`    expected: ${JSON.stringify(presentation.expected)}`)
    console.log(`    actual:   ${JSON.stringify(actual)}`)
  }
}

const declaredFailSet = new Set(vectors.declared_defective_fail_set)
let defectiveOk = true
console.log('')
console.log(`boundary: ${defectiveBoundary.name}`)
for (const presentation of vectors.presentations) {
  const actual = defectiveResults.get(presentation.id)!
  const shouldMatchExpected = !declaredFailSet.has(presentation.id)
  const actuallyMatches = matches(actual, presentation.expected)
  const ok = shouldMatchExpected ? actuallyMatches : !actuallyMatches
  if (!ok) defectiveOk = false
  const label = shouldMatchExpected
    ? (ok ? 'MATCH' : 'UNDECLARED MISMATCH')
    : (ok ? 'DECLARED FAIL' : 'DEFECT DID NOT REPRODUCE')
  console.log(`  ${label} ${presentation.id}  verdict=${actual.verdict} reason=${actual.reason}`)
}

const referenceOk = referenceMatched === vectors.presentations.length

console.log('')
console.log(`reference-boundary matched: ${referenceMatched}/${vectors.presentations.length}`)
console.log(`${defectiveBoundary.name} failed exactly the declared set: ${defectiveOk}`)

if (referenceOk && defectiveOk) {
  console.log('PASSED: reference-boundary matched every presentation, defective boundary failed exactly the declared set')
  process.exit(0)
} else {
  console.error('FAILED')
  process.exit(1)
}
