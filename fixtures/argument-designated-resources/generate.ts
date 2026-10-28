// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Generator for fixtures/argument-designated-resources/vectors.json.
//
// Every expected outcome below, decision, execution, trace and store change, is
// written by hand from the profile in README.md. None is computed by harness.ts.
// The generator imports the harness only for canonicalizeResource (to assert
// that every credential and record is already canonical) and callRef (to fill in
// each decision's call reference). The defective-policy categories were also
// written by hand, before either runner was run against them. verify.ts imports
// buildVectors() and requires the committed vectors.json to equal its output
// byte for byte.
//
// Run: npx tsx fixtures/argument-designated-resources/generate.ts
// Writes vectors.json. A second run leaves `git diff` empty.

import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  callRef,
  canonicalizeResource,
  CALL_REF_DOMAIN,
  type Access,
  type Call,
  type Credential,
  type Decision,
  type Execution,
  type Fixture,
  type Json,
  type Operation,
  type ToolContract,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

const R1 = 'res:/store/r1'
const R2 = 'res:/store/r2'
const R3 = 'res:/store/r3'
const STATS = 'res:/svc/stats'
const BILL = 'res:/svc/bill'
const ALICE = 'party:alice'
const BOB = 'party:bob'
const MALLORY = 'party:mallory'
const ADMIN = 'party:store-admin'
const SVC = 'party:svc-tools'

// ---------------------------------------------------------------------------
// Trusted fixture state shared by every presentation.

const resource = (operation: Operation) => ({ kind: 'resource' as const, operation, required: true })
const capability = (operation: Operation) => ({ kind: 'capability' as const, operation, required: true })
const data = (required: boolean) => ({ kind: 'data' as const, required })

const TOOLS: Record<string, ToolContract> = {
  copy: {
    service_identity: SVC,
    target: 'src',
    arguments: { dst: resource('write'), label: data(false), src: resource('read') },
    service_effects: [],
  },
  copy_audited: {
    service_identity: SVC,
    target: 'src',
    arguments: { dst: resource('write'), src: resource('read') },
    service_effects: [{ resource: STATS, operation: 'write', authority: 'cred:svc-stats-write' }],
  },
  copy_with_capability: {
    service_identity: SVC,
    target: 'src',
    arguments: { dst: capability('write'), src: resource('read') },
    service_effects: [],
  },
  export: {
    service_identity: SVC,
    target: 'src',
    arguments: {
      'options.output.format': data(true),
      'options.output.path': resource('write'),
      src: resource('read'),
    },
    service_effects: [],
  },
  normalize: {
    service_identity: SVC,
    target: 'src',
    arguments: { dst: resource('write'), src: resource('read') },
    service_effects: [],
  },
  overwrite: {
    service_identity: SVC,
    target: 'target',
    arguments: { content: data(true), target: resource('write') },
    service_effects: [],
  },
  replicate: {
    service_identity: SVC,
    target: 'src',
    arguments: { 'dsts[]': resource('write'), src: resource('read') },
    service_effects: [],
  },
}

const ISSUER_RECORDS: Record<string, string[]> = {
  [ADMIN]: ['res:/store'],
  [SVC]: ['res:/svc'],
}

const INITIAL_STORE: Record<string, string> = {
  [R1]: 'alpha',
  [R2]: 'beta',
  [R3]: 'gamma',
  [BILL]: 'billing-records',
  [STATS]: 'none',
}

// ---------------------------------------------------------------------------
// Credential library. A presentation's trusted state is the service baseline
// plus the credentials its case lists.

const root = (id: string, holder: string, issuer: string, res: string, operations: Operation[], delegable = false): Credential => ({
  id, holder, issuer, resource: res, operations, delegable, parent: null,
})
const child = (id: string, holder: string, issuer: string, parent: string, res: string, operations: Operation[]): Credential => ({
  id, holder, issuer, resource: res, operations, delegable: false, parent,
})

const LIBRARY: Credential[] = [
  root('cred:alice-r1-read', ALICE, ADMIN, R1, ['read']),
  root('cred:alice-r1-rw', ALICE, ADMIN, R1, ['read', 'write']),
  root('cred:alice-r2-read', ALICE, ADMIN, R2, ['read']),
  root('cred:alice-r2-write', ALICE, ADMIN, R2, ['write']),
  root('cred:alice-r3-write', ALICE, ADMIN, R3, ['write']),
  root('cred:mallory-r2-write', MALLORY, ADMIN, R2, ['write']),
  root('cred:alice-r2-write-from-mallory', ALICE, MALLORY, R2, ['write']),
  root('cred:bob-drafts-rw-delegable', BOB, ADMIN, 'res:/store/r2/drafts', ['read', 'write'], true),
  child('cred:alice-r2-write-via-drafts', ALICE, BOB, 'cred:bob-drafts-rw-delegable', R2, ['write']),
  root('cred:bob-r2-write-delegable', BOB, ADMIN, R2, ['write'], true),
  child('cred:alice-r2-write-via-bob', ALICE, BOB, 'cred:bob-r2-write-delegable', R2, ['write']),
  root('cred:bob-r2-write-not-delegable', BOB, ADMIN, R2, ['write'], false),
  child('cred:alice-r2-write-via-bob-not-delegable', ALICE, BOB, 'cred:bob-r2-write-not-delegable', R2, ['write']),
  root('cred:bob-store-rw-delegable', BOB, ADMIN, 'res:/store', ['read', 'write'], true),
  child('cred:alice-r2-rw-via-bob', ALICE, BOB, 'cred:bob-store-rw-delegable', R2, ['read', 'write']),
  root('cred:svc-home', SVC, SVC, 'res:/svc', ['read', 'write']),
  root('cred:svc-stats-write', SVC, SVC, STATS, ['write']),
  root('cred:svc-r2-write', SVC, ADMIN, R2, ['write']),
]
const BY_ID = new Map(LIBRARY.map((c) => [c.id, c]))
const SERVICE_BASELINE = ['cred:svc-home', 'cred:svc-stats-write']

// ---------------------------------------------------------------------------
// Case definitions.

const call = (tool: string, args: { [key: string]: Json }, authority: { [path: string]: string }): Call => ({
  tool, requester: ALICE, arguments: args, authority,
})

const acc = (operation: Operation, res: string, path: string, authority: string | null): Access => ({
  operation, resource: res, path, authority, holder: authority === null ? null : BY_ID.get(authority)!.holder,
})

interface Expected {
  decision: Decision
  execution: Execution
  trace: Access[]
  store_changes: Record<string, string>
  forbidden_access: { operation: Operation; resource: string; path: string } | null
}

const admit = (trace: Access[], store_changes: Record<string, string>, execution: Execution = { status: 'completed' }): Expected => ({
  decision: { verdict: 'admitted', reason: 'all_designations_authorized' },
  execution,
  trace,
  store_changes,
  forbidden_access: null,
})

const refuseWith = (
  reason: string,
  detail: Omit<Decision, 'verdict' | 'reason'>,
  forbidden: Expected['forbidden_access'],
): Expected => ({
  decision: { verdict: 'refused', reason, ...detail },
  execution: { status: 'not_run' },
  trace: [],
  store_changes: {},
  forbidden_access: forbidden,
})

const forbid = (operation: Operation, res: string, path: string) => ({ operation, resource: res, path })

interface CaseDef {
  id: string
  tests_proposed_text: string[]
  differs_from: string | null
  note: string
  credentials: string[]
  call: Call
  decided_call?: Call
  inject_failure?: { path: string }
  expected: Expected
}

const OPERANDS = 'csr-operands'
const SELECTED = 'csr-selected-authority'
const CLOSED = 'csr-closed-arguments'
const SERVICE = 'csr-service-effects'
const HOLDER = 'csr-holder-bound-credentials'
const EXACT = 'csr-exact-call'
const TB = 'target-binding'

const COPY_R1_R2 = call('copy', { dst: R2, src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' })
const COPY_R1_R2_TRACE = [acc('read', R1, 'src', 'cred:alice-r1-read'), acc('write', R2, 'dst', 'cred:alice-r2-write')]
const COPY_R1_R1RW = (dst: string) => call('copy', { dst, src: R1 }, { dst: 'cred:alice-r1-rw', src: 'cred:alice-r1-rw' })
const CAP = (cred: string) => call('copy_with_capability', { dst: { capability: cred }, src: R1 }, { src: 'cred:alice-r1-read' })

const CASES: CaseDef[] = [
  {
    id: 'ADR-01-admit-copy-source-and-destination-covered',
    tests_proposed_text: [TB, OPERANDS, SELECTED, EXACT],
    differs_from: null,
    note: 'Control. Alice selects her r1 read credential for src and her r2 write credential for dst, and a decision naming this exact call is presented. The copy runs.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: COPY_R1_R2,
    decided_call: COPY_R1_R2,
    expected: admit(COPY_R1_R2_TRACE, { [R2]: 'alpha' }),
  },
  {
    id: 'ADR-02-refuse-destination-not-covered',
    tests_proposed_text: [TB, OPERANDS, SELECTED],
    differs_from: 'ADR-01: Alice holds only an r1 read and write credential and selects it for both operands. No decision is presented.',
    note: 'The call target (src) is covered. Only the destination named inside an argument is not.',
    credentials: ['cred:alice-r1-rw'],
    call: COPY_R1_R1RW(R2),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dst', resource: R2, operation: 'write' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-03-refuse-deputy-holds-destination-caller-does-not',
    tests_proposed_text: [TB, SELECTED, SERVICE],
    differs_from: 'ADR-02: the service identity also holds cred:svc-r2-write. Alice\'s credentials and selection are unchanged.',
    note: 'The name-based confused deputy (Hardy 1988). The service could write r2 under its own credential, and a boundary that lets the service\'s credentials stand in for the caller\'s admits the call.',
    credentials: ['cred:alice-r1-rw', 'cred:svc-r2-write'],
    call: COPY_R1_R1RW(R2),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dst', resource: R2, operation: 'write' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-04-refuse-nested-designation-not-covered',
    tests_proposed_text: [TB, OPERANDS],
    differs_from: 'ADR-02: the uncovered destination is two levels deep, at options.output.path, next to a data sibling options.output.format.',
    note: 'export reads src and writes the resource named at options.output.path. Alice has only an r1 read credential and selects it for both.',
    credentials: ['cred:alice-r1-read'],
    call: call('export', { options: { output: { format: 'csv', path: R2 } }, src: R1 }, { 'options.output.path': 'cred:alice-r1-read', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'options.output.path', resource: R2, operation: 'write' }, forbid('write', R2, 'options.output.path')),
  },
  {
    id: 'ADR-04b-admit-nested-designation-covered',
    tests_proposed_text: [OPERANDS],
    differs_from: 'ADR-04: Alice also holds an r2 write credential and selects it for options.output.path.',
    note: 'Positive control for nesting. The export writes csv:alpha into r2.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('export', { options: { output: { format: 'csv', path: R2 } }, src: R1 }, { 'options.output.path': 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: admit([acc('read', R1, 'src', 'cred:alice-r1-read'), acc('write', R2, 'options.output.path', 'cred:alice-r2-write')], { [R2]: 'csv:alpha' }),
  },
  {
    id: 'ADR-04c-refuse-literal-dotted-key',
    tests_proposed_text: [CLOSED],
    differs_from: 'ADR-04b: the destination is supplied under one literal top-level key "options.output.path" instead of nested objects.',
    note: 'An argument key must match [a-z][a-z0-9_]*, so a path string can never be read two ways. The refusal names the key in bracket-quoted form.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('export', { 'options.output.path': R2, src: R1 }, { 'options.output.path': 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_key_invalid', { path: '["options.output.path"]' }, null),
  },
  {
    id: 'ADR-05-refuse-one-array-element-not-covered',
    tests_proposed_text: [TB, OPERANDS],
    differs_from: 'ADR-02: the destinations are an array. dsts[0] is covered, dsts[1] is r3 and Alice selects her r2 credential for it.',
    note: 'replicate writes every element of dsts. The refusal names the exact index, and the covered r2 is not written either, because nothing runs before full admission.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('replicate', { dsts: [R2, R3], src: R1 }, { 'dsts[0]': 'cred:alice-r2-write', 'dsts[1]': 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dsts[1]', resource: R3, operation: 'write' }, forbid('write', R3, 'dsts[1]')),
  },
  {
    id: 'ADR-05b-admit-every-array-element-covered',
    tests_proposed_text: [OPERANDS],
    differs_from: 'ADR-05: Alice also holds an r3 write credential and selects it for dsts[1].',
    note: 'Positive control for arrays. Both destinations receive alpha.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write', 'cred:alice-r3-write'],
    call: call('replicate', { dsts: [R2, R3], src: R1 }, { 'dsts[0]': 'cred:alice-r2-write', 'dsts[1]': 'cred:alice-r3-write', src: 'cred:alice-r1-read' }),
    expected: admit(
      [acc('read', R1, 'src', 'cred:alice-r1-read'), acc('write', R2, 'dsts[0]', 'cred:alice-r2-write'), acc('write', R3, 'dsts[1]', 'cred:alice-r3-write')],
      { [R2]: 'alpha', [R3]: 'alpha' },
    ),
  },
  {
    id: 'ADR-05c-admit-then-second-write-fails',
    tests_proposed_text: [OPERANDS],
    differs_from: 'ADR-05b: the fixture injects a failure at the dsts[1] write.',
    note: 'Admission is unchanged. Execution stops at dsts[1] and is reported as partial. The r2 write already done is kept and nothing is rolled back. The profile governs authority, not atomicity.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write', 'cred:alice-r3-write'],
    call: call('replicate', { dsts: [R2, R3], src: R1 }, { 'dsts[0]': 'cred:alice-r2-write', 'dsts[1]': 'cred:alice-r3-write', src: 'cred:alice-r1-read' }),
    inject_failure: { path: 'dsts[1]' },
    expected: admit(
      [acc('read', R1, 'src', 'cred:alice-r1-read'), acc('write', R2, 'dsts[0]', 'cred:alice-r2-write')],
      { [R2]: 'alpha' },
      { status: 'partial', stopped_at: 'dsts[1]', cause: 'injected_failure' },
    ),
  },
  {
    id: 'ADR-06-admit-resource-shaped-label-declared-data',
    tests_proposed_text: [OPERANDS],
    differs_from: 'ADR-01: a label argument carries the string res:/store/r3, over which Alice holds nothing. No decision is presented.',
    note: 'The contract declares label as data. Designation comes from the contract, not from what a string looks like, and the tool never touches r3.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy', { dst: R2, label: R3, src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: admit(COPY_R1_R2_TRACE, { [R2]: 'alpha' }),
  },
  {
    id: 'ADR-06b-admit-identifier-passed-by-value',
    tests_proposed_text: [OPERANDS],
    differs_from: 'ADR-09: Alice selects an r2 write credential, and the content written is the string res:/store/r3.',
    note: 'By value. overwrite writes the characters res:/store/r3 into r2. It needs authority over r2 only, and r3 is never read.',
    credentials: ['cred:alice-r2-write'],
    call: call('overwrite', { content: R3, target: R2 }, { target: 'cred:alice-r2-write' }),
    expected: admit([acc('write', R2, 'target', 'cred:alice-r2-write')], { [R2]: R3 }),
  },
  {
    id: 'ADR-06c-refuse-identifier-passed-by-reference',
    tests_proposed_text: [OPERANDS, SELECTED],
    differs_from: 'ADR-06b: the same identifier is passed by reference, as the src of a copy into r2. Alice holds only her r2 write credential and selects it for both operands.',
    note: 'By reference. copy reads r3, so it needs read authority over r3, which Alice does not have.',
    credentials: ['cred:alice-r2-write'],
    call: call('copy', { dst: R2, src: R3 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r2-write' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'src', resource: R3, operation: 'read' }, forbid('read', R3, 'src')),
  },
  {
    id: 'ADR-07-refuse-argument-not-classified-by-contract',
    tests_proposed_text: [CLOSED],
    differs_from: 'ADR-01: the call carries an argument, compression, that the copy contract does not mention. No decision is presented.',
    note: 'Closed-argument profile. The value does not look like a resource and the tool would ignore it. The profile refuses it anyway, because the boundary cannot know what an unclassified argument does.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy', { compression: 'gzip', dst: R2, src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_designation_unknown', { path: 'compression' }, null),
  },
  {
    id: 'ADR-07b-refuse-empty-container-not-classified',
    tests_proposed_text: [CLOSED],
    differs_from: 'ADR-07: the undeclared argument is extra, holding an empty object.',
    note: 'An empty container is still a supplied argument. A walk that visits only leaves never sees it.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy', { dst: R2, extra: {}, src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_designation_unknown', { path: 'extra' }, null),
  },
  {
    id: 'ADR-07c-refuse-required-operand-missing',
    tests_proposed_text: [CLOSED],
    differs_from: 'ADR-01: dst is absent. No decision is presented.',
    note: 'The contract declares dst as required. A call that omits it is refused before any designation is checked.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy', { src: R1 }, { src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_operand_missing', { path: 'dst' }, null),
  },
  {
    id: 'ADR-07d-refuse-resource-operand-not-a-string',
    tests_proposed_text: [OPERANDS],
    differs_from: 'ADR-01: dst holds an empty object instead of an identifier. No decision is presented.',
    note: 'A declared resource operand is a node, whatever its value. An object there has no identifier.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy', { dst: {}, src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_resource_identifier_invalid', { path: 'dst' }, null),
  },
  {
    id: 'ADR-08-refuse-traversal-resolves-outside-credential',
    tests_proposed_text: [TB, OPERANDS],
    differs_from: 'ADR-02: dst is spelled res:/store/r1/../r2, which begins with the covered res:/store/r1/ and resolves to res:/store/r2.',
    note: 'Coverage is decided on the resolved identifier, the same one the tool writes. A raw prefix comparison reads it as beneath r1.',
    credentials: ['cred:alice-r1-rw'],
    call: COPY_R1_R1RW('res:/store/r1/../r2'),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dst', resource: R2, operation: 'write' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-08b-admit-cased-alias-resolves-inside-credential',
    tests_proposed_text: [TB, OPERANDS],
    differs_from: 'ADR-01: dst is spelled RES:/Store/R2, a cased spelling of the covered res:/store/r2. No decision is presented.',
    note: 'Resolution works in both directions. A boundary that refuses every non-canonical spelling passes ADR-08 and fails this one.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy', { dst: 'RES:/Store/R2', src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: admit(COPY_R1_R2_TRACE, { [R2]: 'alpha' }),
  },
  {
    id: 'ADR-08c-refuse-traversal-above-root',
    tests_proposed_text: [OPERANDS],
    differs_from: 'ADR-08: dst is res:/store/../../r2, whose second .. has no segment left to remove.',
    note: 'The designation has no canonical identifier, so it is refused as invalid before any credential is consulted.',
    credentials: ['cred:alice-r1-rw'],
    call: COPY_R1_R1RW('res:/store/../../r2'),
    expected: refuseWith('argument_resource_identifier_invalid', { path: 'dst' }, null),
  },
  {
    id: 'ADR-09-refuse-operation-not-granted-on-resource',
    tests_proposed_text: [TB, OPERANDS],
    differs_from: 'ADR-06b: Alice holds and selects only an r2 read credential.',
    note: 'The credential names the resource. It does not carry the operation the tool performs on it. Read and write are disjoint toy rights.',
    credentials: ['cred:alice-r2-read'],
    call: call('overwrite', { content: 'quarterly figures', target: R2 }, { target: 'cred:alice-r2-read' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'target', resource: R2, operation: 'write' }, forbid('write', R2, 'target')),
  },
  {
    id: 'ADR-10-admit-capability-held-by-requester',
    tests_proposed_text: [HOLDER],
    differs_from: 'ADR-01: dst carries a capability reference to cred:alice-r2-write instead of a name, so designation and authority arrive together.',
    note: 'Capability form. The designated resource is the credential\'s own. The credential is resolved against trusted state, is held by Alice and is issued by the owner of res:/store.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: CAP('cred:alice-r2-write'),
    expected: admit([acc('read', R1, 'src', 'cred:alice-r1-read'), acc('write', R2, 'dst', 'cred:alice-r2-write')], { [R2]: 'alpha' }),
  },
  {
    id: 'ADR-10b-refuse-capability-held-by-another-party',
    tests_proposed_text: [HOLDER],
    differs_from: 'ADR-10: the capability is cred:mallory-r2-write, held by party:mallory.',
    note: 'Holder-bound profile only. A capability passed along by its holder is not Alice\'s authority here. This says nothing about bearer tokens, which this profile does not model.',
    credentials: ['cred:alice-r1-read', 'cred:mallory-r2-write'],
    call: CAP('cred:mallory-r2-write'),
    expected: refuseWith('authority_not_held_by_requester', { path: 'dst' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-10c-refuse-capability-wider-than-issuer-authority',
    tests_proposed_text: [HOLDER],
    differs_from: 'ADR-10: the capability is delegated by party:bob from a parent over res:/store/r2/drafts only, and asserts all of res:/store/r2.',
    note: 'The write to r2 lies outside the parent\'s authority, so it is refused whether the over-broad child is rejected outright, as here, or intersected with its parent.',
    credentials: ['cred:alice-r1-read', 'cred:bob-drafts-rw-delegable', 'cred:alice-r2-write-via-drafts'],
    call: CAP('cred:alice-r2-write-via-drafts'),
    expected: refuseWith('authority_exceeds_issuer_authority', { path: 'dst' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-10d-refuse-capability-operation-narrower-than-tool-operation',
    tests_proposed_text: [HOLDER, OPERANDS],
    differs_from: 'ADR-10: the capability is cred:alice-r2-read, and the tool writes dst.',
    note: 'The capability-form counterpart of ADR-09.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-read'],
    call: CAP('cred:alice-r2-read'),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dst', resource: R2, operation: 'write' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-10e-admit-equal-authority-delegation',
    tests_proposed_text: [HOLDER],
    differs_from: 'ADR-10: the capability is delegated by party:bob, whose delegable parent covers exactly r2 write, the same as the child.',
    note: 'Non-amplification permits equality. A child no wider than its parent is valid even when it is not narrower.',
    credentials: ['cred:alice-r1-read', 'cred:bob-r2-write-delegable', 'cred:alice-r2-write-via-bob'],
    call: CAP('cred:alice-r2-write-via-bob'),
    expected: admit([acc('read', R1, 'src', 'cred:alice-r1-read'), acc('write', R2, 'dst', 'cred:alice-r2-write-via-bob')], { [R2]: 'alpha' }),
  },
  {
    id: 'ADR-10f-refuse-issuer-may-exercise-but-not-delegate',
    tests_proposed_text: [HOLDER],
    differs_from: 'ADR-10e: party:bob\'s parent covers r2 write but is not delegable.',
    note: 'Holding an exercise right does not grant a delegation right. Bob could write r2 himself and still cannot pass that on.',
    credentials: ['cred:alice-r1-read', 'cred:bob-r2-write-not-delegable', 'cred:alice-r2-write-via-bob-not-delegable'],
    call: CAP('cred:alice-r2-write-via-bob-not-delegable'),
    expected: refuseWith('authority_issuer_cannot_delegate', { path: 'dst' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-10g-refuse-root-issuer-without-standing',
    tests_proposed_text: [HOLDER],
    differs_from: 'ADR-10: the capability is a root credential issued by party:mallory, which the trusted issuer records do not list as owning anything under res:/store.',
    note: 'Issuer standing comes from trusted fixture-side records, not from what the credential says about itself.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write-from-mallory'],
    call: CAP('cred:alice-r2-write-from-mallory'),
    expected: refuseWith('authority_issuer_without_standing', { path: 'dst' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-11-refuse-argument-changed-after-decision',
    tests_proposed_text: [EXACT],
    differs_from: 'ADR-11b: the decision names copy(src=r1, dst=r2), and the presented call has dst=r3 with Alice\'s r3 write credential selected for it.',
    note: 'Both destinations are fully authorized, so scope checking cannot mask the binding check. The call is refused only because it is not the call the decision named.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write', 'cred:alice-r3-write'],
    call: call('copy', { dst: R3, src: R1 }, { dst: 'cred:alice-r3-write', src: 'cred:alice-r1-read' }),
    decided_call: COPY_R1_R2,
    expected: refuseWith('call_does_not_match_decision', {}, forbid('write', R3, 'dst')),
  },
  {
    id: 'ADR-11b-admit-unchanged-call-under-decision',
    tests_proposed_text: [EXACT],
    differs_from: 'ADR-11: the presented call is the decided call.',
    note: 'Unchanged-call control with the same trusted state as ADR-11.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write', 'cred:alice-r3-write'],
    call: COPY_R1_R2,
    decided_call: COPY_R1_R2,
    expected: admit(COPY_R1_R2_TRACE, { [R2]: 'alpha' }),
  },
  {
    id: 'ADR-12-refuse-read-credential-selected-for-destination',
    tests_proposed_text: [SELECTED],
    differs_from: 'ADR-12b: Alice holds both an r2 read and an r2 write credential and selects the read one for dst.',
    note: 'Holding authority is weaker than selecting it. The boundary evaluates only the credential selected for the operand and does not search Alice\'s other credentials.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-read', 'cred:alice-r2-write'],
    call: call('copy', { dst: R2, src: R1 }, { dst: 'cred:alice-r2-read', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dst', resource: R2, operation: 'write' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-12b-admit-write-credential-selected-for-destination',
    tests_proposed_text: [SELECTED],
    differs_from: 'ADR-12: Alice selects her r2 write credential for dst.',
    note: 'Explicit-selection positive control.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-read', 'cred:alice-r2-write'],
    call: COPY_R1_R2,
    expected: admit(COPY_R1_R2_TRACE, { [R2]: 'alpha' }),
  },
  {
    id: 'ADR-12c-refuse-no-credential-selected-for-destination',
    tests_proposed_text: [SELECTED],
    differs_from: 'ADR-12: Alice selects nothing for dst.',
    note: 'An operand with no selected authority is refused even though Alice holds a credential that would cover it.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-read', 'cred:alice-r2-write'],
    call: call('copy', { dst: R2, src: R1 }, { src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_authority_not_selected', { path: 'dst' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-13-refuse-repeated-resource-sources-swapped',
    tests_proposed_text: [TB, SELECTED],
    differs_from: 'ADR-13b: the two selections are swapped, so the stronger delegated read and write credential sits on src and the read-only root credential sits on dst.',
    note: 'normalize(src=r2, dst=r2) designates r2 twice with different operations. Each occurrence is checked against its own selection. The stronger credential selected for src does not stand in for dst.',
    credentials: ['cred:alice-r2-read', 'cred:bob-store-rw-delegable', 'cred:alice-r2-rw-via-bob'],
    call: call('normalize', { dst: R2, src: R2 }, { dst: 'cred:alice-r2-read', src: 'cred:alice-r2-rw-via-bob' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dst', resource: R2, operation: 'write' }, forbid('write', R2, 'dst')),
  },
  {
    id: 'ADR-13b-admit-repeated-resource-each-source-selected',
    tests_proposed_text: [TB, SELECTED],
    differs_from: 'ADR-13: src selects the root r2 read credential and dst selects the r2 read and write credential delegated by party:bob.',
    note: 'Positive control. Two authority sources, one per occurrence. normalize upper-cases r2 in place.',
    credentials: ['cred:alice-r2-read', 'cred:bob-store-rw-delegable', 'cred:alice-r2-rw-via-bob'],
    call: call('normalize', { dst: R2, src: R2 }, { dst: 'cred:alice-r2-rw-via-bob', src: 'cred:alice-r2-read' }),
    expected: admit([acc('read', R2, 'src', 'cred:alice-r2-read'), acc('write', R2, 'dst', 'cred:alice-r2-rw-via-bob')], { [R2]: 'BETA' }),
  },
  {
    id: 'ADR-13c-refuse-repeated-resource-second-operation-uncovered',
    tests_proposed_text: [SELECTED],
    differs_from: 'ADR-13b: Alice holds only an r2 write credential and selects it for both occurrences.',
    note: 'dst is covered for write. src is not covered for read. The read must not disappear because r2 was already checked once for another operation.',
    credentials: ['cred:alice-r2-write'],
    call: call('normalize', { dst: R2, src: R2 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r2-write' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'src', resource: R2, operation: 'read' }, forbid('read', R2, 'src')),
  },
  {
    id: 'ADR-14-admit-service-writes-own-statistics',
    tests_proposed_text: [SELECTED, SERVICE],
    differs_from: 'ADR-01: the tool is copy_audited, whose contract declares a service-owned write to res:/svc/stats under cred:svc-stats-write.',
    note: 'Hardy\'s statistics file. Caller data moves under Alice\'s selected credentials, and the service records the copy in its own fixed resource under its own declared credential.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy_audited', { dst: R2, src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: admit(
      [...COPY_R1_R2_TRACE, acc('write', STATS, 'service_effects[0]', 'cred:svc-stats-write')],
      { [R2]: 'alpha', [STATS]: `copy ${R1} -> ${R2}` },
    ),
  },
  {
    id: 'ADR-14b-refuse-destination-in-service-home',
    tests_proposed_text: [SELECTED, SERVICE],
    differs_from: 'ADR-14: dst is res:/svc/bill, inside the service\'s own home, and Alice selects her r2 write credential for it.',
    note: 'Hardy\'s billing file. The service could write there under cred:svc-home, but the caller chose this destination and holds no authority over it.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy_audited', { dst: BILL, src: R1 }, { dst: 'cred:alice-r2-write', src: 'cred:alice-r1-read' }),
    expected: refuseWith('argument_resource_not_authorized', { path: 'dst', resource: BILL, operation: 'write' }, forbid('write', BILL, 'dst')),
  },
  {
    id: 'ADR-14c-refuse-caller-selects-service-effect-credential',
    tests_proposed_text: [SERVICE, HOLDER],
    differs_from: 'ADR-14: dst is the service\'s statistics resource and Alice selects the service-effect credential cred:svc-stats-write for it.',
    note: 'The service-owned exception cannot be redirected. The declared service credential authorizes the service\'s fixed effect, and a caller cannot select it for an operand of its own.',
    credentials: ['cred:alice-r1-read', 'cred:alice-r2-write'],
    call: call('copy_audited', { dst: STATS, src: R1 }, { dst: 'cred:svc-stats-write', src: 'cred:alice-r1-read' }),
    expected: refuseWith('authority_not_held_by_requester', { path: 'dst' }, forbid('write', STATS, 'dst')),
  },
]

// ---------------------------------------------------------------------------
// Defective policies. Each changes one knob of one stage of harness.ts and
// leaves every other knob at its reference value. The categories are what the
// change does on these vectors, worked out by hand.

const CATEGORIES = [
  'unsafe_admission',
  'admission_without_forbidden_access',
  'false_refusal',
  'wrong_diagnosis',
  'wrong_effect',
  'wrong_attribution',
] as const
type Category = (typeof CATEGORIES)[number]

interface PolicyDef {
  name: string
  stage: string
  change: string
  characteristic_cases: string[]
  declared: Partial<Record<Category, string[]>>
}

const ids = (...short: string[]): string[] =>
  short.map((s) => {
    const found = CASES.find((c) => c.id.startsWith(`ADR-${s}-`))
    if (found === undefined) throw new Error(`generate: no case ADR-${s}`)
    return found.id
  })

const POLICIES: PolicyDef[] = [
  {
    name: 'no-call-binding',
    stage: 'B',
    change: 'A presented decision is not compared with the call.',
    characteristic_cases: ids('11'),
    declared: { unsafe_admission: ids('11') },
  },
  {
    name: 'leaf-walk',
    stage: 'V',
    change: 'Undeclared-path refusal and designation see only non-container values, as in revision 0.1. An empty container is invisible, and a declared operand holding one yields no designation.',
    characteristic_cases: ids('07b', '07d'),
    declared: { admission_without_forbidden_access: ids('07b', '07d') },
  },
  {
    name: 'open-schema',
    stage: 'V',
    change: 'An argument path the contract does not declare is ignored instead of refused.',
    characteristic_cases: ids('07'),
    declared: { admission_without_forbidden_access: ids('07', '07b') },
  },
  {
    name: 'no-required-check',
    stage: 'V',
    change: 'Required operands are not checked for presence.',
    characteristic_cases: ids('07c'),
    declared: { admission_without_forbidden_access: ids('07c') },
  },
  {
    name: 'target-only',
    stage: 'E',
    change: 'Only the operand at the contract\'s target path is a designation. Validation, binding and service effects are unchanged.',
    characteristic_cases: ids('02', '04', '05'),
    declared: {
      unsafe_admission: ids('02', '03', '04', '05', '08', '10b', '10c', '10d', '10f', '10g', '12', '12c', '13', '14b', '14c'),
      admission_without_forbidden_access: ids('07d', '08c'),
      wrong_attribution: ids('01', '04b', '05b', '05c', '06', '08b', '10', '10e', '11b', '12b', '13b', '14'),
    },
  },
  {
    name: 'shallow-args',
    stage: 'E',
    change: 'Only top-level operands are designations. An operand inside an object or an array is not.',
    characteristic_cases: ids('04'),
    declared: {
      unsafe_admission: ids('04', '05'),
      wrong_attribution: ids('04b', '05b', '05c'),
    },
  },
  {
    name: 'shape-guessing',
    stage: 'E',
    change: 'A declared node holding a string that begins with res: in any case is a resource designation, with the contract\'s operation for a resource operand and read for data. A resource operand holding anything else is not a designation. Capability operands are unchanged.',
    characteristic_cases: ids('06'),
    declared: {
      admission_without_forbidden_access: ids('07d'),
      false_refusal: ids('06', '06b'),
    },
  },
  {
    name: 'dedup-by-resource',
    stage: 'E',
    change: 'After resolution, a designation whose resource was already designated earlier in the walk is skipped.',
    characteristic_cases: ids('13c'),
    declared: {
      unsafe_admission: ids('13c'),
      wrong_attribution: ids('13b'),
    },
  },
  {
    name: 'no-canonicalization',
    stage: 'R',
    change: 'Coverage compares the raw designation string with the same covering rule. The tool still resolves canonically.',
    characteristic_cases: ids('08'),
    declared: {
      unsafe_admission: ids('08'),
      false_refusal: ids('08b'),
      wrong_diagnosis: ids('08c'),
    },
  },
  {
    name: 'wallet-search',
    stage: 'A',
    change: 'When the selected credential fails for a name-form operand, any credential the requester holds in trusted state that passes C and K is used instead.',
    characteristic_cases: ids('12'),
    declared: { unsafe_admission: ids('12', '12c', '13') },
  },
  {
    name: 'pooled-selection',
    stage: 'A',
    change: 'When the selected credential fails for a name-form operand, any credential selected anywhere in the call that passes C and K is used instead.',
    characteristic_cases: ids('13'),
    declared: { unsafe_admission: ids('13') },
  },
  {
    name: 'deputy-authority',
    stage: 'A',
    change: 'When the selected credential fails for a name-form operand, any credential held by the tool\'s service identity that passes C and K for that identity is used instead.',
    characteristic_cases: ids('03'),
    declared: { unsafe_admission: ids('03', '14b', '14c') },
  },
  {
    name: 'holder-unchecked',
    stage: 'C',
    change: 'The credential\'s holder is not compared with the requester.',
    characteristic_cases: ids('10b'),
    declared: { unsafe_admission: ids('10b', '14c') },
  },
  {
    name: 'self-asserted-issuer',
    stage: 'C',
    change: 'A root credential\'s issuer is accepted without consulting the trusted issuer records.',
    characteristic_cases: ids('10g'),
    declared: { unsafe_admission: ids('10g') },
  },
  {
    name: 'delegation-equals-exercise',
    stage: 'C',
    change: 'A parent credential\'s delegable flag is ignored, so holding an exercise right is treated as permission to delegate it.',
    characteristic_cases: ids('10f'),
    declared: { unsafe_admission: ids('10f') },
  },
  {
    name: 'no-attenuation-check',
    stage: 'C',
    change: 'A delegated credential is not compared with its parent\'s resource and operations.',
    characteristic_cases: ids('10c'),
    declared: { unsafe_admission: ids('10c') },
  },
  {
    name: 'strict-attenuation',
    stage: 'C',
    change: 'A delegated credential must be strictly narrower than its parent, so an equal delegation is refused.',
    characteristic_cases: ids('10e'),
    declared: { false_refusal: ids('10e') },
  },
  {
    name: 'resource-not-operation',
    stage: 'K',
    change: 'Coverage checks the resource and ignores the operation. Attenuation along the chain is unchanged.',
    characteristic_cases: ids('09'),
    declared: { unsafe_admission: ids('09', '10d', '12', '13', '13c') },
  },
  {
    name: 'caller-authority-for-service-effects',
    stage: 'F',
    change: 'A service-owned effect needs a credential the caller selects for it, which is revision 0.1\'s rule that service authority is never used. No call selects one.',
    characteristic_cases: ids('14'),
    declared: { false_refusal: ids('14') },
  },
]

// ---------------------------------------------------------------------------
// Proposed text.

const PROPOSED_TEXT = {
  'target-binding': {
    role: 'motivating concept, not the rule under test',
    repository: 'https://github.com/aeoess/agent-authority-lifecycle',
    document: 'AUTHORITY-LIFECYCLE.md',
    section: 'Lifecycle concepts are separate > Authority and dependencies',
    commit: '5c1bf09ee29d517f2f19c9bb9212543a7c44b227',
    commit_version: '0.1.2-draft',
    also_verbatim_at_commit: '57eb7421e3437d8d5fc372225dc49a9176c281f4',
    quote: 'Target binding. Which resource, counterparty or object the authority applies to. Continuity of a name does not by itself establish continuity of the thing named.',
    status_in_that_document: 'proposed',
    draft04_counterpart: {
      section: '8.1. Concepts',
      lines: '3634-3636',
      quote: 'Target binding Which resource, counterparty or object the authority applies to. Continuity of a name does not on its own establish continuity of the thing named.',
      attaches_a_rule: false,
    },
  },
  [OPERANDS]: {
    profile: 'caller-supplied-resource profile, revision 0.2',
    quote: 'For this family\'s caller-supplied-resource profile, the boundary identifies every resource operand that the trusted tool contract says will be accessed, and the operation required on that operand.',
    status: 'proposed in README.md',
  },
  [SELECTED]: {
    profile: 'caller-supplied-resource profile, revision 0.2',
    quote: 'It authorizes each operand using authority explicitly selected for that operand in this invocation. It does not substitute ambient service credentials or other credentials held by the requester.',
    status: 'proposed in README.md',
  },
  [CLOSED]: {
    profile: 'caller-supplied-resource profile, revision 0.2',
    quote: 'Supplied arguments the contract does not classify are refused under this profile, and so is a call that omits an operand the contract requires.',
    status: 'proposed in README.md',
  },
  [SERVICE]: {
    profile: 'caller-supplied-resource profile, revision 0.2',
    quote: 'Any service-owned effect uses a separately declared authority source and cannot be redirected by that exception to a resource the caller selects.',
    status: 'proposed in README.md',
  },
  [HOLDER]: {
    profile: 'caller-supplied-resource profile, revision 0.2',
    quote: 'Under this profile a credential is resolved against trusted state, must be held by the authenticated requester, and must chain to an issuer the trusted issuer records give standing over the resource. A delegated credential needs a delegable parent held by its issuer and may be equal to that parent but no wider.',
    status: 'proposed in README.md',
  },
  [EXACT]: {
    profile: 'caller-supplied-resource profile, revision 0.2',
    quote: 'When a decision is presented, the boundary admits only the exact call the decision names, including its authority selections.',
    status: 'proposed in README.md, an analogue of draft-pidlisnyi-aps-04 section 9.2 over this family\'s own call reference',
  },
}

const DRAFT04 = {
  document: 'draft-pidlisnyi-aps-04',
  url: 'https://www.ietf.org/archive/id/draft-pidlisnyi-aps-04.txt',
  states_this_rule: false,
  target: {
    section: '5.1. Action Reference Computation',
    lines: '2433-2436',
    quote: 'target is the exact resource, tool, or endpoint against which the action will be dispatched; a profile MUST define its target string construction.',
  },
  exact_call: {
    section: '9.2. The Exact Call',
    lines: '6237-6241',
    quote: 'At the next authorization boundary the boundary MUST compare the call it is about to admit against the action the approval names, and MUST NOT admit a call whose action reference differs from it. An argument changed after the decision produces a different action reference, so the comparison catches it without any separate argument-level rule.',
  },
  exact_call_non_establishment: {
    section: '9.2. The Exact Call',
    lines: '6252-6253',
    quote: 'It does not establish that the arguments mean what the requesting agent intended them to mean.',
  },
}

// ---------------------------------------------------------------------------

function assertCanonical(res: string, where: string): void {
  if (canonicalizeResource(res) !== res) throw new Error(`generate: ${where} ${res} is not a canonical identifier`)
}

function referencedCredentials(c: CaseDef): string[] {
  const out: string[] = []
  const calls = c.decided_call === undefined ? [c.call] : [c.call, c.decided_call]
  for (const k of calls) {
    out.push(...Object.values(k.authority))
    const walk = (v: Json): void => {
      if (Array.isArray(v)) v.forEach(walk)
      else if (v !== null && typeof v === 'object') {
        if (typeof v.capability === 'string' && Object.keys(v).length === 1) out.push(v.capability)
        else Object.values(v).forEach(walk)
      }
    }
    walk(k.arguments)
  }
  return out
}

export function buildVectors(): unknown {
  for (const cred of LIBRARY) assertCanonical(cred.resource, `credential ${cred.id}`)
  for (const [issuer, roots] of Object.entries(ISSUER_RECORDS)) roots.forEach((r) => assertCanonical(r, `issuer record ${issuer}`))
  for (const r of Object.keys(INITIAL_STORE)) assertCanonical(r, 'initial store')
  for (const [name, tool] of Object.entries(TOOLS)) tool.service_effects.forEach((e) => assertCanonical(e.resource, `${name} service effect`))

  const fixture: Fixture = { tools: TOOLS, issuer_records: ISSUER_RECORDS, initial_store: INITIAL_STORE }
  const seen = new Set<string>()
  const presentations = CASES.map((c) => {
    if (seen.has(c.id)) throw new Error(`generate: duplicate case ${c.id}`)
    seen.add(c.id)
    const idsInState = [...new Set([...SERVICE_BASELINE, ...c.credentials])].sort()
    const credentials = idsInState.map((id) => {
      const cred = BY_ID.get(id)
      if (cred === undefined) throw new Error(`generate: ${c.id} lists unknown credential ${id}`)
      return cred
    })
    for (const cred of credentials) {
      if (cred.parent !== null && !idsInState.includes(cred.parent)) throw new Error(`generate: ${c.id} lacks parent ${cred.parent}`)
    }
    for (const id of referencedCredentials(c)) {
      if (!idsInState.includes(id)) throw new Error(`generate: ${c.id} references ${id}, which is not in its trusted state`)
    }
    if (c.expected.decision.verdict === 'admitted' && c.expected.forbidden_access !== null) {
      throw new Error(`generate: ${c.id} is admitted and names a forbidden access`)
    }
    return {
      id: c.id,
      status: 'candidate_against_proposed',
      tests_proposed_text: c.tests_proposed_text,
      differs_from: c.differs_from,
      note: c.note,
      trusted_state: { credentials },
      call: c.call,
      decision: c.decided_call === undefined ? null : { call: c.decided_call, call_ref: callRef(c.decided_call) },
      inject_failure: c.inject_failure ?? null,
      expected: c.expected,
    }
  })

  const defective_policies = POLICIES.map((p) => {
    const declared: Record<string, string[]> = {}
    for (const category of CATEGORIES) declared[category] = [...(p.declared[category] ?? [])].sort()
    for (const id of p.characteristic_cases) {
      if (!CATEGORIES.some((cat) => declared[cat]!.includes(id))) throw new Error(`generate: ${p.name} characteristic ${id} is not declared`)
    }
    return { name: p.name, stage: p.stage, change: p.change, characteristic_cases: p.characteristic_cases, declared }
  })

  return {
    family: 'argument-designated-resources',
    profile: 'caller-supplied-resource profile, revision 0.2',
    status: 'candidate_against_proposed',
    status_meaning: 'The proposed text these vectors test is immature. This is an ordinary lab-authored fixture, not a docs/CANDIDATES.md submission.',
    description:
      'Resources designated inside invocation arguments (the confused deputy). A synthetic boundary in front of a synthetic tool registry decides whether every resource operand a call designates is authorized by the credential the caller selected for that operand, separately from service-owned effects that run under a declared service credential. Admitted calls run against an in-memory store with an access trace. Every vector is candidate against proposed text. draft-pidlisnyi-aps-04 states no such rule. See README.',
    evaluation: 'Each presentation is an independent evaluation against a fresh copy of initial_store. No state is carried between presentations and presentation order does not matter.',
    assumptions: [
      'The requester is an assumed authenticated identity.',
      'Tool contracts are trusted and honest: each tool performs exactly the accesses its program in README "Tools" lists. Dishonest or stale contracts are outside v0.',
      'Credentials and issuer records are trusted fixture-side state. A call names credentials by identifier only.',
      'Resolution is lexical and pinned. The boundary and the tool resolve through the same function and nothing changes between admission and execution.',
    ],
    proposed_text: PROPOSED_TEXT,
    draft04: DRAFT04,
    identifiers: {
      definition: 'README.md, section Identifier grammar',
      covering_rule: 'A credential over canonical identifier E covers canonical identifier R when R equals E or R begins with E followed by /.',
    },
    call_ref: {
      domain: CALL_REF_DOMAIN,
      construction: '"sha256:" || lowercase-hex(SHA-256(ASCII(domain) || 0x00 || UTF8(JCS(call))))',
      note: 'This family\'s own call reference over its own call object {tool, requester, arguments, authority}. It is not an APS action_ref.',
    },
    categories: CATEGORIES,
    ...fixture,
    defective_policies,
    presentations,
  }
}

export function serializeVectors(): string {
  return `${JSON.stringify(buildVectors(), null, 2)}\n`
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  writeFileSync(join(here, 'vectors.json'), serializeVectors())
  console.log('wrote fixtures/argument-designated-resources/vectors.json')
}
