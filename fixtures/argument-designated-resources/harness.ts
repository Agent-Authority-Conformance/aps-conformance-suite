// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the argument-designated-resources candidate family,
// caller-supplied-resource profile, revision 0.2.
//
// WHAT THIS IS. A synthetic enforcement point in front of a synthetic tool
// registry and a synthetic in-memory resource store. Each tool has a trusted
// contract that declares, per argument path, whether the argument is a resource
// operand, a capability operand or plain data, and which operation the tool
// performs on each operand. A call names, per operand path, the credential it
// selects as authority for that operand. Credentials are resolved against
// trusted fixture state. A tool may also have service-owned effects, each with
// a fixed resource and a separately declared service credential. When the
// boundary admits a call, the tool runs against the store and every access is
// recorded in a trace. Nothing here is an APS type, an APS receipt or an APS
// decision. A result here is a statement about this model and nothing else.
//
// THE STAGES. The reference runs these in order and stops at the first refusal.
//
//   B  binding       a presented decision must name exactly this call
//   V  validation    argument keys, undeclared paths, required operands
//   E  enumeration   which operands are designations, from the contract
//   R  resolution    canonical resource identifiers
//   A  selection     the credential selected for this operand, and no other
//   C  credential    holder, issuer standing, delegation permission, attenuation
//   K  coverage      the credential covers this resource for this operation
//   F  service       service-owned effects under their declared credential
//
// Each defective policy changes exactly one knob of one stage. Every other
// knob keeps its reference value. README "Defective policies" lists them.
//
// Node builtins only. No wall clock, no randomness, no network.

import { createHash } from 'node:crypto'

export type Operation = 'read' | 'write'

export type OperandSpec =
  | { kind: 'resource'; operation: Operation; required: boolean }
  | { kind: 'capability'; operation: Operation; required: boolean }
  | { kind: 'data'; required: boolean }

export interface ServiceEffect {
  resource: string
  operation: Operation
  authority: string
}

export interface ToolContract {
  service_identity: string
  target: string
  arguments: Record<string, OperandSpec>
  service_effects: ServiceEffect[]
}

export interface Credential {
  id: string
  holder: string
  issuer: string
  resource: string
  operations: Operation[]
  delegable: boolean
  parent: string | null
}

export type Json = string | boolean | null | Json[] | { [key: string]: Json }

export interface Call {
  tool: string
  requester: string
  arguments: { [key: string]: Json }
  authority: { [path: string]: string }
}

export interface Presentation {
  trusted_state: { credentials: Credential[] }
  call: Call
  decision: { call: Call; call_ref: string } | null
  inject_failure: { path: string } | null
}

export interface Fixture {
  tools: Record<string, ToolContract>
  issuer_records: Record<string, string[]>
  initial_store: Record<string, string>
}

export interface Decision {
  verdict: 'admitted' | 'refused'
  reason: string
  path?: string
  resource?: string
  operation?: Operation
}

export interface Access {
  operation: Operation
  resource: string
  path: string
  authority: string | null
  holder: string | null
}

export interface Execution {
  status: 'not_run' | 'completed' | 'partial'
  stopped_at?: string
  cause?: 'injected_failure' | 'operand_unresolvable' | 'resource_absent'
}

export interface Outcome {
  decision: Decision
  execution: Execution
  trace: Access[]
  store: Record<string, string>
}

// ---------------------------------------------------------------------------
// Identifiers. README "Identifier grammar" is the definition. This function and
// verify.py's are two implementations of it. The boundary and the tool both
// resolve through it, so they always agree on which resource a string names.

const SEGMENT = /^[a-z0-9_-]+$/

export function canonicalizeResource(raw: string): string | null {
  if (raw.length < 5 || raw.slice(0, 4).toLowerCase() !== 'res:' || raw[4] !== '/') return null
  const stack: string[] = []
  for (const part of raw.slice(5).split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') {
      if (stack.length === 0) return null
      stack.pop()
      continue
    }
    const lowered = part.replace(/[A-Z]/g, (c) => c.toLowerCase())
    if (!SEGMENT.test(lowered)) return null
    stack.push(lowered)
  }
  if (stack.length === 0) return null
  return `res:/${stack.join('/')}`
}

/** An identifier covers itself and every identifier beneath it. */
export function covers(entry: string, resource: string): boolean {
  return resource === entry || resource.startsWith(`${entry}/`)
}

export const ARGUMENT_KEY = /^[a-z][a-z0-9_]*$/

// ---------------------------------------------------------------------------
// The call reference. Not an APS action_ref. It follows the domain-separated
// digest style of draft-pidlisnyi-aps-04 section 5.1 over this family's own
// call object, so that "the exact call" has a byte-level meaning here.

export const CALL_REF_DOMAIN = 'ADR-CALL-REF-V0'

/** RFC 8785 JCS for the value space this family uses: strings, booleans, null,
 *  arrays and objects, printable ASCII only. Numbers are refused. */
export function jcs(value: Json): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') {
    if (!/^[\x20-\x7e]*$/.test(value)) throw new Error(`jcs: non-printable-ASCII string ${JSON.stringify(value)}`)
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort()
    return `{${keys.map((k) => `${jcs(k)}:${jcs(value[k] as Json)}`).join(',')}}`
  }
  throw new Error(`jcs: unsupported value of type ${typeof value}`)
}

export function callRef(call: Call): string {
  const preimage = Buffer.concat([
    Buffer.from(CALL_REF_DOMAIN, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(jcs(call as unknown as Json), 'utf8'),
  ])
  return `sha256:${createHash('sha256').update(preimage).digest('hex')}`
}

// ---------------------------------------------------------------------------
// Policies.

export interface Policy {
  readonly name: string
  readonly binding: boolean
  readonly walk: 'nodes' | 'leaves'
  readonly undeclared: 'refuse' | 'ignore'
  readonly requiredOperands: boolean
  readonly enumerate: 'contract' | 'target-only' | 'top-level' | 'shape'
  readonly dedupByResource: boolean
  readonly canonicalize: boolean
  readonly fallback: 'none' | 'wallet' | 'pooled' | 'service'
  readonly checkHolder: boolean
  readonly standing: 'issuer-records' | 'self-asserted'
  readonly checkDelegable: boolean
  readonly attenuation: 'within' | 'none' | 'strict'
  readonly checkOperation: boolean
  readonly serviceEffects: 'declared' | 'caller'
}

export const REFERENCE: Policy = {
  name: 'reference-boundary',
  binding: true,
  walk: 'nodes',
  undeclared: 'refuse',
  requiredOperands: true,
  enumerate: 'contract',
  dedupByResource: false,
  canonicalize: true,
  fallback: 'none',
  checkHolder: true,
  standing: 'issuer-records',
  checkDelegable: true,
  attenuation: 'within',
  checkOperation: true,
  serviceEffects: 'declared',
}

export const DEFECTIVE: readonly Policy[] = [
  { ...REFERENCE, name: 'no-call-binding', binding: false },
  { ...REFERENCE, name: 'leaf-walk', walk: 'leaves' },
  { ...REFERENCE, name: 'open-schema', undeclared: 'ignore' },
  { ...REFERENCE, name: 'no-required-check', requiredOperands: false },
  { ...REFERENCE, name: 'target-only', enumerate: 'target-only' },
  { ...REFERENCE, name: 'shallow-args', enumerate: 'top-level' },
  { ...REFERENCE, name: 'shape-guessing', enumerate: 'shape' },
  { ...REFERENCE, name: 'dedup-by-resource', dedupByResource: true },
  { ...REFERENCE, name: 'no-canonicalization', canonicalize: false },
  { ...REFERENCE, name: 'wallet-search', fallback: 'wallet' },
  { ...REFERENCE, name: 'pooled-selection', fallback: 'pooled' },
  { ...REFERENCE, name: 'deputy-authority', fallback: 'service' },
  { ...REFERENCE, name: 'holder-unchecked', checkHolder: false },
  { ...REFERENCE, name: 'self-asserted-issuer', standing: 'self-asserted' },
  { ...REFERENCE, name: 'delegation-equals-exercise', checkDelegable: false },
  { ...REFERENCE, name: 'no-attenuation-check', attenuation: 'none' },
  { ...REFERENCE, name: 'strict-attenuation', attenuation: 'strict' },
  { ...REFERENCE, name: 'resource-not-operation', checkOperation: false },
  { ...REFERENCE, name: 'caller-authority-for-service-effects', serviceEffects: 'caller' },
]

// ---------------------------------------------------------------------------
// Argument tree helpers.

/** Own-property lookup. Every table keyed by a caller-supplied string goes
 *  through this, so a key such as `constructor` never reaches Object.prototype. */
export function own<T>(table: { readonly [key: string]: T }, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined
}

function isObject(value: Json | undefined): value is { [key: string]: Json } {
  return value !== null && value !== undefined && typeof value === 'object' && !Array.isArray(value)
}

function isCapabilityRef(value: Json | undefined): value is { capability: string } {
  if (!isObject(value)) return false
  const keys = Object.keys(value)
  return keys.length === 1 && keys[0] === 'capability' && typeof value.capability === 'string'
}

interface Node {
  path: string
  pattern: string
  value: Json
  spec: OperandSpec
}

class Refusal {
  constructor(readonly decision: Decision) {}
}

function refuse(reason: string, detail: Omit<Decision, 'verdict' | 'reason'> = {}): never {
  throw new Refusal({ verdict: 'refused', reason, ...detail })
}

/** 'object' or 'array' when some declared pattern lies beneath `pattern`. */
function containerKind(contract: ToolContract, pattern: string): 'object' | 'array' | null {
  for (const declared of Object.keys(contract.arguments)) {
    if (declared.startsWith(`${pattern}.`)) return 'object'
    if (declared.startsWith(`${pattern}[]`)) return 'array'
  }
  return null
}

function childPath(parent: string, key: string): string {
  return parent === '' ? key : `${parent}.${key}`
}

function invalidKeyPath(parent: string, key: string): string {
  return `${parent}[${JSON.stringify(key)}]`
}

/** Reference walk (V1 and V2 over nodes). Declared nodes are leaves of the walk
 *  whatever their value. A container on the way to a declared path is entered
 *  only if it has the container type the contract implies. */
function walkNodes(policy: Policy, contract: ToolContract, args: { [key: string]: Json }): Node[] {
  const out: Node[] = []
  const visitChild = (value: Json, path: string, pattern: string): void => {
    const spec = own(contract.arguments, pattern)
    if (spec !== undefined) {
      out.push({ path, pattern, value, spec })
      return
    }
    const kind = containerKind(contract, pattern)
    if (kind === 'object') {
      if (isObject(value)) visitObject(value, path, pattern)
      return
    }
    if (kind === 'array') {
      if (Array.isArray(value)) value.forEach((item, i) => visitChild(item, `${path}[${i}]`, `${pattern}[]`))
      return
    }
    if (policy.undeclared === 'refuse') refuse('argument_designation_unknown', { path })
  }
  const visitObject = (obj: { [key: string]: Json }, path: string, pattern: string): void => {
    for (const key of Object.keys(obj).sort()) {
      if (!ARGUMENT_KEY.test(key)) refuse('argument_key_invalid', { path: invalidKeyPath(path, key) })
      visitChild(obj[key] as Json, childPath(path, key), childPath(pattern, key))
    }
  }
  visitObject(args, '', '')
  return out
}

/** leaf-walk: V2 and E see only non-container values. Every container is
 *  entered, declared or not, and a container with nothing inside is invisible.
 *  A declared capability path is still one leaf. */
function walkLeaves(policy: Policy, contract: ToolContract, args: { [key: string]: Json }): Node[] {
  const out: Node[] = []
  const visit = (value: Json, path: string, pattern: string): void => {
    const spec = own(contract.arguments, pattern)
    if (path !== '' && spec?.kind === 'capability') {
      out.push({ path, pattern, value, spec })
    } else if (isObject(value)) {
      for (const key of Object.keys(value).sort()) {
        if (!ARGUMENT_KEY.test(key)) refuse('argument_key_invalid', { path: invalidKeyPath(path, key) })
        visit(value[key] as Json, childPath(path, key), childPath(pattern, key))
      }
    } else if (Array.isArray(value)) {
      value.forEach((item, i) => visit(item, `${path}[${i}]`, `${pattern}[]`))
    } else if (spec !== undefined) {
      out.push({ path, pattern, value, spec })
    } else if (policy.undeclared === 'refuse') {
      refuse('argument_designation_unknown', { path })
    }
  }
  visit(args, '', '')
  return out
}

/** V3. A declared pattern is present when every object key on the way exists
 *  and, for an array pattern, the array itself exists. */
function present(args: { [key: string]: Json }, pattern: string): boolean {
  let current: Json | undefined = args
  for (const segment of pattern.split('.')) {
    const isArray = segment.endsWith('[]')
    const key = isArray ? segment.slice(0, -2) : segment
    if (!isObject(current) || !Object.prototype.hasOwnProperty.call(current, key)) return false
    current = current[key]
    if (isArray) return Array.isArray(current)
  }
  return true
}

/** Concrete path lookup, `options.output.path` or `dsts[1]`. */
export function valueAt(args: { [key: string]: Json }, path: string): Json | undefined {
  let current: Json | undefined = args
  for (const token of path.match(/[^.[\]]+|\[\d+\]/g) ?? []) {
    if (token.startsWith('[')) {
      if (!Array.isArray(current)) return undefined
      current = current[Number(token.slice(1, -1))]
    } else {
      if (!isObject(current) || !Object.prototype.hasOwnProperty.call(current, token)) return undefined
      current = current[token]
    }
  }
  return current
}

// ---------------------------------------------------------------------------
// Credentials.

interface Context {
  policy: Policy
  fixture: Fixture
  credentials: Map<string, Credential>
}

function credential(ctx: Context, id: string): Credential {
  const found = ctx.credentials.get(id)
  if (found === undefined) throw new Error(`harness input error: credential ${id} is not in trusted state`)
  return found
}

/** C2 to C4 along the chain. Returns a refusal reason or null. */
function chainFailure(ctx: Context, start: Credential): string | null {
  const { policy } = ctx
  let current = start
  for (;;) {
    if (current.parent === null) {
      if (policy.standing === 'issuer-records') {
        const owned = own(ctx.fixture.issuer_records, current.issuer) ?? []
        if (!owned.some((root) => covers(root, current.resource))) return 'authority_issuer_without_standing'
      }
      return null
    }
    const parent = credential(ctx, current.parent)
    if (parent.holder !== current.issuer) return 'authority_issuer_without_standing'
    if (policy.checkDelegable && !parent.delegable) return 'authority_issuer_cannot_delegate'
    if (policy.attenuation !== 'none') {
      const within = covers(parent.resource, current.resource) && current.operations.every((op) => parent.operations.includes(op))
      const narrower = current.resource !== parent.resource || current.operations.length < parent.operations.length
      if (!within || (policy.attenuation === 'strict' && !narrower)) return 'authority_exceeds_issuer_authority'
    }
    current = parent
  }
}

/** C1 to C4, then K. Returns the refusal or null. */
function credentialFailure(
  ctx: Context,
  cred: Credential,
  expectedHolder: string,
  resource: string,
  operation: Operation,
  path: string,
): Decision | null {
  if (ctx.policy.checkHolder && cred.holder !== expectedHolder) {
    return { verdict: 'refused', reason: 'authority_not_held_by_requester', path }
  }
  const chain = chainFailure(ctx, cred)
  if (chain !== null) return { verdict: 'refused', reason: chain, path }
  if (!covers(cred.resource, resource) || (ctx.policy.checkOperation && !cred.operations.includes(operation))) {
    return { verdict: 'refused', reason: 'argument_resource_not_authorized', path, resource, operation }
  }
  return null
}

function byId(a: Credential, b: Credential): number {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

// ---------------------------------------------------------------------------
// The boundary.

interface Designation {
  path: string
  kind: 'resource' | 'capability'
  operation: Operation
  value: Json
}

function designations(policy: Policy, contract: ToolContract, nodes: Node[]): Designation[] {
  const out: Designation[] = []
  for (const node of nodes) {
    const { spec } = node
    if (policy.enumerate === 'shape') {
      if (spec.kind === 'capability') {
        out.push({ path: node.path, kind: 'capability', operation: spec.operation, value: node.value })
      } else if (typeof node.value === 'string' && /^res:/i.test(node.value)) {
        out.push({ path: node.path, kind: 'resource', operation: spec.kind === 'resource' ? spec.operation : 'read', value: node.value })
      }
      continue
    }
    if (spec.kind === 'data') continue
    if (policy.enumerate === 'target-only' && node.path !== contract.target) continue
    if (policy.enumerate === 'top-level' && (node.pattern.includes('.') || node.pattern.includes('['))) continue
    out.push({ path: node.path, kind: spec.kind, operation: spec.operation, value: node.value })
  }
  return out
}

export interface Admission {
  decision: Decision
  admitted: Record<string, string>
}

export function decide(policy: Policy, fixture: Fixture, presentation: Presentation): Admission {
  const { call } = presentation
  const ctx: Context = {
    policy,
    fixture,
    credentials: new Map(presentation.trusted_state.credentials.map((c) => [c.id, c])),
  }
  const admitted: Record<string, string> = {}
  try {
    // B
    if (policy.binding && presentation.decision !== null && callRef(call) !== presentation.decision.call_ref) {
      refuse('call_does_not_match_decision')
    }
    const contract = own(fixture.tools, call.tool)
    if (contract === undefined) throw new Error(`harness input error: unknown tool ${call.tool}`)

    // V
    const nodes = policy.walk === 'nodes' ? walkNodes(policy, contract, call.arguments) : walkLeaves(policy, contract, call.arguments)
    if (policy.requiredOperands) {
      for (const pattern of Object.keys(contract.arguments).sort()) {
        if (contract.arguments[pattern]!.required && !present(call.arguments, pattern)) {
          refuse('argument_operand_missing', { path: pattern })
        }
      }
    }

    // E, R, A, C, K
    const seen = new Set<string>()
    for (const d of designations(policy, contract, nodes)) {
      if (d.kind === 'capability') {
        if (!isCapabilityRef(d.value)) refuse('argument_resource_identifier_invalid', { path: d.path })
        const cred = credential(ctx, d.value.capability)
        const failure = credentialFailure(ctx, cred, call.requester, cred.resource, d.operation, d.path)
        if (failure !== null) throw new Refusal(failure)
        admitted[d.path] = cred.id
        continue
      }
      if (typeof d.value !== 'string') refuse('argument_resource_identifier_invalid', { path: d.path })
      const resource = policy.canonicalize ? canonicalizeResource(d.value) : d.value
      if (resource === null) refuse('argument_resource_identifier_invalid', { path: d.path })
      if (policy.dedupByResource) {
        if (seen.has(resource)) continue
        seen.add(resource)
      }
      const selected = own(call.authority, d.path)
      const failure =
        selected === undefined
          ? { verdict: 'refused' as const, reason: 'argument_authority_not_selected', path: d.path }
          : credentialFailure(ctx, credential(ctx, selected), call.requester, resource, d.operation, d.path)
      if (failure === null) {
        admitted[d.path] = selected!
        continue
      }
      if (policy.fallback !== 'none') {
        let pool: Credential[]
        let holder = call.requester
        if (policy.fallback === 'wallet') {
          pool = [...ctx.credentials.values()].filter((c) => c.holder === call.requester)
        } else if (policy.fallback === 'pooled') {
          pool = [...new Set(Object.values(call.authority))].map((id) => credential(ctx, id))
        } else {
          holder = contract.service_identity
          pool = [...ctx.credentials.values()].filter((c) => c.holder === contract.service_identity)
        }
        const substitute = pool.sort(byId).find((c) => credentialFailure(ctx, c, holder, resource, d.operation, d.path) === null)
        if (substitute !== undefined) {
          admitted[d.path] = substitute.id
          continue
        }
      }
      throw new Refusal(failure)
    }

    // F
    contract.service_effects.forEach((effect, i) => {
      const path = `service_effects[${i}]`
      const detail = { path, resource: effect.resource, operation: effect.operation }
      let cred: Credential
      let holder: string
      if (policy.serviceEffects === 'declared') {
        cred = credential(ctx, effect.authority)
        holder = contract.service_identity
      } else {
        const selected = own(call.authority, path)
        if (selected === undefined) refuse('service_effect_not_authorized', detail)
        cred = credential(ctx, selected)
        holder = call.requester
      }
      if (credentialFailure(ctx, cred, holder, effect.resource, effect.operation, path) !== null) {
        refuse('service_effect_not_authorized', detail)
      }
      admitted[path] = cred.id
    })
  } catch (e) {
    if (e instanceof Refusal) return { decision: e.decision, admitted: {} }
    throw e
  }
  return { decision: { verdict: 'admitted', reason: 'all_designations_authorized' }, admitted }
}

// ---------------------------------------------------------------------------
// The tool. It runs only after admission, reads its own arguments and resolves
// them with the same canonicalizeResource the boundary uses. Each program is
// fixed and is listed in README "Tools".

class Stop {
  constructor(readonly path: string, readonly cause: NonNullable<Execution['cause']>) {}
}

function sortedStore(store: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const key of Object.keys(store).sort()) out[key] = store[key]!
  return out
}

export function execute(fixture: Fixture, presentation: Presentation, admitted: Record<string, string>): Omit<Outcome, 'decision'> {
  const { call } = presentation
  const contract = own(fixture.tools, call.tool)!
  const args = call.arguments
  const credentials = new Map(presentation.trusted_state.credentials.map((c) => [c.id, c]))
  const store: Record<string, string> = { ...fixture.initial_store }
  const trace: Access[] = []

  const resolve = (path: string): string | null => {
    const value = valueAt(args, path)
    const spec = own(contract.arguments, path.replace(/\[\d+\]/g, '[]'))
    if (spec?.kind === 'capability') {
      if (!isCapabilityRef(value)) return null
      return credentials.get(value.capability)?.resource ?? null
    }
    return typeof value === 'string' ? canonicalizeResource(value) : null
  }
  const record = (operation: Operation, resource: string, path: string): void => {
    const authority = own(admitted, path) ?? null
    trace.push({ operation, resource, path, authority, holder: authority === null ? null : credentials.get(authority)!.holder })
  }
  const gate = (path: string): void => {
    if (presentation.inject_failure !== null && presentation.inject_failure.path === path) throw new Stop(path, 'injected_failure')
  }
  const read = (path: string): string => {
    gate(path)
    const resource = resolve(path)
    if (resource === null) throw new Stop(path, 'operand_unresolvable')
    if (!Object.prototype.hasOwnProperty.call(store, resource)) throw new Stop(path, 'resource_absent')
    record('read', resource, path)
    return store[resource]!
  }
  const write = (path: string, value: string): void => {
    gate(path)
    const resource = resolve(path)
    if (resource === null) throw new Stop(path, 'operand_unresolvable')
    store[resource] = value
    record('write', resource, path)
  }
  const serviceWrite = (index: number, value: string): void => {
    const path = `service_effects[${index}]`
    gate(path)
    const effect = contract.service_effects[index]!
    store[effect.resource] = value
    record('write', effect.resource, path)
  }
  const data = (path: string): string => {
    const value = valueAt(args, path)
    if (typeof value !== 'string') throw new Error(`harness input error: data argument ${path} is not a string`)
    return value
  }

  let execution: Execution = { status: 'completed' }
  try {
    switch (call.tool) {
      case 'copy':
      case 'copy_with_capability':
        write('dst', read('src'))
        break
      case 'copy_audited':
        write('dst', read('src'))
        serviceWrite(0, `copy ${resolve('src')} -> ${resolve('dst')}`)
        break
      case 'export': {
        const content = read('src')
        write('options.output.path', `${data('options.output.format')}:${content}`)
        break
      }
      case 'replicate': {
        const content = read('src')
        const dsts = valueAt(args, 'dsts')
        if (!Array.isArray(dsts)) throw new Stop('dsts[]', 'operand_unresolvable')
        dsts.forEach((_, i) => write(`dsts[${i}]`, content))
        break
      }
      case 'overwrite':
        write('target', data('content'))
        break
      case 'normalize':
        write('dst', read('src').replace(/[a-z]/g, (c) => c.toUpperCase()))
        break
      default:
        throw new Error(`harness input error: no program for tool ${call.tool}`)
    }
  } catch (e) {
    if (!(e instanceof Stop)) throw e
    execution = { status: 'partial', stopped_at: e.path, cause: e.cause }
  }
  return { execution, trace, store: sortedStore(store) }
}

export function evaluate(policy: Policy, fixture: Fixture, presentation: Presentation): Outcome {
  const { decision, admitted } = decide(policy, fixture, presentation)
  if (decision.verdict === 'refused') {
    return { decision, execution: { status: 'not_run' }, trace: [], store: sortedStore({ ...fixture.initial_store }) }
  }
  return { decision, ...execute(fixture, presentation, admitted) }
}
