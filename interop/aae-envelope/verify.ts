// Conformance runner for the AAE chain-envelope interop vectors. Run as:
//   npm run verify:aae-envelope
//   (or: npx tsx interop/aae-envelope/verify.ts)
//
// Loads the four V*.json vectors (MoltyCel AAE chain-envelope shape:
// {"chain":[parent, child]}), maps each AAE credential to a REAL APS
// delegation via a small adapter, then decides each chain with the SHIPPED
// APS verifier primitives - verifyDelegation (signature / expiry / notBefore /
// revocation / depth) and scopeCovers (monotonic narrowing). The decision is
// real SDK output; this runner only adapts inputs and asserts the expected
// result + reason code per vector. It also reads the SDK's per-node `valid`
// flag and fails a vector when that flag disagrees with the node-level
// conditions the decision was derived from.
//
// The repo's existing fixtures use tsx runner scripts (see
// fixtures/composition/*/verify.ts), not vitest; this runner follows that
// convention. Same contract: walk vectors, assert expected, exit non-zero on
// any mismatch.
//
// V4 note: revocation is consulted WHEN THE CHAIN IS VERIFIED (check-time
// cascade). A revoked parent invalidates the child subtree in the same
// verification pass - not on a later lookup. Matches NEG-STALE-REVOCATION.
//
// Revocation input is fixture-supplied revocation state: the status written in
// each vector's revocation_check object, handed to the SDK as
// cachedRevocationState. It is never live revocation resolution. No endpoint is
// queried, and AAE's revocation_check (an HTTPS URI template) is not read as one.
//
// Clock: verifyDelegation reads Date.now() for expiry, notBefore and evidence
// freshness and takes no evaluation-instant option, so this runner reads the
// same clock (Date.now) for checkedAt. Results for time-bounded vectors (V3)
// depend on when the runner is executed.
//
// The functions below are exported for runners/ts/aae-envelope-revocation-evidence.test.ts;
// the vector walk at the bottom runs only when this file is the entry point.

import { readFileSync, realpathSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ── Load the SHIPPED APS SDK verifier (published package; no source modified) ──
// Resolves the `agent-passport-system` package pinned at an exact version in
// package.json, so a clean checkout plus `npm ci` is self-contained. APS_SDK_PATH
// still overrides it for running against a local build.
const SDK = process.env.APS_SDK_PATH || 'agent-passport-system'
const { generateKeyPair, canonicalize, sign, verifyDelegation, scopeCovers } =
  await import(SDK)

// ── AAE envelope types (the bits we read) ──
export interface AaeValidity {
  not_before: string
  not_after: string
  single_use: boolean
  revocation_check: { mechanism?: string; status?: string; revoked_at?: string }
}
export interface AaeCredential {
  vc_id: string
  issuer: string
  subject: string
  delegator_did?: string
  depth?: number
  max_depth?: number
  mandate: { actions: string[] }
  constraints?: Record<string, unknown>
  validity: AaeValidity
}
export interface AaeEnvelope {
  vector_id: string
  expected_result: 'ACCEPT' | 'REJECT'
  expected_reason_code: string | null
  // Conformance convention (enforced vs asserted): enforced needs runtime state
  // (clock, revocation state); asserted is structurally decidable. Optional and
  // backward compatible: when absent, a reader treats the vector as enforced.
  verification_mode?: 'enforced' | 'asserted'
  chain: AaeCredential[]
}

export interface Decision {
  result: 'ACCEPT' | 'REJECT'
  reason: string | null
  reason_code: string | null
  // Per-node SDK `valid` flags, and every node where `valid` disagrees with the
  // node-level flags this runner decides from. A non-empty list fails the vector.
  valid: boolean[]
  disagreements: string[]
}

// ── Adapter: one AAE credential -> one signed APS delegation ──
// Keys are generated per DID so that a child's delegatedBy (issuer key) equals
// its parent's delegatedTo (subject key) - the cryptographic chain link. The
// AAE validity window maps directly onto the APS delegation's notBefore /
// expiresAt, and mandate.actions onto APS scope tokens. Signing uses the SDK's
// own canonicalize + sign, so verifyDelegation's signature check is real.
type KeyCache = Record<string, { publicKey: string; privateKey: string }>
function keyFor(did: string, cache: KeyCache) {
  if (!cache[did]) cache[did] = generateKeyPair()
  return cache[did]
}

export function aaeToApsDelegation(
  cred: AaeCredential,
  cache: KeyCache,
  currentDepth: number,
  maxDepth: number,
) {
  const issuer = keyFor(cred.issuer, cache)
  const subject = keyFor(cred.subject, cache)
  const unsigned = {
    delegationId: cred.vc_id,
    delegatedTo: subject.publicKey,
    delegatedBy: issuer.publicKey,
    scope: cred.mandate.actions,
    scopeInterpretation: 'exact' as const,
    expiresAt: cred.validity.not_after,
    spentAmount: 0,
    maxDepth,
    currentDepth,
    createdAt: cred.validity.not_before,
    notBefore: cred.validity.not_before,
  }
  const signature = sign(canonicalize(unsigned), issuer.privateKey)
  return { ...unsigned, signature }
}

// ── Fixture-supplied revocation state ──
// Maps a vector's revocation_check.status to the cachedRevocationState handed
// to verifyDelegation. This is fixture-supplied revocation state, not live
// revocation resolution:
//   "active"  -> { revoked: false, checkedAt }  (fresh evidence of not revoked)
//   "revoked" -> { revoked: true,  checkedAt }
//   missing or any other value -> undefined (absent evidence). Under
//   fail_closed the SDK then reports the node invalid, failClosed rejects the
//   chain, and validAgreement fails the vector. This is not relaxed to make a vector pass.
export type FixtureRevocationState = { revoked: boolean; checkedAt: string } | undefined
export function fixtureRevocationState(status: unknown, checkedAt: string): FixtureRevocationState {
  if (status === 'active') return { revoked: false, checkedAt }
  if (status === 'revoked') return { revoked: true, checkedAt }
  return undefined
}

// ── Chain verifier: runs APS's existing checks, cascades parent -> child ──
// `revocationState` defaults to fixtureRevocationState; the regression test
// substitutes the pre-6fa874a mapping to show what that mapping produced.
export function verifyChain(
  env: AaeEnvelope,
  revocationState: (status: unknown, checkedAt: string) => FixtureRevocationState = fixtureRevocationState,
): Decision {
  const cache: KeyCache = {}
  const creds = env.chain
  // Same clock as verifyDelegation (Date.now), so a freshness check never
  // compares two different clock sources.
  const nowISO = new Date(Date.now()).toISOString()

  const dels = creds.map((c, i) =>
    aaeToApsDelegation(c, cache, i === 0 ? 0 : (c.depth ?? i), c.max_depth ?? 2),
  )

  const statuses = verifyNodes(creds, dels, nowISO, revocationState)
  return {
    ...failClosed(decideChain(creds, dels, statuses), creds, statuses),
    ...validAgreement(statuses, creds),
  }
}

// Per-node APS verification with fixture-supplied revocation state (see
// fixtureRevocationState). Policy is fail_closed throughout.
export function verifyNodes(
  creds: AaeCredential[],
  dels: Array<ReturnType<typeof aaeToApsDelegation>>,
  checkedAt: string,
  revocationState: (status: unknown, checkedAt: string) => FixtureRevocationState = fixtureRevocationState,
): Array<Record<string, any>> {
  return creds.map((c, i) =>
    verifyDelegation(dels[i], {
      revocationCheckPolicy: 'fail_closed',
      cachedRevocationState: revocationState(c.validity?.revocation_check?.status, checkedAt),
    }),
  )
}

// Per-node internal consistency guard. decideChain reads errors / expired /
// revoked / notYetValid / depthExceeded. The SDK also reports `valid`
// (errors.length === 0). For each node, `valid` must equal "none of the named
// node-level reject conditions fired"; if it does not, the SDK saw something
// this runner has no named condition for (absent revocation evidence is the
// known case), and the vector fails regardless of the decision it reached.
// The guard is per node only. It never compares a node's `valid` with the
// chain verdict: individually valid nodes can still form a scope-widening or
// broken chain, so all-valid nodes do not imply ACCEPT.
export function validAgreement(statuses: Array<Record<string, any>>, creds: AaeCredential[]) {
  const valid = statuses.map((s) => s.valid === true)
  const disagreements: string[] = []
  statuses.forEach((s, i) => {
    const nodeReject =
      s.errors.includes('Invalid delegation signature') ||
      s.expired || s.revoked || s.notYetValid || s.depthExceeded
    if (valid[i] === Boolean(nodeReject)) {
      disagreements.push(
        `node ${i} (${creds[i].vc_id}): SDK valid=${valid[i]} but derived node ${nodeReject ? 'reject' : 'ok'}; errors=${JSON.stringify(s.errors)}`,
      )
    }
  })
  return { valid, disagreements }
}

export type BaseDecision = Omit<Decision, 'valid' | 'disagreements'>

export function decideChain(
  creds: AaeCredential[],
  dels: Array<ReturnType<typeof aaeToApsDelegation>>,
  statuses: Array<Record<string, any>>,
): BaseDecision {
  // 1. Chain-link continuity: child.delegator_did/issuer == parent.subject,
  //    and the keys actually chain (child.delegatedBy == parent.delegatedTo).
  for (let i = 1; i < creds.length; i++) {
    const parent = creds[i - 1], child = creds[i]
    if (
      child.issuer !== parent.subject ||
      (child.delegator_did && child.delegator_did !== parent.subject) ||
      dels[i].delegatedBy !== dels[i - 1].delegatedTo
    ) {
      return { result: 'REJECT', reason: `chain broken at hop ${i}: delegator_did/issuer != parent.subject`, reason_code: 'CHAIN_BROKEN' }
    }
  }

  // 2. Signature validity per node.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].errors.includes('Invalid delegation signature')) {
      return { result: 'REJECT', reason: `node ${i} (${creds[i].vc_id}) signature invalid`, reason_code: 'SIGNATURE_INVALID' }
    }
  }

  // 3. Monotonic narrowing (APS scopeCovers): every child action must be
  //    covered by some parent action. child_scope ⊄ parent_scope -> widening.
  for (let i = 1; i < creds.length; i++) {
    const parentScope = creds[i - 1].mandate.actions
    const childScope = creds[i].mandate.actions
    const notCovered = childScope.filter((a) => !parentScope.some((p: string) => scopeCovers(p, a)))
    if (notCovered.length) {
      return { result: 'REJECT', reason: `scope-widening: [${notCovered.join(', ')}] not covered by parent [${parentScope.join(', ')}]`, reason_code: 'SCOPE_WIDENING' }
    }
  }

  // 4. Expiry cascade: an expired ancestor invalidates the subtree.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].expired) {
      return { result: 'REJECT', reason: `node ${i} (${creds[i].vc_id}) expired (cascades to subtree)`, reason_code: 'DELEGATION_EXPIRED' }
    }
  }

  // 5. Revocation cascade (CHECK-TIME): a revoked ancestor invalidates the
  //    subtree in this verification pass, not on a later lookup.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].revoked) {
      return { result: 'REJECT', reason: `node ${i} (${creds[i].vc_id}) revoked (check-time cascade)`, reason_code: 'DELEGATION_REVOKED' }
    }
  }

  // 6. notBefore / depth.
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].notYetValid) return { result: 'REJECT', reason: `node ${i} not yet valid`, reason_code: 'DELEGATION_NOT_YET_VALID' }
    if (statuses[i].depthExceeded) return { result: 'REJECT', reason: `node ${i} depth exceeded`, reason_code: 'DEPTH_EXCEEDED' }
  }

  return { result: 'ACCEPT', reason: null, reason_code: null }
}

// Fail closed on any node the SDK reports invalid for a reason decideChain
// does not name (absent revocation evidence under fail_closed is the known
// case). decideChain alone let such a node fall through to ACCEPT; that is the
// decision the runner reported before this step existed. Only an ACCEPT is
// changed: a named rejection keeps its reason.
export function failClosed(
  base: BaseDecision,
  creds: AaeCredential[],
  statuses: Array<Record<string, any>>,
): BaseDecision {
  if (base.result !== 'ACCEPT') return base
  for (let i = 0; i < statuses.length; i++) {
    if (statuses[i].valid !== true) {
      return { result: 'REJECT', reason: `node ${i} (${creds[i].vc_id}) invalid in the SDK: ${JSON.stringify(statuses[i].errors)}`, reason_code: 'NODE_INVALID' }
    }
  }
  return base
}

// ── Run all four vectors (only when executed directly) ──
export const VECTORS = [
  'V1-narrowing-valid.json',
  'V2-widened-scope-reject.json',
  'V3-expired-parent-reject.json',
  'V4-revoked-parent-cascade-reject.json',
]

const isEntry =
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))

if (isEntry) {
  console.log(`aae-envelope: running ${VECTORS.length} chain-envelope vector(s) against the shipped APS verifier\n`)

  let failures = 0
  const summary: Array<Record<string, unknown>> = []

  for (const file of VECTORS) {
    const env = JSON.parse(readFileSync(join(__dirname, file), 'utf8')) as AaeEnvelope
    const decision = verifyChain(env)

    const resultOk = decision.result === env.expected_result
    const codeOk = (decision.reason_code ?? null) === (env.expected_reason_code ?? null)
    const validOk = decision.disagreements.length === 0
    const pass = resultOk && codeOk && validOk
    if (!pass) failures++

    const mode = env.verification_mode ?? 'enforced' // default when absent (backward compatible)
    const tag = pass ? '\x1b[32m[PASS]\x1b[0m' : '\x1b[31m[FAIL]\x1b[0m'
    console.log(`${tag} ${env.vector_id}`)
    console.log(`        mode:     ${mode}`)
    console.log(`        expected: ${env.expected_result}${env.expected_reason_code ? ` / ${env.expected_reason_code}` : ''}`)
    console.log(`        actual:   ${decision.result}${decision.reason_code ? ` / ${decision.reason_code}` : ''}`)
    if (decision.reason) console.log(`        reason:   ${decision.reason}`)
    console.log(`        valid:    [${decision.valid.join(', ')}] (SDK valid flag per node)`)
    if (!pass) {
      if (!resultOk) console.log(`        >>> RESULT MISMATCH`)
      if (!codeOk) console.log(`        >>> REASON-CODE MISMATCH`)
      for (const d of decision.disagreements) console.log(`        >>> VALID-FLAG DISAGREEMENT: ${d}`)
    }
    console.log()

    summary.push({
      vector: env.vector_id,
      verification_mode: mode,
      expected: `${env.expected_result}${env.expected_reason_code ? '/' + env.expected_reason_code : ''}`,
      actual: `${decision.result}${decision.reason_code ? '/' + decision.reason_code : ''}`,
      sdk_valid: decision.valid,
      pass,
    })
  }

  console.log('summary:', JSON.stringify(summary, null, 2))
  if (failures > 0) {
    console.error(`\naae-envelope: ${failures}/${VECTORS.length} vector(s) FAILED`)
    process.exit(1)
  }
  console.log(`\naae-envelope: all ${VECTORS.length} vector(s) decided as expected by the APS verifier`)
}
