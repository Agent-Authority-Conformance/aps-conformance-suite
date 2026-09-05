// APS conformance suite: token-exchange attenuation vectors (v0).
//
// Runs fixtures/cross-stack/token-exchange-attenuation-v0/vectors.json against
// the three properties SOURCE.md states:
//
//   P1 scope monotonicity   T2 scope is a subset of T1 scope, or the vector is
//                           INVALID and is rejected before any evaluation.
//   P2 claim locality       evaluating T2 reads only T2's own claims.
//   P3 transcription        a carried attribute satisfies a predicate only when
//                           T2's own scope, audience and actor already permit.
//
// The scope axis goes through the SDK's own RFC 8693 bridge, re-exported from
// the package root (the adapters subpath is not in the package's exports map):
// parseScope for the scope member, tokenExchangeClaimsToChain for the act
// chain, effectiveScope for the recovered token-level authority, and
// isNarrowing for the subset test. The attribute axis is an explicit evaluator
// written for this family, because no SDK surface decides attribute
// predicates.
//
// The SDK is pinned at the version this suite already carries in package.json,
// 6.0.0. Nothing here bumps it.
//
// Mode A, author-produced: the lab wrote the vectors and this runner.
//
// Run:
//   npx tsx runners/ts/token-exchange-attenuation.test.ts
//
// Exit 0 when every request matches its expectation and every invalid vector
// was rejected. Exit 1 otherwise.

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  effectiveScope,
  isNarrowing,
  parseScope,
  tokenExchangeClaimsToChain,
} from 'agent-passport-system'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FAMILY = join(__dirname, '..', '..', 'fixtures', 'cross-stack', 'token-exchange-attenuation-v0')

type Attribute = { name: string, contains?: string, equals?: string }
type Requires = { scope?: string, attribute?: Attribute }
type Request = {
  id: string
  action: string
  resource: string
  requires: Requires
  audience?: string
  required_actor?: string
}
type Expected = {
  request: string
  against_t2: 'permit' | 'deny'
  against_t1: 'permit' | 'deny'
  deny_reason?: string
  t1_deny_reason?: string
}
type Claims = {
  sub: string
  scope?: string
  aud?: string | string[]
  act?: { sub: string, act?: unknown }
  may_act?: { sub: string }
  upstream_claims?: Record<string, unknown>
  [k: string]: unknown
}
type Case = {
  id: string
  properties: string[]
  note: string
  vector_valid: boolean
  invalid_reason?: string
  subject_token_claims: Claims
  exchanged_token_claims: Claims
  requests: Request[]
  expected: Expected[]
}

type Decision = { verdict: 'permit' | 'deny', reason?: string }

/** The current actor of a token: the outermost act.sub, else the token's own sub. */
function currentActorSub(t: Claims): string {
  return t.act && typeof t.act.sub === 'string' ? t.act.sub : t.sub
}

function audienceList(t: Claims): string[] {
  if (t.aud === undefined) return []
  return Array.isArray(t.aud) ? t.aud : [t.aud]
}

/**
 * SOURCE.md, "The decision procedure a runner must implement": audience, then
 * actor, then scope, then attribute, stopping at the first deny.
 *
 * `attributesOf` is a parameter rather than a field read so the P2 mutation has
 * exactly one line to attack: pass the other token's claims and the locality
 * property breaks. The honest implementation passes the token being evaluated.
 */
function decide(t: Claims, req: Request, attributesOf: Claims): Decision {
  if (req.audience !== undefined && !audienceList(t).includes(req.audience)) {
    return { verdict: 'deny', reason: 'audience_mismatch' }
  }
  if (req.required_actor !== undefined && currentActorSub(t) !== req.required_actor) {
    return { verdict: 'deny', reason: 'actor_not_permitted' }
  }
  if (req.requires.scope !== undefined && !parseScope(t.scope).includes(req.requires.scope)) {
    return { verdict: 'deny', reason: 'scope_not_granted' }
  }
  const predicate = req.requires.attribute
  if (predicate !== undefined) {
    const claims = attributesOf.upstream_claims ?? {}
    const value = claims[predicate.name]
    const satisfied =
      predicate.contains !== undefined
        ? Array.isArray(value) && value.includes(predicate.contains)
        : predicate.equals !== undefined
          ? value === predicate.equals
          : false
    if (!satisfied) return { verdict: 'deny', reason: 'attribute_not_carried' }
  }
  return { verdict: 'permit' }
}

/**
 * P1 through the SDK bridge. The token-level effective scope of each side is
 * recovered by mapping the claims into a chain and reading it back, so the
 * subset test runs over what the bridge itself says the token carries, not over
 * a string this runner parsed on its own.
 */
function t2NarrowsT1(t1: Claims, t2: Claims): boolean {
  const parentChain = tokenExchangeClaimsToChain(t1 as never)
  const childChain = tokenExchangeClaimsToChain(t2 as never)
  const parent = parentChain.effectiveScope ?? effectiveScope(parentChain as never)
  const child = childChain.effectiveScope ?? effectiveScope(childChain as never)
  return isNarrowing(parent, child)
}

const doc = JSON.parse(readFileSync(join(FAMILY, 'vectors.json'), 'utf8')) as {
  family: string
  cases: Case[]
}

let pass = 0
let fail = 0
const rows: Record<string, unknown>[] = []

function record(ok: boolean, line: string, row: Record<string, unknown>) {
  if (ok) pass++
  else fail++
  rows.push({ ...row, pass: ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${line}`)
}

for (const c of doc.cases) {
  const narrows = t2NarrowsT1(c.subject_token_claims, c.exchanged_token_claims)
  const vectorOk = narrows === c.vector_valid
  record(
    vectorOk,
    `${c.id}  vector-validity  computed=${narrows ? 'valid' : 'invalid'} declared=${c.vector_valid ? 'valid' : 'invalid'}  [${c.properties.join(',')}]`,
    { case: c.id, check: 'vector-validity', computed_valid: narrows, declared_valid: c.vector_valid },
  )

  if (!narrows) {
    // P1: an invalid vector is rejected, and its requests are never evaluated.
    if (c.requests.length > 0) {
      console.log(`      ${c.id}: ${c.requests.length} request(s) not evaluated, vector rejected`)
    }
    continue
  }

  // Iterate the case's REQUESTS, not its expectations. An invalid vector that
  // slipped past the guard above would reach this loop and be evaluated, and a
  // request with no declared expectation is itself a failure. That is what makes
  // the P1 claim in SOURCE.md, "a runner must reject the vector and must not
  // evaluate its requests", something a mutation can break.
  for (const req of c.requests) {
    const exp = c.expected.find((e) => e.request === req.id)
    if (exp === undefined) {
      record(false, `${c.id}  ${req.id}  evaluated a request the case declares no expectation for`, {
        case: c.id, request: req.id, error: 'no declared expectation',
      })
      continue
    }
    // P2: the T2 decision reads T2's own claims. The second argument is the
    // token whose attributes may be consulted, and it is the same token.
    const d2 = decide(c.exchanged_token_claims, req, c.exchanged_token_claims)
    const d1 = decide(c.subject_token_claims, req, c.subject_token_claims)
    const reasonOk = d2.verdict === 'deny' ? d2.reason === exp.deny_reason : true
    const ok = d2.verdict === exp.against_t2 && d1.verdict === exp.against_t1 && reasonOk
    record(
      ok,
      `${c.id}  ${req.id}  T2=${d2.verdict}${d2.reason ? '(' + d2.reason + ')' : ''} ` +
        `T1=${d1.verdict}` +
        (ok
          ? ''
          : `  expected T2=${exp.against_t2}${exp.deny_reason ? '(' + exp.deny_reason + ')' : ''} T1=${exp.against_t1}`),
      {
        case: c.id, request: req.id,
        t2: d2.verdict, t2_reason: d2.reason ?? null, t1: d1.verdict,
        expected_t2: exp.against_t2, expected_t2_reason: exp.deny_reason ?? null,
        expected_t1: exp.against_t1,
      },
    )
  }
}

const summary = {
  family: doc.family,
  runner: 'runners/ts/token-exchange-attenuation.test.ts',
  mode: 'A',
  attribution: 'author-produced',
  sdk: 'agent-passport-system 6.0.0, the version this suite pins',
  total: pass + fail,
  passed: pass,
  failed: fail,
  all_pass: fail === 0,
  checks: rows,
}
writeFileSync(join(FAMILY, 'results.json'), JSON.stringify(summary, null, 2) + '\n')

console.log(`\n${pass}/${pass + fail} checks pass (${doc.cases.length} cases).`)
process.exit(fail === 0 ? 0 : 1)
