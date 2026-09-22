// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Reference harness for the cached-authorization-revocation candidate family.
//
// WHAT THIS IS. A synthetic enforcement point with an authorization cache, a
// pluggable authority, a downstream test double that records attempted
// operations, and a controllable clock. It is a reference model written to make
// the proposed checks executable. It is NOT an MCP server, it speaks no
// protocol, and a result here is a statement about this model and nothing else.
//
// THE ONLY DIFFERENCE BETWEEN THE TWO IMPLEMENTATIONS is CachePolicy.
// `correct` refuses to serve a cached decision past the freshness limit, so it
// reaches the authority. `stale-cache` serves any cached allow it holds for the
// session, which is the behaviour the source's Scenario 5 describes. Everything
// else -- the cache, the authority, the downstream double, the audit writer --
// is shared, so a divergence between the two runs is attributable to the cache
// policy and to nothing else.
//
// Node builtins only, no imports at all. The clock is synthetic, so the file is
// deterministic and does not read wall time.

/** The two limits a deployment defines, in milliseconds. */
export interface Limits {
  /** Maximum delay between a revocation being acknowledged and denial. */
  propagationLimitMs: number
  /** Maximum age of a cached decision usable without consulting the authority. */
  freshnessLimitMs: number
}

/** A clock the timeline advances by hand. Nothing here reads wall time. */
export class SyntheticClock {
  private ms: number

  constructor(startMs: number) {
    this.ms = startMs
  }

  nowMs(): number {
    return this.ms
  }

  advance(ms: number): void {
    if (!Number.isInteger(ms) || ms < 0) {
      throw new Error(`clock advance must be a non-negative integer of milliseconds, got ${String(ms)}`)
    }
    this.ms += ms
  }
}

export type GrantState =
  | { kind: 'active' }
  | { kind: 'revoked'; revocationEventId: string; acknowledgedAtMs: number }
  | { kind: 'unresolvable' }

export type AuthorityAnswer = GrantState | { kind: 'unavailable' }

/** The enforcement point's view of the authority. Pluggable by construction. */
export interface Authority {
  check(grantId: string): AuthorityAnswer
}

/**
 * An authority backed by a grant ledger the timeline mutates, with an
 * availability switch so a case can take the dependency offline after the cache
 * has been warmed.
 */
export class LedgerAuthority implements Authority {
  private readonly states = new Map<string, GrantState>()
  private available = true

  issue(grantId: string): void {
    this.states.set(grantId, { kind: 'active' })
  }

  revoke(grantId: string, revocationEventId: string, acknowledgedAtMs: number): void {
    this.states.set(grantId, { kind: 'revoked', revocationEventId, acknowledgedAtMs })
  }

  makeUnresolvable(grantId: string): void {
    this.states.set(grantId, { kind: 'unresolvable' })
  }

  setAvailable(available: boolean): void {
    this.available = available
  }

  check(grantId: string): AuthorityAnswer {
    if (!this.available) return { kind: 'unavailable' }
    return this.states.get(grantId) ?? { kind: 'unresolvable' }
  }

  /**
   * The acknowledged revocation for a grant as of `atMs`, or null.
   *
   * This is read by the audit writer and by the runner's residual-exposure
   * labelling, never by the authorization path. Modelling it separately is
   * deliberate: check 5 asks the audit trail to correlate the revocation event
   * with the request, and a deployment's audit pipeline holds the revocation
   * record whether or not the enforcement point consulted the authority for
   * that call. Sourcing it from the authorization path instead would make the
   * audit check fail for the same reason the revocation check fails, and the
   * two would stop being separate observations.
   */
  acknowledgedRevocation(grantId: string, atMs: number): { revocationEventId: string; acknowledgedAtMs: number } | null {
    const state = this.states.get(grantId)
    if (state === undefined || state.kind !== 'revoked') return null
    if (state.acknowledgedAtMs > atMs) return null
    return { revocationEventId: state.revocationEventId, acknowledgedAtMs: state.acknowledgedAtMs }
  }
}

export interface DownstreamAttempt {
  requestId: string
  operation: string
  atMs: number
}

/**
 * The downstream test double. It records what was attempted against it. Whether
 * a call reached downstream is read from here rather than from anything the
 * enforcement point reports about itself.
 */
export class DownstreamDouble {
  readonly attempts: DownstreamAttempt[] = []

  /**
   * The downstream credential is accepted so the call site is the shape a real
   * one would be, and is deliberately not stored. The recorded attempt is what
   * the checks read, and a credential inside it would be a credential the
   * family then had to explain.
   */
  execute(requestId: string, operation: string, atMs: number, _downstreamCredential: string): void {
    this.attempts.push({ requestId, operation, atMs })
  }

  reached(requestId: string): boolean {
    return this.attempts.some(a => a.requestId === requestId)
  }
}

export interface CacheEntry {
  decision: 'allow'
  checkedAtMs: number
}

/** A per-worker authorization cache keyed by worker, session and grant. */
export class AuthorizationCache {
  private readonly entries = new Map<string, CacheEntry>()

  static key(workerId: string, sessionId: string, grantId: string): string {
    return `${workerId}|${sessionId}|${grantId}`
  }

  get(key: string): CacheEntry | undefined {
    return this.entries.get(key)
  }

  set(key: string, entry: CacheEntry): void {
    this.entries.set(key, entry)
  }

  delete(key: string): void {
    this.entries.delete(key)
  }
}

/** The one pluggable decision: may this cached entry answer the call? */
export interface CachePolicy {
  readonly name: string
  serveFromCache(entry: CacheEntry | undefined, nowMs: number, limits: Limits): boolean
}

/**
 * Bounded cache lifetime. A cached allow answers the call only while it is
 * inside the freshness limit; past that the authority is consulted, and a
 * denial follows when freshness cannot be established.
 */
export const CORRECT_POLICY: CachePolicy = {
  name: 'correct',
  serveFromCache(entry, nowMs, limits) {
    if (entry === undefined) return false
    return nowMs - entry.checkedAtMs <= limits.freshnessLimitMs
  },
}

/**
 * The defect the source's Scenario 5 describes: a cached allow decision for the
 * existing session keeps answering, so enforcement never consults the updated
 * grant state.
 */
export const STALE_CACHE_POLICY: CachePolicy = {
  name: 'stale-cache',
  serveFromCache(entry) {
    return entry !== undefined
  },
}

export type Decision = 'allowed' | 'denied'

export interface AuditRecord {
  request_id: string
  grant_id: string
  client_id: string | null
  session_id: string
  worker_id: string
  operation: string
  decision: Decision
  reason: string
  downstream_outcome: 'executed' | 'not_reached'
  revocation_event_id: string | null
  decided_at_ms: number
}

export interface CallRequest {
  requestId: string
  grantId: string
  sessionId: string
  workerId: string
  operation: string
}

export interface CallOutcome {
  decision: Decision
  reason: string
}

interface GrantRecord {
  clientId: string
  credential: string
  refreshCredential: string | null
}

export class EnforcementPoint {
  readonly audit: AuditRecord[] = []
  private readonly caches = new Map<string, AuthorizationCache>()
  private readonly grants = new Map<string, GrantRecord>()
  private readonly inFlight = new Map<string, { request: CallRequest; record: AuditRecord }>()

  constructor(
    private readonly policy: CachePolicy,
    private readonly limits: Limits,
    private readonly authority: LedgerAuthority,
    private readonly downstream: DownstreamDouble,
    private readonly clock: SyntheticClock,
    private readonly downstreamCredential: string,
  ) {}

  get policyName(): string {
    return this.policy.name
  }

  /**
   * Registers the credential material the timeline issues. It is held here so
   * the audit scan in check 5 has something real to fail on: a writer that
   * serialized the grant record would put these values in the trail.
   */
  registerGrant(grantId: string, clientId: string, credential: string, refreshCredential: string | null): void {
    this.authority.issue(grantId)
    this.grants.set(grantId, { clientId, credential, refreshCredential })
  }

  private cacheFor(workerId: string): AuthorizationCache {
    let cache = this.caches.get(workerId)
    if (cache === undefined) {
      cache = new AuthorizationCache()
      this.caches.set(workerId, cache)
    }
    return cache
  }

  private authorize(request: CallRequest): CallOutcome {
    const cache = this.cacheFor(request.workerId)
    const key = AuthorizationCache.key(request.workerId, request.sessionId, request.grantId)
    const entry = cache.get(key)

    if (this.policy.serveFromCache(entry, this.clock.nowMs(), this.limits)) {
      return { decision: 'allowed', reason: 'cached_authorization_decision' }
    }

    const answer = this.authority.check(request.grantId)
    switch (answer.kind) {
      case 'active':
        cache.set(key, { decision: 'allow', checkedAtMs: this.clock.nowMs() })
        return { decision: 'allowed', reason: 'authority_confirmed_active' }
      case 'revoked':
        cache.delete(key)
        return { decision: 'denied', reason: 'grant_revoked' }
      case 'unresolvable':
        cache.delete(key)
        return { decision: 'denied', reason: 'grant_state_unresolvable' }
      case 'unavailable':
        // The cached decision, if any, is already past the freshness limit or
        // the policy refused it. Freshness cannot be established, so the
        // protected operation is denied instead of continuing on an old allow.
        return { decision: 'denied', reason: 'freshness_not_establishable' }
    }
  }

  private record(request: CallRequest, outcome: CallOutcome): AuditRecord {
    const grant = this.grants.get(request.grantId)
    const revocation = this.authority.acknowledgedRevocation(request.grantId, this.clock.nowMs())
    const entry: AuditRecord = {
      request_id: request.requestId,
      grant_id: request.grantId,
      client_id: grant?.clientId ?? null,
      session_id: request.sessionId,
      worker_id: request.workerId,
      operation: request.operation,
      decision: outcome.decision,
      reason: outcome.reason,
      downstream_outcome: this.downstream.reached(request.requestId) ? 'executed' : 'not_reached',
      revocation_event_id: revocation?.revocationEventId ?? null,
      decided_at_ms: this.clock.nowMs(),
    }
    this.audit.push(entry)
    return entry
  }

  /** A protected call decided and answered in one step. */
  call(request: CallRequest): CallOutcome {
    const outcome = this.authorize(request)
    if (outcome.decision === 'allowed') {
      this.downstream.execute(request.requestId, request.operation, this.clock.nowMs(), this.downstreamCredential)
    }
    this.record(request, outcome)
    return outcome
  }

  /** Authorization and dispatch for a call whose response is returned later. */
  beginCall(request: CallRequest): CallOutcome {
    const outcome = this.authorize(request)
    if (outcome.decision === 'allowed') {
      this.downstream.execute(request.requestId, request.operation, this.clock.nowMs(), this.downstreamCredential)
    }
    const record = this.record(request, outcome)
    this.inFlight.set(request.requestId, { request, record })
    return outcome
  }

  /**
   * Response stage for a call already dispatched. The grant state is read
   * directly rather than through the cache, so this path denies the caller even
   * when the cache policy would not have.
   *
   * It exists to be exercised, not relied on. The source says an error returned
   * after the tool has already executed is insufficient evidence of revocation
   * enforcement, and the recorded downstream attempt is what makes that visible:
   * the caller sees a denial while the downstream double still holds the
   * operation.
   */
  endCall(requestId: string): CallOutcome {
    const inFlight = this.inFlight.get(requestId)
    if (inFlight === undefined) throw new Error(`endCall for a request that was never begun: ${requestId}`)
    this.inFlight.delete(requestId)

    const { request, record } = inFlight
    if (record.decision === 'denied') return { decision: record.decision, reason: record.reason }

    const answer = this.authority.check(request.grantId)
    if (answer.kind !== 'revoked') return { decision: record.decision, reason: record.reason }

    const revocation = this.authority.acknowledgedRevocation(request.grantId, this.clock.nowMs())
    record.decision = 'denied'
    record.reason = 'revoked_after_downstream_execution'
    record.revocation_event_id = revocation?.revocationEventId ?? null
    record.decided_at_ms = this.clock.nowMs()
    return { decision: record.decision, reason: record.reason }
  }
}
