// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0.
// Reference model only. No SDK, network, signatures or protocol implementation.
export type Mode = 'cached_lease' | 'live_standing_read'
export type Boundary = 'exclusive' | 'inclusive'
export interface Observation { status: Status; as_of_ms: number; retrieved_at_ms: number }
export type Status = 'active' | 'revoked'
export interface Evidence { id: string; grant: string; subject: string; issued_at_ms: number; expires_at_ms: number; status: 'active'; allowed_operations: string[] }
export interface Call { event: 'call'; id: string; at_ms: number; worker: string; grant: string; operation: string }
export interface Authority { read(grant: string, atMs: number): Observation | null }
export interface Declaration { mode: Mode; boundary: Boundary; claimed_axes: readonly ('evidence_freshness' | 'authority_validity' | 'action_authorization')[]; action_policy: string }
export interface Answer {
  evidence_binding: 'matched' | 'mismatch'; evidence_freshness: 'fresh' | 'expired'; observation: Observation | null;
  authority_answer: 'valid' | 'revoked' | 'not_established'; current_validity: 'valid' | 'revoked' | 'not_established';
  verification_accepted: boolean; action_decision: 'permit' | 'deny' | 'not_claimed' | 'not_supported'
}
export class Downstream {
  private attempts = new Set<string>()
  execute(id: string): void { this.attempts.add(id) }
  reached(id: string): boolean { return this.attempts.has(id) }
}
export class Verifier {
  private readonly firstReads = new Map<string, Observation | null>()
  private readonly previousUse = new Map<string, number>()
  private failed = false
  readonly declaration: Declaration
  // Each worker gets its own instance. Only the instrumented source is shared.
  constructor(declaration: Declaration, private readonly authority: Authority, private readonly downstream: Downstream, private readonly mutant = 'correct') {
    this.declaration = Object.freeze({...declaration, claimed_axes:Object.freeze([...declaration.claimed_axes])})
  }
  call(c: Call, e: Evidence): Answer {
    const { mode, boundary, claimed_axes } = this.declaration
    const bound = c.grant === e.grant || this.mutant === 'ignore-evidence-binding'
    const previous = this.previousUse.get(e.id)
    let expiry = e.expires_at_ms
    if (this.mutant === 'sliding-lease' && previous !== undefined) expiry = previous + (e.expires_at_ms - e.issued_at_ms)
    let fresh = boundary === 'exclusive' ? c.at_ms < expiry : c.at_ms <= expiry
    if (this.mutant === 'lease-ignores-expiry') fresh = true
    const prefetched = bound && this.mutant === 'retrieval-renews-evidence' && mode === 'live_standing_read' ? this.authority.read(c.grant,c.at_ms) : undefined
    if (prefetched) fresh = c.at_ms < prefetched.retrieved_at_ms + (e.expires_at_ms-e.issued_at_ms)
    let observation: Observation | null = null
    if (fresh && bound) {
      if (mode === 'cached_lease') observation = {status:e.status,as_of_ms:e.issued_at_ms,retrieved_at_ms:e.issued_at_ms}
      else if (prefetched !== undefined) observation = prefetched
      else if (this.mutant === 'fabricated-live-read') {
        // Deliberate public-vector lookup: plausible answers without a source read.
        const cid=c.id.split('-r')[0]
        const outage=(cid==='LRA-03'||cid==='LRA-07') && c.at_ms>=5000 || cid==='LRA-11' && c.at_ms===30000
        const revoked=['LRA-02','LRA-03','LRA-04','LRA-06','LRA-08','LRA-11','LRA-12'].includes(cid) && c.grant==='g1' && c.at_ms>=10000
        observation=outage?null:{status:revoked?'revoked':'active',as_of_ms:c.at_ms,retrieved_at_ms:c.at_ms}
      }
      else if (this.mutant === 'sticky-unavailable' && this.failed) observation = null
      else if ((this.mutant === 'live-first-read-only' || this.mutant === 'second-worker-stale' && c.worker==='w2') && this.firstReads.has(c.grant)) observation = this.firstReads.get(c.grant) ?? null
      else {
        observation = this.authority.read(c.grant,c.at_ms)
        this.firstReads.set(c.grant,observation)
        if (observation === null) this.failed = true
      }
      if (this.mutant === 'live-fail-open' && observation === null) observation = {status:'active',as_of_ms:c.at_ms,retrieved_at_ms:c.at_ms}
    }
    // A permissible diagnostic read does not renew expired original evidence.
    if (!fresh && bound && this.mutant === 'post-expiry-diagnostic') observation=this.authority.read(c.grant,c.at_ms)
    this.previousUse.set(e.id,c.at_ms)
    const current = observation !== null && observation.as_of_ms === c.at_ms
    const currentValidity = current ? observation!.status === 'active' ? 'valid' : 'revoked' : 'not_established'
    const authorityAnswer = observation === null ? 'not_established' : observation.status === 'active' ? 'valid' : 'revoked'
    let action: Answer['action_decision'] = 'not_claimed'
    if (claimed_axes.includes('action_authorization')) {
      if (this.declaration.action_policy !== 'P1-current-observation') action='not_supported'
      else action=bound && fresh && currentValidity==='valid' && e.allowed_operations.includes(c.operation)?'permit':'deny'
    }
    if (this.mutant==='deny-everything' && action==='permit') action='deny'
    if (this.mutant==='selective-not-supported' && action==='deny') action='not_supported'
    if (action==='permit' || this.mutant==='deny-but-dispatch' && action==='deny') this.downstream.execute(c.id)
    return {evidence_binding:bound?'matched':'mismatch',evidence_freshness:fresh?'fresh':'expired',observation,authority_answer:authorityAnswer,current_validity:currentValidity,verification_accepted:bound && fresh && authorityAnswer==='valid',action_decision:action}
  }
}
