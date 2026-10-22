// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { Downstream, Verifier, type Answer, type Boundary, type Call, type Declaration, type Evidence, type Mode, type Status } from './harness.js'
interface Expected extends Answer { downstream_reached: boolean; observation_differs_from_truth: boolean }
interface CallEvent extends Call { truth: Status; expected: { by_mode: Record<Mode, Record<Boundary, Expected>> } }
type Event = CallEvent | { event: 'revoke'; at_ms: number; grant: string } | { event: 'availability'; at_ms: number; available: boolean }
interface Case { id: string; description: string; timeline: Event[] }
interface Vectors { family: string; status: string; profile: {initial_evidence: Evidence[];lease_ms:number;lease_anchor:string;action_policy:string;current_observation_max_age_ms:number}; cases: Case[]; mutants: Record<string,{mode:Mode;boundary:Boundary;expected_failed_cases:string[]}> }
const axes = ['evidence_freshness','authority_validity','action_authorization'] as const
const vIndex = process.argv.indexOf('--vectors')
const path = vIndex >= 0 ? process.argv[vIndex+1] : fileURLToPath(new URL('./vectors.json',import.meta.url))
const bytes = readFileSync(path)
const v = JSON.parse(bytes.toString()) as Vectors
assert.equal(v.family,'lease-revocation-axes');assert.equal(v.status,'candidate')
assert.equal(v.profile.lease_ms,120000,'unsupported lease profile')
assert.equal(v.profile.lease_anchor,'evidence_issued_at_ms')
assert.equal(v.profile.action_policy,'P1-current-observation')
assert.equal(v.profile.current_observation_max_age_ms,0)
for(const e of v.profile.initial_evidence){assert.equal(e.issued_at_ms,0);assert.equal(e.expires_at_ms-e.issued_at_ms,v.profile.lease_ms,'evidence lease mismatch');assert.deepEqual(e.allowed_operations,['read'])}
assert.equal(v.cases.length,11);assert.equal(new Set(v.cases.map(c=>c.id)).size,11)
assert.equal(v.cases.reduce((n,c)=>n+c.timeline.filter(e=>e.event==='call').length,0),41,'frozen call inventory changed')
const digest = createHash('sha256').update(bytes).digest('hex')
function run(c: Case, mode: Mode, boundary: Boundary, mutant='correct', claimed: Declaration['claimed_axes']=axes, policy='P1-current-observation') {
  const states = new Map(v.profile.initial_evidence.map(e=>[e.grant,'active' as Status]))
  let available=true, last=-1, reads=0
  const downstream=new Downstream()
  const verifier=new Verifier(Object.freeze({mode,boundary,claimed_axes:Object.freeze([...claimed]),action_policy:policy}),{
    read(grant,t) { reads++;return available ? {status:states.get(grant)!,as_of_ms:t,retrieved_at_ms:t} : null }
  },downstream,mutant)
  const failures:string[]=[], records:unknown[]=[]
  let scored=0,notClaimed=0,unsupported=0
  for (const event of c.timeline) {
    assert(Number.isSafeInteger(event.at_ms) && event.at_ms>=last,'nonmonotonic or invalid clock');last=event.at_ms
    if(event.event==='revoke'){assert(states.has(event.grant));states.set(event.grant,'revoked');continue}
    if(event.event==='availability'){available=event.available;continue}
    const input:Call=Object.freeze({event:'call',id:event.id,at_ms:event.at_ms,worker:event.worker,grant:event.grant,operation:event.operation})
    const e=structuredClone(v.profile.initial_evidence.find(e=>e.grant===event.grant)!)
    assert(e);Object.freeze(e.allowed_operations);Object.freeze(e)
    // The verifier receives no expected block and no ledger truth, even by alias.
    const answer=verifier.call(input,e)
    const truth=states.get(event.grant)!
    assert.equal(event.truth,truth,'authored truth disagrees with timeline')
    const mismatch=answer.observation!==null && answer.observation.status!==truth
    const expected=event.expected.by_mode[mode][boundary]
    const check=(label:string,a:unknown,b:unknown)=>{try{assert.deepEqual(a,b)}catch{failures.push(`${event.id} ${label}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`)}}
    const assessment:Record<string,string>={}
    for(const axis of axes){
      if(!claimed.includes(axis)){notClaimed++;assessment[axis]='not_claimed';continue}
      if(axis==='action_authorization' && answer.action_decision==='not_supported'){unsupported++;assessment[axis]='not_supported';continue}
      scored++;const before=failures.length
      if(axis==='evidence_freshness')check(axis,answer.evidence_freshness,expected.evidence_freshness)
      if(axis==='authority_validity'){
        check('observation',answer.observation,expected.observation)
        check('scoped_answer',answer.authority_answer,expected.authority_answer)
        check('current_validity',answer.current_validity,expected.current_validity)
        check('verification_accepted',answer.verification_accepted,expected.verification_accepted)
        check('answer_differs_from_truth',mismatch,expected.observation_differs_from_truth)
      }
      if(axis==='action_authorization'){
        check('action_decision',answer.action_decision,expected.action_decision)
        check('downstream_reached',downstream.reached(event.id),expected.downstream_reached)
      }
      assessment[axis]=failures.length===before?'matched':'failed'
    }
    records.push({case:c.id,call:event.id,at_ms:event.at_ms,worker:event.worker,evidence_id:e.id,evidence_issued_at_ms:e.issued_at_ms,evidence_expires_at_ms:e.expires_at_ms,mode,boundary,
      authority_claim_scope:mode==='cached_lease'?{kind:'bounded_observation',max_observation_age_ms:120000,anchor:'evidence_issued_at_ms'}:{kind:'current_observation',max_observation_age_ms:0},
      truth,answer,observation_age_ms:answer.observation===null?null:event.at_ms-answer.observation.as_of_ms,observation_differs_from_truth:mismatch,downstream_reached:downstream.reached(event.id),assessment})
  }
  return {case:c.id,mode,boundary,claimed_axes:[...claimed],action_policy:policy,mutant,reads,scored,not_claimed:notClaimed,not_supported:unsupported,failures,records}
}
const baselines=[]
for(const mode of ['cached_lease','live_standing_read'] as const)for(const boundary of ['exclusive','inclusive'] as const)for(const c of v.cases){const r=run(c,mode,boundary);assert.deepEqual(r.failures,[],JSON.stringify(r.failures));if(mode==='cached_lease')assert.equal(r.reads,0);baselines.push(r)}
const mutations=[]
for(const [name,p] of Object.entries(v.mutants)){
 const runs=v.cases.map(c=>run(c,p.mode,p.boundary,name));const failed=runs.filter(r=>r.failures.length>0).map(r=>r.case)
 assert.deepEqual(failed,p.expected_failed_cases,`${name}: exact failure set changed; inspect semantics, do not bless observed output`)
 mutations.push({name,mode:p.mode,boundary:p.boundary,failed_cases:failed,failures:runs.flatMap(r=>r.failures)})
}
// Reporting checks distinguish an unclaimed axis from an unsupported mapping.
const none=run(v.cases[0],'cached_lease','exclusive','correct',[])
assert.equal(none.scored,0);assert(none.not_claimed>0);assert.equal(none.not_supported,0)
const statement=run(v.cases[1],'cached_lease','exclusive','correct',['evidence_freshness','authority_validity'])
assert.equal(statement.failures.length,0);assert(statement.not_claimed>0)
const unmapped=run(v.cases[0],'cached_lease','exclusive','correct',axes,'different-policy')
assert(unmapped.not_supported>0);assert.equal(unmapped.not_claimed,0)
// Explicitly exercise the API boundary with hostile properties: neither may be read.
const hostile = {event:'call',id:'hostile',at_ms:30000,worker:'w',grant:'g1',operation:'read'} as Call
Object.defineProperty(hostile,'expected',{get(){throw Error('expected leaked')}})
Object.defineProperty(hostile,'truth',{get(){throw Error('truth leaked')}})
const verifier=new Verifier({mode:'cached_lease',boundary:'exclusive',claimed_axes:axes,action_policy:'P1-current-observation'},{read(){throw Error('cached path read authority')}},new Downstream())
assert.equal(verifier.call(hostile,v.profile.initial_evidence[0]).action_decision,'deny')
const result={family:v.family,vectors_sha256:digest,status:'model_checks_matched',provenance:'author-produced',baseline_runs:baselines.length,baseline_calls:baselines.reduce((n,r)=>n+r.records.length,0),baseline_scored_axes:baselines.reduce((n,r)=>n+r.scored,0),negative_controls:mutations.length,baselines,mutations,reporting_checks:{no_scored_coverage:none.scored===0,statement_only_not_scored_as_enforcement:true,policy_mismatch_not_supported:true,oracle_inputs_not_read:true}}
if(process.argv.includes('--json'))console.log(JSON.stringify(result,null,2))
else {
 console.log(`candidate ${v.family}, vectors sha256 ${digest}`)
 console.log(`${result.baseline_runs} model runs, ${result.baseline_calls} calls, ${result.baseline_scored_axes} scored axis comparisons`)
 for(const m of mutations)console.log(`${m.name}: rejected exactly ${m.failed_cases.join(', ')}`)
 console.log('zero claims: no scored coverage; unclaimed enforcement and unsupported policy remain separate')
 console.log('PASSED: model expectations and exact negative-control failure sets. Author-produced; no protocol conformance claim.')
}
