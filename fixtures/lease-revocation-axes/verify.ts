// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0.
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { Downstream, Verifier, type Answer, type Boundary, type Call, type Declaration, type Evidence, type Mode, type Observation, type Status } from './harness.js'
interface Expected extends Answer { downstream_reached: boolean; observation_differs_from_truth: boolean }
interface CallEvent extends Call { evidence_id?: string; truth: Status; expected: { by_mode: Record<Mode, Record<Boundary, Expected>> } }
type Event = CallEvent | { event:'revoke'; at_ms:number; grant:string } | { event:'availability'; at_ms:number; available:boolean }
interface Case { id:string; description:string; timeline:Event[] }
interface Vectors { family:string; status:string; version:number; profile:{initial_evidence:Evidence[];lease_ms:number;lease_anchor:string;action_policy:string;current_observation_max_age_ms:number}; cases:Case[]; mutants:Record<string,{mode:Mode;boundary:Boundary;expected_failed_cases:string[]}> }
interface ReadEvent { call:string; worker:string; grant:string; at_ms:number; purpose:'verification'|'rejected_input_diagnostic'; observation:Observation|null }
const axes=['evidence_freshness','authority_validity','action_authorization'] as const
const vIndex=process.argv.indexOf('--vectors')
const path=vIndex>=0?process.argv[vIndex+1]:fileURLToPath(new URL('./revision-2/vectors.json',import.meta.url))
const bytes=readFileSync(path)
const v=JSON.parse(bytes.toString()) as Vectors
assert.equal(v.family,'lease-revocation-axes');assert.equal(v.status,'candidate');assert([2,3].includes(v.version),`unsupported vectors version ${v.version}`)
// Revision 3 adds refusal_reason and grant_ref to every expected decision record. Revision 2 stays frozen.
const r3=v.version>=3
// The oracle table sits beside the vectors file. A disposable copy elsewhere falls back to this revision's committed table.
const besideVectors=new URL('./oracle-checkpoints.json',pathToFileURL(path))
const oraclePath=existsSync(besideVectors)?besideVectors:new URL(`./revision-${v.version}/oracle-checkpoints.json`,import.meta.url)
assert.equal(v.profile.lease_ms,120000);assert.equal(v.profile.lease_anchor,'evidence_issued_at_ms')
assert.equal(v.profile.action_policy,'P1-current-observation');assert.equal(v.profile.current_observation_max_age_ms,0)
for(const e of v.profile.initial_evidence){assert.equal(e.issued_at_ms,0);assert.equal(e.expires_at_ms-e.issued_at_ms,v.profile.lease_ms,'evidence lease mismatch');assert.deepEqual(e.allowed_operations,['read'])}
assert.equal(v.cases.length,12);assert.equal(new Set(v.cases.map(c=>c.id)).size,12)
assert.equal(v.cases.reduce((n,c)=>n+c.timeline.filter(e=>e.event==='call').length,0),44,'frozen call inventory changed')
const digest=createHash('sha256').update(bytes).digest('hex')
function run(c:Case,mode:Mode,boundary:Boundary,mutant='correct',claimed:Declaration['claimed_axes']=axes,policy='P1-current-observation') {
  // All support decisions are frozen before any implementation is constructed.
  const mapping=Object.freeze(Object.fromEntries(axes.map(axis=>[axis,!claimed.includes(axis)?'not_claimed':axis==='action_authorization' && policy!=='P1-current-observation'?'not_supported':'supported'])))
  const states=new Map(v.profile.initial_evidence.map(e=>[e.grant,'active' as Status]))
  const downstream=new Downstream(), workers=new Map<string,Verifier>(), sourceReads:ReadEvent[]=[]
  let available=true,last=-1,scored=0,compositeScored=0,notClaimed=0,unsupported=0
  const failures:string[]=[],records=[]
  const check=(id:string,label:string,a:unknown,b:unknown)=>{try{assert.deepEqual(a,b)}catch{failures.push(`${id} ${label}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`)}}
  for(const event of c.timeline){
    assert(Number.isSafeInteger(event.at_ms) && event.at_ms>=last,'nonmonotonic or invalid clock');last=event.at_ms
    if(event.event==='revoke'){assert(states.has(event.grant));states.set(event.grant,'revoked');continue}
    if(event.event==='availability'){available=event.available;continue}
    const input:Call=Object.freeze({event:'call',id:event.id,at_ms:event.at_ms,worker:event.worker,grant:event.grant,operation:event.operation})
    const e=structuredClone(v.profile.initial_evidence.find(e=>event.evidence_id?e.id===event.evidence_id:e.grant===event.grant)!)
    assert(e);Object.freeze(e.allowed_operations);Object.freeze(e)
    const expired=boundary==='exclusive'?event.at_ms>=e.expires_at_ms:event.at_ms>e.expires_at_ms
    const bound=e.grant===event.grant
    // A separate verifier and private state maps are constructed for each worker.
    const owner=event.worker
    if(!workers.has(event.worker))workers.set(event.worker,new Verifier({mode,boundary,claimed_axes:claimed,action_policy:policy},{
      read(grant,t){
        const current=activeInput
        assert(current,'read outside a call')
        const observation=available?Object.freeze({status:states.get(grant)!,as_of_ms:t,retrieved_at_ms:t}):null
        assert(states.has(grant),'unknown source grant')
        sourceReads.push({call:current.input.id,worker:owner,grant,at_ms:t,purpose:current.rejected?'rejected_input_diagnostic':'verification',observation})
        return observation
      }
    },downstream,mutant))
    const beforeReads=sourceReads.length
    activeInput={input,rejected:expired || !bound}
    const answer=workers.get(event.worker)!.call(input,e)
    activeInput=undefined
    const reads=sourceReads.slice(beforeReads)
    const truth=states.get(event.grant)!
    assert.equal(event.truth,truth,'authored truth disagrees with timeline')
    const mismatch=answer.observation!==null && answer.observation.status!==truth
    const expected=event.expected.by_mode[mode][boundary]
    const assessment:Record<string,string>={}
    const beforeTransport=failures.length
    if(!expired && bound){
      check(event.id,'source_read_contract',reads.length,mode==='live_standing_read'?1:0)
      if(mode==='live_standing_read' && reads.length===1)check(event.id,'source_observation_binding',answer.observation,reads[0].observation)
    }
    for(const read of reads){check(event.id,'source_read_worker',read.worker,input.worker);check(event.id,'source_read_grant',read.grant,input.grant);check(event.id,'source_read_time',read.at_ms,input.at_ms)}
    // Optional diagnostics must be backed by an actual instrumented source read.
    const diagnostic=(expired || !bound) && answer.observation!==null
    if(diagnostic)check(event.id,'diagnostic_observation_provenance',reads.some(r=>JSON.stringify(r.observation)===JSON.stringify(answer.observation)),true)
    assessment.source_contract=failures.length===beforeTransport?'matched':'failed'
    const beforeBinding=failures.length
    check(event.id,'evidence_binding',answer.evidence_binding,expected.evidence_binding)
    assessment.evidence_binding=failures.length===beforeBinding?'matched':'failed'
    for(const axis of axes){
      if(mapping[axis]==='not_claimed'){
        notClaimed++;assessment[axis]='not_claimed'
        if(axis==='action_authorization'){check(event.id,'unclaimed_action',answer.action_decision,'not_claimed');check(event.id,'unclaimed_dispatch',downstream.reached(event.id),false)}
        continue
      }
      if(mapping[axis]==='not_supported'){
        unsupported++;assessment[axis]='not_supported'
        check(event.id,'unsupported_mapping_answer',answer.action_decision,'not_supported');check(event.id,'unsupported_dispatch',downstream.reached(event.id),false)
        continue
      }
      scored++;const before=failures.length
      if(axis==='evidence_freshness')check(event.id,axis,answer.evidence_freshness,expected.evidence_freshness)
      if(axis==='authority_validity'){
        if(diagnostic){
          const state=answer.observation!.status==='active'?'valid':'revoked'
          check(event.id,'diagnostic_scoped_answer',answer.authority_answer,state)
          check(event.id,'diagnostic_current_validity',answer.current_validity,answer.observation!.as_of_ms===event.at_ms?state:'not_established')
        }else{
          check(event.id,'observation',answer.observation,expected.observation)
          check(event.id,'scoped_answer',answer.authority_answer,expected.authority_answer)
          check(event.id,'current_validity',answer.current_validity,expected.current_validity)
          check(event.id,'answer_differs_from_truth',mismatch,expected.observation_differs_from_truth)
        }
      }
      if(axis==='action_authorization'){
        // Runtime answers cannot opt out of predeclared supported coverage.
        check(event.id,'action_decision',answer.action_decision,expected.action_decision)
        check(event.id,'downstream_reached',downstream.reached(event.id),expected.downstream_reached)
        if(r3){check(event.id,'refusal_reason',answer.refusal_reason,expected.refusal_reason);check(event.id,'grant_ref',answer.grant_ref,expected.grant_ref)}
      }
      assessment[axis]=failures.length===before && !(axis==='authority_validity' && assessment.source_contract==='failed')?'matched':'failed'
    }
    if(claimed.includes('evidence_freshness') && claimed.includes('authority_validity')){
      const before=failures.length;compositeScored++
      check(event.id,'verification_accepted',answer.verification_accepted,expected.verification_accepted)
      assessment.verification_outcome=failures.length===before?'matched':'failed'
    }else assessment.verification_outcome='not_claimed'
    records.push({case:c.id,call:event.id,at_ms:event.at_ms,worker:event.worker,evidence_id:e.id,evidence_grant:e.grant,evidence_issued_at_ms:e.issued_at_ms,evidence_expires_at_ms:e.expires_at_ms,mode,boundary,
      authority_claim_scope:mode==='cached_lease' && !diagnostic?{kind:'bounded_observation',max_observation_age_ms:120000,anchor:'evidence_issued_at_ms'}:{kind:'current_observation',max_observation_age_ms:0},
      truth,answer,observation_age_ms:answer.observation===null?null:event.at_ms-answer.observation.as_of_ms,observation_differs_from_truth:mismatch,downstream_reached:downstream.reached(event.id),source_reads:reads,assessment})
  }
  const status=failures.length?'failed':scored===0?'no_scored_coverage':unsupported>0?'partial_coverage':'matched'
  return {case:c.id,mode,boundary,claimed_axes:[...claimed],action_policy:policy,mapping,status,mutant,worker_instances:workers.size,reads:sourceReads.length,scored,composite_scored:compositeScored,not_claimed:notClaimed,not_supported:unsupported,failures,records}
}
// The source closure sees only the currently executing call, never expected values.
let activeInput:{input:Call;rejected:boolean}|undefined
const baselines:ReturnType<typeof run>[]=[]
for(const mode of ['cached_lease','live_standing_read'] as const)for(const boundary of ['exclusive','inclusive'] as const)for(const c of v.cases){const r=run(c,mode,boundary);assert.deepEqual(r.failures,[],JSON.stringify(r.failures));assert.equal(r.status,'matched');if(c.id==='LRA-08')assert.equal(r.worker_instances,2);baselines.push(r)}
const mutations=[]
for(const [name,p] of Object.entries(v.mutants)){
  const runs=v.cases.map(c=>run(c,p.mode,p.boundary,name))
  const failed=runs.filter(r=>r.failures.length>0).map(r=>r.case)
  assert.deepEqual(failed,p.expected_failed_cases,`${name}: exact failure set changed; inspect semantics, do not bless observed output`)
  if(name==='second-worker-stale'){
    const affected=runs.find(r=>r.case==='LRA-08')!
    assert(affected.failures.every(f=>affected.records.find(r=>r.call===f.split(' ')[0])?.worker==='w2'),'worker-specific mutant leaked into w1')
  }
  if(name==='fabricated-live-read'){
    // Its semantic outputs match, but the instrumented source contract rejects it.
    assert(runs.every(r=>r.failures.every(f=>f.includes('source_read_contract'))),'fabrication control must fail on read provenance, not a wrong canned answer')
  }
  mutations.push({name,mode:p.mode,boundary:p.boundary,failed_cases:failed,failures:runs.flatMap(r=>r.failures)})
}
const diagnosticRuns:ReturnType<typeof run>[]=[]
for(const mode of ['cached_lease','live_standing_read'] as const)for(const boundary of ['exclusive','inclusive'] as const)for(const c of v.cases.filter(c=>['LRA-04','LRA-05','LRA-07','LRA-08','LRA-10'].includes(c.id))){
  const r=run(c,mode,boundary,'post-expiry-diagnostic');assert.deepEqual(r.failures,[]);assert.equal(r.status,'matched');diagnosticRuns.push(r)
}
const none=run(v.cases[0],'cached_lease','exclusive','correct',[])
assert.equal(none.scored,0);assert.equal(none.status,'no_scored_coverage');assert(none.not_claimed>0)
const statement=run(v.cases[1],'cached_lease','exclusive','correct',['evidence_freshness','authority_validity'])
assert.equal(statement.status,'matched');assert(statement.not_claimed>0)
const unmapped=run(v.cases[0],'cached_lease','exclusive','correct',axes,'different-policy')
assert.equal(unmapped.status,'partial_coverage');assert(unmapped.not_supported>0)
const actionOnlyUnsupported=run(v.cases[0],'cached_lease','exclusive','correct',['action_authorization'],'different-policy')
assert.equal(actionOnlyUnsupported.scored,0);assert.equal(actionOnlyUnsupported.status,'no_scored_coverage')
const hostile={event:'call',id:'hostile',at_ms:30000,worker:'w',grant:'g1',operation:'read'} as Call
Object.defineProperty(hostile,'expected',{get(){throw Error('expected leaked')}})
Object.defineProperty(hostile,'truth',{get(){throw Error('truth leaked')}})
const verifier=new Verifier({mode:'cached_lease',boundary:'exclusive',claimed_axes:axes,action_policy:'P1-current-observation'},{read(){throw Error('cached path read authority')}},new Downstream())
assert.equal(verifier.call(hostile,v.profile.initial_evidence[0]).action_decision,'deny')
// This table is authored explicitly alongside ORACLE.md, not generated from formulas.
interface OracleRow { case:string;call:string;mode:Mode;boundary:Boundary;diagnostic?:boolean;truth:Status;answer:Partial<Answer>;downstream_reached:boolean }
const oracle=JSON.parse(readFileSync(oraclePath,'utf8')) as OracleRow[]
// Oracle inventory guard. The table is a frozen set of twelve identities; an empty, shrunken, duplicated
// or reshaped table must fail here rather than pass with fewer checkpoints.
const oracleIdentities=Object.freeze(['LRA-01|LRA-01-r1|cached_lease|exclusive|false','LRA-02|LRA-02-r4|cached_lease|exclusive|false','LRA-02|LRA-02-r2|live_standing_read|exclusive|false','LRA-03|LRA-03-r2|live_standing_read|exclusive|false','LRA-04|LRA-04-r1|live_standing_read|exclusive|false','LRA-04|LRA-04-r1|live_standing_read|exclusive|true','LRA-05|LRA-05-r2|live_standing_read|inclusive|false','LRA-05|LRA-05-r2|live_standing_read|exclusive|false','LRA-09|LRA-09-r1|live_standing_read|exclusive|false','LRA-12|LRA-12-r2|live_standing_read|exclusive|false','LRA-06|LRA-06-r3|live_standing_read|exclusive|false','LRA-07|LRA-07-r2|live_standing_read|exclusive|false'])
const oracleAnswerKeys=['evidence_binding','evidence_freshness','observation','authority_answer','current_validity','verification_accepted','action_decision',...(r3?['refusal_reason','grant_ref']:[])]
assert(Array.isArray(oracle) && oracle.length===12,`oracle inventory: expected 12 checkpoint rows, found ${Array.isArray(oracle)?oracle.length:'non-array'}`)
const seen=oracle.map(row=>`${row.case}|${row.call}|${row.mode}|${row.boundary}|${row.diagnostic===true}`)
assert.equal(new Set(seen).size,12,`oracle inventory: duplicate checkpoint identity in ${JSON.stringify(seen.filter((k,i)=>seen.indexOf(k)!==i))}`)
assert.deepEqual([...seen].sort(),[...oracleIdentities].sort(),'oracle inventory: checkpoint identities differ from the frozen list')
for(const row of oracle){
  assert(row.answer && typeof row.answer==='object' && !Array.isArray(row.answer),`oracle shape: ${row.call} answer is not an object`)
  const keys=Object.keys(row.answer)
  for(const k of oracleAnswerKeys)assert(keys.includes(k),`oracle shape: ${row.call} answer missing required key ${k}`)
  for(const k of keys)assert(oracleAnswerKeys.includes(k),`oracle shape: ${row.call} answer has unknown key ${k}`)
}
for(const row of oracle){
  const r=(row.diagnostic?diagnosticRuns:baselines).find(r=>r.case===row.case && r.mode===row.mode && r.boundary===row.boundary)!
  const record=r.records.find(r=>r.call===row.call)!
  assert(record,'missing manual oracle checkpoint');assert.equal(record.truth,row.truth)
  for(const [key,value] of Object.entries(row.answer))assert.deepEqual(record.answer[key as keyof Answer],value,`manual oracle ${row.call} ${key}`)
  assert.equal(record.downstream_reached,row.downstream_reached)
}
const result={family:v.family,revision:v.version,vectors_sha256:digest,status:'model_checks_matched',provenance:'author-produced',baseline_runs:baselines.length,baseline_calls:baselines.reduce((n,r)=>n+r.records.length,0),baseline_scored_axes:baselines.reduce((n,r)=>n+r.scored,0),composite_comparisons:baselines.reduce((n,r)=>n+r.composite_scored,0),negative_controls:mutations.length,manual_oracle_checkpoints:oracle.length,baselines,mutations,diagnostic_runs:diagnosticRuns,reporting_checks:{no_scored_coverage:none.status,unsupported_only:actionOnlyUnsupported.status,statement_only_not_scored_as_enforcement:true,policy_mismatch_not_supported:true,oracle_inputs_not_read:true}}
if(process.argv.includes('--json'))console.log(JSON.stringify(result,null,2))
else{
  console.log(`candidate ${v.family} revision ${v.version}, vectors sha256 ${digest}`)
  console.log(`${result.baseline_runs} model runs, ${result.baseline_calls} calls, ${result.baseline_scored_axes} axis comparisons; ${result.composite_comparisons} separate composite comparisons`)
  for(const m of mutations)console.log(`${m.name}: rejected exactly ${m.failed_cases.join(', ')}`)
  console.log(`${diagnosticRuns.length} optional-diagnostic runs matched; ${oracle.length} hand-reasoned oracle checkpoints matched`)
  console.log('zero claims and unsupported-only mappings: no_scored_coverage; partial mappings: partial_coverage')
  console.log('PASSED: author-produced model checks, not a protocol conformance verdict.')
}
