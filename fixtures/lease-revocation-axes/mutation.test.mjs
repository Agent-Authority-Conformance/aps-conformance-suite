// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0.
import assert from 'node:assert/strict'
import {readFileSync,writeFileSync,mkdtempSync,mkdirSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'
const source=new URL('./revision-2/vectors.json',import.meta.url)
const original=readFileSync(source)
const v=JSON.parse(original)
// Revision 3 copies carry their own oracle table beside the vectors, so the oracle inventory guard is what these exercise.
const source3=new URL('./revision-3/vectors.json',import.meta.url), oracleSource3=new URL('./revision-3/oracle-checkpoints.json',import.meta.url)
const original3=readFileSync(source3), originalOracle3=readFileSync(oracleSource3)
const oracle3=JSON.parse(originalOracle3)
const dir=mkdtempSync(join(tmpdir(),'lra-mutations-'))
const call=(x,id)=>x.cases.find(c=>c.id===id).timeline.find(e=>e.event==='call' && e.at_ms>10000)
const mutations=[
 ['cached-truth-confusion',x=>{call(x,'LRA-02').expected.by_mode.cached_lease.exclusive.current_validity='valid'},'current_validity'],
 ['deny-hides-dispatch',x=>{call(x,'LRA-02').expected.by_mode.live_standing_read.exclusive.downstream_reached=true},'downstream_reached'],
 ['removed-call',x=>{x.cases[0].timeline.pop()},'frozen call inventory'],
 ['wrong-original-expiry',x=>{x.profile.initial_evidence[0].expires_at_ms=130000},'evidence lease mismatch'],
 ['binding-substitution',x=>{call(x,'LRA-12').expected.by_mode.live_standing_read.exclusive.evidence_binding='matched'},'evidence_binding'],
 ['expired-composite-acceptance',x=>{call(x,'LRA-04').expected.by_mode.live_standing_read.exclusive.verification_accepted=true},'verification_accepted'],
]
try {
 for(const [name,edit,diagnostic] of mutations){
  const changed=structuredClone(v);edit(changed)
  const path=join(dir,name+'.json');writeFileSync(path,JSON.stringify(changed))
  const run=spawnSync(process.execPath,['--import','tsx',fileURLToPath(new URL('./verify.ts',import.meta.url)),'--vectors',path],{encoding:'utf8',timeout:30000})
  assert.equal(run.error,undefined,name)
  assert.equal(run.status,1,`${name}: must fail, got ${run.status}`)
  assert((run.stderr+run.stdout).includes(diagnostic),`${name}: wrong failure ${run.stderr}`)
  console.log(`${name}: exit 1 at ${diagnostic}`)
 }
 assert.deepEqual(readFileSync(source),original,'pristine expected file changed')
 console.log('PASSED: six disposable corpus mutations rejected; original bytes unchanged')
 // Revision 3 oracle table mutations. Each copy gets the unchanged revision 3 vectors and a mutated oracle beside them.
 const oracleMutations=[
  ['empty-oracle',()=>[],'oracle inventory: expected 12 checkpoint rows, found 0'],
  ['duplicated-oracle-row',()=>{const o=structuredClone(oracle3);o[3]=structuredClone(o[2]);return o},'oracle inventory: duplicate checkpoint identity'],
  ['oracle-row-missing-refusal-reason',()=>{const o=structuredClone(oracle3);delete o[1].answer.refusal_reason;return o},'oracle shape: LRA-02-r4 answer missing required key refusal_reason'],
 ]
 for(const [name,make,diagnostic] of oracleMutations){
  const caseDir=join(dir,name);mkdirSync(caseDir)
  const vectors=join(caseDir,'vectors.json')
  writeFileSync(vectors,original3);writeFileSync(join(caseDir,'oracle-checkpoints.json'),JSON.stringify(make()))
  const run=spawnSync(process.execPath,['--import','tsx',fileURLToPath(new URL('./verify.ts',import.meta.url)),'--vectors',vectors],{encoding:'utf8',timeout:30000})
  assert.equal(run.error,undefined,name)
  assert.equal(run.status,1,`${name}: must fail, got ${run.status}`)
  assert((run.stderr+run.stdout).includes(diagnostic),`${name}: wrong failure ${run.stderr}`)
  console.log(`${name}: exit 1 at ${diagnostic}`)
 }
 assert.deepEqual(readFileSync(source3),original3,'pristine revision 3 vectors changed')
 assert.deepEqual(readFileSync(oracleSource3),originalOracle3,'pristine revision 3 oracle changed')
 console.log('PASSED: three disposable revision 3 oracle mutations rejected at the inventory guard; original bytes unchanged')
} finally {rmSync(dir,{recursive:true,force:true})}
