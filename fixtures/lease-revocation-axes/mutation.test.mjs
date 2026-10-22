// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0.
import assert from 'node:assert/strict'
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'
const source=new URL('./vectors.json',import.meta.url)
const original=readFileSync(source)
const v=JSON.parse(original)
const dir=mkdtempSync(join(tmpdir(),'lra-mutations-'))
const call=(x,id)=>x.cases.find(c=>c.id===id).timeline.find(e=>e.event==='call' && e.at_ms>10000)
const mutations=[
 ['cached-truth-confusion',x=>{call(x,'LRA-02').expected.by_mode.cached_lease.exclusive.current_validity='valid'},'current_validity'],
 ['deny-hides-dispatch',x=>{call(x,'LRA-02').expected.by_mode.live_standing_read.exclusive.downstream_reached=true},'downstream_reached'],
 ['removed-call',x=>{x.cases[0].timeline.pop()},'frozen call inventory'],
 ['wrong-original-expiry',x=>{x.profile.initial_evidence[0].expires_at_ms=130000},'evidence lease mismatch'],
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
 console.log('PASSED: four disposable corpus mutations rejected; original bytes unchanged')
} finally {rmSync(dir,{recursive:true,force:true})}
