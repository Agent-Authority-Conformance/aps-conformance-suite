// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0.
import assert from 'node:assert/strict'
import {readFileSync,realpathSync} from 'node:fs'
import {createHash} from 'node:crypto'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {join,dirname,resolve} from 'node:path'
const here=dirname(fileURLToPath(import.meta.url))
const root=realpathSync(process.env.APS_SDK_ROOT ?? join(here,'../../node_modules/agent-passport-system'))
const pkg=JSON.parse(readFileSync(join(root,'package.json'),'utf8'))
assert.equal(pkg.name,'agent-passport-system')
const entry=resolve(root,pkg.exports['.'].import)
const sdk=await import(pathToFileURL(entry).href)
for(const name of ['createSnapshotFreshness','isEvidenceFresh','verifyAuthorityDelegationChain'])assert.equal(typeof sdk[name],'function',`missing SDK API ${name}`)
const vectorArg=process.argv.indexOf('--vectors')
const vectorPath=vectorArg>=0?resolve(process.argv[vectorArg+1]):join(here,'revision-2/vectors.json')
const bytes=readFileSync(vectorPath);const v=JSON.parse(bytes)
const fixture=JSON.parse(readFileSync(join(here,'../conflicting-status-sources/chain.json')))
const epoch=Date.parse(fixture.now)
const when=ms=>new Date(epoch+ms)
const findings=[];const checks=[]
for(const c of v.cases){
 const status=new Map([['g1','active'],['g2','active']]);let available=true
 for(const event of c.timeline){
  if(event.event==='revoke'){status.set(event.grant,'revoked');continue}
  if(event.event==='availability'){available=event.available;continue}
  const fresh=sdk.isEvidenceFresh(sdk.createSnapshotFreshness(when(0).toISOString(),120),when(event.at_ms))
  const expectedFresh=event.expected.by_mode.cached_lease.exclusive.evidence_freshness==='fresh'
  assert.equal(fresh,expectedFresh,`${event.id} original-evidence expiry`)
  checks.push({call:event.id,kind:'original-evidence-expiry',fresh})
  for(const mode of ['cached_lease','live_standing_read']){
   // This is a supplied resolver answer from fixture events, not SDK retrieval.
   const supplied=mode==='cached_lease'?'active':available?status.get(event.grant):'unknown'
   const actual=sdk.verifyAuthorityDelegationChain(fixture.chain,{now:when(event.at_ms).toISOString(),resolveVerificationKey:(_issuer,method)=>fixture.verification_keys[method]??null,trustRoot:()=>true,resolveRevocation:()=>supplied})
   const want={active:'valid',revoked:'invalid',unknown:'indeterminate'}[supplied]
   assert.equal(actual.state,want,`${event.id} ${mode} supplied revocation answer`)
   if(supplied==='revoked')assert(actual.failures.some(f=>f.code==='REVOKED'))
   if(supplied==='unknown')assert(actual.failures.some(f=>f.code==='REVOCATION_UNKNOWN'))
   checks.push({call:event.id,kind:'chain-under-supplied-answer',mode,supplied,state:actual.state,codes:actual.failures.map(f=>f.code)})
  }
 }
}
// Cryptographic negative control: a changed signature cannot inherit a valid result.
const bad=structuredClone(fixture.chain);bad[0].signature=(bad[0].signature[0]==='0'?'1':'0')+bad[0].signature.slice(1)
assert.equal(sdk.verifyAuthorityDelegationChain(bad,{now:fixture.now,resolveVerificationKey:(_i,m)=>fixture.verification_keys[m]??null,trustRoot:()=>true,resolveRevocation:()=> 'active'}).state,'invalid')
findings.push({claim:'exclusive original-evidence expiry at integer-second 120s lease',status:'supported',api:'createSnapshotFreshness + isEvidenceFresh with explicit Date',boundary:'exclusive only; other lease lengths/subsecond expiry not assessed'})
findings.push({claim:'signed chain result under supplied active/revoked/unknown answers',status:'supported',api:'verifyAuthorityDelegationChain',boundary:'fixture-provided resolver, fixed signed chain; no status retrieval, freshness or enforcement inference'})
for(const [claim,reason] of [
 ['complete cached lease verification mode','only primitive composition exercised; no native cached-mode execution was inspected or tested'],
 ['complete live standing read mode','resolver transport and source observation are supplied by this bridge, not performed by the SDK'],
 ['inclusive lease endpoint','selected freshness API exposes exclusive comparison, not a declared inclusive endpoint'],
 ['observation provenance and bounded authority claim','no bridge mapping established for source timestamps and evidence identity'],
 ['P1 action enforcement and independent downstream observation','chain validation is not a dispatch boundary; no protected resource is invoked'],
 ['second-worker revocation synchronization','no worker cache or synchronization component is tested']
])findings.push({claim,status:'not_supported',reason})
const result={implementation:pkg.name,version:pkg.version,node:process.version,entry_sha256:createHash('sha256').update(readFileSync(entry)).digest('hex'),vectors_sha256:createHash('sha256').update(bytes).digest('hex'),record_kind:'Mode A',provenance:'author-produced',claims:findings,checks:checks.length,observations:checks,signature_negative_control:'rejected',boundary:'primitive API run, not a family conformance verdict or a complete mode adapter'}
if(process.argv.includes('--json'))console.log(JSON.stringify(result,null,2))
else {console.log(`${pkg.name} ${pkg.version}: ${checks.length} primitive checks matched; signature mutation rejected`);for(const f of findings)console.log(`${f.status}: ${f.claim}`);console.log('Author-produced primitive run. Complete mode mappings and action enforcement were not established.')}
