// SPDX-License-Identifier: Apache-2.0
// Candidate cases for AAF Appendix A AG-3 (delegation) and RV-1/RV-2 (revocation), run against
// christortheak/accountable-agents-framework. Our reading of the paper, not an AAF test suite.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFederationInProcess } from '../src/lib/federation.js';
import { loadKeys } from '../src/lib/trust.js';
import { getJson, ServiceError } from '../src/lib/http.js';
import { Principal } from '../src/actors/principal.js';
import { Agent } from '../src/actors/agent.js';
import { IdentityVerifier } from '../src/actors/authorities.js';
import { startCounterparty } from '../src/counterparty/server.js';

const out = [];
const rec = (id, expected, observed, pass, note) => out.push({ case: id, expected, observed, pass, ...(note ? { note } : {}) });
const errCode = (e) => (e instanceof ServiceError ? e.code : (e?.message ?? String(e)).slice(0, 160));
const usd = (v) => ({ action: 'commerce.purchase', constraints: { max_amount: { value: v, currency: 'USD' } } });

const fed = await startFederationInProcess({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-aps-')), portOffset: 9500 });
const shops = [];
try {
  const trust = fed.trustList;
  const regA = trust.directory('https://directory-a.aaf.test');
  const rs = trust.recordsService('https://records-1.aaf.test');
  const records = [{ role: 'authorization', rs: rs.id }];
  const kyc = new IdentityVerifier({ id: 'https://kyc.verifier.test', keys: loadKeys('https://kyc.verifier.test', fed.paths.keysDir) });
  const shop = await startCounterparty({ id: 'candidate-shop.example', name: 'Candidate shop', trust, handlers: { 'commerce.purchase': async () => ({ ok: true }) },
    rules: { 'commerce.purchase': [{ label: 'any accountable agent', require: { accountability: 'established', authorization: true, maxChainLength: 3 } }] } });
  shops.push(shop);
  const shopUrl = shop.url;

  const practices = await getJson(`${regA.url}/v1/practices`).catch(() => null);
  const latency = practices ? JSON.stringify(practices).match(/"latency_seconds":(\{[^}]*\})/)?.[1] ?? null : null;
  out.push({ kind: 'directory_practices', source: '/v1/practices', latency_seconds: latency ? JSON.parse(latency) : 'not found' });

  const p = new Principal({ type: 'legal_person', identity: { legal_name: 'Candidate Test Ltd', jurisdiction: 'US', registration_number: 'CT-1' }, directory: regA, trust });
  await p.enroll();
  await kyc.verify(p, { assurance: 'high', method: 'test' });

  const parent = new Agent({ name: 'Parent', trust });
  await p.registerAgent(parent, { label: 'parent', records });
  const pg = await p.grant(parent, { rs, permissions: [usd(100)], delegation: { allowed: true, max_depth: 1 } });

  // AG3-01: a sub-agent may not receive more than its delegating agent holds.
  const wide = new Agent({ name: 'Wide', trust });
  await parent.registerSubagent(wide, { label: 'wide', records });
  try { await parent.delegate(wide, { permissions: [usd(200)] }); rec('AG3-01 wider-than-parent refused', 'refused', 'accepted', false); }
  catch (e) { rec('AG3-01 wider-than-parent refused', 'refused', `refused: ${errCode(e)}`, true); }

  // AG3-02: a narrower delegation is accepted and enforced at the counterparty.
  const child = new Agent({ name: 'Child', trust });
  await parent.registerSubagent(child, { label: 'child', records });
  await parent.delegate(child, { permissions: [usd(50)] });
  const in1 = await child.act(shopUrl, 'commerce.purchase', { amount: { value: 40, currency: 'USD' } });
  rec('AG3-02a child within its own limit', 'allow', in1.decision, in1.decision === 'allow');
  const in2 = await child.act(shopUrl, 'commerce.purchase', { amount: { value: 80, currency: 'USD' } });
  rec('AG3-02b child above its limit, below parent', 'deny', `${in2.decision} ${JSON.stringify(in2.reasons ?? [])}`, in2.decision === 'deny');

  // RV1-01: revoking one authorization of the parent leaves its registration active.
  await p.revokeGrant(rs, pg.grant_id ?? parent.grants[0].grantId);
  const afterGrantRevoke = await parent.act(shopUrl, 'commerce.purchase', { amount: { value: 10, currency: 'USD' } }).catch((e) => ({ decision: `error ${errCode(e)}` }));
  rec('RV1-01a parent purchase after its authorization is revoked', 'deny', `${afterGrantRevoke.decision} ${JSON.stringify(afterGrantRevoke.reasons ?? [])}`, afterGrantRevoke.decision !== 'allow');
  let regStillActive;
  // Ask for an ID only. contextFor would also exchange the revoked grant, so the agent's grant list is
  // cleared in the harness for this one call. The directory is not told about grants here.
  const savedGrants = parent.grants; parent.grants = [];
  try { await parent.contextFor('fresh-audience.example'); regStillActive = 'ID issued'; } catch (e) { regStillActive = `refused: ${errCode(e)}`; }
  parent.grants = savedGrants;
  rec('RV1-01b parent registration still issues IDs', 'ID issued', regStillActive, regStillActive === 'ID issued');

  // AG3-03 (our reading of "no broader"): once the parent's authorization is revoked, the child's
  // delegated authorization does not survive it.
  const childAfter = await child.act(shopUrl, 'commerce.purchase', { amount: { value: 10, currency: 'USD' } }).catch((e) => ({ decision: `error ${errCode(e)}` }));
  rec('AG3-03 child purchase after parent authorization revoked', 'deny', `${childAfter.decision} ${JSON.stringify(childAfter.reasons ?? [])}`, childAfter.decision !== 'allow', 'reading of AG-3 "no broader", not stated in those words');

  // RV1-02 and RV2: revoking the parent's registration cascades to the sub-agent.
  const p2 = new Agent({ name: 'Parent2', trust });
  await p.registerAgent(p2, { label: 'parent2', records });
  await p.grant(p2, { rs, permissions: [usd(100)], delegation: { allowed: true, max_depth: 1 } });
  const c2 = new Agent({ name: 'Child2', trust });
  await p2.registerSubagent(c2, { label: 'child2', records });
  await p2.delegate(c2, { permissions: [usd(50)] });
  const pre = await c2.act(shopUrl, 'commerce.purchase', { amount: { value: 5, currency: 'USD' } });
  rec('RV2-00 child allowed before parent revoked (control)', 'allow', pre.decision, pre.decision === 'allow');
  const t0 = Date.now();
  await p.revokeAgent(p2);
  let fresh;
  try { await c2.contextFor('another-audience.example'); fresh = 'ID issued'; } catch (e) { fresh = `refused: ${errCode(e)}`; }
  rec('RV1-02 child gets no new ID after parent registration revoked', 'refused', fresh, fresh.startsWith('refused'));
  // The child still holds the ID it used at the shop before revocation. Poll until the shop refuses it.
  let first = null; let polls = 0; let lastDecision = null;
  while (Date.now() - t0 < 45000) {
    polls++;
    const r = await c2.act(shopUrl, 'commerce.purchase', { amount: { value: 5, currency: 'USD' } }).catch((e) => ({ decision: `error ${errCode(e)}` }));
    lastDecision = `${r.decision} ${JSON.stringify(r.reasons ?? [])}`;
    if (r.decision !== 'allow') { first = Date.now() - t0; break; }
    await new Promise((res) => setTimeout(res, 1000));
  }
  rec('RV2-01 shop refuses the child within the published latency', 'refused within bound', first === null ? `still allowed after 45 s (${polls} tries)` : `refused after ${first} ms: ${lastDecision}`, first !== null, 'compare with latency_seconds.bound above');
} finally {
  await Promise.all(shops.map((s) => s.close()));
  await fed.close();
}
for (const l of out) process.stdout.write(JSON.stringify(l) + '\n');
process.exit(out.filter((l) => 'pass' in l).every((l) => l.pass) ? 0 : 1);
