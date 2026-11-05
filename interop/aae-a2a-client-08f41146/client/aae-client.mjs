// aae-client.mjs: an independent A2A client for the AAE extension profile v1
// (https://moltrust.ch/extensions/aae/v1), written for the cross-run of
// MoltyCel/aae-a2a-extension CROSSRUN.md, role "client".
//
// Written from spec/aae-a2a-extension-v1.md, CROSSRUN.md, the IETF text of
// draft-kroehl-agentic-trust-aae-02 and aae_a2a/testkeys.py (named by the guide
// for buyer_mandate()/held_mandate()). Node.js built-ins only: no a2a-sdk, no
// protobuf, no JCS library. It talks to one endpoint on 127.0.0.1 and writes
// only the files named on its command line.
//
// usage: node aae-client.mjs --url http://127.0.0.1:8790 --cases <cases.json>
//          --keys <test-keys.json> --did-dir <dir> --vectors <request-digest.json>
//          --out <result.json> --transcript <transcript.jsonl>
//          --cases-commit <sha> --client-commit <sha> --server-commit <sha>
//          [--participant <name>] [--client-repository <url>]
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const URI = 'https://moltrust.ch/extensions/aae/v1';
const DRAFT = 'draft-kroehl-agentic-trust-aae-02';

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
for (const k of ['url', 'cases', 'keys', 'did-dir', 'vectors', 'out', 'transcript', 'cases-commit', 'client-commit', 'server-commit'])
  if (!args[k]) { console.error(`missing --${k}`); process.exit(2); }

const transcript = fs.openSync(args.transcript, 'w');
const log = (obj) => fs.writeSync(transcript, JSON.stringify({ t: new Date().toISOString(), ...obj }) + '\n');

// ---------- primitives ------------------------------------------------------------
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const b64u = (b) => Buffer.from(b).toString('base64url');

// RFC 8785. Default Array.sort on strings compares UTF-16 code units, which is
// the JCS member order; JSON.stringify gives ES number and string serialization.
function jcs(v) {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('non-finite'); return JSON.stringify(v); }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
}
const requestDigest = (part) => 'sha256:' + sha256(Buffer.from(jcs(part), 'utf8')).toString('hex');
const taggedDigest = (tag, v) =>
  'sha256:' + sha256(Buffer.concat([Buffer.from(tag, 'ascii'), Buffer.from([0]), Buffer.from(jcs(v), 'utf8')])).toString('hex');

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const seedOf = (name) => sha256(Buffer.from('aae-a2a-extension/testkey/v1/' + name, 'utf8'));
const privOf = (name) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seedOf(name)]), format: 'der', type: 'pkcs8' });
const pubRaw = (name) => Buffer.from(crypto.createPublicKey(privOf(name)).export({ format: 'jwk' }).x, 'base64url');
const sign = (name, bytes) => crypto.sign(null, bytes, privOf(name));

function jws(header, payloadBytes, signer) {
  const input = b64u(Buffer.from(JSON.stringify(header), 'utf8')) + '.' + b64u(payloadBytes);
  return input + '.' + b64u(sign(signer, Buffer.from(input, 'ascii')));
}
const z = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

// ---------- self-checks before any case: keys and request_digest vectors ------------
const selfcheck = [];
{
  const keys = JSON.parse(fs.readFileSync(args.keys, 'utf8')).keys;
  for (const [name, k] of Object.entries(keys))
    selfcheck.push({ check: `seed ${name} derived == test-keys.json`, ok: seedOf(name).toString('hex') === k.ed25519_seed_hex });
  for (const f of fs.readdirSync(args['did-dir']).filter((f) => f.endsWith('.json')).sort()) {
    const doc = JSON.parse(fs.readFileSync(path.join(args['did-dir'], f), 'utf8'));
    const name = doc.id.replace('did:example:', '');
    selfcheck.push({ check: `DID ${doc.id} key == derived public key`, ok: doc.verificationMethod[0].publicKeyJwk.x === b64u(pubRaw(name)) });
  }
  for (const v of JSON.parse(fs.readFileSync(args.vectors, 'utf8')).vectors) {
    selfcheck.push({ check: `vector ${v.id} jcs octets`, ok: jcs(v.request_part) === v.jcs });
    selfcheck.push({ check: `vector ${v.id} request_digest`, ok: requestDigest(v.request_part) === v.request_digest });
  }
  log({ selfcheck });
  const bad = selfcheck.filter((c) => !c.ok);
  for (const c of selfcheck) console.log(`selfcheck ${c.ok ? 'ok  ' : 'FAIL'} ${c.check}`);
  if (bad.length) { console.error('self-checks failed; not running cases'); process.exit(3); }
}

// ---------- the request part exactly as cases.json writes it ------------------------
// JSON.parse loses "120.0" and member order; the raw text keeps both, so the
// wire carries the case's bytes and the server's number mapping (spec 6.4) is
// exercised. The local digest is computed over the parsed value.
const casesRaw = fs.readFileSync(args.cases, 'utf8');
const casesDoc = JSON.parse(casesRaw);
function rawRequestPart(id) {
  const at = casesRaw.indexOf(`"id": "${id}"`);
  const start = casesRaw.indexOf('{', casesRaw.indexOf('"request_part":', at));
  let depth = 0, inStr = false;
  for (let i = start; i < casesRaw.length; i++) {
    const c = casesRaw[i];
    if (inStr) { if (c === '\\') i++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true; else if (c === '{') depth++; else if (c === '}' && --depth === 0) return casesRaw.slice(start, i + 1);
  }
  throw new Error('request_part not found for ' + id);
}

// ---------- AAE and response variants (CROSSRUN.md section 3) ------------------------
const buyerMandate = () => ({
  actions: ['read', 'pay'],
  purpose: 'Purchase office supplies on behalf of the principal',
  scope: 'procurement',
  principal_did: 'did:example:principal-acme',
});
const HOLD_ACTION = { verb: 'pay', category: 'office-supplies' };
const heldMandate = () => ({
  ...buyerMandate(),
  principal: { did: 'did:example:principal-acme', public_key: pubRaw('principal').toString('hex') },
  grants: [{
    action_binding: taggedDigest('aae:enforce-action:v1', HOLD_ACTION),
    type_fields: ['verb', 'category'],
    disposition: 'hold',
    constraints: [{ type: 'range', field: 'amount', lo: 0, hi: 300 }, { type: 'exact', field: 'currency', value: 'EUR' }],
  }],
});
const ISSUER_HDR = { alg: 'EdDSA', cty: 'aae+json', kid: 'did:example:issuer#key-1' };

function makeVc(host, { mandate = buyerMandate(), domains = [host], nb, na, singleUse = false } = {}) {
  const now = Date.now();
  nb ??= now - 5 * 60e3; na ??= now + 3600e3;
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://moltrust.ch/contexts/aae/v1'],
    type: ['VerifiableCredential', 'AgentAuthorizationEnvelope'],
    id: 'urn:uuid:' + crypto.randomUUID(),
    issuer: 'did:example:issuer',
    validFrom: z(nb),
    credentialSubject: {
      id: 'did:example:buyer',
      aae: {
        mandate,
        constraints: {
          max_transaction_value: { value: 500, currency: 'EUR', required: true },
          allowed_domains: { value: domains, required: true },
        },
        validity: { not_before: z(nb), not_after: z(na), single_use: singleUse },
      },
    },
  };
}

// returns {jws, vc} ; vc is what the client believes it presented (id, mandate)
function buildAae(variant, host) {
  const now = Date.now();
  const enc = (vc) => Buffer.from(JSON.stringify(vc), 'utf8');
  let vc;
  switch (variant) {
    case 'none': return { jws: null, vc: null };
    case 'valid': vc = makeVc(host); break;
    case 'single_use': vc = makeVc(host, { singleUse: true }); break;
    case 'read_only': vc = makeVc(host, { mandate: { ...buyerMandate(), actions: ['read'] } }); break;
    case 'other_domain': vc = makeVc(host, { domains: ['other-supplier.example'] }); break;
    case 'expired': vc = makeVc(host, { nb: now - 2 * 3600e3, na: now - 3600e3 }); break;
    case 'hold': vc = makeVc(host, { mandate: heldMandate() }); break;
    case 'forged': vc = makeVc(host); return { jws: jws(ISSUER_HDR, enc(vc), 'mallory'), vc };
    case 'payload_not_json':
      return { jws: jws(ISSUER_HDR, Buffer.from('{"issuer": "did:example:issuer", ', 'utf8'), 'issuer'), vc: null };
    case 'duplicate_issuer': {
      vc = makeVc(host);
      const body = '{"issuer":"did:example:other-agent",' + JSON.stringify(vc).slice(1);
      return { jws: jws(ISSUER_HDR, Buffer.from(body, 'utf8'), 'issuer'), vc };
    }
    default: throw new Error('unknown AAE variant ' + variant);
  }
  return { jws: jws(ISSUER_HDR, enc(vc), 'issuer'), vc };
}

const RESPONSE = {
  valid: { signer: 'buyer', iat: 0 },
  wrong_key: { signer: 'mallory', iat: 0 },
  iat_past_inside: { signer: 'buyer', iat: -330 },
  iat_past_outside: { signer: 'buyer', iat: -390 },
  iat_future_inside: { signer: 'buyer', iat: 30 },
  iat_future_outside: { signer: 'buyer', iat: 90 },
};

// ---------- A2A JSON-RPC over fetch (spec Appendix A) --------------------------------
const base = args.url.replace(/\/$/, '');
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)) { console.error('refusing a non-loopback URL'); process.exit(2); }
let endpoint, audience, host, cardUrl = base + '/.well-known/agent-card.json';
let rpcId = 0;
const RAW = '__RAW_REQUEST_PART__';

async function rpc(caseId, message, activate, raw) {
  const id = ++rpcId;
  let body = JSON.stringify({ jsonrpc: '2.0', id, method: 'SendMessage', params: { message } });
  if (raw) body = body.replace(JSON.stringify(RAW), raw);
  const headers = { 'Content-Type': 'application/json', 'A2A-Version': '1.0' };
  if (activate) headers['A2A-Extensions'] = URI;
  const res = await fetch(endpoint, { method: 'POST', headers, body });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch { }
  log({ case: caseId, rpc_id: id, request: { headers, body }, response: { status: res.status, a2a_extensions: res.headers.get('a2a-extensions'), body: text } });
  return { json, status: res.status, echo: res.headers.get('a2a-extensions') };
}

function findKey(o, key) {
  if (o && typeof o === 'object') {
    if (key in o && typeof o[key] !== 'object') return o[key];
    for (const v of Object.values(o)) { const r = findKey(v, key); if (r !== undefined) return r; }
  }
  return undefined;
}

const checks = []; // client-side observations beyond the pass rule
const note = (caseId, what, ok, detail) => { checks.push({ case: caseId, what, ok, ...(detail ? { detail } : {}) }); };

function resultOf(task) {
  return task?.metadata?.[URI]?.result ?? task?.status?.message?.metadata?.[URI]?.result;
}

function taskEntry(caseId, task, part, vc) {
  const r = resultOf(task) || {};
  const e = { task_id: task.id, task_state: task.status?.state, verdict: r.verdict, request_digest: r.request_digest };
  if (Array.isArray(r.steps_passed) && r.verdict !== 'REJECT') e.steps_passed = r.steps_passed;
  if (r.verdict === 'REJECT') { e.step = r.step; e.reason_code = r.reason_code; }
  if (r.ratification) e.ratification_status = r.ratification.status;
  // client checks (spec 8.5, 8.2, 8.3)
  note(caseId, 'request_digest recomputed by client == returned', requestDigest(part) === r.request_digest, { local: requestDigest(part), returned: r.request_digest });
  const inStatus = task?.status?.message?.metadata?.[URI]?.result, inTask = task?.metadata?.[URI]?.result;
  if (r.verdict === 'REJECT' || r.verdict === 'PENDING')
    note(caseId, `${r.verdict} result present in both Task.metadata and status.message.metadata and equal`, !!inStatus && !!inTask && jcs(inStatus) === jcs(inTask));
  if (r.verdict === 'ACCEPT') {
    note(caseId, 'ACCEPT receipt in Task.metadata[URI].result', !!inTask);
    note(caseId, 'receipt aae_id == presented VC id', r.aae_id === vc?.id, { receipt: r.aae_id });
    note(caseId, 'receipt issuer/subject/skill/action', r.issuer === 'did:example:issuer' && r.subject === 'did:example:buyer' && r.skill === part.skill && r.action === 'pay');
    note(caseId, 'receipt draft', r.draft === DRAFT);
  }
  if (r.enforce) {
    const core = r.enforce.core;
    note(caseId, 'enforce.core_digest == tagged digest(aae:enforce-core:v1, core)', taggedDigest('aae:enforce-core:v1', core) === r.enforce.core_digest);
    if (vc) note(caseId, 'enforce.core.mandate_digest == digest(aae:enforce-mandate:v1, mandate presented)', core?.mandate_digest === taggedDigest('aae:enforce-mandate:v1', vc.credentialSubject.aae.mandate));
    note(caseId, 'enforce.core.transaction_digest == digest(aae:enforce-transaction:v1, transaction)', core?.transaction_digest === taggedDigest('aae:enforce-transaction:v1', part.transaction));
    note(caseId, 'enforce.core.action_digest == digest(aae:enforce-action:v1, action)', core?.action_digest === taggedDigest('aae:enforce-action:v1', part.transaction.action));
  }
  if (r.ratification) {
    note(caseId, 'ratification.core_digest == digest(aae:enforce-ratify-core:v1, core)', taggedDigest('aae:enforce-ratify-core:v1', r.ratification.core) === r.ratification.core_digest);
    note(caseId, 'ratification.core.ratifies == enforce.core_digest', r.ratification.core?.ratifies === r.enforce?.core_digest);
  }
  return e;
}

function ratificationFor(variant, coreDigest, mandate) {
  const signer = variant === 'principal' ? 'principal' : 'mallory';
  const authority = variant === 'principal' ? 'did:example:principal-acme' : 'did:example:mallory';
  const statement = { ratify_version: '3.0', ratifies: coreDigest, decision: 'APPROVED', authority };
  const bytes = Buffer.concat([Buffer.from('aae:enforce-ratify-statement:v1', 'ascii'), Buffer.from([0]), Buffer.from(jcs(statement), 'utf8')]);
  return { decision: 'APPROVED', authority_proof: { mandate, authority, signature: sign(signer, bytes).toString('hex') } };
}

// One presentation: presentation message, challenge, challenge response, and for
// the hold cases a ratification. Returns a case entry (Section 6 members).
async function present(c, aae, raw, part) {
  const msg = { messageId: crypto.randomUUID(), role: 'ROLE_USER', parts: [{ data: RAW, mediaType: 'application/json' }] };
  if (c.aae !== 'none') { msg.extensions = [URI]; msg.metadata = { [URI]: { aae: aae.jws } }; }
  const r1 = await rpc(c.id, msg, c.activate !== false, raw);
  if (r1.json?.error) {
    const e = { jsonrpc_code: r1.json.error.code };
    const rc = findKey(r1.json.error.data, 'reason_code'); if (rc !== undefined) e.reason_code = rc;
    return e;
  }
  if (c.activate !== false) note(c.id, 'server echoed A2A-Extensions header', r1.echo === URI, { echo: r1.echo });
  const t1 = r1.json?.result?.task;
  if (!t1) return { notes: 'no task and no error in the first response' };
  if (t1.status?.state !== 'TASK_STATE_AUTH_REQUIRED') return taskEntry(c.id, t1, part, aae.vc);

  const ch = t1.status?.message?.metadata?.[URI]?.challenge;
  // spec 6.3: check aud and aae_id before signing, and refuse otherwise
  const okAud = ch?.aud === audience, okId = ch?.aae_id === aae.vc?.id;
  note(c.id, 'challenge aud == card params.audience', okAud, { aud: ch?.aud });
  note(c.id, 'challenge aae_id == presented VC id', okId);
  note(c.id, 'nonce form <hex32+>.<digits>.<43 b64url>', /^[0-9a-f]{32,}\.\d+\.[A-Za-z0-9_-]{43}$/.test(ch?.nonce || ''));
  if (!okAud || !okId) return { task_id: t1.id, task_state: t1.status.state, notes: 'client refused to sign the challenge (spec 6.3)' };

  const rv = RESPONSE[c.challenge_response];
  const payload = { nonce: ch.nonce, aud: ch.aud, iat: z(Date.now() + rv.iat * 1000), aae_id: ch.aae_id };
  const resp = jws({ alg: 'EdDSA', kid: 'did:example:buyer#key-1' }, Buffer.from(JSON.stringify(payload), 'utf8'), rv.signer);
  const msg2 = {
    messageId: crypto.randomUUID(), role: 'ROLE_USER', taskId: t1.id, contextId: t1.contextId, extensions: [URI],
    parts: [{ text: 'AAE challenge response' }], metadata: { [URI]: { challenge_response: resp } },
  };
  const r2 = await rpc(c.id, msg2, true);
  if (r2.json?.error) return { jsonrpc_code: r2.json.error.code, notes: 'error on the challenge response' };
  let t = r2.json?.result?.task;
  if (!t) return { notes: 'no task in the challenge-response answer' };
  note(c.id, 'task id unchanged across the exchange', t.id === t1.id);

  if (c.ratification && c.ratification !== 'none' && t.status?.state === 'TASK_STATE_INPUT_REQUIRED') {
    const pend = resultOf(t);
    taskEntry(c.id + ' (held, before ratification)', t, part, aae.vc);
    const msg3 = {
      messageId: crypto.randomUUID(), role: 'ROLE_USER', taskId: t.id, contextId: t.contextId, extensions: [URI],
      parts: [{ text: 'AAE ratification' }],
      metadata: { [URI]: { ratification: ratificationFor(c.ratification, pend.enforce.core_digest, aae.vc.credentialSubject.aae.mandate) } },
    };
    const r3 = await rpc(c.id, msg3, true);
    if (r3.json?.error) return { jsonrpc_code: r3.json.error.code, notes: 'error on the ratification' };
    t = r3.json?.result?.task;
    if (!t) return { notes: 'no task in the ratification answer' };
  }
  return taskEntry(c.id, t, part, aae.vc);
}

// ---------- pass rule (CROSSRUN.md section 6), implemented here ----------------------
function judge(exp, e, ctx) {
  const why = [];
  if (exp.kind === 'error') {
    if (e.jsonrpc_code !== exp.jsonrpc_code) why.push(`jsonrpc_code ${e.jsonrpc_code} != ${exp.jsonrpc_code}`);
    return why;
  }
  for (const k of ['task_state', 'verdict', 'request_digest']) if (e[k] !== exp[k]) why.push(`${k} ${e[k]} != ${exp[k]}`);
  if (exp.verdict === 'REJECT' && e.step !== exp.step) why.push(`step ${e.step} != ${exp.step}`);
  if (exp.verdict === 'ACCEPT' && ![1, 2, 3, 4, 5, 6, 7].every((s) => e.steps_passed?.includes(s))) why.push('steps_passed lacks one of 1-7');
  if (exp.ratification_status && e.ratification_status !== exp.ratification_status) why.push(`ratification_status ${e.ratification_status} != ${exp.ratification_status}`);
  if (exp.admission && (e.verdict === 'ACCEPT') !== exp.admission.admitted) why.push('admission differs');
  return why;
}

// ---------- main ---------------------------------------------------------------------
const card = await (await fetch(cardUrl)).json();
log({ agent_card: card });
const ext = (card.capabilities?.extensions || []).find((x) => x.uri === URI);
if (!ext) { console.error('card does not declare the extension'); process.exit(4); }
if (ext.params?.draft !== DRAFT) { console.error('card params.draft differs: ' + ext.params?.draft); process.exit(4); }
endpoint = (card.supportedInterfaces || []).find((i) => /jsonrpc/i.test(i.protocolBinding || ''))?.url || card.url;
audience = ext.params.audience;
host = new URL(audience).hostname;
if (!endpoint || !endpoint.startsWith(base)) { console.error('endpoint not under the base URL: ' + endpoint); process.exit(4); }
note('card', 'extension required: true', ext.required === true);
note('card', 'params.skills place-order -> pay', ext.params.skills?.['place-order']?.action === 'pay');
note('card', 'params.audience == JSON-RPC interface URL (spec 10.5 pin)', audience === endpoint, { audience, endpoint });
note('card', 'deferred_decisions true', ext.params.deferred_decisions === true);
console.log(`endpoint ${endpoint}, audience ${audience}`);

const entries = [];
const taskIds = {};
for (const c of casesDoc.cases) {
  const raw = rawRequestPart(c.id);
  const part = JSON.parse(raw);
  let entry;
  try {
    if (c.expect.kind === 'retry') {
      const aae = buildAae(c.aae, host); // one AAE, the same bytes for every attempt
      const attempts = [];
      for (let i = 0; i < c.attempts; i++) attempts.push(await present(c, aae, raw, part));
      const why = [];
      attempts.forEach((a, i) => why.push(...judge(c.expect.attempts[i], a).map((w) => `attempt ${i + 1}: ${w}`)));
      if (new Set(attempts.map((a) => a.task_id)).size !== attempts.length) why.push('attempts are not distinct tasks');
      entry = { id: c.id, result: why.length ? 'fail' : 'pass', attempts };
      if (why.length) entry.notes = why.join('; ');
    } else {
      const aae = buildAae(c.aae, host);
      const e = await present(c, aae, raw, part);
      const why = judge(c.expect, e);
      if (c.id === 'XR-06' && e.task_id === taskIds['XR-01']) why.push('task id equals XR-01');
      const rcNote = c.expect.reason_code && e.reason_code !== c.expect.reason_code ? `reason_code ${e.reason_code} (expected ${c.expect.reason_code})` : null;
      entry = { id: c.id, result: why.length ? 'fail' : 'pass', ...e };
      const ns = [...why, ...(rcNote ? [rcNote] : []), ...(e.notes ? [e.notes] : [])];
      if (ns.length) entry.notes = ns.join('; '); else delete entry.notes;
      if (e.task_id) taskIds[c.id] = e.task_id;
    }
  } catch (err) {
    entry = { id: c.id, result: 'fail', notes: 'client exception: ' + err.message };
  }
  entries.push(entry);
  console.log(`${c.id}  ${entry.result}  ${entry.task_state || (entry.jsonrpc_code ? 'error ' + entry.jsonrpc_code : '')} ${entry.step ? 'step ' + entry.step + ' ' + entry.reason_code : ''}${entry.attempts ? entry.attempts.map((a) => a.task_state + (a.step ? ' step ' + a.step : '')).join(' / ') : ''}${entry.notes ? '  [' + entry.notes + ']' : ''}`);
}

const summary = { pass: 0, fail: 0, skipped: 0 };
for (const e of entries) summary[e.result]++;
const doc = {
  format: 'aae-a2a-crossrun/1',
  profile: URI,
  draft: DRAFT,
  cases_commit: args['cases-commit'],
  cases_sha256: 'sha256:' + sha256(fs.readFileSync(args.cases)).toString('hex'),
  run_at: z(Date.now()),
  participant: { name: args.participant || 'local run (unpublished)' },
  client: { implementation: 'aae-client.mjs, independent Node.js client (no reference code)', repository: args['client-repository'] || 'local, unpublished', commit: args['client-commit'], dirty: false },
  server: { implementation: 'aae-a2a-extension reference supplier', repository: 'https://github.com/MoltyCel/aae-a2a-extension', commit: args['server-commit'], dirty: false, agent_card: cardUrl },
  cases: entries,
  summary,
};
fs.writeFileSync(args.out, JSON.stringify(doc, null, 2) + '\n');
log({ client_checks: checks });
const badChecks = checks.filter((k) => !k.ok);
console.log(`\nclient checks: ${checks.length - badChecks.length} ok, ${badChecks.length} not ok`);
for (const k of badChecks) console.log('  not ok: ' + k.case + ': ' + k.what + (k.detail ? ' ' + JSON.stringify(k.detail) : ''));
console.log(`\n${summary.pass} pass, ${summary.fail} fail, ${summary.skipped} skipped -> ${args.out}`);
process.exit(summary.fail ? 1 : 0);
