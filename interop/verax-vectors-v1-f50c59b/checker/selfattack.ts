// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Usage: node checker/selfattack.ts <path to verax test-vectors> <out.json>
// Falsification of this checker, not of Verax. Each case copies valid-full to
// a scratch directory, changes one thing, and states the stage this checker
// must report. Cases 1 to 9 mutate the published bytes. Cases 10 to 17 re-sign
// the whole ledger under a key generated here, so rules the vector set does not
// exercise can be tested with valid signatures. Case 10 is the control and must
// be accepted. Case 16 is the regression for a key repeated under a second
// integer encoding. Case 17 is the same shape in the payload, which the label
// count also catches. resign() also re-signs the checkpoint over the
// re-signed chain, under a second generated witness key, so that cases 10 to
// 17 do not read as a checkpoint-coverage mismatch against a checkpoint still
// signed for the original octets. Cases 18 to 23 reach the four stages added
// after the first run (inputs-binding, checkpoint-signature,
// checkpoint-coverage, checkpoint-totals). 18 and 19 mutate
// ledger/inputs.jsonl, which the decision records do not sign over, so no
// record needs re-signing. 20 to 23 re-sign only the checkpoint, under a
// witness key generated here, because a changed claim breaks the original
// witness signature; case 21 is that resigning path's own control and must
// be accepted.

import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { runVector } from './verify.ts'
import { CborMap, cborDecode } from './cbor.ts'

const [root, out] = process.argv.slice(2)
const src = join(root, 'v1', 'valid-full')

function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n]
  if (n < 0x100) return [(major << 5) | 24, n]
  if (n < 0x10000) return [(major << 5) | 25, n >> 8, n & 0xff]
  if (n <= 0xffffffff) return [(major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
  const b = BigInt(n); const o = [(major << 5) | 27]
  for (let i = 7; i >= 0; i--) o.push(Number((b >> BigInt(i * 8)) & 0xffn))
  return o
}
// Encoder for test construction only: ints, text, bytes, null, arrays, maps as [k, v] pairs in the order given.
function enc(v: any): number[] {
  if (v === null) return [0xf6]
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v)
  if (typeof v === 'string') { const b = [...Buffer.from(v, 'utf8')]; return [...head(3, b.length), ...b] }
  if (v instanceof Uint8Array) return [...head(2, v.length), ...v]
  if (Array.isArray(v)) return [...head(4, v.length), ...v.flatMap(enc)]
  if (v && Array.isArray(v.map)) { const e = v.map as Array<[any, any]>; return [...head(5, e.length), ...e.flatMap(([k, x]) => [...enc(k), ...enc(x)])] }
  throw new Error('enc: unsupported')
}
const M = (entries: Array<[any, any]>) => ({ map: entries })
const bytes = (a: number[]) => new Uint8Array(a)
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex')

type Rec = { claims: any; coseHex: string; encoding: string; publicKeyPem: string }
const readLedger = (d: string): Rec[] => readFileSync(join(d, 'ledger', 'decisions.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
const writeLedger = (d: string, rs: Rec[]) => writeFileSync(join(d, 'ledger', 'decisions.jsonl'), rs.map(r => JSON.stringify(r)).join('\n') + '\n')

function scratch(): string { const d = mkdtempSync(join(tmpdir(), 'verax-sa-')); cpSync(src, d, { recursive: true }); return d }

const NAMES: Array<[number, string]> = [[-70501, 'decider'], [-70502, 'subject'], [-70503, 'requestHash'], [-70504, 'policyHash'],
  [-70505, 'inputsHash'], [-70506, 'decision'], [-70507, 'reasonCode'], [-70508, 'ref'], [-70509, 'effectHash'],
  [-70510, 'timestampMs'], [-70511, 'nonce'], [-70512, 'prevRecordHash'], [-70513, 'effectClass']]
const CT = 'application/cedulon-decision-record+cbor'

// Re-sign every record under a fresh key, applying edit(i, claims) first and relinking the chain.
type Raw = { prot?: (kid: Uint8Array) => Uint8Array; payload?: (c: any) => Uint8Array }
function resign(d: string, edit: (i: number, c: any) => { claims: any; drop?: number[]; extra?: Array<[number, any]>; raw?: Raw } | void) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const kid = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest().subarray(0, 8)
  writeFileSync(join(d, 'pins', 'record-key.pem'), pem)
  const rs = readLedger(d)
  let prev: string | null = null
  const outRecs = rs.map((r, i) => {
    let claims = { ...r.claims, prevRecordHash: prev }
    let drop: number[] = []; let extra: Array<[number, any]> = []; let raw: Raw = {}
    const e = edit(i, claims); if (e) { claims = e.claims; drop = e.drop ?? []; extra = e.extra ?? []; raw = e.raw ?? {} }
    const prot = raw.prot ? raw.prot(new Uint8Array(kid)) : bytes(enc(M([[1, -19], [3, CT], [4, new Uint8Array(kid)]])))
    const payload = raw.payload ? raw.payload(claims) : bytes(enc(M([...NAMES.filter(([l]) => !drop.includes(l)).map(([l, n]) => [l, claims[n]] as [number, any]), ...extra])))
    const tbs = bytes(enc(['Signature1', prot, new Uint8Array(0), payload]))
    const sig = sign(null, tbs, privateKey)
    const cose = bytes(enc([prot, M([]), payload, new Uint8Array(sig)]))
    prev = sha(cose)
    return { ...r, claims, publicKeyPem: pem, coseHex: Buffer.from(cose).toString('hex') }
  })
  writeLedger(d, outRecs)
  // Keep the checkpoint consistent with the re-signed chain: recompute
  // receiptCount, chainHeadHash and totals over the new records (their
  // timestampMs and decision are untouched by the edits above, so the
  // window and the counts do not move) and re-sign under a witness key
  // generated here, since the original witness private key is not held.
  if (readCheckpoints(d).length) {
    const counts: Record<string, number> = { allow: 0, deny: 0, defer: 0 }
    for (const r of outRecs) if (r.claims.decision in counts) counts[r.claims.decision]++
    const lastCose = bytes([...Buffer.from(outRecs[outRecs.length - 1].coseHex, 'hex')])
    resignCheckpoint(d, c => ({
      ...c, receiptCount: outRecs.length, chainHeadHash: sha(lastCose),
      totals: { allow: String(counts.allow), deny: String(counts.deny), defer: String(counts.defer) },
    }))
  }
}

type CpRec = { claims: any; coseHex: string; encoding: string; publicKeyPem: string }
const readCheckpoints = (d: string): CpRec[] => readFileSync(join(d, 'ledger', 'checkpoints.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
const writeCheckpoints = (d: string, rs: CpRec[]) => writeFileSync(join(d, 'ledger', 'checkpoints.jsonl'), rs.map(r => JSON.stringify(r)).join('\n') + '\n')
const CP_NAMES: Array<[number, string]> = [[-70101, 'epoch'], [-70102, 'startMs'], [-70103, 'endMs'],
  [-70104, 'receiptCount'], [-70105, 'chainHeadHash'], [-70106, 'totals'], [-70107, 'prevCheckpointHash']]
const CPCT = 'application/cedulon-checkpoint+cbor'

// Re-signs every checkpoint line under a fresh witness key, applying edit(claims) first.
function resignCheckpoint(d: string, edit: (c: any) => any) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const kid = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest().subarray(0, 8)
  writeFileSync(join(d, 'pins', 'witness-key.pem'), pem)
  const rs = readCheckpoints(d)
  const outRecs = rs.map(r => {
    const claims = edit({ ...r.claims })
    const prot = bytes(enc(M([[1, -19], [3, CPCT], [4, new Uint8Array(kid)]])))
    const payload = bytes(enc(M(CP_NAMES.map(([l, n]) =>
      [l, n === 'totals' ? (claims.totals === null ? null : M(Object.entries(claims.totals))) : claims[n]]))))
    const tbs = bytes(enc(['Signature1', prot, new Uint8Array(0), payload]))
    const sig = sign(null, tbs, privateKey)
    const cose = bytes(enc([prot, M([]), payload, new Uint8Array(sig)]))
    return { ...r, claims, publicKeyPem: pem, coseHex: Buffer.from(cose).toString('hex') }
  })
  writeCheckpoints(d, outRecs)
}

function patchCose(d: string, i: number, f: (b: Uint8Array) => Uint8Array) {
  const rs = readLedger(d); rs[i].coseHex = Buffer.from(f(new Uint8Array(Buffer.from(rs[i].coseHex, 'hex')))).toString('hex'); writeLedger(d, rs)
}
function payloadOffset(b: Uint8Array): number {
  const top = cborDecode(b) as any[]; const p = top[2] as Uint8Array
  return Buffer.from(b).indexOf(Buffer.from(p))
}

const cases: Array<[string, string, (d: string) => void]> = [
  ['01 signature byte flipped', 'record-signature', d => patchCose(d, 2, b => { const c = b.slice(); c[c.length - 1] ^= 1; return c })],
  ['02 payload byte flipped', 'record-signature', d => patchCose(d, 2, b => { const c = b.slice(); c[payloadOffset(b) + 40] ^= 1; return c })],
  ['03 COSE_Sign1 tag 18 added', 'record-header', d => patchCose(d, 0, b => bytes([0xd2, ...b]))],
  ['04 unprotected header not empty', 'record-header', d => patchCose(d, 0, b => {
    const t = cborDecode(b) as any[]; return bytes(enc([t[0], M([[33, 1]]), t[2], t[3]])) })],
  ['05 presented nonce changed', 'record-claims', d => { const rs = readLedger(d); rs[1].claims.nonce += 'x'; writeLedger(d, rs) }],
  ['06 duplicate alg in protected header', 'record-header', d => patchCose(d, 0, b => {
    const t = cborDecode(b) as any[]; const p = bytes([...head(5, 4), ...enc(1), ...enc(-19), ...enc(1), ...enc(-19),
      ...enc(3), ...enc(CT), ...enc(4), ...enc((cborDecode(t[0]) as CborMap).get(4))])
    return bytes(enc([p, M([]), t[2], t[3]])) })],
  ['07 middle record removed', 'chain', d => { const rs = readLedger(d); rs.splice(4, 1); writeLedger(d, rs) }],
  ['08 two records swapped', 'chain', d => { const rs = readLedger(d); [rs[3], rs[4]] = [rs[4], rs[3]]; writeLedger(d, rs) }],
  ['09 different key pinned', 'record-header', d => writeFileSync(join(d, 'pins', 'record-key.pem'),
    generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString())],
  ['10 re-signed control, no change', 'none', d => resign(d, () => undefined)],
  ['11 allow without effectClass', 'record-claims', d => resign(d, (i, c) => c.decision === 'allow' ? { claims: { ...c, effectClass: null } } : undefined)],
  ['12 allow with empty ref', 'record-claims', d => resign(d, (i, c) => c.decision === 'allow' ? { claims: { ...c, ref: '' } } : undefined)],
  ['13 twelve labels', 'record-claims', d => resign(d, (i, c) => i === 1 ? { claims: c, drop: [-70513] } : undefined)],
  ['14 uppercase hash', 'record-claims', d => resign(d, (i, c) => i === 1 ? { claims: { ...c, policyHash: c.policyHash.toUpperCase() } } : undefined)],
  ['15 timestampMs above 2^53 - 1', 'record-claims', d => resign(d, (i, c) => i === 1 ? { claims: { ...c, timestampMs: 2 ** 53 } } : undefined)],
  ['16 alg twice, encoded 01 and 18 01', 'record-header', d => resign(d, (i, c) => i === 0 ? { claims: c, raw: {
    prot: kid => bytes([...head(5, 4), 0x01, ...enc(-19), 0x18, 0x01, ...enc(-8), ...enc(3), ...enc(CT), ...enc(4), ...enc(kid)]) } } : undefined)],
  ['17 decision twice, second label in 8 bytes', 'record-claims', d => resign(d, (i, c) => i === 3 ? { claims: c, raw: {
    payload: cl => bytes([...head(5, NAMES.length + 1), ...NAMES.flatMap(([l, n]) => [...enc(l), ...enc(cl[n])]),
      0x3b, 0, 0, 0, 0, 0, 1, 0x13, 0x69, ...enc(cl.decision === 'deny' ? 'allow' : 'deny')]) } } : undefined)],
  ['18 inputs row tampered, record not resigned', 'inputs-binding', d => {
    const rows = readFileSync(join(d, 'ledger', 'inputs.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
    rows[1].inputs.principal.brain += '-tampered'
    writeFileSync(join(d, 'ledger', 'inputs.jsonl'), rows.map(r => JSON.stringify(r)).join('\n') + '\n')
  }],
  ['19 inputs row removed for a record', 'inputs-binding', d => {
    const rows = readFileSync(join(d, 'ledger', 'inputs.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
    rows.splice(1, 1)
    writeFileSync(join(d, 'ledger', 'inputs.jsonl'), rows.map(r => JSON.stringify(r)).join('\n') + '\n')
  }],
  ['20 checkpoint signature byte flipped', 'checkpoint-signature', d => {
    const rows = readCheckpoints(d)
    const b = Buffer.from(rows[0].coseHex, 'hex'); b[b.length - 1] ^= 1
    rows[0].coseHex = b.toString('hex')
    writeCheckpoints(d, rows)
  }],
  ['21 checkpoint re-signed, no change (control)', 'none', d => resignCheckpoint(d, c => c)],
  ['22 checkpoint receiptCount tampered, re-signed', 'checkpoint-coverage', d => resignCheckpoint(d, c => ({ ...c, receiptCount: c.receiptCount + 1 }))],
  ['23 checkpoint totals tampered, re-signed', 'checkpoint-totals', d => resignCheckpoint(d, c => ({ ...c, totals: { ...c.totals, allow: String(Number(c.totals.allow) + 1) } }))],
]

const rows = cases.map(([name, want, mutate]) => {
  const d = scratch()
  try {
    mutate(d)
    const r = runVector(d, name)
    const got = r.firstFailingStage ?? 'none'
    return { name, want, got, ok: got === want, detail: r.findings[0]?.detail ?? '' }
  } catch (e) {
    return { name, want, got: 'THREW', ok: false, detail: (e as Error).message }
  } finally { rmSync(d, { recursive: true, force: true }) }
})
for (const r of rows) console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.name.padEnd(38)} want ${r.want.padEnd(17)} got ${r.got.padEnd(17)} ${r.detail}`)
const neg = rows.filter(r => r.want !== 'none'), ctl = rows.filter(r => r.want === 'none')
console.log(`${neg.filter(r => r.ok).length} of ${neg.length} mutations rejected at the stated stage, ${ctl.filter(r => r.ok).length} of ${ctl.length} re-signed controls accepted`)
writeFileSync(out, JSON.stringify(rows, null, 2) + '\n')
process.exit(rows.every(r => r.ok) ? 0 : 1)
