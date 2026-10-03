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
// count also catches.

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
