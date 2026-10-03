// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Bounded checker for Verax decision ledgers (test-vectors v1 at f50c59b).
// Written from draft-dogru-cedulon-decision-profile-03 Section 4 and its
// normative reference draft-dogru-cedulon-08 Sections 6.1 to 6.3, plus
// RFC 9052 Section 4.4 and RFC 8032. No Verax code is used.
//
// Assessed stages, in the vector set's stage order:
//   record-header     untagged COSE_Sign1, empty unprotected header, alg -19,
//                     content type, kid from the pinned SPKI DER
//   record-signature  Ed25519 over ["Signature1", protected, h'', payload]
//   record-claims     thirteen labels, types, claim rules of profile 4.2,
//                     decoded map equal to the claims presented beside it
//   chain             prevRecordHash null first, then SHA-256 of the previous
//                     record's COSE_Sign1 octets, walked over every record
// Every later stage (inputs-binding to control) is NOT assessed. This file
// never opens expected.json or manifest.json.

import { createHash, createPublicKey, verify as edVerify, type KeyObject } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CborMap, CborTagged, cborDecode, cborEncode, type CborValue } from './cbor.ts'

export const ASSESSED = ['record-header', 'record-signature', 'record-claims', 'chain'] as const
export const NOT_ASSESSED = ['inputs-binding', 'effect-binding', 'index', 'approval-signature',
  'checkpoint-signature', 'checkpoint-coverage', 'checkpoint-totals', 'control'] as const
type Stage = typeof ASSESSED[number]

const CONTENT_TYPE = 'application/cedulon-decision-record+cbor'
const HASH = /^[0-9a-f]{64}$/
const LABELS: Array<[number, string, 'tstr' | 'hash' | 'hash?' | 'tstr?' | 'uint' | 'decision']> = [
  [-70501, 'decider', 'tstr'], [-70502, 'subject', 'tstr'], [-70503, 'requestHash', 'hash'],
  [-70504, 'policyHash', 'hash'], [-70505, 'inputsHash', 'hash?'], [-70506, 'decision', 'decision'],
  [-70507, 'reasonCode', 'tstr'], [-70508, 'ref', 'tstr?'], [-70509, 'effectHash', 'hash?'],
  [-70510, 'timestampMs', 'uint'], [-70511, 'nonce', 'tstr'], [-70512, 'prevRecordHash', 'hash?'],
  [-70513, 'effectClass', 'tstr?'],
]

const sha256 = (b: Uint8Array): Buffer => createHash('sha256').update(b).digest()

export interface Finding { stage: Stage; record: number; detail: string }
export interface VectorResult {
  id: string
  records: number
  assessed: readonly string[]
  notAssessed: readonly string[]
  outcome: 'FAILS_AT_ASSESSED_STAGE' | 'NO_FAILURE_IN_ASSESSED_STAGES'
  firstFailingStage: Stage | null
  findings: Finding[]
  warnings: string[]
  recordHashes: string[]
}

interface Parsed {
  octets: Uint8Array
  protectedBytes?: Uint8Array
  payload?: Uint8Array
  signature?: Uint8Array
  protectedMap?: CborMap
  presented: Record<string, unknown>
  carriedPem?: string
}

function headerStage(p: Parsed, kid: Buffer): string | null {
  let top: CborValue
  try { top = cborDecode(p.octets) } catch (e) { return `COSE octets: ${(e as Error).message}` }
  if (top instanceof CborTagged) return `tagged (tag ${top.tag}); the profile requires untagged COSE_Sign1`
  if (!Array.isArray(top) || top.length !== 4) return 'not an array of four'
  const [prot, unprot, payload, sig] = top
  if (!(prot instanceof Uint8Array)) return 'protected header is not a byte string'
  if (!(unprot instanceof CborMap)) return 'unprotected header is not a map'
  if (unprot.entries.length !== 0) return 'cose-sign1-unprotected: unprotected header is not empty'
  if (!(payload instanceof Uint8Array)) return 'payload is not an embedded byte string'
  if (!(sig instanceof Uint8Array)) return 'signature is not a byte string'
  let pm: CborValue
  try { pm = cborDecode(prot) } catch (e) { return `protected header: ${(e as Error).message}` }
  if (!(pm instanceof CborMap)) return 'protected header does not decode to a map'
  if (pm.get(1) !== -19) return `alg is ${String(pm.get(1))}, not -19`
  if (pm.get(3) !== CONTENT_TYPE) return `content type is ${JSON.stringify(pm.get(3))}`
  const k = pm.get(4)
  if (!(k instanceof Uint8Array)) return 'kid missing or not a byte string'
  if (!kid.equals(Buffer.from(k))) return `kid ${Buffer.from(k).toString('hex')} is not the pinned key's ${kid.toString('hex')}`
  Object.assign(p, { protectedBytes: prot, payload, signature: sig, protectedMap: pm })
  return null
}

function signatureStage(p: Parsed, key: KeyObject): string | null {
  const tbs = cborEncode(['Signature1', p.protectedBytes!, new Uint8Array(0), p.payload!])
  return edVerify(null, tbs, key, p.signature!) ? null : 'Ed25519 signature does not verify under the pinned key'
}

function claimsStage(p: Parsed): string | null {
  let m: CborValue
  try { m = cborDecode(p.payload!) } catch (e) { return `payload: ${(e as Error).message}` }
  if (!(m instanceof CborMap)) return 'payload is not a map'
  const want = new Set(LABELS.map(([l]) => l))
  for (const [k] of m.entries) if (typeof k !== 'number' || !want.has(k)) return `unexpected label ${String(k)}`
  if (m.entries.length !== LABELS.length) return `${m.entries.length} labels, not ${LABELS.length}`
  const c: Record<string, CborValue> = {}
  for (const [label, name, type] of LABELS) {
    const v = m.get(label)!
    const nullable = type.endsWith('?')
    if (v === null) { if (!nullable) return `${name} is null`; c[name] = null; continue }
    if (type === 'uint') {
      if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) return `${name} is not a uint at most 2^53 - 1`
    } else if (typeof v !== 'string') return `${name} is not a text string`
    if ((type === 'hash' || type === 'hash?') && !HASH.test(v as string)) return `${name} breaks the hash grammar`
    if (type === 'decision' && !['allow', 'deny', 'defer'].includes(v as string)) return `decision ${String(v)}`
    c[name] = v
  }
  if (c.decision === 'allow') {
    if (typeof c.ref !== 'string' || c.ref === '') return 'allow without a non-empty ref'
    if (c.effectHash === null) return 'allow with effectHash null'
    if (typeof c.effectClass !== 'string' || c.effectClass === '') return 'allow without a non-empty effectClass'
  } else if (c.effectHash !== null) return `${String(c.decision)} carries a non-null effectHash`
  const pres = p.presented
  const keys = Object.keys(pres).sort()
  const names = LABELS.map(([, n]) => n).sort()
  if (keys.join() !== names.join()) return `presented claims have keys ${keys.join(',')}`
  for (const n of names) if (pres[n] !== c[n]) return `presented ${n} ${JSON.stringify(pres[n])} differs from signed ${JSON.stringify(c[n])}`
  return null
}

export function runVector(dir: string, id: string): VectorResult {
  const pinPem = readFileSync(join(dir, 'pins', 'record-key.pem'), 'utf8')
  const key = createPublicKey(pinPem)
  if (key.asymmetricKeyType !== 'ed25519') throw new Error(`${id}: pinned record key is ${key.asymmetricKeyType}`)
  const kid = sha256(key.export({ type: 'spki', format: 'der' })).subarray(0, 8)
  const lines = readFileSync(join(dir, 'ledger', 'decisions.jsonl'), 'utf8').split('\n').filter(l => l.trim() !== '')
  const recs: Parsed[] = lines.map((l, i) => {
    const o = JSON.parse(l)
    if (typeof o.coseHex !== 'string' || !/^([0-9a-f]{2})+$/.test(o.coseHex)) throw new Error(`${id}: record ${i} coseHex malformed`)
    return { octets: new Uint8Array(Buffer.from(o.coseHex, 'hex')), presented: o.claims ?? {}, carriedPem: o.publicKeyPem }
  })
  const findings: Finding[] = []
  const warnings: string[] = []
  const stageOk = (s: Stage, f: (p: Parsed, i: number) => string | null, only: Parsed[]) => {
    only.forEach((p) => { const i = recs.indexOf(p); const d = f(p, i); if (d) findings.push({ stage: s, record: i, detail: d }) })
  }
  stageOk('record-header', p => headerStage(p, kid), recs)
  const headed = recs.filter((_, i) => !findings.some(f => f.record === i))
  stageOk('record-signature', p => signatureStage(p, key), headed)
  const signed = headed.filter(p => !findings.some(f => f.record === recs.indexOf(p)))
  stageOk('record-claims', p => claimsStage(p), signed)
  // MUST-DP-5: walk every presented record, not only the ones that verified.
  recs.forEach((p, i) => {
    const want = i === 0 ? null : sha256(recs[i - 1].octets).toString('hex')
    let got: CborValue | undefined
    try {
      const top = cborDecode(p.octets) as CborValue[]
      got = (cborDecode(top[2] as Uint8Array) as CborMap).get(-70512)
    } catch { got = undefined }
    if (got !== want) findings.push({ stage: 'chain', record: i, detail: `prevRecordHash ${JSON.stringify(got)}, expected ${JSON.stringify(want)}` })
  })
  // carried-key-mismatch (cedulon-08 6.3) applies only to a record that verifies under the pin.
  recs.forEach((p, i) => {
    if (findings.some(f => f.record === i && f.stage !== 'chain' && f.stage !== 'record-claims')) return
    if (p.carriedPem && p.carriedPem.trim() !== pinPem.trim()) {
      const carried = createPublicKey(p.carriedPem).export({ type: 'spki', format: 'der' })
      if (!Buffer.from(carried).equals(key.export({ type: 'spki', format: 'der' }))) warnings.push(`record ${i}: carried-key-mismatch`)
    }
  })
  const first = ASSESSED.find(s => findings.some(f => f.stage === s)) ?? null
  return {
    id, records: recs.length, assessed: ASSESSED, notAssessed: NOT_ASSESSED,
    outcome: first ? 'FAILS_AT_ASSESSED_STAGE' : 'NO_FAILURE_IN_ASSESSED_STAGES',
    firstFailingStage: first, findings, warnings,
    recordHashes: recs.map(p => sha256(p.octets).toString('hex')),
  }
}
