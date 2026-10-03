// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Bounded checker for Verax decision ledgers (test-vectors v1 at f50c59b).
// Written from draft-dogru-cedulon-decision-profile-03 Section 4 and its
// normative reference draft-dogru-cedulon-08 Sections 6.1 to 6.3 and 7, plus
// RFC 9052 Section 4.4, RFC 8032 and RFC 8785. No Verax code is used.
//
// Assessed stages, in the vector set's stage order:
//   record-header        untagged COSE_Sign1, empty unprotected header, alg -19,
//                        content type, kid from the pinned SPKI DER
//   record-signature     Ed25519 over ["Signature1", protected, h'', payload]
//   record-claims        thirteen labels, types, claim rules of profile 4.2,
//                        decoded map equal to the claims presented beside it
//   chain                prevRecordHash null first, then SHA-256 of the previous
//                        record's COSE_Sign1 octets, walked over every record
//   inputs-binding       a record's signed inputsHash equals SHA-256 of the RFC
//                        8785 canonical JSON of its ledger/inputs.jsonl row's
//                        "inputs" value (profile 4.1), or the row is missing
//   checkpoint-signature a checkpoint's COSE_Sign1, header rules of cedulon-08
//                        6.2, under the pinned witness key
//   checkpoint-coverage  receiptCount and chainHeadHash against the attested
//                        records whose timestampMs falls in [startMs, endMs)
//                        (profile 4.4, cedulon-08 11.1)
//   checkpoint-totals    the signed allow/deny/defer totals against the same
//                        window (profile 4.4, cedulon-08 11.1)
// Every other stage (effect-binding, index, approval-signature, control) is
// NOT assessed. This file never opens expected.json or manifest.json.

import { createHash, createPublicKey, verify as edVerify, type KeyObject } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CborMap, CborTagged, cborDecode, cborEncode, type CborValue } from './cbor.ts'

export const ASSESSED = ['record-header', 'record-signature', 'record-claims', 'chain',
  'inputs-binding', 'checkpoint-signature', 'checkpoint-coverage', 'checkpoint-totals'] as const
export const NOT_ASSESSED = ['effect-binding', 'index', 'approval-signature', 'control'] as const
// The vector set's twelve-stage order (README "Stages" table), used by
// compare.ts to tell a stage reached with every earlier stage assessed apart
// from one reached behind a gap of unassessed stages.
export const STAGE_ORDER = ['record-header', 'record-signature', 'record-claims', 'chain',
  'inputs-binding', 'effect-binding', 'index', 'approval-signature',
  'checkpoint-signature', 'checkpoint-coverage', 'checkpoint-totals', 'control'] as const
type Stage = typeof ASSESSED[number]

const CONTENT_TYPE = 'application/cedulon-decision-record+cbor'
const CHECKPOINT_CONTENT_TYPE = 'application/cedulon-checkpoint+cbor'
const HASH = /^[0-9a-f]{64}$/
const LABELS: Array<[number, string, 'tstr' | 'hash' | 'hash?' | 'tstr?' | 'uint' | 'decision']> = [
  [-70501, 'decider', 'tstr'], [-70502, 'subject', 'tstr'], [-70503, 'requestHash', 'hash'],
  [-70504, 'policyHash', 'hash'], [-70505, 'inputsHash', 'hash?'], [-70506, 'decision', 'decision'],
  [-70507, 'reasonCode', 'tstr'], [-70508, 'ref', 'tstr?'], [-70509, 'effectHash', 'hash?'],
  [-70510, 'timestampMs', 'uint'], [-70511, 'nonce', 'tstr'], [-70512, 'prevRecordHash', 'hash?'],
  [-70513, 'effectClass', 'tstr?'],
]

const sha256 = (b: Uint8Array): Buffer => createHash('sha256').update(b).digest()

// cedulon-08 Section 7: "the canonical encoding" of a JSON document means RFC
// 8785 (JCS), hashed as its UTF-8 octets. This vector set's inputs rows hold
// only ASCII text, safe integers, booleans, null, arrays and objects, so
// sorting member names by UTF-16 code unit and otherwise rendering each leaf
// with JSON.stringify (which already follows the ECMA-262 algorithms JCS
// requires, for strings and for integers in this range) reproduces RFC 8785
// bytes for this set. A document needing JCS's float or lone-surrogate rules
// is outside what this function was built for.
function jcs(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'number' || typeof v === 'string') return JSON.stringify(v)
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    const keys = Object.keys(o).sort()
    return `{${keys.map(k => `${JSON.stringify(k)}:${jcs(o[k])}`).join(',')}}`
  }
  throw new Error(`jcs: unsupported value ${typeof v}`)
}

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

// The shape a COSE_Sign1 octet string decodes into, before any claim set is
// read. Decision records and checkpoints share this shape and the header and
// signature logic below; a decision record additionally carries the claims
// presented beside it (Parsed).
interface Signed {
  octets: Uint8Array
  protectedBytes?: Uint8Array
  payload?: Uint8Array
  signature?: Uint8Array
  protectedMap?: CborMap
}
interface Parsed extends Signed {
  presented: Record<string, unknown>
  carriedPem?: string
}

function headerStage(p: Signed, kid: Buffer, contentType: string): string | null {
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
  if (pm.get(3) !== contentType) return `content type is ${JSON.stringify(pm.get(3))}`
  const k = pm.get(4)
  if (!(k instanceof Uint8Array)) return 'kid missing or not a byte string'
  if (!kid.equals(Buffer.from(k))) return `kid ${Buffer.from(k).toString('hex')} is not the pinned key's ${kid.toString('hex')}`
  Object.assign(p, { protectedBytes: prot, payload, signature: sig, protectedMap: pm })
  return null
}

function signatureStage(p: Signed, key: KeyObject): string | null {
  const tbs = cborEncode(['Signature1', p.protectedBytes!, new Uint8Array(0), p.payload!])
  return edVerify(null, tbs, key, p.signature!) ? null : 'Ed25519 signature does not verify under the pinned key'
}

// checkpoint-signature (stage 9): the vector set's stage table names one
// check for a checkpoint, so a header defect and a signature defect are both
// reported under it, unlike the two stages a decision record gets.
function checkpointStage(p: Signed, kid: Buffer, key: KeyObject): string | null {
  const h = headerStage(p, kid, CHECKPOINT_CONTENT_TYPE)
  if (h) return h
  return signatureStage(p, key)
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

// inputs-binding (stage 5, decision-profile-03 Section 4.1): inputsHash, when
// not null, is "the SHA-256 of whatever further context the Decider
// consulted, encoded the same way [as requestHash]" - the canonical JSON
// encoding of cedulon-08 Section 7. The vector set's ledger/inputs.jsonl row
// matching a record's ref carries that context under its "inputs" member;
// hashing anything else (the whole row, or the row's "inputs.inputs" array)
// does not reproduce the signed inputsHash on valid-full, so this is the one
// construction implemented.
function inputsBindingStage(p: Parsed, inputsByRef: Map<string, unknown>): string | null {
  const m = cborDecode(p.payload!) as CborMap
  const ih = m.get(-70505)
  if (ih === null) return null
  const ref = m.get(-70508) as string
  if (!inputsByRef.has(ref)) return `no ledger/inputs.jsonl row for ref ${JSON.stringify(ref)}`
  const got = sha256(new TextEncoder().encode(jcs(inputsByRef.get(ref)))).toString('hex')
  return got === ih ? null : `inputsHash ${ih} does not match SHA-256 of the canonical inputs row, computed ${got}`
}

interface CheckpointClaims {
  startMs: number; endMs: number; receiptCount: number
  chainHeadHash: string | null; totals: Map<string, string> | null
}

function decodeCheckpointClaims(payload: Uint8Array): CheckpointClaims {
  const m = cborDecode(payload)
  if (!(m instanceof CborMap)) throw new Error('checkpoint payload is not a map')
  const totalsRaw = m.get(-70106)
  let totals: Map<string, string> | null = null
  if (totalsRaw !== null) {
    if (!(totalsRaw instanceof CborMap)) throw new Error('totals is not a map or null')
    totals = new Map()
    for (const [k, v] of totalsRaw.entries) {
      if (typeof k !== 'string' || typeof v !== 'string') throw new Error('totals carries a non-text key or value')
      totals.set(k, v)
    }
  }
  const startMs = m.get(-70102), endMs = m.get(-70103), receiptCount = m.get(-70104), chainHeadHash = m.get(-70105)
  if (typeof startMs !== 'number' || typeof endMs !== 'number' || typeof receiptCount !== 'number') {
    throw new Error('startMs, endMs or receiptCount is not a uint')
  }
  if (chainHeadHash !== null && (typeof chainHeadHash !== 'string' || !HASH.test(chainHeadHash))) {
    throw new Error('chainHeadHash breaks the hash grammar')
  }
  return { startMs, endMs, receiptCount, chainHeadHash: chainHeadHash as string | null, totals }
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
  const stageOk = <T extends Signed>(s: Stage, f: (p: T) => string | null, pool: T[], all: T[]) => {
    pool.forEach((p) => { const i = all.indexOf(p); const d = f(p); if (d) findings.push({ stage: s, record: i, detail: d }) })
  }
  stageOk('record-header', p => headerStage(p, kid, CONTENT_TYPE), recs, recs)
  const headed = recs.filter((_, i) => !findings.some(f => f.record === i))
  stageOk('record-signature', p => signatureStage(p, key), headed, recs)
  const signed = headed.filter(p => !findings.some(f => f.record === recs.indexOf(p)))
  stageOk('record-claims', p => claimsStage(p), signed, recs)
  const claimed = signed.filter(p => !findings.some(f => f.record === recs.indexOf(p) && f.stage === 'record-claims'))
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
  // inputs-binding (stage 5): only over records whose claims are already sound.
  const inputsRows = readFileSync(join(dir, 'ledger', 'inputs.jsonl'), 'utf8').split('\n').filter(l => l.trim() !== '')
    .map(l => JSON.parse(l) as { ref: string; inputs: unknown })
  const inputsByRef = new Map(inputsRows.map(r => [r.ref, r.inputs]))
  stageOk('inputs-binding', p => inputsBindingStage(p, inputsByRef), claimed, recs)

  // attested: a record clean through chain, the population checkpoint-coverage
  // and checkpoint-totals compare against (decision-profile-03 4.4, cedulon-08 11.1).
  const attested = recs.filter((_, i) => !findings.some(f => f.record === i &&
    (f.stage === 'record-header' || f.stage === 'record-signature' || f.stage === 'record-claims' || f.stage === 'chain')))
  const attestedMeta = new Map(attested.map(p => {
    const m = cborDecode(p.payload!) as CborMap
    return [recs.indexOf(p), { ts: m.get(-70510) as number, decision: m.get(-70506) as string }] as const
  }))

  const cpLines = readFileSync(join(dir, 'ledger', 'checkpoints.jsonl'), 'utf8').split('\n').filter(l => l.trim() !== '')
  const checkpoints: Signed[] = cpLines.map((l, i) => {
    const o = JSON.parse(l)
    if (typeof o.coseHex !== 'string' || !/^([0-9a-f]{2})+$/.test(o.coseHex)) throw new Error(`${id}: checkpoint ${i} coseHex malformed`)
    return { octets: new Uint8Array(Buffer.from(o.coseHex, 'hex')) }
  })
  const witnessPem = readFileSync(join(dir, 'pins', 'witness-key.pem'), 'utf8')
  const witnessKey = createPublicKey(witnessPem)
  if (witnessKey.asymmetricKeyType !== 'ed25519') throw new Error(`${id}: pinned witness key is ${witnessKey.asymmetricKeyType}`)
  const witnessKid = sha256(witnessKey.export({ type: 'spki', format: 'der' })).subarray(0, 8)
  stageOk('checkpoint-signature', p => checkpointStage(p, witnessKid, witnessKey), checkpoints, checkpoints)

  checkpoints.forEach((cp, i) => {
    if (findings.some(f => f.stage === 'checkpoint-signature' && f.record === i)) return
    let claims: CheckpointClaims
    try { claims = decodeCheckpointClaims(cp.payload!) } catch (e) {
      findings.push({ stage: 'checkpoint-coverage', record: i, detail: `checkpoint claims: ${(e as Error).message}` })
      return
    }
    const windowRecs = recs.filter((_, ri) => {
      const meta = attestedMeta.get(ri)
      return meta !== undefined && meta.ts >= claims.startMs && meta.ts < claims.endMs
    })
    const expectedHash = windowRecs.length ? sha256(windowRecs[windowRecs.length - 1].octets).toString('hex') : null
    const coverageProblems: string[] = []
    if (claims.receiptCount !== windowRecs.length) {
      coverageProblems.push(`receiptCount ${claims.receiptCount}, ${windowRecs.length} attested record(s) fall in [${claims.startMs}, ${claims.endMs})`)
    }
    if (claims.chainHeadHash !== expectedHash) {
      coverageProblems.push(`chainHeadHash ${JSON.stringify(claims.chainHeadHash)}, expected ${JSON.stringify(expectedHash)}`)
    }
    if (coverageProblems.length) {
      findings.push({ stage: 'checkpoint-coverage', record: i, detail: coverageProblems.join('; ') })
      return
    }
    // checkpoint-totals (stage 11): an issuer that redacts totals signs it
    // null (cedulon-08 11.1, MUST-T11-12); nothing to compare against.
    if (claims.totals === null) return
    const names = ['allow', 'deny', 'defer'] as const
    const gotKeys = [...claims.totals.keys()].sort()
    if (gotKeys.join() !== names.slice().sort().join()) {
      findings.push({ stage: 'checkpoint-totals', record: i, detail: `totals keys ${gotKeys.join(',')}, not allow,defer,deny` })
      return
    }
    const counts: Record<string, number> = { allow: 0, deny: 0, defer: 0 }
    for (const ri of windowRecs.map(p => recs.indexOf(p))) {
      const d = attestedMeta.get(ri)!.decision
      if (d in counts) counts[d]++
    }
    const mismatches = names
      .map(n => ({ n, want: String(counts[n]), got: claims.totals!.get(n)! }))
      .filter(x => x.want !== x.got)
    if (mismatches.length) {
      findings.push({
        stage: 'checkpoint-totals', record: i,
        detail: mismatches.map(x => `totals.${x.n} ${x.got}, computed ${x.want}`).join('; '),
      })
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
