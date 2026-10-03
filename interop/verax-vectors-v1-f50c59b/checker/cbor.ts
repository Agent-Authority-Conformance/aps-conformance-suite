// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Minimal CBOR decoder (RFC 8949 subset) for the Verax ledger checker.
// Adapted from interop/scitt-cose-vectors-ietf126/verifier/cbor.ts, with three
// changes this profile needs: a map that repeats an encoded key is refused
// (draft-dogru-cedulon-08 Section 6, MUST-T4-18), indefinite lengths and
// floats are refused (deterministic CBOR, RFC 8949 Section 4.2.1), and the
// encoder is limited to the Sig_structure subset. No external packages.

export type CborValue =
  | number | string | Uint8Array | boolean | null
  | CborValue[] | CborMap | CborTagged

export class CborMap {
  entries: Array<[CborValue, CborValue]> = []
  get(key: number | string): CborValue | undefined {
    for (const [k, v] of this.entries) if (k === key) return v
    return undefined
  }
  has(key: number | string): boolean {
    return this.entries.some(([k]) => k === key)
  }
}

export class CborTagged {
  tag: number
  value: CborValue
  constructor(tag: number, value: CborValue) { this.tag = tag; this.value = value }
}

class Reader {
  pos = 0
  buf: Uint8Array
  constructor(buf: Uint8Array) { this.buf = buf }
  u8(): number {
    if (this.pos >= this.buf.length) throw new Error('cbor: truncated')
    return this.buf[this.pos++]
  }
  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error('cbor: truncated')
    const out = this.buf.subarray(this.pos, this.pos + n)
    this.pos += n
    return out
  }
}

function readLength(r: Reader, info: number): number {
  if (info < 24) return info
  if (info === 24) return r.u8()
  if (info === 25) { const b = r.bytes(2); return (b[0] << 8) | b[1] }
  if (info === 26) { const b = r.bytes(4); return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0 }
  if (info === 27) {
    const b = r.bytes(8)
    let v = 0n
    for (const x of b) v = (v << 8n) | BigInt(x)
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: integer beyond 2^53 - 1')
    return Number(v)
  }
  throw new Error(`cbor: additional info ${info} refused (indefinite or reserved)`)
}

const hexKey = (b: Uint8Array): string => Buffer.from(b).toString('hex')

function decodeItem(r: Reader, depth: number): CborValue {
  if (depth > 32) throw new Error('cbor: nesting deeper than 32 refused')
  const start = r.pos
  const ib = r.u8()
  const major = ib >> 5
  const info = ib & 0x1f
  switch (major) {
    case 0: return readLength(r, info)
    case 1: return -1 - readLength(r, info)
    case 2: return new Uint8Array(r.bytes(readLength(r, info)))
    case 3: return new TextDecoder('utf-8', { fatal: true }).decode(r.bytes(readLength(r, info)))
    case 4: {
      const n = readLength(r, info)
      const out: CborValue[] = []
      for (let i = 0; i < n; i++) out.push(decodeItem(r, depth + 1))
      return out
    }
    case 5: {
      const n = readLength(r, info)
      const m = new CborMap()
      const seen = new Set<string>()
      for (let i = 0; i < n; i++) {
        const ks = r.pos
        const k = decodeItem(r, depth + 1)
        const enc = hexKey(r.buf.subarray(ks, r.pos))
        if (seen.has(enc)) throw new Error(`cbor: duplicate map key at offset ${ks}`)
        seen.add(enc)
        m.entries.push([k, decodeItem(r, depth + 1)])
      }
      return m
    }
    case 6: return new CborTagged(readLength(r, info), decodeItem(r, depth + 1))
    case 7: {
      if (info === 20) return false
      if (info === 21) return true
      if (info === 22) return null
      throw new Error(`cbor: simple or float value (info ${info}) at offset ${start} refused`)
    }
    default: throw new Error(`cbor: unsupported major type ${major}`)
  }
}

export function cborDecode(buf: Uint8Array): CborValue {
  const r = new Reader(buf)
  const v = decodeItem(r, 0)
  if (r.pos !== buf.length) throw new Error(`cbor: ${buf.length - r.pos} trailing bytes`)
  return v
}

function encodeHead(major: number, n: number): Uint8Array {
  if (n < 24) return Uint8Array.of((major << 5) | n)
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n)
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff)
  if (n <= 0xffffffff) {
    return Uint8Array.of((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff)
  }
  throw new Error('cbor encode: length beyond uint32 not needed here')
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0))
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

/** Encodes text, byte strings and arrays: what the Sig_structure needs. */
export function cborEncode(value: CborValue): Uint8Array {
  if (typeof value === 'string') {
    const b = new TextEncoder().encode(value)
    return concat([encodeHead(3, b.length), b])
  }
  if (value instanceof Uint8Array) return concat([encodeHead(2, value.length), value])
  if (Array.isArray(value)) return concat([encodeHead(4, value.length), ...value.map(cborEncode)])
  throw new Error('cbor encode: unsupported type')
}
