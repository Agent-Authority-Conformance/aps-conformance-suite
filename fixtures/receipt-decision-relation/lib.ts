// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Self-contained primitives for the receipt-decision-relation family.
//
// Deliberately NOT imported from the APS SDK. The whole point of this family is
// that a second implementation, written from the specification rather than from
// the producing code, arrives at the same digests. Sharing the SDK's helpers
// would make the agreement circular. Node's stdlib crypto is the only dependency.

import crypto from 'node:crypto'

/** RFC 8785 JSON Canonicalization Scheme.
 *
 *  Object member names are sorted by their UTF-16 code units, which is what a
 *  bare Array.prototype.sort() on JavaScript strings does, per RFC 8785 3.2.3.
 *  Strings and numbers use the ES2015 serialization that JSON.stringify already
 *  implements. Null is preserved rather than filtered. */
export function canonicalizeJCS(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number': {
      if (!isFinite(value)) throw new Error('JCS does not support Infinity or NaN')
      return JSON.stringify(value)
    }
    case 'string':
      return JSON.stringify(value)
    case 'object': {
      if (Array.isArray(value)) return '[' + value.map(item => canonicalizeJCS(item)).join(',') + ']'
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).sort()
      const pairs: string[] = []
      for (const key of keys) pairs.push(`${JSON.stringify(key)}:${canonicalizeJCS(obj[key])}`)
      return '{' + pairs.join(',') + '}'
    }
    default:
      throw new Error(`JCS: unsupported type ${typeof value}`)
  }
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf-8').digest('hex')
}

/** Domain separation: the tag, one NUL byte, then the canonical form. */
export function tagged(tag: string, canonical: string): string {
  return `${tag}\0${canonical}`
}

export const HEX64 = /^[0-9a-f]{64}$/

/** Exact UTC milliseconds: the only timestamp form APS receipts and decisions
 *  admit. The round trip through Date rejects values that match the shape but
 *  are not real instants, such as a 32nd of a month. */
export function isExactUtcMilliseconds(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false
  const parsed = new Date(value)
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value
}

/** Compare two strings as arrays of Unicode code points.
 *  Not the same as the default string comparison, which orders by UTF-16 code
 *  units and therefore sorts astral characters before U+E000..U+FFFF. */
export function compareCodePoints(a: string, b: string): number {
  const aa = Array.from(a, c => c.codePointAt(0) as number)
  const bb = Array.from(b, c => c.codePointAt(0) as number)
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) if (aa[i] !== bb[i]) return aa[i] - bb[i]
  return aa.length - bb.length
}
