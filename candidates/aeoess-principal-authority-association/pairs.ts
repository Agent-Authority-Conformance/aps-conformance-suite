// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Lists every JSON Pointer at which two vectors' inputs differ. A member present
// on one side only is reported at its own path and not descended into. The
// generator and the runner both use it to hold each declared pair to the one
// element the README says it changes.

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function walk(a: unknown, b: unknown, at: string, out: string[]): void {
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if (i >= a.length || i >= b.length) out.push(`${at}/${i}`)
      else walk(a[i], b[i], `${at}/${i}`, out)
    }
    return
  }
  if (isObject(a) && isObject(b)) {
    for (const k of [...new Set([...Object.keys(a), ...Object.keys(b)])]) {
      const p = `${at}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`
      if (!(k in a) || !(k in b)) out.push(p)
      else walk(a[k], b[k], p, out)
    }
    return
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) out.push(at)
}

export function inputDiffPaths(a: unknown, b: unknown): string[] {
  const out: string[] = []
  walk(a, b, '', out)
  return out.sort()
}
