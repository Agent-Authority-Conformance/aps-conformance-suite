// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// Corpus membership is DERIVED from index.json, never hardcoded.
//
// A hardcoded list silently skips anything it does not name: an indexed but
// invalid fourteenth vector would simply not be verified while the run still
// reported "13/13". Every membership problem is therefore a hard failure:
//
//   missing   — index.json names a file that cannot be read or parsed
//   extra     — a *.json sits in the directory but index.json does not declare it
//   duplicate — index.json declares the same id twice
//   unread    — index.json itself is unreadable, or a case is malformed
//   mismatch  — the file's own `fixture` field disagrees with the id the index
//               names it by (the index must not lie about what it points at)

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

export const INDEX_FILE = 'index.json'

export type CorpusProblemKind = 'missing' | 'extra' | 'duplicate' | 'unread' | 'mismatch'

export interface CorpusProblem {
  kind: CorpusProblemKind
  detail: string
}

export interface CorpusEntry {
  id: string
  file: string
  doc: Record<string, any>
}

export function loadCorpus(dir: string): { entries: CorpusEntry[]; problems: CorpusProblem[] } {
  const entries: CorpusEntry[] = []
  const problems: CorpusProblem[] = []

  let index: any
  try {
    index = JSON.parse(readFileSync(join(dir, INDEX_FILE), 'utf8'))
  } catch (e) {
    problems.push({ kind: 'unread', detail: `${INDEX_FILE}: ${(e as Error).message}` })
    return { entries, problems }
  }

  if (!Array.isArray(index?.cases) || index.cases.length === 0) {
    problems.push({ kind: 'unread', detail: `${INDEX_FILE}: "cases" must be a non-empty array` })
    return { entries, problems }
  }

  const declaredFiles = new Set<string>()
  const fileById = new Map<string, string>()

  for (const [i, c] of (index.cases as any[]).entries()) {
    const id = typeof c?.id === 'string' ? c.id : ''
    const file = typeof c?.file === 'string' ? c.file : ''
    if (!id || !file) {
      problems.push({ kind: 'unread', detail: `cases[${i}]: each case needs a string "id" and "file"` })
      continue
    }
    if (fileById.has(id)) {
      problems.push({ kind: 'duplicate', detail: `id "${id}" declared by both ${fileById.get(id)} and ${file}` })
      continue
    }
    fileById.set(id, file)
    declaredFiles.add(file)

    let doc: any
    try {
      doc = JSON.parse(readFileSync(join(dir, file), 'utf8'))
    } catch (e) {
      problems.push({ kind: 'missing', detail: `${file} (declared for id "${id}"): ${(e as Error).message}` })
      continue
    }
    if (doc?.fixture !== id) {
      problems.push({
        kind: 'mismatch',
        detail: `${file} declares fixture "${String(doc?.fixture)}" but ${INDEX_FILE} names it "${id}"`,
      })
      continue
    }
    entries.push({ id, file, doc })
  }

  let onDisk: string[] = []
  try {
    onDisk = readdirSync(dir).filter((f) => f.endsWith('.json') && f !== INDEX_FILE)
  } catch (e) {
    problems.push({ kind: 'unread', detail: `cannot list ${dir}: ${(e as Error).message}` })
  }
  for (const f of onDisk.sort()) {
    if (!declaredFiles.has(f)) {
      problems.push({ kind: 'extra', detail: `${f} is present but not declared in ${INDEX_FILE}` })
    }
  }

  return { entries, problems }
}
