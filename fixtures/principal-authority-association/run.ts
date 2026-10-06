// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Runner for the principal-authority-association candidate family.
//
// CANDIDATE MATERIAL. Not wired into npm test and not a conformance run.
//
// Runs check.ts over every case in vectors.json and compares all four axes with
// the case's expected block, then holds each declared pair to the input paths it
// declares. Any mismatch, any checker exception, or any problem reading the
// vectors exits 1. In that case no report is written and no PASS line is printed.
// Only after every case and pair matches does it write the report, when
// --report <path> is given, and then print the PASS line.
//
//     npx tsx fixtures/principal-authority-association/run.ts [--report <path>]

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { checkVector, type VectorInputs } from './check.js'
import { inputDiffPaths } from './pairs.js'
import { SDK_VERSION } from './sdk.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const FAMILY = 'principal-authority-association'
const AXES = ['binding', 'root_basis', 'association', 'boundary'] as const

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2)
  const reportIdx = argv.indexOf('--report')
  const reportPath = reportIdx >= 0 ? argv[reportIdx + 1] : undefined
  if (reportIdx >= 0 && !reportPath) {
    console.error(`${FAMILY}: --report needs a path`)
    return 1
  }

  const vectorsPath = path.join(here, 'vectors.json')
  const bytes = fs.readFileSync(vectorsPath)
  const doc = JSON.parse(bytes.toString('utf8'))
  if (doc.status !== 'candidate' || doc.conformance !== false) {
    console.error(`${FAMILY}: vectors.json is not labeled candidate with conformance false`)
    return 1
  }
  const cases = doc.cases as { id: string; name: string; inputs: VectorInputs; expected: Record<string, unknown> }[]
  if (!Array.isArray(cases) || cases.length === 0) {
    console.error(`${FAMILY}: no cases`)
    return 1
  }

  let failures = 0
  const results: unknown[] = []
  for (const c of cases) {
    let actual: Record<string, unknown>
    try {
      actual = (await checkVector(c.inputs)) as unknown as Record<string, unknown>
    } catch (err) {
      failures++
      console.log(`FAIL ${c.id} ${c.name}: checker threw: ${(err as Error).message}`)
      continue
    }
    const bad = AXES.filter((axis) => canonical(actual[axis]) !== canonical(c.expected[axis]))
    if (bad.length > 0) {
      failures++
      for (const axis of bad) {
        console.log(`FAIL ${c.id} ${c.name}: ${axis}`)
        console.log(`  expected ${canonical(c.expected[axis])}`)
        console.log(`  actual   ${canonical(actual[axis])}`)
      }
      continue
    }
    const a = actual.association as { result: string; limb?: string; reason_code: string }
    const b = actual.boundary as { outcome: string; reason_code: string }
    console.log(
      `ok   ${c.id} ${c.name}: association ${a.result}${a.limb ? `/${a.limb}` : ''} ${a.reason_code}, boundary ${b.outcome} ${b.reason_code}`,
    )
    results.push({ id: c.id, name: c.name, actual })
  }

  const byId = new Map(cases.map((c) => [c.id, c]))
  const pairs = doc.pairs as { a: string; b: string; element: string; differing_paths: string[] }[]
  for (const p of pairs) {
    const ca = byId.get(p.a)
    const cb = byId.get(p.b)
    if (!ca || !cb) {
      failures++
      console.log(`FAIL pair ${p.a}/${p.b}: unknown case`)
      continue
    }
    const got = inputDiffPaths(ca.inputs, cb.inputs)
    if (canonical(got) !== canonical(p.differing_paths)) {
      failures++
      console.log(`FAIL pair ${p.a}/${p.b} (${p.element}): inputs differ at ${canonical(got)}, declared ${canonical(p.differing_paths)}`)
      continue
    }
    console.log(`ok   pair ${p.a}/${p.b}: ${p.element}, differs at ${got.join(' ')}`)
  }

  if (failures > 0) {
    console.log(`${FAMILY}: ${failures} failure(s). No report written.`)
    return 1
  }

  if (reportPath) {
    const report = {
      family: FAMILY,
      status: 'candidate',
      conformance: false,
      vectors_sha256: createHash('sha256').update(bytes).digest('hex'),
      sdk: { package: 'agent-passport-system', version: SDK_VERSION },
      node: process.version,
      cases: results,
      pairs: pairs.length,
    }
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)
    console.log(`report ${reportPath}`)
  }
  console.log(`PASS ${FAMILY} (candidate, not conformance): ${cases.length}/${cases.length} cases, ${pairs.length}/${pairs.length} pairs`)
  return 0
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`${FAMILY}: ${(err as Error).stack ?? err}`)
    process.exit(1)
  },
)
