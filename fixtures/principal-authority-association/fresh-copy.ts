// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Shared by negative-runner-check.ts and mutation-check.ts. Copies this family
// and the suite's package.json into a fresh temporary directory, links the
// suite's installed node_modules next to it, optionally applies exact text replacements to one file of the
// copy, and runs the copied runner there with --report pointing into the same
// fresh directory.

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const suiteRoot = path.resolve(here, '..', '..')
const FAMILY_DIR = path.join('fixtures', 'principal-authority-association')

export interface Patch {
  file: string
  find: string
  replace: string
}

export interface FreshRun {
  dir: string
  exitCode: number | null
  stdout: string
  stderr: string
  reportExists: boolean
  passLine: boolean
  failedCases: string[]
}

export function runInFreshCopy(label: string, patches: Patch[] = []): FreshRun {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `paa-${label}-`))
  const family = path.join(dir, FAMILY_DIR)
  fs.mkdirSync(path.dirname(family), { recursive: true })
  fs.cpSync(here, family, { recursive: true })
  // The suite's package.json carries "type": "module", which the .ts files need.
  fs.copyFileSync(path.join(suiteRoot, 'package.json'), path.join(dir, 'package.json'))
  fs.symlinkSync(fs.realpathSync(path.join(suiteRoot, 'node_modules')), path.join(dir, 'node_modules'))

  for (const p of patches) {
    const target = path.join(family, p.file)
    const text = fs.readFileSync(target, 'utf8')
    const count = text.split(p.find).length - 1
    if (count !== 1) throw new Error(`${label}: patch target found ${count} times in ${p.file}, expected exactly 1: ${p.find}`)
    fs.writeFileSync(target, text.replace(p.find, p.replace))
  }

  const reportPath = path.join(dir, 'report.json')
  const tsxCli = path.join(dir, 'node_modules', 'tsx', 'dist', 'cli.mjs')
  const r = spawnSync(process.execPath, [tsxCli, path.join(family, 'run.ts'), '--report', reportPath], {
    cwd: dir,
    encoding: 'utf8',
  })
  const stdout = r.stdout ?? ''
  return {
    dir,
    exitCode: r.status,
    stdout,
    stderr: r.stderr ?? '',
    reportExists: fs.existsSync(reportPath),
    passLine: stdout.split('\n').some((line) => line.startsWith('PASS')),
    failedCases: [...new Set(stdout.split('\n').flatMap((line) => {
      const m = /^FAIL (PAA-\d+|pair \S+)/.exec(line)
      return m ? [m[1]] : []
    }))],
  }
}
