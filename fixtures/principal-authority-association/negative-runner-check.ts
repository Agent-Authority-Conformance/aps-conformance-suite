// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Negative runner check. A runner that cannot fail proves nothing, so this runs
// the family twice, each time in its own fresh directory:
//
//   control   the copy unchanged. Expect exit 0, a report, and a PASS line.
//   forced    checkVector throws on entry. Expect a nonzero exit, no report,
//             and no PASS line.
//
// Exits 0 only when both hold.
//
//     npx tsx fixtures/principal-authority-association/negative-runner-check.ts

import { runInFreshCopy, type FreshRun } from './fresh-copy.js'

function show(label: string, r: FreshRun): void {
  console.log(`${label}: dir ${r.dir}`)
  console.log(`${label}: exit ${r.exitCode}, report ${r.reportExists ? 'present' : 'absent'}, PASS line ${r.passLine ? 'present' : 'absent'}`)
  for (const line of r.stdout.trimEnd().split('\n')) console.log(`  | ${line}`)
  if (r.stderr.trim()) for (const line of r.stderr.trimEnd().split('\n')) console.log(`  ! ${line}`)
}

const control = runInFreshCopy('control')
show('control', control)
const controlOk = control.exitCode === 0 && control.reportExists && control.passLine

const forced = runInFreshCopy('forced', [
  {
    file: 'check.ts',
    find: 'export async function checkVector(inputs: VectorInputs): Promise<CheckResult> {\n',
    replace:
      'export async function checkVector(inputs: VectorInputs): Promise<CheckResult> {\n  throw new Error(\'forced checker failure\')\n',
  },
])
show('forced', forced)
const forcedOk = forced.exitCode !== 0 && forced.exitCode !== null && !forced.reportExists && !forced.passLine

console.log(`negative runner check: control ${controlOk ? 'as expected' : 'NOT as expected'}, forced failure ${forcedOk ? 'as expected' : 'NOT as expected'}`)
process.exit(controlOk && forcedOk ? 0 : 1)
