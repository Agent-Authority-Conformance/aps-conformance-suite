// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mutation check. Each mutation breaks check.ts in one named way, in a fresh copy
// of the family, and runs the copied runner. A mutation is caught when the run
// exits nonzero with at least one failing case, writes no report and prints no
// PASS line. Every patch target must occur exactly once in check.ts, so a
// refactor that moves a target fails this script instead of silently mutating
// nothing.
//
// Exits 0 only when every mutation is caught.
//
//     npx tsx fixtures/principal-authority-association/mutation-check.ts

import { runInFreshCopy, type Patch } from './fresh-copy.js'

const MUTATIONS: { name: string; intent: string; patches: Patch[] }[] = [
  {
    name: 'conflict-as-established',
    intent: 'treat two accepted sources in conflict as established',
    patches: [
      {
        file: 'check.ts',
        find: "if (sameSeen && differentSeen) return notEstablished('source', CODES.sourcesConflict)",
        replace: 'if (sameSeen && differentSeen) return established()',
      },
    ],
  },
  {
    name: 'ignore-expiry',
    intent: 'ignore the statement expires_at',
    patches: [
      {
        file: 'check.ts',
        find: 'if (!(now < st.expires_at)) return',
        replace: 'if (false) return',
      },
    ],
  },
  {
    name: 'accept-any-signer',
    intent: 'accept any signer: skip the signer lookup, the signature and the competence check',
    patches: [
      {
        file: 'check.ts',
        find: 'function signerAccepted(statement: AssociationStatement, profile: AssociationProfile): { limb: Limb; code: string } | null {\n',
        replace:
          'function signerAccepted(statement: AssociationStatement, profile: AssociationProfile): { limb: Limb; code: string } | null {\n  return null\n',
      },
      {
        file: 'check.ts',
        find: 'function isCompetent(source: CompetentSource, inputs: VectorInputs, principal: string): boolean {\n',
        replace: 'function isCompetent(source: CompetentSource, inputs: VectorInputs, principal: string): boolean {\n  return true\n',
      },
    ],
  },
  {
    name: 'negative-as-not-established',
    intent: 'map the reached negative to not established',
    patches: [
      {
        file: 'check.ts',
        find: 'if (differentSeen) return inconsistent()',
        replace: "if (differentSeen) return notEstablished('source', CODES.differentContext)",
      },
    ],
  },
]

let missed = 0
for (const m of MUTATIONS) {
  const r = runInFreshCopy(m.name, m.patches)
  const caught = r.exitCode !== 0 && r.exitCode !== null && r.failedCases.length > 0 && !r.reportExists && !r.passLine
  if (!caught) missed++
  console.log(`${caught ? 'caught' : 'MISSED'} ${m.name} (${m.intent})`)
  console.log(`  exit ${r.exitCode}, failing ${r.failedCases.join(', ') || 'none'}, report ${r.reportExists ? 'present' : 'absent'}, PASS line ${r.passLine ? 'present' : 'absent'}`)
  if (!caught) {
    for (const line of r.stdout.trimEnd().split('\n')) console.log(`  | ${line}`)
    for (const line of r.stderr.trimEnd().split('\n')) if (line) console.log(`  ! ${line}`)
  }
}
console.log(`mutation check: ${MUTATIONS.length - missed}/${MUTATIONS.length} caught`)
process.exit(missed === 0 ? 0 : 1)
