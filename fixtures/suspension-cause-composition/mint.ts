// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Mints chain.json for the suspension-cause-composition fixture, byte for byte.
//
// Keys are Ed25519 seeds derived from the published labels below, so the file
// carries no secret material and anyone can regenerate it. The seed convention
// is the one docs/fixture-format.md records for this suite:
//
//   seed = SHA-256("aps-conformance-suite:scc:" + label)
//
// What this mints, and why each artifact exists:
//
//   GRANT        one-hop principal -> agent AuthorityDelegationV1, valid window
//                open over every evaluation instant in vectors.json. Three
//                concurrent lifecycle causes attach to this grant.
//   GRANT_CLEAN  the same shape with a different nonce and no cause attached.
//                CR-02 presents it as the positive control, so a run that fails
//                every other case still shows the chain, the keys, the
//                signatures and the time facet are sound.
//   three causes fixture-local records, record_type
//                "fixture:lifecycle-cause:v0". Two of kind suspension, one of
//                kind restriction. NOT an APS record type and no SDK claims it.
//   eleven
//   releases     fixture-local records, record_type
//                "fixture:cause-release:v0", each naming one or more cause ids.
//                Also not an APS record type.
//
// Neither reference SDK has an API for a suspension cause, a restriction, a
// release or lifecycle standing. draft-pidlisnyi-aps-03 does not define any of
// them either: its RevocationResolution is exactly 'active' | 'revoked' |
// 'unknown'. So everything in this file past the two AuthorityDelegationV1
// records is supplied by the fixture. README.md says so at length.
//
// Every fixture-local record is canonicalized under RFC 8785 with the SDK's own
// canonicalizeJCS and signed with the SDK's own Ed25519 primitive, so both
// runners rebuild the same preimage bytes.
//
// Run from the suite root with the pinned SDK installed:
//
//     npx tsx fixtures/suspension-cause-composition/mint.ts
//
// Then `git diff` on chain.json should be empty.

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  canonicalizeJCS,
  issueAuthorityDelegation,
  publicKeyFromPrivate,
  sign,
  verify,
  verifyAuthorityDelegationChain,
} from 'agent-passport-system'

const here = path.dirname(fileURLToPath(import.meta.url))

// One clock for the whole family. Every evaluation instant, every imposition
// and every release timestamp is one of these entries, and every vector names
// its instant by label rather than by literal.
const CLOCK = {
  T_GRANT_ISSUED: '2026-09-20T08:00:00.000Z',
  T_IMPOSED: '2026-09-20T09:00:00.000Z',
  T_REVOCATION_RECORDED: '2026-09-20T10:00:00.000Z',
  T_RELEASE_REG: '2026-09-20T11:00:00.000Z',
  T_RELEASE_FIRM: '2026-09-20T11:30:00.000Z',
  T_RELEASE_DECREE: '2026-09-20T12:00:00.000Z',
  T_EVAL: '2026-09-20T13:00:00.000Z',
  T_LATE_RELEASE: '2026-09-20T14:00:00.000Z',
  T_LATER_EVAL: '2026-09-20T15:00:00.000Z',
  T_GRANT_NOT_AFTER: '2026-09-22T00:00:00.000Z',
}

const PRINCIPAL = 'did:aps:example:scc-principal'
const AGENT = 'did:aps:example:scc-agent'
const REGULATOR = 'did:aps:example:scc-regulator'
const FIRM = 'did:aps:example:scc-firm-compliance'
const COURT = 'did:aps:example:scc-court'

const CAUSE_ID = {
  REG: 'scc-cause-reg-suspension',
  FIRM: 'scc-cause-firm-investigation',
  DECREE: 'scc-cause-decree-gate',
}

const CAUSE_ID_NOT_ON_GRANT = 'scc-cause-not-on-this-grant'

function seed(label: string): string {
  return createHash('sha256').update(`aps-conformance-suite:scc:${label}`).digest('hex')
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function authorityVector(notBefore: string, notAfter: string) {
  return {
    scope: { profile: 'aps-hierarchical-v1' as const, grants: ['ledger:post'] },
    spend: { mode: 'unbounded' as const },
    depth: { remaining: 0 },
    time: { not_before: notBefore, not_after: notAfter },
    reputation: { profile: 'aps-score-0-100-v1' as const, ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1' as const, required: [] },
    reversibility: { profile: 'aps-tci-v1' as const, ceiling: 'irreversible' as const },
  }
}

type CauseBody = {
  record_type: 'fixture:lifecycle-cause:v0'
  version: '0.1'
  cause_id: string
  cause_kind: 'suspension' | 'restriction'
  grant_delegation_id: string
  imposed_at: string
  imposed_by: string
  nonce: string
  reason_code: string
  record_id_note: string
  verification_method: string
}

type ReleaseBody = {
  record_type: 'fixture:cause-release:v0'
  version: '0.1'
  grant_delegation_id: string
  nonce: string
  record_id_note: string
  released_at: string
  released_causes: string[]
  releaser: string
  verification_method: string
}

const RECORD_ID_NOTE =
  'record_id is SHA-256 over the RFC 8785 canonical bytes of this body, with no record_id or signature member present.'

function mintSigned<T extends Record<string, unknown>>(body: T, signingPrivateKey: string) {
  const preimage = canonicalizeJCS(body)
  return {
    ...body,
    record_id: sha256Hex(preimage),
    signature: sign(preimage, signingPrivateKey),
  }
}

function main(): void {
  const principalPriv = seed('principal:v1')
  const agentPriv = seed('agent:v1')
  const regulatorPriv = seed('regulator:v1')
  const firmPriv = seed('firm-compliance:v1')
  const courtPriv = seed('court:v1')

  const verificationKeys: Record<string, string> = {
    [`${PRINCIPAL}#key-1`]: publicKeyFromPrivate(principalPriv),
    // The agent never issues a further delegation here (depth.remaining is 0),
    // so no chain verification resolves this key. It is published so the file
    // states, rather than implies, that the subject has one identity.
    [`${AGENT}#key-1`]: publicKeyFromPrivate(agentPriv),
    [`${REGULATOR}#key-1`]: publicKeyFromPrivate(regulatorPriv),
    [`${FIRM}#key-1`]: publicKeyFromPrivate(firmPriv),
    [`${COURT}#key-1`]: publicKeyFromPrivate(courtPriv),
  }

  const grant = issueAuthorityDelegation(
    {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: null,
      issuer: PRINCIPAL,
      subject: AGENT,
      verification_method: `${PRINCIPAL}#key-1`,
      issued_at: CLOCK.T_GRANT_ISSUED,
      nonce: seed('grant-nonce:v1').slice(0, 32),
      authority: authorityVector(CLOCK.T_GRANT_ISSUED, CLOCK.T_GRANT_NOT_AFTER),
    },
    principalPriv,
  )

  const grantClean = issueAuthorityDelegation(
    {
      record_type: 'aps:authority-delegation:v1',
      version: '1.0',
      parent_delegation_id: null,
      issuer: PRINCIPAL,
      subject: AGENT,
      verification_method: `${PRINCIPAL}#key-1`,
      issued_at: CLOCK.T_GRANT_ISSUED,
      nonce: seed('grant-clean-nonce:v1').slice(0, 32),
      authority: authorityVector(CLOCK.T_GRANT_ISSUED, CLOCK.T_GRANT_NOT_AFTER),
    },
    principalPriv,
  )

  function cause(
    label: string,
    causeId: string,
    kind: 'suspension' | 'restriction',
    imposedBy: string,
    reasonCode: string,
    signingKey: string,
  ) {
    const body: CauseBody = {
      record_type: 'fixture:lifecycle-cause:v0',
      version: '0.1',
      cause_id: causeId,
      cause_kind: kind,
      grant_delegation_id: grant.delegation_id,
      imposed_at: CLOCK.T_IMPOSED,
      imposed_by: imposedBy,
      nonce: seed(`${label}-nonce:v1`).slice(0, 32),
      reason_code: reasonCode,
      record_id_note: RECORD_ID_NOTE,
      verification_method: `${imposedBy}#key-1`,
    }
    return mintSigned(body as unknown as Record<string, unknown>, signingKey)
  }

  // Three concurrent causes on one grant, from three different sources. Two are
  // of kind suspension and one of kind restriction, which is the distinction
  // L8 of the proposed text draws and the reason the family has two
  // non-exercisable verdict names rather than one.
  const causes = {
    REG: cause('cause-reg', CAUSE_ID.REG, 'suspension', REGULATOR, 'regulatory_suspension', regulatorPriv),
    FIRM: cause('cause-firm', CAUSE_ID.FIRM, 'suspension', FIRM, 'internal_investigation', firmPriv),
    DECREE: cause('cause-decree', CAUSE_ID.DECREE, 'restriction', COURT, 'external_approval_gate', courtPriv),
  }

  function release(
    label: string,
    releaser: string,
    releasedCauses: string[],
    releasedAt: string,
    signingKey: string,
  ) {
    const body: ReleaseBody = {
      record_type: 'fixture:cause-release:v0',
      version: '0.1',
      grant_delegation_id: grant.delegation_id,
      nonce: seed(`${label}-nonce:v1`).slice(0, 32),
      record_id_note: RECORD_ID_NOTE,
      released_at: releasedAt,
      released_causes: releasedCauses,
      releaser,
      verification_method: `${releaser}#key-1`,
    }
    return mintSigned(body as unknown as Record<string, unknown>, signingKey)
  }

  const releases = {
    // Each cause released by the source that imposed it. These three together
    // are the only way to reach exercisable on GRANT in this family.
    REL_REG_BY_REGULATOR: release(
      'rel-reg-by-regulator',
      REGULATOR,
      [CAUSE_ID.REG],
      CLOCK.T_RELEASE_REG,
      regulatorPriv,
    ),
    REL_FIRM_BY_FIRM: release('rel-firm-by-firm', FIRM, [CAUSE_ID.FIRM], CLOCK.T_RELEASE_FIRM, firmPriv),
    REL_DECREE_BY_COURT: release(
      'rel-decree-by-court',
      COURT,
      [CAUSE_ID.DECREE],
      CLOCK.T_RELEASE_DECREE,
      courtPriv,
    ),
    // The negative control. A genuine, correctly signed release from a real
    // source naming a real cause on this grant. Nothing inside the record is
    // wrong. Only the standing registry says the regulator holds no standing
    // over the firm's own cause.
    REL_FIRM_BY_REGULATOR: release(
      'rel-firm-by-regulator',
      REGULATOR,
      [CAUSE_ID.FIRM],
      CLOCK.T_RELEASE_FIRM,
      regulatorPriv,
    ),
    // Standing is not authorship. The court did not impose the regulator's
    // cause and had no part in it, and the standing registry still places it
    // over that cause.
    REL_REG_BY_COURT: release('rel-reg-by-court', COURT, [CAUSE_ID.REG], CLOCK.T_RELEASE_REG, courtPriv),
    // One record, two causes, standing over both.
    REL_REG_DECREE_BY_COURT: release(
      'rel-reg-decree-by-court',
      COURT,
      [CAUSE_ID.REG, CAUSE_ID.DECREE],
      CLOCK.T_RELEASE_DECREE,
      courtPriv,
    ),
    // One record, three causes, standing over two of them. The third stays.
    REL_ALL_THREE_BY_COURT: release(
      'rel-all-three-by-court',
      COURT,
      [CAUSE_ID.REG, CAUSE_ID.FIRM, CAUSE_ID.DECREE],
      CLOCK.T_RELEASE_DECREE,
      courtPriv,
    ),
    // A body that names the regulator and the regulator's verification method,
    // signed with the firm's private key. The signature does not verify under
    // the key the body points at.
    REL_REG_FORGED: release('rel-reg-forged', REGULATOR, [CAUSE_ID.REG], CLOCK.T_RELEASE_REG, firmPriv),
    // Names a cause id that is not on this grant at all.
    REL_UNKNOWN_CAUSE: release(
      'rel-unknown-cause',
      COURT,
      [CAUSE_ID_NOT_ON_GRANT],
      CLOCK.T_RELEASE_DECREE,
      courtPriv,
    ),
    // Released before the cause it names was imposed.
    REL_FIRM_EARLY: release('rel-firm-early', FIRM, [CAUSE_ID.FIRM], CLOCK.T_GRANT_ISSUED, firmPriv),
    // Released after T_EVAL and before T_LATER_EVAL. CR-15 and CR-16 present it
    // at each instant.
    REL_DECREE_LATE: release(
      'rel-decree-late',
      COURT,
      [CAUSE_ID.DECREE],
      CLOCK.T_LATE_RELEASE,
      courtPriv,
    ),
  }

  // Mint-time assertions. If any fails, chain.json is not written, so a broken
  // fixture cannot be committed silently.
  const resolveKey = (_issuer: string, method: string) => verificationKeys[method] ?? null
  const assertions: Array<[string, boolean]> = []

  for (const [label, instant] of [
    ['T_EVAL', CLOCK.T_EVAL],
    ['T_LATER_EVAL', CLOCK.T_LATER_EVAL],
  ] as const) {
    for (const [name, chain] of [
      ['GRANT', grant],
      ['GRANT_CLEAN', grantClean],
    ] as const) {
      const result = verifyAuthorityDelegationChain([chain], {
        now: instant,
        resolveVerificationKey: resolveKey as never,
        trustRoot: () => true,
        resolveRevocation: () => 'active',
      })
      assertions.push([`${name} verifies valid at ${label} with an active resolver`, result.state === 'valid'])
    }
  }

  const revokedAtEval = verifyAuthorityDelegationChain([grant], {
    now: CLOCK.T_EVAL,
    resolveVerificationKey: resolveKey as never,
    trustRoot: () => true,
    resolveRevocation: () => 'revoked',
  })
  assertions.push([
    'GRANT verifies invalid/REVOKED at T_EVAL with a revoked resolver',
    revokedAtEval.state === 'invalid' && revokedAtEval.failures[0]?.code === 'REVOKED',
  ])

  const unknownAtEval = verifyAuthorityDelegationChain([grant], {
    now: CLOCK.T_EVAL,
    resolveVerificationKey: resolveKey as never,
    trustRoot: () => true,
    resolveRevocation: () => 'unknown',
  })
  assertions.push([
    'GRANT verifies indeterminate/REVOCATION_UNKNOWN at T_EVAL with an unknown resolver',
    unknownAtEval.state === 'indeterminate' && unknownAtEval.failures[0]?.code === 'REVOCATION_UNKNOWN',
  ])

  assertions.push([
    'GRANT and GRANT_CLEAN have distinct delegation ids',
    grant.delegation_id !== grantClean.delegation_id,
  ])

  const allRecords = [...Object.values(causes), ...Object.values(releases)]
  const ids = allRecords.map(r => r.record_id)
  assertions.push(['every fixture record has a distinct record_id', new Set(ids).size === ids.length])

  for (const [label, record] of [...Object.entries(causes), ...Object.entries(releases)]) {
    const { record_id: recordId, signature, ...body } = record as Record<string, unknown> & {
      record_id: string
      signature: string
      verification_method: string
    }
    const preimage = canonicalizeJCS(body)
    assertions.push([`${label} record_id recomputes from its body`, sha256Hex(preimage) === recordId])
    const signatureVerifies = verify(preimage, signature, verificationKeys[record.verification_method])
    const shouldVerify = label !== 'REL_REG_FORGED'
    assertions.push([
      `${label} signature verifies under its own verification_method: expected ${shouldVerify}`,
      signatureVerifies === shouldVerify,
    ])
  }

  // Timeline assertions. The revocation this family cares about is recorded
  // after every cause was imposed and before any release, which is what makes
  // CR-12 a revocation that happened during the suspension rather than one that
  // happened before it or after the last release.
  assertions.push([
    'every cause is imposed at T_IMPOSED',
    Object.values(causes).every(c => c.imposed_at === CLOCK.T_IMPOSED),
  ])
  assertions.push([
    'the revocation instant is after every imposition',
    CLOCK.T_REVOCATION_RECORDED > CLOCK.T_IMPOSED,
  ])
  assertions.push([
    'the revocation instant is before the earliest release used by CR-12',
    CLOCK.T_REVOCATION_RECORDED < CLOCK.T_RELEASE_REG,
  ])
  assertions.push([
    'REL_DECREE_LATE is released after T_EVAL and at or before T_LATER_EVAL',
    releases.REL_DECREE_LATE.released_at > CLOCK.T_EVAL &&
      releases.REL_DECREE_LATE.released_at <= CLOCK.T_LATER_EVAL,
  ])
  assertions.push([
    'REL_FIRM_EARLY is released before the cause it names was imposed',
    releases.REL_FIRM_EARLY.released_at < causes.FIRM.imposed_at,
  ])

  const failed = assertions.filter(([, ok]) => !ok)
  if (failed.length > 0) {
    for (const [name] of failed) console.error(`MINT ASSERTION FAILED: ${name}`)
    process.exit(2)
  }

  const fixture = {
    _note:
      'Generated by fixtures/suspension-cause-composition/mint.ts. Do not hand-edit: every signature and id here recomputes from the published seed labels.',
    sdk: {
      npm_package: 'agent-passport-system',
      npm_version: '7.1.0',
      note: 'The two AuthorityDelegationV1 records, every RFC 8785 canonicalization and every Ed25519 signature here were produced by this package. The cause records, the release records, the cause-standing registry and the verdict names are supplied by this fixture, not by the SDK.',
    },
    seed_convention: 'sha256("aps-conformance-suite:scc:" + label)',
    seed_labels: [
      'principal:v1',
      'agent:v1',
      'regulator:v1',
      'firm-compliance:v1',
      'court:v1',
      'grant-nonce:v1',
      'grant-clean-nonce:v1',
      'cause-reg-nonce:v1',
      'cause-firm-nonce:v1',
      'cause-decree-nonce:v1',
      'rel-reg-by-regulator-nonce:v1',
      'rel-firm-by-firm-nonce:v1',
      'rel-decree-by-court-nonce:v1',
      'rel-firm-by-regulator-nonce:v1',
      'rel-reg-by-court-nonce:v1',
      'rel-reg-decree-by-court-nonce:v1',
      'rel-all-three-by-court-nonce:v1',
      'rel-reg-forged-nonce:v1',
      'rel-unknown-cause-nonce:v1',
      'rel-firm-early-nonce:v1',
      'rel-decree-late-nonce:v1',
    ],
    clock: CLOCK,
    verification_keys: verificationKeys,
    // Which sources hold lifecycle standing over which cause. This registry is
    // the fixture's own modelling choice: the proposed text names lifecycle
    // standing as a concept and does not say where standing comes from or who
    // publishes it. README records that as a finding, not as settled text.
    //
    // REG is listed for the court as well as the regulator that imposed it.
    // That entry is the whole of the superior-source case: standing is not the
    // same thing as authorship.
    cause_standing: {
      REG: [REGULATOR, COURT],
      FIRM: [FIRM],
      DECREE: [COURT],
    },
    cause_sets: {
      GRANT: ['REG', 'FIRM', 'DECREE'],
      GRANT_CLEAN: [],
    },
    // Descriptive only. The revocation a vector sees is the resolver answer the
    // vector supplies, exactly as in fixtures/sponsor-handover. This object
    // exists so CR-12's structural check can state, from the file rather than
    // from prose, that the revocation instant falls inside the suspension
    // window. It is not a revocation record and it is not signed.
    revocation_timeline_note: {
      note: 'Descriptive timeline entry, not a revocation record and not evidence that any revocation occurred. CR-12 supplies the revocation as a resolver answer and uses recorded_at only for its structural window check.',
      grant_delegation_id: grant.delegation_id,
      recorded_at: CLOCK.T_REVOCATION_RECORDED,
    },
    roles: {
      PRINCIPAL_TO_AGENT: grant.delegation_id,
      PRINCIPAL_TO_AGENT_CLEAN: grantClean.delegation_id,
    },
    chains: {
      GRANT: [grant],
      GRANT_CLEAN: [grantClean],
    },
    causes,
    releases,
  }

  fs.writeFileSync(path.join(here, 'chain.json'), JSON.stringify(fixture, null, 2) + '\n', 'utf8')
  console.log(
    `suspension-cause-composition mint: ${assertions.length} mint-time assertions passed, chain.json written`,
  )
}

main()
