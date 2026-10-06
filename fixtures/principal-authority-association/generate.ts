// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Deterministic generator for the principal-authority-association candidate family.
//
// CANDIDATE MATERIAL. Not part of fixtures/manifest.json, not run by npm test.
//
// Every Ed25519 private key is SHA-256 over `${SEED_PREFIX}:${label}` for the
// labels in KEY_LABELS below, every nonce is derived the same way, and every
// timestamp is pinned, so a second run rewrites vectors.json byte for byte. The
// keys are test keys published by this file. No secret material is involved.
//
// The expected block of each case is written out by hand in CASES below. It is
// not computed by check.ts, so the runner compares two separately written
// statements of the result. Both are by the same author.
//
// Run from the suite root:
//
//     npx tsx fixtures/principal-authority-association/generate.ts

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  issueAuthorityDelegation,
  issuePrincipalBindingV1,
  publicKeyFromPrivate,
  sign,
  verifyAuthorityDelegationChain,
  verifyPrincipalBindingV1,
  PRINCIPAL_BINDING_MODULE,
  SDK_VERSION,
  type AuthorityDelegationBodyV1,
} from './sdk.js'
import {
  CODES,
  PROFILE_TYPE,
  SIGNATURE_DOMAIN,
  STATEMENT_TYPE,
  statementSigningInput,
  type AssociationProfile,
  type AssociationStatement,
  type Relation,
  type VectorInputs,
} from './check.js'
import { inputDiffPaths } from './pairs.js'

const here = path.dirname(fileURLToPath(import.meta.url))

const SEED_PREFIX = 'aps-conformance-suite:principal-authority-association'
const KEY_LABELS = {
  principal: 'principal:v1',
  agent: 'agent:v1',
  root_authority: 'root-authority:v1',
  registry_a: 'registry-a:v1',
  registry_b: 'registry-b:v1',
  registry_hr: 'registry-hr:v1',
} as const

const GENERATED_AT = '2026-10-06'

const PRINCIPAL = 'did:aps:example:paa-principal'
const AGENT = 'did:aps:example:paa-agent'
const ROOT_AUTHORITY = 'did:aps:example:paa-root-authority'
const REGISTRY_A = 'did:aps:example:paa-registry-a'
const REGISTRY_B = 'did:aps:example:paa-registry-b'
const REGISTRY_HR = 'did:aps:example:paa-registry-hr'

const AUDIENCE = 'https://rp.example/payments'
const SCOPE = 'payments:refund'
const DOMAIN = 'payments.example'
const OTHER_DOMAIN = 'hr.example'

const BINDING_ISSUED_AT = '2026-10-01T00:00:00.000Z'
const BINDING_EXPIRES_AT = '2027-01-01T00:00:00.000Z'
const ROOT_ISSUED_AT = '2026-10-01T00:00:00.000Z'
const ROOT_NOT_AFTER = '2027-01-01T00:00:00.000Z'
const STATEMENT_ISSUED_AT = '2026-10-02T00:00:00.000Z'
const STATEMENT_EXPIRES_AT = '2026-10-20T00:00:00.000Z'
const EVALUATION_INSTANT = '2026-10-06T12:00:00.000Z'
const EVALUATION_INSTANT_PAST_EXPIRY = '2026-10-21T12:00:00.000Z'

function seed(label: string): string {
  return createHash('sha256').update(`${SEED_PREFIX}:${label}`).digest('hex')
}

function fail(message: string): never {
  console.error(`principal-authority-association generate: ${message}`)
  process.exit(2)
}

const priv = Object.fromEntries(Object.entries(KEY_LABELS).map(([k, label]) => [k, seed(label)])) as Record<
  keyof typeof KEY_LABELS,
  string
>
const pub = Object.fromEntries(Object.entries(priv).map(([k, p]) => [k, publicKeyFromPrivate(p)])) as Record<
  keyof typeof KEY_LABELS,
  string
>

const binding = issuePrincipalBindingV1({
  agent_id: AGENT,
  principal_id: PRINCIPAL,
  verification_method: `${PRINCIPAL}#key-1`,
  audiences: [AUDIENCE],
  authority_profiles: ['aps:authority-delegation:v1'],
  status_uri: 'https://status.example/paa/principal-bindings',
  issued_at: BINDING_ISSUED_AT,
  expires_at: BINDING_EXPIRES_AT,
  nonce: seed('nonce:binding').slice(0, 32),
  principal_private_key_hex: priv.principal,
})

const rootBody: AuthorityDelegationBodyV1 = {
  record_type: 'aps:authority-delegation:v1',
  version: '1.0',
  parent_delegation_id: null,
  issuer: ROOT_AUTHORITY,
  subject: AGENT,
  verification_method: `${ROOT_AUTHORITY}#key-1`,
  issued_at: ROOT_ISSUED_AT,
  nonce: seed('nonce:root').slice(0, 32),
  authority: {
    scope: { profile: 'aps-hierarchical-v1', grants: [SCOPE] },
    spend: { mode: 'unbounded' },
    depth: { remaining: 0 },
    time: { not_before: ROOT_ISSUED_AT, not_after: ROOT_NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1', required: [] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'irreversible' },
  },
}
const root = issueAuthorityDelegation(rootBody, priv.root_authority)

const profile: AssociationProfile = {
  type: PROFILE_TYPE,
  profile_id: 'x-fixture:principal-authority-association-profile:v0',
  competent_sources: [
    {
      source_id: REGISTRY_A,
      verification_key_hex: pub.registry_a,
      competent_for: { principals: [PRINCIPAL], scopes: [SCOPE], domains: [DOMAIN] },
    },
    {
      source_id: REGISTRY_B,
      verification_key_hex: pub.registry_b,
      competent_for: { principals: [PRINCIPAL], scopes: [SCOPE], domains: [DOMAIN] },
    },
    {
      source_id: REGISTRY_HR,
      verification_key_hex: pub.registry_hr,
      competent_for: { principals: [PRINCIPAL], scopes: [SCOPE], domains: [OTHER_DOMAIN] },
    },
  ],
}

function statement(relation: Relation, source: 'registry_a' | 'registry_b' | 'registry_hr'): AssociationStatement {
  const sourceId = { registry_a: REGISTRY_A, registry_b: REGISTRY_B, registry_hr: REGISTRY_HR }[source]
  const body = {
    type: STATEMENT_TYPE,
    principal_ref: PRINCIPAL,
    root_ref: root.delegation_id,
    relation,
    source_id: sourceId,
    issued_at: STATEMENT_ISSUED_AT,
    expires_at: STATEMENT_EXPIRES_AT,
  } as const
  return { ...body, signature: sign(statementSigningInput(body), priv[source]) }
}

function inputs(evidence: AssociationStatement[], evaluationInstant = EVALUATION_INSTANT): VectorInputs {
  return {
    evaluation_instant: evaluationInstant,
    context: { audience: AUDIENCE, scope: SCOPE, domain: DOMAIN },
    principal_binding: binding,
    root_delegation: root,
    association_evidence: evidence,
    trust_anchors: {
      root_issuers: [ROOT_AUTHORITY],
      verification_keys: {
        [`${PRINCIPAL}#key-1`]: pub.principal,
        [`${ROOT_AUTHORITY}#key-1`]: pub.root_authority,
      },
    },
    revocation_state: {
      source: 'fixture-supplied: every delegation is active. Revocation is not what this family tests.',
      every_delegation: 'active',
    },
    association_profile: profile,
  }
}

const ACCEPTED = {
  binding: { result: 'accepted', sdk_state: 'valid', sdk_code: 'OK' },
  root_basis: { result: 'accepted', sdk_state: 'valid', sdk_failures: [] as string[] },
}

const BOUNDARY_NOT_ESTABLISHED = {
  outcome: 'not_established',
  reason_code: CODES.boundaryNotEstablished,
  authorized_for_named_principal: false,
}

const CASES = [
  {
    id: 'PAA-1',
    name: 'missing',
    description: 'No association evidence is presented. The binding and the root each verify.',
    inputs: inputs([]),
    expected: {
      ...ACCEPTED,
      association: { result: 'not_established', limb: 'source', reason_code: CODES.notPresented, aps_04_defined_shape: true },
      boundary: BOUNDARY_NOT_ESTABLISHED,
    },
    defined_by: 'aps-04',
    citations: ['aps-04 19.2.10 lines 11317-11324', 'aps-04 2.3 lines 717-724', 'aps-04 lines 3726-3738'],
    notes: [
      'Not established is the evidential verdict of -04 lines 3726-3731: a source is missing.',
      'The boundary does not report the action as taken for the principal the chain names (-04 19.2.10, lines 11322-11324).',
    ],
  },
  {
    id: 'PAA-2',
    name: 'wrong-source',
    description:
      'One statement says same_authority_context. Its signer is in the profile and its signature verifies, but the profile makes that signer competent for domain hr.example, not payments.example.',
    inputs: inputs([statement('same_authority_context', 'registry_hr')]),
    expected: {
      ...ACCEPTED,
      association: { result: 'not_established', limb: 'source', reason_code: CODES.sourceNotCompetent, aps_04_defined_shape: true },
      boundary: BOUNDARY_NOT_ESTABLISHED,
    },
    defined_by: 'aps-04',
    citations: ['aps-04 2.3 lines 719-721', 'aps-04 lines 3726-3730', 'AIN-WRP 7.3', 'AIN-WRP B.7'],
    notes: [
      'An answer from a source the model does not accept for that state names the source limb (-04 lines 719-721).',
      'AIN-WRP 7.3 and B.7 make competence depend on principal, scope and domain. Here the domain is what fails.',
      'A statement signed by the agent itself would stop one check earlier, as an unrecognized source. No vector exercises that.',
    ],
  },
  {
    id: 'PAA-3',
    name: 'stale',
    description:
      'A competent source said same_authority_context, but the evaluation instant is past the statement expires_at. The binding and the root are still current at that instant.',
    inputs: inputs([statement('same_authority_context', 'registry_a')], EVALUATION_INSTANT_PAST_EXPIRY),
    expected: {
      ...ACCEPTED,
      association: { result: 'not_established', limb: 'freshness', reason_code: CODES.expired, aps_04_defined_shape: true },
      boundary: BOUNDARY_NOT_ESTABLISHED,
    },
    defined_by: 'aps-04',
    citations: ['aps-04 2.3 lines 721-723', 'aps-04 lines 3726-3729'],
    notes: ['Freshness: an answer existed but was older than the bound declared for its source (-04 lines 721-723).'],
  },
  {
    id: 'PAA-4',
    name: 'conflict',
    description: 'Two competent, fresh sources disagree. Registry A says same_authority_context, registry B says different_authority_context.',
    inputs: inputs([statement('same_authority_context', 'registry_a'), statement('different_authority_context', 'registry_b')]),
    expected: {
      ...ACCEPTED,
      association: { result: 'not_established', limb: 'source', reason_code: CODES.sourcesConflict, aps_04_defined_shape: true },
      boundary: BOUNDARY_NOT_ESTABLISHED,
    },
    defined_by: 'aps-04',
    citations: ['aps-04 2.3 lines 720-721', 'aps-04 lines 3729-3730'],
    notes: [
      'Two accepted sources in unresolved conflict name the source limb (-04 lines 720-721).',
      'The profile ranks no source above another, so neither statement is discarded.',
    ],
  },
  {
    id: 'PAA-5',
    name: 'shown-wrong',
    description: 'One competent, fresh source says different_authority_context, and nothing conflicts with it.',
    inputs: inputs([statement('different_authority_context', 'registry_a')]),
    expected: {
      ...ACCEPTED,
      association: { result: 'inconsistent', reason_code: CODES.differentContext, aps_04_defined_shape: false },
      boundary: { outcome: 'denied', reason_code: CODES.boundaryInconsistent, authorized_for_named_principal: false },
    },
    defined_by: 'fixture-local',
    citations: ['aps-04 lines 677-686', 'aps-04 lines 3731-3736', 'aps-04 19.2.10 lines 11300-11307', 'AIN-WRP 7.3', 'AIN-WRP B.7'],
    notes: [
      'This case is the seam between the two drafts.',
      'AIN-WRP 7.3 and B.7 let a source competent for this principal, scope and domain settle the question for the relying party, and here it settles it in the negative.',
      'The verifier has reached a conclusion, so -04 forbids reporting not established for it (lines 677-678 and 3731-3733).',
      '-04 gives shapes for three negatives only (lines 679-686) and defines no artifact for the association (19.2.10, lines 11300-11307), so it defines no shape for this one.',
      'The value inconsistent and the boundary reason X_FIXTURE_PRINCIPAL_AUTHORITY_INCONSISTENT are fixture local. They are not a proposal for how either draft should define this negative.',
    ],
  },
  {
    id: 'PAA-6',
    name: 'positive-control',
    description: 'One competent, fresh source says same_authority_context.',
    inputs: inputs([statement('same_authority_context', 'registry_a')]),
    expected: {
      ...ACCEPTED,
      association: { result: 'established', reason_code: CODES.established, aps_04_defined_shape: false },
      boundary: { outcome: 'authorized', reason_code: CODES.boundaryAuthorized, authorized_for_named_principal: true },
    },
    defined_by: 'fixture-local',
    citations: ['aps-04 19.2.10 lines 11317-11321'],
    notes: [
      'Established under the fixture profile only. -04 defines no artifact for the association, so this result is fixture local as well.',
      'Authorized here means only that the association check passes. It is subject to every other check this vector does not exercise.',
    ],
  },
]

const PAIRS = [
  { a: 'PAA-1', b: 'PAA-6', element: 'statement added', differing_paths: ['/association_evidence/0'] },
  {
    a: 'PAA-5',
    b: 'PAA-6',
    element: 'relation flipped (the signature changes with it)',
    differing_paths: ['/association_evidence/0/relation', '/association_evidence/0/signature'],
  },
  {
    a: 'PAA-2',
    b: 'PAA-6',
    element: 'signer changed (source_id and signature change together)',
    differing_paths: ['/association_evidence/0/signature', '/association_evidence/0/source_id'],
  },
  { a: 'PAA-3', b: 'PAA-6', element: 'clock moved past expiry', differing_paths: ['/evaluation_instant'] },
]

async function selfCheck(): Promise<void> {
  // Every vector shares one binding and one root, so checking them once at each
  // evaluation instant used covers every vector.
  for (const now of [EVALUATION_INSTANT, EVALUATION_INSTANT_PAST_EXPIRY]) {
    const b = await verifyPrincipalBindingV1(binding, {
      now,
      resolve_key: () => ({ state: 'resolved', public_key_hex: pub.principal }),
    })
    if (b.state !== 'valid') fail(`binding does not verify at ${now}: ${b.code}`)
    const r = verifyAuthorityDelegationChain([root], {
      now,
      resolveVerificationKey: () => pub.root_authority,
      trustRoot: (d) => d.issuer === ROOT_AUTHORITY,
      resolveRevocation: () => 'active',
    })
    if (r.state !== 'valid') fail(`root does not verify at ${now}: ${JSON.stringify(r.failures)}`)
  }
  const byId = new Map(CASES.map((c) => [c.id, c]))
  for (const p of PAIRS) {
    const got = inputDiffPaths(byId.get(p.a)!.inputs, byId.get(p.b)!.inputs)
    if (JSON.stringify(got) !== JSON.stringify(p.differing_paths)) {
      fail(`pair ${p.a}/${p.b}: inputs differ at ${JSON.stringify(got)}, declared ${JSON.stringify(p.differing_paths)}`)
    }
  }
}

await selfCheck()

const document = {
  family: 'principal-authority-association',
  status: 'candidate',
  conformance: false,
  label: 'candidate material, not conformance. Not in fixtures/manifest.json and not run by npm test.',
  authorship: 'author-produced. The vectors, the expected blocks and the checker are by the same author.',
  fixture_local: [
    `the association statement type ${STATEMENT_TYPE}`,
    `the association profile type ${PROFILE_TYPE}`,
    'the association values established and inconsistent',
    'every reason code with the X_FIXTURE_ prefix',
  ],
  references: {
    'aps-04': 'draft-pidlisnyi-aps-04 (line numbers refer to the published text)',
    'AIN-WRP': 'draft-tanase-ain-authoritative-resolution-00',
  },
  generated_at: GENERATED_AT,
  generator: 'fixtures/principal-authority-association/generate.ts',
  sdk: {
    package: 'agent-passport-system',
    version: SDK_VERSION,
    principal_binding_module: PRINCIPAL_BINDING_MODULE,
    principal_binding_module_note: 'not exported from the package root in this version. Loaded by file URL.',
  },
  seeds: {
    derivation: 'Ed25519 private key = SHA-256(UTF-8 of `${seed_prefix}:${label}`), hex',
    seed_prefix: SEED_PREFIX,
    labels: KEY_LABELS,
    nonce_derivation: 'first 32 hex characters of SHA-256(`${seed_prefix}:nonce:binding`) and of `nonce:root`',
  },
  statement_signature: {
    algorithm: 'Ed25519 via the SDK sign and verify',
    signing_input: `UTF-8 string "${SIGNATURE_DOMAIN}", one U+0000, then RFC 8785 JCS of the statement without its signature member`,
  },
  statement_check_order: [
    `1 shape, else ${CODES.malformed} (source)`,
    `2 signer listed in the profile, else ${CODES.sourceUnrecognized} (source). Signature verifies under its key, else ${CODES.signatureUnverified} (source)`,
    `3 principal_ref and root_ref name this binding principal and this root, else ${CODES.refsNotCovered} (coverage)`,
    `4 signer competent for the context principal, scope and domain, else ${CODES.sourceNotCompetent} (source)`,
    `5 issued_at not after the evaluation instant, else ${CODES.datedAfterEvaluation} (source)`,
    `6 evaluation instant before expires_at, else ${CODES.expired} (freshness)`,
  ],
  aggregation: [
    `no statements: not_established, source, ${CODES.notPresented}`,
    `accepted statements disagree: not_established, source, ${CODES.sourcesConflict}`,
    `accepted statements all say different_authority_context: inconsistent, ${CODES.differentContext}`,
    `accepted statements all say same_authority_context: established, ${CODES.established}`,
    'nothing accepted: not_established with the limb and reason of the statement that got furthest through the checks',
  ],
  pairs: PAIRS,
  cases: CASES,
}

const outPath = path.join(here, 'vectors.json')
fs.writeFileSync(outPath, `${JSON.stringify(document, null, 2)}\n`)
console.log(`wrote ${path.relative(process.cwd(), outPath)}: ${CASES.length} cases, ${PAIRS.length} pairs, sdk ${SDK_VERSION}`)
