// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Generator for fixtures/lifecycle-credential-events/vectors.json.
//
// Every instant below is a literal. Nothing reads the wall clock, the network
// or a random source. The pinned records and their RFC 8785 digests are
// produced by running the reference verifier in harness.ts over the boundaries
// declared here, so vectors.json is derived, never hand-written.
//
// From the suite root:
//
//     npm run generate:lifecycle-credential-events
//
// Then `git diff` on vectors.json shows exactly what changed.

import { readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CHECK_IDS,
  REFERENCE_VERIFIER,
  canonicalRecordBytes,
  evaluateVector,
  type Boundary,
  type CheckId,
  type CredentialFacts,
  type EventRecord,
  type TrustPolicy,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

const SEED_INPUT = 'aac-lifecycle-credential-events-v0'
const PROPOSED_TEXT = {
  repository: 'aeoess/agent-authority-lifecycle',
  commit: '2bf5c7e',
  lifecycle_document_commit: '7796e22',
  version: '0.2-draft for CASES.md, 0.1.2-draft for AUTHORITY-LIFECYCLE.md',
  note:
    'The text under test, not an external source for any factual claim. Cited by commit so a reader can pin what this fixture was written against. Every case id below is a section heading under "Credential events" in CASES.md at this commit.',
}

const chain = JSON.parse(readFileSync(join(here, 'chain.json'), 'utf8')) as {
  seed_input: string
  subjects: { principal: string; integrator: string; agent: string }
  chain: Array<{ delegation_id: string }>
}

const P = chain.subjects.principal
const I = chain.subjects.integrator
const A = chain.subjects.agent
const OPERATOR = 'did:aps:example:lce-operator'
const OTHER_TENANT = 'did:aps:example:lce-other-tenant'
const OTHER_AGENT = 'did:aps:example:lce-other-agent'
const SIBLING = 'did:aps:example:lce-sibling-agent'
const CREDENTIAL_REF = chain.chain[1].delegation_id

const NOW = '2026-09-20T13:00:00Z'

function cred(patch: Partial<CredentialFacts> = {}): CredentialFacts {
  return {
    issued_at: '2026-09-20T11:00:00Z',
    not_before: '2026-09-20T11:00:00Z',
    not_after: '2026-09-21T00:00:00Z',
    claimed_audience: 'enterprise',
    declared_scope: ['billing:submit'],
    status_lookup: true,
    subject: A,
    ...patch,
  }
}

function policy(required: CheckId[], patch: Partial<TrustPolicy> = {}): TrustPolicy {
  return {
    roots: [{ root_id: 'root-acme' }],
    clock_tolerance_s: 300,
    authority_graph: [],
    enumerated_reach_list: [],
    authorizers: [],
    required_checks: required,
    ...patch,
  }
}

// ── event builders ────────────────────────────────────────────────────────

const ev = {
  keyScope(populations: string[], patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-key-scope',
      type: 'key_scope',
      attestor: P,
      attestor_standing: 'declared',
      key_id: `${P}#key-1`,
      populations,
      ...patch,
    }
  },
  reachableScope(grants: string[], patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-reachable-scope',
      type: 'reachable_scope_attestation',
      attestor: 'did:aps:example:lce-network-attestor',
      attestor_standing: 'declared',
      grants,
      ...patch,
    }
  },
  provenance(patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-provenance',
      type: 'provenance_attestation',
      attestor: 'did:aps:example:lce-build-transparency-log',
      attestor_standing: 'declared',
      independent_of_signing_key: true,
      ...patch,
    }
  },
  authorizerAddition(authorizerId: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: `e-addition-${authorizerId}`,
      type: 'authorizer_addition',
      attestor: A,
      attestor_standing: 'declared',
      authorizer_id: authorizerId,
      added_at: '2026-09-20T11:10:00Z',
      ...patch,
    }
  },
  disclosure(subject: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-disclosure',
      type: 'compromise_disclosure',
      attestor: subject,
      attestor_standing: 'declared',
      subject,
      disclosed_at: '2026-09-20T12:30:00Z',
      self_initiated: false,
      ...patch,
    }
  },
  reattestation(covers: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: `e-reattest-${covers}`,
      type: 'reattestation',
      attestor: P,
      attestor_standing: 'declared',
      covers,
      at: '2026-09-20T12:45:00Z',
      ...patch,
    }
  },
  logIntegrityFinding(start: string, end: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-log-integrity',
      type: 'issuance_log_integrity_finding',
      attestor: 'did:aps:example:lce-forensics',
      attestor_standing: 'declared',
      issuer: P,
      window: { start, end },
      ...patch,
    }
  },
  misbehaviourFinding(patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-misbehaviour',
      type: 'issuer_misbehaviour_finding',
      attestor: 'did:aps:example:lce-transparency-monitor',
      attestor_standing: 'declared',
      issuer: P,
      discovered_by: 'external_monitor',
      period: { start: '2026-09-14T00:00:00Z', end: '2026-09-20T12:00:00Z' },
      ...patch,
    }
  },
  plannedRotation(patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-planned-rotation',
      type: 'planned_rotation',
      attestor: P,
      attestor_standing: 'declared',
      key_id: `${P}#key-1`,
      cryptoperiod_end: '2026-09-20T12:00:00Z',
      ...patch,
    }
  },
  exposureFinding(exposureStart: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-exposure',
      type: 'exposure_window_finding',
      attestor: 'did:aps:example:lce-cve-disclosure',
      attestor_standing: 'declared',
      key_id: `${P}#key-1`,
      exposure_start: exposureStart,
      discovered_at: '2026-09-20T12:00:00Z',
      ...patch,
    }
  },
  compromiseFinding(point: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-key-compromise',
      type: 'key_compromise_finding',
      attestor: 'did:aps:example:lce-forensics',
      attestor_standing: 'declared',
      key_id: `${P}#key-1`,
      compromise_point: point,
      ...patch,
    }
  },
  independentTimestamp(datedAt: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-independent-timestamp',
      type: 'independent_timestamp_attestation',
      attestor: 'did:aps:example:lce-transparency-log',
      attestor_standing: 'declared',
      artifact_dated_at: datedAt,
      ...patch,
    }
  },
  revocation(credentialRef: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: `e-revocation-${credentialRef.split(':').pop()}`,
      type: 'revocation',
      attestor: P,
      attestor_standing: 'declared',
      credential_ref: credentialRef,
      recorded_at: '2026-09-20T12:30:00Z',
      ...patch,
    }
  },
  timeAttestation(referenceNow: string, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-time-attestation',
      type: 'time_attestation',
      attestor: 'did:aps:example:lce-time-attestor',
      attestor_standing: 'declared',
      reference_now: referenceNow,
      ...patch,
    }
  },
  accountingCoverage(complete: boolean, patch: Partial<EventRecord> = {}): EventRecord {
    return {
      event_id: 'e-accounting-coverage',
      type: 'accounting_coverage_basis',
      attestor: 'did:aps:example:lce-gateway-evidence-log',
      attestor_standing: 'declared',
      interval: { start: '2026-09-20T11:00:00Z', end: '2026-09-20T12:30:00Z' },
      complete,
      ...patch,
    }
  },
}

function boundary(
  id: string,
  required: CheckId[],
  events: EventRecord[],
  patch: {
    gateway_now?: string
    credential?: Partial<CredentialFacts>
    policy?: Partial<TrustPolicy>
    prior?: string | null
  } = {},
): Boundary {
  return {
    boundary_id: id,
    gateway_now: patch.gateway_now ?? NOW,
    credential: cred(patch.credential),
    trust_policy: policy(required, patch.policy),
    events,
    prior_record_sha256: patch.prior ?? null,
  }
}

// ── the vectors ───────────────────────────────────────────────────────────

interface VectorSpec {
  id: string
  case_id: string | null
  group: string
  role: string
  description: string
  proposed_sections: string[]
  draft_03: { states_the_rule: boolean; note: string }
  boundaries: Boundary[]
}

const GRAPH_I_TO_A = [{ from: I, to: A, relation: 'issued_delegation_to' }]
const GRAPH_OPERATOR_REACHES_A = [
  { from: OPERATOR, to: I, relation: 'could_mint_credentials_for' },
  { from: I, to: A, relation: 'issued_delegation_to' },
]
const GRAPH_OPERATOR_ELSEWHERE = [
  { from: OPERATOR, to: OTHER_TENANT, relation: 'could_mint_credentials_for' },
  { from: I, to: A, relation: 'issued_delegation_to' },
]

const CONCEPT = (name: string) => `Lifecycle concepts are separate > ${name}`

const SPECS: VectorSpec[] = [
  {
    id: 'CE-00-positive-control-every-check-established',
    case_id: null,
    group: 'family control',
    role: 'positive control',
    description:
      'All thirteen checks declared, every input record present with a declared attestor. The control that shows the whole path reaches valid before any record is withheld, so a later not established is attributable to the withheld record and not to the shape of the boundary.',
    proposed_sections: [CONCEPT('Verification and evidence > Status observation')],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.3 fixes the order of chain verification steps. It does not define a per-boundary required-check set, so the join this vector exercises is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'CE-00.b1',
        CHECK_IDS,
        [
          ev.keyScope(['enterprise']),
          ev.reachableScope(['billing:submit']),
          ev.provenance(),
          ev.authorizerAddition('authy-device-1'),
          ev.timeAttestation(NOW),
          ev.accountingCoverage(true),
        ],
        { policy: { authorizers: ['authy-device-1'], authority_graph: GRAPH_I_TO_A } },
      ),
    ],
  },

  // ── LC-D-001 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-001-a-third-party-disclosure-is-a-trigger',
    case_id: 'LC-D-001',
    group: 'compromise trigger and reach',
    role: 'core',
    description:
      'An integrator discloses its own token-store compromise. The org itself revoked nothing and holds no revocation record. The credential is reachable from the disclosed subject over the declared authority graph and has not been re-attested since the disclosure.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Notice'),
      CONCEPT('Verification and evidence > Status observation'),
      'Invariants > L1. Revoking an ancestor invalidates the authority that depends on it',
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.3 requires a revocation result for every chain member. It does not define an ingestion path for a third party\'s own compromise disclosure as a status input, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary('LC-D-001-a.b1', ['signature_and_key_version', 'compromise_reach'], [ev.disclosure(I)], {
        policy: { authority_graph: GRAPH_I_TO_A, enumerated_reach_list: [A] },
      }),
    ],
  },
  {
    id: 'LC-D-001-b-reattested-after-disclosure',
    case_id: 'LC-D-001',
    group: 'compromise trigger and reach',
    role: 'positive',
    description:
      'The same disclosure, followed by a re-attestation of this credential from a party the trust policy declares as having standing. Replacement standing is established by a new record, not by the disclosure ageing out.',
    proposed_sections: [
      CONCEPT('Parties and standing > Lifecycle standing'),
      'Invariants > L3. Reauthorization creates new authority',
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'That new authority must come from a fresh grant is proposed, not stated in draft-03. This vector checks a re-attestation record, not a draft-03 rule.',
    },
    boundaries: [
      boundary(
        'LC-D-001-b.b1',
        ['signature_and_key_version', 'compromise_reach'],
        [ev.disclosure(I), ev.reattestation('credential')],
        { policy: { authority_graph: GRAPH_I_TO_A, enumerated_reach_list: [A] } },
      ),
    ],
  },
  {
    id: 'LC-D-001-c-unattributed-compromise-claim-is-not-a-trigger',
    case_id: 'LC-D-001',
    group: 'compromise trigger and reach',
    role: 'bound on the rule',
    description:
      'A compromise claim arrives from a party whose standing to make it the trust policy does not declare. It is recorded and it does not become a trigger. The boundary says the claim was seen and not acted on, which is different from saying the claim is false.',
    proposed_sections: [
      CONCEPT('Parties and standing > Issuer standing'),
      CONCEPT('Verification and evidence > Evidence attestor'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 2.5 specifies a resolution model for external and evidence signers. It does not rule on an unattributed compromise claim, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-D-001-c.b1',
        ['signature_and_key_version', 'compromise_reach'],
        [
          ev.disclosure(I, {
            attestor: 'did:aps:example:lce-unattributed-report',
            attestor_standing: 'not_declared',
          }),
        ],
        { policy: { authority_graph: GRAPH_I_TO_A, enumerated_reach_list: [A] } },
      ),
    ],
  },
  {
    id: 'LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record',
    case_id: 'LC-D-001',
    group: 'compromise trigger and reach',
    role: 'two boundaries',
    description:
      'Two boundaries. The first runs before any disclosure exists and records valid. The second runs after the disclosure and records not established, referencing the first record by digest. The earlier record is not rewritten and its digest still matches what was pinned for it.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Evidence'),
      CONCEPT('Verification and evidence > Notice'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.5.1 separates current validity from a verifiable revocation history. It does not specify a chained boundary record of the shape this vector pins.',
    },
    boundaries: [
      boundary('LC-D-001-d.b1', ['signature_and_key_version', 'compromise_reach'], [], {
        gateway_now: '2026-09-20T12:00:00Z',
        policy: { authority_graph: GRAPH_I_TO_A },
      }),
      boundary('LC-D-001-d.b2', ['signature_and_key_version', 'compromise_reach'], [ev.disclosure(I)], {
        prior: 'PRIOR',
        policy: { authority_graph: GRAPH_I_TO_A, enumerated_reach_list: [A] },
      }),
    ],
  },

  // ── LC-D-003 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-003-a-reach-over-the-graph-not-the-believed-list',
    case_id: 'LC-D-003',
    group: 'compromise trigger and reach',
    role: 'core, and the case a naive implementation admits wrongly',
    description:
      'The org raises its own rotation trigger after an upstream compromise. The credential is reachable from the compromised subject over the declared authority graph and is absent from the list the deployment maintains of grants it believes are live. Reach is measured over the graph, so the credential is in scope.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Coverage and completeness'),
      'Invariants > L12. Completeness is a separate and stronger claim',
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.5.1 says cascade completeness is not verifiable from individual revocation records and requires a cascade-completion record. It does not define the reachable set a rotation must cover, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-D-003-a.b1',
        ['signature_and_key_version', 'compromise_reach'],
        [ev.disclosure(I, { self_initiated: true, attestor: P })],
        { policy: { authority_graph: GRAPH_I_TO_A, enumerated_reach_list: [OTHER_AGENT] } },
      ),
    ],
  },
  {
    id: 'LC-D-003-b-both-bases-agree-so-agreement-establishes-nothing',
    case_id: 'LC-D-003',
    group: 'compromise trigger and reach',
    role: 'bound on the control',
    description:
      'The same boundary with the credential also present on the maintained list. Both reach bases reach the same verdict here, so a run that only looks at the verdict cannot tell the two bases apart. The record still names which basis was used.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Coverage and completeness'),
      'Invariants > L11. No silent authority resurrection',
    ],
    draft_03: {
      states_the_rule: false,
      note: 'As for LC-D-003-a.',
    },
    boundaries: [
      boundary(
        'LC-D-003-b.b1',
        ['signature_and_key_version', 'compromise_reach'],
        [ev.disclosure(I, { self_initiated: true, attestor: P })],
        { policy: { authority_graph: GRAPH_I_TO_A, enumerated_reach_list: [A] } },
      ),
    ],
  },

  // ── LC-D-004 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-004-a-operator-identity-reaches-an-independent-tree',
    case_id: 'LC-D-004',
    group: 'compromise trigger and reach',
    role: 'core',
    description:
      'A compromised operator identity is not an ancestor in this credential\'s chain. The declared graph records that the identity could mint credentials for the subject that issued this credential, so the credential is reachable from it even though no chain hop names it.',
    proposed_sections: [
      CONCEPT('Authority and dependencies > Authority path and dependency'),
      CONCEPT('Verification and evidence > Coverage and completeness'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.3 verifies one root-to-leaf chain. It has no notion of an identity that is reachable to a chain without appearing in it, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-D-004-a.b1',
        ['signature_and_key_version', 'compromise_reach'],
        [ev.disclosure(OPERATOR, { self_initiated: true, attestor: P })],
        { policy: { authority_graph: GRAPH_OPERATOR_REACHES_A, enumerated_reach_list: [] } },
      ),
    ],
  },
  {
    id: 'LC-D-004-b-operator-identity-with-no-edge-to-this-tree',
    case_id: 'LC-D-004',
    group: 'compromise trigger and reach',
    role: 'bound on the rule',
    description:
      'The same compromised operator identity, with the declared graph placing its reach in a different tenant\'s tree. Reach over the graph is not reach over everything, so this credential stays valid. Without this vector the reach rule would be indistinguishable from denying everything after any compromise.',
    proposed_sections: [CONCEPT('Authority and dependencies > Authority path and dependency')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-004-a.' },
    boundaries: [
      boundary(
        'LC-D-004-b.b1',
        ['signature_and_key_version', 'compromise_reach'],
        [ev.disclosure(OPERATOR, { self_initiated: true, attestor: P })],
        { policy: { authority_graph: GRAPH_OPERATOR_ELSEWHERE, enumerated_reach_list: [] } },
      ),
    ],
  },

  // ── LC-D-009 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-009-a-enforced-scope-exceeds-declared-scope',
    case_id: 'LC-D-009',
    group: 'declared bound against an independently attested fact',
    role: 'core',
    description:
      'The credential declares one grant. The enforcement boundary attests that what the credential can actually reach includes a second grant the delegation never declared. The containment check is established false, so the verdict is invalid rather than not established.',
    proposed_sections: [
      CONCEPT('Authority and dependencies > Target binding'),
      CONCEPT('Authority and dependencies > Action or capability binding'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.2 compares a child\'s declared scope against its parent\'s. It states no check of a declared scope against what a resource-side boundary actually enforces, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-D-009-a.b1',
        ['signature_and_key_version', 'enforced_scope_containment'],
        [ev.reachableScope(['billing:submit', 'pos:write'])],
      ),
    ],
  },
  {
    id: 'LC-D-009-b-no-reachable-scope-attestation',
    case_id: 'LC-D-009',
    group: 'declared bound against an independently attested fact',
    role: 'core',
    description:
      'No attestation of what the enforcement boundary actually reaches. The declared scope is still readable on the credential, and the containment question has no evidence either way, so the check is not established rather than passed.',
    proposed_sections: [CONCEPT('Verification and evidence > Coverage and completeness')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-009-a.' },
    boundaries: [
      boundary('LC-D-009-b.b1', ['signature_and_key_version', 'enforced_scope_containment'], []),
    ],
  },
  {
    id: 'LC-D-009-c-enforced-scope-contained',
    case_id: 'LC-D-009',
    group: 'declared bound against an independently attested fact',
    role: 'positive',
    description:
      'The attested reachable scope is contained in the declared scope. The check is established from a record, and the record names which attestation established it.',
    proposed_sections: [CONCEPT('Authority and dependencies > Target binding')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-009-a.' },
    boundaries: [
      boundary(
        'LC-D-009-c.b1',
        ['signature_and_key_version', 'enforced_scope_containment'],
        [ev.reachableScope(['billing:submit'])],
      ),
    ],
  },

  // ── LC-D-011 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-011-a-inherited-root-past-its-reattestation-deadline',
    case_id: 'LC-D-011',
    group: 'inherited trust',
    role: 'core',
    description:
      'The trust policy carries a root that entered it by inheriting another organization\'s root. The deadline the policy declared for re-establishing that root under the inheriting party\'s own root has passed with no re-attestation record.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Verifier trust policy'),
      CONCEPT('Parties and standing > Principal binding'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.3 takes root trust as a verifier policy input. It says nothing about a root that entered the policy by inheritance, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary('LC-D-011-a.b1', ['signature_and_key_version', 'inherited_root_reattestation'], [], {
        policy: {
          roots: [
            { root_id: 'root-acme' },
            {
              root_id: 'root-acquired-legacy',
              inherited_at: '2026-09-18T00:00:00Z',
              reattestation_deadline: '2026-09-20T00:00:00Z',
            },
          ],
        },
      }),
    ],
  },
  {
    id: 'LC-D-011-b-inherited-root-inside-its-deadline',
    case_id: 'LC-D-011',
    group: 'inherited trust',
    role: 'bound on the rule',
    description:
      'The same inherited root, inside the declared deadline. The inheritance alone does not make the root unusable; the passing of a declared deadline with no record does.',
    proposed_sections: [CONCEPT('Verification and evidence > Verifier trust policy')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-011-a.' },
    boundaries: [
      boundary('LC-D-011-b.b1', ['signature_and_key_version', 'inherited_root_reattestation'], [], {
        policy: {
          roots: [
            { root_id: 'root-acme' },
            {
              root_id: 'root-acquired-legacy',
              inherited_at: '2026-09-18T00:00:00Z',
              reattestation_deadline: '2026-09-25T00:00:00Z',
            },
          ],
        },
      }),
    ],
  },
  {
    id: 'LC-D-011-c-inherited-root-reestablished',
    case_id: 'LC-D-011',
    group: 'inherited trust',
    role: 'positive',
    description:
      'The deadline has passed and a re-attestation record from a party with declared standing re-establishes the inherited root under the inheriting party\'s own root.',
    proposed_sections: [CONCEPT('Parties and standing > Lifecycle standing')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-011-a.' },
    boundaries: [
      boundary(
        'LC-D-011-c.b1',
        ['signature_and_key_version', 'inherited_root_reattestation'],
        [ev.reattestation('inherited_root')],
        {
          policy: {
            roots: [
              { root_id: 'root-acme' },
              {
                root_id: 'root-acquired-legacy',
                inherited_at: '2026-09-18T00:00:00Z',
                reattestation_deadline: '2026-09-20T00:00:00Z',
              },
            ],
          },
        },
      ),
    ],
  },

  // ── LC-D-014 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-014-a-issuance-log-integrity-unestablished-for-the-window',
    case_id: 'LC-D-014',
    group: 'issuer-level findings',
    role: 'core',
    description:
      'A forensic finding says the issuer\'s own issuance-log integrity cannot be established for a window, and the credential\'s claimed issuance instant falls inside it. A revocation record naming a different credential does not settle the question for this one.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Coverage and completeness'),
      'Invariants > L12. Completeness is a separate and stronger claim',
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.3 assumes a verifier can establish revocation state per member. It does not address whether the issuer\'s own issuance records are trustworthy enough to identify which members to name, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-D-014-a.b1',
        ['signature_and_key_version', 'issuance_log_integrity'],
        [
          ev.logIntegrityFinding('2026-09-20T09:00:00Z', '2026-09-20T12:00:00Z'),
          ev.revocation(SIBLING),
        ],
      ),
    ],
  },
  {
    id: 'LC-D-014-b-issued-outside-the-covered-window',
    case_id: 'LC-D-014',
    group: 'issuer-level findings',
    role: 'bound on the rule',
    description:
      'The same finding, with the credential\'s claimed issuance instant outside the window the finding covers. The finding does not reach every artifact the issuer ever signed.',
    proposed_sections: [CONCEPT('Authority lifecycle state > Authority epoch')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-014-a.' },
    boundaries: [
      boundary(
        'LC-D-014-b.b1',
        ['signature_and_key_version', 'issuance_log_integrity'],
        [ev.logIntegrityFinding('2026-09-19T00:00:00Z', '2026-09-20T10:00:00Z')],
      ),
    ],
  },
  {
    id: 'LC-D-014-c-reestablished-from-a-reverified-root',
    case_id: 'LC-D-014',
    group: 'issuer-level findings',
    role: 'positive',
    description:
      'Inside the covered window, with a re-attestation covering the issuance window from a party with declared standing. The burden is discharged by a new record about the window, not by revoking artifacts one at a time.',
    proposed_sections: [CONCEPT('Parties and standing > Lifecycle standing')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-014-a.' },
    boundaries: [
      boundary(
        'LC-D-014-c.b1',
        ['signature_and_key_version', 'issuance_log_integrity'],
        [
          ev.logIntegrityFinding('2026-09-20T09:00:00Z', '2026-09-20T12:00:00Z'),
          ev.reattestation('issuance_window'),
        ],
      ),
    ],
  },

  // ── LC-D-025 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-025-a-revoked-and-accounting-not-established',
    case_id: 'LC-D-025',
    group: 'two claims answered separately',
    role: 'core',
    description:
      'A revocation record names this credential and the boundary looks status up, so the authority question is answered invalid. The separate question of what was done under the credential while it was valid has no coverage basis, so it is recorded as not established. One verdict does not answer the other question.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Coverage and completeness'),
      CONCEPT('Verification and evidence > Evidence'),
    ],
    draft_03: {
      states_the_rule: true,
      note:
        'draft-03 Section 3.5.1 states the separation this vector relies on: "The model separates two questions that MUST NOT collapse into one mutable lookup". It does not define a coverage basis for exercised authority, which is the part this vector pins as candidate.',
    },
    boundaries: [
      boundary(
        'LC-D-025-a.b1',
        ['signature_and_key_version', 'revocation_effectiveness', 'exercised_authority_accounting'],
        [ev.revocation(A)],
      ),
    ],
  },
  {
    id: 'LC-D-025-b-revoked-and-accounting-established',
    case_id: 'LC-D-025',
    group: 'two claims answered separately',
    role: 'positive on the second claim',
    description:
      'The same revocation, with a coverage basis record that claims completeness over the interval the credential was valid. The authority verdict is unchanged and the second claim is now established, which shows the two move independently.',
    proposed_sections: [CONCEPT('Verification and evidence > Coverage and completeness')],
    draft_03: { states_the_rule: true, note: 'As for LC-D-025-a.' },
    boundaries: [
      boundary(
        'LC-D-025-b.b1',
        ['signature_and_key_version', 'revocation_effectiveness', 'exercised_authority_accounting'],
        [ev.revocation(A), ev.accountingCoverage(true)],
      ),
    ],
  },

  // ── LC-D-029 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-029-a-no-provenance-attestation',
    case_id: 'LC-D-029',
    group: 'declared bound against an independently attested fact',
    role: 'core',
    description:
      'The signature verifies under the key version authorized at the artifact\'s own issuance instant, and nothing attests how the artifact was produced. The signature check is established and the provenance check is not, and the second is not satisfied by the first.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Evidence attestor'),
      'Invariants > L9. Key rotation is not delegation revocation',
    ],
    draft_03: {
      states_the_rule: true,
      note:
        'draft-03 Section 2.6 states the shape this vector relies on: a signal\'s provenance tier and its verification status are independent axes and "a verifier MUST NOT infer verification from tier". It states no build-provenance requirement for a signed artifact, which is the candidate part.',
    },
    boundaries: [
      boundary('LC-D-029-a.b1', ['signature_and_key_version', 'artifact_provenance'], []),
    ],
  },
  {
    id: 'LC-D-029-b-provenance-attestor-is-the-signing-key-holder',
    case_id: 'LC-D-029',
    group: 'declared bound against an independently attested fact',
    role: 'core',
    description:
      'A provenance attestation exists and its attestor is the party that holds the signing key. It restates the signature\'s own claim, so it does not establish the separate claim, and the check stays not established.',
    proposed_sections: [CONCEPT('Verification and evidence > Evidence attestor')],
    draft_03: { states_the_rule: true, note: 'As for LC-D-029-a.' },
    boundaries: [
      boundary(
        'LC-D-029-b.b1',
        ['signature_and_key_version', 'artifact_provenance'],
        [ev.provenance({ attestor: I, independent_of_signing_key: false })],
      ),
    ],
  },
  {
    id: 'LC-D-029-c-independent-provenance-attestation',
    case_id: 'LC-D-029',
    group: 'declared bound against an independently attested fact',
    role: 'positive',
    description:
      'A provenance attestation from an attestor independent of the signing key, with declared standing. Both checks are established from separate records.',
    proposed_sections: [CONCEPT('Verification and evidence > Evidence attestor')],
    draft_03: { states_the_rule: true, note: 'As for LC-D-029-a.' },
    boundaries: [
      boundary(
        'LC-D-029-c.b1',
        ['signature_and_key_version', 'artifact_provenance'],
        [ev.provenance()],
      ),
    ],
  },

  // ── LC-D-033 ────────────────────────────────────────────────────────────
  {
    id: 'LC-D-033-a-authorizer-with-no-addition-record',
    case_id: 'LC-D-033',
    group: 'provenance of an attached authorizer',
    role: 'core',
    description:
      'Two authorizers are attached to the credential\'s identity and only one has a record of how it was attached. Presence on the list is a fact about the list. It is not a record that the addition was itself authorized.',
    proposed_sections: [
      CONCEPT('Parties and standing > Issuer standing'),
      CONCEPT('Authority and dependencies > Presented credential or session'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 2.4 governs an identity\'s signing keys and their historical resolution. It does not require a record of how an additional authorizer came to be attached to an identity, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-D-033-a.b1',
        ['signature_and_key_version', 'authorizer_addition_provenance'],
        [ev.authorizerAddition('authy-device-1')],
        { policy: { authorizers: ['authy-device-1', 'authy-device-2'] } },
      ),
    ],
  },
  {
    id: 'LC-D-033-b-addition-attestor-standing-not-declared',
    case_id: 'LC-D-033',
    group: 'provenance of an attached authorizer',
    role: 'core',
    description:
      'Both authorizers have an addition record, and one was added through an internal path whose standing to attach an authorizer to this identity the trust policy does not declare. The record exists and the standing does not, which is not established rather than established false.',
    proposed_sections: [CONCEPT('Parties and standing > Issuer standing')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-033-a.' },
    boundaries: [
      boundary(
        'LC-D-033-b.b1',
        ['signature_and_key_version', 'authorizer_addition_provenance'],
        [
          ev.authorizerAddition('authy-device-1'),
          ev.authorizerAddition('authy-device-2', {
            attestor: 'did:aps:example:lce-provider-internal-tooling',
            attestor_standing: 'not_declared',
          }),
        ],
        { policy: { authorizers: ['authy-device-1', 'authy-device-2'] } },
      ),
    ],
  },
  {
    id: 'LC-D-033-c-every-authorizer-attested',
    case_id: 'LC-D-033',
    group: 'provenance of an attached authorizer',
    role: 'positive',
    description:
      'Every attached authorizer has an addition record from a party with declared standing.',
    proposed_sections: [CONCEPT('Parties and standing > Issuer standing')],
    draft_03: { states_the_rule: false, note: 'As for LC-D-033-a.' },
    boundaries: [
      boundary(
        'LC-D-033-c.b1',
        ['signature_and_key_version', 'authorizer_addition_provenance'],
        [ev.authorizerAddition('authy-device-1'), ev.authorizerAddition('authy-device-2')],
        { policy: { authorizers: ['authy-device-1', 'authy-device-2'] } },
      ),
    ],
  },

  // ── LC-F-013 ────────────────────────────────────────────────────────────
  {
    id: 'LC-F-013-a-clock-disagreement-is-its-own-outcome',
    case_id: 'LC-F-013',
    group: 'clock disagreement',
    role: 'core',
    description:
      'The boundary\'s own clock reads past the credential\'s window. An attested reference clock places the boundary inside the window, and the two disagree by more than the declared tolerance. The artifact is not invalidated; this verification attempt is not established, and the record says so with the skew and the tolerance.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Status observation'),
      'Invariants > L10. Expiry is not revocation',
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.3 returns valid, invalid, indeterminate or unsupported and lists current validity as a step. It names no clock tolerance and no skew outcome, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-F-013-a.b1',
        ['signature_and_key_version', 'clock_agreement'],
        [ev.timeAttestation('2026-09-20T13:00:00Z')],
        { gateway_now: '2026-09-21T02:00:00Z' },
      ),
    ],
  },
  {
    id: 'LC-F-013-b-expiry-with-clocks-agreeing',
    case_id: 'LC-F-013',
    group: 'clock disagreement',
    role: 'the outcome it has to stay distinct from',
    description:
      'The clocks agree inside the tolerance and the boundary is past the credential\'s not_after. This is an expiry and the record says expiry, which is the outcome a skew rejection must not be recorded as.',
    proposed_sections: ['Invariants > L10. Expiry is not revocation'],
    draft_03: {
      states_the_rule: true,
      note:
        'Current validity is a draft-03 Section 3.3 step and this outcome is ordinary. It is here so the not established outcome in LC-F-013-a is distinguishable from it in the record.',
    },
    boundaries: [
      boundary(
        'LC-F-013-b.b1',
        ['signature_and_key_version', 'clock_agreement'],
        [ev.timeAttestation('2026-09-21T02:00:30Z')],
        { gateway_now: '2026-09-21T02:00:00Z' },
      ),
    ],
  },
  {
    id: 'LC-F-013-c-clocks-agree-inside-the-window',
    case_id: 'LC-F-013',
    group: 'clock disagreement',
    role: 'positive',
    description: 'Clocks agree inside the tolerance and the boundary is inside the window.',
    proposed_sections: [CONCEPT('Verification and evidence > Status observation')],
    draft_03: { states_the_rule: true, note: 'As for LC-F-013-b.' },
    boundaries: [
      boundary(
        'LC-F-013-c.b1',
        ['signature_and_key_version', 'clock_agreement'],
        [ev.timeAttestation('2026-09-20T13:00:10Z')],
      ),
    ],
  },

  // ── LC-F-033 ────────────────────────────────────────────────────────────
  {
    id: 'LC-F-033-a-issuer-population-trust-not-established',
    case_id: 'LC-F-033',
    group: 'issuer-level findings',
    role: 'core',
    description:
      'An external monitor finds a pattern of issuance outside the issuer\'s stated policy over a period. This chain was not among the ones caught and carries no revocation record. The question the finding raises is about the issuer\'s whole population, and this chain\'s own cleanliness does not answer it.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Verifier trust policy'),
      CONCEPT('Verification and evidence > Coverage and completeness'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.3 makes root trust a verifier policy input and does not define how a systemic issuer finding enters or changes it, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-F-033-a.b1',
        ['signature_and_key_version', 'issuer_population_trust'],
        [ev.misbehaviourFinding()],
      ),
    ],
  },
  {
    id: 'LC-F-033-b-issuer-population-reattested',
    case_id: 'LC-F-033',
    group: 'issuer-level findings',
    role: 'positive',
    description:
      'The same finding, with a re-attestation covering the issuer population from a party with declared standing.',
    proposed_sections: [CONCEPT('Parties and standing > Lifecycle standing')],
    draft_03: { states_the_rule: false, note: 'As for LC-F-033-a.' },
    boundaries: [
      boundary(
        'LC-F-033-b.b1',
        ['signature_and_key_version', 'issuer_population_trust'],
        [ev.misbehaviourFinding(), ev.reattestation('issuer_population')],
      ),
    ],
  },

  // ── LC-F-035 ────────────────────────────────────────────────────────────
  {
    id: 'LC-F-035-a-revocation-not-yet-effective-for-this-credential-class',
    case_id: 'LC-F-035',
    group: 'revocation effectiveness as a credential-class property',
    role: 'core',
    description:
      'A revocation record names the credential, and the credential class is verified by signature alone with no status lookup at this boundary. The revocation is recorded and is not yet effective for this class; the credential stays valid to a holder-side verifier until its own not_after. The record says which, rather than reporting a revocation that took effect.',
    proposed_sections: [
      'Invariants > L8. Suspension is not revocation',
      CONCEPT('Authority and dependencies > Presented credential or session'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 3.5 makes revocation irreversible and requires a recheck at execution time. It does not make revocation effectiveness a property of a credential format, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-F-035-a.b1',
        ['signature_and_key_version', 'revocation_effectiveness'],
        [ev.revocation(A)],
        { credential: { status_lookup: false } },
      ),
    ],
  },
  {
    id: 'LC-F-035-b-revocation-effective-where-status-is-looked-up',
    case_id: 'LC-F-035',
    group: 'revocation effectiveness as a credential-class property',
    role: 'the outcome it has to stay distinct from',
    description:
      'The same revocation at a boundary that does look status up for this credential class. Here the revocation is effective from the instant it was recorded and the verdict is invalid. The same record produces two different, declared answers at two boundaries.',
    proposed_sections: [CONCEPT('Authority lifecycle state > Revocation')],
    draft_03: {
      states_the_rule: true,
      note:
        'The recheck at execution time is draft-03 Section 3.5. The per-class effectiveness field this vector pins is not.',
    },
    boundaries: [
      boundary(
        'LC-F-035-b.b1',
        ['signature_and_key_version', 'revocation_effectiveness'],
        [ev.revocation(A)],
      ),
    ],
  },

  // ── LC-G-001 ────────────────────────────────────────────────────────────
  {
    id: 'LC-G-001-a-planned-rotation-opens-no-suspect-window',
    case_id: 'LC-G-001',
    group: 'suspect window and its boundary',
    role: 'core',
    description:
      'A key reaches the end of a cryptoperiod declared when it was generated and the issuer rotates on schedule. No compromise is recorded. The boundary was set in advance, so there is no suspect window and nothing the outgoing key signed needs re-examination.',
    proposed_sections: [
      'Invariants > L9. Key rotation is not delegation revocation',
      CONCEPT('Authority lifecycle state > Authority epoch'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 2.4 makes a retired key eligible for artifacts inside its validity interval. It does not distinguish a planned rotation from a compromise-driven one, which is what this vector pins.',
    },
    boundaries: [
      boundary(
        'LC-G-001-a.b1',
        ['signature_and_key_version', 'suspect_window_partition'],
        [ev.plannedRotation()],
      ),
    ],
  },

  // ── LC-G-002 ────────────────────────────────────────────────────────────
  {
    id: 'LC-G-002-a-window-starts-at-exposure-not-discovery',
    case_id: 'LC-G-002',
    group: 'suspect window and its boundary',
    role: 'core',
    description:
      'A finding dates the start of a key\'s exposure earlier than the instant anyone noticed it. The credential\'s claimed issuance instant falls between the two. Measured from exposure it is inside the suspect window, and absence of evidence of misuse is not evidence that there was none.',
    proposed_sections: [
      CONCEPT('Authority lifecycle state > Authority epoch'),
      CONCEPT('Verification and evidence > Status observation'),
    ],
    draft_03: {
      states_the_rule: false,
      note:
        'draft-03 Section 2.4 requires acceptable timestamp or log evidence when a result depends on which side of a key boundary an artifact was signed. It does not define where a compromise window starts, so this is not a draft-03 conformance case.',
    },
    boundaries: [
      boundary(
        'LC-G-002-a.b1',
        ['signature_and_key_version', 'suspect_window_partition'],
        [ev.exposureFinding('2026-09-20T09:00:00Z')],
      ),
    ],
  },
  {
    id: 'LC-G-002-b-issued-before-the-exposure-start',
    case_id: 'LC-G-002',
    group: 'suspect window and its boundary',
    role: 'bound on the rule',
    description:
      'The same finding with exposure starting after the credential\'s claimed issuance instant. The window has a start, and an artifact before it keeps its standing.',
    proposed_sections: [CONCEPT('Authority lifecycle state > Authority epoch')],
    draft_03: { states_the_rule: false, note: 'As for LC-G-002-a.' },
    boundaries: [
      boundary(
        'LC-G-002-b.b1',
        ['signature_and_key_version', 'suspect_window_partition'],
        [ev.exposureFinding('2026-09-20T11:30:00Z')],
      ),
    ],
  },

  // ── LC-G-003 ────────────────────────────────────────────────────────────
  {
    id: 'LC-G-003-a-independently-dated-before-the-compromise-point',
    case_id: 'LC-G-003',
    group: 'suspect window and its boundary',
    role: 'positive',
    description:
      'A compromise is independently dated to a point, and the artifact is independently dated before it by an attestor with declared standing. The partition is drawn with evidence from a source other than the compromised key, and material before the point keeps its standing.',
    proposed_sections: [
      CONCEPT('Verification and evidence > Evidence attestor'),
      CONCEPT('Authority lifecycle state > Authority epoch'),
    ],
    draft_03: {
      states_the_rule: true,
      note:
        'draft-03 Section 2.4 states the requirement this vector relies on: when the result depends on which side of a boundary an artifact was signed, "a profile MUST identify an acceptable timestamp, transparency-log, or equivalent evidence source". Which boundary a compromise sets is not stated.',
    },
    boundaries: [
      boundary(
        'LC-G-003-a.b1',
        ['signature_and_key_version', 'suspect_window_partition'],
        [
          ev.compromiseFinding('2026-09-20T11:30:00Z'),
          ev.independentTimestamp('2026-09-20T11:00:00Z'),
        ],
      ),
    ],
  },
  {
    id: 'LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact',
    case_id: 'LC-G-003',
    group: 'suspect window and its boundary',
    role: 'core',
    description:
      'The same compromise point, with no independent dating of the artifact. The only date available is the one inside the artifact, signed by the key under question, which is exactly what a holder of that key could have chosen. The side of the boundary the artifact falls on is not established.',
    proposed_sections: [CONCEPT('Verification and evidence > Evidence attestor')],
    draft_03: {
      states_the_rule: true,
      note:
        'draft-03 Section 2.4 says the artifact timestamp is an issuer claim and that without acceptable evidence the key-authority result is indeterminate. This vector pins that shape for a compromise partition, which draft-03 does not itself define.',
    },
    boundaries: [
      boundary(
        'LC-G-003-b.b1',
        ['signature_and_key_version', 'suspect_window_partition'],
        [ev.compromiseFinding('2026-09-20T11:30:00Z')],
      ),
    ],
  },
  {
    id: 'LC-G-003-c-independently-dated-inside-the-window',
    case_id: 'LC-G-003',
    group: 'suspect window and its boundary',
    role: 'core',
    description:
      'Independent dating places the artifact after the compromise point. Standing is not established for it, which is not the same as establishing that it was forged.',
    proposed_sections: [CONCEPT('Authority lifecycle state > Authority epoch')],
    draft_03: { states_the_rule: true, note: 'As for LC-G-003-b.' },
    boundaries: [
      boundary(
        'LC-G-003-c.b1',
        ['signature_and_key_version', 'suspect_window_partition'],
        [
          ev.compromiseFinding('2026-09-20T10:30:00Z'),
          ev.independentTimestamp('2026-09-20T11:00:00Z'),
        ],
      ),
    ],
  },

  // ── LC-G-004 ────────────────────────────────────────────────────────────
  {
    id: 'LC-G-004-a-key-scope-does-not-cover-the-claimed-audience',
    case_id: 'LC-G-004',
    group: 'declared bound against an independently attested fact',
    role: 'core',
    description:
      'The signing key\'s declared population is one category and the artifact claims a broader one. The signature verifies and the scope containment is established false, so the verdict is invalid. A valid signature establishes who signed, not that the signer was scoped to sign for this.',
    proposed_sections: [
      CONCEPT('Parties and standing > Issuer standing'),
      CONCEPT('Verification and evidence > Verifier trust policy'),
    ],
    draft_03: {
      states_the_rule: true,
      note:
        'draft-03 Section 7 states the shape for imported grants: the audience "is carried in the binding but not enforced by it; the relying party at the point of use MUST reject an audience mismatch". It states no equivalent scope check on a signing key\'s declared population.',
    },
    boundaries: [
      boundary(
        'LC-G-004-a.b1',
        ['signature_and_key_version', 'key_scope_containment'],
        [ev.keyScope(['consumer'])],
      ),
    ],
  },
  {
    id: 'LC-G-004-b-no-key-scope-declared',
    case_id: 'LC-G-004',
    group: 'declared bound against an independently attested fact',
    role: 'core',
    description:
      'No record declares what population the signing key was scoped to. The containment question has no evidence either way, so the check is not established rather than passed on the strength of the signature.',
    proposed_sections: [CONCEPT('Verification and evidence > Verifier trust policy')],
    draft_03: { states_the_rule: false, note: 'As for LC-G-004-a.' },
    boundaries: [
      boundary('LC-G-004-b.b1', ['signature_and_key_version', 'key_scope_containment'], []),
    ],
  },
  {
    id: 'LC-G-004-c-key-scope-covers-the-claimed-audience',
    case_id: 'LC-G-004',
    group: 'declared bound against an independently attested fact',
    role: 'positive',
    description:
      'The declared population includes the claimed audience, established from the key-scope record rather than inferred from the signature.',
    proposed_sections: [CONCEPT('Parties and standing > Issuer standing')],
    draft_03: { states_the_rule: true, note: 'As for LC-G-004-a.' },
    boundaries: [
      boundary(
        'LC-G-004-c.b1',
        ['signature_and_key_version', 'key_scope_containment'],
        [ev.keyScope(['consumer', 'enterprise'])],
      ),
    ],
  },
]

// ── negative controls ─────────────────────────────────────────────────────
//
// Each control changes exactly one axis of the reference policy. `scope` is
// every vector the control is run against, not only the ones predicted to
// diverge, so a declared divergence that quietly stops happening is visible.
// `must_fail` is where the written record differs at all. `must_change_verdict`
// is the subset where the verdict itself differs, which is the stronger claim.

interface ControlSpec {
  name: string
  axis: string
  scope: string[]
  must_fail: string[]
  must_change_verdict: string[]
}

const byCase = (caseId: string) => SPECS.filter(s => s.case_id === caseId).map(s => s.id)
const byGroup = (group: string) => SPECS.filter(s => s.group === group).map(s => s.id)

const CONTROLS: ControlSpec[] = [
  {
    name: 'self-initiated-triggers-only',
    axis: 'whether a compromise disclosure from another party is ingested as a trigger at all',
    scope: [...byCase('LC-D-001'), ...byCase('LC-F-033')],
    must_fail: [
      'LC-D-001-a-third-party-disclosure-is-a-trigger',
      'LC-D-001-b-reattested-after-disclosure',
      'LC-D-001-c-unattributed-compromise-claim-is-not-a-trigger',
      'LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record',
    ],
    must_change_verdict: [
      'LC-D-001-a-third-party-disclosure-is-a-trigger',
      'LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record',
    ],
  },
  {
    name: 'enumerated-reach-basis',
    axis: 'what reachability from a compromised subject is computed over',
    scope: [...byCase('LC-D-003'), ...byCase('LC-D-004')],
    must_fail: byCase('LC-D-003').concat(byCase('LC-D-004')),
    must_change_verdict: [
      'LC-D-003-a-reach-over-the-graph-not-the-believed-list',
      'LC-D-004-a-operator-identity-reaches-an-independent-tree',
    ],
  },
  {
    name: 'signature-satisfies-other-checks',
    axis: 'whether a valid signature stands in for a separately declared check',
    scope: [...byCase('LC-D-009'), ...byCase('LC-D-029'), ...byCase('LC-G-004')],
    must_fail: [...byCase('LC-D-009'), ...byCase('LC-D-029'), ...byCase('LC-G-004')],
    must_change_verdict: [
      'LC-D-009-a-enforced-scope-exceeds-declared-scope',
      'LC-D-009-b-no-reachable-scope-attestation',
      'LC-D-029-a-no-provenance-attestation',
      'LC-D-029-b-provenance-attestor-is-the-signing-key-holder',
      'LC-G-004-a-key-scope-does-not-cover-the-claimed-audience',
      'LC-G-004-b-no-key-scope-declared',
    ],
  },
  {
    name: 'grandfather-inherited-root',
    axis: 'whether a root that entered the policy by inheritance needs its own re-establishment record',
    scope: byCase('LC-D-011'),
    must_fail: byCase('LC-D-011'),
    must_change_verdict: ['LC-D-011-a-inherited-root-past-its-reattestation-deadline'],
  },
  {
    name: 'per-artifact-revocation-settles-log-integrity',
    axis: 'what settles a finding about the issuer\'s own issuance-log integrity',
    scope: byCase('LC-D-014'),
    must_fail: [
      'LC-D-014-a-issuance-log-integrity-unestablished-for-the-window',
      'LC-D-014-c-reestablished-from-a-reverified-root',
    ],
    must_change_verdict: ['LC-D-014-a-issuance-log-integrity-unestablished-for-the-window'],
  },
  {
    name: 'issuer-population-from-caught-chains',
    axis: 'whether a systemic issuer finding is answered chain by chain',
    scope: byCase('LC-F-033'),
    must_fail: byCase('LC-F-033'),
    must_change_verdict: ['LC-F-033-a-issuer-population-trust-not-established'],
  },
  {
    name: 'revocation-closes-accounting',
    axis: 'whether the accounting of what was done is inferred from the current authority status',
    scope: byCase('LC-D-025'),
    must_fail: byCase('LC-D-025'),
    must_change_verdict: [],
  },
  {
    name: 'presence-implies-authorized-addition',
    axis: 'whether presence on the authorizer list establishes that the addition was authorized',
    scope: byCase('LC-D-033'),
    must_fail: byCase('LC-D-033'),
    must_change_verdict: [
      'LC-D-033-a-authorizer-with-no-addition-record',
      'LC-D-033-b-addition-attestor-standing-not-declared',
    ],
  },
  {
    name: 'skew-is-expiry',
    axis: 'how a clock disagreement beyond tolerance is categorized',
    scope: byCase('LC-F-013'),
    must_fail: ['LC-F-013-a-clock-disagreement-is-its-own-outcome'],
    must_change_verdict: ['LC-F-013-a-clock-disagreement-is-its-own-outcome'],
  },
  {
    name: 'revocation-is-universal',
    axis: 'whether revocation effectiveness is a property of the credential class',
    scope: byCase('LC-F-035'),
    must_fail: byCase('LC-F-035'),
    must_change_verdict: ['LC-F-035-a-revocation-not-yet-effective-for-this-credential-class'],
  },
  {
    name: 'every-rotation-is-a-trigger',
    axis: 'whether a planned rotation at a declared cryptoperiod end opens a suspect window',
    scope: [...byCase('LC-G-001'), ...byCase('LC-G-003')],
    must_fail: byCase('LC-G-001'),
    must_change_verdict: byCase('LC-G-001'),
  },
  {
    name: 'discovery-dated-window',
    axis: 'where a suspect window starts when exposure and discovery differ',
    scope: byCase('LC-G-002'),
    must_fail: byCase('LC-G-002'),
    must_change_verdict: ['LC-G-002-a-window-starts-at-exposure-not-discovery'],
  },
  {
    name: 'trust-claimed-issued-at',
    axis: 'which timestamp partitions artifacts around a compromise point',
    scope: byCase('LC-G-003'),
    must_fail: [
      'LC-G-003-a-independently-dated-before-the-compromise-point',
      'LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact',
      'LC-G-003-c-independently-dated-inside-the-window',
    ],
    must_change_verdict: ['LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact'],
  },
  {
    name: 'skip-unestablished-checks',
    axis: 'what a declared check with no input record resolves to',
    scope: SPECS.map(s => s.id),
    must_fail: [
      'LC-D-001-a-third-party-disclosure-is-a-trigger',
      'LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record',
      'LC-D-003-a-reach-over-the-graph-not-the-believed-list',
      'LC-D-003-b-both-bases-agree-so-agreement-establishes-nothing',
      'LC-D-004-a-operator-identity-reaches-an-independent-tree',
      'LC-D-009-b-no-reachable-scope-attestation',
      'LC-D-011-a-inherited-root-past-its-reattestation-deadline',
      'LC-D-014-a-issuance-log-integrity-unestablished-for-the-window',
      'LC-D-025-a-revoked-and-accounting-not-established',
      'LC-D-029-a-no-provenance-attestation',
      'LC-D-029-b-provenance-attestor-is-the-signing-key-holder',
      'LC-D-033-a-authorizer-with-no-addition-record',
      'LC-D-033-b-addition-attestor-standing-not-declared',
      'LC-F-033-a-issuer-population-trust-not-established',
      'LC-G-002-a-window-starts-at-exposure-not-discovery',
      'LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact',
      'LC-G-003-c-independently-dated-inside-the-window',
      'LC-G-004-b-no-key-scope-declared',
    ],
    must_change_verdict: [
      'LC-D-001-a-third-party-disclosure-is-a-trigger',
      'LC-D-001-d-later-finding-does-not-rewrite-the-earlier-record',
      'LC-D-003-a-reach-over-the-graph-not-the-believed-list',
      'LC-D-003-b-both-bases-agree-so-agreement-establishes-nothing',
      'LC-D-004-a-operator-identity-reaches-an-independent-tree',
      'LC-D-009-b-no-reachable-scope-attestation',
      'LC-D-011-a-inherited-root-past-its-reattestation-deadline',
      'LC-D-014-a-issuance-log-integrity-unestablished-for-the-window',
      'LC-D-029-a-no-provenance-attestation',
      'LC-D-029-b-provenance-attestor-is-the-signing-key-holder',
      'LC-D-033-a-authorizer-with-no-addition-record',
      'LC-D-033-b-addition-attestor-standing-not-declared',
      'LC-F-033-a-issuer-population-trust-not-established',
      'LC-G-002-a-window-starts-at-exposure-not-discovery',
      'LC-G-003-b-only-the-compromised-keys-own-claim-dates-the-artifact',
      'LC-G-003-c-independently-dated-inside-the-window',
      'LC-G-004-b-no-key-scope-declared',
    ],
  },
]

// ── emit ──────────────────────────────────────────────────────────────────

const cases = SPECS.map(spec => {
  const records = evaluateVector(
    spec.boundaries,
    CREDENTIAL_REF,
    REFERENCE_VERIFIER,
    spec.id,
    spec.case_id,
  )
  return {
    id: spec.id,
    case_id: spec.case_id,
    group: spec.group,
    role: spec.role,
    label: 'candidate_against_proposed',
    description: spec.description,
    proposed_text: { ...PROPOSED_TEXT, sections: spec.proposed_sections, case_id: spec.case_id },
    draft_03: spec.draft_03,
    boundaries: spec.boundaries.map((b, i) => ({
      boundary_id: b.boundary_id,
      gateway_now: b.gateway_now,
      credential: b.credential,
      trust_policy: b.trust_policy,
      events: b.events,
      prior_record_sha256: b.prior_record_sha256,
      expected: {
        verdict: records[i].verdict,
        verdict_reason: records[i].verdict_reason,
        record: records[i],
        canonical_bytes_len: Buffer.byteLength(canonicalRecordBytes(records[i]), 'utf8'),
        canonical_sha256: createHash('sha256')
          .update(canonicalRecordBytes(records[i]), 'utf8')
          .digest('hex'),
      },
    })),
  }
})

const out = {
  family: 'lifecycle-credential-events',
  version: '1',
  status: 'candidate',
  label: 'candidate_against_proposed',
  description:
    'Credential-event cases from the "Credential events" section of CASES.md, built as one family. A boundary declares which checks its policy requires; each check resolves from its own records to established_valid, established_invalid or not_established; no check is satisfied by another check; and the verdict is the join in the settled verdict vocabulary. Every vector is a candidate against proposed text. Nothing here is a conformance claim about APS or any published specification.',
  proposed_text: PROPOSED_TEXT,
  verdict_vocabulary: [
    'valid',
    'invalid',
    'not established',
    'not yet effective',
    'suspended',
    'restricted',
  ],
  verdict_vocabulary_note:
    'The settled vocabulary. This family reaches valid, invalid and not established for a credential at a boundary. "not yet effective" is used for the state of a revocation record that cannot take effect for a credential class before that credential expires. No case here reaches suspended or restricted; those belong to suspension and external-restriction families.',
  check_results: ['established_valid', 'established_invalid', 'not_established'],
  check_ids: CHECK_IDS,
  determinism: {
    seed_input: SEED_INPUT,
    seed_sha256_hex: createHash('sha256').update(SEED_INPUT, 'utf8').digest('hex'),
    canonicalization: 'RFC 8785 JSON Canonicalization Scheme',
    canonicalization_ref: 'https://www.rfc-editor.org/rfc/rfc8785',
    digest: 'SHA-256 over the RFC 8785 canonical bytes of the credential-event record',
    clock: 'every instant is a literal in generate.ts; no wall-clock read anywhere',
    chain: 'chain.json, minted by mint.py from the same seed_input',
  },
  credential_ref: CREDENTIAL_REF,
  credential_ref_note:
    'The delegation_id of the leaf hop in chain.json. The credential this family asks about.',
  controls: CONTROLS,
  cases,
}

writeFileSync(join(here, 'vectors.json'), JSON.stringify(out, null, 2) + '\n', 'utf8')
console.log(
  `wrote vectors.json: ${cases.length} cases, ` +
  `${cases.reduce((n, c) => n + c.boundaries.length, 0)} boundaries, ` +
  `${CONTROLS.length} controls`,
)
