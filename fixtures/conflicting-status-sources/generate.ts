// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Deterministic generator for fixtures/conflicting-status-sources/vectors.json.
//
// WHAT IS DECLARED BY HAND AND WHAT IS COMPUTED. The case inputs, the expected
// decision, the expected reason, the property each case belongs to and each
// negative control's declared fail set are written out below as data. They are
// the fixture's claim and no code derives them. The generator computes only
// what follows mechanically from the inputs: each answer's age at the
// boundary, the coverage count, the RFC 8785 canonical bytes of the resulting
// status-observation record and their SHA-256.
//
// Nothing here reads the wall clock, a random source or the network. Every
// instant comes from the constants below, and the key material the record's
// delegation_ref points at comes from chain.json, minted by mint.py from a
// published seed.
//
// Run from the suite root:
//
//     npm run generate:conflicting-status-sources
//
// Then `git diff` on vectors.json should be empty.

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

import {
  REFERENCE_VERIFIER,
  canonicalRecordBytes,
  evaluateCase,
  recordDigest,
  type Boundary,
  type Verdict,
} from './harness.js'

const here = dirname(fileURLToPath(import.meta.url))

const SEED_INPUT = 'aac-conflicting-status-sources-v0'

const T = {
  base: '2026-09-20T12:00:00Z',
  minus60: '2026-09-20T11:59:00Z',
  minus90: '2026-09-20T11:58:30Z',
  minus120: '2026-09-20T11:58:00Z',
  minus300: '2026-09-20T11:55:00Z',
  minus301: '2026-09-20T11:54:59Z',
  minus900: '2026-09-20T11:45:00Z',
  minus1800: '2026-09-20T11:30:00Z',
  minus7200: '2026-09-20T10:00:00Z',
  later: '2026-09-20T12:10:00Z',
  laterMinus60: '2026-09-20T12:09:00Z',
  laterMinus300: '2026-09-20T12:05:00Z',
}

const A = { source_id: 'registry-a', freshness_bound_s: 300 }
const B = { source_id: 'registry-b', freshness_bound_s: 600 }
const SNAP = { source_id: 'snapshot-c', freshness_bound_s: 3600 }

const ONLINE_A = { mode: 'online' as const, required_sources: [A] }
const ONLINE_AB = { mode: 'online' as const, required_sources: [A, B] }
const OFFLINE = {
  mode: 'offline' as const,
  required_sources: [A],
  snapshot_source: SNAP,
  declared_offline_bound_s: 3600,
}

interface BoundaryDecl {
  boundary: Boundary
  expected: { decision: Verdict; reason: string }
}

interface CaseDecl {
  id: string
  property: 'C' | 'F' | 'O'
  role: 'positive control' | 'negative' | 'positive'
  description: string
  proposed_text_sections: string[]
  draft_03_note: string
  boundaries: BoundaryDecl[]
}

const PROPOSED_STATUS_OBSERVATION =
  'Lifecycle concepts are separate > Verification and evidence > Status observation'
const PROPOSED_COVERAGE =
  'Lifecycle concepts are separate > Verification and evidence > Coverage and completeness'
const PROPOSED_TRUST_POLICY =
  'Lifecycle concepts are separate > Verification and evidence > Verifier trust policy'
const PROPOSED_L7 = 'Invariants > L7. Unknown revocation state is not active'
const PROPOSED_EVIDENCE =
  'Lifecycle concepts are separate > Verification and evidence > Evidence'

const DRAFT03_SINGLE_ANSWER =
  'draft-03 Section 3.3 rules one revocation result per chain member. It does not ' +
  'state a rule for two status sources answering about the same member, so the ' +
  'multi-source decision this case checks is not a draft-03 conformance case.'

const DRAFT03_STALE =
  'draft-03 Section 3.3 states that an unavailable or stale revocation result is ' +
  'indeterminate, and that a caller must not collapse indeterminate into valid. It ' +
  'does not define a per-source freshness bound, and it does not state what the ' +
  'result is when one source is stale and another is fresh, so the boundary verdict ' +
  'this case checks is not a draft-03 conformance case.'

const DRAFT03_OFFLINE =
  'draft-03 Section 3.3 does not describe an offline verifier admitting on a ' +
  'snapshot inside a declared bound, and Section 5.4 requires a decision to include ' +
  'revocation observations without stating the fields one carries. This case is not ' +
  'a draft-03 conformance case.'

function one(
  boundary_id: string,
  evaluated_at: string,
  trust_policy: Boundary['trust_policy'],
  observations: Boundary['observations'],
  decision: Verdict,
  reason: string,
  prior: string | null = null,
): BoundaryDecl {
  return {
    boundary: { boundary_id, evaluated_at, trust_policy, observations, prior_record_sha256: prior },
    expected: { decision, reason },
  }
}

const CASES: CaseDecl[] = [
  {
    id: 'CSS-01-single-source-active-admits',
    property: 'C',
    role: 'positive control',
    description:
      'One required source, one answer inside its freshness bound, active. The control ' +
      'that shows the admit path works before any disagreement is introduced.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_TRUST_POLICY],
    draft_03_note: DRAFT03_SINGLE_ANSWER,
    boundaries: [
      one(
        'CSS-01.b1',
        T.base,
        ONLINE_A,
        [{ source_id: 'registry-a', answer: 'active', as_of: T.minus60 }],
        'admit',
        'status_active_all_sources_agree',
      ),
    ],
  },
  {
    id: 'CSS-02-two-sources-agree-active-admits',
    property: 'C',
    role: 'positive control',
    description:
      'Both required sources answer active inside their own bounds. Coverage is complete ' +
      'and the states agree, which is the only shape that admits online.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_COVERAGE],
    draft_03_note: DRAFT03_SINGLE_ANSWER,
    boundaries: [
      one(
        'CSS-02.b1',
        T.base,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'active', as_of: T.minus60 },
          { source_id: 'registry-b', answer: 'active', as_of: T.minus120 },
        ],
        'admit',
        'status_active_all_sources_agree',
      ),
    ],
  },
  {
    id: 'CSS-03-two-sources-agree-revoked-denies',
    property: 'C',
    role: 'negative',
    description:
      'Both required sources answer revoked inside their bounds. Agreement on revoked is ' +
      'not a conflict, and the reason says revoked rather than conflict.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_L7],
    draft_03_note: DRAFT03_SINGLE_ANSWER,
    boundaries: [
      one(
        'CSS-03.b1',
        T.base,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'revoked', as_of: T.minus60 },
          { source_id: 'registry-b', answer: 'revoked', as_of: T.minus90 },
        ],
        'deny',
        'status_revoked',
      ),
    ],
  },
  {
    id: 'CSS-04-fresh-conflict-denies-with-conflict-reason',
    property: 'C',
    role: 'negative',
    description:
      'The family core. Two sources the verifier trusts, both inside their own freshness ' +
      'bounds, disagree about the same delegation: one active, one revoked. The verdict is ' +
      'deny with a conflict reason, and the record names both sources and both states.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_TRUST_POLICY, PROPOSED_EVIDENCE],
    draft_03_note: DRAFT03_SINGLE_ANSWER,
    boundaries: [
      one(
        'CSS-04.b1',
        T.base,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'active', as_of: T.minus60 },
          { source_id: 'registry-b', answer: 'revoked', as_of: T.minus120 },
        ],
        'deny',
        'status_sources_conflict',
      ),
    ],
  },
  {
    id: 'CSS-05-stale-revoked-against-fresh-active-denies',
    property: 'C',
    role: 'negative',
    description:
      'The negative control a naive implementation passes wrongly. The revoked answer is ' +
      'past its source freshness bound and the active answer is inside its own, so an ' +
      'implementation that discards stale answers before deciding sees one fresh active ' +
      'answer and admits. A revocation that was observed does not become unobserved with ' +
      'age, so the reference verifier still counts it and the states still conflict.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_L7],
    draft_03_note:
      DRAFT03_STALE +
      ' draft-03 Section 3.5 does state that revocation is irreversible, which is why an ' +
      'observed revocation is still counted here, but it states nothing about weighing it ' +
      'against a fresher answer from a second source.',
    boundaries: [
      one(
        'CSS-05.b1',
        T.base,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'active', as_of: T.minus60 },
          { source_id: 'registry-b', answer: 'revoked', as_of: T.minus900 },
        ],
        'deny',
        'status_sources_conflict',
      ),
    ],
  },
  {
    id: 'CSS-06-one-source-stale-past-bound-not-established',
    property: 'F',
    role: 'negative',
    description:
      'Both sources answer active, but one answer is older than that source freshness ' +
      'bound. The stale answer is not false and it is not a revocation. It establishes ' +
      'nothing, so the boundary verdict is not_established, not admit and not deny.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_COVERAGE, PROPOSED_L7],
    draft_03_note: DRAFT03_STALE,
    boundaries: [
      one(
        'CSS-06.b1',
        T.base,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'active', as_of: T.minus60 },
          { source_id: 'registry-b', answer: 'active', as_of: T.minus900 },
        ],
        'not_established',
        'status_stale_beyond_bound',
      ),
    ],
  },
  {
    id: 'CSS-07-required-source-silent-not-established',
    property: 'F',
    role: 'negative',
    description:
      'One required source produced no answer at all. The answers that did arrive agree on ' +
      'active, so an implementation that measures coverage over what arrived admits. ' +
      'Coverage is measured against the declared source set, so this is not_established ' +
      'with a coverage reason, which is a different finding from a stale answer.',
    proposed_text_sections: [PROPOSED_COVERAGE, PROPOSED_TRUST_POLICY],
    draft_03_note:
      'draft-03 states no coverage requirement over a declared set of status sources, so ' +
      'this case is not a draft-03 conformance case.',
    boundaries: [
      one(
        'CSS-07.b1',
        T.base,
        ONLINE_AB,
        [{ source_id: 'registry-a', answer: 'active', as_of: T.minus60 }],
        'not_established',
        'status_coverage_incomplete',
      ),
    ],
  },
  {
    id: 'CSS-08-no-usable-answer-not-established',
    property: 'F',
    role: 'negative',
    description:
      'One source answers past its bound and the other does not answer. Nothing usable and ' +
      'determinate remains, and the reason distinguishes that from a stale answer inside a ' +
      'covered set and from a missing source.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_L7],
    draft_03_note: DRAFT03_STALE,
    boundaries: [
      one(
        'CSS-08.b1',
        T.base,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'active', as_of: T.minus900 },
          { source_id: 'registry-b', answer: 'unavailable' },
        ],
        'not_established',
        'status_no_usable_observation',
      ),
    ],
  },
  {
    id: 'CSS-09-offline-snapshot-within-declared-bound-admits',
    property: 'O',
    role: 'positive',
    description:
      'A verifier that declared itself offline, with a snapshot source and a bound it ' +
      'declared in advance, holds a snapshot inside that bound saying active. It may admit, ' +
      'and the record it writes has to name the snapshot it admitted on and the age that ' +
      'snapshot had at the boundary.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_TRUST_POLICY, PROPOSED_EVIDENCE],
    draft_03_note: DRAFT03_OFFLINE,
    boundaries: [
      one(
        'CSS-09.b1',
        T.base,
        OFFLINE,
        [
          { source_id: 'registry-a', answer: 'unavailable' },
          { source_id: 'snapshot-c', answer: 'active', as_of: T.minus1800 },
        ],
        'admit',
        'admitted_on_snapshot_within_declared_bound',
      ),
    ],
  },
  {
    id: 'CSS-10-offline-snapshot-past-declared-bound-not-established',
    property: 'O',
    role: 'negative',
    description:
      'The same offline verifier, with a snapshot older than the bound it declared. The ' +
      'declared bound is the whole basis for the offline admission, so past it the ' +
      'snapshot establishes nothing.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_L7],
    draft_03_note: DRAFT03_OFFLINE,
    boundaries: [
      one(
        'CSS-10.b1',
        T.base,
        OFFLINE,
        [
          { source_id: 'registry-a', answer: 'unavailable' },
          { source_id: 'snapshot-c', answer: 'active', as_of: T.minus7200 },
        ],
        'not_established',
        'status_stale_beyond_bound',
      ),
    ],
  },
  {
    id: 'CSS-11-offline-snapshot-revoked-denies',
    property: 'O',
    role: 'negative',
    description:
      'The offline verifier holds a snapshot inside its declared bound saying revoked. ' +
      'Being offline is a reason to admit less, never a reason to soften an observed ' +
      'revocation, so this denies.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_L7],
    draft_03_note: DRAFT03_OFFLINE,
    boundaries: [
      one(
        'CSS-11.b1',
        T.base,
        OFFLINE,
        [
          { source_id: 'registry-a', answer: 'unavailable' },
          { source_id: 'snapshot-c', answer: 'revoked', as_of: T.minus1800 },
        ],
        'deny',
        'status_revoked',
      ),
    ],
  },
  {
    id: 'CSS-13-answer-exactly-at-the-bound-admits',
    property: 'F',
    role: 'positive',
    description:
      'The answer is exactly as old as the bound declared for its source. The bound is ' +
      'inclusive, so this admits. It is here so the pair with CSS-14 pins which side of ' +
      'the boundary each verdict sits on, rather than leaving it to a reader to assume.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_TRUST_POLICY],
    draft_03_note: DRAFT03_STALE,
    boundaries: [
      one(
        'CSS-13.b1',
        T.base,
        ONLINE_A,
        [{ source_id: 'registry-a', answer: 'active', as_of: T.minus300 }],
        'admit',
        'status_active_all_sources_agree',
      ),
    ],
  },
  {
    id: 'CSS-14-answer-one-second-past-the-bound-not-established',
    property: 'F',
    role: 'negative',
    description:
      'One second older than CSS-13 and the only source in the trust policy. Nothing usable ' +
      'remains, so the verdict is not_established. The answer still says active and the ' +
      'fixture does not call it false.',
    proposed_text_sections: [PROPOSED_STATUS_OBSERVATION, PROPOSED_L7],
    draft_03_note: DRAFT03_STALE,
    boundaries: [
      one(
        'CSS-14.b1',
        T.base,
        ONLINE_A,
        [{ source_id: 'registry-a', answer: 'active', as_of: T.minus301 }],
        'not_established',
        'status_no_usable_observation',
      ),
    ],
  },
  {
    id: 'CSS-12-later-conflict-does-not-rewrite-the-earlier-record',
    property: 'C',
    role: 'negative',
    description:
      'Two authorization boundaries ten minutes apart. The first admits on two agreeing ' +
      'active answers. By the second, one source reports revoked and the other still ' +
      'reports active, so the second boundary denies on a conflict. The second record ' +
      'references the first by digest. The first record is not rewritten, and the vector ' +
      'pins its bytes so a runner that rewrote it would fail.',
    proposed_text_sections: [PROPOSED_EVIDENCE, PROPOSED_STATUS_OBSERVATION],
    draft_03_note: DRAFT03_SINGLE_ANSWER,
    boundaries: [
      one(
        'CSS-12.b1',
        T.base,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'active', as_of: T.minus60 },
          { source_id: 'registry-b', answer: 'active', as_of: T.minus120 },
        ],
        'admit',
        'status_active_all_sources_agree',
      ),
      one(
        'CSS-12.b2',
        T.later,
        ONLINE_AB,
        [
          { source_id: 'registry-a', answer: 'active', as_of: T.laterMinus60 },
          { source_id: 'registry-b', answer: 'revoked', as_of: T.laterMinus300 },
        ],
        'deny',
        'status_sources_conflict',
        'PRIOR',
      ),
    ],
  },
]

/** Declared fail sets. Each control changes exactly one axis of the reference
 *  policy and runs against every case of its property, not only the ones
 *  predicted to fail, so a declared failure that stops failing is loud. */
const CONTROLS = [
  {
    name: 'latest-answer-wins',
    axis: 'disagreement resolution',
    scope: [
      'CSS-01-single-source-active-admits',
      'CSS-02-two-sources-agree-active-admits',
      'CSS-03-two-sources-agree-revoked-denies',
      'CSS-04-fresh-conflict-denies-with-conflict-reason',
      'CSS-05-stale-revoked-against-fresh-active-denies',
      'CSS-12-later-conflict-does-not-rewrite-the-earlier-record',
    ],
    must_fail: [
      'CSS-04-fresh-conflict-denies-with-conflict-reason',
      'CSS-05-stale-revoked-against-fresh-active-denies',
      'CSS-12-later-conflict-does-not-rewrite-the-earlier-record',
    ],
  },
  {
    name: 'drop-stale-then-decide',
    axis: 'what survives the freshness bound, and what coverage is measured over',
    scope: [
      'CSS-02-two-sources-agree-active-admits',
      'CSS-05-stale-revoked-against-fresh-active-denies',
      'CSS-06-one-source-stale-past-bound-not-established',
      'CSS-07-required-source-silent-not-established',
      'CSS-08-no-usable-answer-not-established',
      'CSS-13-answer-exactly-at-the-bound-admits',
      'CSS-14-answer-one-second-past-the-bound-not-established',
    ],
    must_fail: [
      'CSS-05-stale-revoked-against-fresh-active-denies',
      'CSS-06-one-source-stale-past-bound-not-established',
      'CSS-07-required-source-silent-not-established',
    ],
  },
  {
    name: 'offline-admit-without-recording',
    axis: 'whether an offline admission records the snapshot and age it used',
    scope: [
      'CSS-09-offline-snapshot-within-declared-bound-admits',
      'CSS-10-offline-snapshot-past-declared-bound-not-established',
      'CSS-11-offline-snapshot-revoked-denies',
    ],
    must_fail: ['CSS-09-offline-snapshot-within-declared-bound-admits'],
  },
]

interface ChainFixture {
  seed_input: string
  now: string
  verification_keys: Record<string, string>
  chain: Array<{ delegation_id: string }>
}

const chain = JSON.parse(readFileSync(join(here, 'chain.json'), 'utf8')) as ChainFixture
const delegationRef = chain.chain[0].delegation_id

const cases = CASES.map(decl => {
  const records = evaluateCase(
    decl.boundaries.map(b => b.boundary),
    delegationRef,
    REFERENCE_VERIFIER,
  )
  const boundaries = decl.boundaries.map((b, i) => {
    const record = records[i]
    if (record.decision !== b.expected.decision || record.reason !== b.expected.reason) {
      throw new Error(
        `${decl.id} ${b.boundary.boundary_id}: declared ${b.expected.decision}/${b.expected.reason}, ` +
        `reference verifier produced ${record.decision}/${record.reason}`,
      )
    }
    const bytes = canonicalRecordBytes(record)
    return {
      boundary_id: b.boundary.boundary_id,
      evaluated_at: b.boundary.evaluated_at,
      trust_policy: b.boundary.trust_policy,
      observations: b.boundary.observations,
      prior_record_sha256: b.boundary.prior_record_sha256,
      expected: {
        decision: b.expected.decision,
        reason: b.expected.reason,
        record,
        canonical_bytes_len: Buffer.byteLength(bytes, 'utf8'),
        canonical_sha256: recordDigest(record),
      },
    }
  })
  return {
    id: decl.id,
    property: decl.property,
    role: decl.role,
    label: 'candidate_against_proposed',
    description: decl.description,
    proposed_text: {
      repository: 'aeoess/agent-authority-lifecycle',
      commit: '5c1bf09',
      version: '0.1.2-draft',
      sections: decl.proposed_text_sections,
    },
    draft_03: { states_the_rule: false, note: decl.draft_03_note },
    boundaries,
  }
})

const vectors = {
  family: 'conflicting-status-sources',
  version: '1',
  status: 'candidate',
  label: 'candidate_against_proposed',
  description:
    'Status observation and coverage at one authorization boundary. Two status sources a ' +
    'verifier trusts disagree about the same delegation, a source answers past its declared ' +
    'freshness bound, and a verifier that declared itself offline admits on a snapshot inside ' +
    'a bound it declared in advance. Every case is a candidate against proposed text. Nothing ' +
    'here is a conformance claim about APS or any published specification.',
  proposed_text: {
    repository: 'aeoess/agent-authority-lifecycle',
    commit: '5c1bf09',
    version: '0.1.2-draft',
    note:
      'The text under test, not an external source for any claim. Cited by section name and ' +
      'commit so a reader can pin what this fixture was written against.',
  },
  determinism: {
    seed_input: SEED_INPUT,
    seed_sha256_hex: createHash('sha256').update(SEED_INPUT, 'utf8').digest('hex'),
    canonicalization: 'RFC 8785 JSON Canonicalization Scheme',
    canonicalization_ref: 'https://www.rfc-editor.org/rfc/rfc8785',
    digest: 'SHA-256 over the RFC 8785 canonical bytes of the status-observation record',
    clock: 'every instant is a constant in generate.ts; no wall-clock read anywhere',
    chain: 'chain.json, minted by mint.py from the same seed_input',
  },
  delegation_ref: delegationRef,
  sources: [A, B, SNAP],
  reasons: {
    status_active_all_sources_agree:
      'admit; every required source answered inside its freshness bound and every answer was active',
    status_revoked:
      'deny; a source the verifier trusts answered revoked and no usable answer disagreed',
    status_sources_conflict:
      'deny; two sources the verifier trusts gave different determinate answers about the same delegation',
    status_stale_beyond_bound:
      'not_established; an answer the verdict needed was older than the bound declared for its source',
    status_coverage_incomplete:
      'not_established; a source the trust policy requires produced no answer at all',
    status_no_usable_observation:
      'not_established; no source produced a usable determinate answer',
    admitted_on_snapshot_within_declared_bound:
      'admit; an offline verifier used a snapshot inside the bound it declared, and recorded which snapshot and what age',
  },
  controls: CONTROLS,
  cases,
}

writeFileSync(join(here, 'vectors.json'), JSON.stringify(vectors, null, 2) + '\n', 'utf8')
console.log(
  `conflicting-status-sources: wrote vectors.json, ${cases.length} cases, ` +
  `${cases.reduce((n, c) => n + c.boundaries.length, 0)} boundaries`,
)
