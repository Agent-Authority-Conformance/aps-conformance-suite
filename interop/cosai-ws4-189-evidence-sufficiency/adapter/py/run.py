"""Build the candidate cases and run the checker. Candidates carry
`expected_if_adopted`, not `expected`: the #189 rule is a freeze candidate."""
import glob
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import checker  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
CAND = os.path.join(ROOT, 'candidates-proposed')
os.makedirs(CAND, exist_ok=True)

SINK_EVIDENCE = {
    'request':    {'gated_on': None,              'present': True},
    'mcp':        {'gated_on': None,              'present': True},
    'completion': {'gated_on': None,              'present': True},
    'agent':      {'gated_on': 'read_agent',      'present': False},
    'delegation': {'gated_on': 'read_delegation', 'present': False},
    'labels':     {'gated_on': 'read_labels',     'present': False},
}
PROVENANCE = {
    'source': 'praxis-proxy/policy PR #84 (feat(audit): decision and effect auditing)',
    'observed_at': '5b76fa6f6cd64ff54d7237c2fe3166ba397d6999',
    'observed_on': '2026-09-10',
    'note': 'pre-fix behavior; PR head has since moved. No prior-art source vector, new case.',
    'authored_by': 'Levaj2000 on cosai-oasis/ws4-secure-design-agentic-systems#189, 2026-09-11T18:15Z',
}

cases = [
    {
        'id': 'CAND-COSAI-189-SINK-01',
        'status': 'candidate_against_proposed',
        'proposed_rule': 'cosai-oasis/ws4-secure-design-agentic-systems#189 freeze candidate (aeoess comment 2026-09-11T17:57Z); not normative',
        'checker_input': {
            'property': {'name': 'no_delegation_occurred', 'kind': 'narrow_absence',
                         'statement': 'the audited session contains no delegation event'},
            'evidence': SINK_EVIDENCE,
            'context': {'producer_declared_capabilities': [],   # explicit empty, not unknown
                        'evaluation_scope': 'single sink, single session'},
            'runtime_outcome': {'hash_chain': 'intact', 'signature': 'valid',
                                'carried_as': 'evidence that the records are intact, never a verdict on the property'},
        },
        'expected_if_adopted': {'verdict': 'not_established', 'unmet_obligation': 'producer_capability_coverage'},
        'provenance': PROVENANCE,
        'author_rationale': 'The declared-capabilities state establishes that production coverage for delegation was never established, so the absent block is absence of evidence, not evidence of absence.',
    },
    {
        'id': 'CAND-COSAI-189-SINK-02-COUNTERFACTUAL',
        'status': 'candidate_against_proposed',
        'proposed_rule': 'same as SINK-01',
        'checker_input': {
            'property': {'name': 'no_delegation_occurred', 'kind': 'narrow_absence',
                         'statement': 'the audited session contains no delegation event'},
            'evidence': SINK_EVIDENCE,
            'context': {'producer_declared_capabilities': ['read_delegation'],
                        'evaluation_scope': 'single sink, single session'},
            'runtime_outcome': {'hash_chain': 'intact', 'signature': 'valid'},
        },
        'expected_if_adopted': {'verdict': 'pass', 'unmet_obligation': None},
        'provenance': dict(PROVENANCE, note='Counterfactual stated by the author in the same comment: had the sink declared read_delegation and the block still been absent, the absence is evidence of absence and can support the narrow property. Hypothetical, not observed.'),
    },
    {
        'id': 'CAND-COSAI-189-SINK-03-UNKNOWN',
        'status': 'candidate_against_proposed',
        'proposed_rule': 'same as SINK-01; exercises the explicit-empty versus unknown distinction the author drew',
        'checker_input': {
            'property': {'name': 'no_delegation_occurred', 'kind': 'narrow_absence'},
            'evidence': SINK_EVIDENCE,
            'context': {'producer_declared_capabilities': None,   # unknown, not declared
                        'evaluation_scope': 'single sink, single session'},
            'runtime_outcome': {'hash_chain': 'intact', 'signature': 'valid'},
        },
        'expected_if_adopted': {'verdict': 'not_established', 'unmet_obligation': 'producer_capability_coverage'},
        'provenance': dict(PROVENANCE, note='Lab-authored variant. The author distinguished explicit empty declaration from unknown; this case fixes that an unknown declaration also fails to establish coverage. Not from the source comment.'),
    },
]

results = []
for c in cases:
    p = os.path.join(CAND, c['id'] + '.json')
    with open(p, 'w') as f:
        json.dump(c, f, indent=1, sort_keys=True); f.write('\n')
    obs = checker.evaluate(c['checker_input'])
    exp = c['expected_if_adopted']
    ok = obs['verdict'] == exp['verdict'] and obs['unmet_obligation'] == exp['unmet_obligation']
    results.append({'id': c['id'], 'status': c['status'], 'observed': obs, 'expected_if_adopted': exp,
                    'reproduced_under_proposed_rule': ok,
                    'fixture_sha256': hashlib.sha256(open(p, 'rb').read()).hexdigest()})
    print(f"{c['id']:40} {'reproduced' if ok else 'NOT_REPRODUCED'}  {obs['verdict']} / {obs['unmet_obligation']}")

with open(os.path.join(ROOT, 'results.json'), 'w') as f:
    json.dump(results, f, indent=1, sort_keys=True); f.write('\n')
sys.exit(0 if all(r['reproduced_under_proposed_rule'] for r in results) else 1)
