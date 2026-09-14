"""Candidate cases for the #189 freeze candidate. Candidates carry `expected_if_adopted`,
not `expected`: the rule is proposed, not normative.

TWO MODES, and verification never writes to the committed tree.

  python3 run.py --generate   write the fixtures and results.json
  python3 run.py              VERIFY: read the committed fixtures read-only, regenerate
                              into scratch and diff, run the checker, compare against the
                              committed expectations, and exit nonzero on any mismatch.

The previous single mode regenerated the fixtures before evaluating them, so altering a
committed expectation was silently repaired and the run still exited 0. Reported by
imran-siddique on cosai-oasis/ws4-secure-design-agentic-systems#189, 2026-09-14."""
import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile

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
                        'evaluation_scope': 'single sink, single session',
                        # The second premise. Field visibility is not interval
                        # completeness, and the session-wide negative needs both.
                        # ASSUMED by this counterfactual, not observed in the
                        # incident; establishing it belongs to a separate
                        # verifier surface, never to this checker.
                        # `scope` must equal `evaluation_scope`: a completeness
                        # premise that names a different interval cannot
                        # authorise a negative over the evaluated one.
                        'observation_coverage': {
                            'scope': 'single sink, single session',
                            'status': 'established',
                            'basis': 'assumed by this counterfactual; establishment belongs to a separate verifier surface'}},
            'runtime_outcome': {'hash_chain': 'intact', 'signature': 'valid'},
        },
        'expected_if_adopted': {'verdict': 'pass', 'unmet_obligation': None},
        'provenance': dict(PROVENANCE, note='Counterfactual stated by the author in the same comment: had the sink declared read_delegation and the block still been absent, the absence is evidence of absence and can support the narrow property. Hypothetical, not observed. Carries the session observation-coverage premise as ASSUMED after imran-siddique and Levaj2000 established on #189 that a declared capability is field visibility and not interval completeness.'),
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

MODE = '--generate' if '--generate' in sys.argv else 'verify'


def build(case, outdir):
    """Serialise one case deterministically. Returns (path, bytes)."""
    p = os.path.join(outdir, case['id'] + '.json')
    blob = (json.dumps(case, indent=1, sort_keys=True) + '\n').encode()
    with open(p, 'wb') as f:
        f.write(blob)
    return p, blob


def evaluate_all(read_from):
    """Run the checker over the fixtures AS THEY EXIST at `read_from`. The committed
    fixture is the input, never something this function just rewrote."""
    out = []
    for case in cases:
        path = os.path.join(read_from, case['id'] + '.json')
        with open(path, 'rb') as f:
            blob = f.read()
        onfile = json.loads(blob)
        obs = checker.evaluate(onfile['checker_input'])
        exp = onfile['expected_if_adopted']
        ok = obs['verdict'] == exp['verdict'] and obs['unmet_obligation'] == exp['unmet_obligation']
        out.append({'id': onfile['id'], 'status': onfile['status'], 'observed': obs,
                    'expected_if_adopted': exp, 'reproduced_under_proposed_rule': ok,
                    'fixture_sha256': hashlib.sha256(blob).hexdigest()})
    return out


if MODE == '--generate':
    for c in cases:
        build(c, CAND)
    results = evaluate_all(CAND)
    with open(os.path.join(ROOT, 'results.json'), 'w') as f:
        json.dump(results, f, indent=1, sort_keys=True); f.write('\n')
    for r in results:
        print(f"{r['id']:40} generated  {r['observed']['verdict']} / {r['observed']['unmet_obligation']}")
    sys.exit(0 if all(r['reproduced_under_proposed_rule'] for r in results) else 1)

# ---- verify mode: READ-ONLY over the committed tree ----
failures = []

# (0) the candidate set must be EXACTLY the expected ids. Checking only that the
#     known cases are present lets an unverified fixture be dropped into the
#     directory and go unexamined, which is the invariant imran-siddique's
#     proposed check.py enforces on #91.
expected_ids = {c['id'] for c in cases}
present_ids = {os.path.splitext(f)[0] for f in os.listdir(CAND) if f.endswith('.json')}
for extra in sorted(present_ids - expected_ids):
    failures.append(f'{extra}: unexpected candidate file in candidates-proposed/, '
                    'not one of the declared cases')
for missing in sorted(expected_ids - present_ids):
    failures.append(f'{missing}: declared candidate file is missing')

# (a) regenerate into scratch and diff against the committed bytes. A committed fixture
#     that differs from what the generator would produce is a failure, never a repair.
scratch = tempfile.mkdtemp(prefix='cosai189-')
for c in cases:
    _, fresh = build(c, scratch)
    committed_path = os.path.join(CAND, c['id'] + '.json')
    if not os.path.exists(committed_path):
        failures.append(f"{c['id']}: committed fixture missing"); continue
    with open(committed_path, 'rb') as f:
        committed = f.read()
    if committed != fresh:
        failures.append(f"{c['id']}: committed fixture differs from regenerated bytes "
                        f"(committed sha256 {hashlib.sha256(committed).hexdigest()[:16]}, "
                        f"regenerated {hashlib.sha256(fresh).hexdigest()[:16]})")
shutil.rmtree(scratch, ignore_errors=True)

# (b) run the checker over the committed fixtures and compare to their committed expectations
results = evaluate_all(CAND)
for r in results:
    mark = 'reproduced' if r['reproduced_under_proposed_rule'] else 'NOT_REPRODUCED'
    print(f"{r['id']:40} {mark}  {r['observed']['verdict']} / {r['observed']['unmet_obligation']}")
    if not r['reproduced_under_proposed_rule']:
        failures.append(f"{r['id']}: observed {r['observed']['verdict']}/"
                        f"{r['observed']['unmet_obligation']} != expected "
                        f"{r['expected_if_adopted']['verdict']}/{r['expected_if_adopted']['unmet_obligation']}")

# (c) committed results.json must match what the committed fixtures produce
rp = os.path.join(ROOT, 'results.json')
if os.path.exists(rp):
    with open(rp, 'rb') as f:
        committed_results = f.read()
    fresh_results = (json.dumps(results, indent=1, sort_keys=True) + '\n').encode()
    if committed_results != fresh_results:
        failures.append('results.json differs from what the committed fixtures produce')
else:
    failures.append('results.json missing')

if failures:
    print('\nVERIFY FAILED:')
    for f_ in failures:
        print('  -', f_)
    sys.exit(1)
print('\nverify: committed fixtures, expectations and results.json all agree')
sys.exit(0)
