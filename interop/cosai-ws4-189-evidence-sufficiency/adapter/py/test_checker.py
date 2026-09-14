"""Checker regressions. These are not corpus cases."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import checker
from checker import CandidateInputError, UnsupportedVerification

SCOPE = 'single sink, single session'
COVERAGE = {'scope': SCOPE, 'status': 'established', 'basis': 'test fixture'}


def inp(delegation, declared=None, coverage=COVERAGE, prop='no_delegation_occurred',
        scope=SCOPE):
    ctx = {'producer_declared_capabilities': declared}
    if scope is not None:
        ctx['evaluation_scope'] = scope
    if coverage is not None:
        ctx['observation_coverage'] = coverage
    d = {'evidence': {'delegation': delegation}, 'context': ctx, 'runtime_outcome': {}}
    if prop is not None:
        d['property'] = {'name': prop}
    return d


def raises(exc, ci, why):
    try:
        checker.evaluate(ci)
    except exc:
        return
    except Exception as e:
        raise AssertionError(f'{why}: expected {exc.__name__}, got {type(e).__name__}: {e}')
    raise AssertionError(f'{why}: expected {exc.__name__}, got a verdict')


# --- baseline inference ---
assert checker.evaluate(inp({'present': True, 'gated_on': None, 'value': {'events': []}}))['verdict'] == 'pass'
assert checker.evaluate(inp({'present': True, 'gated_on': None, 'value': {'events': [{'kind': 'x'}]}}))['verdict'] == 'fail'
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'}, declared=[]))['verdict'] == 'not_established'
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'}, declared=['read_delegation']))['verdict'] == 'pass'

# --- the verdict vocabulary is exactly three ---
SEEN = set()
for case in [inp({'present': True, 'gated_on': None, 'value': {'events': []}}),
             inp({'present': True, 'gated_on': None, 'value': {'events': [1]}}),
             inp({'present': False, 'gated_on': 'read_delegation'}, declared=[]),
             inp({'present': False, 'gated_on': 'read_delegation'}, declared=['x'], coverage=None)]:
    SEEN.add(checker.evaluate(case)['verdict'])
assert SEEN <= {'pass', 'fail', 'not_established'}, SEEN

# --- FINDING 1 (imran-siddique, #189, 2026-09-14): a missing descriptor key is
# --- structural, never a value. Before the fix, deleting gated_on reached pass.
raises(CandidateInputError, inp({'present': False}, declared=[]), 'missing gated_on')
raises(CandidateInputError, inp({'present': False}, declared=['read_delegation']), 'missing gated_on, declared')
raises(CandidateInputError, inp({'gated_on': 'read_delegation'}, declared=[]), 'missing present')
for bad_gate in [123, [], {}, True]:
    raises(CandidateInputError, inp({'present': False, 'gated_on': bad_gate}), f'gated_on={bad_gate!r}')
# an EXPLICIT null gate is a declared descriptor and stays evaluable
assert checker.evaluate(inp({'present': False, 'gated_on': None}, declared=[]))['verdict'] == 'pass'

# --- FINDING 2: an unsupported verification path is not a verdict. It sits in the
# --- freeze candidate's sentence beside malformed input, parser failure and
# --- internal error, and it raises like they do.
raises(UnsupportedVerification, inp({'present': False, 'gated_on': None}, prop='some_other_property'),
       'unsupported property')
raises(CandidateInputError, inp({'present': False, 'gated_on': None}, prop=None), 'missing property')

# --- FINDING 3: field visibility is not interval completeness. The session-wide
# --- negative requires BOTH premises. Confirmed by imran-siddique and Levaj2000
# --- on #189: "Without it, the session-wide absence property stays not_established."
r = checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'},
                         declared=['read_delegation'], coverage=None))
assert r['verdict'] == 'not_established' and r['unmet_obligation'] == 'observation_coverage', r
# a structurally malformed descriptor is an input error, not a verdict
for bad in [{}, {'status': 'assumed'}, {'status': None}, {'established': True},
            'established', True]:
    raises(CandidateInputError, inp({'present': False, 'gated_on': 'read_delegation'},
                                    declared=['read_delegation'], coverage=bad),
           f'malformed coverage {bad!r}')
# a WELL-FORMED descriptor that is not established is a verdict
for status in ['assumed', 'established_later', 'pending', 'unknown']:
    r = checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'},
                             declared=['read_delegation'],
                             coverage={'scope': SCOPE, 'status': status}))
    assert r['unmet_obligation'] == 'observation_coverage', (status, r)
# an ungated absent field still needs interval completeness
assert checker.evaluate(inp({'present': False, 'gated_on': None}, declared=[],
                            coverage=None))['unmet_obligation'] == 'observation_coverage'
# the two premises stay distinct and capability is checked first, so its
# obligation is never masked by the completeness one
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'},
                            declared=[], coverage=None))['unmet_obligation'] == 'producer_capability_coverage'
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'},
                            declared=None, coverage=None))['unmet_obligation'] == 'producer_capability_coverage'
# both present reaches pass
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'},
                            declared=['read_delegation']))['verdict'] == 'pass'

# --- malformed present evidence remains an input error, not a verdict
for bad in [{'present': True, 'gated_on': None},
            {'present': True, 'gated_on': None, 'value': {}},
            {'present': True, 'gated_on': None, 'value': {'events': None}},
            {'present': True, 'gated_on': None, 'value': 'text'},
            {'present': 'yes', 'gated_on': 'read_delegation'}]:
    raises(CandidateInputError, inp(bad), f'malformed present {bad!r}')
raises(CandidateInputError, inp({'present': False, 'gated_on': 'read_delegation'}, declared='read_delegation'),
       'string declaration must not satisfy membership')

print('test_checker: ok (baseline, three-valued verdict, and the four #189 regressions)')

# --- SECOND ADVERSARIAL PASS. Imran's exact mutation was repaired, but the
# --- invariant behind finding 3 was still reachable two other ways.

# A. Every path to a NEGATIVE pass must require interval completeness. A present
#    delegation block with zero events is a negative just like an absent one.
r = checker.evaluate(inp({'present': True, 'gated_on': None, 'value': {'events': []}},
                         declared=['read_delegation'], coverage=None))
assert r['verdict'] == 'not_established' and r['unmet_obligation'] == 'observation_coverage', r
# but one observed event is a witness and settles the positive without completeness
r = checker.evaluate(inp({'present': True, 'gated_on': None, 'value': {'events': [{'k': 'x'}]}},
                         declared=['read_delegation'], coverage=None))
assert r['verdict'] == 'fail' and r['unmet_obligation'] is None, r
# and with coverage present the empty block reaches pass
assert checker.evaluate(inp({'present': True, 'gated_on': None, 'value': {'events': []}},
                            declared=['read_delegation']))['verdict'] == 'pass'

# B. The completeness premise must be bound to the evaluated interval.
raises(CandidateInputError, inp({'present': False, 'gated_on': 'read_delegation'},
                                declared=['read_delegation'],
                                coverage={'status': 'established'}),
       'coverage without scope')
raises(CandidateInputError, inp({'present': False, 'gated_on': 'read_delegation'},
                                declared=['read_delegation'],
                                coverage={'scope': SCOPE}),
       'coverage without status')
raises(CandidateInputError, inp({'present': False, 'gated_on': 'read_delegation'},
                                declared=['read_delegation'], coverage='established'),
       'coverage not an object')
r = checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'},
                         declared=['read_delegation'],
                         coverage={'scope': 'one invocation', 'status': 'established'}))
assert r['verdict'] == 'not_established' and r['unmet_obligation'] == 'observation_coverage', r

# C. The evaluated interval itself must be declared, or the premise is unbound.
raises(CandidateInputError, inp({'present': False, 'gated_on': 'read_delegation'},
                                declared=['read_delegation'], scope=None),
       'missing evaluation_scope')
raises(CandidateInputError, inp({'present': False, 'gated_on': 'read_delegation'},
                                declared=['read_delegation'], scope=''),
       'empty evaluation_scope')

# D. Matching scope reaches pass.
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'},
                            declared=['read_delegation'],
                            coverage={'scope': SCOPE, 'status': 'established'}))['verdict'] == 'pass'

print('test_checker: ok (second adversarial pass: no-event paths and scope binding)')
