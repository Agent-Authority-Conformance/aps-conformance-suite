"""Checker regressions. These are not corpus cases."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import checker

def inp(delegation, declared=None):
    return {'property': {'name': 'no_delegation_occurred'},
            'evidence': {'delegation': delegation},
            'context': {'producer_declared_capabilities': declared},
            'runtime_outcome': {}}

assert checker.evaluate(inp({'present': True, 'value': {'events': []}}))['verdict'] == 'pass'
assert checker.evaluate(inp({'present': True, 'value': {'events': [{'kind': 'x'}]}}))['verdict'] == 'fail'
for bad in [{'present': True}, {'present': True, 'value': {}}, {'present': True, 'value': {'events': None}},
            {'present': True, 'value': 'text'}, {'present': 'yes', 'gated_on': 'read_delegation'}]:
    try:
        checker.evaluate(inp(bad)); raise AssertionError('malformed present evidence must not yield a verdict: %r' % bad)
    except ValueError:
        pass
try:
    checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'}, declared='read_delegation'))
    raise AssertionError('string declaration must not satisfy membership')
except ValueError:
    pass
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'}, declared=[]))['verdict'] == 'not_established'
assert checker.evaluate(inp({'present': False, 'gated_on': 'read_delegation'}, declared=['read_delegation']))['verdict'] == 'pass'
print('test_checker: ok')
