"""Checker regressions for the CoSAI #149 decision-to-effect corpus. These are
not corpus cases. Includes the adversarial pass performed before commit: for
every negative/not_established case, an attempt to flip it to `pass` by
deleting or mutating exactly one field. Every attempt below is asserted to end
in fail, not_established, or a structural error -- never pass.
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import checker
from checker import CandidateInputError, UnsupportedVerification

SCOPE = 'evaluated scope'
CLAIM = 'claim-a'


def admission(action_id='act-1', args_digest='sha256:orig', tool='t', decision='authorized'):
    return {'action_id': action_id, 'tool': tool, 'args_digest': args_digest, 'decision': decision}


def closure(ref='act-1', dispatch=None, self_report=None, read_back=None, credential_use=None):
    d = {
        'ref': ref,
        'dispatch': dispatch or {'status': 'dispatched', 'args_digest': 'sha256:orig'},
        'tool_self_report': self_report or {'status': 'success'},
        'read_back': read_back or {'status': 'agrees', 'observed_digest': 'sha256:orig'},
    }
    if credential_use is not None:
        d['credential_use'] = credential_use
    return d


def ctx(scope=SCOPE, claim=None, coverage=None):
    c = {'evaluation_scope': scope}
    if claim is not None:
        c['claim_ref'] = claim
    if coverage is not None:
        c['observation_coverage'] = coverage
    return c


def inp(prop, adm, clo, context, runtime_outcome=None):
    d = {'property': {'name': prop}, 'evidence': {'admission': adm, 'closure': clo}, 'context': context}
    if runtime_outcome is not None:
        d['runtime_outcome'] = runtime_outcome
    return d


def raises(exc, ci, why):
    try:
        checker.evaluate(ci)
    except exc:
        return
    except Exception as e:
        raise AssertionError(f'{why}: expected {exc.__name__}, got {type(e).__name__}: {e}')
    raise AssertionError(f'{why}: expected {exc.__name__}, got a verdict')


def not_pass(ci, why):
    """Used throughout the adversarial pass: the observed result must never be
    a verdict of pass, whether that is fail, not_established, or a raise."""
    try:
        r = checker.evaluate(ci)
    except (CandidateInputError, UnsupportedVerification):
        return
    assert r['verdict'] != 'pass', f'{why}: reached pass, expected fail/not_established/structural-error: {r}'
    return r


# =========================== exact_call: baseline ===========================
assert checker.evaluate(inp('exact_call', admission(),
    closure(dispatch={'status': 'dispatched', 'args_digest': 'sha256:orig'}), ctx()))['verdict'] == 'pass'
assert checker.evaluate(inp('exact_call', admission(),
    closure(dispatch={'status': 'dispatched', 'args_digest': 'sha256:MUTATED'}), ctx()))['verdict'] == 'fail'
assert checker.evaluate(inp('exact_call', admission(),
    closure(dispatch={'status': 'refused',
                       'refusal': {'reason': 'r', 'attributed_cause': 'args_mismatch'}}),
    ctx()))['verdict'] == 'pass'
r = checker.evaluate(inp('exact_call', admission(),
    closure(dispatch={'status': 'refused',
                       'refusal': {'reason': 'r', 'attributed_cause': 'rate_limited'}}),
    ctx()))
assert r['verdict'] == 'not_established' and r['unmet_obligation'] == 'refusal_attribution', r

# =========================== effect_verified: baseline ===========================
assert checker.evaluate(inp('effect_verified', admission(),
    closure(read_back={'status': 'agrees', 'observed_digest': 'x'}), ctx()))['verdict'] == 'pass'
assert checker.evaluate(inp('effect_verified', admission(),
    closure(read_back={'status': 'disagrees', 'observed_digest': 'x'}), ctx()))['verdict'] == 'fail'
r = checker.evaluate(inp('effect_verified', admission(),
    closure(read_back={'status': 'unavailable', 'reason': 'timeout'}), ctx()))
assert r['verdict'] == 'not_established' and r['unmet_obligation'] == 'read_back', r

# =========================== non_bypassability: baseline ===========================
COVERED = {'status': 'established', 'scope': SCOPE, 'claim_ref': CLAIM}
GOVERNED = {'credential': 'c', 'path': 'governed', 'admission_ref': 'act-1'}
ALT_UNCOVERED = {'credential': 'c', 'path': 'alternate', 'admission_ref': None}

r = checker.evaluate(inp('non_bypassability', admission(),
    closure(credential_use=GOVERNED), ctx(claim=CLAIM, coverage=COVERED)))
assert r['verdict'] == 'pass', r
r = checker.evaluate(inp('non_bypassability', admission(),
    closure(credential_use=GOVERNED), ctx()))
assert r['verdict'] == 'not_established' and r['unmet_obligation'] == 'observation_coverage', r
r = checker.evaluate(inp('non_bypassability', None,
    closure(credential_use=ALT_UNCOVERED), ctx()))
assert r['verdict'] == 'fail' and r['unmet_obligation'] is None, r

# =========================== the verdict vocabulary is exactly three ===========================
SEEN = set()
for r in [
    checker.evaluate(inp('exact_call', admission(), closure(), ctx())),
    checker.evaluate(inp('exact_call', admission(),
        closure(dispatch={'status': 'dispatched', 'args_digest': 'x'}), ctx())),
    checker.evaluate(inp('effect_verified', admission(),
        closure(read_back={'status': 'unavailable', 'reason': 'r'}), ctx())),
    checker.evaluate(inp('non_bypassability', None, closure(credential_use=ALT_UNCOVERED), ctx())),
]:
    SEEN.add(r['verdict'])
assert SEEN <= {'pass', 'fail', 'not_established'}, SEEN

# =========================== unsupported property / structural errors ===========================
raises(UnsupportedVerification, inp('some_other_property', admission(), closure(), ctx()),
       'unsupported property')
raises(CandidateInputError, {'evidence': {'admission': None, 'closure': closure()}, 'context': ctx()},
       'missing property')
raises(CandidateInputError, inp('exact_call', admission(), closure(), ctx()) | {'property': {}},
       'property without name')

# evidence / admission structural errors
raises(CandidateInputError, {'property': {'name': 'exact_call'}, 'context': ctx(),
                              'evidence': {'closure': closure()}},
       "evidence missing the 'admission' key entirely (vs explicit null)")
raises(CandidateInputError, inp('exact_call', {'tool': 't'}, closure(), ctx()),
       'admission missing action_id')
raises(CandidateInputError, inp('exact_call', 'not-a-dict', closure(), ctx()),
       'admission not an object')

# closure structural errors
raises(CandidateInputError, {'property': {'name': 'exact_call'}, 'context': ctx(),
                              'evidence': {'admission': admission(), 'closure': None}},
       'closure is null')
raises(CandidateInputError, inp('exact_call', admission(), {'ref': 'x'}, ctx()),
       'closure missing dispatch')
raises(CandidateInputError, inp('exact_call', admission(),
                                 closure(dispatch={'status': 'dispatched'}), ctx()),
       'dispatched closure missing args_digest')
raises(CandidateInputError, inp('exact_call', admission(),
                                 closure(dispatch={'status': 'refused', 'refusal': {'reason': 'r'}}),
                                 ctx()),
       'refused closure missing attributed_cause')
raises(CandidateInputError, inp('exact_call', admission(),
                                 closure(dispatch={'status': 'refused'}), ctx()),
       'refused closure missing refusal object entirely')
raises(CandidateInputError, inp('exact_call', admission(),
                                 closure(dispatch={'status': 'sideways', 'args_digest': 'x'}), ctx()),
       'dispatch status neither dispatched nor refused')
raises(CandidateInputError, inp('effect_verified', admission(),
                                 closure(read_back={'status': 'unavailable'}), ctx()),
       'read_back unavailable missing reason')
raises(CandidateInputError, inp('effect_verified', admission(),
                                 closure(read_back={'status': 'unavailable', 'reason': ''}), ctx()),
       'read_back unavailable with a blank reason')
raises(CandidateInputError, inp('effect_verified', admission(),
                                 closure(read_back={'status': 'agrees'}), ctx()),
       'read_back agrees missing observed_digest')
raises(CandidateInputError, inp('non_bypassability', admission(),
                                 closure(credential_use={'credential': 'c', 'path': 'governed'}),
                                 ctx()),
       'credential_use missing admission_ref key')
raises(CandidateInputError, inp('non_bypassability', admission(),
                                 closure(credential_use={'credential': 'c', 'path': 'sideways',
                                                          'admission_ref': None}), ctx()),
       'credential_use.path neither governed nor alternate')
raises(CandidateInputError, inp('non_bypassability', admission(), closure(), ctx()),
       'non_bypassability with no credential_use at all')

# context structural errors
raises(CandidateInputError, inp('exact_call', admission(), closure(), {}),
       'context missing evaluation_scope')
raises(CandidateInputError, inp('exact_call', admission(), closure(), {'evaluation_scope': ''}),
       'context with a blank evaluation_scope')
raises(CandidateInputError, inp('non_bypassability', admission(),
                                 closure(credential_use=GOVERNED),
                                 ctx(coverage={'status': 'established', 'scope': SCOPE})),
       'observation_coverage missing claim_ref')
raises(CandidateInputError, inp('non_bypassability', admission(),
                                 closure(credential_use=GOVERNED),
                                 ctx(coverage={'status': 'established', 'claim_ref': CLAIM})),
       'observation_coverage missing scope')
raises(CandidateInputError, inp('non_bypassability', admission(),
                                 closure(credential_use=GOVERNED),
                                 {'evaluation_scope': SCOPE,
                                  'observation_coverage': {'status': 'established', 'scope': SCOPE,
                                                            'claim_ref': CLAIM}}),
       'observation_coverage supplied but context.claim_ref is absent')

# runtime_outcome must be an object, never a bare value mimicking a verdict
raises(CandidateInputError, inp('effect_verified', admission(),
                                 closure(read_back={'status': 'unavailable', 'reason': 'r'}),
                                 ctx(), runtime_outcome='not_established'),
       'runtime_outcome supplied as a bare string mimicking the verdict')
raises(CandidateInputError, inp('effect_verified', admission(),
                                 closure(read_back={'status': 'unavailable', 'reason': 'r'}),
                                 ctx(), runtime_outcome='EFFECT_INDETERMINATE'),
       'runtime_outcome supplied as a bare status string')

# non_bypassability: a 'governed' claim that does not resolve to a covering
# admission is malformed, not a lesser verdict -- see adversarial pass below
# for why this must not become an escape from `fail`.
raises(CandidateInputError, inp('non_bypassability', None,
                                 closure(credential_use={'credential': 'c', 'path': 'governed',
                                                          'admission_ref': 'act-1'}), ctx()),
       "credential_use.path 'governed' with no admission at all")
raises(CandidateInputError, inp('non_bypassability', admission(action_id='act-OTHER'),
                                 closure(credential_use={'credential': 'c', 'path': 'governed',
                                                          'admission_ref': 'act-1'}), ctx()),
       "credential_use.path 'governed' with admission_ref not matching the supplied admission")

print('test_checker: ok (baseline, three-valued verdict, structural errors)')

# =========================================================================
# ADVERSARIAL PASS. For every negative/not_established corpus case, an
# attempt to reach `pass` by deleting or mutating exactly one field. Every
# attempt is asserted to end in fail, not_established, or a structural
# error, and each doubles as a permanent regression here.
# =========================================================================

# --- D2E-EXACT-01 (fail): dispatched with mutated args -----------------------
base = inp('exact_call', admission(args_digest='sha256:orig'),
           closure(dispatch={'status': 'dispatched', 'args_digest': 'sha256:MUTATED'}), ctx())
# Attack 1: inject a refusal object ALONGSIDE a dispatched status, hoping the
# checker keys off the mere presence of 'refusal' instead of 'status'. Must
# still be evaluated on the dispatched branch and still fail.
attacked = inp('exact_call', admission(args_digest='sha256:orig'),
               closure(dispatch={'status': 'dispatched', 'args_digest': 'sha256:MUTATED',
                                  'refusal': {'reason': 'r', 'attributed_cause': 'args_mismatch'}}),
               ctx())
r = not_pass(attacked, 'EXACT-01 attack: inject refusal object beside a dispatched status')
assert r is not None and r['verdict'] == 'fail', r
# Attack 2: delete the closure record entirely.
del_closure = {'property': {'name': 'exact_call'},
               'evidence': {'admission': admission(args_digest='sha256:orig')}, 'context': ctx()}
raises(CandidateInputError, del_closure, 'EXACT-01 attack: delete the closure record')

# --- D2E-BYPASS-01 (fail): alternate path, uncovered ------------------------
# Attack 1: relabel the alternate path as 'governed' while still supplying no
# admission at all, hoping the relabel is read at face value. Must not
# silently become fail-open pass or even a lesser not_established; a
# 'governed' claim that resolves to nothing is malformed input.
attacked = inp('non_bypassability', None,
               closure(credential_use={'credential': 'cred-shared-secret', 'path': 'governed',
                                        'admission_ref': None}), ctx())
raises(CandidateInputError, attacked, "BYPASS-01 attack: relabel 'alternate' as 'governed' with no admission")
# Attack 2: supply an admission record, but with an action_id that does not
# match admission_ref, hoping mere presence of *an* admission object is
# enough to "cover" the use.
attacked = inp('non_bypassability', admission(action_id='act-UNRELATED'),
               closure(credential_use={'credential': 'cred-shared-secret', 'path': 'alternate',
                                        'admission_ref': 'act-1'}), ctx())
r = not_pass(attacked, 'BYPASS-01 attack: unrelated admission present, ids do not match')
assert r is not None and r['verdict'] == 'fail', r

# --- D2E-BYPASS-02 (not_established): no bypass observed, coverage absent --
# Attack 1: supply observation_coverage for a DIFFERENT scope than evaluated.
attacked = inp('non_bypassability', admission(),
               closure(credential_use=GOVERNED),
               ctx(claim=CLAIM, coverage={'status': 'established', 'scope': 'a different scope',
                                          'claim_ref': CLAIM}))
r = not_pass(attacked, 'BYPASS-02 attack: coverage bound to a different scope')
assert r is not None and r['verdict'] == 'not_established' and r['unmet_obligation'] == 'observation_coverage', r
# Attack 2: coverage matches scope but status is not 'established'.
attacked = inp('non_bypassability', admission(),
               closure(credential_use=GOVERNED),
               ctx(claim=CLAIM, coverage={'status': 'assumed', 'scope': SCOPE, 'claim_ref': CLAIM}))
r = not_pass(attacked, 'BYPASS-02 attack: coverage present but not established')
assert r is not None and r['verdict'] == 'not_established' and r['unmet_obligation'] == 'observation_coverage', r

# --- D2E-POS-01-NON-BYPASSABILITY-UNCOVERED (not_established) --------------
# Attack: coverage matching scope but bound to a DIFFERENT claim than the one
# under evaluation. This is the "different claim than required" attack named
# explicitly in the spec for this corpus.
attacked = inp('non_bypassability', admission(),
               closure(credential_use=GOVERNED),
               ctx(claim=CLAIM, coverage={'status': 'established', 'scope': SCOPE,
                                          'claim_ref': 'a-different-claim'}))
r = not_pass(attacked, 'POS-01-NONBYPASS-UNCOVERED attack: coverage bound to a different claim')
assert r is not None and r['verdict'] == 'not_established' and r['unmet_obligation'] == 'observation_coverage', r
assert 'a-different-claim' in r['reason'] and CLAIM in r['reason'], r

# --- D2E-EFFECT-01 (fail): self-report success, read-back disagrees --------
# Attack 1: delete observed_digest from a disagreeing read-back.
attacked = inp('effect_verified', admission(),
               closure(read_back={'status': 'disagrees'}), ctx())
raises(CandidateInputError, attacked, 'EFFECT-01 attack: delete observed_digest from a disagreeing read-back')
# Attack 2: delete tool_self_report entirely.
c = closure(read_back={'status': 'disagrees', 'observed_digest': 'x'})
del c['tool_self_report']
attacked = {'property': {'name': 'effect_verified'}, 'evidence': {'admission': admission(), 'closure': c},
            'context': ctx()}
raises(CandidateInputError, attacked, 'EFFECT-01 attack: delete tool_self_report entirely')

# --- D2E-EFFECT-02 (not_established): read-back unavailable ----------------
# Attack 1: blank the read-back-unavailable reason.
attacked = inp('effect_verified', admission(),
               closure(read_back={'status': 'unavailable', 'reason': ''}), ctx())
raises(CandidateInputError, attacked, 'EFFECT-02 attack: blank the read-back-unavailable reason')
# Attack 2: delete the reason key entirely.
attacked = inp('effect_verified', admission(),
               closure(read_back={'status': 'unavailable'}), ctx())
raises(CandidateInputError, attacked, 'EFFECT-02 attack: delete the read-back-unavailable reason key')
# Attack 3: sneak an observed_digest into an 'unavailable' read-back, hoping
# its mere presence is read as agreement.
attacked = inp('effect_verified', admission(),
               closure(read_back={'status': 'unavailable', 'reason': 'timeout',
                                   'observed_digest': 'sha256:orig'}), ctx())
r = not_pass(attacked, "EFFECT-02 attack: sneak observed_digest into an 'unavailable' read-back")
assert r is not None and r['verdict'] == 'not_established' and r['unmet_obligation'] == 'read_back', r

# --- D2E-EFFECT-03 (not_established): EFFECT_INDETERMINATE carried as evidence
# Attack 1: sneak runtime_outcome in AS IF it were the verdict (bare string).
attacked = inp('effect_verified', admission(),
               closure(read_back={'status': 'unavailable', 'reason': 'indeterminate at runtime'}),
               ctx(), runtime_outcome='not_established')
raises(CandidateInputError, attacked, 'EFFECT-03 attack: runtime_outcome as a bare verdict-shaped string')
# Attack 2: runtime_outcome FALSELY claims success while read_back stays
# unavailable. The property verdict must come only from read_back, never
# leak in from runtime_outcome, so this must still be not_established.
attacked = inp('effect_verified', admission(),
               closure(read_back={'status': 'unavailable', 'reason': 'indeterminate at runtime'}),
               ctx(), runtime_outcome={'status': 'EFFECT_SUCCESS'})
r = not_pass(attacked, 'EFFECT-03 attack: runtime_outcome falsely claims EFFECT_SUCCESS')
assert r is not None and r['verdict'] == 'not_established' and r['unmet_obligation'] == 'read_back', r
# Attack 3: delete runtime_outcome entirely -- verdict must be unchanged,
# confirming it is purely optional evidence and never load-bearing.
attacked = inp('effect_verified', admission(),
               closure(read_back={'status': 'unavailable', 'reason': 'indeterminate at runtime'}), ctx())
r = checker.evaluate(attacked)
assert r['verdict'] == 'not_established' and r['unmet_obligation'] == 'read_back', r

print('test_checker: ok (adversarial pass: every attempt ended in fail, not_established, or a structural error)')
