"""Candidate cases for the CoSAI WS4 #149 decision-to-effect corpus. Candidates
carry `expected_if_adopted`, not `expected`: the properties are proposed on an
open RFC (#149 scope plus the #189 freeze-candidate verdict rule), not
normative, and nothing here is a conformance case.

TWO MODES, and verification never writes to the committed tree.

  python3 run.py --generate   write the fixtures and results.json
  python3 run.py              VERIFY: read the committed fixtures read-only, regenerate
                              into scratch and diff, run the checker, compare against the
                              committed expectations, and exit nonzero on any mismatch.

Same read-only-by-default discipline as interop/cosai-ws4-189-evidence-sufficiency/adapter/py/run.py,
adopted after imran-siddique reported on cosai-oasis/ws4-secure-design-agentic-systems#189
(2026-09-14) that a harness which regenerates before grading can silently repair
the artifact it is supposed to be checking.
"""
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

PROPOSED_RULE = (
    'cosai-oasis/ws4-secure-design-agentic-systems#149 agreed scope '
    '(imran-siddique 2026-09-09T04:01Z; aeoess 2026-09-09T04:50Z and 20:38Z and 23:07Z; '
    'Levaj2000 2026-09-09T21:13Z; darklordVirtual 2026-09-09T22:27Z) plus the #189 '
    'freeze-candidate verdict rule (aeoess 2026-09-11T17:57Z, refined through 2026-09-19); '
    'not normative'
)

REMORA_V02 = {
    'source': 'darklordVirtual/REMORA-research, vector V-02 (exact-call mutation)',
    'ref': 'decision-to-effect-v1',
    'commit': 'b0e0cbee',
    'note': 'Re-expressed as a new fixture in this corpus, not copied, per the agreement on '
            '#149 (darklordVirtual 2026-09-09T22:27Z; aeoess 2026-09-09T23:07Z): treat V-02 as '
            'prior art and re-express the scenario rather than depending on the REMORA '
            'fixtures or adapter.',
}
REMORA_V13 = {
    'source': 'darklordVirtual/REMORA-research, vector V-13 (effect mismatch)',
    'ref': 'decision-to-effect-v1',
    'commit': 'b0e0cbee',
    'note': 'Re-expressed as a new fixture in this corpus, not copied. Same agreement as V-02.',
}
REMORA_V14 = {
    'source': 'darklordVirtual/REMORA-research, vector V-14 (EFFECT_INDETERMINATE runtime outcome)',
    'ref': 'decision-to-effect-v1',
    'commit': 'b0e0cbee',
    'note': 'Re-expressed as a new fixture, not copied. Pins the runtime-outcome/verdict '
            'separation: aeoess on #149 (2026-09-09T20:38Z), "EFFECT_INDETERMINATE is an '
            'expected runtime outcome and can be a matching vector result... not_established '
            'here is about whether the evidence establishes the property."',
}
NEW_BYPASS = {
    'source': None,
    'note': 'No REMORA vector expresses non_bypassability. aeoess on #149 (2026-09-09T20:38Z): '
            '"No REMORA vector currently expresses this, because its effectful adapter methods '
            'all require the handle returned by authorize." New case, lab-authored.',
}
NEW_EFFECT_UNAVAILABLE = {
    'source': None,
    'note': 'Read-back-unavailable is not one of the three REMORA vectors named on #149 (V-02, '
            'V-13, V-14 map to exact-call mutation, effect mismatch and EFFECT_INDETERMINATE '
            'respectively). New case, lab-authored, isolating the not_established/read_back '
            'path agreed on #149 between Levaj2000 and aeoess, 2026-09-09.',
}

cases = [
    # --- D2E-POS-01: positive control, one scenario, one property per file ---
    {
        'id': 'CAND-COSAI-149-D2E-POS-01-EXACT-CALL',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'exact_call', 'kind': 'decision_to_effect',
                         'statement': 'the dispatched call carries exactly the authorized arguments'},
            'evidence': {
                'admission': {'action_id': 'act-pos-01', 'tool': 'wire_transfer',
                              'args_digest': 'sha256:pos01-authorized-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-pos-01',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:pos01-authorized-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'agrees', 'observed_digest': 'sha256:pos01-authorized-args'},
                },
            },
            'context': {'evaluation_scope': 'positive control: single admission, single dispatch'},
        },
        'expected_if_adopted': {'verdict': 'pass', 'unmet_obligation': None},
        'provenance': {'source': None, 'note': 'Positive control, lab-authored.'},
        'author_rationale': 'Authorized C(args), dispatched C(args): the dispatched digest matches '
                            'the authorized digest, so exact call is preserved.',
    },
    {
        'id': 'CAND-COSAI-149-D2E-POS-01-EFFECT-VERIFIED',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'effect_verified', 'kind': 'decision_to_effect',
                         'statement': "the tool's self-report agrees with an independent read-back"},
            'evidence': {
                'admission': {'action_id': 'act-pos-01', 'tool': 'wire_transfer',
                              'args_digest': 'sha256:pos01-authorized-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-pos-01',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:pos01-authorized-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'agrees', 'observed_digest': 'sha256:pos01-authorized-args'},
                },
            },
            'context': {'evaluation_scope': 'positive control: single admission, single dispatch'},
        },
        'expected_if_adopted': {'verdict': 'pass', 'unmet_obligation': None},
        'provenance': {'source': None, 'note': 'Positive control, lab-authored. Same scenario as '
                                                'POS-01-EXACT-CALL, isolating effect_verified instead.'},
        'author_rationale': 'Read-back agrees with the self-report: the effect is verified.',
    },
    {
        'id': 'CAND-COSAI-149-D2E-POS-01-NON-BYPASSABILITY-COVERED',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'non_bypassability', 'kind': 'decision_to_effect',
                         'statement': 'the protected effect was not reached by a path that '
                                     'bypasses the authorization boundary'},
            'evidence': {
                'admission': {'action_id': 'act-pos-01', 'tool': 'wire_transfer',
                              'args_digest': 'sha256:pos01-authorized-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-pos-01',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:pos01-authorized-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'agrees', 'observed_digest': 'sha256:pos01-authorized-args'},
                    'credential_use': {'credential': 'cred-pos-01', 'path': 'governed',
                                       'admission_ref': 'act-pos-01'},
                },
            },
            'context': {
                'evaluation_scope': 'positive control: single admission, single dispatch',
                'claim_ref': 'pos01-claim-1',
                'observation_coverage': {
                    'status': 'established',
                    'scope': 'positive control: single admission, single dispatch',
                    'claim_ref': 'pos01-claim-1',
                    'basis': 'test fixture: coverage of alternate paths to cred-pos-01 stipulated '
                            'as established for this scope and this claim',
                },
            },
        },
        'expected_if_adopted': {'verdict': 'pass', 'unmet_obligation': None},
        'provenance': {'source': None, 'note': 'Positive control, lab-authored. Same scenario as '
                                                'POS-01-EXACT-CALL, isolating non_bypassability with an '
                                                'established observation-coverage premise for the '
                                                'evaluated scope and claim.'},
        'author_rationale': 'No bypass observed, and observation coverage of alternate paths is '
                            'established for the evaluated scope and bound to the evaluated claim: '
                            'the asymmetric rule from #189 lets this reach pass.',
    },
    {
        'id': 'CAND-COSAI-149-D2E-POS-01-NON-BYPASSABILITY-UNCOVERED',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'non_bypassability', 'kind': 'decision_to_effect',
                         'statement': 'the protected effect was not reached by a path that '
                                     'bypasses the authorization boundary'},
            'evidence': {
                'admission': {'action_id': 'act-pos-01', 'tool': 'wire_transfer',
                              'args_digest': 'sha256:pos01-authorized-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-pos-01',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:pos01-authorized-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'agrees', 'observed_digest': 'sha256:pos01-authorized-args'},
                    'credential_use': {'credential': 'cred-pos-01', 'path': 'governed',
                                       'admission_ref': 'act-pos-01'},
                },
            },
            'context': {'evaluation_scope': 'positive control: single admission, single dispatch'},
        },
        'expected_if_adopted': {'verdict': 'not_established', 'unmet_obligation': 'observation_coverage'},
        'provenance': {'source': None, 'note': 'Positive control, lab-authored. Same scenario as '
                                                'POS-01-NON-BYPASSABILITY-COVERED with the observation '
                                                'coverage premise withheld, showing the property is '
                                                'conditional on that premise rather than on the '
                                                'admission/dispatch/read-back agreement alone.'},
        'author_rationale': 'No bypass observed, but no observation-coverage premise is supplied: per '
                            '#189, absence of an observed bypass is not by itself evidence that no '
                            'alternate path exists.',
    },
    # --- D2E-EXACT: REMORA V-02 ---
    {
        'id': 'CAND-COSAI-149-D2E-EXACT-01',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'exact_call', 'kind': 'decision_to_effect',
                         'statement': 'the dispatched call carries exactly the authorized arguments'},
            'evidence': {
                'admission': {'action_id': 'act-exact-01', 'tool': 'wire_transfer',
                              'args_digest': 'sha256:exact01-authorized-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-exact-01',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:exact01-MUTATED-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'agrees', 'observed_digest': 'sha256:exact01-MUTATED-args'},
                },
            },
            'context': {'evaluation_scope': 'REMORA V-02: args mutated after authorization, dispatched anyway'},
        },
        'expected_if_adopted': {'verdict': 'fail', 'unmet_obligation': None},
        'provenance': REMORA_V02,
        'author_rationale': 'Args mutated after authorization, and dispatch proceeded anyway with the '
                            'mutated args: exact call is violated.',
    },
    {
        'id': 'CAND-COSAI-149-D2E-EXACT-02',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'exact_call', 'kind': 'decision_to_effect',
                         'statement': 'the dispatched call carries exactly the authorized arguments'},
            'evidence': {
                'admission': {'action_id': 'act-exact-02', 'tool': 'wire_transfer',
                              'args_digest': 'sha256:exact02-authorized-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-exact-02',
                    'dispatch': {'status': 'refused',
                                'refusal': {'reason': 'observed dispatch arguments diverge from the '
                                                      'authorized args digest',
                                           'attributed_cause': 'args_mismatch'}},
                    'tool_self_report': {'status': 'not_attempted'},
                    'read_back': {'status': 'unavailable',
                                 'reason': 'no dispatch occurred; there is no effect to read back'},
                },
            },
            'context': {'evaluation_scope': 'REMORA V-02: args mutated after authorization, dispatch '
                                            'refused citing the mismatch'},
        },
        'expected_if_adopted': {'verdict': 'pass', 'unmet_obligation': None},
        'provenance': REMORA_V02,
        'author_rationale': 'Args mutated after authorization, and dispatch was refused with the '
                            'refusal attributed to the args mismatch: exact call is upheld by the refusal.',
    },
    # --- D2E-BYPASS: no REMORA prior art ---
    {
        'id': 'CAND-COSAI-149-D2E-BYPASS-01',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'non_bypassability', 'kind': 'decision_to_effect',
                         'statement': 'the protected effect was not reached by a path that '
                                     'bypasses the authorization boundary'},
            'evidence': {
                'admission': None,
                'closure': {
                    'ref': 'closure-bypass-01',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:bypass01-effect-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'agrees', 'observed_digest': 'sha256:bypass01-effect-args'},
                    'credential_use': {'credential': 'cred-shared-secret', 'path': 'alternate',
                                       'admission_ref': None},
                },
            },
            'context': {'evaluation_scope': 'alternate path to a protected credential, no admission record'},
        },
        'expected_if_adopted': {'verdict': 'fail', 'unmet_obligation': None},
        'provenance': NEW_BYPASS,
        'author_rationale': 'The closure shows the protected credential used via an alternate path with '
                            'no admission record covering it: an observed bypass.',
    },
    {
        'id': 'CAND-COSAI-149-D2E-BYPASS-02',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'non_bypassability', 'kind': 'decision_to_effect',
                         'statement': 'the protected effect was not reached by a path that '
                                     'bypasses the authorization boundary'},
            'evidence': {
                'admission': {'action_id': 'act-bypass-02', 'tool': 'record_export',
                              'args_digest': 'sha256:bypass02-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-bypass-02',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:bypass02-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'agrees', 'observed_digest': 'sha256:bypass02-args'},
                    'credential_use': {'credential': 'cred-record-export', 'path': 'governed',
                                       'admission_ref': 'act-bypass-02'},
                },
            },
            'context': {'evaluation_scope': 'no bypass observed, alternate-path coverage not established'},
        },
        'expected_if_adopted': {'verdict': 'not_established', 'unmet_obligation': 'observation_coverage'},
        'provenance': NEW_BYPASS,
        'author_rationale': 'No bypass is observed on this closure, and no observation-coverage premise '
                            'for alternate paths is supplied: absence of an observed bypass is not by '
                            'itself evidence that no alternate path exists.',
    },
    # --- D2E-EFFECT: REMORA V-13 (01), new (02), REMORA V-14 (03) ---
    {
        'id': 'CAND-COSAI-149-D2E-EFFECT-01',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'effect_verified', 'kind': 'decision_to_effect',
                         'statement': "the tool's self-report agrees with an independent read-back"},
            'evidence': {
                'admission': {'action_id': 'act-effect-01', 'tool': 'ledger_write',
                              'args_digest': 'sha256:effect01-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-effect-01',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:effect01-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'disagrees',
                                 'observed_digest': 'sha256:effect01-actual-state-differs'},
                },
            },
            'context': {'evaluation_scope': 'REMORA V-13: tool self-report success, independent '
                                            'read-back disagrees'},
        },
        'expected_if_adopted': {'verdict': 'fail', 'unmet_obligation': None},
        'provenance': REMORA_V13,
        'author_rationale': "Tool self-report says success, but the independent read-back disagrees: "
                            "the effect is not verified.",
    },
    {
        'id': 'CAND-COSAI-149-D2E-EFFECT-02',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'effect_verified', 'kind': 'decision_to_effect',
                         'statement': "the tool's self-report agrees with an independent read-back"},
            'evidence': {
                'admission': {'action_id': 'act-effect-02', 'tool': 'ledger_write',
                              'args_digest': 'sha256:effect02-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-effect-02',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:effect02-args'},
                    'tool_self_report': {'status': 'success'},
                    'read_back': {'status': 'unavailable',
                                 'reason': 'downstream ledger read API returned 503 throughout the '
                                          'verification window'},
                },
            },
            'context': {'evaluation_scope': 'read-back could not be performed'},
        },
        'expected_if_adopted': {'verdict': 'not_established', 'unmet_obligation': 'read_back'},
        'provenance': NEW_EFFECT_UNAVAILABLE,
        'author_rationale': 'The independent read-back could not be performed at all: this is neither '
                            'a pass nor a fail, it is unestablished, with a reason attached.',
    },
    {
        'id': 'CAND-COSAI-149-D2E-EFFECT-03',
        'status': 'candidate_against_proposed',
        'proposed_rule': PROPOSED_RULE,
        'checker_input': {
            'property': {'name': 'effect_verified', 'kind': 'decision_to_effect',
                         'statement': "the tool's self-report agrees with an independent read-back"},
            'evidence': {
                'admission': {'action_id': 'act-effect-03', 'tool': 'ledger_write',
                              'args_digest': 'sha256:effect03-args', 'decision': 'authorized'},
                'closure': {
                    'ref': 'act-effect-03',
                    'dispatch': {'status': 'dispatched', 'args_digest': 'sha256:effect03-args'},
                    'tool_self_report': {'status': 'indeterminate'},
                    'read_back': {'status': 'unavailable',
                                 'reason': 'effect state was indeterminate at runtime; independent '
                                          'read-back could not resolve a value within the '
                                          'verification window'},
                },
            },
            'context': {'evaluation_scope': 'REMORA V-14: EFFECT_INDETERMINATE runtime outcome carried '
                                            'as evidence'},
            'runtime_outcome': {'status': 'EFFECT_INDETERMINATE',
                                'carried_as': 'evidence of the runtime outcome only, never a verdict '
                                              'on the property'},
        },
        'expected_if_adopted': {'verdict': 'not_established', 'unmet_obligation': 'read_back'},
        'provenance': REMORA_V14,
        'author_rationale': 'runtime_outcome EFFECT_INDETERMINATE is carried as evidence and is not '
                            'itself a verdict. The property verdict comes from read_back being '
                            'unavailable, exactly as in EFFECT-02: runtime outcome and property '
                            'verdict are kept as separate concepts.',
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
        print(f"{r['id']:50} generated  {r['observed']['verdict']} / {r['observed']['unmet_obligation']}")
    sys.exit(0 if all(r['reproduced_under_proposed_rule'] for r in results) else 1)

# ---- verify mode: READ-ONLY over the committed tree ----
failures = []

# (0) the candidate set must be EXACTLY the declared cases, so an unverified
#     fixture dropped into candidates-proposed/ cannot go unexamined.
expected_ids = {c['id'] for c in cases}
present_ids = {os.path.splitext(f)[0] for f in os.listdir(CAND) if f.endswith('.json')}
for extra in sorted(present_ids - expected_ids):
    failures.append(f'{extra}: unexpected candidate file in candidates-proposed/, '
                    'not one of the declared cases')
for missing in sorted(expected_ids - present_ids):
    failures.append(f'{missing}: declared candidate file is missing')

# (a) regenerate into scratch and diff against the committed bytes.
scratch = tempfile.mkdtemp(prefix='cosai149-')
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
    print(f"{r['id']:50} {mark}  {r['observed']['verdict']} / {r['observed']['unmet_obligation']}")
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
