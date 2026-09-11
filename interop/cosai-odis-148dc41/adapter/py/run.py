import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import odis  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
CORPUS = os.path.join(ROOT, 'corpus')
CAND = os.path.join(ROOT, 'candidates-proposed')
os.makedirs(CORPUS, exist_ok=True)
os.makedirs(CAND, exist_ok=True)

PROFILE_REF = {'uri': odis.LAB_PROFILE['uri'], 'digest': odis.LAB_PROFILE_DIGEST}

OAR = {   # 6.3: MUST object. Grant expiry is not earlier than any delegation expiry below.
    'issuer': 'https://idp.lab.example',
    'subject': 'urn:principal:alice',
    'audience': 'https://l2.lab.example',
    'grant_id': 'urn:grant:9b2e1c7a-4d3f-4a8e-9f1b-2c6d8e0a1b3c',
    'issued_at': '2026-09-11T19:00:00Z',
    'expires_at': '2026-09-12T19:00:00Z',
}

root = {
    'delegation_id': '2f5c7a9e-1b3d-4e6f-8a0c-1d2e3f4a5b6c',   # fixed 128-bit fixture id
    'issuer': 'https://l2.lab.example',
    'originating_principal': 'urn:principal:alice',
    'originating_authorization_ref': OAR,
    'actor': 'urn:agent:coordinator',
    'delegation_chain': [],
    'task_id': 'task-0001',
    'granted_authorizations': ['calendar.read', 'calendar.write', 'mail.send'],
    'resource_indicators': ['https://cal.example', 'https://mail.example'],
    'constraints': {'max_amount': 100, 'max_depth': 3},
    'attenuation_profile_ref': PROFILE_REF,
    'issued_at': '2026-09-11T20:00:00Z',
    'expires_at': '2026-09-11T21:00:00Z',
}


def child_of(parent, **over):
    c = {
        'delegation_id': '7e1a4c2b-9d8f-4b3e-a6c5-0f1e2d3c4b5a',   # fixed 128-bit fixture id
        'issuer': parent['issuer'],
        'parent_delegation_ref': {'issuer': parent['issuer'], 'delegation_id': parent['delegation_id'],
                                  'record_digest': odis.record_digest(parent)},
        'originating_principal': parent['originating_principal'],
        'originating_authorization_ref': parent['originating_authorization_ref'],
        'actor': 'urn:agent:worker',
        'delegation_chain': [{'issuer': parent['issuer'], 'delegation_id': parent['delegation_id'],
                              'record_digest': odis.record_digest(parent)}],
        'task_id': parent['task_id'],
        'granted_authorizations': ['calendar.read'],
        'resource_indicators': ['https://cal.example'],
        'constraints': {'max_amount': 50, 'max_depth': 3},
        'attenuation_profile_ref': PROFILE_REF,
        'issued_at': '2026-09-11T20:05:00Z',
        'expires_at': '2026-09-11T20:30:00Z',
    }
    c.update(over)
    return c


def emit(dirpath, fx):
    p = os.path.join(dirpath, fx['id'] + '.json')
    with open(p, 'w') as f:
        json.dump(fx, f, indent=1, sort_keys=True); f.write('\n')
    return p


# ---------------------------------------------------------------- normative (6.3 / L2-06)
fixtures = []
fixtures.append({'id': 'ODIS-ATT-00', 'variant': 'positive', 'parents': [root], 'child': child_of(root),
                 'normative': ['6.3: equal to or narrower than the immediate parent under attenuation_profile_ref'],
                 'expected': {'result': 'pass'}})
fixtures.append({'id': 'ODIS-ATT-01', 'variant': 'negative', 'parents': [root],
                 'child': child_of(root, granted_authorizations=['calendar.read', 'files.delete']),
                 'normative': ['6.3: delegation_chain[N].granted_authorizations is a semantic subset of delegation_chain[N-1].granted_authorizations',
                               'L2-06: the sub-agent MUST receive authority equal to or narrower than its parent'],
                 'mutation': 'child grants files.delete, absent from parent',
                 'expected': {'result': 'fail_closed', 'check': 'attenuation'}})
fixtures.append({'id': 'ODIS-ATT-02', 'variant': 'negative', 'parents': [root],
                 'child': child_of(root, expires_at='2026-09-11T22:00:00Z'),
                 'normative': ['6.3: expires_at <= parent.expires_at (child delegations cannot outlive parents)',
                               '6.3 Delegation Record table: expires_at MUST NOT exceed the parent delegation\'s expiry'],
                 'mutation': 'child expires 22:00, parent 21:00',
                 'expected': {'result': 'fail_closed', 'check': 'expiry'}})
tampered_root = copy.deepcopy(root); tampered_root['granted_authorizations'].append('files.delete')
fixtures.append({'id': 'ODIS-ATT-03', 'variant': 'negative', 'parents': [tampered_root], 'child': child_of(root),
                 'normative': ['6.3: a verifier MUST resolve the parent by issuer and delegation_id and MUST confirm that its digest equals record_digest',
                               '6.3: a ... mismatched record MUST cause chain validation to fail closed'],
                 'mutation': 'the record resolved as parent differs from the one the child\'s record_digest was computed over',
                 'expected': {'result': 'fail_closed', 'check': 'parent_digest'}})
fixtures.append({'id': 'ODIS-ATT-04', 'variant': 'negative', 'parents': [root],
                 'child': child_of(root, attenuation_profile_ref={'uri': 'urn:vendor:profile:opaque:v9', 'digest': 'sha256:' + '0' * 64}),
                 'normative': ['L2-06: unknown, lossy, unsupported, or indeterminate comparisons MUST fail closed',
                               '6.3: an unresolved, ambiguous, cyclic, lossy, or indeterminate parent comparison MUST fail closed'],
                 'mutation': 'child names an attenuation_profile_ref the verifier does not hold; the authorization sets are otherwise a clean subset',
                 'expected': {'result': 'fail_closed', 'check': 'profile'},
                 'note': 'Tests the behavior the text already fixes. It does not ask whether unavailable, unsupported and indeterminate should be distinguished in the result; that is a diagnostic taxonomy question, not a behavior question.'})

results = []
for fx in fixtures:
    p = emit(CORPUS, fx)
    obs = odis.validate_non_root(fx['child'], fx['parents'])
    exp = fx['expected']
    ok = obs['result'] == exp['result'] and (exp['result'] == 'pass' or obs['check'] == exp['check'])
    results.append({'id': fx['id'], 'variant': fx['variant'], 'expected': exp, 'observed': obs,
                    'status': 'reproduced' if ok else 'NOT_REPRODUCED',
                    'fixture_sha256': hashlib.sha256(open(p, 'rb').read()).hexdigest()})

# ---------------------------------------------------------------- candidates against PROPOSED text (issues #5, #6)
# These are NOT ODIS conformance cases. They encode requirements proposed in
# open issues with zero comments as of 2026-09-11 and are kept apart so they
# cannot be read as current normative semantics.
candidates = [
    {'id': 'CAND-ODIS-6-AGENTID-UNIQ', 'status': 'candidate_against_proposed', 'source': 'cosai-oasis/ws4-odis#6 (open, author szh, 2026-08-04)',
     'proposed_text': 'The issuer MUST verify that agent_id resolves to exactly one active Agent Registration Record within the trust domain. If resolution returns more than one record ... issuance MUST fail closed.',
     'input': {'agent_id': 'arn:aws:iam::123456789012:role/SharedRole',
               'registration_records': [{'agent_id': 'arn:aws:iam::123456789012:role/SharedRole', 'record_id': 'reg-1', 'status': 'active'},
                                        {'agent_id': 'arn:aws:iam::123456789012:role/SharedRole', 'record_id': 'reg-2', 'status': 'active'}]},
     'expected_if_adopted': {'result': 'fail_closed', 'check': 'agent_id_resolution'},
     'current_normative_status': 'Not required by ODIS.md at the pinned revision. 6.1 defines agent_id as a stable logical agent identifier with no uniqueness constraint.'},
    {'id': 'CAND-ODIS-5-VERIFICATION-METHOD', 'status': 'candidate_against_proposed', 'source': 'cosai-oasis/ws4-odis#5 (open, author szh, 2026-08-04)',
     'proposed_text': 'When attestation_evidence includes a platform-provisioned credential, the descriptor MUST carry verification_method',
     'input': {'attestation_evidence': [{'type': 'platform_provisioned', 'platform': 'example-cloud', 'token_ref': 'opaque'}],
               'verification_method': None},
     'expected_if_adopted': {'result': 'fail_closed', 'check': 'verification_method_absent'},
     'current_normative_status': 'Not required by ODIS.md at the pinned revision. 6.2 defines no verification_method field.'},
]
for c in candidates:
    emit(CAND, c)

out = os.path.join(ROOT, 'results.json')
json.dump(results, open(out, 'w'), indent=1, sort_keys=True); open(out, 'a').write('\n')
for r in results:
    print(f"{r['id']:14} {r['variant']:9} {r['status']}  {r['observed']['reason']}")
print('profile digest:', odis.LAB_PROFILE_DIGEST)
sys.exit(1 if any(r['status'] != 'reproduced' for r in results) else 0)
