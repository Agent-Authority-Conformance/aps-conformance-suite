"""Generate corpus/*.json for draft-sharif-agent-audit-trail-03.

Fixed test keys (scalar constants, not secrets) and RFC 6979 deterministic
ECDSA, so regeneration reproduces the stored corpus byte for byte.
"""
import copy
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(__file__))
import aat  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), '..', '..', 'corpus')
os.makedirs(OUT, exist_ok=True)

AGENT_SCALAR = 0x1111111111111111111111111111111111111111111111111111111111111111
RECORDER_SCALAR = 0x2222222222222222222222222222222222222222222222222222222222222222
agent_key = ec.derive_private_key(AGENT_SCALAR, ec.SECP256R1())
recorder_key = ec.derive_private_key(RECORDER_SCALAR, ec.SECP256R1())


def pem(pub):
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()


SESSION = 'a1b2c3d4-e5f6-4890-abcd-ef1234567890'
AGENT = 'urn:agent:fixture-bot.lab.example'

BASE = {
    'agent_id': AGENT,
    'agent_version': '1.0.0',
    'session_id': SESSION,
    'trust_level': 'L1',
}


def genesis():
    return dict(BASE, **{
        'record_id': 'a1000000-0000-4000-8000-000000000001',
        'timestamp': '2026-09-11T20:00:00.000Z',
        'action_type': 'lifecycle',
        'action_detail': {'event': 'session_start', 'new_state': 'active',
                          'trigger': 'fixture', 'recording_mode': 'self'},
        'outcome': 'success',
        'record_phase': 'concurrent',
        'parent_record_id': None,
        'prev_hash': None,
    })


def decision(parent, phase):
    return dict(BASE, **{
        'record_id': 'a1000000-0000-4000-8000-000000000002',
        'timestamp': '2026-09-11T20:00:00.100Z',
        'action_type': 'decision',
        'action_detail': {'decision_type': 'reject', 'policy_ref': 'fixture-policy-v1'},
        'outcome': 'denied',
        'deny_reasons': ['CAPABILITY_NOT_GRANTED'],
        'record_phase': phase,
        'parent_record_id': parent['record_id'],
        'prev_hash': aat.record_hash_hex(parent),
    })


def write(fx):
    path = os.path.join(OUT, fx['id'] + '.json')
    with open(path, 'w') as f:
        json.dump(fx, f, indent=1, sort_keys=True)
        f.write('\n')
    print('wrote', path)


agent_pub = pem(agent_key.public_key())
recorder_pub = pem(recorder_key.public_key())

# ---- pair 1: chain integrity (6.1, 6.3 step 2)
g = genesis()
g['signature'] = aat.sign_record(g, agent_key)          # 6.2
d = decision(g, 'pre_execution')                        # prev_hash covers g INCLUDING signature
d['signature'] = aat.sign_record(d, agent_key)
write({
    'id': 'AAT-CHAIN-01', 'variant': 'positive',
    'normative': ['6.1 prev_hash(N) = hex(SHA-256(JCS(record(N-1))))',
                  '6.2 note: prev_hash is computed over the COMPLETE previous record INCLUDING its signature field',
                  '6.3 step 2'],
    'records': [g, d], 'verification_key_pem': agent_pub,
    'expected': {'ok': True, 'primary': 'chain verifies'},
})
g2 = copy.deepcopy(g)
g2['action_detail']['trigger'] = 'fixture-mutated-after-child-written'
g2['signature'] = aat.sign_record(g2, agent_key)   # re-signed, so only the chain link is stale
write({
    'id': 'AAT-CHAIN-02', 'variant': 'negative',
    'normative': ['6.3 step 2c: if the values differ, the chain is broken at record N and the trail MUST be flagged as tampered'],
    'mutation': 'records[0].action_detail.trigger changed and records[0] re-signed after records[1] was written; records[1].prev_hash unchanged. Isolates 6.3 step 2c: every signature still verifies.',
    'records': [g2, copy.deepcopy(d)], 'verification_key_pem': agent_pub,
    'expected': {'ok': False, 'primary': '6.3 step 2c'},
})

# ---- pair 2: signature preimage (6.2)
s1 = genesis()
s1['signature'] = aat.sign_record(s1, agent_key)
write({
    'id': 'AAT-SIG-01', 'variant': 'positive',
    'normative': ['6.2 step 1: construct the complete audit record with all fields EXCEPT the "signature" field',
                  '6.2 step 5: IEEE P1363 fixed-length r||s, Base64url'],
    'records': [s1], 'verification_key_pem': agent_pub,
    'expected': {'ok': True, 'primary': 'signature verifies'},
})
s2 = genesis()
wrong = dict(s2, signature='')                          # preimage that INCLUDES signature:""
s2['signature'] = aat.sign_record(s2, agent_key, preimage_override=aat.jcs(wrong))
write({
    'id': 'AAT-SIG-02', 'variant': 'negative',
    'normative': ['6.2: the signing preimage omits the signature member; when verifying, the verifier MUST remove the "signature" field before computing the hash'],
    'mutation': 'signature was computed over JCS(record with signature:"" present); cryptographically valid over the wrong preimage',
    'records': [s2], 'verification_key_pem': agent_pub,
    'expected': {'ok': False, 'primary': '6.3 step 3'},
})

# ---- pair 3: denied decision phase (4.2, 6.3 step 6)
p = genesis()
pd = decision(p, 'pre_execution')
write({
    'id': 'AAT-PHASE-01', 'variant': 'positive',
    'normative': ['4.2: when action_type is "decision" and outcome is "denied", the record MUST have record_phase set to "pre_execution"',
                  '6.3 step 6', 'C.5 check 7'],
    'records': [p, pd], 'expected': {'ok': True, 'primary': 'phase consistent'},
})
p2 = genesis()
pd2 = decision(p2, 'post_execution')
write({
    'id': 'AAT-PHASE-02', 'variant': 'negative',
    'normative': ['4.2: when action_type is "decision" and outcome is "denied", the record MUST have record_phase set to "pre_execution"'],
    'mutation': 'records[1].record_phase = post_execution',
    'records': [p2, pd2], 'expected': {'ok': False, 'primary': '6.3 step 6'},
})

# ---- unresolved: independent recorder, two keys (5.2 vs 6.2 vs 6.3)
u = genesis()
u['trust_level'] = 'L2'   # 5.2: independent recording is the L2+ recommendation
u['action_detail']['recording_mode'] = 'independent'
u['action_detail']['recording_component_id'] = 'urn:gateway:recorder.lab.example'
u['recording_component'] = 'urn:gateway:recorder.lab.example'
u['signature'] = aat.sign_record(u, recorder_key)       # 5.2: recorder signs with ITS OWN key
write({
    'id': 'AAT-RECORDER-01', 'variant': 'unresolved',
    'normative': [
        '5.2: the independent component SHOULD sign records using its own key, distinct from the agent\'s key',
        '6.2 step 4: sign the hash using ECDSA P-256 with the agent\'s private key',
        '6.3 step 3: if signatures are present, verify each signature using the agent\'s public key',
        '3.2 recording_component: a URI; no signer key reference is defined on the record',
    ],
    'observation': 'Signer-key inconsistency. The record is signed per 5.2 with the recorder key. Applying 6.3 step 3 literally (agent public key) fails. Applying the recorder key succeeds. The draft does not say which key a verifier applies when recording_component is present, and defines no field from which to resolve it.',
    'records': [u],
    'agent_key_pem': agent_pub, 'recorder_key_pem': recorder_pub,
    'expected': None,
    'expected_note': 'No expected result is assigned. Assigning one would decide the signer-key inconsistency on the author\'s behalf.',
})
