#!/usr/bin/env python3
"""Drop #11 verification: receipts v2 profile + signer_independence + chain root + act-binding."""
import json, hashlib, base64, sys
import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def jcs(o):
    if isinstance(o, dict):
        return '{' + ','.join(jcs_str(k) + ':' + jcs(o[k]) for k in sorted(o)) + '}'
    if isinstance(o, list):
        return '[' + ','.join(jcs(x) for x in o) + ']'
    if isinstance(o, str):
        return jcs_str(o)
    raise ValueError(f'non-string scalar: {o!r}')

def jcs_str(s):
    return json.dumps(s, ensure_ascii=False)

def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def b64u_dec(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

def resolve_did_key(did):
    if not did.startswith('did:key:z'):
        return None, ('DID_URI_INVALID', 'not_a_did_key_z_uri')
    body = did[len('did:key:z'):]
    try:
        raw = base58.b58decode(body)
    except Exception as e:
        return None, ('DID_URI_INVALID', 'base58btc_decode')
    if len(raw) < 3 or raw[:2] != b'\xed\x01':
        return None, ('DID_URI_INVALID', 'multicodec_prefix')
    return raw[2:], None

ID_TAG = b'AGENTLAIR-RECEIPT-ID-V2\x00'
SIG_TAG = b'AGENTLAIR-RECEIPT-SIG-V2\x00'

def verify_v2(receipt, closed):
    errs = []
    keys = set(receipt.keys())
    if not keys.issubset(set(closed)):
        errs.append('PROFILE_VIOLATION')
    body0 = {k: v for k, v in receipt.items() if k not in ('receipt_id', 'signature')}
    rid = 'r2:' + b64u(hashlib.sha256(ID_TAG + jcs(body0).encode()).digest())
    if receipt.get('receipt_id') != rid:
        errs.append('RECEIPT_ID_MISMATCH')
    sig = receipt.get('signature')
    if sig is None:
        errs.append('SIGNATURE_MISSING')
        return errs, rid
    did = sig.get('signer_did')
    if did is None:
        errs.append('SIGNER_DID_MISSING')
        return errs, rid
    pub, err = resolve_did_key(did)
    if err:
        errs.append(err[0])
        return errs, rid
    env_minus_sig = {k: v for k, v in receipt.items() if k != 'signature'}
    sig_form = {'receipt': env_minus_sig, 'signer': {'signer_did': did, 'alg': sig['alg']}}
    msg = SIG_TAG + jcs(sig_form).encode()
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(b64u_dec(sig['value']), msg)
    except InvalidSignature:
        errs.append('SIGNATURE_INVALID')
    return errs, rid

import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument("receipts_fixture")
_ap.add_argument("aat_fixture")
_args = _ap.parse_args()
doc = json.load(open(_args.receipts_fixture))
closed = doc['profile']['closed_schema']
print('== RECEIPTS v2: 9 vectors ==')
allok = True
for v in doc['vectors']:
    errs, rid = verify_v2(v['receipt'], closed)
    ok = sorted(errs) == sorted(v['expected_errors'])
    allok &= ok
    print(f"  {v['id']:45s} got={sorted(errs)!s:60s} {'OK' if ok else 'MISMATCH expected ' + str(sorted(v['expected_errors']))}")
print('VECTORS:', 'ALL MATCH' if allok else 'MISMATCH')

print('== signer_independence, re-run from published bytes ==')
si = doc['signer_independence']
ra, rb = si['receipt_a'], si['receipt_b']
def v2_id(env):
    body0 = {k: v for k, v in env.items() if k not in ('receipt_id', 'signature')}
    return 'r2:' + b64u(hashlib.sha256(ID_TAG + jcs(body0).encode()).digest())
ida, idb = v2_id(ra), v2_id(rb)
print('  ids recompute equal:', ida == idb == si['v2_receipt_id'], ida)
def v2_sigcheck(env):
    sig = env['signature']
    pub, err = resolve_did_key(sig['signer_did'])
    if err: return False
    ems = {k: v for k, v in env.items() if k != 'signature'}
    msg = SIG_TAG + jcs({'receipt': ems, 'signer': {'signer_did': sig['signer_did'], 'alg': sig['alg']}}).encode()
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(b64u_dec(sig['value']), msg); return True
    except InvalidSignature: return False
print('  sig A verifies:', v2_sigcheck(ra), ' sig B verifies:', v2_sigcheck(rb))
print('  signatures differ:', ra['signature']['value'] != rb['signature']['value'])
def r1_id(env):
    body0 = {k: v for k, v in env.items() if k not in ('receipt_id', 'signature')}
    return 'r1:' + b64u(hashlib.sha256(('agentlair-receipt/v1:' + jcs(body0)).encode()).digest())
r1a, r1b = r1_id(ra), r1_id(rb)
print('  r1 ids differ:', r1a != r1b, '| match stated:', r1a == si['r1_receipt_id_a'], r1b == si['r1_receipt_id_b'])

print('== chain root cross-check ==')
chain = doc['vectors'][0]['receipt']['delegation_chain']
cj = jcs(chain)
bare = hashlib.sha256(cj.encode()).hexdigest()
tagged = 'cr2:' + b64u(hashlib.sha256(b'AGENTLAIR-CHAIN-ROOT-V2\x00' + cj.encode()).digest())
cc = doc['chain_cross_check']
print('  jcs bytes:', len(cj.encode()), '(stated', cc['chain_jcs_bytes'], ')')
print('  bare  ==', bare == cc['bare_root'], bare)
print('  tagged==', tagged == cc['tagged_root'], tagged)
print('  bare == OUR 2026-08-05 published:', bare == '6dc0edff881bbd29f2dc62b1cfd6c18af5593ae83e0afe5d450cee0f7071b574')

print('== act-binding digest recompute ==')
aat = json.load(open(_args.aat_fixture))
ab = aat['vectors'][2]['act_binding']
digest = 'sha256:' + b64u(hashlib.sha256(jcs(ab['preimage']).encode()).digest())
print('  recomputed ==', digest == ab['hash'], digest)
tok = aat['vectors'][2]['aat']
payload = json.loads(b64u_dec(tok.split('.')[1]))
claim = payload.get('urn:dashclaw:act-binding')
print('  claim in token matches file hash:', claim is not None and claim.get('hash') == ab['hash'])
print('== nbf absence check (finding-1 declaration honesty) ==')
for v in aat['vectors']:
    p = json.loads(b64u_dec(v['aat'].split('.')[1]))
    print(f"  {v['id']:35s} nbf_present={('nbf' in p)!s:5s} declared={v['lower_bound_source']}")
