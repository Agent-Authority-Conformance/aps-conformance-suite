#!/usr/bin/env python3
"""Regenerates derived/ and vectors.json from source/.

Run from this directory: python3 gen.py
Deterministic: every derived key comes from a published label, ECDSA
signatures use RFC 6979. A second run produces the same bytes.
"""
import hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tpmq

PREFIX = 'aps-conformance-suite:tactiq-tpm-bound-key:'
# AK name from the signed AK registration record (TactiQ OS rc13 and rc14 L3 evidence).
REGISTERED_AK_NAME = '000b35c0941662473b6dc78ce636d83dfcaf1bbdfa68bb69121dd9b3c0b414df0a0a'
# Ed25519 key whose RFC 7638 thumbprint is the qualifying data of source/q15.
WORKLOAD_X = bytes.fromhex('17aa9dffa8c80335dd534317985569523523e0633a600b93775e5d0b60d18930')
REF_PCRS = list(range(10))


def rd(p):
    return open(p, 'rb').read()


def wr(p, b):
    with open(p, 'wb') as f:
        f.write(b)


def main():
    os.makedirs('derived', exist_ok=True)
    ak = rd('source/ak.pub')
    assert tpmq.name(ak).hex() == REGISTERED_AK_NAME, 'source/ak.pub is not the registered AK'

    q15 = {e: rd(f'source/q15.{e}') for e in ('msg', 'sig', 'pcr')}
    q02 = {e: rd(f'source/q02.{e}') for e in ('msg', 'sig', 'pcr')}
    a15, a02 = tpmq.parse_attest(q15['msg']), tpmq.parse_attest(q02['msg'])
    v15, v02 = tpmq.parse_pcr(q15['pcr'], a15['sel']), tpmq.parse_pcr(q02['pcr'], a02['sel'])
    for q, a, v in ((q15, a15, v15), (q02, a02, v02)):
        assert tpmq.verify_sig(ak, q['msg'], q['sig'])
        assert hashlib.sha256(b''.join(v[i] for i in a['sel'])).digest() == a['pcr_digest']
    assert a15['extra'] == tpmq.thumbprint(WORKLOAD_X)
    assert a15['sel'] == a02['sel']
    assert any(v15[i] != v02[i] for i in REF_PCRS)

    other_x = tpmq.ed25519_x(PREFIX + 'other-workload-key')
    other_jkt = tpmq.thumbprint(other_x)

    # TQB-03: a second device. Its own AK claims the same attributes, is not registered,
    # and signs a byte-identical TPMS_ATTEST.
    sk = tpmq.p256_key(PREFIX + 'unregistered-ak')
    uak = tpmq.public_with_key(ak, sk)
    wr('derived/unregistered-ak.pub', uak)
    wr('derived/tqb03.sig', tpmq.sign_tpmt(sk, q15['msg']))
    assert tpmq.verify_sig(uak, q15['msg'], rd('derived/tqb03.sig'))

    # TQB-04: qualifying data rewritten to another key's thumbprint, signature kept.
    o = a15['extra_off']
    m = q15['msg'][:o] + other_jkt + q15['msg'][o + 32:]
    assert len(m) == len(q15['msg'])
    wr('derived/tqb04.msg', m)

    # TQB-05: PCR values edited to the older state, quote and signature kept.
    edited = dict(v15)
    for i in REF_PCRS:
        edited[i] = v02[i]
    wr('derived/tqb05.pcr', tpmq.write_pcr(q15['pcr'], a15['sel'], edited))

    ref15 = {str(i): v15[i].hex() for i in REF_PCRS}
    ref02 = {str(i): v02[i].hex() for i in REF_PCRS}
    q15p = {'msg': 'source/q15.msg', 'sig': 'source/q15.sig', 'pcr': 'source/q15.pcr'}

    def vec(vid, title, ak_path, quote, jkt, ref, ref_src, verdict, reason):
        return {'id': vid, 'title': title, 'ak': ak_path, 'quote': quote,
                'grant_cnf_jkt': jkt.hex(),
                'reference': {'source': ref_src, 'pcrs': ref},
                'expected': {'verdict': verdict, 'reason': reason}}

    vectors = [
        vec('TQB-01-control', 'grant bound to the key the registered device quoted, state equal to the reference',
            'source/ak.pub', q15p, tpmq.thumbprint(WORKLOAD_X), ref15, 'source/q15', 'accept', 'all_checks_passed'),
        vec('TQB-02-grant-bound-to-another-key', 'grant bound to a key the device evidence does not name',
            'source/ak.pub', q15p, other_jkt, ref15, 'source/q15', 'reject', 'key_not_bound'),
        vec('TQB-03-second-device-unregistered-ak', 'same quote bytes signed on a second device by an AK that claims the same attributes but is not registered',
            'derived/unregistered-ak.pub', dict(q15p, sig='derived/tqb03.sig'), tpmq.thumbprint(WORKLOAD_X),
            ref15, 'source/q15', 'reject', 'ak_not_registered'),
        vec('TQB-04-qualifying-data-retargeted', 'qualifying data rewritten to another key, original signature kept',
            'source/ak.pub', dict(q15p, msg='derived/tqb04.msg'), other_jkt, ref15, 'source/q15', 'reject', 'signature_invalid'),
        vec('TQB-05-pcr-values-edited', 'PCR values edited to match an older reference, quote and signature kept',
            'source/ak.pub', dict(q15p, pcr='derived/tqb05.pcr'), tpmq.thumbprint(WORKLOAD_X),
            ref02, 'source/q02', 'reject', 'pcr_digest_mismatch'),
        vec('TQB-06-same-device-changed-state', 'same device and AK, measured boot state differs from the reference the grant was issued against',
            'source/ak.pub', q15p, tpmq.thumbprint(WORKLOAD_X), ref02, 'source/q02', 'reject', 'state_mismatch'),
    ]
    doc = {
        'candidate': 'tactiq-tpm-bound-key',
        'trust': {'registered_ak_name': REGISTERED_AK_NAME,
                  'required_ak_attributes': ['fixedTPM', 'fixedParent', 'restricted', 'sign']},
        'reference_pcrs': REF_PCRS,
        'seed_prefix': PREFIX,
        'vectors': vectors,
    }
    with open('vectors.json', 'w') as f:
        json.dump(doc, f, indent=2); f.write('\n')
    print(f'wrote {len(vectors)} vectors')


if __name__ == '__main__':
    main()
