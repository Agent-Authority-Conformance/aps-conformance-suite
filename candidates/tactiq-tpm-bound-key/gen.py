#!/usr/bin/env python3
"""Regenerates derived/ and vectors.json from source/.

Run from this directory: python3 gen.py
Deterministic: every derived key comes from a published label, ECDSA
signatures use RFC 6979. A second run produces the same bytes.
Two families: `vectors` (TQB-01 to TQB-06, a quote over a key thumbprint) and
`bound_key_vectors` (TQB-07 to TQB-16, a TPM2_Certify of a TPM key and a DPoP
proof that key signed, both over verifier challenges).
"""
import hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tpmq
import boundkey as bk

PREFIX = 'aps-conformance-suite:tactiq-tpm-bound-key:'
# AK name from the signed AK registration record (source repository, rc13 and rc14 L3 evidence).
REGISTERED_AK_NAME = '000b35c0941662473b6dc78ce636d83dfcaf1bbdfa68bb69121dd9b3c0b414df0a0a'
# Ed25519 key whose RFC 7638 thumbprint is the qualifying data of source/q15.
WORKLOAD_X = bytes.fromhex('17aa9dffa8c80335dd534317985569523523e0633a600b93775e5d0b60d18930')
REF_PCRS = list(range(10))


def rd(p):
    return open(p, 'rb').read()


def wr(p, b):
    with open(p, 'wb') as f:
        f.write(b)


def nonce(path):
    return rd(path).decode().strip()


def bound_key_vectors(ak):
    """TQB-07 to TQB-16 from the 2026-11-25 board evidence in source/bk.* and source/xk.*."""
    n1, n2, n3 = nonce('source/n1.hex'), nonce('source/n2.hex'), nonce('source/n3.hex')
    bpub, bmsg, bsig = rd('source/bk.pub'), rd('source/bk.certify.msg'), rd('source/bk.certify.sig')
    xpub, xmsg, xsig = rd('source/xk.pub'), rd('source/xk.certify.msg'), rd('source/xk.certify.sig')
    jwt = rd('source/bk.pop.jwt').decode().strip()
    for pub, msg, sig, n in ((bpub, bmsg, bsig, n1), (xpub, xmsg, xsig, n3)):
        a = bk.parse_certify(msg)
        assert tpmq.verify_sig(ak, msg, sig) and a['type'] == bk.TPM_ST_ATTEST_CERTIFY
        assert a['extra'].hex() == n and a['name'] == tpmq.name(pub)
    hdr, pl, ok = bk.jws_verify(jwt)
    assert ok and hdr['jwk'] == bk.jwk_of(bpub) and pl['nonce'] == n2
    jkt = bk.ec_thumbprint(bk.jwk_of(bpub))

    # TQB-09: the certify of the board key signed instead by the software AK of TQB-03.
    sk = tpmq.p256_key(PREFIX + 'unregistered-ak')
    wr('derived/tqb09.sig', tpmq.sign_tpmt(sk, bmsg))
    # TQB-10: one byte of the certified name changed, AK signature kept.
    a = bk.parse_certify(bmsg)
    m = bytearray(bmsg); m[a['name_off'] + 10] ^= 0x01
    wr('derived/tqb10.msg', bytes(m))
    # TQB-13: one claim of the DPoP payload changed, signature kept.
    h, p, sg = jwt.split('.')
    pl2 = dict(pl, htm='GET')
    wr('derived/tqb13.jwt', ('.'.join([h, bk.b64u(json.dumps(pl2, separators=(',', ':')).encode()), sg]) + '\n').encode())
    # TQB-14: a valid DPoP proof over the same challenge from a software key with its own JWK.
    other = tpmq.p256_key(PREFIX + 'other-pop-key')
    wr('derived/tqb14.jwt', (bk.jws_sign(other, dict(hdr, jwk=bk.jwk_of_key(other)), pl) + '\n').encode())
    other_jkt = bk.ec_thumbprint(bk.jwk_of_key(other))

    good = {'ak': 'source/ak.pub', 'key': 'source/bk.pub',
            'certify': {'msg': 'source/bk.certify.msg', 'sig': 'source/bk.certify.sig'},
            'pop': 'source/bk.pop.jwt', 'grant_cnf_jkt': jkt.hex(),
            'challenge': {'certify': n1, 'pop': n2}}

    def vec(vid, title, verdict, reason, **over):
        v = json.loads(json.dumps(good))
        for k, val in over.items():
            v[k] = val
        return dict({'id': vid, 'title': title}, **v, expected={'verdict': verdict, 'reason': reason})

    return [
        vec('TQB-07-control', 'TPM key certified by the registered AK over the certify challenge, DPoP proof signed by it over the proof challenge, grant bound to its thumbprint',
            'accept', 'all_checks_passed'),
        vec('TQB-08-exportable-key-certified', 'key created on the board without fixedTPM and fixedParent, honestly certified by the same AK over its own challenge',
            'reject', 'key_exportable', key='source/xk.pub',
            certify={'msg': 'source/xk.certify.msg', 'sig': 'source/xk.certify.sig'},
            challenge={'certify': n3, 'pop': n2}),
        vec('TQB-09-certify-by-unregistered-ak', 'same certify bytes signed by the software AK of TQB-03, not registered',
            'reject', 'ak_not_registered', ak='derived/unregistered-ak.pub',
            certify={'msg': 'source/bk.certify.msg', 'sig': 'derived/tqb09.sig'}),
        vec('TQB-10-certified-name-edited', 'one byte of the certified name changed, AK signature kept',
            'reject', 'certify_signature_invalid', certify={'msg': 'derived/tqb10.msg', 'sig': 'source/bk.certify.sig'}),
        vec('TQB-11-certify-replayed', 'the certify of TQB-07 presented to a verifier whose challenge was another value',
            'reject', 'certify_challenge_mismatch', challenge={'certify': n3, 'pop': n2}),
        vec('TQB-12-key-not-the-certified-one', 'certify of the board key presented with the public area of a different key from the same TPM',
            'reject', 'key_not_certified', key='source/xk.pub'),
        vec('TQB-13-proof-payload-edited', 'one claim of the DPoP payload changed, signature kept',
            'reject', 'proof_signature_invalid', pop='derived/tqb13.jwt'),
        vec('TQB-14-proof-from-another-key', 'valid DPoP proof over the right challenge, signed by a software key that carries its own JWK',
            'reject', 'proof_key_not_certified_key', pop='derived/tqb14.jwt'),
        vec('TQB-15-proof-replayed', 'the DPoP proof of TQB-07 presented to a verifier whose proof challenge was another value',
            'reject', 'proof_challenge_mismatch', challenge={'certify': n1, 'pop': n3}),
        vec('TQB-16-grant-bound-to-another-key', 'evidence and proof valid, grant bound to the thumbprint of another key',
            'reject', 'key_not_bound', grant_cnf_jkt=other_jkt.hex()),
    ]


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

    # TQB-03: a simulated second device. Its AK is a software P-256 key derived from a
    # published label; its public area claims the same attributes as the registered AK.
    # It is not registered, and it signs a byte-identical TPMS_ATTEST.
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

    def vec(vid, title, ak_path, quote, jkt, ref, ref_src, verdict, reason, tq):
        return {'id': vid, 'title': title, 'ak': ak_path, 'quote': quote,
                'grant_cnf_jkt': jkt.hex(),
                'reference': {'source': ref_src, 'pcrs': ref},
                'expected': {'verdict': verdict, 'reason': reason, 'tpm2_checkquote': tq}}

    vectors = [
        vec('TQB-01-control', 'grant bound to the key the registered device quoted, state equal to the reference',
            'source/ak.pub', q15p, tpmq.thumbprint(WORKLOAD_X), ref15, 'source/q15', 'accept', 'all_checks_passed', 'verifies'),
        vec('TQB-02-grant-bound-to-another-key', 'grant bound to a key the device evidence does not name',
            'source/ak.pub', q15p, other_jkt, ref15, 'source/q15', 'reject', 'key_not_bound', 'verifies'),
        vec('TQB-03-simulated-unregistered-ak', 'simulated second device: same quote bytes signed by a software AK derived from a published label, claiming the same attributes, not registered',
            'derived/unregistered-ak.pub', dict(q15p, sig='derived/tqb03.sig'), tpmq.thumbprint(WORKLOAD_X),
            ref15, 'source/q15', 'reject', 'ak_not_registered', 'verifies'),
        vec('TQB-04-qualifying-data-retargeted', 'qualifying data rewritten to another key, original signature kept',
            'source/ak.pub', dict(q15p, msg='derived/tqb04.msg'), other_jkt, ref15, 'source/q15', 'reject', 'signature_invalid', 'fails'),
        vec('TQB-05-pcr-values-edited', 'PCR values edited to match an older reference, quote and signature kept',
            'source/ak.pub', dict(q15p, pcr='derived/tqb05.pcr'), tpmq.thumbprint(WORKLOAD_X),
            ref02, 'source/q02', 'reject', 'pcr_digest_mismatch', 'fails'),
        vec('TQB-06-same-device-changed-state', 'same device and AK, measured boot state differs from the reference the grant was issued against',
            'source/ak.pub', q15p, tpmq.thumbprint(WORKLOAD_X), ref02, 'source/q02', 'reject', 'state_mismatch', 'verifies'),
    ]
    bound = bound_key_vectors(ak)
    doc = {
        'candidate': 'tactiq-tpm-bound-key',
        'trust': {'registered_ak_name': REGISTERED_AK_NAME,
                  'required_ak_attributes': ['fixedTPM', 'fixedParent', 'restricted', 'sign']},
        'reference_pcrs': REF_PCRS,
        'seed_prefix': PREFIX,
        'vectors': vectors,
        'bound_key_vectors': bound,
    }
    with open('vectors.json', 'w') as f:
        json.dump(doc, f, indent=2); f.write('\n')
    print(f'wrote {len(vectors)} quote vectors and {len(bound)} bound-key vectors')


if __name__ == '__main__':
    main()
