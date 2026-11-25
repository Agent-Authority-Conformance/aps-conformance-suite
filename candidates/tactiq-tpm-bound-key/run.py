#!/usr/bin/env python3
"""Evaluates every vector in vectors.json and compares with its expected result.

Run from this directory: python3 run.py
Needs Python 3 and the `cryptography` package. No network, no TPM.
With --tpm2-tools, also runs tpm2_checkquote on every quote and scores its
result against expected.tpm2_checkquote in the vector; a mismatch is a failure,
and a missing tpm2_checkquote makes the run NOT ESTABLISHED (exit status 2).

Order of checks, first failure is the reason:
  1. ak_not_registered   presented AK name differs from the registered name,
                         or it lacks fixedTPM, fixedParent, restricted, sign
  2. signature_invalid   quote signature does not verify under the presented AK,
                         or the message is not a TPM-generated quote
  3. pcr_digest_mismatch PCR values do not reproduce the signed pcrDigest
  4. key_not_bound       qualifying data differs from the grant's cnf.jkt
  5. state_mismatch      a quoted PCR differs from the reference
The reference values are themselves taken from a quote that must verify
under the registered AK; a reference that does not is a harness error.

Bound-key vectors (TQB-07 to TQB-16), first failure is the reason:
  1. ak_not_registered           as above
  2. certify_signature_invalid   certify does not verify under the presented AK,
                                 or is not a TPM-generated TPM2_Certify
  3. certify_challenge_mismatch  certify qualifying data is not the verifier's
                                 certify challenge
  4. key_not_certified           presented key's name is not the certified name
  5. key_exportable              key lacks fixedTPM, fixedParent,
                                 sensitiveDataOrigin or sign, or is restricted
  6. proof_signature_invalid     DPoP proof does not verify under the JWK in
                                 its header, or is not typ dpop+jwt, alg ES256
  7. proof_key_not_certified_key that JWK is not the certified key
  8. proof_challenge_mismatch    the proof's nonce is not the verifier's proof
                                 challenge
  9. key_not_bound               the grant's cnf.jkt is not the RFC 7638
                                 thumbprint of the certified key
tpm2_checkquote does not apply to these vectors (no quote).
Exit status 0 when every vector matched its expectation, 1 otherwise,
2 when none failed but tpm2_checkquote was requested and could not run.
"""
import hashlib, json, os, struct, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tpmq
import boundkey as bk


def rd(p):
    return open(p, 'rb').read()


def evaluate(v, trust, ak_registered):
    ak = rd(v['ak'])
    try:
        attrs = tpmq.parse_public(ak)[0]
    except ValueError:
        return 'reject', 'ak_not_registered'
    need = tpmq.FIXED_TPM | tpmq.FIXED_PARENT | tpmq.RESTRICTED | tpmq.SIGN
    if tpmq.name(ak).hex() != trust['registered_ak_name'] or attrs & need != need:
        return 'reject', 'ak_not_registered'
    msg, sig, pcr = (rd(v['quote'][k]) for k in ('msg', 'sig', 'pcr'))
    try:
        a = tpmq.parse_attest(msg)
    except (ValueError, IndexError):
        return 'reject', 'signature_invalid'
    if a['magic'] != tpmq.TPM_GENERATED or a['type'] != tpmq.TPM_ST_ATTEST_QUOTE \
            or not tpmq.verify_sig(ak, msg, sig):
        return 'reject', 'signature_invalid'
    try:
        vals = tpmq.parse_pcr(pcr, a['sel'])
    except ValueError:
        return 'reject', 'pcr_digest_mismatch'
    if hashlib.sha256(b''.join(vals[i] for i in a['sel'])).digest() != a['pcr_digest']:
        return 'reject', 'pcr_digest_mismatch'
    if a['extra'] != bytes.fromhex(v['grant_cnf_jkt']):
        return 'reject', 'key_not_bound'
    for i, ref in v['reference']['pcrs'].items():
        if vals.get(int(i), b'').hex() != ref:
            return 'reject', 'state_mismatch'
    return 'accept', 'all_checks_passed'


def evaluate_bound_key(v, trust):
    ak = rd(v['ak'])
    try:
        attrs = tpmq.parse_public(ak)[0]
    except ValueError:
        return 'reject', 'ak_not_registered'
    need = tpmq.FIXED_TPM | tpmq.FIXED_PARENT | tpmq.RESTRICTED | tpmq.SIGN
    if tpmq.name(ak).hex() != trust['registered_ak_name'] or attrs & need != need:
        return 'reject', 'ak_not_registered'
    msg, sig = rd(v['certify']['msg']), rd(v['certify']['sig'])
    try:
        a = bk.parse_certify(msg)
    except (ValueError, IndexError, struct.error):
        return 'reject', 'certify_signature_invalid'
    if a['magic'] != tpmq.TPM_GENERATED or a['type'] != bk.TPM_ST_ATTEST_CERTIFY \
            or not tpmq.verify_sig(ak, msg, sig):
        return 'reject', 'certify_signature_invalid'
    if a['extra'].hex() != v['challenge']['certify']:
        return 'reject', 'certify_challenge_mismatch'
    key = rd(v['key'])
    try:
        kattrs = tpmq.parse_public(key)[0]
    except ValueError:
        return 'reject', 'key_not_certified'
    if tpmq.name(key) != a['name']:
        return 'reject', 'key_not_certified'
    need = tpmq.FIXED_TPM | tpmq.FIXED_PARENT | bk.SENSITIVE_DATA_ORIGIN | tpmq.SIGN
    if kattrs & need != need or kattrs & tpmq.RESTRICTED:
        return 'reject', 'key_exportable'
    try:
        hdr, pl, ok = bk.jws_verify(rd(v['pop']).decode().strip())
    except (ValueError, KeyError):
        return 'reject', 'proof_signature_invalid'
    if not ok or hdr.get('typ') != 'dpop+jwt':
        return 'reject', 'proof_signature_invalid'
    if {k: hdr['jwk'].get(k) for k in ('crv', 'kty', 'x', 'y')} != bk.jwk_of(key):
        return 'reject', 'proof_key_not_certified_key'
    if pl.get('nonce') != v['challenge']['pop']:
        return 'reject', 'proof_challenge_mismatch'
    if bk.ec_thumbprint(bk.jwk_of(key)).hex() != v['grant_cnf_jkt']:
        return 'reject', 'key_not_bound'
    return 'accept', 'all_checks_passed'


def reference_ok(v, ak):
    src = v['reference']['source']
    msg, sig, pcr = (rd(f'{src}.{e}') for e in ('msg', 'sig', 'pcr'))
    a = tpmq.parse_attest(msg)
    vals = tpmq.parse_pcr(pcr, a['sel'])
    return (tpmq.verify_sig(ak, msg, sig)
            and hashlib.sha256(b''.join(vals[i] for i in a['sel'])).digest() == a['pcr_digest']
            and all(vals[int(i)].hex() == h for i, h in v['reference']['pcrs'].items()))


def tpm2_cross_check(v):
    """tpm2_checkquote over the presented AK, quote, signature and PCR values.

    Returns 'verifies' or 'fails'. It checks the signature and the PCR digest,
    not registration, key binding or the reference state.
    """
    q = v['quote']
    a = tpmq.parse_attest(rd(q['msg']))
    r = subprocess.run(['tpm2_checkquote', '-u', v['ak'], '-m', q['msg'], '-s', q['sig'],
                        '-f', q['pcr'], '-g', 'sha256', '-q', a['extra'].hex()],
                       capture_output=True, text=True)
    return 'verifies' if r.returncode == 0 else 'fails'


def main():
    doc = json.load(open('vectors.json'))
    ak = rd('source/ak.pub')
    cross = '--tpm2-tools' in sys.argv
    bad = 0; notrun = 0
    for v in doc['vectors']:
        if not reference_ok(v, ak):
            print(f'HARNESS ERROR {v["id"]}: reference source does not verify'); bad += 1; continue
        got = evaluate(v, doc['trust'], ak)
        exp = (v['expected']['verdict'], v['expected']['reason'])
        ok = got == exp
        line = f'{v["id"]}: {got[0]} {got[1]}'
        if not ok:
            line += f' (expected {exp[0]} {exp[1]})'
        if cross:
            want = v['expected']['tpm2_checkquote']
            try:
                tq = tpm2_cross_check(v)
                line += f'  [tpm2_checkquote: {tq}'
                if tq != want:
                    ok = False; line += f', expected {want}'
                line += ']'
            except OSError:
                notrun += 1; line += '  [tpm2_checkquote: NOT RUN]'
        bad += not ok
        print(f'{"ok  " if ok else "FAIL"} {line}')
    for v in doc.get('bound_key_vectors', []):
        got = evaluate_bound_key(v, doc['trust'])
        exp = (v['expected']['verdict'], v['expected']['reason'])
        ok = got == exp
        line = f'{v["id"]}: {got[0]} {got[1]}' + ('' if ok else f' (expected {exp[0]} {exp[1]})')
        bad += not ok
        print(f'{"ok  " if ok else "FAIL"} {line}')
    if bad:
        print(f'FAILED: {bad} vector(s)'); sys.exit(1)
    if notrun:
        print(f'NOT ESTABLISHED: tpm2_checkquote could not run for {notrun} vector(s), none failed')
        sys.exit(2)
    mode = ' (including tpm2_checkquote)' if cross else ''
    total = len(doc['vectors']) + len(doc.get('bound_key_vectors', []))
    print(f'PASSED: {total} vectors matched their expected results{mode}')


if __name__ == '__main__':
    main()
