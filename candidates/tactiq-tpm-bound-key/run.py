#!/usr/bin/env python3
"""Evaluates every vector in vectors.json and compares with its expected result.

Run from this directory: python3 run.py
Needs Python 3 and the `cryptography` package. No network, no TPM.
With --tpm2-tools, also cross-checks every signature with tpm2_checkquote.

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
Exit status 0 when every vector matched its expectation, 1 otherwise.
"""
import hashlib, json, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tpmq


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


def reference_ok(v, ak):
    src = v['reference']['source']
    msg, sig, pcr = (rd(f'{src}.{e}') for e in ('msg', 'sig', 'pcr'))
    a = tpmq.parse_attest(msg)
    vals = tpmq.parse_pcr(pcr, a['sel'])
    return (tpmq.verify_sig(ak, msg, sig)
            and hashlib.sha256(b''.join(vals[i] for i in a['sel'])).digest() == a['pcr_digest']
            and all(vals[int(i)].hex() == h for i, h in v['reference']['pcrs'].items()))


def tpm2_cross_check(v):
    q = v['quote']
    a = tpmq.parse_attest(rd(q['msg']))
    r = subprocess.run(['tpm2_checkquote', '-u', v['ak'], '-m', q['msg'], '-s', q['sig'],
                        '-f', q['pcr'], '-g', 'sha256', '-q', a['extra'].hex()],
                       capture_output=True, text=True)
    return r.returncode == 0


def main():
    doc = json.load(open('vectors.json'))
    ak = rd('source/ak.pub')
    cross = '--tpm2-tools' in sys.argv
    bad = 0
    for v in doc['vectors']:
        if not reference_ok(v, ak):
            print(f'HARNESS ERROR {v["id"]}: reference source does not verify'); bad += 1; continue
        got = evaluate(v, doc['trust'], ak)
        exp = (v['expected']['verdict'], v['expected']['reason'])
        ok = got == exp; bad += not ok
        line = f'{"ok  " if ok else "FAIL"} {v["id"]}: {got[0]} {got[1]}'
        if not ok:
            line += f' (expected {exp[0]} {exp[1]})'
        if cross:
            line += f'  [tpm2_checkquote: {"verifies" if tpm2_cross_check(v) else "fails"}]'
        print(line)
    if bad:
        print(f'FAILED: {bad} vector(s)'); sys.exit(1)
    print(f'PASSED: {len(doc["vectors"])} vectors matched their expected results')


if __name__ == '__main__':
    main()
