"""Run the clean-room verifier vaid_cr.py over VAID A2A vectors pinned by a sha256 manifest.

usage: python3 -I run_vectors.py <vectors-dir> <manifest.sha256>

Exit 0 only when the directory holds exactly the vectors the manifest names, each with its
pinned digest, and every vector's (result, error code) equals its expected pair.
Exit 1 when any vector mismatches or raises. Exit 2 on a usage problem, an empty corpus
or manifest, or a corpus that does not match the manifest.
"""
import hashlib
import importlib.util
import os
import sys


def sha256(path):
    with open(path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[2])
        return 2
    vec, man = argv[1], argv[2]
    here = os.path.dirname(os.path.abspath(__file__))
    cr = os.path.join(here, 'vaid_cr.py')
    spec = importlib.util.spec_from_file_location('vaid_cr', cr)
    V = importlib.util.module_from_spec(spec)
    sys.modules['vaid_cr'] = V
    spec.loader.exec_module(V)

    pinned = {}
    with open(man, encoding='utf-8') as fh:
        for line in fh:
            if line.strip():
                digest, name = line.split(None, 1)
                pinned[name.strip()] = digest
    if not pinned:
        print('FAIL empty manifest')
        return 2
    present = sorted(f for f in os.listdir(vec) if f[:2].isdigit() and f.endswith('.json')) if os.path.isdir(vec) else []
    if not present:
        print('FAIL empty corpus')
        return 2
    if set(present) != set(pinned):
        print('FAIL corpus does not match manifest:', sorted(set(present) ^ set(pinned)))
        return 2
    for f in present:
        if sha256(os.path.join(vec, f)) != pinned[f]:
            print(f'FAIL digest mismatch: {f}')
            return 2

    print('vaid_cr.py sha256', sha256(cr))
    print('manifest sha256', sha256(man))
    ok = 0
    for f in present:
        exp = ('?', '?')
        try:
            with open(os.path.join(vec, f), encoding='utf-8') as fh:
                d = V.parse_strict(fh.read())
            exp = (d['expected_result'], d['expected_error_code'])
            v = V.verify(d['inputs']['leaf'], d['inputs']['chain'], d['requested_action'], V.load_trust(d['trust_config']),
                         V.set_revocation(d['revoked_vaid_ids']), V.parse_ts(d['verification_time']))
            got, det = (v.result, v.code), f'step={v.step} {v.detail}'
        except Exception as e:  # any exception is a failed vector, never a pass
            got, det = ('EXCEPTION', type(e).__name__), str(e)[:120]
        match = got == exp
        ok += match
        print(f"{'OK ' if match else 'XX '} {f:<46} expected={exp} got={got} {det[:100]}")
    print(f'{ok}/{len(present)} as expected')
    return 0 if ok == len(present) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
