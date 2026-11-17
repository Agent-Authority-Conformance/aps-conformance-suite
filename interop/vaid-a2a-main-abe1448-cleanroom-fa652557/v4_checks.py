"""Controls for the sig_version 4 branches of vaid_cr.py that no VAID vector reaches.

usage: python3 -I v4_checks.py <path to a v4 vector 01-valid-two-hop-chain.json>

Each case edits vector 01's leaf, re-signs it with the README's published test-only
kernel seed (0x42 * 32) so the signature is valid, and checks the verdict code.
Exit 0 when every case gives its expected code, 1 otherwise.
"""
import copy
import hashlib
import importlib.util
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('vaid_cr', os.path.join(here, 'vaid_cr.py'))
V = importlib.util.module_from_spec(spec); sys.modules['vaid_cr'] = V; spec.loader.exec_module(V)
SK = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)


def sign(doc):
    u = dict(doc); u['kernel_signature'] = None
    doc['kernel_signature'] = list(SK.sign(hashlib.sha256(V.jcs(u).encode()).digest()))
    return doc


def main(path):
    d = V.parse_strict(open(path, encoding='utf-8').read())
    trust = V.load_trust(d['trust_config']); now = V.parse_ts(d['verification_time'])
    rev = V.set_revocation([]); act = d['requested_action']
    leaf0, chain0 = d['inputs']['leaf'], d['inputs']['chain']

    def run(leaf, chain=None, v=V.verify_v4, **kw):
        return v(leaf, copy.deepcopy(chain0) if chain is None else chain, act, trust, rev, now, **kw)

    def edit(fn, resign=True):
        x = copy.deepcopy(leaf0); fn(x); return sign(x) if resign else x

    def unknown_kind(x): x['scope_boundary'].append({'kind': 'amount_limit', 'value': 5})
    def extra_member(x): x['scope_boundary'][0]['max'] = 5
    def bare(x): x['scope_boundary'] = [e['value'] for e in x['scope_boundary']]
    def nonstr_prefix(x): x['scope_boundary'][0]['value'] = 7
    def empty_kind(x): x['scope_boundary'][0]['kind'] = ''
    def as_v3(x): x['sig_version'] = 3
    def obj_boundary(x): x['scope_boundary'] = {'kind': 'prefix', 'value': 'a'}
    root = chain0[0]
    ch_unknown = copy.deepcopy(root); unknown_kind(ch_unknown); sign(ch_unknown)

    cases = [
        ('vector 01 unchanged passes', run(leaf0), ('pass', None)),
        ('re-signed unchanged leaf passes (signer control)', run(edit(lambda x: None)), ('pass', None)),
        ('unknown kind on leaf, S.10', run(edit(unknown_kind)), ('fail', 'unknown_scope_kind')),
        ('unknown kind on chain doc, step 2a', run(leaf0, [ch_unknown]), ('fail', 'unknown_scope_kind')),
        ('extra member in entry, S.8', run(edit(extra_member)), ('fail', 'unparseable')),
        ('bare-string boundary, S.8 before sig_version', run(edit(bare)), ('fail', 'unparseable')),
        ('bare-string boundary with sig_version 3, S.13', run(edit(lambda x: (bare(x), as_v3(x)))), ('fail', 'unparseable')),
        ('prefix value not a string, S.8', run(edit(nonstr_prefix)), ('fail', 'unparseable')),
        ('empty kind, S.8', run(edit(empty_kind)), ('fail', 'unparseable')),
        ('boundary is an object, S.8', run(edit(obj_boundary)), ('fail', 'unparseable')),
        ('typed boundary with sig_version 3 in v4', run(edit(as_v3)), ('fail', 'unsupported_sig_version')),
        ('v4 doc to the v3 verifier, unchanged v3 behaviour', run(leaf0, v=V.verify), ('fail', 'unsupported_sig_version')),
        ('chain [null], input shape', run(leaf0, [None]), ('fail', 'unparseable')),
        ('no leaf, no chain, requireVaid false', run(None, []), ('pass', 'no_vaid')),
        ('no leaf, chain present', run(None, copy.deepcopy(chain0)), ('fail', 'unparseable')),
        ('no leaf, requireVaid true', run(None, [], policy=V.PolicyV4(require_vaid=True)), ('fail', 'no_vaid')),
        ('leaf not an object', run([1]), ('fail', 'unparseable')),
    ]
    ok = 0
    for name, v, exp in cases:
        got = (v.result, v.code); m = got == exp; ok += m
        print(f"{'OK ' if m else 'XX '} {name:<52} expected={exp} got={got} step={v.step}")
    print(f'{ok}/{len(cases)} as expected')
    return 0 if ok == len(cases) else 1


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[2]); sys.exit(2)
    sys.exit(main(sys.argv[1]))
