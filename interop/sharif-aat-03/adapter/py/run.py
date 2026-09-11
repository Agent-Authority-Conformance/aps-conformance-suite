import glob
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(__file__))
import aat  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
CORPUS = os.path.join(ROOT, 'corpus')


def load_key(pem):
    return serialization.load_pem_public_key(pem.encode())


results = []
for path in sorted(glob.glob(os.path.join(CORPUS, '*.json'))):
    fx = json.load(open(path))
    entry = {'id': fx['id'], 'variant': fx['variant'],
             'fixture_sha256': hashlib.sha256(open(path, 'rb').read()).hexdigest()}
    if fx['variant'] == 'unresolved':
        with_agent = aat.verify_chain(fx['records'], load_key(fx['agent_key_pem']))
        with_recorder = aat.verify_chain(fx['records'], load_key(fx['recorder_key_pem']))
        entry.update({
            'observed_with_agent_key': with_agent,
            'observed_with_recorder_key': with_recorder,
            'expected': None,
            'status': 'unresolved',
        })
    else:
        key = load_key(fx['verification_key_pem']) if 'verification_key_pem' in fx else None
        obs = aat.verify_chain(fx['records'], key)
        exp = fx['expected']
        if exp['ok']:
            reproduced = obs['ok'] and obs['findings'] == []
        else:
            # Isolation is a property of this corpus: a negative fails exactly
            # one 6.3 check, and it is the expected one.
            reproduced = (not obs['ok']) and len(obs['findings']) == 1 and exp['primary'] in obs['findings'][0]
        entry.update({'observed': obs, 'expected': exp,
                      'status': 'reproduced' if reproduced else 'NOT_REPRODUCED'})
    results.append(entry)

out = os.path.join(ROOT, 'results.json')
with open(out, 'w') as f:
    json.dump(results, f, indent=1, sort_keys=True)
    f.write('\n')
for r in results:
    print(f"{r['id']:16} {r['variant']:10} {r['status']}")
    if r['status'] == 'unresolved':
        print('   agent key   :', r['observed_with_agent_key']['findings'] or 'ok')
        print('   recorder key:', r['observed_with_recorder_key']['findings'] or 'ok')
    elif r['status'] != 'reproduced':
        print('   ', r['observed'])
bad = [r for r in results if r['status'] == 'NOT_REPRODUCED']
sys.exit(1 if bad else 0)
