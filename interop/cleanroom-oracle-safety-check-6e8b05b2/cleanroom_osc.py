#!/usr/bin/env python3
"""Clean-room recompute of the JCS / SHA-256 / Ed25519 outer-witness surfaces of the
oracle-safety-check vectors. rfc8785 + cryptography + stdlib only. No suite, SDK or vendored code."""
import json, hashlib, sys, os
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
D = sys.argv[1]; idx = json.load(open(os.path.join(D, 'index.json')))
names = [c if isinstance(c, str) else (c.get('id') or c.get('fixture') or c.get('name')) for c in idx['cases']]
ok = 0
for n in sorted(names):
    d = json.load(open(os.path.join(D, f'{n}.json')))
    cb = rfc8785.dumps(d['envelope'])
    jcs_ok = cb.hex() == d['canonical_bytes_hex']
    sha_ok = hashlib.sha256(cb).hexdigest() == d['canonical_sha256']
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(d['ed25519_pubkey_hex'])).verify(bytes.fromhex(d['ed25519_signature_over_canonical_hex']), cb); sig_ok = True
    except Exception: sig_ok = False
    good = jcs_ok and sha_ok and sig_ok; ok += good
    print(f"{'ok  ' if good else 'FAIL'} {n:22} sha256(file)={hashlib.sha256(open(os.path.join(D,f'{n}.json'),'rb').read()).hexdigest()[:16]} jcs={jcs_ok} sha={sha_ok} ed25519={sig_ok}")
print(f"\n{ok}/{len(names)} vectors: JCS bytes, SHA-256 and Ed25519 outer witness all reproduce")
sys.exit(0 if ok == len(names) else 1)
