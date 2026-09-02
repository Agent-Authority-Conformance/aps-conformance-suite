#!/usr/bin/env python3
"""Clean-room verifier for attenu-guard evidence bundles (bundle_vectors_v1), written
2026-09-02 by aeoess from tests/vectors/README.md at attenu-io/attenu-guard v0.11.0 and
the description field of the vector file only. No attenu_guard code was read or imported.
Dependencies: rfc8785 (RFC 8785 JCS), hashlib, hmac. Failures are {reason, seq, node}.

Rules implemented (from the README):
  integrity          entry.hash != sha256(prev_hash_ascii || JCS(entry minus hash)), or
                     seq != position, or prev_hash != previous hash (genesis: 64 zeros)
  integrity(anchor)  HMAC-SHA256(secret, JCS(anchor minus kid/sig/verified)) != sig, or
                     anchor.seq/head != last entry's seq/hash            (seq/node null)
  not_narrower       spawn.granted not a subset of the parent's authority (mine; no vector)
  uncontained        allow scope outside the acting node's authority     (mine; no vector)
  params_mismatch    outcome.invoked_params_hash != its allow's authorized_params_hash
  outcome_without_allow  outcome call_id never issued by any allow
  outcome_before_allow   outcome precedes the allow that issued its call_id
  duplicate_outcome  second terminal outcome for one call_id (positioned on the second)
  duplicate_call_id  second allow carrying a call_id already issued (on the second)
"""
import hashlib, hmac, json, sys
import rfc8785

GENESIS = '0' * 64

def jcs(o): return rfc8785.dumps(o)

def scope_covers(pattern, scope):
    if pattern == scope: return True
    if pattern.endswith('.*'):
        base = pattern[:-2]
        return scope.startswith(base + '.')
    return False

def authority_subset(child, parent):
    for s in child.get('scopes', []):
        if not any(scope_covers(p, s) for p in parent.get('scopes', [])): return False
    pc = {c['key']: c for c in parent.get('constraints', [])}
    for c in child.get('constraints', []):
        p = pc.get(c['key'])
        if p is None: continue  # child adds a constraint the parent did not have: narrower
        if 'max' in c and 'max' in p and c['max'] > p['max']: return False
    if 'ttl' in child and 'ttl' in parent and child['ttl'] > parent['ttl']: return False
    return True

def verify_bundle(bundle, signer):
    F = []
    def fail(reason, seq, node): F.append({'reason': reason, 'seq': seq, 'node': node})
    entries = bundle.get('entries', [])
    # 1. hash chain
    prev = GENESIS
    for i, e in enumerate(entries):
        seq, node = e.get('seq'), e.get('node')
        body = {k: v for k, v in e.items() if k != 'hash'}
        want = hashlib.sha256(prev.encode('ascii') + jcs(body)).hexdigest()
        if seq != i or e.get('prev_hash') != prev or e.get('hash') != want:
            fail('integrity', seq, node)
        prev = e.get('hash', prev)
    # 2. anchor
    a = bundle.get('anchor', {})
    abody = {k: v for k, v in a.items() if k not in ('kid', 'sig', 'verified')}
    key = bytes.fromhex(signer['secret_hex'])
    want_sig = hmac.new(key, jcs(abody), hashlib.sha256).hexdigest()
    last = entries[-1] if entries else {}
    if a.get('sig') != want_sig or a.get('seq') != last.get('seq') or a.get('head') != last.get('hash'):
        fail('integrity(anchor)', None, None)
    # 3. authorities: root authority, spawn granted (subset of parent)
    auth = {}
    for e in entries:
        if e.get('event') == 'root':
            auth[e['node']] = e.get('authority', {})
        elif e.get('event') == 'spawn':
            parent = auth.get(e.get('parent'), {})
            g = e.get('granted', {})
            if not authority_subset(g, parent): fail('not_narrower', e.get('seq'), e.get('node'))
            auth[e['node']] = g
    # 4. containment on allows, and v2 execution binding
    allow_by_call = {}          # call_id -> (seq, node, authorized_params_hash)
    allow_seqs = {}             # call_id -> list of allow seqs (any position)
    for e in entries:
        if e.get('event') == 'allow':
            allow_seqs.setdefault(e.get('call_id'), []).append(e.get('seq'))
    outcome_seen = set()
    for e in entries:
        ev, seq, node = e.get('event'), e.get('seq'), e.get('node')
        if ev == 'allow':
            sc = e.get('scope')
            if sc is not None and not any(scope_covers(p, sc) for p in auth.get(node, {}).get('scopes', [])):
                fail('uncontained', seq, node)
            cid = e.get('call_id')
            if cid in allow_by_call: fail('duplicate_call_id', seq, node)
            else: allow_by_call[cid] = (seq, node, e.get('authorized_params_hash'))
        elif ev == 'outcome':
            cid = e.get('call_id')
            if cid in outcome_seen:
                fail('duplicate_outcome', seq, node); continue
            outcome_seen.add(cid)
            al = allow_by_call.get(cid)
            if al is None:
                fail('outcome_before_allow' if cid in allow_seqs else 'outcome_without_allow', seq, node); continue
            if al[2] != e.get('invoked_params_hash'): fail('params_mismatch', seq, node)
    return {'accepted': not F, 'failures': F}

def main(path):
    d = json.load(open(path))
    ok = 0; bad = 0
    for c in d['cases']:
        r = verify_bundle(c['bundle'], c['signer'])
        want_accept = c['expect'] == 'accept'
        missing = [x for x in c['expect_failures'] if x not in r['failures']]
        extra = [x for x in r['failures'] if x not in c['expect_failures']]
        good = (r['accepted'] == want_accept) and not missing
        ok += good; bad += (not good)
        print(f"{'ok  ' if good else 'FAIL'} {c['name']:28} expect={c['expect']:6} got={'accept' if r['accepted'] else 'reject'} "
              f"required={json.dumps(c['expect_failures'])} reported={json.dumps(r['failures'])}"
              + (f" MISSING={json.dumps(missing)}" if missing else '') + (f" extra={json.dumps(extra)}" if extra else ''))
    print(f"\n{ok} ok, {bad} mismatches, {len(d['cases'])} cases")
    sys.exit(0 if bad == 0 else 1)

if __name__ == '__main__':
    main(sys.argv[1])
