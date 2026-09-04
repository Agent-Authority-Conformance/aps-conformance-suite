#!/usr/bin/env python3
"""Clean-room verifier for attenu-guard observer envelopes (envelope_vectors_v1),
written 2026-09-04 by aeoess from tests/vectors/README.md at attenu-io/attenu-guard
v0.13.0 (sections "Observer envelope vectors", "The envelope", "The seven named
failures", "Scoring, and the two rules on where a failure may land") and the
description field of the vector file only. No attenu_guard code was read or
imported, Python or TypeScript; this file was written and first run before the
package was installed for direction 1. Dependencies: rfc8785 (RFC 8785 JCS),
cryptography (Ed25519), hashlib, hmac.

The bundle-level half (chain hashes, anchor, authority, containment, execution
binding) is carried unchanged from this lab's own clean-room verifier for
bundle_vectors_v1, interop/attenu-guard-0.11.0-bundles/cleanroom/verify_bundle_v1.py,
which was written from the same README's bundle sections. Envelope failures are
{reason, seq, node} like chain failures and join the same list.

Envelope rules implemented (from the README):
  claim first        an entry is claimed as soon as subject.seq finds it, before the
                     rest of the envelope is judged, so a second envelope over that
                     entry cannot escape the duplicate rule by being defective too
  envelope_duplicate_subject  a second envelope naming an entry an earlier envelope in
                     the same array already named; the entry reports process-asserted
  envelope_non_canonical      the bytes as received are not JCS of what they parse to,
                     or the envelope holds a value JCS cannot represent
  envelope_unknown_version    v other than 1, or typ other than delegation-event-observation
  envelope_unknown_member     a member added anywhere in the envelope at v1
  envelope_subject_mismatch   a subject missing a member its event requires, a seq that
                     is not an integer or an event that is not a string, an event v1 has
                     no subject for, an entry_hash that disagrees with the hash
                     recomputed for that seq, or a locator that disagrees with the entry
                     found
  envelope_unknown_witness    witness.kid names a key not in witness_keys or is not a
                     string, or an alg other than EdDSA
  envelope_bad_signature      the signature does not verify under the key witness.kid
                     names, or sig is not a hex string

Position: the entry seq locates, not the node the subject names. An envelope failure
lands only on the hop that envelope covers. No chain-level failure is ever raised
because an envelope failed.

Two readings this verifier had to choose, both recorded in SOURCE.md rather than
argued: a version this build does not know stops that envelope's remaining checks,
and witness_keys is trusted input, so a malformed row there raises.
"""
import hashlib
import hmac
import json
import sys

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS = '0' * 64
TYP = 'delegation-event-observation'
ENVELOPE_MEMBERS = {'v', 'typ', 'subject', 'observed', 'witness', 'sig'}
SUBJECT_SPAWN = {'chain_id', 'node', 'seq', 'entry_hash', 'event'}
SUBJECT_ALLOW = SUBJECT_SPAWN | {'call_id'}
SUBJECT_BY_EVENT = {'spawn': SUBJECT_SPAWN, 'allow': SUBJECT_ALLOW}
OBSERVED_MEMBERS = {'result', 'at', 'method'}
WITNESS_MEMBERS = {'kid', 'alg'}


def jcs(o):
    return rfc8785.dumps(o)


def scope_covers(pattern, scope):
    if pattern == scope:
        return True
    if pattern.endswith('.*'):
        return scope.startswith(pattern[:-2] + '.')
    return False


def authority_subset(child, parent):
    for s in child.get('scopes', []):
        if not any(scope_covers(p, s) for p in parent.get('scopes', [])):
            return False
    pc = {c['key']: c for c in parent.get('constraints', [])}
    for c in child.get('constraints', []):
        p = pc.get(c['key'])
        if p is None:
            continue
        if 'max' in c and 'max' in p and c['max'] > p['max']:
            return False
    if 'ttl' in child and 'ttl' in parent and child['ttl'] > parent['ttl']:
        return False
    return True


def entry_hashes(entries):
    """Recompute each entry's hash from the bundle, genesis-anchored."""
    out = []
    prev = GENESIS
    for e in entries:
        body = {k: v for k, v in e.items() if k != 'hash'}
        out.append(hashlib.sha256(prev.encode('ascii') + jcs(body)).hexdigest())
        prev = e.get('hash', prev)
    return out


def verify_chain(bundle, signer, fail):
    entries = bundle.get('entries', [])
    recomputed = entry_hashes(entries)
    prev = GENESIS
    for i, e in enumerate(entries):
        seq, node = e.get('seq'), e.get('node')
        if seq != i or e.get('prev_hash') != prev or e.get('hash') != recomputed[i]:
            fail('integrity', seq, node)
        prev = e.get('hash', prev)
    a = bundle.get('anchor')
    if a is not None and signer is not None:
        abody = {k: v for k, v in a.items() if k not in ('kid', 'sig', 'verified')}
        key = bytes.fromhex(signer['secret_hex'])
        want = hmac.new(key, jcs(abody), hashlib.sha256).hexdigest()
        last = entries[-1] if entries else {}
        if a.get('sig') != want or a.get('seq') != last.get('seq') or a.get('head') != last.get('hash'):
            fail('integrity(anchor)', None, None)
    auth = {}
    for e in entries:
        if e.get('event') == 'root':
            auth[e['node']] = e.get('authority', {})
        elif e.get('event') == 'spawn':
            g = e.get('granted', {})
            if not authority_subset(g, auth.get(e.get('parent'), {})):
                fail('not_narrower', e.get('seq'), e.get('node'))
            auth[e['node']] = g
    allow_by_call = {}
    allow_seqs = {}
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
            if cid in allow_by_call:
                fail('duplicate_call_id', seq, node)
            else:
                allow_by_call[cid] = (seq, node, e.get('authorized_params_hash'))
        elif ev == 'outcome':
            cid = e.get('call_id')
            if cid in outcome_seen:
                fail('duplicate_outcome', seq, node)
                continue
            outcome_seen.add(cid)
            al = allow_by_call.get(cid)
            if al is None:
                fail('outcome_before_allow' if cid in allow_seqs else 'outcome_without_allow', seq, node)
                continue
            if al[2] != e.get('invoked_params_hash'):
                fail('params_mismatch', seq, node)


def load_trust_set(witness_keys):
    """witness_keys is deployment input, not attacker input: a bad row raises."""
    trusted = {}
    for row in witness_keys or []:
        kid = row.get('kid')
        if not isinstance(kid, str):
            raise ValueError(f'witness_keys row has no string kid: {row!r}')
        if row.get('alg') != 'EdDSA':
            raise ValueError(f'witness_keys row {kid} declares alg {row.get("alg")!r}, not EdDSA')
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(row['public_key_hex']))
        except Exception as exc:
            raise ValueError(f'witness_keys row {kid} carries an unusable public_key_hex: {exc}') from exc
        trusted[kid] = pub
    return trusted


def verify_envelopes(bundle, witness_keys, fail, raw_hex=None):
    """Return {seq_string: state} for every entry, reporting failures through fail()."""
    entries = bundle.get('entries', [])
    recomputed = entry_hashes(entries)
    states = {str(i): 'process-asserted' for i in range(len(entries))}
    envelopes = bundle.get('envelopes')
    if envelopes is None:
        return states, {}
    trusted = load_trust_set(witness_keys)
    claimed = set()
    results = {}
    for index, env in enumerate(envelopes):
        subject = env.get('subject') if isinstance(env, dict) else None
        seq = subject.get('seq') if isinstance(subject, dict) else None
        found = entries[seq] if isinstance(seq, int) and not isinstance(seq, bool) and 0 <= seq < len(entries) else None
        # Position is the entry seq locates, never the node the subject names.
        at_seq = found.get('seq') if found is not None else (seq if isinstance(seq, int) else None)
        at_node = found.get('node') if found is not None else None
        key = at_seq if found is not None else ('unlocated', index)
        if key in claimed:
            fail('envelope_duplicate_subject', at_seq, at_node)
            if found is not None:
                states[str(found['seq'])] = 'process-asserted'
                results.pop(str(found['seq']), None)
            continue
        claimed.add(key)
        bad = _judge_envelope(env, subject, found, recomputed, trusted, raw_hex, fail, at_seq, at_node)
        if not bad and found is not None:
            states[str(found['seq'])] = 'witness-signed'
            observed = env.get('observed') or {}
            results[str(found['seq'])] = observed.get('result')
    return states, results


def _judge_envelope(env, subject, found, recomputed, trusted, raw_hex, fail, at_seq, at_node):
    """Run the envelope checks in order; return True when any of them failed."""
    bad = False
    if not isinstance(env, dict):
        fail('envelope_unknown_member', at_seq, at_node)
        return True
    if raw_hex is not None:
        try:
            received = bytes.fromhex(raw_hex)
            if received != jcs(json.loads(received.decode('utf-8'))):
                fail('envelope_non_canonical', at_seq, at_node)
                bad = True
        except Exception:
            fail('envelope_non_canonical', at_seq, at_node)
            bad = True
    try:
        preimage = jcs({k: v for k, v in env.items() if k != 'sig'})
    except Exception:
        fail('envelope_non_canonical', at_seq, at_node)
        return True
    if env.get('v') != 1 or env.get('typ') != TYP:
        fail('envelope_unknown_version', at_seq, at_node)
        return True
    event = subject.get('event') if isinstance(subject, dict) else None
    allowed_subject = SUBJECT_BY_EVENT.get(event) if isinstance(event, str) else None
    added = set(env) - ENVELOPE_MEMBERS
    if isinstance(subject, dict) and allowed_subject is not None:
        added |= set(subject) - allowed_subject
    observed = env.get('observed')
    if isinstance(observed, dict):
        added |= set(observed) - OBSERVED_MEMBERS
    witness = env.get('witness')
    if isinstance(witness, dict):
        added |= set(witness) - WITNESS_MEMBERS
    if added:
        fail('envelope_unknown_member', at_seq, at_node)
        bad = True
    if not _subject_ok(subject, found, recomputed, allowed_subject):
        fail('envelope_subject_mismatch', at_seq, at_node)
        bad = True
    kid = witness.get('kid') if isinstance(witness, dict) else None
    alg = witness.get('alg') if isinstance(witness, dict) else None
    public = trusted.get(kid) if isinstance(kid, str) else None
    if public is None or alg != 'EdDSA':
        fail('envelope_unknown_witness', at_seq, at_node)
        return True
    sig = env.get('sig')
    try:
        raw_sig = bytes.fromhex(sig)
    except Exception:
        fail('envelope_bad_signature', at_seq, at_node)
        return True
    try:
        public.verify(raw_sig, preimage)
    except InvalidSignature:
        fail('envelope_bad_signature', at_seq, at_node)
        bad = True
    return bad


def _subject_ok(subject, found, recomputed, allowed_subject):
    if not isinstance(subject, dict) or allowed_subject is None:
        return False
    if set(subject) < allowed_subject:
        return False
    seq = subject.get('seq')
    if not isinstance(seq, int) or isinstance(seq, bool) or found is None:
        return False
    if subject.get('entry_hash') != recomputed[found['seq']]:
        return False
    for locator in ('chain_id', 'node'):
        if locator in allowed_subject and subject.get(locator) != found.get(locator):
            return False
    if subject.get('event') != found.get('event'):
        return False
    if 'call_id' in allowed_subject and subject.get('call_id') != found.get('call_id'):
        return False
    return True


def verify(case):
    failures = []

    def fail(reason, seq, node):
        failures.append({'reason': reason, 'seq': seq, 'node': node})

    bundle = case['bundle']
    verify_chain(bundle, case.get('signer'), fail)
    states, results = verify_envelopes(bundle, case.get('witness_keys'), fail, case.get('raw_hex'))
    return {'accepted': not failures, 'failures': failures, 'states': states, 'results': results}


def canonical_bytes_of_single_envelope(bundle):
    envelopes = bundle.get('envelopes') or []
    if len(envelopes) != 1:
        return None
    return jcs({k: v for k, v in envelopes[0].items() if k != 'sig'})


def main(path):
    data = json.load(open(path, encoding='utf-8'))
    ok = 0
    bad = 0
    print(f"{data['version']} revision {data['revision']}, {len(data['cases'])} cases")
    for case in data['cases']:
        report = verify(case)
        want_accept = case['expect'] == 'accept'
        missing = [x for x in case['expect_failures'] if x not in report['failures']]
        extra = [x for x in report['failures'] if x not in case['expect_failures']]
        states_ok = report['states'] == case['expect_states']
        canonical_ok = True
        if 'canonical_hex' in case:
            produced = canonical_bytes_of_single_envelope(case['bundle'])
            canonical_ok = produced is not None and produced.hex() == case['canonical_hex']
        good = report['accepted'] == want_accept and not missing and states_ok and canonical_ok
        ok += good
        bad += not good
        line = (
            f"{'ok  ' if good else 'FAIL'} {case['name']:32} "
            f"expect={case['expect']:6} got={'accept' if report['accepted'] else 'reject'} "
            f"states={'match' if states_ok else 'DIFFER'} "
            f"required={json.dumps(case['expect_failures'])} reported={json.dumps(report['failures'])}"
        )
        if 'canonical_hex' in case:
            line += f" canonical_hex={'match' if canonical_ok else 'DIFFER'}"
        if missing:
            line += f" MISSING={json.dumps(missing)}"
        if extra:
            line += f" extra={json.dumps(extra)}"
        witnessed = sorted((s, report['results'].get(s)) for s, v in report['states'].items() if v == 'witness-signed')
        if witnessed:
            line += ' witness-signed=' + ','.join(f'{s}({r})' for s, r in witnessed)
        print(line)
    print(f"\n{ok} ok, {bad} mismatches, {len(data['cases'])} cases")
    sys.exit(0 if bad == 0 else 1)


if __name__ == '__main__':
    main(sys.argv[1])
