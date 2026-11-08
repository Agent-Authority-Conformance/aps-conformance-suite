#!/usr/bin/env python3
"""Author-written reference oracle. Not independent evidence of implementation conformance."""
import json, sys
from pathlib import Path

UINT64_MAX = 2**64 - 1

def time_inputs(i):
    now, expiry = i.get('verifier_now_unix_s'), i.get('lease_expiry_unix_s')
    if type(now) is not int or type(expiry) is not int:
        return None
    if not (0 <= now <= UINT64_MAX and 0 <= expiry <= UINT64_MAX):
        return None
    return now, expiry

def evaluate(i, rule='DERIVE'):
    values = time_inputs(i)
    if values is None:
        return 'insufficient_input'  # ICAM local precondition, not an IQA code
    now, expiry = values
    if rule == 'WIRE_TIME_GATE':
        # Section 7.2 step 2 ONLY. A pass is not a valid frame or accepted authority.
        return 'time_gate_reject' if expiry < now else 'time_gate_pass'
    if rule != 'DERIVE':
        raise ValueError('unknown rule: ' + str(rule))
    conv = i.get('boundary_convention')
    if conv not in ('fresh_at_instant', 'expired_at_instant', None):
        return 'invalid_convention'  # ICAM local precondition
    # supplied_boundary_classification is intentionally never consulted.
    if now < expiry: return 'fresh'
    if now > expiry: return 'expired'
    if conv is None: return 'boundary_undetermined'  # interpretive; SHOULD not MUST
    return 'fresh' if conv == 'fresh_at_instant' else 'expired'

def main(path):
    doc = json.loads(Path(path).read_text(encoding='utf-8'))
    failures=0
    for c in doc['cases']:
        observed = evaluate(c['input'],c['rule'])
        ok=observed==c['expected']; failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} {c['id']} [{c['layer']}/{c['case_status']}] expected={c['expected']} actual={observed}")
    print(f"SUMMARY {len(doc['cases'])-failures}/{len(doc['cases'])} agree; author-produced fixture consistency only")
    return int(failures!=0)
if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv)>1 else str(Path(__file__).with_name('vectors.json'))))
