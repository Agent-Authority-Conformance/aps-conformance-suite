#!/usr/bin/env python3
"""Metamorphic flag-independence and cross-layer equality test. No external IUT."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check import evaluate
C=json.loads(Path(__file__).with_name('vectors.json').read_text(encoding='utf-8'))['cases']
flags=('before','at','after',None,'nonsense')
checks=0
for c in C:
    i=c['input']; expected=evaluate(i,c['rule'])
    for flag in flags:
        alt={**i,'supplied_boundary_classification':flag}
        assert evaluate(alt,c['rule'])==expected,(c['id'],flag)
        checks+=1
# At equality wire time gate passes even for expired-at-instant reliance.
for c in C:
    i=c['input']
    if i.get('verifier_now_unix_s')==i.get('lease_expiry_unix_s') and type(i.get('verifier_now_unix_s')) is int:
        assert evaluate(i,'WIRE_TIME_GATE')=='time_gate_pass'
print(f'PASS {checks} flag-substitution invariance checks; equality wire-time gate separate (author-produced)')
