#!/usr/bin/env python3
"""Mutation sensitivity: 8 independently named faulty rules; author-produced only."""
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check import evaluate
C=json.loads(Path(__file__).with_name('vectors.json').read_text(encoding='utf-8'))['cases']
def base(c): return evaluate(c['input'],c['rule'])
def trust_flag(c):
    i=c['input'];hint=i.get('supplied_boundary_classification')
    if c['rule']!='DERIVE' or hint is None: return base(c)
    if hint=='before': return 'fresh'
    if hint=='after': return 'expired'
    if hint=='at':
        if i.get('boundary_convention') is None: return 'boundary_undetermined'
        return 'fresh' if i.get('boundary_convention')=='fresh_at_instant' else 'expired'
    return base(c)
def equality_fresh(c):
    i=c['input'];return 'fresh' if c['rule']=='DERIVE' and i.get('verifier_now_unix_s')==i.get('lease_expiry_unix_s') else base(c)
def equality_expired(c):
    i=c['input'];return 'expired' if c['rule']=='DERIVE' and i.get('verifier_now_unix_s')==i.get('lease_expiry_unix_s') else base(c)
def reverse(c):
    i=c['input'];n,e=i.get('verifier_now_unix_s'),i.get('lease_expiry_unix_s')
    if c['rule']=='DERIVE' and type(n)==int and type(e)==int and n!=e:return 'expired' if n<e else 'fresh'
    return base(c)
def default_inclusive(c):
    i=c['input'];return 'fresh' if c['rule']=='DERIVE' and i.get('boundary_convention') is None and i.get('verifier_now_unix_s')==i.get('lease_expiry_unix_s') else base(c)
def missing_clock(c):
    i=c['input'];return 'fresh' if c['rule']=='DERIVE' and i.get('verifier_now_unix_s') is None else base(c)
def missing_expiry(c):
    i=c['input'];return 'fresh' if c['rule']=='DERIVE' and i.get('lease_expiry_unix_s') is None else base(c)
def equality_frame_rejected(c):
    i=c['input'];return 'time_gate_reject' if c['rule']=='WIRE_TIME_GATE' and i.get('verifier_now_unix_s')==i.get('lease_expiry_unix_s') else base(c)
M={'trust-unverified-boundary-flag':trust_flag,'always-fresh-at-equality':equality_fresh,'always-expired-at-equality':equality_expired,'reversed-time-order':reverse,'assume-inclusive-undeclared':default_inclusive,'missing-clock-fails-open':missing_clock,'missing-expiry-fails-open':missing_expiry,'wire-frame-equality-rejected':equality_frame_rejected}
def main():
    killed=0
    for name,fn in M.items():
        hits=[c['id'] for c in C if fn(c)!=c['expected']];killed+=bool(hits)
        print(('KILLED ' if hits else 'ALIVE  ')+name+' by '+','.join(hits))
    print(f'SUMMARY {killed}/{len(M)} mutants killed (author-produced)')
    return int(killed!=len(M))
if __name__=='__main__':sys.exit(main())
