# Recompute hash references between the Bernstein TRACE trust-record vectors. Exits nonzero on any mismatch.
# digest = "sha256:" + sha256(RFC 8785 serialization of the full parsed record), rfc8785 0.1.4.
# A sort_keys JSON digest is printed for contrast only. It differs from RFC 8785 in more than key order.
import json,hashlib,rfc8785,sys
V=sys.argv[1] if len(sys.argv)>1 else 'vectors'
L=lambda n: json.load(open(f'{V}/{n}-trust-record.json'))
def dig(r): return 'sha256:'+hashlib.sha256(rfc8785.dumps(r)).hexdigest()
def sortkeys(r): return 'sha256:'+hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
for p,c in [('delegated-parent','delegated-child'),('delegated-child','delegated-grandchild'),('supplementary-plane-parent','supplementary-plane-child')]:
    P,C=L(p),L(c); want=C['delegation']['parent_record_hash']
    assert dig(P)==want, f'{c}: parent_record_hash does not match the RFC 8785 digest of {p}'
    print(f'{c} -> {p}: rfc8785_match=True sort_keys_match={sortkeys(P)==want}')
A=L('aggregate'); refs=[x for x in A.get('references',[]) if x.get('rel')=='member-execution']
members={n:L(n) for n in ['delegated-parent','delegated-child','delegated-grandchild']}
assert len(refs)==len(members)==3, f'expected 3 member-execution references, got {len(refs)}'
matched=set()
for r in refs:
    hit=[n for n,m in members.items() if dig(m)==r.get('digest')]
    assert len(hit)==1, f'unexpected digest matches for {r.get("id")}: {hit}'
    name=hit[0]
    assert r.get('id')==members[name].get('subject'), f'id {r.get("id")} is not the subject of {name}'
    assert name not in matched, f'duplicate member {name}'
    matched.add(name)
    print(f"  ref id={r.get('id')} digest_matches={name} id_equals_subject=True")
assert matched==set(members), f'members not covered: {set(members)-matched}'
print('aggregate: 3 references, 3 distinct members, all digests and ids match')
print('ALL CHECKS PASS')
