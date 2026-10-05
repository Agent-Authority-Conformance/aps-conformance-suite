set -u
rm -rf /tmp/rs/aevmut && cp -r /tmp/rs/aev /tmp/rs/aevmut && cd /tmp/rs/aevmut
f=vectors-receipt-signature/receipts/v814de39bf68212fc.json
python3 - "$f" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
def find(o):
    if isinstance(o,dict):
        for k,v in o.items():
            if k in ('signature','sig') and isinstance(v,str): return (o,k)
        for v in o.values():
            r=find(v)
            if r: return r
    return None
r=find(d); assert r, "no signature field"
o,k=r; s=o[k]; i=10; c='A' if s[i]!='A' else 'B'
o[k]=s[:i]+c+s[i+1:]
json.dump(d,open(p,'w'),indent=2)
print('flipped char',i,'of field',k,'(length',len(s),')')
PY
export VERITASACTA_VERIFY_VERSION=0.10.21 PATH=/tmp/rs/venv13/bin:$PATH
agent-evidence-vectors --corpus vectors-receipt-signature --verifier 'python3 vectors-receipt-signature/tools/veritasacta-verify.py' > /tmp/rs/ctrl2.txt 2>&1; echo "ctrl2_exit=$?"
grep -E "v814de39bf68212fc|^totals" /tmp/rs/ctrl2.txt
