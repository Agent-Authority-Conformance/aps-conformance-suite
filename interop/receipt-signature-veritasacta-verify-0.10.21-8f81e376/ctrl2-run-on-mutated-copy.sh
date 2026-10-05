set -u
cd /tmp/rs/aevmut
export VERITASACTA_VERIFY_VERSION=0.10.21 PATH=/tmp/rs/venv13/bin:$PATH
python3 -c "import json;d=json.load(open('vectors-receipt-signature/receipts/v814de39bf68212fc.json'));print('sig now starts', str(d)[:0], 'ok')"
diff <(python3 -m json.tool /tmp/rs/aev/vectors-receipt-signature/receipts/v814de39bf68212fc.json) <(python3 -m json.tool vectors-receipt-signature/receipts/v814de39bf68212fc.json) | head -4
agent-evidence-vectors --vectors /tmp/rs/aevmut/vectors-receipt-signature --verifier 'python3 /tmp/rs/aev/vectors-receipt-signature/tools/veritasacta-verify.py' > /tmp/rs/ctrl2.txt 2>&1; echo "ctrl2_exit=$?"
grep -E "v814de39bf68212fc|^totals|refus|digest" /tmp/rs/ctrl2.txt | head -6
echo "--- unmutated copy through the same --vectors path (control for the control)"
agent-evidence-vectors --vectors /tmp/rs/aev/vectors-receipt-signature --verifier 'python3 /tmp/rs/aev/vectors-receipt-signature/tools/veritasacta-verify.py' > /tmp/rs/ctrl2ok.txt 2>&1; echo "ctrl2ok_exit=$?"; grep "^totals" /tmp/rs/ctrl2ok.txt
