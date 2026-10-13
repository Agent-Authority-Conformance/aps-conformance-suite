# Falsifiability probe for check.py: each mutant of the vector file must make it exit non-zero.
# Usage: python3 -I mutate.py <check.py> <vectors.json> <source.json> <scratch dir>
import json, subprocess, sys
from pathlib import Path

check, vectors, source, scratch = sys.argv[1], Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
scratch.mkdir(parents=True, exist_ok=True)
base = json.loads(vectors.read_text(encoding='utf-8'))

def m_hint_back(s): s['drift_definition']['annotations']['readOnlyHint'] = True
def m_extra_field(s): s['drift_definition']['title'] = 'X'
def m_expect_binds(s): next(v for v in s['vectors'] if v['name'] == 'annotation-drift')['expect']['tool_digest_binds'] = True
def m_baseline_desc(s): s['observed_tools'][0]['description'] += ' '
def m_drift_gate_digest(s):
    by = {v['name']: v for v in s['vectors']}
    by['annotation-drift']['gate']['observed_tool_digest'] = by['annotation-match']['gate']['observed_tool_digest']

bad = 0
for name, fn in [('drift-hint-back-true', m_hint_back), ('drift-extra-field', m_extra_field),
                 ('expect-drift-binds', m_expect_binds), ('baseline-desc-edit', m_baseline_desc),
                 ('drift-gate-digest', m_drift_gate_digest)]:
    s = json.loads(json.dumps(base))
    fn(s)
    out = scratch / f'{name}.json'
    out.write_text(json.dumps(s, ensure_ascii=False), encoding='utf-8')
    r = subprocess.run([sys.executable, '-I', check, str(out), source], capture_output=True, text=True)
    fails = r.stdout.count('  FAIL  ')
    caught = r.returncode != 0 and fails > 0
    bad += not caught
    print(f'{name}: exit={r.returncode} fails={fails} {"caught" if caught else "MISSED"}')
print('all mutants caught' if bad == 0 else f'{bad} mutant(s) missed')
sys.exit(1 if bad else 0)
