#!/usr/bin/env python3
"""icam_runner.py -- independent (non-author-produced) runner for the
icam-temporal-derivation candidate (lab PR #218, merged at 3c36e95).

Operator: ShaoBao Li (Lee) / Aicent Stack (RTTP CRI 27 / IQA CRI 28).
Normative basis: draft-li-rttp-iqa-addressing-02 (TXT sha256 02491c5a...85044),
sections 6.1, 6.3, 7.2. Rules below are derived from the published draft text,
not from the candidate's reference oracle (check.py); the candidate's input and
result vocabulary is adopted only as the interface contract.

Two layers, kept separate (candidate "bounded question"):
  DERIVE         -- section 6.1 lease reliance: a verifier checks the stated
                    expiry against its own clock; an expired lease MUST be
                    treated as expired. Whether the lease instant itself is
                    fresh or expired is a deployment convention; implementations
                    SHOULD declare which boundary they use.
  WIRE_TIME_GATE -- section 7.2 verification step (2) ONLY: the receiver
                    "rejects the frame if lease_expiry is earlier than the
                    current time". Strictly earlier rejects; the instant of
                    equality passes this isolated gate regardless of the
                    reliance convention. A pass is NOT an accepted frame.

The advisory input supplied_boundary_classification is never consulted: it is
not an IQA wire field, and the candidate's negative controls exist to punish
any oracle that trusts it.
"""
import hashlib
import json
import sys
from pathlib import Path

UINT64_MAX = 2**64 - 1
CONVENTIONS = ('fresh_at_instant', 'expired_at_instant')

DRAFT_SHA = '02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044'
VENDOR_REF = '3c36e95'


def _integral_clocks(inp):
    """Both clock values must be present integers within the u64 wire range
    (section 7.2: lease_expiry is unsigned 64-bit big-endian, Unix seconds)."""
    now, expiry = inp.get('verifier_now_unix_s'), inp.get('lease_expiry_unix_s')
    if type(now) is not int or type(expiry) is not int:
        return None
    if not (0 <= now <= UINT64_MAX and 0 <= expiry <= UINT64_MAX):
        return None
    return now, expiry


def derive_reliance(inp):
    """Section 6.1 reliance derivation, from the verifier's own clock."""
    clocks = _integral_clocks(inp)
    if clocks is None:
        return 'insufficient_input'          # local precondition, not an IQA code
    now, expiry = clocks
    conv = inp.get('boundary_convention')
    if conv is not None and conv not in CONVENTIONS:
        return 'invalid_convention'          # local precondition: bad declared input, regardless of time relation
    if now < expiry:
        return 'fresh'
    if now > expiry:
        return 'expired'
    if conv is None:
        # Equality with no declared convention: the draft says implementations
        # SHOULD declare; with nothing declared the honest result is that the
        # boundary is undetermined (interpretive, not a wire refusal reason).
        return 'boundary_undetermined'
    return 'fresh' if conv == 'fresh_at_instant' else 'expired'


def wire_time_gate(inp):
    """Section 7.2 step (2) only: reject iff lease_expiry is earlier than now."""
    clocks = _integral_clocks(inp)
    if clocks is None:
        return 'insufficient_input'
    now, expiry = clocks
    return 'time_gate_reject' if expiry < now else 'time_gate_pass'


RULES = {'DERIVE': derive_reliance, 'WIRE_TIME_GATE': wire_time_gate}


def run(vectors):
    records, failures = [], 0
    for c in vectors['cases']:
        observed = RULES[c['rule']](c['input'])
        agree = observed == c['expected']
        failures += not agree
        records.append({'id': c['id'], 'rule': c['rule'], 'layer': c.get('layer'),
                        'case_status': c.get('case_status'), 'basis': c.get('basis'),
                        'expected': c['expected'], 'observed': observed,
                        'agree': agree})
    return records, failures


# --- independent mutation battery (ours, distinct from the candidate's) ---
def _mutants():
    def m_trust_flag(inp):
        flag = inp.get('supplied_boundary_classification')
        if flag == 'before':
            return 'fresh'
        if flag == 'after':
            return 'expired'
        return derive_reliance(inp)

    def m_always_fresh(inp):
        return 'fresh'

    def m_always_expired(inp):
        return 'expired'

    def m_gate_strict(inp):
        c = _integral_clocks(inp)
        if c is None:
            return 'insufficient_input'
        now, expiry = c
        return 'time_gate_reject' if expiry <= now else 'time_gate_pass'

    def m_undeclared_inclusive(inp):
        r = derive_reliance(inp)
        return 'fresh' if r == 'boundary_undetermined' else r

    def m_hardcode_120(inp):
        c = _integral_clocks(inp)
        if c is None:
            return 'insufficient_input'
        now, expiry = c
        return 'fresh' if expiry - now <= 120 else 'expired'

    return {
        'trusts-advisory-flag': m_trust_flag,
        'always-fresh': m_always_fresh,
        'always-expired': m_always_expired,
        'wire-gate-rejects-equality': m_gate_strict,
        'undeclared-boundary-inclusive': m_undeclared_inclusive,
        'hardcoded-120s-window': m_hardcode_120,
    }


def run_mutations(vectors):
    out = {}
    for name, fn in _mutants().items():
        killed_by = []
        for c in vectors['cases']:
            if c['rule'] == 'WIRE_TIME_GATE' and name not in ('wire-gate-rejects-equality',):
                # mutation battery for DERIVE mutants: only score gate cases
                # against the gate mutant and vice versa
                if fn is not wire_time_gate and name != 'wire-gate-rejects-equality':
                    continue
            observed = fn(c['input'])
            if observed != c['expected']:
                killed_by.append(c['id'])
        out[name] = killed_by
    return out


def main(argv):
    vectors_path = argv[1] if len(argv) > 1 else None
    out_path = argv[2] if len(argv) > 2 else None
    doc = json.loads(Path(vectors_path).read_text(encoding='utf-8'))
    records, failures = run(doc)
    for r in records:
        print('%s %-6s [%s/%s] expected=%-22s observed=%-22s %s'
              % ('PASS' if r['agree'] else 'FAIL', r['id'], r['layer'], r['case_status'],
                 r['expected'], r['observed'], '' if r['agree'] else '<< MISMATCH'))
    total = len(records)
    print('SUMMARY %d/%d agree (independent runner, non-author-produced)' % (total - failures, total))

    mut = run_mutations(doc)
    killed = sum(1 for v in mut.values() if v)
    for name, by in mut.items():
        print('MUTANT %-30s %s' % (name, ('killed by ' + ','.join(by)) if by else 'SURVIVED'))
    print('MUTATION SUMMARY %d/%d killed (independent battery)' % (killed, len(mut)))

    if out_path:
        vendor_files = {}
        vdir = Path(vectors_path).parent
        for f in ('CANDIDATE.md', 'CHECKSUMS.sha256', 'RUN_REPORT.txt', 'check.py',
                  'metamorphic.py', 'mutate.py', 'vectors.json'):
            p = vdir / f
            if p.exists():
                vendor_files[f] = hashlib.sha256(p.read_bytes()).hexdigest()
        payload = {
            'runner': 'icam-runner',
            'operator': 'ShaoBao Li (Lee) / Aicent Stack',
            'mode': 'independent (non-author-produced) run of author-produced vectors',
            'candidate': {'name': doc['name'], 'revision': doc.get('revision'),
                          'vendor_ref': VENDOR_REF,
                          'vendor_files_sha256': vendor_files},
            'normative_basis': {'draft': 'draft-li-rttp-iqa-addressing-02',
                                'sections': ['6.1', '6.3', '7.2'],
                                'txt_sha256': DRAFT_SHA},
            'summary': {'cases': total, 'agree': total - failures,
                        'mutants': len(mut), 'mutants_killed': killed},
            'records': records,
            'mutation_battery': mut,
        }
        Path(out_path).write_text(json.dumps(payload, indent=1, sort_keys=True) + '\n',
                                  encoding='utf-8', newline='')
        print('run output written:', out_path)
    return int(failures != 0 or killed != len(mut))


if __name__ == '__main__':
    sys.exit(main(sys.argv))
