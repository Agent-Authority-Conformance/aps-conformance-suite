#!/usr/bin/env python3
"""Extract a runner's OWN reported vector numbers from its output.

WHY THIS IS SEPARATE FROM THE EXIT CODE. A command's exit status says one thing:
the command succeeded or it did not. It is not a vector count. The first version
of run-all.sh printed `pass=1 fail=0 skip=0` for every runner, derived from the
exit code alone, which reads like a one-vector suite. This reads the numbers the
runner itself printed, and reports nothing when the runner printed none.

Output: one line, `vectors=<n|na> vpass=<n|na> vfail=<n|na> vskip=<n|na> src=<pattern>`
"""
import re, sys, json

PATTERNS = [
    ('total-line',
     re.compile(r'^TOTAL:\s+(?P<total>\d+)\s+vectors\s+pass=(?P<p>\d+)\s+fail=(?P<f>\d+)\s+skip=(?P<s>\d+)', re.M)),
    ('summary-match',
     re.compile(r'^SUMMARY:\s+(?P<p>\d+)/(?P<total>\d+)\s+match expectation,\s+(?P<f>\d+)\s+failure', re.M)),
    ('n-of-m-declared',
     re.compile(r'ALL PASS \((?P<p>\d+) of (?P<total>\d+) declared fixture', re.M)),
    ('n-slash-m-checks',
     re.compile(r'^(?P<p>\d+)/(?P<total>\d+)\s+checks pass', re.M)),
    ('n-slash-m-colon',
     re.compile(r'^(?P<p>\d+)/(?P<total>\d+):\s', re.M)),
    ('n-slash-m-pass',
     re.compile(r'(?P<p>\d+)/(?P<total>\d+)\s+pass\b', re.M)),
    ('cases-reproduced',
     re.compile(r'^cases (?P<total>\d+), reproduced (?P<p>\d+), passed (?:true|True)', re.M)),
    ('mutations',
     re.compile(r'^ALL (?P<total>\d+) DECLARED MUTATIONS DETECTED', re.M)),
    ('pytest',
     re.compile(r'^(?P<p>\d+) passed(?:, (?P<f>\d+) failed)?', re.M)),
]

def from_json(text):
    """aat_runner.py and friends emit a JSON document with its own summary."""
    m = re.search(r'"vector_count":\s*(\d+)', text)
    if not m:
        return None
    total = int(m.group(1))
    mm = re.search(r'"matched":\s*(\d+)', text)
    mf = re.search(r'"failed":\s*(\d+)', text)
    if mm is None or mf is None:
        return None
    return total, int(mm.group(1)), int(mf.group(1)), total - int(mm.group(1)) - int(mf.group(1)), 'json-summary'

def main():
    text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
    j = from_json(text)
    if j:
        total, p, f, s, src = j
        print('vectors=%d vpass=%d vfail=%d vskip=%d src=%s' % (total, p, f, max(s, 0), src))
        return
    for name, pat in PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        g = m.groupdict()
        total = int(g['total']) if g.get('total') else None
        p = int(g['p']) if g.get('p') else None
        f = int(g['f']) if g.get('f') else None
        s = int(g['s']) if g.get('s') else None
        if name == 'mutations':
            p = total; f = 0; s = 0
        if total is not None and p is not None and f is None:
            f = total - p
        if s is None:
            s = 0 if (total is not None and p is not None and f is not None and p + f == total) else None
        out = []
        out.append('vectors=%s' % (total if total is not None else 'na'))
        out.append('vpass=%s' % (p if p is not None else 'na'))
        out.append('vfail=%s' % (f if f is not None else 'na'))
        out.append('vskip=%s' % (s if s is not None else 'na'))
        out.append('src=%s' % name)
        print(' '.join(out))
        return
    print('vectors=na vpass=na vfail=na vskip=na src=none')

if __name__ == '__main__':
    main()
