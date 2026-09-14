"""Harness regressions. These test run.py AS AN ARTIFACT, not the checker.

The point of finding 4 on #189 was that a harness which regenerates the fixtures
before grading them cannot be tested at all. These pin the read-only property
itself: a detected mutation must be reported AND left on disk untouched.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RECORD = os.path.abspath(os.path.join(HERE, '..', '..'))
CASE = 'CAND-COSAI-189-SINK-01.json'


def _copy_record():
    tmp = tempfile.mkdtemp(prefix='cosai189-harness-')
    dst = os.path.join(tmp, 'record')
    shutil.copytree(RECORD, dst, ignore=shutil.ignore_patterns('__pycache__'))
    return tmp, dst


def _verify(root):
    return subprocess.run([sys.executable, 'adapter/py/run.py'], cwd=root,
                          capture_output=True, text=True)


def _sha(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def case(name, mutate, expect_in_output=None):
    tmp, root = _copy_record()
    try:
        path = os.path.join(root, 'candidates-proposed', CASE)
        mutate(root, path)
        before = _sha(path) if os.path.exists(path) else None
        r = _verify(root)
        assert r.returncode != 0, f'{name}: verify exited 0 on a mutated record'
        if expect_in_output:
            blob = r.stdout + r.stderr
            assert expect_in_output in blob, f'{name}: {expect_in_output!r} not reported\n{blob}'
        if before is not None:
            after = _sha(path)
            assert after == before, (f'{name}: verify REPAIRED the mutated file '
                                     f'({before[:12]} -> {after[:12]})')
        print(f'  ok  {name}')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _mutate_expectation(root, path):
    d = json.load(open(path))
    d['expected_if_adopted']['verdict'] = 'fail'
    open(path, 'w').write(json.dumps(d, indent=1, sort_keys=True) + '\n')


def _mutate_input(root, path):
    d = json.load(open(path))
    d['checker_input']['context']['producer_declared_capabilities'] = ['read_delegation']
    open(path, 'w').write(json.dumps(d, indent=1, sort_keys=True) + '\n')


def _add_extra(root, path):
    shutil.copy(path, os.path.join(root, 'candidates-proposed', 'CAND-UNVERIFIED-EXTRA.json'))


def _remove_case(root, path):
    os.remove(path)


case('mutated expectation is detected and left untouched', _mutate_expectation)
case('mutated checker input is detected and left untouched', _mutate_input)
case('an unexpected extra candidate file fails verification', _add_extra,
     'unexpected candidate file')
case('a missing declared candidate fails verification', _remove_case)

# clean record still verifies
tmp, root = _copy_record()
try:
    r = _verify(root)
    assert r.returncode == 0, f'clean record failed verification\n{r.stdout}{r.stderr}'
    print('  ok  clean record verifies')
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print('test_harness: ok')
