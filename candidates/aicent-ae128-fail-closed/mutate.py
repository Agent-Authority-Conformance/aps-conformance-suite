#!/usr/bin/env python3
"""Weaken or distort each rule in a plausible way and show that some case catches
it. Exit 0 when every mutant is killed."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check


def accept_all(frame):
    return None


def reject_all(frame):
    return "length"


def verify_true(frame, key=check.KEY):
    return True


def verify_false(frame, key=check.KEY):
    return False


def verify_unzeroed(frame, key=check.KEY):
    # distortion: HMAC covers the raw frame, attestation bytes not zeroed
    mac = __import__("hmac").new(key, bytes(frame), __import__("hashlib").sha256).digest()
    return __import__("hmac").compare_digest(mac, frame[32:64])


def verify_truncated_coverage(frame, key=check.KEY):
    # distortion: coverage stops at byte 80; the standing byte at offset 80 and
    # everything after it rides unauthenticated (extension is zero on parseable
    # frames, so the positive frame still verifies)
    mac = __import__("hmac").new(key, frame[0:32] + b"\x00" * 32 + frame[64:80],
                                 __import__("hashlib").sha256).digest()
    return __import__("hmac").compare_digest(mac, frame[32:64])


P = check.parse
M = {
 "parse: length check dropped": lambda f: None if len(f) in (127, 129) else P(f),
 "parse: magic accepted": lambda f: None if f[0:4] != b"IQAE" else P(f),
 "parse: version accepted": lambda f: None if f[4] != 1 else P(f),
 "parse: algorithm accepted": lambda f: None if f[5] != 1 else P(f),
 "parse: flags check dropped": lambda f: None if f[6:8] != b"\x00\x00" else P(f),
 "parse: standing closed set opened": lambda f: None if f[80] not in check.STANDING_SET else P(f),
 "parse: reserved ignored": lambda f: None if any(f[81:96]) else P(f),
 "parse: extension ignored": lambda f: None if any(f[96:128]) else P(f),
 "parse: organ charset ignored": lambda f: None if any(b > 0x7F for b in f[64:72]) else P(f),
 "parse: always accept": accept_all,
 "parse: always reject": reject_all,
 "verify: always pass": verify_true,
 "verify: always fail": verify_false,
 "verify: zeroing omitted": verify_unzeroed,
 "verify: coverage stops before standing byte": verify_truncated_coverage,
}

def main():
    cases = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))["cases"]
    killed = 0
    for name, fn in M.items():
        if name.startswith("parse:"):
            # parse mutant: every case must still evaluate to its expectation
            hits = [c["id"] for c in cases if not check.evaluate(c, fn, check.verify)]
        else:
            # verify mutant: only parse-accept cases reach verification, and a
            # parse mutant would never touch them; attribute kills honestly
            hits = [c["id"] for c in cases
                    if c["expect_parse"] == "accept"
                    and not check.evaluate(c, check.parse, fn)]
        killed += bool(hits)
        print(("killed " if hits else "ALIVE  ") + f"{name:45} by {','.join(hits) or '-'}")
    print(f"{killed}/{len(M)} mutants killed")
    return 0 if killed == len(M) else 1

if __name__ == "__main__":
    sys.exit(main())
