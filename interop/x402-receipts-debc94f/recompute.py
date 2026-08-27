#!/usr/bin/env python3
"""Independent recomputation of every x402-receipts vector envelopeDigest.

Standard library only: json and hashlib. Imports no code from the repository under
test. The pinned expected digests are loaded only AFTER every digest has been
computed, so no expected value can influence a computed one.

SPEC.md section 1 at the pinned SHA states the construction:

    receiptDigest(receipt) === envelopeDigest(receipt) === sha256hex(canonicalizeJCS(receipt))

and names the canonicalization "RFC 8785 (JCS)". The JCS rules this script implements
are the ones that corpus exercises; the float rule raises NotImplementedError rather
than approximating, so an input needing it is reported instead of guessed.

Usage:  python3 recompute.py [path-to-x402-receipts-checkout]
Default path: /tmp/x402-receipts-repro
"""
import glob
import hashlib
import json
import os
import re
import sys

REPO = sys.argv[1] if len(sys.argv) > 1 else "/tmp/x402-receipts-repro"

# ---- RFC 8785 (JCS) for this corpus's value domain --------------------------

def utf16_code_units(s):
    """RFC 8785 section 3.2.3: object members sort by UTF-16 code unit sequence."""
    b = s.encode("utf-16-be")
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)]

def js_number(n):
    """RFC 8785 section 3.2.2.3: the ECMAScript Number::toString algorithm.

    This corpus carries integers only. Any non-integer reaches the float branch and
    raises, because a wrong float serialization would silently produce a wrong digest.
    """
    if isinstance(n, bool):
        raise TypeError("bool is not a number")
    if isinstance(n, int):
        if not (-(2 ** 53 - 1) <= n <= (2 ** 53 - 1)):
            raise ValueError("integer outside the exactly representable range: %r" % (n,))
        return str(n)
    raise NotImplementedError(
        "non-integer number %r: the JCS float serialization rule is not implemented "
        "here, and this script does not approximate it" % (n,)
    )

def jcs(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return js_number(value)
    if isinstance(value, str):
        # Standard JSON string encoding: mandatory escapes for the quote, the
        # backslash and control characters below 0x20, and nothing further.
        # ensure_ascii=False so any non-ASCII character passes through literally.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: utf16_code_units(kv[0]))
        return "{" + ",".join(jcs(k) + ":" + jcs(v) for k, v in members) + "}"
    raise TypeError("value of type %s has no JCS serialization here" % type(value).__name__)

def envelope_digest(receipt):
    return hashlib.sha256(jcs(receipt).encode("utf-8")).hexdigest()

# ---- which rules this corpus actually exercises -----------------------------

def survey(objs):
    seen = {"objects": 0, "arrays": 0, "strings": 0, "integers": 0, "nulls": 0, "bools": 0}
    non_ascii_keys, non_ascii_strings, control_chars, non_integers, astral_keys = [], [], [], [], []

    def walk(o):
        if isinstance(o, dict):
            seen["objects"] += 1
            for k, v in o.items():
                if any(ord(c) > 127 for c in k):
                    non_ascii_keys.append(k)
                if any(ord(c) > 0xFFFF for c in k):
                    astral_keys.append(k)
                walk(v)
        elif isinstance(o, list):
            seen["arrays"] += 1
            for v in o:
                walk(v)
        elif isinstance(o, bool):
            seen["bools"] += 1
        elif isinstance(o, int):
            seen["integers"] += 1
        elif isinstance(o, float):
            non_integers.append(o)
        elif isinstance(o, str):
            seen["strings"] += 1
            if any(ord(c) > 127 for c in o):
                non_ascii_strings.append(o)
            if any(ord(c) < 0x20 for c in o):
                control_chars.append(o)
        elif o is None:
            seen["nulls"] += 1

    for o in objs:
        walk(o)
    return seen, non_ascii_keys, non_ascii_strings, control_chars, non_integers, astral_keys

# ---- run --------------------------------------------------------------------

def main():
    paths = sorted(glob.glob(os.path.join(REPO, "vectors", "*.json")))
    if not paths:
        print("no vectors found under %s" % os.path.join(REPO, "vectors"))
        return 2

    receipts, computed = [], []
    for p in paths:
        vector = json.load(open(p, encoding="utf-8"))
        receipts.append(vector["receipt"])
        computed.append((os.path.basename(p)[:-5], envelope_digest(vector["receipt"])))

    seen, na_keys, na_strings, ctrl, floats, astral = survey(receipts)

    print("value domain across the %d receipt envelopes" % len(receipts))
    print("  objects %(objects)d  arrays %(arrays)d  strings %(strings)d  integers %(integers)d"
          "  nulls %(nulls)d  booleans %(bools)d" % seen)
    print("  non-ASCII keys: %d   non-ASCII string values: %d   control characters: %d"
          "   non-integer numbers: %d   astral-plane keys: %d"
          % (len(na_keys), len(na_strings), len(ctrl), len(floats), len(astral)))
    print()
    print("JCS rules EXERCISED by these inputs")
    print("  RFC 8785 3.2.3   member ordering by UTF-16 code unit, on %d objects" % seen["objects"])
    print("  RFC 8785 3.2.2.3 ECMAScript Number::toString, on %d integers" % seen["integers"])
    print("  string encoding with mandatory escapes only, on %d strings" % seen["strings"])
    print("  separators with no whitespace, on every container")
    print("  UTF-8 output encoding, at the hash boundary")
    print()
    print("JCS rules NOT exercised by these inputs, so this run is no evidence about them")
    if not astral:
        print("  non-BMP (astral) key ordering: no astral key present")
    if not floats:
        print("  float serialization: no non-integer number present")
    if not ctrl:
        print("  control character escaping: no control character present")
    if not na_strings and not na_keys:
        print("  non-ASCII passthrough: no non-ASCII character present")
    if seen["arrays"] == 0:
        print("  array serialization inside the envelope: no array present")
    print()

    # Expected values are read only now, after every digest above is computed.
    pinned = {}
    md = os.path.join(REPO, "vectors", "VECTORS.md")
    text = open(md, encoding="utf-8").read()
    for m in re.finditer(r"\|\s*`([a-z0-9\-]+)`\s*\|\s*`([0-9a-f]{64})`\s*\|", text):
        pinned[m.group(1)] = m.group(2)

    print("%-42s%-68s%s" % ("vector", "independent sha256", "matches pinned"))
    print("-" * 128)
    matched = 0
    for vid, digest in computed:
        same = digest == pinned.get(vid)
        matched += 1 if same else 0
        print("%-42s%-68s%s" % (vid, digest, "YES" if same else "NO"))
    print("-" * 128)
    print("vectors independently recomputed: %d   matching the pinned digest: %d"
          % (len(computed), matched))
    return 0 if matched == len(computed) else 1

if __name__ == "__main__":
    sys.exit(main())
