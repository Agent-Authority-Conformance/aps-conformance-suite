#!/usr/bin/env python3
"""Weaken or distort each rule in a plausible way and show that some case catches
it. Exit 0 when every mutant is killed."""
import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check

D = check.derive
shard16 = lambda a: hashlib.sha256(a.encode("ascii")).digest()[:16].hex()


def m_truncate_8(case):
    if case["rule"] == "R-SHARD":
        a = case["input"]["authority"]
        return hashlib.sha256(a.encode("ascii")).digest()[:8].hex() == case["expect_shard_hex"]
    return check.evaluate(case)


def m_truncate_32(case):
    if case["rule"] == "R-SHARD":
        a = case["input"]["authority"]
        return hashlib.sha256(a.encode("ascii")).digest().hex() == case["expect_shard_hex"]
    return check.evaluate(case)


def m_lowercase_first(case):
    rules = dict(check.RULES)
    rules["R-SHARD"] = lambda c: shard16(c["input"]["authority"].lower()) == c["expect_shard_hex"]
    rules["R-CANONICAL-FORM"] = lambda c: (
        "conformant" if (c["outcome"].get("derivation_refused") is False
                         and c["outcome"].get("route_shard_hex") == shard16(
                             c["input"]["authority"].lower()))
        else check.RULES["R-CANONICAL-FORM"](c))
    return check.evaluate(case, rules)


def m_include_action(case):
    rules = dict(check.RULES)
    def r_ai(c):
        i, o = c["input"], c["outcome"]
        ha = hashlib.sha256(i["uri_a"].encode("utf-8")).digest()[:16].hex()
        hb = hashlib.sha256(i["uri_b"].encode("utf-8")).digest()[:16].hex()
        return "conformant" if o.get("same_route_shard") == (ha == hb) else "nonconformant"
    rules["R-ACTION-INDEPENDENT"] = r_ai
    return check.evaluate(case, rules)


def m_include_scheme(case):
    rules = dict(check.RULES)
    def r_ao(c):
        return ("conformant" if c["outcome"].get("route_shard_hex") ==
                hashlib.sha256(c["input"]["derivation_input"].encode("utf-8")).digest()[:16].hex()
                else "nonconformant")
    rules["R-AUTHORITY-ONLY"] = r_ao
    return check.evaluate(case, rules)


def m_intent_only(case):
    rules = dict(check.RULES)
    def r_fa(c):
        i, o = c["input"], c["outcome"]
        intent = i["derivation_input"].split(".")[0]
        exp = shard16(intent)
        return "conformant" if o.get("route_shard_hex") == exp else "nonconformant"
    rules["R-FULL-AUTHORITY"] = r_fa
    return check.evaluate(case, rules)


def m_display_form_routing(case):
    rules = dict(check.RULES)
    def r_da(c):
        i, o = c["input"], c["outcome"]
        same = i["authority_a"].split(".")[0] == i["authority_b"].split(".")[0]
        return "conformant" if o.get("treated_as_same_subject", False) == same else "nonconformant"
    rules["R-DISTINCT-AUTHORITIES"] = r_da
    return check.evaluate(case, rules)


M = {
 "derive: truncation 8 octets": m_truncate_8,
 "derive: no truncation (32 octets)": m_truncate_32,
 "derive: uppercase lowercased before hashing": m_lowercase_first,
 "derive: action participates": m_include_action,
 "derive: scheme participates": m_include_scheme,
 "derive: intent segment alone": m_intent_only,
 "derive: display form routing accepted": m_display_form_routing,
}

M["property rules: always conformant"] = lambda c: True
M["property rules: always nonconformant"] = lambda c: "nonconformant"


def main():
    cases = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))["cases"]
    killed = 0
    for name, fn in M.items():
        hits = [c["id"] for c in cases if check.evaluate(c, _wrap(fn)) != c.get("expect", True)]
        killed += bool(hits)
        print(("killed " if hits else "ALIVE  ") + f"{name:45} by {','.join(hits) or '-'}")
    print(f"{killed}/{len(M)} mutants killed")
    return 0 if killed == len(M) else 1


def _wrap(fn):
    def evaluator(case, rules=None):
        try:
            r = fn(case)
        except Exception:
            r = None
        if case["rule"] == "R-SHARD":
            return r is True
        return r
    return evaluator


if __name__ == "__main__":
    sys.exit(main())
