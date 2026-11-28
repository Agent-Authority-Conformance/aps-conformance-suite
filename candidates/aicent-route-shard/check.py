#!/usr/bin/env python3
"""Recompute each case's derivation or property verdict, compare with the
declared expectation. Rules are derived from the pinned source text
(draft-li-rttp-iqa-addressing-02, sections 4.4, 4.2 and 9.1), not from any
implementation. Standard library only. Exit 0 when every case agrees, 1
otherwise."""
import hashlib, json, os, sys


def derive(authority):
    """SHA-256(ASCII(canonical_authority))[0:16] per sec. 4.4; refuses input
    outside the canonical form (lowercase US-ASCII, sec. 4.2)."""
    if any(c.isupper() for c in authority):
        return None  # invalid input, MUST NOT be normalised
    try:
        raw = authority.encode("ascii")
    except UnicodeEncodeError:
        return None  # canonical_authority is US-ASCII
    return hashlib.sha256(raw).digest()[:16].hex()


def r_shard(case):
    got = derive(case["input"]["authority"])
    return got == case["expect_shard_hex"]


def shard_of(text):
    return hashlib.sha256(text.encode("utf-8")).digest()[:16].hex()


def r_action_independent(case):
    i, o = case["input"], case["outcome"]
    a, b = i["uri_a"], i["uri_b"]
    auth_a = a.split("://", 1)[1].split("/", 1)[0]
    auth_b = b.split("://", 1)[1].split("/", 1)[0]
    same = derive(auth_a) == derive(auth_b)
    return ("conformant" if o.get("same_route_shard") == same else "nonconformant")


def r_authority_only(case):
    i, o = case["input"], case["outcome"]
    text = i["derivation_input"]
    # the derivation takes the authority alone: strip scheme and action if given
    auth = text.split("://", 1)[1] if "://" in text else text
    auth = auth.split("/", 1)[0]
    expected = derive(auth)
    return ("conformant" if o.get("route_shard_hex") == expected and expected is not None
            else "nonconformant")


def r_canonical_form(case):
    i, o = case["input"], case["outcome"]
    refused = derive(i["authority"]) is None
    if o.get("derivation_refused"):
        return "conformant" if refused else "nonconformant"
    # a derivation was produced: it must not exist for non-canonical input
    return "nonconformant" if refused else "conformant"


def r_full_authority(case):
    i, o = case["input"], case["outcome"]
    text = i["derivation_input"]
    # canonical_authority is intent "." pillar "." root: exactly three segments
    if text.count(".") != 2 or any(s == "" for s in text.split(".")):
        return "nonconformant"  # the derivation input is not a full authority
    expected = derive(text)
    return ("conformant" if expected is not None
            and o.get("route_shard_hex") == expected else "nonconformant")


def r_distinct(case):
    i, o = case["input"], case["outcome"]
    if o.get("routed_by_display_form") or o.get("treated_as_same_subject"):
        return "nonconformant"  # the display form is not a sole identifier
    if "same_route_shard" in o:
        same = derive(i["authority_a"]) == derive(i["authority_b"])
        return "conformant" if o["same_route_shard"] == same else "nonconformant"
    return "conformant"


RULES = {"R-SHARD": r_shard, "R-ACTION-INDEPENDENT": r_action_independent,
         "R-AUTHORITY-ONLY": r_authority_only, "R-CANONICAL-FORM": r_canonical_form,
         "R-FULL-AUTHORITY": r_full_authority, "R-DISTINCT-AUTHORITIES": r_distinct}


def evaluate(case, rules=RULES):
    if callable(rules) and not isinstance(rules, dict):
        return rules(case)
    return rules[case["rule"]](case)


def main(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")):
    doc = json.load(open(path, encoding="utf-8"))
    bad = 0
    for c in doc["cases"]:
        got = evaluate(c)
        ok = got == c.get("expect", True)
        flag = "BAD" if not ok else "ok "
        bad += not ok
        print(f"{flag} {c['id']:7} {c['rule']:22} {c['name'][:54]}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
