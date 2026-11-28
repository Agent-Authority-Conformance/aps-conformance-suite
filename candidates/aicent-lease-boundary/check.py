#!/usr/bin/env python3
"""Recompute each case's verdict from its input and outcome, compare with the declared expectation.
Standard library only. Exit 0 when every case agrees, 1 otherwise."""
import json, os, sys

def combine(parts):
    values = list(parts.values())
    if "nonconformant" in values:
        return "nonconformant"
    if "ambiguous" in values:
        return "ambiguous"
    return "conformant"

def declared_parts(i, o):
    if i.get("declared_boundary") is not None:
        return None
    # sect-6.1: whether the lease instant itself counts as fresh or as expired is a
    # deployment convention, and implementations SHOULD declare which boundary they use.
    # With no declaration, an answer at the boundary instant sits inside one of the two
    # licensed readings, and the case cannot be settled until the boundary is declared.
    licensed = o.get("reason") is None or o.get("reason") == "evidence_expired"
    return {"answer_within_a_convention": "conformant" if licensed else "nonconformant",
            "declaration": "ambiguous"}

def r_declared(i, o):
    p = declared_parts(i, o)
    if p:
        return combine(p)
    if i.get("frame_accepted_at_equality"):
        # sect-7.2, verification procedure step 2: the receiver rejects the frame when
        # lease_expiry is earlier than the current time, so a frame at the boundary instant
        # is accepted; the declared convention governs reliance on the answer, not frame
        # validity, and the two layers are distinct.
        return "conformant" if o.get("reason") == "evidence_expired" else "nonconformant"
    if i.get("declared_boundary") == "fresh_at_instant":
        return "conformant" if o.get("reason") is None else "nonconformant"
    return "conformant" if o.get("reason") == "evidence_expired" else "nonconformant"

def r_noextend(i, o):
    past = i["now_ms"] > i["lease_expiry_ms"]
    if not past:
        return "conformant" if o.get("reason") is None else "nonconformant"
    # sect-6.1: an answer whose lease has expired MUST be treated as expired; a verifier
    # MUST NOT extend, renew, or reinterpret an expired lease except by obtaining a new
    # answer. sect-6.3-eval: an answer read past its expiry MUST be answered as expired,
    # never replayed as fresh.
    return "conformant" if o.get("reason") == "evidence_expired" else "nonconformant"

def r_mode(i, o):
    # Every mode case in this family has an unreachable organ at answer time; the rule is
    # about what the declared mode and the age of the cache owe then. The mapping of an
    # unreachable source to authority_not_determined, never read as assent, is taken as
    # given here (it is tested by the aicent-grant-ref candidate); what is tested is the
    # mode-conditional refusal and the policy split of cached-lease mode.
    if i["mode"] == "live":
        # sect-6.2: in live mode every call is expected to be refused when the organ is
        # unreachable, regardless of the age of any cached answer.
        return "conformant" if o.get("reason") == "authority_not_determined" else "nonconformant"
    if not i.get("cache_fresh"):
        # An expired cache is refused under the first applicable value of the closed set;
        # the unreachable organ adds nothing to an answer whose lease has already expired.
        return "conformant" if o.get("reason") == "evidence_expired" else "nonconformant"
    if i.get("policy") == "current":
        # sect-6.2: a policy that demands a current observation refuses the call with
        # authority_not_determined.
        return "conformant" if o.get("reason") == "authority_not_determined" else "nonconformant"
    # sect-6.2: a policy that accepts lease-fresh evidence may admit it, with any exposure
    # bounded by the lease itself.
    return "conformant" if o.get("reason") is None else "nonconformant"

def r_window(i, o):
    # sect-6.1: a verifier checks the stated expiry against its own clock; operators MAY
    # configure other window lengths and the mechanism does not depend on the default
    # value, so an answer whose stated lease has not expired is not refused.
    if i["now_ms"] < i["lease_expiry_ms"]:
        return "conformant" if o.get("reason") is None else "nonconformant"
    return "conformant" if o.get("reason") == "evidence_expired" else "nonconformant"

RULES = {"R-DECLARED": r_declared, "R-NOEXTEND": r_noextend,
         "R-MODE": r_mode, "R-WINDOW": r_window}

def evaluate(case, rules=RULES):
    return rules[case["rule"]](case["input"], case["outcome"])

def parts(case):
    i, o = case["input"], case["outcome"]
    if case["rule"] == "R-DECLARED":
        return declared_parts(i, o)
    return None

def main(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")):
    doc = json.load(open(path, encoding="utf-8"))
    bad = 0
    for c in doc["cases"]:
        got = evaluate(c)
        got_parts = parts(c)
        miss = got != c["expect"] or got_parts != c.get("expect_parts")
        flag = "BAD" if miss else "ok "
        bad += miss
        print(f"{flag} {c['id']:7} {c['rule']:11} expect={c['expect']:13} got={got}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
