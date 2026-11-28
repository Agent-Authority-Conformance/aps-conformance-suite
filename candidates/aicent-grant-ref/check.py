#!/usr/bin/env python3
"""Recompute each case's verdict from its input and outcome, compare with the declared expectation.
Standard library only. Exit 0 when every case agrees, 1 otherwise."""
import json, os, sys

# The closed refusal vocabulary of sect-8.1, in priority order:
# the reason is the first value in the list whose condition applies.
FIVE = ("evidence_binding_mismatch", "evidence_expired", "authority_not_determined",
        "authority_revoked", "operation_not_permitted")

def combine(parts):
    values = list(parts.values())
    if "nonconformant" in values:
        return "nonconformant"
    if "ambiguous" in values:
        return "ambiguous"
    return "conformant"

def first_applicable(i):
    # sect-8.1: the reason is the first value in the list whose condition applies.
    # Authority sources that cannot be reached, or whose only observation predates the
    # request, are refused under authority_not_determined; that mapping is R-NOTDET's
    # jurisdiction, so this function covers the other four conditions in list order.
    if i.get("binding_mismatch"):
        return "evidence_binding_mismatch"
    if i.get("evidence_expired"):
        return "evidence_expired"
    if i.get("authority") == "revoked":
        return "authority_revoked"
    if i.get("operation_permitted") is False:
        return "operation_not_permitted"
    return None

def r_order(i, o):
    p = order_parts(i, o)
    if p:
        return combine(p)
    exp = first_applicable(i)
    if exp is None:
        return "conformant" if o.get("reason") is None else "nonconformant"
    return "conformant" if o.get("reason") == exp else "nonconformant"

def order_parts(i, o):
    if not i.get("race_boundary"):
        return None
    # sect-8.2: a revocation arriving just before or just after an invocation ends is a
    # boundary no protocol erases. Whether the answer owed revoked, not-determined, or a
    # permit at that boundary is not settled by sections 8.1 and 8.2; the legibility of
    # the record and the emitted value are.
    exp = first_applicable(i)
    return {"value": "conformant" if o.get("reason") == exp else "nonconformant",
            "boundary_call": "ambiguous"}

def r_notdet(i, o):
    p = notdet_parts(i, o)
    if p:
        return combine(p)
    return "conformant" if o.get("reason") == "authority_not_determined" else "nonconformant"

def notdet_parts(i, o):
    if i.get("computed_over") != "label":
        return None
    # sect-8.1: a refusal computed over labels or unrecorded context alone is not auditable,
    # and producing one is not a conformance target of the section. The verdict the response
    # itself earns is not stated; the value and the never-assent property are.
    ok = o.get("reason") == "authority_not_determined"
    return {"value_and_assent": "conformant" if ok else "nonconformant",
            "computation_source": "ambiguous"}

def r_closed(i, o):
    if "reason" not in o:
        return "nonconformant"
    r = o["reason"]
    if r is not None and r not in FIVE:
        return "nonconformant"
    return "conformant"

def r_nullobs(i, o):
    gr = o.get("grant_ref") or {}
    relied = i.get("relied_on_observation") or {}
    if not relied.get("present") or not relied.get("fresh"):
        # sect-8.2: observation_as_of_ms is null whenever the observation the answer
        # relied on is absent or not fresh, even if a later, successful observation is
        # available at answer time.
        if gr.get("observation_as_of_ms") is not None:
            return "nonconformant"
    diag = i.get("diagnostic_read")
    if diag and not relied.get("fresh"):
        # A diagnostic read performed after the relied-on evidence expired does not
        # backfill the member and does not renew evidence.
        if gr.get("expires_at_ms") is not None and gr["expires_at_ms"] > i["grant_expires_at_ms"]:
            return "nonconformant"
    return "conformant"

def r_grantref(i, o):
    gr = o.get("grant_ref")
    if not isinstance(gr, dict):
        return "nonconformant"
    for member in ("grant", "evidence_id", "issued_at_ms", "expires_at_ms", "observation_as_of_ms"):
        if member not in gr:
            return "nonconformant"
    return "conformant"

RULES = {"R-ORDER": r_order, "R-NOTDET": r_notdet, "R-CLOSED": r_closed,
         "R-NULLOBS": r_nullobs, "R-GRANTREF": r_grantref}

def evaluate(case, rules=RULES):
    return rules[case["rule"]](case["input"], case["outcome"])

def parts(case):
    i, o = case["input"], case["outcome"]
    if case["rule"] == "R-ORDER":
        return order_parts(i, o)
    if case["rule"] == "R-NOTDET":
        return notdet_parts(i, o)
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
