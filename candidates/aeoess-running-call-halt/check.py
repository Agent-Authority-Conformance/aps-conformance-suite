#!/usr/bin/env python3
"""Recompute each case's verdict from its input and outcome, compare with the declared expectation.
Standard library only. Exit 0 when every case agrees, 1 otherwise."""
import json, os, sys

# The reasons 0088 defines for an answer that arrived (tryLater, not_authoritative, internal_error).
ARRIVED = ("tryLater", "not_authoritative", "internal_error")

def combine(parts):
    values = list(parts.values())
    if "nonconformant" in values:
        return "nonconformant"
    if "ambiguous" in values:
        return "ambiguous"
    return "conformant"

def r_admit(i, o):
    return "conformant" if o.get("new_call") == "DENIED" else "nonconformant"

def r_fts(i, o):
    call = i["call"]
    if call["kind"] != "non_interruptible" or call["contract"] != "FINISH_THEN_STOP":
        return "ambiguous"
    rc, ob = o["receipt"]["operation_completed"], o["observer"]["completed"]
    return "conformant" if (rc is True and ob is True) else "nonconformant"

def first_checkpoint_at_or_after(cps, t):
    after = sorted((ts, cid) for cid, ts in cps.items() if ts >= t)
    return after[0][1] if after else None

def r_sac(i, o):
    call = i["call"]
    target = first_checkpoint_at_or_after(call["checkpoints"], i["t_observed"])
    if target is None:
        return "ambiguous"
    r, ob = o["receipt"], o["observer"]
    ok = (r["operation_completed"] is False and r["checkpoint_id"] == target
          and ob["completed"] is False and ob["last_checkpoint"] == target)
    return "conformant" if ok else "nonconformant"

def r_obs(i, o):
    r, ob = o["receipt"], o["observer"]
    ok = r["operation_completed"] == ob["completed"] and r.get("checkpoint_id") == ob.get("last_checkpoint")
    return "conformant" if ok else "nonconformant"

def reason_of(o):
    return ((o.get("receipt") or {}).get("incomplete_check") or {}).get("reason")

def notdet_parts(i, o):
    r = o.get("receipt") or {}
    if i["registry"] == "stale_root":
        if o.get("state") != "PAUSE":
            return {"state": "nonconformant"}
        # 0108 lists stale_root among the not-determined modes, 0088 calls a stale-root answer a
        # completed check, m1031 says every authority_not_determined receipt carries an
        # incomplete_check reason. The state is decided, the determination is not.
        return {"state": "conformant", "determination": "ambiguous"}
    halt = "conformant" if (o.get("state") == "PAUSE" and r.get("trigger") == "registry_unreachable"
                            and r.get("determination") == "authority_not_determined") else "nonconformant"
    reason = reason_of(o)
    if reason is None or reason in ARRIVED:
        # The block is required (0088, m1031), and no answer arrived, so none is inferred (0090, m1031).
        receipt = "nonconformant"
    else:
        # Required and recorded separately, but the sources name no value for a missing answer.
        receipt = "ambiguous"
    return {"halt": halt, "receipt": receipt}

def incomplete_parts(i, o):
    reason = reason_of(o)
    if i["responder"] in ARRIVED:
        return {"recorded_answer": "conformant" if reason == i["responder"] else "nonconformant"}
    inferred = "nonconformant" if reason in ARRIVED else "conformant"
    value = "nonconformant" if (reason is None or reason in ARRIVED) else "ambiguous"
    return {"no_inferred_answer": inferred, "recorded_value": value}

def split_parts(i, o):
    return {"admission": r_admit(i, o), "effects": r_fts(i, o)}

PARTS = {"R-NOTDET": notdet_parts, "R-INCOMPLETE": incomplete_parts, "R-SPLIT": split_parts}

RULES = {"R-ADMIT": r_admit, "R-FTS": r_fts, "R-SAC": r_sac, "R-OBS": r_obs,
         "R-NOTDET": lambda i, o: combine(notdet_parts(i, o)),
         "R-INCOMPLETE": lambda i, o: combine(incomplete_parts(i, o)),
         "R-SPLIT": lambda i, o: combine(split_parts(i, o))}

def evaluate(case, rules=RULES):
    return rules[case["rule"]](case["input"], case["outcome"])

def parts(case):
    fn = PARTS.get(case["rule"])
    return fn(case["input"], case["outcome"]) if fn else None

def main(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")):
    doc = json.load(open(path))
    bad = 0
    for c in doc["cases"]:
        got = evaluate(c)
        got_parts = parts(c)
        miss = got != c["expect"] or got_parts != c.get("expect_parts")
        flag = "BAD" if miss else "ok "
        bad += miss
        print(f"{flag} {c['id']:6} {c['rule']:13} expect={c['expect']:13} got={got}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
