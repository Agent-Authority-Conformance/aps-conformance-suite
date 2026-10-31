#!/usr/bin/env python3
"""Recompute each case's verdict from its input and outcome, compare with the declared expectation.
Standard library only. Exit 0 when every case agrees, 1 otherwise."""
import json, os, sys

REQUIRED_RESTORE = ("evidence_list", "verifier_role", "validity_window")
INCOMPLETE_SET = ("tryLater", "not_authoritative", "internal_error")

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

def r_notdet(i, o):
    trig = {"unreachable": "registry_unreachable", "stale_root": "stale_root"}[i["registry"]]
    r = o.get("receipt") or {}
    ok = o.get("state") == "PAUSE" and r.get("trigger") == trig and r.get("determination") == "authority_not_determined"
    if i["registry"] == "stale_root":
        # 0108 lists stale_root as not determined, 0088 calls a stale-root answer a completed check.
        # Both reject ACTIVE. They disagree on PAUSE with authority_not_determined.
        if o.get("state") == "ACTIVE":
            return "nonconformant"
        return "ambiguous" if ok else "nonconformant"
    return "conformant" if ok else "nonconformant"

def r_incomplete(i, o):
    reason = ((o.get("receipt") or {}).get("incomplete_check") or {}).get("reason")
    if i["responder"] == "tryLater":
        return "conformant" if reason == "tryLater" else "nonconformant"
    if reason in INCOMPLETE_SET:
        return "nonconformant"
    return "ambiguous"

def r_exempt(i, o):
    cause, state = i["halt_cause"], o.get("state")
    if cause in ("authority_revoked", "authority_not_determined"):
        return "nonconformant" if state == "RESUMED" else "conformant"
    if state == "RESUMED":
        return "conformant" if (o.get("receipt") or {}).get("resume_basis") == "exemption" else "nonconformant"
    return "conformant"

def r_restore(i, o):
    missing = [k for k in REQUIRED_RESTORE if not i["restore"].get(k)]
    if not missing:
        return "conformant" if o.get("state") == "RESUMED" else "nonconformant"
    named = set((o.get("receipt") or {}).get("missing") or [])
    return "conformant" if (o.get("state") == "PAUSE" and set(missing) <= named) else "nonconformant"

def r_rollback(i, o):
    if i["rollback_target_integrity"] is False:
        return "conformant" if o.get("state") == "ROLLBACK" else "nonconformant"
    return "conformant"

def r_oneway(i, o):
    if i.get("regime") == "one_way" and i["halt_cause"] == "authority_revoked":
        return "nonconformant" if o.get("state") == "RESUMED" else "conformant"
    return "conformant"

def r_window(i, o):
    if i.get("window_closed_before_verify"):
        r = o.get("receipt") or {}
        return "conformant" if (o.get("state") == "PAUSE" and r.get("reason") == "window_closed") else "nonconformant"
    return "conformant"

def r_split(i, o):
    admit = r_admit(i, o)
    fts = r_fts(i, o)
    return "conformant" if (admit == "conformant" and fts == "conformant") else "nonconformant"

def r_recur(i, o):
    return "conformant" if o.get("state") == "PAUSE" else "nonconformant"

RULES = {"R-ADMIT": r_admit, "R-FTS": r_fts, "R-SAC": r_sac, "R-OBS": r_obs, "R-NOTDET": r_notdet,
         "R-INCOMPLETE": r_incomplete, "R-EXEMPT": r_exempt, "R-RESTORE": r_restore,
         "R-ROLLBACK": r_rollback, "R-ONEWAY": r_oneway, "R-RECUR": r_recur,
         "R-WINDOW": r_window, "R-SPLIT": r_split}

def evaluate(case, rules=RULES):
    return rules[case["rule"]](case["input"], case["outcome"])

def parts(case):
    if case["rule"] != "R-SPLIT":
        return None
    return {"admission": r_admit(case["input"], case["outcome"]), "effects": r_fts(case["input"], case["outcome"])}

def main(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")):
    doc = json.load(open(path))
    bad = 0
    for c in doc["cases"]:
        got = evaluate(c)
        miss = got != c["expect"] or ("expect_parts" in c and parts(c) != c["expect_parts"])
        flag = "BAD" if miss else "ok "
        bad += miss
        print(f"{flag} {c['id']:6} {c['rule']:13} expect={c['expect']:13} got={got}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
