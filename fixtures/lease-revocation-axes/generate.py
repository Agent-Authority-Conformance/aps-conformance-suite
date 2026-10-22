#!/usr/bin/env python3
"""Authoring procedure. Never called by verify or npm test. Uses no harness code."""
import json
from pathlib import Path
P = Path(__file__).parent
# An event time is absolute synthetic milliseconds. Assertions are authored here,
# then frozen in vectors.json before the reference model is executed.
def call(t, worker="w1", grant="g1", operation="read"):
    return {"event":"call", "at_ms":t,"worker":worker,"grant":grant,"operation":operation}
def revoke(t=10000): return {"event":"revoke","at_ms":t,"grant":"g1"}
def availability(t, value): return {"event":"availability","at_ms":t,"available":value}
CASES = [
 ("LRA-01", "positive control", [call(0),call(30000),call(60000),call(119000)]),
 ("LRA-02", "shared revocation timeline", [call(0),revoke(),call(30000),call(60000),call(119000)]),
 ("LRA-03", "revocation while source unreachable", [call(0),availability(5000,False),revoke(),call(30000),call(60000),call(119000)]),
 ("LRA-04", "expiry with revoked reachable and unreachable source", [revoke(),call(121000),availability(122000,False),call(123000)]),
 ("LRA-05", "declared expiry endpoint, no revocation", [call(119999),call(120000),call(120001)]),
 ("LRA-06", "independent delegation for the same subject", [call(0),revoke(),call(30000),call(30000,grant="g2")]),
 ("LRA-07", "outage without revocation", [call(0),availability(5000,False),call(30000),call(119000),call(121000)]),
 ("LRA-08", "same evidence on two workers", [call(0),call(0,"w2"),revoke(),call(30000),call(30000,"w2"),call(121000,"w2")]),
 ("LRA-09", "fresh valid authority does not authorize another operation", [call(0,operation="write"),call(30000,operation="write")]),
 ("LRA-10", "cache use must not slide original expiry", [call(0),call(30000),call(60000),call(90000),call(119000),call(121000)]),
 ("LRA-11", "temporary outage recovers to active and revoked grants", [revoke(),availability(30000,False),call(30000),call(30000,grant="g2"),availability(45000,True),call(60000),call(60000,grant="g2")]),
]
def expected(t, active, available, operation, mode, inclusive):
    fresh = t <= 120000 if inclusive else t < 120000
    if not fresh: observation=None
    elif mode=="cached_lease": observation={"status":"active","as_of_ms":0,"retrieved_at_ms":0}
    elif available: observation={"status":"active" if active else "revoked","as_of_ms":t,"retrieved_at_ms":t}
    else: observation=None
    current = "not_established" if observation is None or observation["as_of_ms"] != t else ("valid" if observation["status"]=="active" else "revoked")
    scoped = ("valid" if observation["status"]=="active" else "revoked") if observation else "not_established"
    accepted = fresh and scoped=="valid"
    permit = fresh and current=="valid" and operation=="read"
    return {"evidence_freshness":"fresh" if fresh else "expired", "observation":observation,
      "authority_answer":scoped,"current_validity":current,"verification_accepted":accepted,
      "action_decision":"permit" if permit else "deny","downstream_reached":permit,
      "observation_differs_from_truth":observation is not None and (observation["status"]=="active") != active}
result=[]
for cid,description,events in CASES:
    active={"g1":True,"g2":True};available=True; timeline=[]; n=0
    for event in events:
        e=dict(event)
        if e["event"]=="revoke":active[e["grant"]]=False
        elif e["event"]=="availability":available=e["available"]
        else:
            n+=1;e["id"]=f"{cid}-r{n}";e["truth"]="active" if active[e["grant"]] else "revoked"
            e["expected"]={"by_mode":{mode:{boundary:expected(e["at_ms"],active[e["grant"]],available,e["operation"],mode,boundary=="inclusive") for boundary in ["exclusive","inclusive"]} for mode in ["cached_lease","live_standing_read"]}}
        timeline.append(e)
    result.append({"id":cid,"description":description,"timeline":timeline})
# Failure sets are specified before running the model, from each mutation's semantics.
mutants={
 "lease-ignores-expiry":["LRA-04","LRA-05","LRA-07","LRA-08","LRA-10"],
 "sliding-lease":["LRA-04","LRA-05","LRA-07","LRA-08","LRA-10"],
 "live-fail-open":["LRA-03","LRA-07","LRA-11"],
 "sticky-unavailable":["LRA-11"],
 "retrieval-renews-evidence":["LRA-04","LRA-05","LRA-08","LRA-10"],
 "deny-but-dispatch":["LRA-02","LRA-03","LRA-04","LRA-05","LRA-06","LRA-07","LRA-08","LRA-09","LRA-10","LRA-11"],
 "deny-everything":["LRA-01","LRA-02","LRA-03","LRA-05","LRA-06","LRA-07","LRA-08","LRA-10","LRA-11"],
 "live-first-read-only":["LRA-01","LRA-02","LRA-03","LRA-06","LRA-07","LRA-08","LRA-09","LRA-10","LRA-11"],
}
# Each defect is exercised under one pinned profile. Baselines cover both endpoints.
profiles={k:{"mode":"cached_lease" if k in ["lease-ignores-expiry","sliding-lease"] else "live_standing_read","boundary":"exclusive","expected_failed_cases":v} for k,v in mutants.items()}
# Sliding mutation updates on every attempted use, including refused attempts.
# LRA04 has a second late attempt; 05/07/08/10 reuse within a lease-sized gap.
v={"family":"lease-revocation-axes","status":"candidate","version":1,
 "source":{"kind":"discussion_proposals","list":"public-agentprotocol@w3.org","messages":[{"author":"Larry Lewis","date":"2026-10-21","contribution":"three separate axes and T=0/10/30/60/119 timeline"},{"author":"ShaoBao Li (Lee)","date":"2026-10-21","contribution":"120 second lease and named cached/live verification expectations"},{"author":"Tymofii Pidlisnyi","date":"2026-10-21","contribution":"offer to host neutral cases and run APS first"}]},
 "profile":{"lease_ms":120000,"lease_anchor":"evidence_issued_at_ms","action_policy":"P1-current-observation","current_observation_max_age_ms":0,"clock":"synthetic atomic reads; milliseconds","boundary_source_status":"not specified by discussion","initial_evidence":[{"id":"e1","grant":"g1","subject":"same-subject","issued_at_ms":0,"expires_at_ms":120000,"status":"active","allowed_operations":["read"]},{"id":"e2","grant":"g2","subject":"same-subject","issued_at_ms":0,"expires_at_ms":120000,"status":"active","allowed_operations":["read"]}]},
 "cases":result,"mutants":profiles}
(P/"vectors.json").write_text(json.dumps(v,indent=2)+"\n")
