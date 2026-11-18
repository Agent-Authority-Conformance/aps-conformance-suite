#!/usr/bin/env python3
"""CX-*: an expiring grant on the ancestor edge, evaluated through the chain with
the check cache on. The grant carries grant_time and grant_duration, the caller
supplies current_time. A cached allow for one current_time must not answer a
check made with a later current_time. Revision r2, 2026-11-18: every response is
validated (status and field types) before scoring. An error or malformed body is
ERROR, never deny or absent. CX-09 requires HTTP 400 whose message names
current_time, any other status or message is a DIFF."""
import json, sys, urllib.request, uuid

B = "http://127.0.0.1:8080"
LABEL = sys.argv[1]
OUT = []


def http(path, body):
    req = urllib.request.Request(B + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def rec(case, expected, observed, note):
    if str(observed).startswith(("ERROR", "MALFORMED")) and not str(expected).startswith("ERROR"):
        v = "ERROR"
    else:
        v = "RECORD" if expected == "either" else ("AGREE" if expected == observed else "DIFF")
    OUT.append({"case": case, "expected": expected, "observed": observed, "verdict": v, "note": note})
    print(f"{case:6} expected={expected:9} observed={observed:9} {v} {note}", flush=True)


ts = lambda hms: f"2026-11-18T{hms}Z"
_, st = http("/stores", {"name": "cx-" + uuid.uuid4().hex[:6]})
S = st["id"]
TS = {"type_name": "TYPE_NAME_TIMESTAMP"}
model = {"schema_version": "1.1", "type_definitions": [
    {"type": "user"},
    {"type": "group", "relations": {"member": {"this": {}}},
     "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
    {"type": "folder", "relations": {"viewer": {"this": {}}},
     "metadata": {"relations": {"viewer": {"directly_related_user_types": [
         {"type": "group", "relation": "member", "condition": "not_expired"}]}}}},
    {"type": "doc", "relations": {"parent": {"this": {}},
                                  "viewer": {"tupleToUserset": {"tupleset": {"relation": "parent"},
                                                                "computedUserset": {"relation": "viewer"}}}},
     "metadata": {"relations": {"parent": {"directly_related_user_types": [{"type": "folder"}]}}}}],
    "conditions": {"not_expired": {"name": "not_expired",
                                   "expression": "current_time < grant_time + grant_duration",
                                   "parameters": {"current_time": TS, "grant_time": TS,
                                                  "grant_duration": {"type_name": "TYPE_NAME_DURATION"}}}}}
code, m = http(f"/stores/{S}/authorization-models", model)
assert code == 201 or code == 200, (code, m)
M = m["authorization_model_id"]
code, w = http(f"/stores/{S}/write", {"authorization_model_id": M, "writes": {"tuple_keys": [
    {"user": "user:alice", "relation": "member", "object": "group:eng"},
    {"user": "group:eng#member", "relation": "viewer", "object": "folder:x",
     "condition": {"name": "not_expired", "context": {"grant_time": ts("00:00:00"), "grant_duration": "1h"}}},
    {"user": "folder:x", "relation": "parent", "object": "doc:y"}]}})
assert code == 200, (code, w)


LAST = {}


def check(mode, now):
    body = {"authorization_model_id": M, "consistency": mode,
            "tuple_key": {"user": "user:alice", "relation": "viewer", "object": "doc:y"}}
    if now is not None:
        body["context"] = {"current_time": now}
    code, r = http(f"/stores/{S}/check", body)
    LAST.update(code=code, body=r)
    if code != 200:
        return f"ERROR{code}"
    if not isinstance(r.get("allowed"), bool):
        return "MALFORMED"
    return "allow" if r["allowed"] else "deny"


def lookup(mode, now):
    code, r = http(f"/stores/{S}/list-objects", {"authorization_model_id": M, "consistency": mode,
                   "type": "doc", "relation": "viewer", "user": "user:alice",
                   "context": {"current_time": now}})
    if code != 200:
        return f"ERROR{code}"
    objs = r.get("objects")
    if not (isinstance(objs, list) and all(isinstance(o, str) for o in objs)):
        return "MALFORMED"
    return "listed" if "doc:y" in objs else "absent"


H, L = "HIGHER_CONSISTENCY", "MINIMIZE_LATENCY"
rec("CX-01", "allow", check(H, ts("00:30:00")), "strongest, inside the grant")
warm = [(check(L, ts("00:30:00")), lookup(L, ts("00:30:00"))) for _ in range(3)]
rec("CX-W", "warmed", "warmed" if all(w == ("allow", "listed") for w in warm) else f"not-warmed {warm}", "cache warm-up, each response validated")
rec("CX-02", "allow", check(L, ts("00:30:00")), "default, inside the grant, cache warm")
rec("CX-03", "deny", check(L, ts("01:30:00")), "default, after expiry, same chain, cache warm for 00:30")
rec("CX-04", "deny", check(H, ts("01:30:00")), "strongest, after expiry")
rec("CX-05", "allow", check(L, ts("00:59:59")), "default, one second before expiry")
rec("CX-06", "deny", check(L, ts("01:00:00")), "default, at expiry, strict less-than")
rec("CX-07", "absent", lookup(L, ts("01:30:00")), "default lookup after expiry, cache warm for 00:30")
rec("CX-08", "allow", check(L, ts("00:30:00")), "default, back inside the grant after the expired checks")
o = check(L, None)
msg = json.dumps(LAST.get("body", {}))
cx09 = "ERROR400-names-current_time" if (o == "ERROR400" and "current_time" in msg) else f"{o} {msg[:160]}"
rec("CX-09", "ERROR400-names-current_time", cx09, f"default, current_time omitted, body={msg[:300]}")
import hashlib
d = sum(r["verdict"] == "DIFF" for r in OUT)
a = sum(r["verdict"] == "AGREE" for r in OUT)
er = sum(r["verdict"] == "ERROR" for r in OUT)
json.dump({"impl": "openfga", "label": LABEL, "harness": "rp_cond2.py",
           "harness_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
           "agree": a, "diff": d, "error": er, "results": OUT},
          open(f"out/openfga-cx-{LABEL}.json", "w"), indent=1)
print(f"TOTAL {len(OUT)} AGREE {a} DIFF {d} ERROR {er}")
sys.exit(1 if d or er else 0)
