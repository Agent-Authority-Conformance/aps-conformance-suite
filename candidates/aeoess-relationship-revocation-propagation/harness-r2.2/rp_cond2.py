#!/usr/bin/env python3
"""CX-*: an expiring grant on the ancestor edge, evaluated through the chain with
the check cache on. The grant carries grant_time and grant_duration, the caller
supplies current_time. A cached allow for one current_time must not answer a
check made with a later current_time.

Revision r2.2, 2026-11-18. Every response is validated (status and field types)
before scoring, and transport failures or non-JSON bodies are ERROR, never deny
or absent. CX-09 requires HTTP 400 with code validation_error and a message
field that names current_time. The rest of the body is not searched. Every
request is kept in the output. The output directory is created before any
server is contacted. Changes from r2: the CX-09 oracle, transport and JSON
error handling, the request log, the output directory, and a main() so the
judging functions can be tested without a server.

usage: rp_cond2.py <label> [--out DIR]
"""
import hashlib, json, os, sys, time, urllib.error, urllib.request, uuid

B = "http://127.0.0.1:8080"
OUT, LOG, LAST = [], [], {}
T0 = time.monotonic()


def transport(path, body):
    req = urllib.request.Request(B + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, json.dumps({"_transport_error": repr(e)})


CALL = transport  # replaced by the self-test


def http(path, body):
    ts = round(time.monotonic() - T0, 4)
    code, text = CALL(path, body)
    LOG.append({"t_start": ts, "t_end": round(time.monotonic() - T0, 4), "path": path,
                "req": body, "status": code, "resp": text[:2000]})
    try:
        parsed = json.loads(text or "{}")
    except ValueError:
        parsed = {"_not_json": text[:200]}
    return code, parsed if isinstance(parsed, dict) else {"_not_object": parsed}


def rec(case, expected, observed, note):
    if str(observed).startswith(("ERROR", "MALFORMED")) and not str(expected).startswith("ERROR"):
        v = "ERROR"
    else:
        v = "RECORD" if expected == "either" else ("AGREE" if expected == observed else "DIFF")
    OUT.append({"case": case, "expected": expected, "observed": observed, "verdict": v, "note": note})
    print(f"{case:6} expected={expected:9} observed={observed:9} {v} {note}", flush=True)


def judge_cx09(code, body):
    """HTTP 400, code validation_error, and a string message naming current_time."""
    msg = body.get("message")
    if code == 400 and body.get("code") == "validation_error" and isinstance(msg, str) and "current_time" in msg:
        return "ERROR400-names-current_time"
    return f"status={code} code={body.get('code')!r} message={str(msg)[:120]!r}"


def check(S, M, mode, now):
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


def lookup(S, M, mode, now):
    code, r = http(f"/stores/{S}/list-objects", {"authorization_model_id": M, "consistency": mode,
                   "type": "doc", "relation": "viewer", "user": "user:alice",
                   "context": {"current_time": now}})
    if code != 200:
        return f"ERROR{code}"
    objs = r.get("objects")
    if not (isinstance(objs, list) and all(isinstance(o, str) for o in objs)):
        return "MALFORMED"
    return "listed" if "doc:y" in objs else "absent"


def setup():
    ts = lambda hms: f"2026-11-18T{hms}Z"
    code, st = http("/stores", {"name": "cx-" + uuid.uuid4().hex[:6]})
    if code not in (200, 201) or not isinstance(st.get("id"), str):
        raise RuntimeError(f"store create {code} {st}")
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
    if code not in (200, 201) or not isinstance(m.get("authorization_model_id"), str):
        raise RuntimeError(f"model write {code} {m}")
    M = m["authorization_model_id"]
    code, w = http(f"/stores/{S}/write", {"authorization_model_id": M, "writes": {"tuple_keys": [
        {"user": "user:alice", "relation": "member", "object": "group:eng"},
        {"user": "group:eng#member", "relation": "viewer", "object": "folder:x",
         "condition": {"name": "not_expired", "context": {"grant_time": ts("00:00:00"), "grant_duration": "1h"}}},
        {"user": "folder:x", "relation": "parent", "object": "doc:y"}]}})
    if code != 200 or w != {}:
        raise RuntimeError(f"tuple write {code} {w}")
    return S, M


def run_cases(S, M):
    ts = lambda hms: f"2026-11-18T{hms}Z"
    H, L = "HIGHER_CONSISTENCY", "MINIMIZE_LATENCY"
    rec("CX-01", "allow", check(S, M, H, ts("00:30:00")), "strongest, inside the grant")
    warm = [(check(S, M, L, ts("00:30:00")), lookup(S, M, L, ts("00:30:00"))) for _ in range(3)]
    rec("CX-W", "warmed", "warmed" if all(w == ("allow", "listed") for w in warm) else f"not-warmed {warm}",
        "cache warm-up, each response validated")
    rec("CX-02", "allow", check(S, M, L, ts("00:30:00")), "default, inside the grant, cache warm")
    rec("CX-03", "deny", check(S, M, L, ts("01:30:00")), "default, after expiry, same chain, cache warm for 00:30")
    rec("CX-04", "deny", check(S, M, H, ts("01:30:00")), "strongest, after expiry")
    rec("CX-05", "allow", check(S, M, L, ts("00:59:59")), "default, one second before expiry")
    rec("CX-06", "deny", check(S, M, L, ts("01:00:00")), "default, at expiry, strict less-than")
    rec("CX-07", "absent", lookup(S, M, L, ts("01:30:00")), "default lookup after expiry, cache warm for 00:30")
    rec("CX-08", "allow", check(S, M, L, ts("00:30:00")), "default, back inside the grant after the expired checks")
    check(S, M, L, None)
    body = LAST.get("body", {})
    rec("CX-09", "ERROR400-names-current_time", judge_cx09(LAST.get("code"), body),
        f"default, current_time omitted, body={json.dumps(body)[:300]}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    label = argv[0]
    out = argv[argv.index("--out") + 1] if "--out" in argv else "out"
    os.makedirs(out, exist_ok=True)
    path = f"{out}/openfga-cx-{label}.json"
    with open(path, "a"):
        pass  # fail before server work if the destination is not writable
    aborted = None
    try:
        run_cases(*setup())
    except Exception as e:
        aborted = repr(e)
        print("ABORTED", aborted, flush=True)
    d = sum(r["verdict"] == "DIFF" for r in OUT)
    a = sum(r["verdict"] == "AGREE" for r in OUT)
    er = sum(r["verdict"] == "ERROR" for r in OUT)
    with open(path, "w") as f:
        json.dump({"impl": "openfga", "label": label, "harness": "rp_cond2.py r2.2",
                   "harness_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
                   "agree": a, "diff": d, "error": er, "aborted": aborted,
                   "results": OUT, "requests": LOG}, f, indent=1)
    print(f"TOTAL {len(OUT)} AGREE {a} DIFF {d} ERROR {er}")
    return 2 if aborted else (1 if d or er else 0)


if __name__ == "__main__":
    sys.exit(main())
