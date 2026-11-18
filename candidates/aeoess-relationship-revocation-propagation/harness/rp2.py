#!/usr/bin/env python3
"""relationship-revocation-propagation, harness revision r2.1 (2026-11-18).

r2.1 changes only the warm-up preconditions: check and lookup are confirmed
together 3 times in a row, because SpiceDB minimize_latency reads are not
monotonic (r2.0 run s2 saw deny, deny, deny, then listed).

Tests inherited permission through a relationship chain in a relationship-based
authorization server:
    user:alice -member-> group:eng -viewer-> folder:x <-parent- doc:y
alice can view doc:y only through the chain. Each edge is revoked in turn.
This is not signed agent delegation and no protected operation is invoked.

Three scenarios per edge, each on its own freshly created chain:
  IM  immediate: after the acknowledged revoke, the next requests use the
      strongest read the implementation names and must deny. Same for re-grant.
  PR  propagation: caches warmed in the default mode, revoke, then only
      default-mode reads. No strongest read touches this chain.
  RG  recovery: a cached deny in the default mode, re-grant, then only
      default-mode reads.

Strict timing rule for PR and RG: every default-mode request that STARTS at or
after ack_end + bound + tolerance must return the post-change answer. Samples
before that are recorded only. bound and tolerance are explicit inputs and are
written to the output with their class (documented, configured-setting,
submitter-derived, or observational, in which case no timing verdict is given).

Responses are validated before scoring. A transport error, a non-2xx status,
an unknown enum value or a missing field is ERROR or MALFORMED, never deny.

usage: rp2.py <openfga|spicedb|permify> <label> --bound S --tolerance S
              --bound-class C [--horizon-extra S] [--server-pattern P]
"""
import argparse, hashlib, json, subprocess, sys, time, urllib.error, urllib.request, uuid

T0 = time.monotonic()
LOG = []


class ProtocolError(Exception):
    def __init__(self, kind, detail):
        super().__init__(f"{kind}: {detail}")
        self.kind, self.detail = kind, detail


def now():
    return round(time.monotonic() - T0, 4)


def transport(method, url, body=None, headers=None):
    """Returns (status, text, t_start, t_end). Never raises for HTTP status."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"content-type": "application/json", **(headers or {})})
    t_start = now()
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    except Exception as e:  # connection refused, timeout
        LOG.append({"t_start": t_start, "t_end": now(), "url": url, "transport_error": repr(e)})
        raise ProtocolError("ERROR", f"transport {e!r}")
    t_end = now()
    LOG.append({"t_start": t_start, "t_end": t_end, "url": url.split("/", 3)[-1],
                "req": body, "status": status, "resp": text[:2000]})
    return status, text, t_start, t_end


CALL = transport  # replaced by the self-test


def call_json(method, url, body=None, headers=None, ok=(200, 201)):
    status, text, ts, te = CALL(method, url, body, headers)
    if status not in ok:
        raise ProtocolError("ERROR", f"HTTP {status} {text[:300]}")
    try:
        return json.loads(text), ts, te
    except ValueError:
        raise ProtocolError("MALFORMED", f"not JSON: {text[:200]}")


def need(cond, detail):
    if not cond:
        raise ProtocolError("MALFORMED", detail)


class OpenFGA:
    name = "openfga"
    base = "http://127.0.0.1:8080"
    strong_name = "HIGHER_CONSISTENCY"
    default_name = "MINIMIZE_LATENCY"
    STRONG, DEFAULT = "HIGHER_CONSISTENCY", "MINIMIZE_LATENCY"

    def __init__(self):
        r, _, _ = call_json("POST", f"{self.base}/stores", {"name": "rp2-" + uuid.uuid4().hex[:8]})
        need(isinstance(r.get("id"), str) and r["id"], "store id")
        self.store = r["id"]
        model = {"schema_version": "1.1", "type_definitions": [
            {"type": "user"},
            {"type": "group", "relations": {"member": {"this": {}}},
             "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
            {"type": "folder", "relations": {"viewer": {"this": {}}},
             "metadata": {"relations": {"viewer": {"directly_related_user_types": [
                 {"type": "user"}, {"type": "group", "relation": "member"}]}}}},
            {"type": "doc", "relations": {
                "parent": {"this": {}},
                "viewer": {"union": {"child": [
                    {"this": {}},
                    {"tupleToUserset": {"tupleset": {"relation": "parent"},
                                        "computedUserset": {"relation": "viewer"}}}]}}},
             "metadata": {"relations": {
                 "parent": {"directly_related_user_types": [{"type": "folder"}]},
                 "viewer": {"directly_related_user_types": [{"type": "user"}]}}}}]}
        r, _, _ = call_json("POST", f"{self.base}/stores/{self.store}/authorization-models", model)
        need(isinstance(r.get("authorization_model_id"), str), "model id")
        self.model = r["authorization_model_id"]

    def edges(self, k):
        return {"member": (f"user:alice{k}", "member", f"group:eng{k}"),
                "grant": (f"group:eng{k}#member", "viewer", f"folder:x{k}"),
                "parent": (f"folder:x{k}", "parent", f"doc:y{k}")}

    def write(self, k, add=(), delete=()):
        e = self.edges(k)
        tk = lambda n: dict(zip(("user", "relation", "object"), e[n]))
        body = {"authorization_model_id": self.model}
        if add:
            body["writes"] = {"tuple_keys": [tk(n) for n in add]}
        if delete:
            body["deletes"] = {"tuple_keys": [tk(n) for n in delete]}
        r, ts, te = call_json("POST", f"{self.base}/stores/{self.store}/write", body)
        need(r == {}, f"write body {r}")
        return None, ts, te

    def check(self, k, mode, token=None):
        r, ts, te = call_json("POST", f"{self.base}/stores/{self.store}/check", {
            "authorization_model_id": self.model, "consistency": mode,
            "tuple_key": {"user": f"user:alice{k}", "relation": "viewer", "object": f"doc:y{k}"}})
        need(isinstance(r.get("allowed"), bool), f"check body {r}")
        return ("allow" if r["allowed"] else "deny"), ts, te

    def lookup(self, k, mode, token=None):
        r, ts, te = call_json("POST", f"{self.base}/stores/{self.store}/list-objects", {
            "authorization_model_id": self.model, "consistency": mode,
            "type": "doc", "relation": "viewer", "user": f"user:alice{k}"})
        objs = r.get("objects")
        need(isinstance(objs, list) and all(isinstance(o, str) for o in objs), f"list-objects body {r}")
        return ("listed" if f"doc:y{k}" in objs else "absent"), ts, te


class SpiceDB:
    name = "spicedb"
    base = "http://127.0.0.1:8443"
    hdr = {"authorization": "Bearer rplabkey"}
    strong_name = "fully_consistent, and at_least_as_fresh(write token)"
    default_name = "minimize_latency"
    STRONG, DEFAULT = {"fullyConsistent": True}, {"minimizeLatency": True}
    PERM = {"PERMISSIONSHIP_HAS_PERMISSION": "allow", "PERMISSIONSHIP_NO_PERMISSION": "deny",
            "PERMISSIONSHIP_CONDITIONAL_PERMISSION": "indeterminate"}
    schema = """definition user {}
definition group {
  relation member: user
}
definition folder {
  relation viewer: user | group#member
  permission view = viewer
}
definition doc {
  relation parent: folder
  relation viewer: user
  permission view = viewer + parent->view
}"""

    def __init__(self):
        r, _, _ = call_json("POST", f"{self.base}/v1/schema/write", {"schema": self.schema}, self.hdr)
        need(isinstance(r.get("writtenAt", {}).get("token"), str), f"schema write {r}")

    def edges(self, k):
        return {"member": ("group", f"eng{k}", "member", "user", f"alice{k}", None),
                "grant": ("folder", f"x{k}", "viewer", "group", f"eng{k}", "member"),
                "parent": ("doc", f"y{k}", "parent", "folder", f"x{k}", None)}

    def _rel(self, k, n):
        rt, rid, rel, st, sid, srel = self.edges(k)[n]
        subj = {"object": {"objectType": st, "objectId": sid}}
        if srel:
            subj["optionalRelation"] = srel
        return {"resource": {"objectType": rt, "objectId": rid}, "relation": rel, "subject": subj}

    def write(self, k, add=(), delete=()):
        ups = [{"operation": "OPERATION_TOUCH", "relationship": self._rel(k, n)} for n in add]
        ups += [{"operation": "OPERATION_DELETE", "relationship": self._rel(k, n)} for n in delete]
        r, ts, te = call_json("POST", f"{self.base}/v1/relationships/write", {"updates": ups}, self.hdr)
        tok = r.get("writtenAt", {}).get("token")
        need(isinstance(tok, str) and tok, f"write token {r}")
        return tok, ts, te

    def _cons(self, mode, token):
        if mode == "fresh":
            need(token, "fresh read without token")
            return {"atLeastAsFresh": {"token": token}}
        if mode == "exact":
            need(token, "exact read without token")
            return {"atExactSnapshot": {"token": token}}
        return mode

    def check(self, k, mode, token=None):
        r, ts, te = call_json("POST", f"{self.base}/v1/permissions/check", {
            "consistency": self._cons(mode, token),
            "resource": {"objectType": "doc", "objectId": f"y{k}"}, "permission": "view",
            "subject": {"object": {"objectType": "user", "objectId": f"alice{k}"}}}, self.hdr)
        p = r.get("permissionship")
        need(p in self.PERM, f"permissionship {r}")
        need(isinstance(r.get("checkedAt", {}).get("token"), str), f"checkedAt {r}")
        return self.PERM[p], ts, te

    def lookup(self, k, mode, token=None):
        status, text, ts, te = CALL("POST", f"{self.base}/v1/permissions/resources", {
            "consistency": self._cons(mode, token), "resourceObjectType": "doc", "permission": "view",
            "subject": {"object": {"objectType": "user", "objectId": f"alice{k}"}}}, self.hdr)
        if status != 200:
            raise ProtocolError("ERROR", f"HTTP {status} {text[:300]}")
        ids = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                j = json.loads(line)
            except ValueError:
                raise ProtocolError("MALFORMED", f"stream line {line[:200]}")
            if "error" in j:
                raise ProtocolError("ERROR", f"stream error {line[:300]}")
            rid = j.get("result", {}).get("resourceObjectId")
            need(isinstance(rid, str), f"stream record {line[:200]}")
            need(j["result"].get("permissionship") in ("LOOKUP_PERMISSIONSHIP_HAS_PERMISSION", None),
                 f"stream permissionship {line[:200]}")
            ids.append(rid)
        return ("listed" if f"y{k}" in ids else "absent"), ts, te


class Permify:
    name = "permify"
    base = "http://127.0.0.1:3476/v1/tenants/t1"
    strong_name = "snap_token returned by the write under test (read at least as fresh as that write)"
    default_name = "no snap_token (latest transaction id)"
    STRONG, DEFAULT = "token", None
    CAN = {"CHECK_RESULT_ALLOWED": "allow", "CHECK_RESULT_DENIED": "deny"}
    schema = """entity user {}
entity group {
  relation member @user
}
entity folder {
  relation viewer @user @group#member
  permission view = viewer
}
entity doc {
  relation parent @folder
  relation viewer @user
  permission view = viewer or parent.view
}"""

    def __init__(self):
        r, _, _ = call_json("POST", f"{self.base}/schemas/write", {"schema": self.schema})
        need(isinstance(r.get("schema_version"), str) and r["schema_version"], f"schema {r}")
        self.sv = r["schema_version"]

    def edges(self, k):
        return {"member": ("group", f"eng{k}", "member", "user", f"alice{k}", ""),
                "grant": ("folder", f"x{k}", "viewer", "group", f"eng{k}", "member"),
                "parent": ("doc", f"y{k}", "parent", "folder", f"x{k}", "")}

    def write(self, k, add=(), delete=()):
        tok, ts0, te = None, None, None
        e = self.edges(k)
        if add:
            tuples = []
            for n in add:
                et, eid, rel, st, sid, srel = e[n]
                subj = {"type": st, "id": sid}
                if srel:
                    subj["relation"] = srel
                tuples.append({"entity": {"type": et, "id": eid}, "relation": rel, "subject": subj})
            r, ts0, te = call_json("POST", f"{self.base}/data/write",
                                   {"metadata": {"schema_version": self.sv}, "tuples": tuples})
            tok = r.get("snap_token")
            need(isinstance(tok, str) and tok, f"write token {r}")
        for n in delete:
            et, eid, rel, st, sid, srel = e[n]
            r, ts, te = call_json("POST", f"{self.base}/data/delete", {"tuple_filter": {
                "entity": {"type": et, "ids": [eid]}, "relation": rel,
                "subject": {"type": st, "ids": [sid], "relation": srel}}, "attribute_filter": {}})
            ts0 = ts0 if ts0 is not None else ts
            tok = r.get("snap_token")
            need(isinstance(tok, str) and tok, f"delete token {r}")
        return tok, ts0, te

    def _meta(self, mode, token):
        m = {"schema_version": self.sv, "depth": 20}
        if mode == "token":
            need(token, "token read without token")
            m["snap_token"] = token
        return m

    def check(self, k, mode, token=None):
        r, ts, te = call_json("POST", f"{self.base}/permissions/check", {"metadata": self._meta(mode, token),
                              "entity": {"type": "doc", "id": f"y{k}"}, "permission": "view",
                              "subject": {"type": "user", "id": f"alice{k}"}})
        need(r.get("can") in self.CAN, f"check body {r}")
        return self.CAN[r["can"]], ts, te

    def lookup(self, k, mode, token=None):
        r, ts, te = call_json("POST", f"{self.base}/permissions/lookup-entity", {
            "metadata": self._meta(mode, token), "entity_type": "doc", "permission": "view",
            "subject": {"type": "user", "id": f"alice{k}"}})
        ids = r.get("entity_ids")
        need(isinstance(ids, list) and all(isinstance(i, str) for i in ids), f"lookup body {r}")
        return ("listed" if f"y{k}" in ids else "absent"), ts, te


RESULTS = []
POLL_S = 0.25


def rec(scn, case, expected, observed, verdict=None, **extra):
    if verdict is None:
        verdict = "AGREE" if observed == expected else "DIFF"
    row = {"scenario": scn, "case": case, "expected": expected, "observed": observed, "verdict": verdict}
    row.update(extra)
    RESULTS.append(row)
    print(f"{case:9} expected={str(expected):8} observed={str(observed):9} {verdict} "
          + " ".join(f"{a}={b}" for a, b in extra.items() if a != "samples"), flush=True)
    return row


def safe(fn, *a, **kw):
    """Returns (value, t_start, t_end); ProtocolError becomes (kind, None, None)."""
    try:
        return fn(*a, **kw)
    except ProtocolError as e:
        print(f"   protocol {e}", flush=True)
        return e.kind, None, None


def scored(scn, case, expected, fn, *a, gap_from=None, **kw):
    v, ts, te = safe(fn, *a, **kw)
    verdict = "ERROR" if v in ("ERROR", "MALFORMED") else None
    extra = {"t_start": ts, "t_end": te}
    if gap_from is not None and ts is not None:
        extra["start_after_ack_s"] = round(ts - gap_from, 4)
    return rec(scn, case, expected, v, verdict, **extra)


def score_window(samples, ack_end, bound, tol, expected):
    """samples: list of (t_start, t_end, value). Strict rule on start times."""
    limit = ack_end + bound + tol
    after = [s for s in samples if s[0] >= limit]
    bad = [s for s in after if s[2] != expected]
    errors = [s for s in samples if s[2] in ("ERROR", "MALFORMED", "indeterminate")]
    if errors:
        return "ERROR", after, bad
    if len(after) < 4:
        return "ERROR", after, bad  # not enough samples past the limit to judge
    return ("DIFF" if bad else "AGREE"), after, bad


def wait_default(impl, k, want, deadline, want_lookup=None):
    """Default-mode reads until `want` (and, if given, the lookup answer
    `want_lookup`) is seen 3 times in a row. Default reads are not monotonic in
    every implementation, so check and lookup are confirmed together.
    Returns (samples, ok)."""
    seen, out = 0, []
    while time.monotonic() - T0 < deadline:
        v, ts, te = safe(impl.check, k, impl.DEFAULT)
        out.append((ts, te, v))
        lv = None
        if want_lookup is not None:
            lv, lts, lte = safe(impl.lookup, k, impl.DEFAULT)
            out.append((lts, lte, lv))
        if "ERROR" in (v, lv) or "MALFORMED" in (v, lv):
            return out, False
        ok = v == want and (want_lookup is None or lv == want_lookup)
        seen = seen + 1 if ok else 0
        if seen >= 3:
            return out, True
        time.sleep(POLL_S)
    return out, False


def strong_token(impl, tok):
    return impl.STRONG if not isinstance(impl, Permify) else "token"


def scenario_im(impl, E, edge, k, horizon):
    s = "IM"
    tok_setup, _, ack0 = impl.write(k, add=("member", "grant", "parent"))
    rec_v = scored(s, f"IM-{E}-01", "allow", impl.check, k, impl.STRONG, token=tok_setup)
    warm, ok = wait_default(impl, k, "allow", now() + horizon, want_lookup="listed")
    rec(s, f"IM-{E}-W", "allow", "warmed" if ok else "not-warmed", "RECORD" if ok else "ERROR",
        warm_samples=len(warm))
    tok_rev, _, ack = impl.write(k, delete=(edge,))
    scored(s, f"IM-{E}-02", "deny", impl.check, k, impl.STRONG, token=tok_rev, gap_from=ack)
    scored(s, f"IM-{E}-03", "absent", impl.lookup, k, impl.STRONG, token=tok_rev, gap_from=ack)
    if isinstance(impl, SpiceDB):
        scored(s, f"IM-{E}-04", "deny", impl.check, k, "fresh", token=tok_rev, gap_from=ack)
        scored(s, f"IM-{E}-05", "allow", impl.check, k, "exact", token=tok_setup, gap_from=ack)
    tok_re, _, ack2 = impl.write(k, add=(edge,))
    scored(s, f"IM-{E}-09", "allow", impl.check, k, impl.STRONG, token=tok_re, gap_from=ack2)
    scored(s, f"IM-{E}-10", "listed", impl.lookup, k, impl.STRONG, token=tok_re, gap_from=ack2)
    if isinstance(impl, SpiceDB):
        scored(s, f"IM-{E}-11", "allow", impl.check, k, "fresh", token=tok_re, gap_from=ack2)


def poll(impl, k, until, lookup_every=1):
    checks, looks, i = [], [], 0
    while time.monotonic() - T0 < until:
        v, ts, te = safe(impl.check, k, impl.DEFAULT)
        checks.append((ts, te, v))
        if i % lookup_every == 0:
            lv, lts, lte = safe(impl.lookup, k, impl.DEFAULT)
            looks.append((lts, lte, lv))
        i += 1
        time.sleep(POLL_S)
    return checks, looks


def window_rows(s, case, expected, samples, ack, args, stale_value):
    stale = [x for x in samples if x[2] == stale_value]
    extra = {"ack_end": ack, "samples": samples, "n": len(samples),
             "last_stale_start_after_ack_s": round(stale[-1][0] - ack, 4) if stale else None,
             "last_stale_end_after_ack_s": round(stale[-1][1] - ack, 4) if stale else None}
    if args.bound_class == "observational":
        rec(s, case, expected, "see samples", "RECORD", **extra)
        return
    verdict, after, bad = score_window(samples, ack, args.bound, args.tolerance, expected)
    extra.update({"limit_after_ack_s": args.bound + args.tolerance, "n_scored": len(after),
                  "n_bad": len(bad)})
    rec(s, case, expected, expected if verdict == "AGREE" else ("violation" if verdict == "DIFF" else "error"),
        verdict, **extra)


def scenario_pr(impl, E, edge, k, args, horizon):
    s = "PR"
    impl.write(k, add=("member", "grant", "parent"))
    warm, ok = wait_default(impl, k, "allow", now() + horizon, want_lookup="listed")
    rec(s, f"PR-{E}-W", "allow", "warmed" if ok else "not-warmed", "RECORD" if ok else "ERROR",
        warm_samples=len(warm), warm_tail=[x[2] for x in warm[-6:]])
    if not ok:
        return
    _, _, ack = impl.write(k, delete=(edge,))
    checks, looks = poll(impl, k, ack + horizon)
    first = checks[0] if checks else (None, None, None)
    rec(s, f"PR-{E}-06", "either", first[2], "RECORD", start_after_ack_s=round(first[0] - ack, 4) if first[0] else None)
    window_rows(s, f"PR-{E}-07", "deny", checks, ack, args, "allow")
    window_rows(s, f"PR-{E}-08", "absent", looks, ack, args, "listed")


def scenario_rg(impl, E, edge, k, args, horizon):
    s = "RG"
    impl.write(k, add=("member", "grant", "parent"))
    w1, ok1 = wait_default(impl, k, "allow", now() + horizon, want_lookup="listed")
    impl.write(k, delete=(edge,))
    w2, ok2 = wait_default(impl, k, "deny", now() + horizon, want_lookup="absent")
    ok = ok1 and ok2
    rec(s, f"RG-{E}-W", "deny", "warmed" if ok else "not-warmed", "RECORD" if ok else "ERROR",
        warm_samples=len(w1) + len(w2), warm_tail=[x[2] for x in w2[-6:]])
    if not ok:
        return
    _, _, ack = impl.write(k, add=(edge,))
    checks, looks = poll(impl, k, ack + horizon)
    window_rows(s, f"RG-{E}-10", "allow", checks, ack, args, "deny")
    window_rows(s, f"RG-{E}-11", "listed", looks, ack, args, "absent")


def server_args(pattern):
    if not pattern:
        return None
    try:
        out = subprocess.run(["pgrep", "-fl", pattern], capture_output=True, text=True, timeout=5).stdout
        return [l for l in out.splitlines() if "rp2.py" not in l]
    except Exception as e:
        return [repr(e)]


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("impl", choices=["openfga", "spicedb", "permify"])
    p.add_argument("label")
    p.add_argument("--bound", type=float, required=True)
    p.add_argument("--tolerance", type=float, required=True)
    p.add_argument("--bound-class", required=True,
                   choices=["documented", "configured-setting", "submitter-derived", "observational"])
    p.add_argument("--bound-source", default="")
    p.add_argument("--horizon-extra", type=float, default=3.0)
    p.add_argument("--server-pattern", default="")
    p.add_argument("--scenarios", default="IM,PR,RG")
    p.add_argument("--out", default="out")
    args = p.parse_args(argv)
    impl = {"openfga": OpenFGA, "spicedb": SpiceDB, "permify": Permify}[args.impl]()
    horizon = args.bound + args.tolerance + args.horizon_extra
    scns = args.scenarios.split(",")
    for E, edge in (("G", "grant"), ("M", "member"), ("P", "parent")):
        if "IM" in scns:
            scenario_im(impl, E, edge, "i" + E + uuid.uuid4().hex[:6], horizon)
        if "PR" in scns:
            scenario_pr(impl, E, edge, "p" + E + uuid.uuid4().hex[:6], args, horizon)
        if "RG" in scns:
            scenario_rg(impl, E, edge, "r" + E + uuid.uuid4().hex[:6], args, horizon)
    tally = {v: sum(r["verdict"] == v for r in RESULTS) for v in ("AGREE", "DIFF", "ERROR", "RECORD")}
    meta = {"harness": "rp2.py", "harness_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
            "impl": args.impl, "label": args.label, "bound_s": args.bound, "tolerance_s": args.tolerance,
            "bound_class": args.bound_class, "bound_source": args.bound_source,
            "horizon_extra_s": args.horizon_extra, "poll_s": POLL_S, "scenarios": scns,
            "strong_mode": impl.strong_name, "default_mode": impl.default_name,
            "server_process": server_args(args.server_pattern),
            "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - (time.monotonic() - T0))),
            "python": sys.version.split()[0], "tally": tally,
            "timing_rule": "requests starting at or after ack_end + bound + tolerance must return the post-change answer; earlier samples recorded only; finite sampling, not an all-times proof"}
    with open(f"{args.out}/{args.impl}-{args.label}.json", "w") as f:
        json.dump({"meta": meta, "results": RESULTS, "requests": LOG}, f, indent=1)
    print("TALLY", json.dumps(tally))
    return 0 if tally["DIFF"] == 0 and tally["ERROR"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
