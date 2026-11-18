#!/usr/bin/env python3
"""Fault injection for rp2.py and rp_cond2.py (r2.2). No server. Exit 0 only if
every probe behaves. Sections 1 to 3 are the r2.1 probes. Section 4 adds the
full-path regressions from the second Codex review.

1. Malformed or error responses never score as deny or absent.
2. The strict timing rule rejects a stale allow that starts after the limit
   (the review's 11 s stale, 10 s bound case) and accepts one inside it.
3. End to end: a fake server that stays stale 1.6 s past a 1.0 s bound
   (tolerance 0.2 s) gives DIFF in PR, and a fake within the bound gives AGREE.
"""
import importlib.util, json, sys, time

import os, tempfile
HERE = os.path.dirname(__file__) or "."
spec = importlib.util.spec_from_file_location("rp2", sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "rp2.py"))
rp2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp2)
fails = []


def expect(name, cond):
    print(("ok   " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


def kind_of(fn):
    try:
        fn()
        return "returned"
    except rp2.ProtocolError as e:
        return e.kind


# 1. response validation
bodies = {"empty object": (200, "{}"), "server error": (500, "{}"), "not json": (200, "<html>"),
          "wrong enum": (200, json.dumps({"permissionship": "PERMISSIONSHIP_UNSPECIFIED", "checkedAt": {"token": "t"},
                                          "can": "CHECK_RESULT_UNSPECIFIED", "allowed": "yes"}))}
for label, (status, text) in bodies.items():
    rp2.CALL = lambda m, u, b=None, h=None, s=status, t=text: (s, t, 0.0, 0.0)
    for cls in (rp2.OpenFGA, rp2.SpiceDB, rp2.Permify):
        o = object.__new__(cls)
        o.store = o.model = o.sv = "x"
        mode = o.STRONG
        k = kind_of(lambda: o.check("k", mode, token="t"))
        expect(f"{cls.__name__} check {label} -> {k}", k in ("MALFORMED", "ERROR"))
        k = kind_of(lambda: o.lookup("k", mode, token="t"))
        expect(f"{cls.__name__} lookup {label} -> {k}", k in ("MALFORMED", "ERROR"))
# SpiceDB stream error record must not become absent
rp2.CALL = lambda m, u, b=None, h=None: (200, json.dumps({"error": {"code": 13}}), 0.0, 0.0)
o = object.__new__(rp2.SpiceDB)
expect("SpiceDB stream error record", kind_of(lambda: o.lookup("k", o.STRONG)) == "ERROR")

# 2. strict window scoring
s11 = [(t / 4, t / 4 + 0.01, "allow" if t / 4 < 11 else "deny") for t in range(0, 64)]
v, after, bad = rp2.score_window(s11, 0.0, 10.0, 0.5, "deny")
expect(f"stale until 11 s, bound 10 s, tol 0.5 s -> {v} ({len(bad)} bad)", v == "DIFF")
s10 = [(t / 4, t / 4 + 0.01, "allow" if t / 4 < 10.25 else "deny") for t in range(0, 64)]
v, after, bad = rp2.score_window(s10, 0.0, 10.0, 0.5, "deny")
expect(f"stale until 10.25 s, bound 10 s, tol 0.5 s -> {v}", v == "AGREE")
v, _, _ = rp2.score_window([(11.0, 11.1, "deny")], 0.0, 10.0, 0.5, "deny")
expect(f"too few samples past the limit -> {v}", v == "ERROR")
v, _, _ = rp2.score_window(s10 + [(15.0, 15.1, "MALFORMED")], 0.0, 10.0, 0.5, "deny")
expect(f"malformed sample in window -> {v}", v == "ERROR")


# 3. end to end with a fake OpenFGA
class FakeFGA:
    def __init__(self, stale_s):
        self.stale_s, self.revoked_at = stale_s, None

    def __call__(self, method, url, body=None, headers=None):
        t = rp2.now()
        path = url.split("8080", 1)[1]
        if path == "/stores":
            return 201, json.dumps({"id": "s"}), t, t
        if path.endswith("/authorization-models"):
            return 201, json.dumps({"authorization_model_id": "m"}), t, t
        if path.endswith("/write"):
            self.revoked_at = t if "deletes" in body else None
            return 200, "{}", t, t
        visible = self.revoked_at is None or (t - self.revoked_at) < self.stale_s
        if path.endswith("/check"):
            return 200, json.dumps({"allowed": visible}), t, t
        return 200, json.dumps({"objects": [body["user"].replace("user:alice", "doc:y")] if visible else []}), t, t


for stale, want in ((1.6, "DIFF"), (0.5, "AGREE")):
    rp2.RESULTS.clear()
    rp2.CALL = FakeFGA(stale)
    impl = rp2.OpenFGA()
    args = type("A", (), {"bound": 1.0, "tolerance": 0.2, "bound_class": "configured-setting"})()
    rp2.scenario_pr(impl, "G", "grant", "e2e", args, 1.0 + 0.2 + 1.5)
    row = [r for r in rp2.RESULTS if r["case"] == "PR-G-07"][0]
    expect(f"fake stale {stale} s, bound 1.0 s -> {row['verdict']}", row["verdict"] == want)



# 4. full-path regressions (r2.2)
class FailAfterRevoke(FakeFGA):
    """Correct until the first revoke, then every read fails in `mode`."""
    def __init__(self, mode):
        super().__init__(0.0)
        self.mode, self.failing = mode, False

    def __call__(self, method, url, body=None, headers=None):
        path = url.split("8080", 1)[1]
        if self.failing and (path.endswith("/check") or path.endswith("/list-objects")):
            t = rp2.now()
            if self.mode == "http500":
                return 500, "{}", t, t
            if self.mode == "malformed":
                return 200, "{}", t, t
            raise rp2.ProtocolError("ERROR", "transport ConnectionRefusedError (synthetic)")
        if path.endswith("/write") and body and "deletes" in body:
            self.failing = True
        return super().__call__(method, url, body, headers)


tmp = tempfile.mkdtemp(prefix="rrp-selftest-")
for mode in ("http500", "malformed", "transport"):
    for cls in ("observational", "configured-setting"):
        rp2.RESULTS.clear(); rp2.LOG.clear()
        rp2.CALL = FailAfterRevoke(mode)
        out = os.path.join(tmp, f"{mode}-{cls}", "nested")  # does not exist yet
        try:
            code = rp2.main(["openfga", "probe", "--bound", "0.3", "--tolerance", "0.2", "--bound-class", cls,
                             "--horizon-extra", "1.0", "--scenarios", "PR", "--out", out])
        except Exception as e:
            code = f"raised {e!r}"
        path = os.path.join(out, "openfga-probe.json")
        saved = json.load(open(path)) if os.path.exists(path) else None
        errs = saved["meta"]["tally"]["ERROR"] if saved else None
        expect(f"{mode} during poll, {cls}: exit {code}, saved={saved is not None}, ERROR rows={errs}",
               code in (1, 2) and saved is not None and errs and errs > 0)

# an unwritable destination fails before any server request
calls = []
rp2.CALL = lambda *a, **k: calls.append(a) or (500, "{}", 0.0, 0.0)
blocker = os.path.join(tmp, "a-file")
open(blocker, "w").close()
try:
    rp2.main(["openfga", "probe", "--bound", "0", "--tolerance", "0.5", "--bound-class", "documented",
              "--out", os.path.join(blocker, "sub")])
    raised = False
except Exception as e:  # an OSError is the expected outcome, anything else is a failure
    raised = isinstance(e, OSError)
expect(f"unwritable output fails before server contact (raised={raised}, requests={len(calls)})",
       raised and not calls)

# a genuine empty SpiceDB stream is absence, not an error
rp2.CALL = lambda m, u, b=None, h=None: (200, "", 0.0, 0.0)
o = object.__new__(rp2.SpiceDB)
v = rp2.safe(o.lookup, "k", o.STRONG)[0]
expect(f"SpiceDB empty stream -> {v}", v == "absent")

# CX-09 oracle and full rp_cond2 path
cspec = importlib.util.spec_from_file_location("rp_cond2", os.path.join(HERE, "rp_cond2.py"))
cx = importlib.util.module_from_spec(cspec)
cspec.loader.exec_module(cx)
good = {"code": "validation_error", "message": "missing context parameters '[current_time]'"}
decoy = {"code": "validation_error", "message": "something unrelated", "unrelated_field": "current_time"}
expect("CX-09 judge accepts the documented error", cx.judge_cx09(400, good) == "ERROR400-names-current_time")
expect("CX-09 judge rejects current_time outside the message", cx.judge_cx09(400, decoy) != "ERROR400-names-current_time")
expect("CX-09 judge rejects HTTP 500", cx.judge_cx09(500, good) != "ERROR400-names-current_time")
expect("CX-09 judge rejects another error code", cx.judge_cx09(400, dict(good, code="internal")) != "ERROR400-names-current_time")


def fake_cx(missing_body):
    state = {}

    def call(path, body):
        if path == "/stores":
            return 201, json.dumps({"id": "s"})
        if path.endswith("/authorization-models"):
            return 201, json.dumps({"authorization_model_id": "m"})
        if path.endswith("/write"):
            return 200, "{}"
        now = body.get("context", {}).get("current_time")
        if now is None:
            return 400, json.dumps(missing_body)
        ok = now < "2026-11-18T01:00:00Z"
        if path.endswith("/check"):
            return 200, json.dumps({"allowed": ok})
        return 200, json.dumps({"objects": ["doc:y"] if ok else []})
    return call


for body, want, label in ((good, 0, "documented error"), (decoy, 1, "decoy field")):
    cx.OUT.clear(); cx.LOG.clear(); cx.LAST.clear()
    cx.CALL = fake_cx(body)
    out = os.path.join(tmp, "cx-" + label.replace(" ", "-"), "nested")
    code = cx.main(["probe", "--out", out])
    saved = json.load(open(os.path.join(out, "openfga-cx-probe.json")))
    expect(f"rp_cond2 full path, {label}: exit {code} (want {want}), requests logged {len(saved['requests'])}",
           code == want and len(saved["requests"]) > 0)

print("SELFTEST", "PASS" if not fails else f"FAIL {len(fails)}")
sys.exit(1 if fails else 0)
