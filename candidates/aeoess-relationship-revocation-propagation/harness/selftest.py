#!/usr/bin/env python3
"""Fault injection for rp2.py. No server. Exit 0 only if every probe behaves.

1. Malformed or error responses never score as deny or absent.
2. The strict timing rule rejects a stale allow that starts after the limit
   (the review's 11 s stale, 10 s bound case) and accepts one inside it.
3. End to end: a fake server that stays stale 1.6 s past a 1.0 s bound
   (tolerance 0.2 s) gives DIFF in PR, and a fake within the bound gives AGREE.
"""
import importlib.util, json, sys, time

spec = importlib.util.spec_from_file_location("rp2", sys.argv[1] if len(sys.argv) > 1 else "rp2.py")
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

print("SELFTEST", "PASS" if not fails else f"FAIL {len(fails)}")
sys.exit(1 if fails else 0)
