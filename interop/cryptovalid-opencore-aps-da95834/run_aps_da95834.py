#!/usr/bin/env python3
"""aps-conformance-suite @ da95834 (merge of #147), checker = PUBLIC cryptovalid-opencore 0.17.0 (tag v0.17.0 = db7cabf).
Families: canonical-bytes (JCS v1 + v2), actionref-canonical (draft-01 §4.1 form), accountability-record.
Expected values are read ONLY for the comparison. Fixture bytes are checked against fixtures/manifest.json first.
Usage: python run_aps_da95834.py <suite_dir> <out_json>"""
import hashlib, json, os, sys, unicodedata
import cryptovalid_aps as aps
from cryptovalid_acta import jcs
from importlib.metadata import version

SUITE, OUT = sys.argv[1], sys.argv[2]
FX = os.path.join(SUITE, "fixtures")
FILES = {"jcs-v1": "canonical-bytes/canonical-bytes-jcs-v1.json", "jcs-v2": "canonical-bytes/canonical-bytes-jcs-v2.json",
         "actionref": "actionref-canonical/actionref-canonical-fixture-v1.json",
         "accountability": "accountability-record/accountability-record-fixture-v1.json"}
res = {"suite_commit": os.popen(f"git -C {SUITE} rev-parse HEAD").read().strip(),
       "checker": {"package": "cryptovalid-opencore", "version": version("cryptovalid-opencore"), "tag": "v0.17.0", "commit": "db7cabf",
                   "python": sys.version.split()[0], "cryptography": version("cryptography")},
       "fixture_sha256": {}, "vectors": [], "controls": []}

# 0. fixture bytes vs manifest
man = {e["path"]: e["canonical_sha256"] for e in json.load(open(os.path.join(FX, "manifest.json")))["fixtures"]}
for k, rel in FILES.items():
    h = hashlib.sha256(open(os.path.join(FX, rel), "rb").read()).hexdigest()
    res["fixture_sha256"][rel] = {"sha256": h, "manifest": man.get(rel), "match": h == man.get(rel)}
    assert h == man.get(rel), f"fixture bytes differ from manifest: {rel}"

def row(family, name, expected, observed, match, note=""):
    res["vectors"].append({"family": family, "vector": name, "expected": expected, "observed": observed,
                           "result": "match" if match else "diverge", "note": note})
    return match

# C1. JCS bytes + sha256
def c1(fn, record=True):
    n = 0
    for k in ("jcs-v1", "jcs-v2"):
        for v in json.load(open(os.path.join(FX, FILES[k])))["vectors"]:
            try:
                b = fn(v["input"]); got, sha = b.hex(), hashlib.sha256(b).hexdigest()
            except Exception as e:  # noqa: BLE001
                got, sha = f"ERROR {type(e).__name__}: {e}", ""
            ok = got == v["canonical_bytes_hex"] and sha == v["canonical_sha256"]
            n += ok
            if record:
                row(f"canonical-bytes/{k}", v["name"], {"bytes_hex": v["canonical_bytes_hex"], "sha256": v["canonical_sha256"]},
                    {"bytes_hex": got, "sha256": sha}, ok)
    return n

# C2. action_ref draft-01 §4.1 form; the two duplicate-scope negatives are implementation-specific at da95834
def c2(fn, record=True):
    n = 0
    for v in json.load(open(os.path.join(FX, FILES["actionref"])))["vectors"]:
        negative = v.get("expected_verification") is False
        obs = {}
        for mode, kw in (("draft-01", {}), ("reject_duplicate_scopes", {"reject_duplicate_scopes": True})):
            try:
                ref, order = fn(v["input"], **kw) if kw else fn(v["input"])
                obs[mode] = {"accepted": True, "action_ref": ref, "canonical_scope_order": order}
            except ValueError as e:
                obs[mode] = {"accepted": False, "rejected": str(e)}
        if negative:
            exp = {"expected_verification": False, "rejection_kind": v["rejection_kind"], "label": "implementation-specific (README at da95834)"}
            ok = obs["draft-01"]["accepted"] and not obs["reject_duplicate_scopes"]["accepted"]
            note = "draft-01 reading accepts (no duplicate rule in -01); the implementation-specific option rejects, as the family now labels it"
        else:
            exp = {"action_ref": v["action_ref"], "canonical_scope_order": v["canonical_scope_order"]}
            ok = all(obs[m].get("action_ref") == v["action_ref"] and obs[m].get("canonical_scope_order") == v["canonical_scope_order"] for m in obs)
            note = "identical in both modes"
        n += ok
        if record:
            row("actionref-canonical", v["name"], exp, obs, ok, note)
    return n

# C3. accountability-record
def c3(pub=None, mutate=None, record=True):
    fx = json.load(open(os.path.join(FX, FILES["accountability"])))
    pub = pub or fx["keypair"]["publicKeyHex"]
    n, layer_ok, neg = 0, 0, 0
    for v in fx["vectors"]:
        rec = json.loads(json.dumps(v["record"]))
        if mutate:
            rec = mutate(rec)
        r = aps.verify_accountability_record(rec, pub)
        exp_ok = v["expected_verification"] in (True, "True")
        ok = r["ok"] == exp_ok
        if not exp_ok:
            neg += 1; layer_ok += r.get("layer") == v.get("rejection_kind")
        n += ok
        if record:
            row("accountability-record", v["name"], {"verifies": exp_ok, "rejection_kind": v.get("rejection_kind"),
                "payload": "unverified (detached)" if "action" not in v["record"] else "inline"},
                {"verifies": r["ok"], "layer": r.get("layer"), "payload_verified": r.get("payload_verified"), "why": r["why"]}, ok,
                "" if ok and (exp_ok or r.get("layer") == v.get("rejection_kind")) else
                (f"rejected at layer {r.get('layer')!r}, the vector names {v.get('rejection_kind')!r}" if ok else ""))
    return n, layer_ok, neg

n1 = c1(jcs); n2 = c2(aps.action_ref_native_01); n3, l3, neg3 = c3()
res["summary"] = {"canonical-bytes": f"{n1}/18", "actionref-canonical": f"{n2}/6", "accountability-record": f"{n3}/12",
                  "accountability_rejection_layer_as_named": f"{l3}/{neg3}"}

# positive controls: the runner must be able to fail
def naive(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
res["controls"].append({"family": "canonical-bytes", "control": "json.dumps(sort_keys) instead of JCS (code-point key order, Python numbers)",
                        "match": f"{c1(naive, record=False)}/18", "expected": "fewer than 18"})
def utf16(inp, **kw):
    scopes = sorted((unicodedata.normalize("NFC", x) for x in inp["scopeRequired"]), key=lambda x: x.encode("utf-16-be"))
    return hashlib.sha256(jcs({**inp, "scopeRequired": scopes})).hexdigest(), scopes
def no_nfc(inp, **kw):
    scopes = sorted(inp["scopeRequired"]); return hashlib.sha256(jcs({**inp, "scopeRequired": scopes})).hexdigest(), scopes
res["controls"].append({"family": "actionref-canonical", "control": "scopeRequired sorted by UTF-16 code units", "match": f"{c2(utf16, record=False)}/6", "expected": "fewer than 6"})
res["controls"].append({"family": "actionref-canonical", "control": "no NFC normalisation", "match": f"{c2(no_nfc, record=False)}/6", "expected": "fewer than 6"})
def flip_sig(rec):
    s = bytearray(bytes.fromhex(rec["sig"])); s[0] ^= 1; rec["sig"] = s.hex(); return rec
def drop_sig(rec):
    rec.pop("sig", None); return rec
def tamper_action(rec):
    if "action" in rec: rec["action"]["type"] = rec["action"]["type"] + "x"
    return rec
fx = json.load(open(os.path.join(FX, FILES["accountability"])))
for name, kw in (("first signature byte flipped on every record", {"mutate": flip_sig}), ("sig removed", {"mutate": drop_sig}),
                 ("inline action.type altered (digest must break)", {"mutate": tamper_action}),
                 ("verified under the fixture's wrong_keypair public key", {"pub": fx["wrong_keypair"]["publicKeyHex"]})):
    n, _, _ = c3(record=False, **kw)
    res["controls"].append({"family": "accountability-record", "control": name, "match": f"{n}/12", "expected": "fewer than 12"})
json.dump(res, open(OUT, "w"), indent=1)
print(json.dumps(res["fixture_sha256"], indent=1)); print("SUMMARY", json.dumps(res["summary"])); print("CONTROLS"); [print(" ", json.dumps(c)) for c in res["controls"]]
for r in res["vectors"]:
    print(f"{r['result']:8} {r['family']:28} {r['vector']:40} {r['note']}")
