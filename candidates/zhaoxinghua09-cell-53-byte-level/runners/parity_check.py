#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""parity_check.py —— 两个 v2 候选件的两侧逐例比对

做的事：
  1) 让 Python 侧导出向量（授权表 / 带签名的委派链）
  2) 让 Node 侧读同一份向量、用它自己的库（node:crypto）独立判
  3) 逐例比 verdict，并把 reasons 串也逐字比 —— 只比 verdict 会放过「对但理由不同」的偏差
  4) 再跑一次「反例注入」：把向量里的 expect 改成错的，两侧都应当不通过（证明比对本身有效）

用法：
  python parity_check.py            # 跑两侧 + 反例注入，写 out/parity_20261127.json
"""
from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "out")
NODE = os.environ.get("ZC_NODE") or "node"
PY = sys.executable


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return p.returncode, p.stdout.strip(), p.stderr.strip()


ALIAS = {"narrowing_vectors.json": "narrowing.json", "cascade_vectors.json": "cascade-revocation.json",
         "predispatch_vectors.json": "pre-dispatch-authorization.json", "session_vectors.json": "session-gate.json",
         "jcs_vectors.json": "jcs.json", "merkle_vectors.json": "merkle.json",
         "actionref_vectors.json": "action-ref.json",
         "dup_vectors.json": "dup-member.json", "nonce_vectors.json": "nonce-replay.json",
         "recompute_vectors.json": "recompute-41.json", "actionref_hist_vectors.json": "actionref-historical.json", "actionref_v2_member_vectors.json": "actionref-v2-members.json"}


def vec_path(vectors):
    """开发布局 out/<name> 与候选目录布局 vectors/<alias> 都认"""
    p = os.path.join(OUT, vectors)
    if os.path.isfile(p):
        return p
    alt = os.path.join(os.path.dirname(HERE), "vectors", ALIAS.get(vectors, vectors))
    if os.path.isfile(alt):
        return alt
    return p


def one(name, py_script, js_script, vectors):
    src = vec_path(vectors)
    # 别让「跑比对」写到证据里：三个导出模式的件会把 --vectors 传进来的文件重写一遍，
    # 一跑清单就对不上。所以先把向量拷进临时目录，两侧只读副本，反例注入也写副本。
    work = tempfile.mkdtemp(prefix="parity_")
    vpath = os.path.join(work, "vectors.json")
    shutil.copyfile(src, vpath)
    rc1, o1, e1 = run([PY, os.path.join(HERE, py_script), "--vectors", vpath])
    rc2, o2, e2 = run([NODE, os.path.join(HERE, js_script), vpath, "--json"])
    if rc1 != 0 or rc2 != 0:
        return {"pair": name, "ok": False, "error": {"py": e1[-400:], "js": e2[-400:]}}
    # Python 侧结果：用 --json 再跑一次拿机读。新版件（先出的四件除外）支持 --json+--vectors，
    # 老件把 --vectors 当导出模式，会把 JSON 换成一行提示，所以按源码能力决定传不传。
    src = open(os.path.join(HERE, py_script), encoding="utf-8").read()
    extra = ["--vectors", vpath] if "a.vectors and not a.json" in src else []
    rc3, o3, _ = run([PY, os.path.join(HERE, py_script), "--json"] + extra)
    py = json.loads(o3)
    js = json.loads(o2)

    rows = []
    ok = True
    by_id_js = {r["id"]: r for r in js["rows"]}
    for r in py["rows"]:
        j = by_id_js.get(r["id"])
        same_v = j is not None and j["got"] == r["got"]
        # 理由串逐字比：有的件用 reasons，有的件用 code+also，统一摊平成字符串列表再比
        pr = list(r.get("reasons") or ([r.get("code")] + list(r.get("also") or [])))
        jr = list(j.get("reasons") or ([j.get("code")] + list(j.get("also") or []))) if j else None
        same_r = j is not None and sorted(map(str, jr)) == sorted(map(str, pr))
        # 有层名的件（session_gate）额外比层：判对但层错等于没判对
        same_l = True
        if "layer" in r:
            same_l = j is not None and j.get("layer") == r.get("layer")
        good = same_v and same_r and same_l
        ok &= good
        rows.append({"id": r["id"], "py": r["got"], "js": j["got"] if j else None,
                     "py_layer": r.get("layer"), "js_layer": j.get("layer") if j else None,
                     "py_reasons": pr, "js_reasons": jr,
                     "same_verdict": same_v, "same_reasons": same_r, "same_layer": same_l, "ok": good})

    # 反例注入：把 expect 改错，两侧都必须判不过
    tampered = os.path.join(work, "_tampered_vectors.json")
    vec = json.load(open(vpath, encoding="utf-8"))
    for c in vec["cases"]:
        c["expect"] = "__TAMPERED__"
    json.dump(vec, open(tampered, "w", encoding="utf-8"), ensure_ascii=False)
    rc_js_t, o_js_t, _ = run([NODE, os.path.join(HERE, js_script), tampered, "--json"])
    neg_ok = rc_js_t != 0
    ok &= neg_ok
    os.unlink(tampered)

    return {"pair": name, "python": py["verdict"], "node": js["verdict"],
            "py_pass": py["passed"], "js_pass": js["passed"], "total": py["total"],
            "all_same": ok, "rows": rows, "negative_control_on_node": neg_ok}


PAIRS = [("narrowing", "narrowing_check.py", "narrowing_check.mjs", "narrowing_vectors.json"),
         ("cascade", "cascade_revoke.py", "cascade_revoke.mjs", "cascade_vectors.json"),
         ("predispatch", "mcp_predispatch.py", "mcp_predispatch.mjs", "predispatch_vectors.json"),
         ("sessiongate", "session_gate.py", "session_gate.mjs", "session_vectors.json"),
         ("jcs", "jcs_check.py", "jcs_check.mjs", "jcs_vectors.json"),
         ("merkle", "merkle_root.py", "merkle_root.mjs", "merkle_vectors.json"),
         ("actionref", "action_ref_dual.py", "action_ref_dual.mjs", "actionref_vectors.json"),
         ("dupmember", "dupmember_check.py", "dupmember_check.mjs", "dup_vectors.json"),
         ("noncereplay", "nonce_replay.py", "nonce_replay.mjs", "nonce_vectors.json"),
         ("recompute41", "recompute41.py", "recompute41.mjs", "recompute_vectors.json"),
         ("actionrefhist", "actionref_historical.py", "actionref_historical.mjs", "actionref_hist_vectors.json"),
         ("actionrefmembers", "actionref_v2_members.py", "actionref_v2_members.mjs", "actionref_v2_member_vectors.json")]


def main():
    # 只跑本目录里真的有的件：候选目录只带字节级三族，应当自洽跑通而不是报四件缺失
    present = [p for p in PAIRS
               if os.path.isfile(os.path.join(HERE, p[1])) and os.path.isfile(os.path.join(HERE, p[2]))]
    res = {"time": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
           "pairs": [one(*p) for p in present],
           "families_run": [p[0] for p in present]}
    res["verdict"] = "PASS" if res["pairs"] and all(p.get("all_same") for p in res["pairs"]) else "FAIL"
    path = os.environ.get("ZC_PARITY_OUT") or os.path.join(tempfile.gettempdir(), "parity_20261127.json")
    json.dump(res, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    for p in res["pairs"]:
        if p.get("error"):
            print("FAIL " + p["pair"] + " 两侧跑不起来: " + json.dumps(p["error"], ensure_ascii=False))
            continue
        print(("PASS " if p["all_same"] else "FAIL ") + p["pair"].ljust(10)
              + f"py {p['py_pass']}/{p['total']}  js {p['js_pass']}/{p['total']}"
              + f"  逐例同判定 {sum(1 for r in p['rows'] if r['same_verdict'])}/{len(p['rows'])}"
              + f"  逐字同理由 {sum(1 for r in p['rows'] if r['same_reasons'])}/{len(p['rows'])}"
              + f"  反例注入拦截={p['negative_control_on_node']}")
        for r in p["rows"]:
            if not r["ok"]:
                print("   DIFF " + r["id"] + f" py={r['py']} js={r['js']}")
    print("VERDICT: " + res["verdict"] + " -> " + path)
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())





