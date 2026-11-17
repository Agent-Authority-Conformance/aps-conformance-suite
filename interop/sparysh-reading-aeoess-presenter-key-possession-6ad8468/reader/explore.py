import json, base64, sys
def b(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
d = json.load(open(sys.argv[1]))
base = d["cases"][0]["input"]
for c in d["cases"]:
    i = c["input"]; o = c["outcome"]
    diffs = {}
    for k in ("request", "token_claims", "policy"):
        for kk in set(i[k]) | set(base[k]):
            if i[k].get(kk) != base[k].get(kk): diffs[f"{k}.{kk}"] = i[k].get(kk)
    if i["access_token"] != base["access_token"]: diffs["access_token"] = i["access_token"]
    other = set(i) - {"request","token_claims","policy","access_token","dpop"}
    dp = i["dpop"]
    try:
        parts = dp.split(".") if isinstance(dp, str) else None
        h = b(parts[0]).decode(); p = b(parts[1]).decode()
    except Exception as e:
        h = p = f"<{e!r}> {str(dp)[:80]}"
    print(c["id"], json.dumps(o, separators=(",",":")))
    print("   diffs:", diffs, "other:", other, "nparts:", len(parts) if parts else None)
    print("   H:", h); print("   P:", p)
