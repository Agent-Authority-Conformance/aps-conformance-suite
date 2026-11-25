"""Compare this reading's answers with the candidate's expected.json.

Run only after the answers are written. Prints one line per case and a
summary; writes comparison.json.
"""
import json
import sys


def ours_expect(a):
    if a["answer"] == "valid":
        return "valid"
    if a["answer"] == "invalid":
        return "invalid:" + a["reason"]
    return "waiting:" + a["missing"]


def ours_payload(a):
    return "ok" if a["answer"] == "valid" else a["reason"]


def ours_form(a):
    if a["answer"] != "valid":
        return "neither", None
    return {"identity-ref": "key", "row-ref": "row", "hash-digest": "digest"}[a["form"]], a.get("digest")


def main(answers_path, expected_path, cases_path, out_path):
    ans = json.load(open(answers_path))["answers"]
    exp = json.load(open(expected_path))
    cases = {c["id"]: c for c in json.load(open(cases_path))}
    rows, summary = [], {}
    for cid in sorted(exp):
        e, lvl = exp[cid], cases[cid]["level"]
        if lvl == "family":
            if cid in ans:
                pass
            else:
                rows.append({"id": cid, "level": lvl, "source_id": e["id"], "verdict": "not_read"})
                summary.setdefault((lvl, "not_read"), 0)
                summary[(lvl, "not_read")] += 1
                continue
        a = ans[cid]
        row = {"id": cid, "level": lvl, "source_id": e["id"], "section": e["section"]}
        if lvl == "value":
            f, d = ours_form(a)
            row.update(expected=[e["form"], e.get("digest_hex")], ours=[f, d])
            same_form = f == e["form"]
            same_digest = e.get("digest_hex") is None or d == e.get("digest_hex")
            row["verdict"] = "agree" if same_form and same_digest else "differ"
        elif lvl == "payload":
            o = ours_payload(a)
            row.update(expected=e["expect"], ours=o)
            if o == e["expect"]:
                row["verdict"] = "agree"
            elif (o == "ok") == (e["expect"] == "ok"):
                row["verdict"] = "same_class_other_reason"
            else:
                row["verdict"] = "differ"
        else:
            o = ours_expect(a)
            x = e["expect"]
            row.update(expected=x, ours=o)
            if o == x:
                row["verdict"] = "agree"
            elif o.split(":")[0] == x.split(":")[0]:
                row["verdict"] = "same_class_other_reason"
            else:
                row["verdict"] = "differ"
            if o == "valid" and x == "valid":
                checks = {}
                for ek, ok in (("row_id_hex", "row_id"), ("statement_id_hex", "statement_id"),
                               ("kid_hex", "kid"), ("iss", "iss"), ("object_id_hex", "object_id")):
                    if ek in e:
                        checks[ek] = (a.get(ok) == e[ek])
                row["value_checks"] = checks
                if not all(checks.values()):
                    row["verdict"] = "valid_values_differ"
        if a.get("readings"):
            row["readings"] = a["readings"]
        row["description"] = e.get("description")
        rows.append(row)
        key = (lvl, row["verdict"])
        summary[key] = summary.get(key, 0) + 1
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"rows": rows, "summary": {f"{k[0]}/{k[1]}": v for k, v in sorted(summary.items())}},
                  f, indent=1, sort_keys=True)
        f.write("\n")
    for k, v in sorted(summary.items()):
        print(f"{v:4d}  {k[0]:10s} {k[1]}")


if __name__ == "__main__":
    main(*sys.argv[1:5])
