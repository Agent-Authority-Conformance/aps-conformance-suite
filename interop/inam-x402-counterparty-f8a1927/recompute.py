"""Mode B recomputation of INAM's x402 CounterpartyContext vectors.

Usage: python3 recompute.py <path to tests/vectors/x402-counterparty-context.json>

Checks per vector:
  canon-py   rfc8785 (Python) over policy_input equals policy_input_canonical
  canon-js   canonicalize (npm) over policy_input equals policy_input_canonical
  sha256     'sha256:' + sha256(policy_input_canonical) equals context.policy_input_hash
  presented  lowercasing presented.bound_wallet and presented.pay_to gives policy_input
  decision   the rule stated in the file's description, applied by this script,
             gives context.decision and context.reason

Exit 0 only if every check on every vector matches.
"""
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from pathlib import Path

import rfc8785

HERE = Path(__file__).resolve().parent
RANK = {"none": 0, "countersigned": 1, "independently_verified": 2}


def rule(i):
    if i["revoked"]:
        return "payee INAM ID is revoked"
    if not i["bound_wallet"] or i["bound_wallet"] not in i["pay_to"]:
        return "payTo is not an address this INAM ID proved control of"
    if RANK[i["evidence_level"]] < RANK[i["policy"]["minEvidence"]]:
        return f"evidence {i['evidence_level']} is below {i['policy']['minEvidence']}"
    if i["trust_score"] < i["policy"]["minTrustScore"]:
        return f"trustScore {i['trust_score']} is below {i['policy']['minTrustScore']}"
    return "ok"


def main(corpus):
    raw = Path(corpus).read_bytes()
    doc = json.loads(raw)
    vectors = doc["vectors"]
    js = json.loads(subprocess.check_output(["node", str(HERE / "canonical.mjs"), corpus]))
    diverged = 0
    for n, v in enumerate(vectors, 1):
        i, p, ctx = v["policy_input"], v["presented"], v["context"]
        canon = v["policy_input_canonical"]
        reason = rule(i)
        checks = {
            "canon-py": rfc8785.dumps(i).decode("utf-8") == canon,
            "canon-js": js[n - 1] == canon,
            "sha256": "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest() == ctx["policy_input_hash"],
            "presented": p["bound_wallet"].lower() == i["bound_wallet"]
            and [a.lower() for a in p["pay_to"]] == i["pay_to"],
            "decision": ctx["reason"] == reason and ctx["decision"] == ("allow" if reason == "ok" else "deny"),
        }
        bad = [k for k, ok in checks.items() if not ok]
        if bad:
            diverged += 1
            print(f"{n} DIVERGE {' '.join(bad)} | {v['name']} | observed reason: {reason}")
        else:
            print(f"{n} MATCH {' '.join(checks)} | {v['name']}")
    print(f"{len(vectors) - diverged}/{len(vectors)} match")
    print("corpus sha256 " + hashlib.sha256(raw).hexdigest())
    print(f"Python {platform.python_version()}; rfc8785 {importlib.metadata.version('rfc8785')}")
    print("Node " + subprocess.check_output(["node", "--version"], text=True).strip())
    return 1 if diverged else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
