#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python reference-SDK runner for the lifecycle-multiple-principals-and-conflict family.

This runner does not reimplement the family's fourteen deciders. It reads the same
vectors.json and chain.json as verify.ts and, for every layer where the PyPI SDK
(`agent-passport-system`, 4.x) exposes an API, it calls that API:

    agent_passport.verify_authority_delegation_chain   every chain_state claim
    agent_passport.verify                              every minted approval signature,
                                                       over the same content bytes
    agent_passport.canonicalize_jcs                    RFC 8785 canonical bytes

For every layer with no PyPI API it prints not_supported with the reason the vector
records, and never substitutes an answer of its own. The support table is produced by the
run rather than written by hand, so it cannot drift from what the SDK actually exposes.

The one layer the npm SDK supplies and this one does not is the multi-class threshold
behind the gate cases. npm exports evaluateThreshold; the PyPI SDK at 4.x exposes no
charter, office, approval-request or threshold module. That absence is asserted by this
run, so a later PyPI release that adds one makes the run fail loudly rather than leaving a
stale line in the README.

Run, with the pinned SDK installed into a virtual environment:

    python3 -m venv /tmp/g2-venv
    /tmp/g2-venv/bin/pip install 'agent-passport-system>=4.1,<5'
    /tmp/g2-venv/bin/python fixtures/lifecycle-multiple-principals-and-conflict/verify_python_sdk.py

Exit 0 when every supported PyPI probe matches and every absent API is accounted for,
1 on a mismatch, 2 on a malformed fixture or a missing SDK. No network.

This is a manual run and is not part of `npm test`, the same convention
fixtures/ancestor-revocation-chain/validate.py and
fixtures/runtime-authority-denial-continuity/verify.py already follow for a Python side
kept out of the Node-only CI gate.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

try:
    import agent_passport as ap
    from agent_passport import canonicalize_jcs, verify, verify_authority_delegation_chain
except ImportError:  # pragma: no cover - environment problem, not a fixture problem
    print("verify_python_sdk.py: agent-passport-system is not installed in this interpreter")
    print("  python3 -m venv <venv> && <venv>/bin/pip install 'agent-passport-system>=4.1,<5'")
    sys.exit(2)

HERE = Path(__file__).resolve().parent


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


chain_fixture = read_json("chain.json")
vectors_doc = read_json("vectors.json")

if (
    chain_fixture.get("_placeholder")
    or not isinstance(chain_fixture.get("now"), str)
    or not chain_fixture.get("chains")
    or not chain_fixture.get("verification_keys")
    or not chain_fixture.get("roles")
    or not chain_fixture.get("approvals", {}).get("signatures")
):
    print(
        "chain.json is a placeholder or missing chains, keys, roles or approvals. Run mint.py.",
        file=sys.stderr,
    )
    sys.exit(2)

role_by_delegation_id = {v: k for k, v in chain_fixture["roles"].items()}
for name, chain in chain_fixture["chains"].items():
    for member in chain:
        if member.get("delegation_id") not in role_by_delegation_id:
            print(f"chain {name} has a member with no registered role", file=sys.stderr)
            sys.exit(2)

APPROVALS = chain_fixture["approvals"]


def resolve_key(_issuer, verification_method, _issued_at):
    return chain_fixture["verification_keys"].get(verification_method)


def verify_chain(name: str, revoked_roles):
    revoked = set(revoked_roles or [])

    def resolve_revocation(delegation):
        return "revoked" if role_by_delegation_id.get(delegation.get("delegation_id")) in revoked else "active"

    result = verify_authority_delegation_chain(
        chain_fixture["chains"][name],
        now=chain_fixture["now"],
        resolve_verification_key=resolve_key,
        trust_root=lambda _root: True,
        resolve_revocation=resolve_revocation,
    )
    first = result.failures[0] if result.failures else None
    return {
        "state": result.state,
        "failure_code": first.code if first is not None else None,
        "failure_index": first.index if first is not None else None,
    }


print(f"{vectors_doc['family']}: {len(vectors_doc['vectors'])} vectors, all {vectors_doc['label']}")
src = vectors_doc["proposed_text_source"]
print(
    f"proposed text: {src['repo']} at or after {src['commit_floor']}, cases from "
    f"{src['cases_version']}, section \"{src['section']}\""
)
print(f"cases covered: {', '.join(vectors_doc['cases_covered'])}")
print(f"PyPI agent-passport-system: {ap.__version__}")
print()

probes = 0
probe_fails = 0
not_supported: dict[str, str] = {}

print("SDK probes, PyPI agent-passport-system")
for vector in vectors_doc["vectors"]:
    entries = [(vector["sdk"]["pypi"], [])]
    entries += [(a["pypi"], a.get("revoked_roles", [])) for a in vector.get("also_runs", [])]
    for probe, revoked in entries:
        if not probe.get("supported"):
            not_supported[f"{vector['concept']}/{probe['layer']}"] = probe.get(
                "reason", "(no reason recorded)"
            )
            continue
        if probe["layer"] != "chain_state" or not isinstance(probe.get("chain"), str):
            probe_fails += 1
            print(
                f"  MISMATCH {vector['id']} declares supported layer \"{probe['layer']}\", "
                "which this runner does not call"
            )
            continue
        observed = verify_chain(probe["chain"], revoked)
        probes += 1
        want = probe["expected"]
        if (
            observed["state"] == want["state"]
            and observed["failure_code"] == want["failure_code"]
            and observed["failure_index"] == want["failure_index"]
        ):
            suffix = (
                f"/{observed['failure_code']}@{observed['failure_index']}"
                if observed["failure_code"]
                else ""
            )
            print(f"  MATCH    {vector['id']} chain {probe['chain']} {observed['state']}{suffix}")
        else:
            probe_fails += 1
            print(
                f"  MISMATCH {vector['id']} chain {probe['chain']} expected "
                f"{json.dumps(want, sort_keys=True)} observed {json.dumps(observed, sort_keys=True)}"
            )

print(f"  {probes - probe_fails}/{probes} supported PyPI probes matched")
print()

print("layers with no PyPI API, recorded not_supported rather than faked")
for layer, reason in sorted(not_supported.items()):
    print(f"  {layer}: {reason}")
print()

# The approval signature layer. Both SDKs produce and verify byte-identical Ed25519
# signatures over the same content, so the gate material is not a TypeScript-only artifact.
print("approval signature layer, verified by the PyPI SDK")
good = 0
bad = 0
for ref, record in sorted(APPROVALS["signatures"].items()):
    subject = APPROVALS["subjects"][record["subject_key"]]
    public_key = APPROVALS["actors"][record["actor"]]
    ok = verify(subject["content"], record["signature"], public_key) is True
    should_verify = not ref.endswith(":tampered")
    if ok == should_verify:
        if should_verify:
            good += 1
        else:
            bad += 1
    else:
        probe_fails += 1
        print(f"  FAIL {ref} verifies={ok}, expected {should_verify}")
print(f"  ok   {good} minted signatures verify and {bad} tampered signature does not")
print()

# The npm SDK has evaluateThreshold and the PyPI SDK has no equivalent. Asserted here so
# the not_supported reason cannot go stale.
threshold_names = [
    n for n in dir(ap) if any(k in n.lower() for k in ("quorum", "charter", "office", "threshold", "approval"))
]
print("PyPI gate surface, enumerated in this run")
print(
    "  dir(agent_passport) names matching quorum|charter|office|threshold|approval: "
    f"{threshold_names}"
)
EXPECTED_ABSENT_SURFACE = ["ThresholdDispute", "request_human_approval"]
unexpected = [n for n in threshold_names if n not in EXPECTED_ABSENT_SURFACE]
if unexpected:
    probe_fails += 1
    print(
        "  MISMATCH the fixture records that this SDK has no multi-class threshold or "
        f"charter API, but this run found {unexpected}. Update the not_supported reasons."
    )
else:
    print(
        "  ok   no multi-class threshold, charter, office or quorum API; the only matches "
        f"are the unrelated {' and '.join(EXPECTED_ABSENT_SURFACE)}"
    )
print()

print("RFC 8785 JCS canonical digests of the signed delegation records")
records = 0
for name, chain in sorted(chain_fixture["chains"].items()):
    for member in chain:
        body = {k: v for k, v in member.items() if k not in ("signature", "delegation_id")}
        digest = hashlib.sha256(canonicalize_jcs(body).encode("utf-8")).hexdigest()
        records += 1
        print(f"  {name} {role_by_delegation_id[member['delegation_id']]} jcs-sha256 {digest}")
print(f"  {records} records canonicalized")
print()

if probe_fails > 0:
    print("FAILED")
    sys.exit(1)
print("PASSED: every supported PyPI probe matched and every absent API is accounted for")
sys.exit(0)
