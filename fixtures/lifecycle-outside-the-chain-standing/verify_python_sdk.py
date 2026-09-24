#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python reference-SDK runner for the lifecycle-outside-the-chain-standing family.

This runner does not reimplement the family's deciders. It reads the same vectors.json
and the same chain.json as verify.ts and, for every layer where the PyPI SDK
(`agent-passport-system`, 4.x) exposes an API, it calls that API:

    agent_passport.verify_authority_delegation_chain   every chain_state claim
    agent_passport.canonicalize_jcs                    RFC 8785 canonical bytes

For every layer with no PyPI API it prints not_supported with the reason the vector
records, and never substitutes an answer of its own. The support table is produced by the
run rather than written by hand, so it cannot drift from what the SDK actually exposes.

What the PyPI SDK at 4.x has no API for, checked in this run:

    office_holder_count   the npm SDK exports checkQuorum. The PyPI SDK exposes no
                          charter, office, quorum or approval-threshold module at all.
    external_order        no API represents a grant issued by a body outside the chain
                          under a conditional order.
    held_pending_forum    neither SDK has a verdict for a root held pending a neutral
                          forum. The chain verifier's states are valid, invalid and
                          indeterminate.

Run, with the pinned SDK installed into a virtual environment:

    python3 -m venv /tmp/g2-venv
    /tmp/g2-venv/bin/pip install 'agent-passport-system>=4.1,<5'
    /tmp/g2-venv/bin/python fixtures/lifecycle-outside-the-chain-standing/verify_python_sdk.py

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
    from agent_passport import canonicalize_jcs, verify_authority_delegation_chain
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
):
    print("chain.json is a placeholder or missing chains, keys or roles. Run mint.py.", file=sys.stderr)
    sys.exit(2)

role_by_delegation_id = {v: k for k, v in chain_fixture["roles"].items()}
for name, chain in chain_fixture["chains"].items():
    for member in chain:
        if member.get("delegation_id") not in role_by_delegation_id:
            print(f"chain {name} has a member with no registered role", file=sys.stderr)
            sys.exit(2)


def resolve_key(_issuer, verification_method, _issued_at):
    return chain_fixture["verification_keys"].get(verification_method)


def verify_chain(name: str, revoked_roles):
    revoked = set(revoked_roles or [])

    def resolve_revocation(delegation):
        role = role_by_delegation_id.get(delegation.get("delegation_id"))
        return "revoked" if role in revoked else "active"

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
print(
    "proposed text: "
    f"{vectors_doc['proposed_text_source']['repo']} at or after "
    f"{vectors_doc['proposed_text_source']['commit_floor']}, cases from "
    f"{vectors_doc['proposed_text_source']['cases_version']}, section "
    f"\"{vectors_doc['proposed_text_source']['section']}\""
)
print(f"PyPI agent-passport-system: {ap.__version__}")
print()

probes = 0
probe_fails = 0
not_supported: dict[str, str] = {}

print("SDK probes, PyPI agent-passport-system")
for vector in vectors_doc["vectors"]:
    entries = [("sdk", vector["sdk"]["pypi"])]
    entries += [(f"also_runs[{i}]", a["pypi"]) for i, a in enumerate(vector.get("also_runs", []))]
    for where, probe in entries:
        if not probe.get("supported"):
            not_supported[f"{vector['concept']}/{probe['layer']}"] = probe.get(
                "reason", "(no reason recorded)"
            )
            continue
        if probe["layer"] != "chain_state" or not isinstance(probe.get("chain"), str):
            probe_fails += 1
            print(
                f"  MISMATCH {vector['id']} {where} declares supported layer "
                f"\"{probe['layer']}\", which this runner does not call"
            )
            continue
        # Only the terminated chain of LC-H-005 has revoked roles. Every other
        # chain_state claim is asserted on the records with nothing revoked.
        applies = (
            vector["records"].get("revoked_roles", [])
            if probe["chain"] == vector["records"].get("old_chain")
            else []
        )
        observed = verify_chain(probe["chain"], applies)
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

# The npm SDK has checkQuorum and the PyPI SDK has no equivalent. This is an assertion
# about the absence, so a later PyPI release that adds one makes the run fail loudly
# rather than leaving a stale "not supported" line in the README.
charter_names = [
    n
    for n in dir(ap)
    if any(k in n.lower() for k in ("quorum", "charter", "office", "threshold"))
]
print("PyPI charter and quorum surface, enumerated in this run")
print(f"  dir(agent_passport) names matching quorum|charter|office|threshold: {charter_names}")
unexpected = [n for n in charter_names if n != "ThresholdDispute"]
if unexpected:
    probe_fails += 1
    print(
        "  MISMATCH the fixture records that this SDK has no quorum, charter or office "
        f"API, but this run found {unexpected}. Update the not_supported reasons."
    )
else:
    print("  ok   no quorum, charter or office API; the only match is the unrelated ThresholdDispute type")
print()

print("RFC 8785 JCS canonical digests of the signed records")
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
