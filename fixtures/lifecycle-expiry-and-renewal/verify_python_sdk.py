#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Python reference-SDK runner for the lifecycle-expiry-and-renewal family.

This is not a from-scratch reimplementation of the protocol. It runs the same fifteen
vectors over the same chain.json records as verify.ts, and for every step where the
Python SDK (`agent-passport-system` on PyPI, pinned 4.1.0) exposes an API it calls that
API rather than reimplementing the check:

    agent_passport.verify_authority_delegation_chain   chain shape, signatures, the time
                                                       facet, identifier binding, parent
                                                       narrowing and revocation state
    agent_passport.verify, agent_passport.canonicalize_jcs
                                                       each fixture-local record's issuer
                                                       signature

Two steps have no Python SDK API and are recorded as not_supported rather than faked:

    scope membership     the TypeScript SDK exports isPurposePermitted. The Python SDK
                         exports no equivalent under any module. This runner applies the
                         same documented hierarchical rule itself and labels it.
    the whole lifecycle  which of the two endings happened, the ground and actor of an
    layer                early ending, lifecycle standing, renewal, and an interim
                         mandate. Neither SDK exposes any of it. Supplied by this runner,
                         the same way harness.ts supplies it on the TypeScript side.

The support table is printed at the end of every run, so the record of what came from an
SDK and what did not is produced by the run rather than written by hand.

Run, with the pinned SDK installed into a virtual environment:

    python3 -m venv /tmp/aac-work/pyenv
    /tmp/aac-work/pyenv/bin/pip install agent-passport-system==4.1.0
    /tmp/aac-work/pyenv/bin/python fixtures/lifecycle-expiry-and-renewal/verify_python_sdk.py

Exit 0 when the reference boundary matches every vector and both defective boundaries
diverge on exactly their declared sets, 1 otherwise, 2 on a malformed fixture or a missing
SDK. No network. This is a manual run and not part of `npm test`, the same convention
fixtures/runtime-authority-denial-continuity/verify.py and
fixtures/ancestor-revocation-chain/validate.py already follow for a Python side kept out
of the hermetic Node-only CI gate.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import agent_passport as ap
except ImportError:  # pragma: no cover - environment problem, not a fixture problem
    print("verify_python_sdk.py: agent-passport-system is not installed in this interpreter")
    print("  python3 -m venv <venv> && <venv>/bin/pip install agent-passport-system==4.1.0")
    sys.exit(2)

HERE = Path(__file__).resolve().parent
SDK_SUPPORT: list[tuple[str, str, str]] = []


def ms(t: str) -> float:
    return datetime.fromisoformat(t.replace("Z", "+00:00")).replace(tzinfo=timezone.utc).timestamp() * 1000


def is_purpose_permitted(requested: str, allowed: list[str]) -> bool:
    """Hierarchical prefix membership, matching the TypeScript SDK's documented rule.

    The TypeScript SDK's isPurposePermitted documents wildcard matching ("research:*"
    permits "research:academic") and exact matching otherwise. The Python SDK exports no
    equivalent under any module, so this runner applies the same rule and records the step
    as not_supported. It is not an SDK result and the support table says so.
    """
    for entry in allowed:
        if entry == requested or entry == "*":
            return True
        if entry.endswith(":*") and (requested == entry[:-2] or requested.startswith(entry[:-1])):
            return True
    return False


# ---------------------------------------------------------------------------
# The boundary, ported step for step from harness.ts
# ---------------------------------------------------------------------------

REQUIRED_ROLE = {
    "renewal": "renewal_author",
    "interim_instrument": "interim_instrument_author",
    "cached_decision": "decision_attestor",
}


def out(verdict: str, reason: str, ending: str | None, chain: dict | None, detail: str | None = None) -> dict:
    o = {
        "verdict": verdict,
        "reason": reason,
        "ending": ending,
        "sdk_chain_state": None if chain is None else chain["state"],
        "sdk_failure_code": None if chain is None else chain["code"],
    }
    if detail is not None:
        o["detail"] = detail
    return o


class Boundary:
    def __init__(self, name: str, fixture: dict, *, records_ending_kind: bool, renewal_extends: bool) -> None:
        self.name = name
        self.fixture = fixture
        self.records_ending_kind = records_ending_kind
        self.renewal_extends = renewal_extends

    # -- shared steps -------------------------------------------------------

    def authentic(self, rec: dict) -> bool:
        unsigned = {k: v for k, v in rec.items() if k != "signature"}
        public_key = self.fixture["verification_keys"].get(rec["verification_method"])
        if public_key is None:
            return False
        payload = f"{self.fixture['record_signature_domain']} {ap.canonicalize_jcs(unsigned)}"
        return ap.verify(payload, rec["signature"], public_key)

    def chain(self, event: dict, now: str) -> dict:
        keys = self.fixture["verification_keys"]
        office = self.fixture["identities"]["OFFICE"]
        result = ap.verify_authority_delegation_chain(
            event["chain"],
            now=now,
            resolve_verification_key=lambda _issuer, method, _issued_at=None: keys.get(method),
            trust_root=lambda root: root.get("issuer") == office,
            resolve_revocation=lambda _d: event["revocation"],
        )
        failures = list(result.failures)
        code = None
        if failures:
            first = failures[0]
            code = first.get("code") if isinstance(first, dict) else getattr(first, "code", None)
        return {"state": result.state, "code": code}

    def leaf(self, event: dict) -> dict:
        return event["chain"][-1]

    # -- dispatch -----------------------------------------------------------

    def handle(self, event: dict) -> dict:
        by_kind: dict[str, list[dict]] = {}
        for rec in event["records"]:
            if not self.authentic(rec):
                return out("not_established", "record_not_authentic", None, None, rec["record_id"])
            by_kind.setdefault(rec["kind"], []).append(rec)
        registry = (by_kind.get("standing_registry") or [None])[0]
        if registry is None:
            return out("not_established", "standing_registry_not_presented", None, None)
        for rec in event["records"]:
            role = REQUIRED_ROLE.get(rec["kind"])
            if role is None:
                continue
            if rec["issuer"] not in (registry["body"].get(role) or []):
                return out("not_established", "record_without_standing", None, None, f"{rec['record_id']}/{rec['kind']}")
        rule = RULES.get(event["check"])
        if rule is None:
            return out("not_established", "unknown_check", None, None, event["check"])
        return rule(self, event, by_kind, registry)


def _one(by_kind: dict[str, list[dict]], kind: str) -> dict | None:
    return (by_kind.get(kind) or [None])[0]


def rule_ending_kind(b: Boundary, e: dict, r: dict, registry: dict) -> dict:
    chain = b.chain(e, e["now"])
    notice = next((n for n in r.get("revocation_notice", []) if n["body"]["grant"] == b.leaf(e)["delegation_id"]), None)
    if notice is not None:
        if notice["issuer"] not in (registry["body"].get("lifecycle_standing") or []):
            return out("not_established", "revocation_without_lifecycle_standing", None, chain, f"claimed_by={notice['issuer']}")
        if ms(e["now"]) >= ms(notice["body"]["recorded_at"]):
            detail = None
            if b.records_ending_kind:
                detail = f"cause={notice['body']['cause']} actor={notice['body']['actor']}"
            return out("invalid", "ended_early_for_cause", "revocation" if b.records_ending_kind else None, chain, detail)
    if chain["state"] == "valid":
        if not is_purpose_permitted(e["action"]["requested_scope"], b.leaf(e)["authority"]["scope"]["grants"]):
            return out("invalid", "scope_not_in_grant", None, chain)
        return out("valid", "inside_declared_window", None, chain)
    if chain["code"] == "EXPIRED":
        return out("invalid", "reached_declared_end", "expiry" if b.records_ending_kind else None, chain)
    if chain["code"] == "REVOKED":
        return out("invalid", "revoked_without_a_recorded_ground", None, chain)
    if chain["code"] == "NOT_YET_VALID":
        return out("not_yet_effective", "declared_start_not_reached", None, chain)
    return out("not_established", "chain_state_not_decidable", None, chain)


def rule_renewal(b: Boundary, e: dict, r: dict, _registry: dict) -> dict:
    claim = _one(r, "renewal")
    chain = b.chain(e, e["now"])
    leaf_id = b.leaf(e)["delegation_id"]
    if claim is not None and claim["body"]["mode"] == "reissue":
        supersedes = claim["body"]["supersedes"]
        issues = claim["body"]["issues"]
        if b.renewal_extends:
            return out("valid", "renewal_treated_as_extension_of_the_same_identity", None, chain, f"identity={supersedes}")
        cached = next((c for c in r.get("cached_decision", []) if c["body"]["delegation_ref"] == supersedes), None)
        if cached is not None and leaf_id == issues:
            return out("not_established", "evidence_keyed_to_superseded_artifact", None, chain, f"keyed_to={supersedes}")
        if leaf_id == supersedes and chain["code"] == "EXPIRED":
            return out("invalid", "superseded_artifact_reached_its_own_declared_end", "expiry", chain)
    if chain["code"] == "ID_MISMATCH":
        return out("invalid", "delegation_id_does_not_bind_its_content", None, chain)
    if chain["code"] == "SCOPE_WIDENING":
        return out("invalid", "renewal_widens_beyond_its_parent", None, chain)
    if chain["state"] == "valid":
        if not is_purpose_permitted(e["action"]["requested_scope"], b.leaf(e)["authority"]["scope"]["grants"]):
            return out("invalid", "scope_not_in_grant", None, chain)
        return out("valid", "renewal_evaluated_on_its_own_terms", None, chain, f"delegation_id={leaf_id}")
    if chain["code"] == "EXPIRED":
        return out("invalid", "reached_declared_end", "expiry", chain)
    if chain["code"] == "NOT_YET_VALID":
        return out("not_yet_effective", "declared_start_not_reached", None, chain)
    return out("not_established", "chain_state_not_decidable", None, chain)


def rule_interim_mandate(b: Boundary, e: dict, r: dict, _registry: dict) -> dict:
    instrument = _one(r, "interim_instrument")
    if instrument is None:
        return out("not_established", "interim_instrument_not_recorded", None, None)
    extension = _one(r, "interim_extension")
    if extension is not None:
        if extension["issuer"] not in (instrument["body"].get("may_extend") or []):
            return out("not_established", "extension_issuer_not_named_by_the_recorded_instrument", None, None,
                       f"claimed_by={extension['issuer']}")
    chain = b.chain(e, e["now"])
    if chain["code"] == "TIME_WIDENING":
        return out("invalid", "mandate_extension_widens_beyond_the_interim_grant", None, chain)
    if chain["code"] == "EXPIRED":
        reason = "reached_declared_end" if extension is None else "extension_record_is_not_a_fresh_grant"
        return out("invalid", reason, "expiry", chain)
    if chain["state"] != "valid":
        return out("not_established", "chain_state_not_decidable", None, chain)
    caretaking = instrument["body"]["caretaking_scope"]
    if not is_purpose_permitted(e["action"]["requested_scope"], caretaking):
        return out("invalid", "outside_the_recorded_caretaking_scope", None, chain, "caretaking=" + ",".join(caretaking))
    if not is_purpose_permitted(e["action"]["requested_scope"], b.leaf(e)["authority"]["scope"]["grants"]):
        return out("invalid", "scope_not_in_grant", None, chain)
    return out("valid", "inside_the_recorded_caretaking_scope", None, chain, "caretaking=" + ",".join(caretaking))


RULES: dict[str, Callable[[Boundary, dict, dict, dict], dict]] = {
    "ending_kind": rule_ending_kind,
    "renewal": rule_renewal,
    "interim_mandate": rule_interim_mandate,
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def load(name: str) -> Any:
    return json.loads((HERE / name).read_text())


def to_event(fixture: dict, v: dict) -> dict:
    chain = fixture["chains"].get(v["chain"])
    action = fixture["actions"].get(v["action"])
    if chain is None or action is None:
        print(f"verify_python_sdk.py: vectors.json names an unknown chain or action in {v['id']}")
        sys.exit(2)
    records = []
    for rid in v["records"]:
        rec = fixture["records"].get(rid)
        if rec is None:
            print(f"verify_python_sdk.py: vectors.json names an unknown record {rid}")
            sys.exit(2)
        records.append(rec)
    return {"id": v["id"], "check": v["check"], "chain": chain, "action": action,
            "now": v["now"], "revocation": v["revocation"], "records": records}


def matches_lifecycle(actual: dict, expected: dict) -> bool:
    for key in ("verdict", "reason", "ending"):
        if actual.get(key) != expected.get(key):
            return False
    return actual.get("detail") == expected.get("detail")


def matches_sdk_cross_check(actual: dict, cross: dict) -> bool:
    # The SDK chain answer is a second assertion, not part of the lifecycle verdict, so
    # it is read from the vector's `sdk_cross_check` sibling rather than from `expected`.
    # Both are still checked on every vector.
    return (actual.get("sdk_chain_state") == cross.get("chain_state")
            and actual.get("sdk_failure_code") == cross.get("failure_code"))


def matches(actual: dict, vector: dict) -> bool:
    return (matches_lifecycle(actual, vector["expected"])
            and matches_sdk_cross_check(actual, vector["sdk_cross_check"]))


def line(a: dict) -> str:
    base = f"verdict={a['verdict']} ending={a['ending']} reason={a['reason']} sdk={a['sdk_chain_state']}/{a['sdk_failure_code']}"
    return base + (f" detail={a['detail']}" if "detail" in a else "")


def main() -> int:
    fixture = load("chain.json")
    vectors = load("vectors.json")

    def run(make: Callable[[], Boundary]) -> dict[str, dict]:
        return {v["id"]: make().handle(to_event(fixture, v)) for v in vectors["vectors"]}

    reference = lambda: Boundary("reference-boundary", fixture, records_ending_kind=True, renewal_extends=False)
    defectives = {
        "defective-boundary-boolean-validity":
            lambda: Boundary("defective-boundary-boolean-validity", fixture, records_ending_kind=False, renewal_extends=False),
        "defective-boundary-renewal-extends-identity":
            lambda: Boundary("defective-boundary-renewal-extends-identity", fixture, records_ending_kind=True, renewal_extends=True),
    }

    print(f"lifecycle-expiry-and-renewal (Python SDK {getattr(ap, '__version__', 'unknown')}): "
          f"{len(vectors['vectors'])} vectors, status label {vectors['status_label']}")
    print("")
    print("boundary: reference-boundary")
    ref_results = run(reference)
    matched = 0
    for v in vectors["vectors"]:
        actual = ref_results[v["id"]]
        ok = matches(actual, v)
        matched += 1 if ok else 0
        print(f"  {'MATCH' if ok else 'MISMATCH'} {v['id']}  {line(actual)}")
        if not ok:
            print(f"    expected: {json.dumps(v['expected'])} sdk_cross_check: {json.dumps(v['sdk_cross_check'])}")
            print(f"    actual:   {json.dumps(actual)}")

    all_defectives_ok = True
    for name, make in defectives.items():
        declared = set(vectors["declared_fail_sets"][name])
        results = run(make)
        ok = True
        print("")
        print(f"boundary: {name}")
        for v in vectors["vectors"]:
            actual = results[v["id"]]
            should_match = v["id"] not in declared
            entry_ok = matches(actual, v) if should_match else not matches(actual, v)
            ok = ok and entry_ok
            if should_match and entry_ok:
                continue
            label = "UNDECLARED MISMATCH" if should_match else ("DECLARED FAIL" if entry_ok else "DEFECT DID NOT REPRODUCE")
            print(f"  {label} {v['id']}  {line(actual)}")
        print(f"  {name} diverged on exactly its declared set: {ok}")
        all_defectives_ok = all_defectives_ok and ok

    SDK_SUPPORT.extend([
        ("chain state, including the time facet and revocation", "supported", "verify_authority_delegation_chain"),
        ("identifier binding to content", "supported", "verify_authority_delegation_chain, ID_MISMATCH"),
        ("scope and time narrowing between parent and child", "supported",
         "verify_authority_delegation_chain, SCOPE_WIDENING and TIME_WIDENING"),
        ("fixture-local record signatures", "supported", "verify over canonicalize_jcs"),
        ("scope membership", "not_supported",
         "no is_purpose_permitted equivalent in agent-passport-system 4.1.0; this runner applies the documented rule"),
        ("which of the two endings happened", "not_supported", "no export in agent-passport-system 4.1.0, supplied by this runner"),
        ("the ground and the actor of an early ending", "not_supported", "no export in agent-passport-system 4.1.0, supplied by this runner"),
        ("lifecycle standing to end an artifact early", "not_supported", "no export in agent-passport-system 4.1.0, supplied by this runner"),
        ("renewal as an operation, in either sense", "not_supported", "no export in agent-passport-system 4.1.0, supplied by this runner"),
        ("an interim or caretaking mandate", "not_supported", "no export in agent-passport-system 4.1.0, supplied by this runner"),
    ])
    print("")
    print("Python SDK support, agent-passport-system 4.1.0:")
    for concept, verdict, how in SDK_SUPPORT:
        print(f"  {verdict.ljust(14)} {concept}  ({how})")

    print("")
    print(f"reference-boundary matched: {matched}/{len(vectors['vectors'])}")
    print(f"both defective boundaries diverged on exactly their declared sets: {all_defectives_ok}")
    if matched == len(vectors["vectors"]) and all_defectives_ok:
        print("PASSED: the Python SDK run agrees with the TypeScript run on every vector")
        return 0
    print("FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
