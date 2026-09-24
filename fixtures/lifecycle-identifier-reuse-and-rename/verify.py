#!/usr/bin/env python3
"""Second implementation of the lifecycle-identifier-reuse-and-rename boundary rules.

Runs the same thirteen presentations in vectors.json over the same chain.json
records, through a from-scratch implementation of the boundary steps and the same
declared defective negative control. No network access.

What this file gets from the Python SDK, agent-passport-system 4.x:

  * verify_authority_delegation_chain, for the grant's structural, temporal,
    signature and revocation state
  * agent_passport.canonicalize_jcs, for the exact RFC 8785 byte sequences the
    TypeScript side signed, which is what makes the custodian record signature
    checks a cross-language claim rather than a same-code replay
  * agent_passport.crypto.verify, for the Ed25519 signatures on the identifier
    binding and retention records

What it does NOT get from the Python SDK. No identifier binding, custodian
standing, controller pin or continuity interval surface exists in the installed
package, so every one of those steps is written out here. That is a recorded gap,
not a claim that the Python SDK decided any of it. See README "SDK findings" and
sdk-probe.py.

Run from the suite root with agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-identifier-reuse-and-rename/verify.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, crypto
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent

BINDING_DROP = ("binding_id", "signature")
RETENTION_DROP = ("retention_id", "signature")


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chain.json")
vectors = read_json("vectors.json")

if fixture.get("_placeholder") or not fixture.get("grants") or not fixture.get("custodian_standing"):
    print(
        "lifecycle-identifier-reuse-and-rename chain.json is not minted. Run "
        "`npx tsx fixtures/lifecycle-identifier-reuse-and-rename/mint.ts` first.",
        file=sys.stderr,
    )
    sys.exit(2)

if vectors.get("status") != "candidate_against_proposed":
    print("vectors.json must declare status candidate_against_proposed", file=sys.stderr)
    sys.exit(2)

PROPOSED = set(vectors.get("proposed_text", {}))
for presentation in vectors["presentations"]:
    if presentation.get("status") != "candidate_against_proposed":
        print(f"{presentation['id']} lost its candidate label", file=sys.stderr)
        sys.exit(2)
    named = presentation.get("tests_proposed_text") or []
    if not named or any(name not in PROPOSED for name in named):
        print(f"{presentation['id']} names undefined proposed text", file=sys.stderr)
        sys.exit(2)
    if presentation.get("case_id") not in presentation["id"]:
        print(f"{presentation['id']} does not carry its CASES.md case id", file=sys.stderr)
        sys.exit(2)

CUSTODIAN_STANDING = fixture["custodian_standing"]
CUSTODIAN_KEYS = fixture["custodian_keys"]
VERIFICATION_KEYS = fixture["verification_keys"]


def body_of(record: dict, drop) -> dict:
    return {key: value for key, value in record.items() if key not in drop}


def covers(from_: str, until, instant: str) -> bool:
    """Half-open [from, until). A null `until` is open-ended."""
    if instant < from_:
        return False
    if until is None:
        return True
    return instant < until


def subtract(gaps, from_: str, until: str):
    """Subtract a covered interval from a list of gaps, half-open throughout."""
    out = []
    for gap in gaps:
        gap_from, gap_until = gap
        if gap_until is not None and from_ >= gap_until:
            out.append(gap)
            continue
        if until <= gap_from:
            out.append(gap)
            continue
        if from_ > gap_from:
            out.append((gap_from, from_))
        if gap_until is None or until < gap_until:
            out.append((until, gap_until))
    return out


def dependency_grant(kind: str, identifier: str) -> str:
    return f"extid:{kind}:{identifier}"


def show_gap(gap) -> str:
    return f"{gap[0]}..{gap[1] if gap[1] is not None else 'open'}"


class Boundary:
    def __init__(self, name: str, **defects: bool) -> None:
        self.name = name
        self.undeclared_admits = defects["undeclared_admits"]
        self.unpinned_admits = defects["unpinned_admits"]
        self.string_match_is_enough = defects["string_match_is_enough"]
        self.trusts_self_asserted_custodian = defects["trusts_self_asserted_custodian"]

    def acceptable(self, records, drop):
        out = []
        for record in records:
            key = CUSTODIAN_KEYS.get(record["custodian"])
            if key is None:
                continue
            if not crypto.verify(canonicalize_jcs(body_of(record, drop)), record["signature"], key):
                continue
            if not self.trusts_self_asserted_custodian:
                if CUSTODIAN_STANDING.get(record["identifier_kind"]) != record["custodian"]:
                    continue
            out.append(record)
        return out

    def admit(self, vector) -> dict:
        grant = fixture["grants"][vector["grant"]]
        bindings = [fixture["bindings"][name] for name in vector["bindings"]]
        retentions = [fixture["retentions"][name] for name in vector["retentions"]]
        kind = vector["relies_on_kind"]
        identifier = vector["relies_on_identifier"]
        at = vector["at"]

        chain = verify_authority_delegation_chain(
            [grant],
            now=at,
            resolve_verification_key=lambda _issuer, method, _issued_at: VERIFICATION_KEYS.get(method),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _delegation: vector["revocation"],
        )
        if chain.state != "valid":
            code = chain.failures[0].code if chain.failures else "none"
            return {
                "verdict": "invalid",
                "reason": "authority_chain_not_valid",
                "detail": f"{chain.state}/{code}",
                "chain_state": chain.state,
            }

        grants = grant["authority"]["scope"]["grants"]
        dependency = dependency_grant(kind, identifier)

        if dependency not in grants and not self.undeclared_admits:
            return {
                "verdict": "not_established",
                "reason": "identifier_dependency_not_declared",
                "detail": dependency,
                "chain_state": chain.state,
                "controller_at_instant": None,
            }

        pin_prefix = f"{dependency}:controller:"
        pins = [g[len(pin_prefix):] for g in grants if g.startswith(pin_prefix)]
        if not pins and not self.unpinned_admits:
            return {
                "verdict": "not_established",
                "reason": "identifier_controller_not_pinned",
                "detail": dependency,
                "chain_state": chain.state,
                "controller_at_instant": None,
            }

        if self.string_match_is_enough:
            return {
                "verdict": "valid",
                "reason": "identifier_continuity_established",
                "detail": f"matched={dependency}",
                "chain_state": chain.state,
                "controller_at_instant": pins[0] if pins else None,
            }

        relevant = [
            b
            for b in self.acceptable(bindings, BINDING_DROP)
            if b["identifier_kind"] == kind and b["identifier"] == identifier
        ]
        at_instant = [b for b in relevant if covers(b["bound_from"], b["bound_until"], at)]
        holders = sorted({b["controller"] for b in at_instant})
        if not holders:
            return {
                "verdict": "not_established",
                "reason": "identifier_binding_lapsed",
                "detail": f"no_binding_covers={at}",
                "chain_state": chain.state,
                "controller_at_instant": None,
            }
        if len(holders) > 1:
            return {
                "verdict": "not_established",
                "reason": "identifier_binding_conflict",
                "detail": f"holders={'|'.join(holders)}",
                "chain_state": chain.state,
                "controller_at_instant": None,
            }
        holder = holders[0]
        if holder not in pins:
            return {
                "verdict": "not_established",
                "reason": "identifier_controller_changed",
                "detail": f"pinned={'|'.join(pins)} holder={holder}",
                "chain_state": chain.state,
                "controller_at_instant": holder,
            }

        gaps = [(grant["issued_at"], at)]
        for b in relevant:
            if b["controller"] != holder:
                continue
            gaps = subtract(gaps, b["bound_from"], b["bound_until"] if b["bound_until"] is not None else at)

        if gaps:
            acceptable_retentions = [
                r
                for r in self.acceptable(retentions, RETENTION_DROP)
                if r["identifier_kind"] == kind and r["identifier"] == identifier
            ]
            uncovered = gaps
            for r in acceptable_retentions:
                uncovered = subtract(uncovered, r["retained_from"], r["retained_until"])
            if uncovered:
                acceptable_ids = {r["retention_id"] for r in acceptable_retentions}
                present_but_unacceptable = [
                    r
                    for r in retentions
                    if r["identifier_kind"] == kind
                    and r["identifier"] == identifier
                    and r["retention_id"] not in acceptable_ids
                ]
                covered = uncovered
                for r in present_but_unacceptable:
                    covered = subtract(covered, r["retained_from"], r["retained_until"])
                if not covered:
                    return {
                        "verdict": "not_established",
                        "reason": "retention_custodian_without_standing",
                        "detail": "|".join(sorted(r["custodian"] for r in present_but_unacceptable)),
                        "chain_state": chain.state,
                        "controller_at_instant": holder,
                    }
                return {
                    "verdict": "not_established",
                    "reason": "identifier_continuity_gap_uncovered",
                    "detail": ",".join(show_gap(g) for g in uncovered),
                    "chain_state": chain.state,
                    "controller_at_instant": holder,
                }
            return {
                "verdict": "valid",
                "reason": "identifier_continuity_established",
                "detail": "retained_gap=" + ",".join(show_gap(g) for g in gaps),
                "chain_state": chain.state,
                "controller_at_instant": holder,
            }

        return {
            "verdict": "valid",
            "reason": "identifier_continuity_established",
            "detail": "continuously_bound",
            "chain_state": chain.state,
            "controller_at_instant": holder,
        }


def matches(actual: dict, expected: dict) -> bool:
    if actual["verdict"] != expected["verdict"] or actual["reason"] != expected["reason"]:
        return False
    if "detail" in expected and actual.get("detail") != expected["detail"]:
        return False
    if "chain_state" in expected and actual.get("chain_state") != expected["chain_state"]:
        return False
    if "controller_at_instant" in expected and actual.get("controller_at_instant") != expected["controller_at_instant"]:
        return False
    return True


def render(outcome: dict) -> str:
    parts = [f"{outcome['verdict']}/{outcome['reason']}"]
    for key in ("chain_state", "controller_at_instant", "detail"):
        if key in outcome:
            parts.append(f"{key}={outcome[key]}")
    return " ".join(parts)


def run(boundary: Boundary):
    results = {}
    print(f"\n{boundary.name}")
    for vector in vectors["presentations"]:
        outcome = boundary.admit(vector)
        ok = matches(outcome, vector["expected"])
        results[vector["id"]] = ok
        print(f"  {'MATCH        ' if ok else 'DIVERGES     '} {vector['id']}  {render(outcome)}")
        if not ok and boundary.name == "reference-boundary":
            print(f"    expected: {json.dumps(vector['expected'], sort_keys=True)}", file=sys.stderr)
    return results


reference = run(
    Boundary(
        "reference-boundary",
        undeclared_admits=False,
        unpinned_admits=False,
        string_match_is_enough=False,
        trusts_self_asserted_custodian=False,
    )
)
defective = run(
    Boundary(
        "defective-boundary-the-string-is-the-identifier",
        undeclared_admits=True,
        unpinned_admits=True,
        string_match_is_enough=True,
        trusts_self_asserted_custodian=True,
    )
)

total = len(vectors["presentations"])
reference_matched = sum(1 for ok in reference.values() if ok)
declared = vectors["declared_defective_fail_set"]
declared_set = set(declared)
undeclared = sorted(vid for vid, ok in defective.items() if not ok and vid not in declared_set)
declared_but_passing = sorted(vid for vid in declared if defective.get(vid) is True)

print("")
print(f"reference-boundary matched: {reference_matched}/{total}")
print(f"defective-boundary declared failing set: {len(declared)}")
if undeclared:
    print(f"  undeclared divergence: {', '.join(undeclared)}", file=sys.stderr)
if declared_but_passing:
    print(f"  declared but matched: {', '.join(declared_but_passing)}", file=sys.stderr)

ok = reference_matched == total and not undeclared and not declared_but_passing
print(
    "PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly "
    "the declared set (python)"
    if ok
    else "FAILED (python)"
)
sys.exit(0 if ok else 1)
