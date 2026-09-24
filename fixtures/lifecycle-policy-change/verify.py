#!/usr/bin/env python3
"""Second implementation of the lifecycle-policy-change boundary rules, in Python.

Runs the same thirteen presentations in vectors.json over the same chain.json
records, through a from-scratch implementation of the boundary steps and the same
declared defective negative control. No network access.

What this file gets from the Python SDK, agent-passport-system 4.x:

  * verify_authority_delegation_chain, for the grant's structural, temporal,
    signature and revocation state
  * agent_passport.canonicalize_jcs, for the exact RFC 8785 byte sequences the
    TypeScript side signed, which is what makes the record signature checks a
    cross-language claim rather than a same-code replay
  * agent_passport.crypto.verify, for the Ed25519 signatures on the policy version,
    operative pointer and decision records

What it does NOT get from the Python SDK. No policy-version registry, no operative
pointer resolution, no rollback classification and no decision-rendering API exist
in the installed package, so every one of those steps is written out here. That is
a recorded gap, not a claim that the Python SDK decided any of it. See README
"SDK findings" and sdk-probe.py.

Run from the suite root with agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-policy-change/verify.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_passport import canonicalize_jcs, crypto
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent

POINTER_DROP = ("pointer_id", "signature")
DECISION_DROP = ("decision_id", "signature")


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chain.json")
vectors = read_json("vectors.json")

if fixture.get("_placeholder") or not fixture.get("chains", {}).get("GRANT") or not fixture.get("pointers"):
    print(
        "lifecycle-policy-change chain.json is not minted. Run "
        "`npx tsx fixtures/lifecycle-policy-change/mint.ts` first.",
        file=sys.stderr,
    )
    sys.exit(2)

if vectors.get("status") != "candidate_against_proposed":
    print("lifecycle-policy-change vectors.json must declare status candidate_against_proposed", file=sys.stderr)
    sys.exit(2)

PROPOSED = set(vectors.get("proposed_text", {}))
for presentation in vectors["presentations"]:
    if presentation.get("status") != "candidate_against_proposed":
        print(f"lifecycle-policy-change {presentation['id']} lost its candidate label", file=sys.stderr)
        sys.exit(2)
    named = presentation.get("tests_proposed_text") or []
    if not named or any(name not in PROPOSED for name in named):
        print(f"lifecycle-policy-change {presentation['id']} names undefined proposed text", file=sys.stderr)
        sys.exit(2)
    if presentation.get("case_id") not in presentation["id"]:
        print(f"lifecycle-policy-change {presentation['id']} does not carry its CASES.md case id", file=sys.stderr)
        sys.exit(2)

GRANT = fixture["chains"]["GRANT"]
POLICY_VERSIONS = fixture["policy_versions"]
POLICY_STANDING = fixture["policy_standing"]
RECORD_KEYS = fixture["record_keys"]
GATEWAY = fixture["parties"]["gateway"]
VERIFICATION_KEYS = fixture["verification_keys"]


def body_of(record: dict, drop) -> dict:
    return {key: value for key, value in record.items() if key not in drop}


def evaluate(rules: dict, amount: int, approval_presented: bool) -> str:
    """The one rule evaluator this family has, reimplemented from the README."""
    if amount > rules["max_amount"]:
        return "deny"
    if rules["approval_required"] and not approval_presented:
        return "deny"
    return "allow"


class Boundary:
    def __init__(self, name: str, **defects: bool) -> None:
        self.name = name
        self.trusts_self_asserted_standing = defects["trusts_self_asserted_standing"]
        self.breaks_pointer_ties = defects["breaks_pointer_ties"]
        self.trusts_pointer_kind = defects["trusts_pointer_kind"]
        self.renders_against_operative_now = defects["renders_against_operative_now"]
        self.tightening_invalidates_grant = defects["tightening_invalidates_grant"]

    def acceptable_pointers(self, pointer_set):
        out = []
        for pointer in pointer_set:
            issuer = pointer["authority"]
            key = RECORD_KEYS.get(issuer)
            if key is None:
                continue
            message = canonicalize_jcs(body_of(pointer, POINTER_DROP))
            if not crypto.verify(message, pointer["signature"], key):
                continue
            if not self.trusts_self_asserted_standing and issuer not in POLICY_STANDING:
                continue
            out.append(pointer)
        return out

    def operative_at(self, pointer_set, at: str) -> dict:
        acceptable = [p for p in self.acceptable_pointers(pointer_set) if p["effective_from"] <= at]
        if not acceptable:
            return {"verdict": "not_established", "reason": "no_operative_policy_version", "operative_version_id": None}
        latest = max(p["effective_from"] for p in acceptable)
        at_latest = [p for p in acceptable if p["effective_from"] == latest]
        targets = sorted({p["operative_version_id"] for p in at_latest})
        if len(targets) > 1:
            if not self.breaks_pointer_ties:
                return {
                    "verdict": "not_established",
                    "reason": "operative_pointer_ambiguous",
                    "detail": f"effective_from={latest} targets={'|'.join(targets)}",
                    "operative_version_id": None,
                }
            winner = sorted(at_latest, key=lambda p: p["pointer_id"], reverse=True)[0]
            return {
                "verdict": "valid",
                "reason": "operative_version_resolved",
                "operative_version_id": winner["operative_version_id"],
            }
        return {"verdict": "valid", "reason": "operative_version_resolved", "operative_version_id": targets[0]}

    def decide(self, vector) -> dict:
        pointer_set = [fixture["pointers"][label] for label in vectors["pointer_sets"][vector["pointer_set"]]]
        if vector["mode"] == "action":
            return self.decide_action(vector, pointer_set)
        if vector["mode"] == "pointer":
            return self.decide_pointer(vector, pointer_set)
        return self.decide_render(vector, pointer_set)

    def decide_action(self, vector, pointer_set) -> dict:
        chain = verify_authority_delegation_chain(
            GRANT,
            now=vector["at"],
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
        if "ledger:export" not in GRANT[0]["authority"]["scope"]["grants"]:
            return {
                "verdict": "not_established",
                "reason": "scope_not_granted",
                "detail": "ledger:export",
                "chain_state": chain.state,
            }

        operative = self.operative_at(pointer_set, vector["at"])
        if operative["verdict"] != "valid":
            return {**operative, "chain_state": chain.state}
        version = POLICY_VERSIONS.get(operative["operative_version_id"])
        if version is None:
            return {
                "verdict": "not_established",
                "reason": "operative_policy_version_unresolvable",
                "detail": operative["operative_version_id"],
                "chain_state": chain.state,
                "operative_version_id": operative["operative_version_id"],
            }

        outcome = evaluate(version["rules"], vector["amount"], vector["approval_presented"])
        if outcome == "deny":
            if self.tightening_invalidates_grant:
                return {
                    "verdict": "invalid",
                    "reason": "grant_invalid_under_current_policy",
                    "chain_state": chain.state,
                    "operative_version_id": version["version_id"],
                }
            return {
                "verdict": "restricted",
                "reason": "denied_under_operative_policy_version",
                "detail": f"amount={vector['amount']} approval_presented={str(vector['approval_presented']).lower()}",
                "chain_state": chain.state,
                "operative_version_id": version["version_id"],
            }
        return {
            "verdict": "valid",
            "reason": "allowed_under_operative_policy_version",
            "chain_state": chain.state,
            "operative_version_id": version["version_id"],
        }

    def decide_pointer(self, vector, pointer_set) -> dict:
        operative = self.operative_at(pointer_set, vector["at"])
        if operative["verdict"] != "valid":
            return {**operative, "pointer_classification": None}
        classify = fixture["pointers"][vector["classify"]]
        accepted = any(p["pointer_id"] == classify["pointer_id"] for p in self.acceptable_pointers(pointer_set))
        if not accepted and not self.trusts_self_asserted_standing:
            return {
                "verdict": "not_established",
                "reason": "pointer_issuer_without_policy_standing",
                "detail": classify["authority"],
                "operative_version_id": operative["operative_version_id"],
                "pointer_classification": None,
            }
        if classify["kind"] != "rollback":
            return {
                "verdict": "valid",
                "reason": "pointer_is_not_a_rollback_claim",
                "operative_version_id": operative["operative_version_id"],
                "pointer_classification": classify["kind"],
            }
        if self.trusts_pointer_kind:
            return {
                "verdict": "valid",
                "reason": "rollback_to_previously_operative_version",
                "operative_version_id": operative["operative_version_id"],
                "pointer_classification": "rollback_to_existing_version",
            }
        earlier = [p for p in self.acceptable_pointers(pointer_set) if p["effective_from"] < classify["effective_from"]]
        previously_operative = any(p["operative_version_id"] == classify["operative_version_id"] for p in earlier)
        target = POLICY_VERSIONS.get(classify["operative_version_id"])
        if target is None:
            return {
                "verdict": "not_established",
                "reason": "rollback_target_version_unresolvable",
                "detail": classify["operative_version_id"],
                "operative_version_id": operative["operative_version_id"],
                "pointer_classification": None,
            }
        if not previously_operative:
            same_rules = sorted(
                version["version_id"]
                for version in POLICY_VERSIONS.values()
                if version["rules_digest"] == target["rules_digest"] and version["version_id"] != target["version_id"]
            )
            detail = f"same_rules_as={'|'.join(same_rules)}" if same_rules else "no_prior_pointer_named_this_version"
            return {
                "verdict": "not_established",
                "reason": "rollback_target_never_previously_operative",
                "detail": detail,
                "operative_version_id": operative["operative_version_id"],
                "pointer_classification": "new_version_not_a_rollback",
            }
        return {
            "verdict": "valid",
            "reason": "rollback_to_previously_operative_version",
            "operative_version_id": operative["operative_version_id"],
            "pointer_classification": "rollback_to_existing_version",
        }

    def decide_render(self, vector, pointer_set) -> dict:
        record = fixture["decisions"][vector["decision"]]
        gateway_key = RECORD_KEYS.get(GATEWAY)
        message = canonicalize_jcs(body_of(record, DECISION_DROP))
        if gateway_key is None or not crypto.verify(message, record["signature"], gateway_key):
            return {"verdict": "not_established", "reason": "decision_signature_unverified"}

        if self.renders_against_operative_now:
            operative = self.operative_at(pointer_set, vector["read_at"])
            version = POLICY_VERSIONS.get(operative.get("operative_version_id") or "")
            if version is None:
                return {"verdict": "not_established", "reason": "no_operative_policy_version"}
        else:
            if record["policy_version_digest"] is None:
                return {
                    "verdict": "not_established",
                    "reason": "decision_not_pinned_to_policy_version",
                    "detail": record["decision_id"],
                }
            version = next(
                (v for v in POLICY_VERSIONS.values() if v["version_digest"] == record["policy_version_digest"]),
                None,
            )
            if version is None:
                return {
                    "verdict": "not_established",
                    "reason": "pinned_policy_version_unresolvable",
                    "detail": record["policy_version_digest"],
                }

        rederived = evaluate(version["rules"], record["amount"], record["approval_presented"])
        if rederived != record["outcome"]:
            return {
                "verdict": "not_established",
                "reason": "recorded_outcome_not_reproducible_under_the_version_used",
                "detail": f"recorded={record['outcome']} rederived={rederived} under={version['version_id']}",
                "operative_version_id": version["version_id"],
            }
        return {
            "verdict": "valid",
            "reason": "decision_renders_under_the_version_used",
            "detail": f"outcome={record['outcome']} under={version['version_id']}",
            "operative_version_id": version["version_id"],
        }


def matches(actual: dict, expected: dict) -> bool:
    if actual["verdict"] != expected["verdict"] or actual["reason"] != expected["reason"]:
        return False
    if "detail" in expected and actual.get("detail") != expected["detail"]:
        return False
    if "chain_state" in expected and actual.get("chain_state") != expected["chain_state"]:
        return False
    if "operative_version_id" in expected and actual.get("operative_version_id") != expected["operative_version_id"]:
        return False
    if "pointer_classification" in expected and actual.get("pointer_classification") != expected["pointer_classification"]:
        return False
    return True


def render(outcome: dict) -> str:
    parts = [f"{outcome['verdict']}/{outcome['reason']}"]
    for key in ("chain_state", "operative_version_id", "pointer_classification", "detail"):
        if key in outcome:
            parts.append(f"{key}={outcome[key]}")
    return " ".join(parts)


def run(boundary: Boundary):
    results = {}
    print(f"\n{boundary.name}")
    for vector in vectors["presentations"]:
        outcome = boundary.decide(vector)
        ok = matches(outcome, vector["expected"])
        results[vector["id"]] = ok
        label = "MATCH        " if ok else "DIVERGES     "
        print(f"  {label} {vector['id']}  {render(outcome)}")
        if not ok and boundary.name == "reference-boundary":
            print(f"    expected: {json.dumps(vector['expected'], sort_keys=True)}", file=sys.stderr)
    return results


reference = run(
    Boundary(
        "reference-boundary",
        trusts_self_asserted_standing=False,
        breaks_pointer_ties=False,
        trusts_pointer_kind=False,
        renders_against_operative_now=False,
        tightening_invalidates_grant=False,
    )
)
defective = run(
    Boundary(
        "defective-boundary-current-policy-is-the-policy",
        trusts_self_asserted_standing=True,
        breaks_pointer_ties=True,
        trusts_pointer_kind=True,
        renders_against_operative_now=True,
        tightening_invalidates_grant=True,
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
