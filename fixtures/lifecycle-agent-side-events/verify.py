#!/usr/bin/env python3
"""Second implementation of the lifecycle-agent-side-events boundary rules.

Runs the same twenty presentations in vectors.json over the same chain.json
records, through a from-scratch implementation of the boundary steps and the same
declared defective negative control. No network access.

What this file gets from the Python SDK, agent-passport-system 4.x:

  * verify_authority_delegation_chain, for the grant's structural, temporal,
    signature and revocation state
  * agent_passport.canonicalize_jcs, for the exact RFC 8785 byte sequences the
    TypeScript side signed, which is what makes the record signature checks a
    cross-language claim rather than a same-code replay
  * agent_passport.crypto.verify, for the Ed25519 signatures on the executor
    lifecycle, action-authorization credential, authority claim, capability consent
    and revocation notice records

What it does NOT get from the Python SDK. No presenter binding, replay record,
executor lifecycle or capability consent surface exists in the installed package,
so every one of those steps is written out here. That is a recorded gap, not a
claim that the Python SDK decided any of it. See README "SDK findings" and
sdk-probe.py.

Run from the suite root with agent-passport-system 4.x installed:

    python3 fixtures/lifecycle-agent-side-events/verify.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent_passport import canonicalize_jcs, crypto
from agent_passport.v2.authority_delegation import verify_authority_delegation_chain

HERE = Path(__file__).resolve().parent

SIGNED_FIELDS_DROPPED = {
    "executor": ("executor_record_id", "signature"),
    "credential": ("credential_id", "signature"),
    "claim": ("claim_id", "signature"),
    "consent": ("consent_id", "signature"),
    "revocation": ("revocation_id", "signature"),
}


def read_json(name: str):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


fixture = read_json("chain.json")
vectors = read_json("vectors.json")

if fixture.get("_placeholder") or not fixture.get("grants") or not fixture.get("standing"):
    print(
        "lifecycle-agent-side-events chain.json is not minted. Run "
        "`npx tsx fixtures/lifecycle-agent-side-events/mint.ts` first.",
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

STANDING = fixture["standing"]
RECORD_KEYS = fixture["record_keys"]
VERIFICATION_KEYS = fixture["verification_keys"]


def body_of(record: dict, drop) -> dict:
    return {key: value for key, value in record.items() if key not in drop}


def add_ms(instant: str, ms: int) -> str:
    parsed = datetime.strptime(instant, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    shifted = parsed + timedelta(milliseconds=ms)
    return shifted.strftime("%Y-%m-%dT%H:%M:%S.") + f"{shifted.microsecond // 1000:03d}Z"


def verified(record: dict, issuer: str, kind: str) -> bool:
    key = RECORD_KEYS.get(issuer)
    if key is None:
        return False
    return crypto.verify(canonicalize_jcs(body_of(record, SIGNED_FIELDS_DROPPED[kind])), record["signature"], key)


class Boundary:
    def __init__(self, name: str, **defects: bool) -> None:
        self.name = name
        self.presenter_is_whoever_presents = defects["presenter_is_whoever_presents"]
        self.claims_supply_scope = defects["claims_supply_scope"]
        self.freshness_only = defects["freshness_only"]
        self.skip_executor_lifecycle = defects["skip_executor_lifecycle"]
        self.declared_is_consented = defects["declared_is_consented"]

    def admit(self, vector) -> dict:
        grant = fixture["grants"][vector["grant"]]
        presenter = fixture["parties"][vector["presenter"]]
        requested = vector["requested_capability"]
        credential = fixture["credentials"][vector["credential"]]
        consumed = [fixture["credentials"][name]["credential_id"] for name in vector["consumed"]]
        cache_lost_at = vector["cache_lost_at"]
        executor_records = [fixture["executors"][name] for name in vector["executor_records"]]
        claims = [fixture["claims"][name] for name in vector["claims"]]
        declared = fixture["capability_declarations"][vector["declared_capabilities"]]
        consents = [fixture["consents"][name] for name in vector["consent_records"]]
        notices = [fixture["revocations"][name] for name in vector["revocation_notices"]]
        at = vector["at"]

        applicable = [
            n
            for n in notices
            if n["delegation_id"] == grant["delegation_id"]
            and n["issuer"] == STANDING["revocation_notice"]
            and verified(n, n["issuer"], "revocation")
            and n["effective_at"] <= at
        ]
        resolver_answer = "revoked" if applicable else "active"

        chain = verify_authority_delegation_chain(
            [grant],
            now=at,
            resolve_verification_key=lambda _issuer, method, _issued_at: VERIFICATION_KEYS.get(method),
            trust_root=lambda _root: True,
            resolve_revocation=lambda _delegation: resolver_answer,
        )
        if chain.state != "valid":
            code = chain.failures[0].code if chain.failures else "none"
            return {
                "verdict": "invalid",
                "reason": "authority_chain_not_valid",
                "detail": f"{chain.state}/{code}",
                "chain_state": chain.state,
            }

        if not self.presenter_is_whoever_presents and presenter != grant["subject"]:
            supporting = [c for c in claims if c["about"] == presenter and verified(c, c["asserter"], "claim")]
            if supporting:
                asserters = "|".join(sorted(c["asserter"] for c in supporting))
                return {
                    "verdict": "not_established",
                    "reason": "self_asserted_authority_claim_is_not_a_grant",
                    "detail": f"asserter={asserters} subject={grant['subject']}",
                    "chain_state": chain.state,
                }
            return {
                "verdict": "not_established",
                "reason": "presenter_not_grant_subject",
                "detail": f"presenter={presenter} subject={grant['subject']}",
                "chain_state": chain.state,
            }

        scope = grant["authority"]["scope"]["grants"]
        claimed = []
        if self.claims_supply_scope:
            for c in claims:
                if verified(c, c["asserter"], "claim"):
                    claimed.extend(c["claimed_grants"])
        if requested not in scope and requested not in claimed:
            ignored = [c for c in claims if requested in c["claimed_grants"]]
            return {
                "verdict": "not_established",
                "reason": "scope_not_granted",
                "detail": f"{requested} ignored_claims={len(ignored)}",
                "chain_state": chain.state,
            }

        if not verified(credential, credential["issuer"], "credential"):
            return {
                "verdict": "not_established",
                "reason": "credential_signature_unverified",
                "chain_state": chain.state,
            }
        if credential["subject"] != grant["subject"] or credential["capability"] != requested:
            return {
                "verdict": "not_established",
                "reason": "credential_binding_mismatch",
                "detail": f"subject={credential['subject']} capability={credential['capability']}",
                "chain_state": chain.state,
            }
        window_end = add_ms(credential["issued_at"], credential["freshness_ms"])
        if at < credential["issued_at"] or at >= window_end:
            return {
                "verdict": "not_established",
                "reason": "credential_outside_freshness_window",
                "detail": f"{credential['issued_at']}..{window_end} at={at}",
                "chain_state": chain.state,
            }
        if not self.freshness_only:
            if cache_lost_at is not None:
                refuse_until = add_ms(cache_lost_at, credential["freshness_ms"])
                if at < refuse_until:
                    return {
                        "verdict": "not_established",
                        "reason": "replay_cache_lost_within_skew_window",
                        "detail": f"lost={cache_lost_at} refuse_until={refuse_until}",
                        "chain_state": chain.state,
                    }
            if credential["credential_id"] in consumed:
                return {
                    "verdict": "not_established",
                    "reason": "credential_already_presented",
                    "detail": credential["credential_id"],
                    "chain_state": chain.state,
                }

        if not self.skip_executor_lifecycle:
            prefix = "executor:"
            for executor_id in [g[len(prefix):] for g in scope if g.startswith(prefix)]:
                records = [
                    r
                    for r in executor_records
                    if r["executor_id"] == executor_id
                    and r["attestor"] == STANDING["executor_lifecycle"]
                    and verified(r, r["attestor"], "executor")
                ]
                if not records:
                    return {
                        "verdict": "not_established",
                        "reason": "named_executor_unresolvable",
                        "detail": executor_id,
                        "chain_state": chain.state,
                    }
                live = any(
                    r["live_from"] <= at and (r["retired_from"] is None or at < r["retired_from"]) for r in records
                )
                if not live:
                    retired = sorted(r["retired_from"] for r in records if r["retired_from"] is not None)
                    return {
                        "verdict": "not_established",
                        "reason": "named_executor_retired",
                        "detail": f"{executor_id} retired_from={retired[0] if retired else 'unknown'}",
                        "chain_state": chain.state,
                    }

        if not self.declared_is_consented:
            if requested not in declared:
                return {
                    "verdict": "not_established",
                    "reason": "capability_not_declared_by_runtime",
                    "detail": requested,
                    "chain_state": chain.state,
                }
            consented = set()
            for record in consents:
                if (
                    record["principal"] == STANDING["capability_consent"]
                    and record["subject"] == grant["subject"]
                    and record["as_of"] <= at
                    and verified(record, record["principal"], "consent")
                ):
                    consented.update(record["consented_capabilities"])
            if requested not in consented:
                listed = "|".join(sorted(consented)) or "none"
                return {
                    "verdict": "restricted",
                    "reason": "capability_not_consented",
                    "detail": f"{requested} consented={listed}",
                    "chain_state": chain.state,
                }

        return {"verdict": "valid", "reason": "action_established", "chain_state": chain.state}


def matches(actual: dict, expected: dict) -> bool:
    if actual["verdict"] != expected["verdict"] or actual["reason"] != expected["reason"]:
        return False
    if "detail" in expected and actual.get("detail") != expected["detail"]:
        return False
    if "chain_state" in expected and actual.get("chain_state") != expected["chain_state"]:
        return False
    return True


def render(outcome: dict) -> str:
    parts = [f"{outcome['verdict']}/{outcome['reason']}"]
    for key in ("chain_state", "detail"):
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
        presenter_is_whoever_presents=False,
        claims_supply_scope=False,
        freshness_only=False,
        skip_executor_lifecycle=False,
        declared_is_consented=False,
    )
)
defective = run(
    Boundary(
        "defective-boundary-same-agent-fresh-signature",
        presenter_is_whoever_presents=True,
        claims_supply_scope=True,
        freshness_only=True,
        skip_executor_lifecycle=True,
        declared_is_consented=True,
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

# The same ten divergences, split by the single defect that causes each one. Each
# boundary below keeps every other check and drops exactly one, so a failing run names
# the axis of wrongness instead of only reporting that an implementation is not the
# reference. Nothing new is decided: the five declared sets must be disjoint and their
# union must be the combined control's declared set, both checked here.
NO_DEFECTS = dict(
    presenter_is_whoever_presents=False,
    claims_supply_scope=False,
    freshness_only=False,
    skip_executor_lifecycle=False,
    declared_is_consented=False,
)
SINGLE_DEFECTS = [
    ("defective-presenter-is-whoever-presents", "presenter_is_whoever_presents"),
    ("defective-claims-supply-scope", "claims_supply_scope"),
    ("defective-freshness-window-only", "freshness_only"),
    ("defective-skips-executor-lifecycle", "skip_executor_lifecycle"),
    ("defective-runtime-declaration-is-consent", "declared_is_consented"),
]

split_sets = vectors["declared_fail_sets"]
split_ok = True
seen: set[str] = set()
for name, flag in SINGLE_DEFECTS:
    entry = split_sets.get(name)
    if entry is None:
        print(f"  vectors.json declares no fail set for {name}", file=sys.stderr)
        split_ok = False
        continue
    for vid in entry["fail_set"]:
        if vid in seen:
            print(f"  {vid} appears in more than one single-defect fail set", file=sys.stderr)
            split_ok = False
        seen.add(vid)
        if vid not in declared_set:
            print(f"  {name} declares {vid}, which the combined control does not", file=sys.stderr)
            split_ok = False
    entry_set = set(entry["fail_set"])
    results = run(Boundary(name, **{**NO_DEFECTS, flag: True}))
    entry_undeclared = sorted(vid for vid, vok in results.items() if not vok and vid not in entry_set)
    not_reproduced = sorted(vid for vid in entry["fail_set"] if results.get(vid) is True)
    if entry_undeclared:
        print(f"  {name} undeclared divergence: {', '.join(entry_undeclared)}", file=sys.stderr)
    if not_reproduced:
        print(f"  {name} declared but matched: {', '.join(not_reproduced)}", file=sys.stderr)
    entry_ok = not entry_undeclared and not not_reproduced
    if not entry_ok:
        split_ok = False
    print(
        f"  {name}: removes {entry['removes']}, and diverged on exactly its "
        f"{len(entry['fail_set'])} declared vectors: {entry_ok}"
    )

if len(seen) != len(declared_set):
    print(
        f"  the five single-defect fail sets cover {len(seen)} vectors, the combined control "
        f"declares {len(declared_set)}",
        file=sys.stderr,
    )
    split_ok = False
print(f"single-defect fail sets partition the combined declared set: {split_ok}")

ok = reference_matched == total and not undeclared and not declared_but_passing and split_ok
print(
    "PASSED: reference-boundary matched every presentation, defective boundary diverged on exactly "
    "the declared set, and each single-defect boundary diverged on exactly its own declared set (python)"
    if ok
    else "FAILED (python)"
)
sys.exit(0 if ok else 1)
