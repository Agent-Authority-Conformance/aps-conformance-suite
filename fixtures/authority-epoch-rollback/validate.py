#!/usr/bin/env python3
"""Python runner for the authority-epoch-rollback candidate family.

Written from README.md, vectors.json and chains.json against the published
PyPI package `agent-passport-system`, not by porting harness.ts or verify.ts.
The two runners share the vectors and the record bytes and nothing else, which
is the only reason agreement between them is worth reporting.

Same contract as the TypeScript runner:

  * every record's RFC 8785 JCS digest is recomputed before any case runs
  * the reference policy must match every case
  * each negative control must fail exactly the cases the fixture declares,
    checked in both directions, and is run only on the group whose gate it
    removes

Run from the suite root with agent-passport-system 4.1.0 or later installed:

    python3 fixtures/authority-epoch-rollback/validate.py

This is a manual run and is not part of `npm test`, which stays Node only.
Exit 0 on agreement, 1 on a mismatch, 2 on a broken fixture.
"""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from agent_passport import (
    InMemoryAuthorityRevocationStore,
    create_authority_revocation_resolver,
    record_authority_revocation,
    verify_authority_delegation_chain,
    verify_authority_revocation,
)
from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import verify as verify_ed25519

HERE = Path(__file__).resolve().parent


def read_json(name):
    with (HERE / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


FIXTURE = read_json("chains.json")
VECTORS = read_json("vectors.json")

KEYS = FIXTURE["verification_keys"]
CHAIN = FIXTURE["chain"]
RECORDS = FIXTURE["records"]
VIEWS = FIXTURE["views"]
ROOT = CHAIN[0]


def resolve_key(_issuer, verification_method, _issued_at=None):
    return KEYS.get(verification_method)


@dataclass(frozen=True)
class Policy:
    name: str
    compare_epochs: bool
    consult_retained_records: bool
    check_fencing_token: bool
    withdrawal_removes_revocation: bool


REFERENCE = Policy("reference", True, True, True, False)
LATEST_READ = Policy("latest-read", False, False, True, False)
UNFENCED_WRITER = Policy("unfenced-writer", True, True, False, False)
CORRECTION_AS_DELETION = Policy("correction-as-deletion", True, True, True, True)


# ── fixture integrity ────────────────────────────────────────────────────────

def jcs_digest(value):
    return hashlib.sha256(canonicalize_jcs(value).encode("utf-8")).hexdigest()


def check_digests():
    problems = []
    for index, member in enumerate(CHAIN):
        actual = jcs_digest(member)
        declared = FIXTURE["digests"]["chain"][index]
        if actual != declared:
            problems.append(f"chain[{index}] declared={declared} actual={actual}")
    for name, declared in FIXTURE["digests"]["records"].items():
        actual = jcs_digest(RECORDS[name])
        if actual != declared:
            problems.append(f"record {name} declared={declared} actual={actual}")
    return problems


# ── the three gates ──────────────────────────────────────────────────────────

def evaluate_withdrawal(withdrawal_name, held_revocation_names):
    """Accepted only if it names a held revocation, verifies, and its signer is
    the party that revocation names as revoker. The reason is returned, never
    swallowed."""
    withdrawal = RECORDS[withdrawal_name]

    target = None
    for name in held_revocation_names:
        candidate = RECORDS.get(name)
        if candidate is not None and candidate.get("revocation_id") == withdrawal["revocation_id"]:
            target = candidate
            break
    if target is None:
        return {"accepted": False, "reason": "withdrawal_names_no_held_revocation"}

    public_key = KEYS.get(withdrawal["verification_method"])
    if public_key is None:
        return {"accepted": False, "reason": "withdrawal_key_unresolvable"}

    body = {k: v for k, v in withdrawal.items() if k != "signature"}
    preimage = FIXTURE["withdrawal_signature_domain"] + "\n" + canonicalize_jcs(body)
    if not verify_ed25519(preimage, withdrawal["signature"], public_key):
        return {"accepted": False, "reason": "withdrawal_signature_invalid"}

    if withdrawal["withdrawn_by"] != target["revoker"]:
        return {"accepted": False, "reason": "withdrawal_signer_is_not_the_revoker"}

    return {"accepted": True, "reason": None}


def materialize_view(view_name, policy):
    """A named view as a real revocation store.

    Revocations enter through record_authority_revocation, which verifies each
    one against its target first, so a 'revoked' answer is the SDK's. Tracked
    delegations are registered explicitly: in this SDK absence from a store is
    'unknown', never 'active'.

    The store exposes no removal method, so the correction-as-deletion control
    models deletion by never writing the record.
    """
    view = VIEWS[view_name]
    withdrawals = [evaluate_withdrawal(name, view["revocations"]) | {"record_name": name}
                   for name in view["withdrawals"]]

    deleted = set()
    if policy.withdrawal_removes_revocation:
        for outcome in withdrawals:
            if not outcome["accepted"]:
                continue
            withdrawal = RECORDS[outcome["record_name"]]
            for name in view["revocations"]:
                if RECORDS[name]["revocation_id"] == withdrawal["revocation_id"]:
                    deleted.add(name)

    held = [name for name in view["revocations"] if name not in deleted]

    store = InMemoryAuthorityRevocationStore()
    for delegation_id in view["tracked"]:
        store.track(delegation_id)
    for name in held:
        revocation = RECORDS[name]
        target = next(
            (m for m in CHAIN if m["delegation_id"] == revocation["delegation_id"]), None
        )
        if target is None:
            raise SystemExit(f"fixture is broken: revocation {name} targets no chain member")
        result = record_authority_revocation(
            store, target, revocation, resolve_verification_key=resolve_key
        )
        if not result.recorded:
            raise SystemExit(
                f"fixture is broken: revocation {name} did not verify: "
                f"{[f.code for f in result.verification.failures]}"
            )

    return {
        "name": view_name,
        "epoch": view["epoch"],
        "store": store,
        "withdrawals": [{"accepted": w["accepted"], "reason": w["reason"]} for w in withdrawals],
        "held": held,
    }


def epoch_gate(observed_epoch, retained_view_name, presented_view_name, policy):
    """A view behind the verifier's high-water mark is stale. A stale view never
    answers 'active': either a retained record establishes 'revoked', or the
    answer is 'unknown', which the chain verifier reads as indeterminate."""
    presented = materialize_view(presented_view_name, policy)
    presented_resolver = create_authority_revocation_resolver(
        presented["store"], resolve_verification_key=resolve_key
    )

    stale = (
        policy.compare_epochs
        and observed_epoch is not None
        and presented["epoch"] < observed_epoch
    )

    retained_resolver = None
    if stale and policy.consult_retained_records and retained_view_name is not None:
        retained_resolver = create_authority_revocation_resolver(
            materialize_view(retained_view_name, policy)["store"],
            resolve_verification_key=resolve_key,
        )

    def resolve(delegation):
        if not stale:
            return presented_resolver(delegation)
        if retained_resolver is not None and retained_resolver(delegation) == "revoked":
            return "revoked"
        return "unknown"

    high_water = (
        presented["epoch"]
        if observed_epoch is None
        else max(observed_epoch, presented["epoch"])
    )
    return {
        "resolve": resolve,
        "presented_epoch": presented["epoch"],
        "stale": stale,
        "high_water_mark_after": high_water,
        "presented_view": presented,
        "presented_answer_for_root": presented_resolver(ROOT),
    }


class EpochPublicationStore:
    """Authority-state publication with a fencing-token gate. A write whose token
    has gone backwards is refused. An equal token has not gone backwards."""

    def __init__(self, check_fencing_token):
        self.check_fencing_token = check_fencing_token
        self.highest_token = None
        self.published_view = None

    def write(self, token, view_name):
        if (
            self.check_fencing_token
            and self.highest_token is not None
            and token < self.highest_token
        ):
            return {"token": token, "view": view_name, "accepted": False, "reason": "stale_fencing_token"}
        self.highest_token = token if self.highest_token is None else max(self.highest_token, token)
        self.published_view = view_name
        return {"token": token, "view": view_name, "accepted": True, "reason": None}

    def published(self):
        if self.published_view is None:
            raise SystemExit("fixture is broken: a case read the publication store before any write")
        return self.published_view


def revocation_still_verifies(record_name):
    revocation = RECORDS[record_name]
    target = next((m for m in CHAIN if m["delegation_id"] == revocation["delegation_id"]), None)
    result = verify_authority_revocation(revocation, target, resolve_verification_key=resolve_key)
    return result.state == "valid"


# ── one case under one policy ────────────────────────────────────────────────

def run_case(case, policy):
    writes = []
    presented_view_name = case["presented_view"]

    if case["publication"] is not None:
        store = EpochPublicationStore(policy.check_fencing_token)
        for write in case["publication"]["writes"]:
            writes.append(store.write(write["token"], write["view"]))
        if presented_view_name != "$published":
            raise SystemExit(f"fixture is broken: {case['id']} has writes but does not read $published")
        presented_view_name = store.published()
    elif presented_view_name == "$published":
        raise SystemExit(f"fixture is broken: {case['id']} reads $published with no writes")

    gate = epoch_gate(
        case["verifier"]["observed_epoch"],
        case["verifier"]["retained_records_from_view"],
        presented_view_name,
        policy,
    )

    result = verify_authority_delegation_chain(
        CHAIN,
        now=FIXTURE["now"],
        resolve_verification_key=resolve_key,
        trust_root=lambda _root: True,
        resolve_revocation=gate["resolve"],
    )
    first = result.failures[0] if result.failures else None

    return {
        "resolver_answer": gate["resolve"](ROOT),
        "state": result.state,
        "failure_code": first.code if first is not None else None,
        "failure_index": first.index if first is not None else None,
        "high_water_mark_after": gate["high_water_mark_after"],
        "published_epoch_after": None if case["publication"] is None else gate["presented_epoch"],
        "presented_view_answer_if_unfenced": gate["presented_answer_for_root"],
        "withdrawals": gate["presented_view"]["withdrawals"],
        "revocation_still_held": "root-revocation" in gate["presented_view"]["held"],
        "revocation_still_verifies": revocation_still_verifies("root-revocation"),
        "writes": writes,
    }


FIELD_CHECKS = (
    ("state", "state"),
    ("failure_code", "failure_code"),
    ("failure_index", "failure_index"),
    ("resolver_answer", "resolver_answer"),
    ("high_water_mark_after", "high_water_mark_after"),
    ("published_epoch_after", "published_epoch_after"),
    ("presented_view_answer_if_unfenced", "presented_view_answer_if_unfenced"),
    ("revocation_still_held", "revocation_still_held"),
    ("revocation_still_verifies", "revocation_still_verifies"),
)


def differences(case, observed):
    expected = case["expected"]
    problems = []

    for expected_key, observed_key in FIELD_CHECKS:
        if expected_key not in expected:
            continue
        want, got = expected[expected_key], observed[observed_key]
        if want != got:
            problems.append(f"{expected_key}: expected {want!r}, observed {got!r}")

    if "withdrawal" in expected:
        want = [expected["withdrawal"]]
        if want != observed["withdrawals"]:
            problems.append(f"withdrawal: expected {want!r}, observed {observed['withdrawals']!r}")

    if case["publication"] is not None:
        want = [
            {
                "token": w["token"],
                "view": w["view"],
                "accepted": w["expected"]["accepted"],
                "reason": w["expected"]["reason"],
            }
            for w in case["publication"]["writes"]
        ]
        if want != observed["writes"]:
            problems.append(f"writes: expected {want!r}, observed {observed['writes']!r}")

    return problems


def main():
    digest_problems = check_digests()
    if digest_problems:
        for problem in digest_problems:
            print(f"FAIL digest {problem}", file=sys.stderr)
        print("authority-epoch-rollback: chains.json digests do not match its own bytes", file=sys.stderr)
        return 2
    print(
        f"digests ok: {len(CHAIN)} chain members and "
        f"{len(FIXTURE['digests']['records'])} records match their declared JCS sha256"
    )

    cases = VECTORS["cases"]
    if any(case["status"] != "candidate_against_proposed" for case in cases):
        print("authority-epoch-rollback: every case must be labelled candidate_against_proposed", file=sys.stderr)
        return 2

    print("")
    print("reference")
    matched = 0
    observed_by_policy = {}
    per_case = {}
    for case in cases:
        observed = run_case(case, REFERENCE)
        per_case[case["id"]] = observed
        problems = differences(case, observed)
        if not problems:
            matched += 1
            suffix = "" if observed["failure_code"] is None else (
                f" code={observed['failure_code']} index={observed['failure_index']}"
            )
            print(f"  PASS {case['id']} answer={observed['resolver_answer']} state={observed['state']}{suffix}")
        else:
            print(f"  FAIL {case['id']}", file=sys.stderr)
            for problem in problems:
                print(f"       {problem}", file=sys.stderr)
    observed_by_policy["reference"] = per_case

    controls = (
        (LATEST_READ, VECTORS["control_policies"]["latest-read"]),
        (UNFENCED_WRITER, VECTORS["control_policies"]["unfenced-writer"]),
        (CORRECTION_AS_DELETION, VECTORS["control_policies"]["correction-as-deletion"]),
    )

    control_problems = 0
    for policy, declaration in controls:
        declared = set(declaration.get("declared_failures", []))
        observed_failures = set()
        per_case = {}
        print("")
        print(f"{policy.name} ({declaration['axis']} removed), group(s): {', '.join(declaration['groups'])}")
        for case in cases:
            if case["group"] not in declaration["groups"]:
                continue
            observed = run_case(case, policy)
            per_case[case["id"]] = observed
            if differences(case, observed):
                observed_failures.add(case["id"])
                print(f"  fails {case['id']} observed state={observed['state']} answer={observed['resolver_answer']}")
            else:
                print(f"  matches {case['id']}")
        observed_by_policy[policy.name] = per_case

        for case_id in sorted(declared - observed_failures):
            print(f"  FAIL {policy.name} was declared to fail {case_id} and it matched instead", file=sys.stderr)
            control_problems += 1
        for case_id in sorted(observed_failures - declared):
            print(f"  FAIL {policy.name} failed {case_id}, which is not in its declared set", file=sys.stderr)
            control_problems += 1

    for case in cases:
        for key, policy_name in (
            ("unfenced_writer_would_return", "unfenced-writer"),
            ("correction_as_deletion_would_return", "correction-as-deletion"),
        ):
            want = case["expected"].get(key)
            if want is None:
                continue
            got = observed_by_policy.get(policy_name, {}).get(case["id"], {}).get("state")
            if got != want:
                print(
                    f"  FAIL {case['id']} declares {policy_name} would return {want}, observed {got}",
                    file=sys.stderr,
                )
                control_problems += 1
            else:
                print(f"  ok   {case['id']}: {policy_name} returned {got}, as declared")

    total = len(cases)
    discriminating = sum(1 for case in cases if case["establishes_epoch_property"])
    unconstrained = [case["id"] for case in cases if case["unconstrained_by_source"]]

    print("")
    print(f"authority-epoch-rollback Python: {matched}/{total} matched under reference")
    print(
        f"  {discriminating} of {total} cases discriminate a fenced implementation "
        "from an unfenced one; the rest are controls"
    )
    print(f"  outcome not determined by the proposed text, excluded from that count: {', '.join(unconstrained)}")

    if matched == total and control_problems == 0:
        print(
            "PASSED: reference matched every case, latest-read, unfenced-writer and "
            "correction-as-deletion each failed exactly their declared set"
        )
        return 0
    print(f"FAILED: reference {matched}/{total}, control problems {control_problems}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
