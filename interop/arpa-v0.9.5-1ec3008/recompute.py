#!/usr/bin/env python3
"""Recompute ARPA authority-evaluation outcomes from the specification text alone.

Imports no repository code. Standard library only: glob, json, os, sys, datetime.

The rules below are transcribed from the numbered steps of section 28.2, "Authority Evaluation
Algorithm", in spec/agent-registry-protocol-v0.9.0.md at pinned SHA
1ec3008effc00f3ccbac26769f5528d97d065c9b. The steps this script implements, as that section
states them:

     3. Confirm that registration status permits the requested class of action.
     4. Confirm that operational and security status permit execution.
     5. Confirm that all required status records satisfy freshness policy.
     8. Verify proofs, issuer competence, validity periods, and revocation status for every
        delegation.
    10. Evaluate the requested action, resource, purpose, jurisdiction, amount, time, deployment,
        and other contextual inputs.
    11. Apply mandatory prohibitions before discretionary conditions.
    12. Determine required approvals and whether they are already satisfied.
    16. Return `allow`, `allow_with_conditions`, `deny`, `indeterminate`, or `not_applicable`.

and the closing rule of the same section:

    A failed mandatory prohibition check MUST result in `deny`. Missing required current status or
    conflicting authoritative evidence SHOULD result in `indeterminate` unless policy explicitly
    requires denial.

Steps 1, 2, 6, 7, 9, 13, 14, 15 and 17 are not implemented: the TV vectors supply an already
resolved single envelope with no delegation lineage, no assurance claims and no named relying-party
policy, so those steps have nothing to act on in this corpus.

Ordering rule this script enforces: for every vector the outcome is computed first, from the input
only, and the vector's own expected_outcome is read from disk afterwards, in a second pass. The
computing function never receives the expected value.

Usage: python3 recompute.py <path to the pinned checkout>
"""
import glob
import json
import os
import sys
from datetime import datetime, timezone

CHECKOUT = sys.argv[1]
PINNED_SHA = "1ec3008effc00f3ccbac26769f5528d97d065c9b"
SPEC_PATH = "spec/agent-registry-protocol-v0.9.0.md"
SPEC_SECTION = "28.2"
VECTOR_DIR = os.path.join(CHECKOUT, "conformance", "test-vectors")

# Step 3 and step 4. The status enumerations are the repository's own, published in
# schemas/status.schema.json; a fail-closed reading treats any lifecycle value other than the
# permitting one as not permitting the requested class of action.
PERMITTING_REGISTRATION = {"active"}
PERMITTING_OPERATION = {"available"}
NON_PERMITTING_SECURITY = {"compromised", "quarantined"}


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def evaluate(vector_input):
    """Section 28.2 steps, in the order the section states them. Input only; no expected value."""
    status = vector_input["agent_status"]
    envelope = vector_input["authority_envelope"]
    request = vector_input["request"]
    now = instant(request["time"])

    if status.get("registration") not in PERMITTING_REGISTRATION:
        return "deny", "step 3: registration status does not permit the requested class of action"

    if status.get("operation") not in PERMITTING_OPERATION:
        return "deny", "step 4: operational status does not permit execution"
    if status.get("security") in NON_PERMITTING_SECURITY:
        return "deny", "step 4: security status does not permit execution"

    max_age = request.get("policy_max_status_age_seconds")
    if max_age is not None:
        age = (now - instant(status["observed_at"])).total_seconds()
        if age > max_age:
            return "indeterminate", (
                "step 5 with the closing rule: status age %.0fs exceeds "
                "policy_max_status_age_seconds %s" % (age, max_age)
            )
    if "valid_until" in status and now > instant(status["valid_until"]):
        return "indeterminate", "step 5 with the closing rule: status record is past its valid_until"

    if now < instant(envelope["effective_from"]) or now >= instant(envelope["effective_until"]):
        return "deny", "step 8: request time is outside the authority envelope validity interval"

    # Step 11 runs before step 12, as the section requires.
    if request["action"] in (envelope.get("prohibitions") or []):
        return "deny", "step 11: the requested action is a mandatory prohibition"

    if request["action"] not in (envelope.get("action_classes") or []):
        return "deny", "step 10: the requested action is outside the envelope action classes"
    resource_scope = envelope.get("resource_scope")
    if resource_scope and request.get("resource") not in resource_scope:
        return "deny", "step 10: the requested resource is outside the envelope resource scope"
    jurisdiction_scope = envelope.get("jurisdiction_scope")
    if jurisdiction_scope and request.get("jurisdiction") not in jurisdiction_scope:
        return "deny", "step 10: the requested jurisdiction is outside the envelope jurisdiction scope"

    amount = request.get("amount")
    limits = envelope.get("limits") or {}
    if amount is not None and "per_transaction" in limits and amount > limits["per_transaction"]:
        return "deny", "step 10: amount exceeds the per_transaction limit"

    for approval in (envelope.get("required_approvals") or []):
        condition = approval.get("condition", "")
        parts = condition.replace(" ", "").split(">")
        if len(parts) == 2 and parts[0] == "amount" and parts[1].isdigit():
            if amount is not None and amount > int(parts[1]):
                return "allow_with_conditions", (
                    'step 12: approval required by condition "%s"' % condition
                )

    return "allow", "steps 3 to 16 satisfied"


def main():
    paths = sorted(glob.glob(os.path.join(VECTOR_DIR, "TV-*.json")))

    print("ARPA v0.9.5 authority-evaluation recomputation from specification text")
    print("checkout   : %s" % CHECKOUT)
    print("pinned SHA : %s" % PINNED_SHA)
    print("rules from : %s section %s" % (SPEC_PATH, SPEC_SECTION))
    print("imports    : glob, json, os, sys, datetime (standard library only)")
    print("")

    # Pass one. Compute from the input only. The expected outcome is not read in this pass.
    computed = []
    for path in paths:
        vector = json.load(open(path, encoding="utf-8"))
        if vector["check"] != "authority_evaluation":
            continue
        outcome, basis = evaluate(vector["input"])
        computed.append((vector["vector_id"], path, outcome, basis))

    print("PASS ONE, computed from the vector input alone, before any expected value was read:")
    for vector_id, _path, outcome, basis in computed:
        print("  %-9s %-22s %s" % (vector_id, outcome, basis))
    print("")

    # Pass two. Only now read each vector's own expected_outcome and compare.
    print("PASS TWO, the vectors' own expected_outcome read from disk and compared:")
    print("")
    print("  %-9s %-22s %-22s %s" % ("vector", "expected", "recomputed", "match"))
    print("  " + "-" * 62)
    matched = 0
    for vector_id, path, outcome, _basis in computed:
        expected = json.load(open(path, encoding="utf-8"))["expected_outcome"]
        match = "yes" if expected == outcome else "no"
        matched += expected == outcome
        print("  %-9s %-22s %-22s %s" % (vector_id, expected, outcome, match))
    print("")
    print("authority-evaluation vectors attempted: %d" % len(computed))
    print("recomputed outcomes matching the vectors' own expected outcomes: %d/%d"
          % (matched, len(computed)))

    skipped = [
        json.load(open(p, encoding="utf-8"))["vector_id"]
        for p in paths
        if json.load(open(p, encoding="utf-8"))["check"] != "authority_evaluation"
    ]
    print("not attempted, check is not authority_evaluation: %s" % ", ".join(skipped))

    return 0 if matched == len(computed) else 1


if __name__ == "__main__":
    sys.exit(main())
