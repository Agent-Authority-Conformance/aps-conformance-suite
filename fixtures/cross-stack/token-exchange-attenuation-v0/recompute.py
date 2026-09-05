#!/usr/bin/env python3
"""Recompute the token-exchange-attenuation-v0 conformance vectors.

Loads vectors.json from this script's own directory, applies the P1 vector
validity check, evaluates every request of every valid case against both the
exchanged token T2 and the subject token T1 using the decision procedure in
SOURCE.md, and compares the outcome with the expected values recorded in the
vectors file.

This is a clean-room implementation. It was written from SOURCE.md and
vectors.json alone, without reference to any other runner or engine, and it
imports nothing outside the Python 3 standard library.

Prints one line per check, writes results-recompute.json beside itself, and
exits 0 only when every check passes.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(HERE, "vectors.json")
RESULTS_PATH = os.path.join(HERE, "results-recompute.json")

# SOURCE.md fixes this set and calls it closed. A reason outside it is a bug
# in this script, not a new case, so the writer path asserts membership.
DENY_REASONS = (
    "scope_not_granted",
    "attribute_not_carried",
    "actor_not_permitted",
    "audience_mismatch",
)


def scope_set(token):
    """Scope as a set of opaque tokens.

    SOURCE.md: split the space-separated scope member on whitespace, and treat
    an absent scope member as the empty set. str.split() with no argument
    collapses runs of whitespace and yields [] for the empty string, which is
    the behaviour wanted here.
    """
    raw = token.get("scope")
    if raw is None:
        return set()
    return set(str(raw).split())


def audience_values(token):
    """T's aud as a list. The member may be a string or an array of strings."""
    aud = token.get("aud")
    if aud is None:
        return []
    if isinstance(aud, list):
        return list(aud)
    return [aud]


def current_actor(token):
    """T's current actor: the sub of the outermost act, else T's own sub.

    The act chain nests inward (act.act is the prior actor), so the outermost
    act is the object hanging directly off the token. Chain depth does not
    change the answer.
    """
    act = token.get("act")
    if isinstance(act, dict) and "sub" in act:
        return act["sub"]
    return token.get("sub")


def same_value(left, right):
    """Equality for scalar claim values.

    Python treats True == 1, which would let a boolean claim satisfy a numeric
    predicate. The vectors are all strings today, but the guard keeps a future
    case from passing for the wrong reason.
    """
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


def attribute_satisfied(token, spec):
    """Does T's own upstream_claims carry this claim with a satisfying value?

    This is the step P2 constrains: it reads the upstream_claims of the token
    under evaluation and nothing else. When T2 is the token, T1 is not consulted.
    """
    claims = token.get("upstream_claims")
    if not isinstance(claims, dict):
        return False
    name = spec["name"]
    if name not in claims:
        return False
    value = claims[name]
    if "contains" in spec:
        # contains is satisfied only when the claim is an array holding the
        # member. A scalar claim never satisfies contains.
        if not isinstance(value, list):
            return False
        return any(same_value(item, spec["contains"]) for item in value)
    if "equals" in spec:
        return same_value(value, spec["equals"])
    raise ValueError("unsupported attribute predicate: %r" % (spec,))


def decide(token, request):
    """Run the decision procedure against one token. Returns (verdict, reason).

    The order is audience, actor, scope, attribute, stopping at the first deny.
    SOURCE.md fixes the order so that two implementations agree on the reason
    and not merely on the verdict, so the early returns below are load-bearing.
    """
    requires = request.get("requires") or {}

    # 1. audience
    audience = request.get("audience")
    if audience is not None and audience not in audience_values(token):
        return "deny", "audience_mismatch"

    # 2. actor
    required_actor = request.get("required_actor")
    if required_actor is not None and current_actor(token) != required_actor:
        return "deny", "actor_not_permitted"

    # 3. scope
    if "scope" in requires and requires["scope"] not in scope_set(token):
        return "deny", "scope_not_granted"

    # 4. attribute
    if "attribute" in requires and not attribute_satisfied(token, requires["attribute"]):
        return "deny", "attribute_not_carried"

    return "permit", None


def p1_holds(case):
    """P1, scope monotonicity: T2's scope is a subset of T1's scope.

    Checked before anything else. A vector that fails it is rejected and its
    requests are never evaluated. The empty set is a subset of everything, so a
    T2 with no scope member at all passes P1.
    """
    t1 = scope_set(case.get("subject_token_claims") or {})
    t2 = scope_set(case.get("exchanged_token_claims") or {})
    return t2.issubset(t1), sorted(t2 - t1)


def expected_index(case):
    """Map request id -> expected entry, for the case's expected list."""
    index = {}
    for entry in case.get("expected") or []:
        index[entry["request"]] = entry
    return index


def main():
    with open(VECTORS_PATH, "r", encoding="utf-8") as handle:
        vectors = json.load(handle)

    lines = []
    case_results = []
    checks = 0
    passes = 0
    failures = 0
    skipped = 0
    rejected = 0

    for case in vectors.get("cases") or []:
        case_id = case["id"]
        claimed_valid = bool(case.get("vector_valid"))
        computed_valid, widened = p1_holds(case)

        checks += 1
        validity_pass = computed_valid == claimed_valid
        if validity_pass:
            passes += 1
            if computed_valid:
                detail = "valid, t2 scope is a subset of t1 scope"
            else:
                detail = "rejected, t2 scope adds %s" % (" ".join(widened) or "nothing nameable",)
            lines.append("PASS  %s  [vector-validity]  %s" % (case_id, detail))
        else:
            failures += 1
            lines.append(
                "FAIL  %s  [vector-validity]  computed vector_valid=%s expected=%s (t2 adds %s)"
                % (case_id, computed_valid, claimed_valid, " ".join(widened) or "nothing")
            )

        case_record = {
            "id": case_id,
            "vector_valid_expected": claimed_valid,
            "vector_valid_computed": computed_valid,
            "t2_scope_tokens_not_in_t1": widened,
            "validity_check": "pass" if validity_pass else "fail",
            "evaluated": computed_valid,
            "requests": [],
        }

        if not computed_valid:
            # A rejected vector's requests are never evaluated. They are still
            # listed, so the result file accounts for every request in the file.
            rejected += 1
            for request in case.get("requests") or []:
                skipped += 1
                lines.append(
                    "SKIP  %s  %s  vector rejected, request not evaluated"
                    % (case_id, request["id"])
                )
                case_record["requests"].append(
                    {"id": request["id"], "evaluated": False, "result": "skipped"}
                )
            case_results.append(case_record)
            continue

        expectations = expected_index(case)
        for request in case.get("requests") or []:
            request_id = request["id"]
            checks += 1

            t2_verdict, t2_reason = decide(case["exchanged_token_claims"], request)
            t1_verdict, t1_reason = decide(case["subject_token_claims"], request)
            if t2_reason is not None:
                assert t2_reason in DENY_REASONS, t2_reason
            if t1_reason is not None:
                assert t1_reason in DENY_REASONS, t1_reason

            expected = expectations.get(request_id)
            mismatches = []
            if expected is None:
                mismatches.append("no expected entry for this request")
            else:
                if t2_verdict != expected.get("against_t2"):
                    mismatches.append(
                        "against_t2 computed=%s expected=%s" % (t2_verdict, expected.get("against_t2"))
                    )
                # deny_reason is only meaningful when the T2 verdict is deny,
                # so it is compared only when both sides say deny.
                if t2_verdict == "deny" and expected.get("against_t2") == "deny":
                    if t2_reason != expected.get("deny_reason"):
                        mismatches.append(
                            "deny_reason computed=%s expected=%s"
                            % (t2_reason, expected.get("deny_reason"))
                        )
                if t1_verdict != expected.get("against_t1"):
                    mismatches.append(
                        "against_t1 computed=%s%s expected=%s"
                        % (
                            t1_verdict,
                            " (%s)" % t1_reason if t1_reason else "",
                            expected.get("against_t1"),
                        )
                    )
                # Some entries also pin the T1 deny reason. It is not required
                # by SOURCE.md, so it is compared only where the file states it.
                if "t1_deny_reason" in expected and t1_verdict == "deny":
                    if t1_reason != expected["t1_deny_reason"]:
                        mismatches.append(
                            "t1_deny_reason computed=%s expected=%s"
                            % (t1_reason, expected["t1_deny_reason"])
                        )

            if mismatches:
                failures += 1
                lines.append("FAIL  %s  %s  %s" % (case_id, request_id, "; ".join(mismatches)))
            else:
                passes += 1
                lines.append("PASS  %s  %s" % (case_id, request_id))

            case_record["requests"].append(
                {
                    "id": request_id,
                    "evaluated": True,
                    "computed": {
                        "against_t2": t2_verdict,
                        "deny_reason": t2_reason,
                        "against_t1": t1_verdict,
                        "against_t1_deny_reason": t1_reason,
                    },
                    "expected": expected,
                    "result": "fail" if mismatches else "pass",
                    "mismatches": mismatches,
                }
            )

        case_results.append(case_record)

    summary = (
        "SUMMARY  cases=%d  rejected=%d  checks=%d  pass=%d  fail=%d  requests_skipped=%d"
        % (len(vectors.get("cases") or []), rejected, checks, passes, failures, skipped)
    )
    for line in lines:
        print(line)
    print(summary)

    results = {
        "family": vectors.get("family"),
        "version": vectors.get("version"),
        "runner": "recompute.py",
        "mode": "clean-room recompute from SOURCE.md and vectors.json",
        "totals": {
            "cases": len(vectors.get("cases") or []),
            "cases_rejected": rejected,
            "checks": checks,
            "pass": passes,
            "fail": failures,
            "requests_skipped": skipped,
        },
        "summary": summary,
        "cases": case_results,
    }
    with open(RESULTS_PATH, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=False)
        handle.write("\n")

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
