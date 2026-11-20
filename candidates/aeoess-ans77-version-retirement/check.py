#!/usr/bin/env python3
"""Checker for candidate aeoess-ans77-version-retirement.

Evaluates each case in vectors.json with a synthetic model of the two ANS-6 caller
verification tiers (badge tier, SCITT tier) and compares the result with the case's
expected outcome. Standard library only. No network, no clock read, no ANS code.

    python3 check.py              run the cases, exit 0 if every case matches
    python3 check.py --mutants    also run single-rule mutants of the model and report
                                  which cases catch each one (exit 0 if all are caught)
"""
import json
import sys
from pathlib import Path

TERMINAL = {"EXPIRED", "REVOKED"}
LIVE = {"ACTIVE", "WARNING"}


def badge_tier(case, m):
    """ANS-6 6.2 and 8.1, read at ans-spec 9284c7e. The badge is computed by the TL from the
    registration's latest event, so status and identity certs come from that event."""
    caller = case["caller"]
    entry = case["tl"][caller["version"]]
    if caller["version"] not in case["dns_badge_versions"]:
        if case.get("badge_rule") == "missing_record_not_retirement" and not m.get("missing_record_is_retirement"):
            # #77 comment 7010705683: a missing record MUST NOT be read as retirement while the
            # TL status is non-terminal, so the badge tier decides from the TL entry.
            if entry["status"] in TERMINAL:
                return {"decision": "reject", "reason": "status_terminal"}
        elif not m.get("badge_ignores_missing_record"):
            return {"decision": "reject", "reason": "no_badge_match"}
    if not m.get("skip_fingerprint") and caller["fingerprint"] not in entry["identity_certs"]:
        return {"decision": "reject", "reason": "fingerprint_not_listed"}
    return status_rule(entry["status"], case["policy"], m)


def scitt_tier(case, m):
    """ANS-6 6.3, 9.4 and 11.1. The caller presents the last status token it obtained."""
    tok = case["status_token"]
    if tok["status"] in TERMINAL:
        return {"decision": "reject", "reason": "status_terminal"}
    allowance = 0 if m.get("no_skew_or_grace") else case["policy"]["skew_s"] + case["policy"]["grace_s"]
    if not m.get("ignore_token_exp") and case["now"] > tok["exp"] + allowance:
        return {"decision": "reject", "reason": "token_expired"}
    if not m.get("skip_fingerprint") and case["caller"]["fingerprint"] not in tok["valid_identity_certs"]:
        return {"decision": "reject", "reason": "fingerprint_not_listed"}
    return status_rule(tok["status"], case["policy"], m)


def status_rule(status, policy, m):
    if status in LIVE:
        return {"decision": "accept", "reason": "ok"}
    if status == "DEPRECATED":
        if m.get("deprecated_as_active"):
            return {"decision": "accept", "reason": "ok"}
        if policy["deprecated"] == "reject":
            return {"decision": "reject", "reason": "deprecated_by_local_policy"}
        return {"decision": "accept_with_warning", "reason": "migration_signal"}
    return {"decision": "reject", "reason": "status_terminal"}


def matches(got, want):
    if isinstance(want.get("decision"), list):
        return got["decision"] in want["decision"]
    return got["decision"] == want["decision"] and (want.get("reason") is None or got["reason"] == want["reason"])


def run(cases, m):
    failures = []
    for c in cases:
        b, s = badge_tier(c, m), scitt_tier(c, m)
        agree = b["decision"] == s["decision"]
        e = c["expected"]
        ok = matches(b, e["badge_tier"]) and matches(s, e["scitt_tier"]) and (
            e.get("tiers_agree") is None or agree == e["tiers_agree"])
        if not ok:
            failures.append(c["id"])
        if not m:
            print(json.dumps({"id": c["id"], "reading": c["reading"], "badge_tier": b, "scitt_tier": s,
                              "tiers_agree": agree, "pass": ok}))
    return failures


MUTANTS = {
    "badge tier reads the TL entry when the _ans-badge record is missing": {"badge_ignores_missing_record": True},
    "SCITT tier ignores the status token exp": {"ignore_token_exp": True},
    "SCITT tier applies no skew or grace allowance": {"no_skew_or_grace": True},
    "DEPRECATED treated as ACTIVE, no migration signal": {"deprecated_as_active": True},
    "identity certificate fingerprint not checked": {"skip_fingerprint": True},
    "badge tier reads a missing record as retirement under the comment 7010705683 rule": {"missing_record_is_retirement": True},
}


def main():
    data = json.loads((Path(__file__).parent / "vectors.json").read_text())
    for c in data["cases"]:
        if c.get("status") != "candidate_against_proposed":
            sys.exit(f"{c['id']}: every case must carry status candidate_against_proposed")
    failures = run(data["cases"], {})
    print(json.dumps({"cases": len(data["cases"]), "failures": failures}))
    code = 1 if failures else 0
    if "--mutants" in sys.argv:
        for name, m in MUTANTS.items():
            caught = run(data["cases"], m)
            print(json.dumps({"mutant": name, "caught_by": caught}))
            if not caught:
                code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
