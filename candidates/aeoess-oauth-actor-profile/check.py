#!/usr/bin/env python3
"""Candidate checker for draft-mcguinness-oauth-actor-profile issuance rules.

Candidate, not conformance. Two text bases, chosen on the command line:
"-01" is repo main at d76465c, "-01+pr32" is d76465c with open PR #32
applied (authorization code wording). Default is -01+pr32. Each case gives AS-side inputs
(grant, delegation basis, recorded chain) and one observed outcome (issued
claims or an error). The checker says whether the outcome satisfies the rules
it covers and which rule decided. An implementer replaces `outcome` with what
their AS actually returned for the same inputs.

Rules covered (section numbers as rendered for -01):
  R-3.4-iss     act objects carry sub and iss; client_profile never inside act
  R-3.5-iff     act present exactly when the token represents delegation;
                sub != client_id alone is not delegation
  R-5.2-shared  a registration shared by several actors is no basis
  R-5.2-derive  actor identity derives from the delegation basis
  R-5.2-basis   auth code: a basis covering this (sub, actor) pair means act
                present. Under -01 the 5.2 MAY conflicts with the 3.5 MUST,
                so a missing act is reported as ambiguous. PR #32 adds
                "regardless of the requested scope" and removes the MAY
  R-5.2-refresh refresh_token grant: carry the recorded chain unchanged or
                reject; never issue a refreshed token without it

Not covered: Token Exchange, TTS, RS processing, depth limits, cnf.
"""
import json
import sys


def act_objects(act):
    while isinstance(act, dict):
        yield act
        act = act.get("act")


def basis_holds(state, sub):
    b = state.get("delegation_basis")
    if not b:
        return False
    if b.get("kind") == "registration" and not b.get("registration_unique", False):
        return False
    if b.get("covers_sub") != sub:
        return False
    return True


def check(case, text="-01+pr32"):
    req, state, out = case["request"], case["as_state"], case["outcome"]
    grant = req["grant_type"]
    recorded = state.get("recorded_act")

    if "error" in out:
        if grant == "refresh_token" and recorded:
            return "conformant", "R-5.2-refresh (reject branch)"
        return "not-evaluated", "rejection outside refresh-with-chain is policy"

    tok = out["issued"]
    act = tok.get("act")

    if act is not None:
        for obj in act_objects(act):
            if "sub" not in obj or "iss" not in obj:
                return "nonconformant", "R-3.4-iss (act object missing sub or iss)"
            if "client_profile" in obj:
                return "nonconformant", "R-3.4-iss (client_profile inside act)"

    if grant == "refresh_token":
        if recorded:
            if act is None:
                return "nonconformant", "R-5.2-refresh (chain dropped)"
            if act != recorded:
                return "nonconformant", "R-5.2-refresh (chain changed)"
            return "conformant", "R-5.2-refresh (carried unchanged)"
        return "not-evaluated", "refresh without recorded chain is not decided here"

    if grant == "authorization_code":
        b = state.get("delegation_basis")
        if b and b.get("kind") == "registration" and not b.get("registration_unique", False):
            if act is not None:
                return "nonconformant", "R-5.2-shared (shared registration is no basis)"
            return "conformant", "R-5.2-shared (no act without basis)"
        if basis_holds(state, tok.get("sub")):
            if act is None:
                if text == "-01":
                    return "ambiguous", "R-3.5-iff MUST vs -01 R-5.2 MAY (basis present, act missing)"
                return "nonconformant", "R-5.2-basis / R-3.5-iff (basis present, act missing)"
            want = b["actor"]
            if (act.get("iss"), act.get("sub")) != (want["iss"], want["sub"]):
                return "nonconformant", "R-5.2-derive (actor not from basis)"
            return "conformant", "R-5.2-basis"
        if act is not None:
            return "nonconformant", "R-3.5-iff (act without a basis covering this sub)"
        return "conformant", "R-3.5-iff (no basis, no act)"

    if grant == "client_credentials":
        if state.get("client_acts_on_own_behalf", True):
            if act is not None:
                return "nonconformant", "R-3.5-iff (client acts on own behalf, no actor separate from sub)"
            return "conformant", "R-3.5-iff"
        return "not-evaluated", "client_credentials on behalf of another subject"

    return "not-evaluated", "grant type not covered"


def main(path, text):
    with open(path) as f:
        cases = json.load(f)["cases"]
    failed = 0
    for c in cases:
        verdict, rule = check(c, text)
        want = c["expect"][text]
        ok = verdict == want and rule.split(" ")[0] == c["expect_rule"][text]
        failed += not ok
        print(f"{'ok  ' if ok else 'MISS'} {c['id']:<6} expect={want:<14} got={verdict:<14} {rule}")
    print(f"text {text}: {len(cases) - failed}/{len(cases)} cases matched expectation")
    return 1 if failed else 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "vectors.json"
    text = sys.argv[2] if len(sys.argv) > 2 else "-01+pr32"
    if text not in ("-01", "-01+pr32"):
        sys.exit("text must be -01 or -01+pr32")
    sys.exit(main(path, text))
