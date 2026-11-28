#!/usr/bin/env python3
"""Mutation check for check.py: each mutant disables one rule. A mutant is
killed when at least one case's verdict or deciding rule stops matching its
expectation under either text, or the checker crashes. Every mutant must be killed, otherwise that rule has no case
that depends on it."""
import json
import sys
import types

MUTANTS = {
    "no-iss-check": ('if "sub" not in obj or "iss" not in obj:', 'if "sub" not in obj:'),
    "no-client_profile-check": ('if "client_profile" in obj:', 'if False:'),
    "refresh-allows-drop": ('return "nonconformant", "R-5.2-refresh (chain dropped)"', 'return "conformant", "m"'),
    "refresh-allows-change": ("if act != recorded:", "if False:"),
    "refresh-reject-not-allowed": ('return "conformant", "R-5.2-refresh (reject branch)"', 'return "nonconformant", "m"'),
    "shared-registration-counts": ('if b and b.get("kind") == "registration" and not b.get("registration_unique", False):', 'if False:'),
    "basis-ignores-sub": ('if b.get("covers_sub") != sub:', "if False:"),
    "act-optional-with-basis": ('if act is None:\n                if text', 'if False:\n                if text'),
    "no-ambiguity-under-01": ('if text == "-01":', "if False:"),
    "actor-not-derived": ('if (act.get("iss"), act.get("sub")) != (want["iss"], want["sub"]):', "if False:"),
    "act-without-basis-ok": ('return "nonconformant", "R-3.5-iff (act without a basis covering this sub)"', 'return "conformant", "m"'),
    "cc-act-ok": ('return "nonconformant", "R-3.5-iff (client acts on own behalf, no actor separate from sub)"', 'return "conformant", "m"'),
}


def load(src):
    m = types.ModuleType("m")
    exec(compile(src, "check_mutant", "exec"), m.__dict__)
    return m


def misses(mod, cases):
    out = []
    for text in ("-01", "-01+pr32"):
        for c in cases:
            try:
                verdict, rule = mod.check(c, text)
            except Exception as e:
                out.append(f"{c['id']}@{text}(crash {type(e).__name__})")
                continue
            if verdict != c["expect"][text] or rule.split(" ")[0] != c["expect_rule"][text]:
                out.append(f"{c['id']}@{text}")
    return out


def main():
    src = open("check.py").read()
    cases = json.load(open("vectors.json"))["cases"]
    base = misses(load(src), cases)
    print("baseline misses:", base or "none")
    survived = 0
    for name, (a, b) in MUTANTS.items():
        n = src.count(a)
        if n != 1:
            print(f"BAD  {name}: pattern found {n} times")
            survived += 1
            continue
        killed_by = misses(load(src.replace(a, b)), cases)
        if not killed_by:
            survived += 1
        print(f"{'kill' if killed_by else 'LIVE'} {name:<28} {', '.join(killed_by)}")
    print(f"{len(MUTANTS) - survived}/{len(MUTANTS)} mutants killed")
    return 1 if (base or survived) else 0


if __name__ == "__main__":
    sys.exit(main())
