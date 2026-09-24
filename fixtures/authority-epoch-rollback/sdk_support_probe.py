#!/usr/bin/env python3
"""Records which of this family's three concepts the PyPI `agent-passport-system`
package has an API for, so the README's not_supported entries are reproducible
rather than asserted.

This probe reports absence of a named surface. It is not a conformance result and
not a defect report: nothing in draft-03 asks the SDK for any of these.

Run: python3 fixtures/authority-epoch-rollback/sdk_support_probe.py
Exit 0 always. It reports, it does not judge.
"""
from __future__ import annotations

import inspect
import re

import agent_passport as ap

PROBES = (
    (
        "authority epoch on delegation, revocation or store state",
        re.compile(r"authority_epoch|revocation_epoch|epoch_of|state_epoch", re.I),
        "AER-01 to AER-06",
    ),
    (
        "fencing token on an authority-mutating write",
        re.compile(r"fencing|fence_token|write_token", re.I),
        "AER-07 to AER-10",
    ),
    (
        "withdrawal or correction of a recorded revocation",
        re.compile(r"withdraw_revocation|revocation_withdrawal|unrevoke|correct_revocation", re.I),
        "AER-11, AER-12",
    ),
)


def main() -> int:
    exported = sorted(name for name in dir(ap) if not name.startswith("_"))
    print(f"agent-passport-system (PyPI) {ap.__version__}, {len(exported)} exports")
    for concept, pattern, needed_for in PROBES:
        hits = [name for name in exported if pattern.search(name)]
        verdict = "not_supported" if not hits else "present: " + ", ".join(hits)
        print(f"  {concept} [{needed_for}]: {verdict}")

    store_methods = [m for m in dir(ap.InMemoryAuthorityRevocationStore) if not m.startswith("_")]
    print(f"  InMemoryAuthorityRevocationStore methods: {', '.join(store_methods)}")
    removal = any(re.search(r"delete|remove|clear|unset", m, re.I) for m in store_methods)
    print(f"  removal method on the revocation store: {'present' if removal else 'not_supported'}")

    print(
        "  resolve_revocation parameter of verify_authority_delegation_chain: "
        f"{inspect.signature(ap.verify_authority_delegation_chain)}"
    )
    print(
        "  the resolver returned by create_authority_revocation_resolver takes the "
        "delegation and nothing else, so there is no argument through which an epoch "
        "or a token could be supplied"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
