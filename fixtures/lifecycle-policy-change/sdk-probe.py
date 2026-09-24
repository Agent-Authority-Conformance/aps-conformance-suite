#!/usr/bin/env python3
"""Records which APIs the PyPI reference SDK actually exposes for this family.

Prints one line per probe: supported, or not_supported with the reason. No
assertions about behaviour, only reachability.

    python3 fixtures/lifecycle-policy-change/sdk-probe.py
"""
from __future__ import annotations

import importlib
import importlib.metadata as metadata

PROBES = [
    ("policy version registry, create", "agent_passport", "create_policy_version"),
    ("policy version registry, resolve at instant", "agent_passport", "resolve_policy_version_at"),
    ("operative pointer, issue", "agent_passport", "issue_operative_policy_pointer"),
    ("operative pointer, resolve", "agent_passport", "resolve_operative_policy_pointer"),
    ("policy rollback, classify", "agent_passport", "classify_policy_rollback"),
    ("decision record, render against pinned version", "agent_passport", "render_decision_against_policy_version"),
    ("policy bundle, create", "agent_passport", "create_policy_bundle"),
    ("policy bundle, verify", "agent_passport", "verify_policy_bundle"),
    ("policy chain, verify", "agent_passport", "verify_policy_chain"),
    ("policy decision, verify", "agent_passport", "verify_policy_decision"),
    ("scope version hash, compute", "agent_passport", "compute_scope_version_hash"),
    ("authority chain, verify", "agent_passport.v2.authority_delegation", "verify_authority_delegation_chain"),
    ("authority delegation, issue root", "agent_passport", "issue_authority_delegation"),
    ("RFC 8785 JCS canonical bytes", "agent_passport", "canonicalize_jcs"),
    ("Ed25519 verify", "agent_passport.crypto", "verify"),
]


def main() -> None:
    version = metadata.version("agent-passport-system")
    print(f"agent-passport-system=={version} (PyPI, Python reference SDK)")
    not_supported = 0
    for label, module_name, attribute in PROBES:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as error:
            not_supported += 1
            print(f"  not_supported  {label:<46} {module_name}: {error}")
            continue
        if callable(getattr(module, attribute, None)):
            print(f"  supported      {label:<46} {module_name}.{attribute}")
        else:
            not_supported += 1
            print(f"  not_supported  {label:<46} {module_name}.{attribute}: not present in the installed package")
    print("")
    print(f"{len(PROBES) - not_supported}/{len(PROBES)} supported. The policy-version, operative-pointer,")
    print("rollback-classification and decision-rendering steps this family decides are implemented")
    print("in verify.py, not by the SDK. See README.")


if __name__ == "__main__":
    main()
