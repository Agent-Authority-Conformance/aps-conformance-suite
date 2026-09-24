#!/usr/bin/env python3
"""Records which APIs the Python reference SDK actually exposes for this family.

Prints one line per probe: supported, or not_supported with the reason. No network
access, no assertions about behaviour, only reachability.

    python3 fixtures/capability-binding-drift/sdk-probe.py
"""
from __future__ import annotations

import importlib
import importlib.metadata as metadata

PROBES = [
    ("tool registry entry, create", "agent_passport", "create_tool_registry_entry"),
    ("tool registry entry, verify", "agent_passport", "verify_tool_integrity"),
    ("tool manifest, create", "agent_passport", "create_tool_manifest"),
    ("tool manifest, verify", "agent_passport", "verify_tool_manifest"),
    ("tool manifest, revise", "agent_passport", "revise_tool_manifest"),
    ("namespace claim, verify", "agent_passport", "verify_namespace_claim"),
    ("authority chain, verify", "agent_passport.v2.authority_delegation", "verify_authority_delegation_chain"),
    ("authority delegation, issue root", "agent_passport", "issue_authority_delegation"),
    ("action reference v2, compute", "agent_passport", "compute_action_ref_v2"),
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
            print(f"  not_supported  {label:<36} {module_name}: {error}")
            continue
        if callable(getattr(module, attribute, None)):
            print(f"  supported      {label:<36} {module_name}.{attribute}")
        else:
            not_supported += 1
            print(f"  not_supported  {label:<36} {module_name}.{attribute}: not present in the installed package")
    print("")
    print("This SDK ships no tool-integrity module at all, so the registry-entry layer")
    print("is reimplemented in verify.py from its crypto and canonicalization primitives.")
    print(f"probes: {len(PROBES)}, not_supported: {not_supported}")


if __name__ == "__main__":
    main()
