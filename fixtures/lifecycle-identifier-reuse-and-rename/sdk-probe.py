#!/usr/bin/env python3
"""Records which APIs the PyPI reference SDK actually exposes for this family.

Prints one line per probe: supported, or not_supported with the reason. No
assertions about behaviour, only reachability.

    python3 fixtures/lifecycle-identifier-reuse-and-rename/sdk-probe.py
"""
from __future__ import annotations

import importlib
import importlib.metadata as metadata

PROBES = [
    ("external identifier binding, issue", "agent_passport", "issue_identifier_binding"),
    ("external identifier binding, verify", "agent_passport", "verify_identifier_binding"),
    ("external identifier controller, resolve at instant", "agent_passport", "resolve_identifier_controller_at"),
    ("external identifier continuity, verify", "agent_passport", "verify_identifier_continuity"),
    ("identifier retention record, issue", "agent_passport", "issue_identifier_retention"),
    ("namespace claim, verify", "agent_passport", "verify_namespace_claim"),
    ("DID document, create", "agent_passport", "create_did_document"),
    ("public key from DID", "agent_passport", "public_key_from_did"),
    ("identity rotation log, verify", "agent_passport", "verify_rotation_log"),
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
            print(f"  not_supported  {label:<50} {module_name}: {error}")
            continue
        if callable(getattr(module, attribute, None)):
            print(f"  supported      {label:<50} {module_name}.{attribute}")
        else:
            not_supported += 1
            print(f"  not_supported  {label:<50} {module_name}.{attribute}: not present in the installed package")
    print("")
    print(f"{len(PROBES) - not_supported}/{len(PROBES)} supported. No exposed API takes an external identifier")
    print("and an instant and answers who controls it, so every identifier step is implemented")
    print("in verify.py, not by the SDK. See README.")


if __name__ == "__main__":
    main()
