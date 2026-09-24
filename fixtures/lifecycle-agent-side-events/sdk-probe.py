#!/usr/bin/env python3
"""Records which APIs the PyPI reference SDK actually exposes for this family.

Prints one line per probe: supported, or not_supported with the reason. No
assertions about behaviour, only reachability.

    python3 fixtures/lifecycle-agent-side-events/sdk-probe.py
"""
from __future__ import annotations

import importlib
import importlib.metadata as metadata

PROBES = [
    ("presenter is the grant subject, verify", "agent_passport", "verify_presenter_is_subject"),
    ("replay cache, consume a presented credential", "agent_passport", "consume_presented_credential"),
    ("replay cache, lost-record refusal window", "agent_passport", "replay_cache_loss_window"),
    ("executor lifecycle record, issue", "agent_passport", "issue_executor_lifecycle_record"),
    ("executor availability at an instant, resolve", "agent_passport", "resolve_executor_availability_at"),
    ("capability consent record, issue", "agent_passport", "issue_capability_consent"),
    ("capability consent at an instant, resolve", "agent_passport", "resolve_capability_consent_at"),
    ("self-asserted authority claim, classify", "agent_passport", "classify_authority_claim"),
    ("approval, verify", "agent_passport", "verify_approval"),
    ("authority revocation, issue", "agent_passport", "issue_authority_revocation"),
    ("authority revocation, verify", "agent_passport", "verify_authority_revocation"),
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
    print(f"{len(PROBES) - not_supported}/{len(PROBES)} supported. The presenter binding, the consumption record")
    print("and its loss rule, the executor lifecycle lookup and the capability consent step are")
    print("implemented in verify.py, not by the SDK. See README.")


if __name__ == "__main__":
    main()
