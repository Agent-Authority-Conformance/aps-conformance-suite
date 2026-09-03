"""RFC 8785 (JCS) canonicalizer — CTEF reference implementation.

Copied VERBATIM from `src/signing.py` (`canonicalize_jcs_strict` +
`_normalize_for_jcs_strict`) in the AgentAvow repo, the CTEF reference
implementation cited by the vector file's `contract.reference_implementation`
field ("src.signing.canonicalize_jcs_strict"). Vendored here so the recompute
resolves without cloning that repo. Stdlib-only.

Provenance (see ../SOURCE.md): AgentAvow repo github.com/AgentAvow/AgentAvow,
commit a0a22f4b7420f370c4f5ebf31d14110593b407f3, file src/signing.py
(sha256 040e480dfe6bfbb8ca5ff2e9915cc4571320bcd786f20cfc5daf9475f79991a2).
"""
from __future__ import annotations

import json
import math


def canonicalize_jcs_strict(payload: object) -> bytes:
    """Serialize *payload* to RFC 8785 (JCS) canonical JSON bytes.

    - Keys sorted by Unicode code point (``sort_keys=True``).
    - ``None`` values preserved (not stripped) at every depth.
    - Non-ASCII emitted as literal UTF-8 bytes (``ensure_ascii=False``).
    - Integer-valued floats normalized to int (``1.0`` -> ``1``) per ECMA-262.
    - Inf/NaN rejected.
    """
    cleaned = _normalize_for_jcs_strict(payload)
    return json.dumps(
        cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _normalize_for_jcs_strict(obj: object) -> object:
    """Like a plain normalizer but preserves ``None`` (RFC 8785 keeps null)."""
    if isinstance(obj, dict):
        return {k: _normalize_for_jcs_strict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_for_jcs_strict(item) for item in obj]
    if isinstance(obj, float):
        if math.isinf(obj) or math.isnan(obj):
            raise ValueError(f"Cannot canonicalize {obj}")
        if obj == int(obj):
            return int(obj)
    return obj
