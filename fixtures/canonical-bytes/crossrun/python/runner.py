#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Python runner for the RFC 8785 canonical-byte cross-run.
#
# Reports where this canonicalizer's bytes and SHA-256 agree with the pinned
# fixture. It is not a verdict on the implementation, and it is not APS
# conformance; it is a byte diff on ten cases.
#
# Canonicalizer under test, in order of preference:
#
#   1. agent_passport.canonical.canonicalize_jcs from the published
#      agent-passport-system distribution on PyPI (see requirements.txt).
#   2. json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False),
#      the standard library encoder, labeled baseline_json_encoder. It does not
#      claim RFC 8785, so its divergences are comparative evidence about the
#      standard library, not a failed conformance run.
#
# WHY (1) IS REFUSED WHEN IT IS AN EDITABLE INSTALL. A `pip install -e` of a
# local checkout resolves to a working tree on this machine, which would make
# the report depend on a sibling repository that a person cloning this suite
# does not have. That is the failure the self-containment rule exists to catch,
# and it is invisible at the import statement, so it is checked explicitly here
# and the runner drops to the labeled baseline instead of reporting a version it
# cannot stand behind.
#
# Every expected value is read from the fixture at run time. Nothing about the
# ten cases is transcribed into this file.
#
# Usage:
#   python3 runner.py [fixture-path]
# Default fixture: ../../canonical-bytes-jcs-v2.json

import hashlib
import json
import os
import platform
import sys
from pathlib import Path

DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent.parent / "canonical-bytes-jcs-v2.json"


def _first_party():
    """Return (fn, name, version) for the published distribution, or None.

    None means either that the distribution is absent or that it resolves to a
    local checkout, which this runner will not report as a published version.
    """
    try:
        import importlib.metadata as md

        from agent_passport.canonical import canonicalize_jcs
    except Exception:
        return None
    try:
        dist = md.distribution("agent-passport-system")
        version = dist.version
        raw = dist.read_text("direct_url.json")
    except Exception:
        return None
    if raw:
        try:
            info = json.loads(raw)
        except ValueError:
            return None
        # A direct_url pointing at a directory, editable or not, is a local
        # checkout rather than an artifact resolved from an index.
        if info.get("dir_info") is not None or str(info.get("url", "")).startswith("file://"):
            return None
    return canonicalize_jcs, "agent_passport.canonical.canonicalize_jcs", version


def _baseline(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def first_divergent_byte_offset(a: bytes, b: bytes):
    """Zero-based offset of the first differing byte.

    When one sequence is an exact prefix of the other there is no differing
    byte, so the answer is the length of the shorter one: the offset a reader
    would look at to see where the two stopped agreeing.
    """
    shared = min(len(a), len(b))
    for i in range(shared):
        if a[i] != b[i]:
            return i
    return None if len(a) == len(b) else shared


def main() -> int:
    fixture_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_FIXTURE
    fixture_bytes = fixture_path.read_bytes()
    fixture = json.loads(fixture_bytes)

    chosen = _first_party()
    if chosen is not None:
        canonicalize, implementation, version = chosen
        kind = "first_party"
    else:
        canonicalize = _baseline
        implementation = 'json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)'
        version = platform.python_version()
        kind = "baseline_json_encoder"
        # Diagnostic on stderr, so stdout stays a clean JSON document. Without
        # this a reader sees "baseline_json_encoder" and cannot tell whether the
        # package is missing, unusable, or was refused for being a local
        # checkout, which are three different things to do something about.
        print(
            "note: falling back to the standard library encoder. "
            "Install the published distribution for a first-party result: "
            "python3 -m pip install -r " + str(Path(__file__).resolve().parent / "requirements.txt"),
            file=sys.stderr,
        )

    cases = []
    for vector in fixture["vectors"]:
        actual = canonicalize(vector["input"]).encode("utf-8")
        expected = bytes.fromhex(vector["canonical_bytes_hex"])
        actual_sha = hashlib.sha256(actual).hexdigest()
        byte_match = actual == expected
        cases.append({
            "name": vector["name"],
            "byte_match": byte_match,
            "sha256_match": actual_sha == vector["canonical_sha256"],
            "actual_bytes_hex": actual.hex(),
            "actual_sha256": actual_sha,
            "first_divergent_byte_offset": None if byte_match else first_divergent_byte_offset(actual, expected),
        })

    json.dump({
        "runner": "python",
        "implementation": implementation,
        "implementation_kind": kind,
        "implementation_version": version,
        "runtime_version": f"python {platform.python_version()}",
        "fixture": str(fixture_path),
        "fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "cases": cases,
        "summary": {
            "total": len(cases),
            "byte_match": sum(1 for c in cases if c["byte_match"]),
            "sha256_match": sum(1 for c in cases if c["sha256_match"]),
        },
    }, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
