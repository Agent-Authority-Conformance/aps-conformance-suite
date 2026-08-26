#!/usr/bin/env python3
"""Standing conformance runner for the aat-pair-v1 fixture corpus.

Runs the checks that were previously performed by hand once a week, one
single-drop script at a time. This runner is generic over the schema: a new
drop is a new fixture file, and a new issuer is a config entry under
runners/issuers/, not a new script.

Per vector it performs:
  a. Ed25519 signature verification against the issuer JWKS, key matched by kid
  b. both window bounds, evaluated against that vector's own verification_time
  c. act-binding digest recompute when the claim is present
  d. comparison of the computed outcome against the vector's expected_result

Across vectors it records two observations that are never failures: whether the
drop carries a single subject, and which jti values repeat. A repeated jti is
intentional in some vectors (the not-yet-valid vector reuses the live token
bytes), so repetition is reported and never deduplicated or skipped.

What a run is: a record of what was executed, against what bytes, by whom, at
what time. It is not a conformance verdict about any implementation.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import getpass
import hashlib
import json
import socket
import sys
import unicodedata
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "aat-pair-v1"
RUNNER_VERSION = "1.0.0"

# Outcome vocabulary. Window outcomes are distinct values, never one boolean.
VALID = "valid"
NBF_REJECT = "nbf_reject"
EXP_REJECT = "exp_reject"
SIG_REJECT = "sig_reject"

WINDOW_INSIDE = "INSIDE"
WINDOW_NOT_YET_VALID = "NOT_YET_VALID"
WINDOW_EXPIRED = "EXPIRED"

_JWKS_CACHE: dict[str, dict[str, Any]] = {}


def b64u_decode(s: str) -> bytes:
    """Decode unpadded base64url."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b: bytes) -> str:
    """Encode to unpadded base64url."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def parse_instant(text: str) -> datetime.datetime:
    """Parse an RFC 3339 instant, accepting the literal Z designator."""
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def _utf16_sort_key(key: str) -> bytes:
    """Sort key giving UTF-16 code unit order, which is what RFC 8785 requires.

    Comparing UTF-16 big-endian byte sequences reproduces code unit ordering
    exactly. This is NOT the same as code point ordering: a supplementary-plane
    character encodes to a lead surrogate in 0xD800..0xDBFF, so it sorts BEFORE
    a BMP character in 0xE000..0xFFFF under this rule and after it under code
    point ordering. The corpus is ASCII today, where the two agree, so the
    distinction is pinned here rather than left to chance.
    """
    return key.encode("utf-16-be")


def canonicalize_jcs(value: Any) -> str:
    """Serialize to RFC 8785 canonical JSON.

    Object keys are sorted by UTF-16 code unit at serialization time, never by
    insertion order. String values are normalized to NFC. No whitespace.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(unicodedata.normalize("NFC", value), ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        return "{" + ",".join(
            json.dumps(unicodedata.normalize("NFC", k), ensure_ascii=False)
            + ":"
            + canonicalize_jcs(v)
            for k, v in items
        ) + "}"
    raise TypeError("cannot canonicalize %r" % type(value).__name__)


def act_binding_digest(preimage: Any) -> str:
    """Return sha256:<base64url> over the JCS canonical bytes of the preimage."""
    canonical = canonicalize_jcs(preimage)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return "sha256:" + b64u_encode(digest)


def load_issuer(name: str, runners_dir: Path) -> dict[str, Any]:
    """Load runners/issuers/<name>.json."""
    path = runners_dir / "issuers" / (name + ".json")
    if not path.is_file():
        raise SystemExit("issuer config not found: %s" % path)
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_jwks(url: str, timeout: int = 20) -> dict[str, Any]:
    """Fetch and index a JWKS by kid. Cached per process."""
    if url not in _JWKS_CACHE:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            document = json.load(response)
        _JWKS_CACHE[url] = {k["kid"]: k for k in document.get("keys", [])}
    return _JWKS_CACHE[url]


def resolve_keys(issuer: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    """Return the issuer's keys indexed by kid, from a URL or from the config.

    An issuer may carry `jwks_inline` instead of `jwks_url`. That exists so a
    synthetic fixture can be verified with no network at all: the regression
    oracle must not be able to fail because a third party's DNS is down.
    """
    inline = issuer.get("jwks_inline")
    if inline is not None:
        return {k["kid"]: k for k in inline.get("keys", [])}
    url = issuer.get("jwks_url")
    if not url:
        raise SystemExit("issuer config has neither jwks_url nor jwks_inline")
    return fetch_jwks(url, timeout=timeout)


def classify_window(
    verification_time: datetime.datetime,
    issued_at: datetime.datetime,
    expires_at: datetime.datetime,
) -> str:
    """Evaluate BOTH bounds and return a distinct outcome for each side.

    The lower bound is checked first and on its own. Reporting a single boolean
    here, or checking only the upper bound, hides a not-yet-valid token behind a
    passing expiry check.
    """
    if verification_time < issued_at:
        return WINDOW_NOT_YET_VALID
    if verification_time > expires_at:
        return WINDOW_EXPIRED
    return WINDOW_INSIDE


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58:
            raise ValueError("bad base58 character")
        n = n * 58 + _B58.index(ch)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + out


def did_key_wellformed(did: str) -> bool:
    """True when a did:key is a syntactically valid Ed25519 key.

    A single dropped character inside the multibase body still base58-decodes
    and still parses as JSON, but the multicodec prefix stops being 0xed01.
    That is exactly what happened to aat-2026-06-24-expired: one lost byte in
    al_nid, undetectable by every check except the signature, for six weeks.
    This is the cheap detector that localises it.
    """
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        return False
    try:
        raw = _b58_decode(did[len("did:key:z"):])
    except ValueError:
        return False
    return raw[:2] == b"\xed\x01" and len(raw) - 2 == 32


def token_fingerprint(token: str) -> dict[str, Any]:
    """Length plus SHA-256 of the compact token string, the convention agreed
    with the issuer on 2026-07-29 so a transport corruption is one line to spot."""
    return {
        "token_len": len(token),
        "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }


_QUARANTINE_CACHE: dict[str, Any] | None = None


def quarantine_entry(vector_id: str, runners_dir: Path | None = None):
    """Return the quarantine record for a vector id, or None.

    Quarantine marks a vector whose LOCAL COPY is unusable. The issuer's
    declared expected_result is never rewritten here.
    """
    global _QUARANTINE_CACHE
    if _QUARANTINE_CACHE is None:
        base = runners_dir or Path(__file__).resolve().parent
        path = base / "quarantine.json"
        if path.exists():
            _QUARANTINE_CACHE = json.loads(path.read_text(encoding="utf-8"))
        else:
            _QUARANTINE_CACHE = {"entries": []}
    for entry in _QUARANTINE_CACHE.get("entries", []):
        if entry.get("vector_id") == vector_id:
            return entry
    return None


def evaluate_vector(
    vector: dict[str, Any],
    keys: dict[str, Any],
    check_lower_bound: bool = True,
    convention_declared: bool = False,
) -> dict[str, Any]:
    """Evaluate one vector and return its record.

    check_lower_bound exists so the test suite can prove that a runner which
    only checks the upper bound fails to detect the AS-RECEIVED defect. It is
    True for every real run.
    """
    token = vector["aat"]
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(b64u_decode(header_b64))
    payload = json.loads(b64u_decode(payload_b64))
    signature = b64u_decode(signature_b64)

    record: dict[str, Any] = {
        "id": vector["id"],
        "kid": header.get("kid"),
        "alg": header.get("alg"),
        "jti": payload.get("jti"),
        "sub": payload.get("sub"),
        "al_name": payload.get("al_name"),
        "expected_result": vector["expected_result"],
    }

    # (a) signature against the JWKS, matched by kid
    key = keys.get(header.get("kid"))
    if key is None:
        record["signature"] = "NO_KEY_FOR_KID"
        signature_ok = False
    else:
        public_key = Ed25519PublicKey.from_public_bytes(b64u_decode(key["x"]))
        try:
            public_key.verify(signature, (header_b64 + "." + payload_b64).encode("ascii"))
            signature_ok = True
        except InvalidSignature:
            signature_ok = False
        record["signature"] = "VALID" if signature_ok else "INVALID"

    # integrity: fingerprint every token, then compare against the declared stamp.
    #
    # An earlier version only compared when a stamp was present, so a vector with
    # no stamp left fingerprint_match unset and the runner reported nothing. The
    # guard was weakest exactly where an unstamped drop would land. A fixture that
    # declares integrity_convention now FAILS any vector without a stamp, and a
    # pre-convention fixture names its unattributable vectors instead of passing
    # them quietly.
    fp = token_fingerprint(token)
    record.update(fp)
    declared_len = vector.get("token_len")
    declared_sha = vector.get("token_sha256")
    if declared_len is None and declared_sha is None:
        record["unattributable"] = True
        record["fingerprint_match"] = False if convention_declared else None
    else:
        record["unattributable"] = False
        record["fingerprint_match"] = (
            declared_len in (None, fp["token_len"])
            and declared_sha in (None, fp["token_sha256"])
        )

    # integrity: al_nid must be a well-formed Ed25519 did:key when present
    al_nid = payload.get("al_nid")
    record["al_nid_wellformed"] = did_key_wellformed(al_nid) if al_nid is not None else None

    # (b) both window bounds against THIS vector's own verification_time
    verification_time = parse_instant(vector["verification_time"])
    issued_at = datetime.datetime.fromtimestamp(payload["iat"], datetime.timezone.utc)
    expires_at = datetime.datetime.fromtimestamp(payload["exp"], datetime.timezone.utc)
    if check_lower_bound:
        window = classify_window(verification_time, issued_at, expires_at)
    else:
        window = WINDOW_EXPIRED if verification_time > expires_at else WINDOW_INSIDE
    record["verification_time"] = verification_time.isoformat()
    record["iat"] = issued_at.isoformat()
    record["exp"] = expires_at.isoformat()
    record["window"] = window
    record["seconds_before_iat"] = int((issued_at - verification_time).total_seconds())

    # (c) act-binding digest recompute, only when the claim is present
    claim = payload.get("urn:dashclaw:act-binding")
    if claim is None:
        record["act_binding"] = "ABSENT"
    else:
        # flat key is ours; AgentLair ships the preimage nested under act_binding (2026-08-26)
        preimage = vector.get("act_binding_preimage")
        if preimage is None and isinstance(vector.get("act_binding"), dict):
            preimage = vector["act_binding"].get("preimage")
        if preimage is None:
            # The claim is present but the fixture does not carry the preimage.
            # Recomputing would mean inventing input, so this is reported and
            # never scored.
            record["act_binding"] = "CLAIM_PRESENT_NO_PREIMAGE"
            record["act_binding_claimed"] = claim.get("hash")
        else:
            computed = act_binding_digest(preimage)
            claimed = claim.get("hash")
            record["act_binding"] = "MATCH" if computed == claimed else "MISMATCH"
            record["act_binding_computed"] = computed
            record["act_binding_claimed"] = claimed
            record["act_binding_canonical"] = canonicalize_jcs(preimage)

    # outcome, then (d) comparison against the declared expectation
    #
    # Precedence is SIGNATURE FIRST, then window. This follows the corpus's own
    # verifier_must text, which says to validate the signature against the
    # pinned JWKS and then check the window.
    #
    # An earlier reference implementation had this reversed. A window rejection
    # therefore masked an unverifiable signature on aat-2026-06-24-expired for
    # six weeks of weekly runs that all reported clean. A token whose signature
    # does not verify says nothing about its window, because the claims it
    # carries are not attributable to the issuer.
    if not signature_ok:
        outcome = SIG_REJECT
    elif window == WINDOW_NOT_YET_VALID:
        outcome = NBF_REJECT
    elif window == WINDOW_EXPIRED:
        outcome = EXP_REJECT
    else:
        outcome = VALID
    record["computed_result"] = outcome
    record["match"] = outcome == vector["expected_result"]
    if not record["match"]:
        record["failure_reason"] = outcome

    entry = quarantine_entry(record["id"])
    if entry is not None:
        record["quarantined"] = True
        record["quarantine_state"] = entry["state"]
        record["quarantine_reason"] = entry["reason"]
        record["quarantine_pending"] = entry["pending"]
    return record


def observe(vectors: list[dict[str, Any]]) -> dict[str, Any]:
    """Cross-vector observations. These are never failures."""
    subs: list[str] = []
    names: list[str] = []
    jtis: list[str] = []
    for vector in vectors:
        payload = json.loads(b64u_decode(vector["aat"].split(".")[1]))
        subs.append(payload.get("sub"))
        names.append(payload.get("al_name"))
        jtis.append(payload.get("jti"))
    repeated = sorted({j for j in jtis if jtis.count(j) > 1})
    return {
        "subjects": sorted(set(subs)),
        "single_subject": len(set(subs)) == 1,
        "al_names": sorted(set(n for n in names if n is not None)),
        "single_al_name": len(set(names)) == 1,
        "jti_total": len(jtis),
        "jti_distinct": len(set(jtis)),
        "jti_repeated": repeated,
        "note": "observations only; a repeated jti is intentional in some vectors "
                "and is neither deduplicated nor skipped",
    }


def run_fixture(
    fixture_path: Path, issuer_name: str, runners_dir: Path, check_lower_bound: bool = True
) -> dict[str, Any]:
    """Run one fixture and return the full machine-readable result."""
    raw = fixture_path.read_bytes()
    fixture = json.loads(raw.decode("utf-8"))
    if fixture.get("schema") != SCHEMA:
        raise SystemExit(
            "fixture schema is %r, expected %r" % (fixture.get("schema"), SCHEMA)
        )
    issuer = load_issuer(issuer_name, runners_dir)
    keys = resolve_keys(issuer)

    records = [
        evaluate_vector(
            v,
            keys,
            check_lower_bound=check_lower_bound,
            convention_declared=bool(fixture.get("integrity_convention")),
        )
        for v in fixture["vectors"]
    ]
    failures = [
        r
        for r in records
        if (not r["match"] or r.get("fingerprint_match") is False)
        and not r.get("quarantined")
    ]
    quarantined = [r for r in records if r.get("quarantined")]
    return {
        "run": {
            "runner": "aat_runner.py",
            "runner_version": RUNNER_VERSION,
            "executed_by": "%s@%s" % (getpass.getuser(), socket.gethostname()),
            "executed_at": datetime.datetime.now(datetime.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "fixture_path": str(fixture_path),
            "fixture_sha256": hashlib.sha256(raw).hexdigest(),
            "schema": fixture["schema"],
            "issuer_config": issuer_name,
            "key_source": issuer.get("jwks_url") or "inline (no network)",
            "pinned_kid": issuer["kid"],
            "kids_offered_by_jwks": sorted(keys.keys()),
            "lower_bound_checked": check_lower_bound,
            "scope": "records what was executed against these bytes by this operator; "
                     "not a conformance verdict about any implementation",
        },
        "vectors": records,
        "observations": observe(fixture["vectors"]),
        "summary": {
            "vector_count": len(records),
            "matched": len([r for r in records if r["match"]]),
            "failed": len(failures),
            "failing_ids": [r["id"] for r in failures],
            "quarantined": [
                {"id": r["id"], "state": r["quarantine_state"], "pending": r["quarantine_pending"]}
                for r in quarantined
            ],
            # Any vector whose signature did not verify. Under signature-first
            # precedence such a vector already scores sig_reject, so this list
            # is a second, independent place the anomaly stays visible.
            "integrity_convention_declared": bool(fixture.get("integrity_convention")),
            # Vectors carrying no length-and-digest stamp. Under a declared
            # convention these are failures; otherwise they are named, never
            # passed silently.
            "unattributable": [r["id"] for r in records if r.get("unattributable")],
            # Integrity, independent of signature and window. A malformed
            # al_nid or a fingerprint mismatch localises a transport corruption
            # to a field instead of leaving it as an opaque signature failure.
            "integrity_anomalies": [
                {
                    "id": r["id"],
                    "al_nid_wellformed": r.get("al_nid_wellformed"),
                    "fingerprint_match": r.get("fingerprint_match"),
                }
                for r in records
                if r.get("al_nid_wellformed") is False or r.get("fingerprint_match") is False
            ],
            "signature_anomalies": [
                {"id": r["id"], "signature": r["signature"]}
                for r in records
                if r["signature"] != "VALID"
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an aat-pair-v1 fixture.")
    parser.add_argument("fixture", type=Path, help="path to the fixture JSON")
    parser.add_argument("--issuer", default="agentlair", help="issuer config name")
    parser.add_argument(
        "--no-lower-bound",
        action="store_true",
        help="skip the not-yet-valid check; used only to prove the test suite catches it",
    )
    args = parser.parse_args(argv)

    runners_dir = Path(__file__).resolve().parent
    result = run_fixture(
        args.fixture, args.issuer, runners_dir, check_lower_bound=not args.no_lower_bound
    )
    print(json.dumps(result, indent=2, sort_keys=False))
    return 0 if result["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
