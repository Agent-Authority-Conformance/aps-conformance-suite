"""Clean-room verifier for the VAID A2A extension (docs/a2a/v1/extension.md).

Written from the prose specification only (extension.md, docs/spec/encoding.md,
docs/spec/scope.md, ADR-0003, ADR-0007, docs/spec/revocation.md R.4.4).
It imports nothing from the VAID repository. Ed25519 comes from `cryptography`,
JCS (RFC 8785) is implemented here for the value types VAID documents use.

Reason codes follow the vector README vocabulary where one exists
(not_attenuated, expired, revoked, out_of_scope, issuer_mismatch) and add
explicit codes for the other branches the spec names, so that a refusal always
says which check produced it.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQUIRED_FIELDS = {
    "sig_version", "vaid_id", "agent_id", "agent_class", "version", "tenant_id",
    "issued_at", "expires_at", "public_key_der", "kernel_signature", "parent_vaid",
    "scope_boundary", "lineage_hash", "capability_set", "trust_domain",
    "kernel_key_thumbprint",
}
THUMB_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
SEPARATORS = ("/", ".")
MAX_DEPTH = 64


class Refusal(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------- parsing (E.7a)
def _no_dupes(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise Refusal("unparseable", f"duplicate member {k!r}")
        seen.add(k)
    return dict(pairs)


def parse_strict(text: str):
    return json.loads(text, object_pairs_hook=_no_dupes)


# ---------------------------------------------------------------- JCS (RFC 8785)
def _jcs_str(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str):
    return k.encode("utf-16-be")


def jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # VAID signed structures carry only small non-negative integers (E.8).
        raise Refusal("unparseable", "non-integer number in signed structure")
    if isinstance(v, str):
        return _jcs_str(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_jcs_str(k) + ":" + jcs(x) for k, x in items) + "}"
    raise Refusal("unparseable", f"unsupported JSON type {type(v).__name__}")


# ---------------------------------------------------------------- keys (E.16)
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def thumbprint_uri(raw_pub: bytes) -> str:
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": b64u(raw_pub)}
    return THUMB_PREFIX + b64u(hashlib.sha256(jcs(jwk).encode()).digest())


@dataclass
class TrustedIssuer:
    trust_domain: str
    raw_key: bytes
    thumb: str


def load_trust(trust_config: dict) -> dict[str, TrustedIssuer]:
    out = {}
    for e in trust_config.get("trustedIssuers", []):
        raw = b64u_dec(e["kernelPublicKey"])
        if len(raw) != 32:
            raise ValueError("trusted kernelPublicKey is not 32 raw bytes")
        t = thumbprint_uri(raw)
        out[t] = TrustedIssuer(e["trustDomain"], raw, t)
    return out


# ---------------------------------------------------------------- grammar (E.15)
def trust_domain_ok(td) -> bool:
    if not isinstance(td, str) or not (1 <= len(td) <= 253):
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(c not in allowed for c in td):
        return False
    labels = td.split(".")
    if len(labels) < 2:
        return False
    for lab in labels:
        if not (1 <= len(lab) <= 63) or lab.startswith("-") or lab.endswith("-"):
            return False
    if all(c in "0123456789" for c in labels[-1]):
        return False
    return True


# ---------------------------------------------------------------- time
def parse_ts(s) -> datetime:
    if not isinstance(s, str):
        raise Refusal("unparseable", "timestamp is not a string")
    t = s.replace("Z", "+00:00").replace("z", "+00:00")
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        raise Refusal("unparseable", f"bad timestamp {s!r}")
    if d.tzinfo is None:
        raise Refusal("unparseable", f"timestamp without offset {s!r}")
    return d.astimezone(timezone.utc)


# ---------------------------------------------------------------- scope (S.3)
def entry_contains(p: str, r: str) -> bool:
    if p == "":
        return True
    if r == p:
        return True
    if any(p.endswith(s) for s in SEPARATORS) and r.startswith(p):
        return True
    return any(r.startswith(p + s) for s in SEPARATORS)


def boundary_contains(boundary: list, r: str) -> bool:
    if len(boundary) == 0:
        return True
    return any(entry_contains(p, r) for p in boundary)


def scope_attenuates(child: list, parent: list) -> bool:
    if len(parent) == 0:
        return True  # parent is unrestricted
    if len(child) == 0:
        return False  # unrestricted child under a restricted parent widens
    return all(boundary_contains(parent, c) for c in child)


def caps_attenuate(child: list, parent: list) -> bool:
    # Assumption A1: capability_set containment is plain set inclusion by exact
    # string equality. The prose spec does not state the rule (see AMBIGUITIES).
    return set(child) <= set(parent)


# ---------------------------------------------------------------- authenticity
def authenticate(doc: dict, trust: dict[str, TrustedIssuer]) -> None:
    """E.2, E.5, E.10, E.15, E.16 and the extension's sec. 2 trust rule."""
    if not isinstance(doc, dict):
        raise Refusal("unparseable", "document is not an object")
    missing = REQUIRED_FIELDS - doc.keys()
    if missing:
        raise Refusal("unparseable", f"missing members {sorted(missing)}")
    sv = doc["sig_version"]
    if type(sv) is not int:
        raise Refusal("unparseable", "sig_version is not a JSON number")
    if sv != 3:
        raise Refusal("unsupported_sig_version", str(sv))
    if not trust_domain_ok(doc["trust_domain"]):
        raise Refusal("malformed_trust_domain", repr(doc["trust_domain"]))
    ti = trust.get(doc["kernel_key_thumbprint"])
    if ti is None:
        raise Refusal("issuer_mismatch", "kernel_key_thumbprint names no trusted key")
    if ti.trust_domain != doc["trust_domain"]:
        raise Refusal("issuer_mismatch", "trust_domain differs from the trusted entry")
    if doc["vaid_id"] != doc["agent_id"]:
        raise Refusal("lineage_inconsistent", "vaid_id != agent_id")
    parent = doc["parent_vaid"]
    material = f"GENESIS:{doc['agent_id']}" if parent is None else f"{parent}:{doc['agent_id']}"
    if hashlib.sha256(material.encode()).hexdigest() != doc["lineage_hash"]:
        raise Refusal("lineage_inconsistent", "lineage_hash does not recompute")
    sig = doc["kernel_signature"]
    if not (isinstance(sig, list) and len(sig) == 64
            and all(type(b) is int and 0 <= b <= 255 for b in sig)):
        raise Refusal("inauthentic", "kernel_signature is not 64 byte values")
    unsigned = dict(doc)
    unsigned["kernel_signature"] = None
    digest = hashlib.sha256(jcs(unsigned).encode("utf-8")).digest()
    try:
        Ed25519PublicKey.from_public_bytes(ti.raw_key).verify(bytes(sig), digest)
    except InvalidSignature:
        raise Refusal("inauthentic", "Ed25519 signature does not verify")


# ---------------------------------------------------------------- revocation
NOT_REVOKED, REVOKED, UNAVAILABLE = "not_revoked", "revoked", "unavailable"
RevocationCheck = Callable[[list], str]  # lineage root..leaf of vaid_ids -> status


def set_revocation(revoked_ids, unavailable=False) -> RevocationCheck:
    revoked_ids = set(revoked_ids)

    def check(lineage):
        if unavailable:
            return UNAVAILABLE
        return REVOKED if any(v in revoked_ids for v in lineage) else NOT_REVOKED
    return check


# ---------------------------------------------------------------- procedure
@dataclass
class Policy:
    require_chain: bool = True
    # How to read sec. 5 step 3's leaf-only clause when chain is not required
    # and no /vaidChain is presented:
    #   "as_written": steps 1-2, step 6 on the leaf, then step 7 (skips step 5)
    #   "strict":     steps 1-2, step 5, step 6 on the leaf, then step 7
    leaf_only_mode: str = "as_written"


@dataclass
class Verdict:
    result: str
    code: Optional[str]
    step: Optional[str]
    detail: str = ""
    path: list = field(default_factory=list)


def verify(leaf, chain, requested_action, trust, revocation: RevocationCheck,
           now: datetime, policy: Policy = Policy()) -> Verdict:
    steps = []

    def refuse(step, r: Refusal):
        return Verdict("fail", r.code, step, r.detail, steps)

    # Step 1, leaf authenticity
    steps.append("1")
    try:
        authenticate(leaf, trust)
    except Refusal as r:
        return refuse("1", r)

    # Step 2, leaf expiry
    steps.append("2")
    try:
        if parse_ts(leaf["expires_at"]) <= now:
            return Verdict("fail", "expired", "2", "leaf", steps)
    except Refusal as r:
        return refuse("2", r)

    chain_present = chain is not None
    if chain_present or policy.require_chain:
        # Step 3, chain integrity back to a trusted root
        steps.append("3")
        bundle = {}
        for d in (chain or []):
            if not isinstance(d, dict) or "vaid_id" not in d:
                return Verdict("fail", "unparseable", "3", "chain member", steps)
            if d["vaid_id"] in bundle:
                return Verdict("fail", "unverifiable", "3", "duplicate vaid_id in bundle", steps)
            bundle[d["vaid_id"]] = d
        lineage = [leaf]
        seen = {leaf["vaid_id"]}
        cur = leaf
        while cur["parent_vaid"] is not None:
            p = bundle.get(cur["parent_vaid"])
            if p is None:
                return Verdict("fail", "unverifiable", "3", f"ancestor {cur['parent_vaid']} not presented", steps)
            if p["vaid_id"] in seen or len(lineage) > MAX_DEPTH:
                return Verdict("fail", "unverifiable", "3", "cycle or depth", steps)
            try:
                authenticate(p, trust)
            except Refusal as r:
                return refuse("3", r)
            try:
                if parse_ts(p["expires_at"]) <= now:
                    return Verdict("fail", "expired", "3", f"ancestor {p['vaid_id']}", steps)
            except Refusal as r:
                return refuse("3", r)
            seen.add(p["vaid_id"])
            lineage.append(p)
            cur = p
        lineage.reverse()  # root .. leaf

        # Step 4, attenuation at every hop
        steps.append("4")
        for parent, child in zip(lineage, lineage[1:]):
            if not scope_attenuates(child["scope_boundary"], parent["scope_boundary"]):
                return Verdict("fail", "not_attenuated", "4", f"scope at {child['vaid_id']}", steps)
            if not caps_attenuate(child["capability_set"], parent["capability_set"]):
                return Verdict("fail", "not_attenuated", "4", f"capabilities at {child['vaid_id']}", steps)
            if (child["tenant_id"], child["trust_domain"]) != (parent["tenant_id"], parent["trust_domain"]):
                return Verdict("fail", "not_attenuated", "4", f"tenant at {child['vaid_id']}", steps)
            if parse_ts(child["expires_at"]) > parse_ts(parent["expires_at"]):
                return Verdict("fail", "not_attenuated", "4", f"expiry at {child['vaid_id']}", steps)
        ids = [d["vaid_id"] for d in lineage]
        run_step5 = True
    else:
        ids = [leaf["vaid_id"]]
        run_step5 = policy.leaf_only_mode == "strict"

    # Step 5, requested action within the leaf's own scope
    if run_step5:
        steps.append("5")
        if not boundary_contains(leaf["scope_boundary"], requested_action):
            return Verdict("fail", "out_of_scope", "5", requested_action, steps)

    # Step 6, revocation over the assembled lineage, fail closed
    steps.append("6")
    status = revocation(ids)
    if status == REVOKED:
        return Verdict("fail", "revoked", "6", "", steps)
    if status != NOT_REVOKED:
        return Verdict("fail", "revocation_unavailable", "6", status, steps)

    steps.append("7")
    return Verdict("pass", None, None, "", steps)
