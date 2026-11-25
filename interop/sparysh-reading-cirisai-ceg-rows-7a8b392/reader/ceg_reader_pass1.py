"""A reading of draft-moore-scitt-ciris-ceg-03, written from its text alone.

Scope: the statement, payload, value and object levels of the lab candidate
cirisai-ceg-rows. The family level needs the family registry of the cited
Constitution, which the draft does not restate; it is read separately.

Every decision this reader takes where the draft leaves a choice is listed
in READINGS, and an answer that rests on one names it.

Primitives are third-party: ML-DSA-65 and Ed25519 from pyca/cryptography,
SHA-256 and SHA-512 from hashlib. CBOR decoding and deterministic
re-encoding are this reading's own (cbor_strict.py).
"""
import base64
import hashlib
import json
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

import cbor_strict as C

ALG = -70100
ROW_CTY = "application/vnd.ciris.row+cbor"
ROW_TYP = "ceg-row/2"
OBJECT_TYPS = ("ceg-genesis-bundle/2", "ceg-revocation-snapshot/2", "ceg-boot-manifest/2")
ROW_TYPES = ("scores", "delegates_to", "supersedes", "withdraws", "recants")
ROW_LABELS = {1, 3, 4, 15, 16, -70001, -70002}          # Table 1
OBJECT_LABELS = {1, 4, 15, 16}                          # Section 7.1
CWT_ROW = {1, 2, 6, 5, 4, -70003}                       # Appendix A cwt-claims
CWT_OBJECT = {1, 6, -70003}                             # Appendix A object-claims
FAMILY_RE = re.compile(r"[a-z0-9_.][a-z0-9_.-]*(:[a-z0-9_.][a-z0-9_.-]*)*")
IDREF_RE = re.compile(r"urn:ietf:params:oauth:ckt:sha-256:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")
IDREF_PREFIX = "urn:ietf:params:oauth:ckt:sha-256:"
LABEL = b"COMPSIG-MLDSA65-Ed25519-SHA512"
PREFIX = b"CompositeAlgorithmSignatures2025"
PERSON_ROLES = {"user", "accord_holder"}
MACHINE_ROLES = {"node", "agent"}
REFS_MEMBERS = ("head", "further_heads", "prev", "answers", "target", "trusted_through", "also")
REFS_SETS = ("further_heads", "trusted_through")
ALSO_ROLES = ("ack", "cites")

# Families the draft itself names. Registration of any other family is in
# [CC]; this reader cannot decide it and says so (R-REGISTRY).
FAMILIES_NAMED_IN_DRAFT = {
    "key:record", "identity:occurrence", "evidence:.suite:.kind:.cell:.prefix",
    "provenance:build_manifest:.target", "accord:.", "accord:lifecycle",
    "accord:invoke:constitutional", "accord:invoke:notify", "accord:invoke:drill",
}
# What the draft says about a family's author column and dimension.
# evidence:...: B.1 says the signer is the author and the row scores a dimension.
FAMILY_FACTS_FROM_DRAFT = {
    "evidence:.suite:.kind:.cell:.prefix": {"authored": True, "scores_dimension": True},
}

READINGS = {
    "R-DET-ORDER": "Step 1 checks determinism of the statement, then the protected header, then the payload, "
                   "in the order Table 3 lists them.",
    "R-MISSING-MEMBER": "A protected-header member that is missing is malformed:<member>; a member that should "
                        "not be there is unexpected:protected.",
    "R-ALG": "A wrong alg is malformed:alg. Table 3 lists cty, typ, row-type, family-id, edition and iss for "
             "malformed:<member> and does not name alg.",
    "R-ROWTYPE": "A row type that is a text string outside the five passes verification and is refused at "
                 "admission with attestation_type_unregistered (Section 3, Table 4); a non-text value is "
                 "malformed:row-type.",
    "R-REGISTRY": "Whether a family or a dimension is registered is in [CC], not in the draft. A family the "
                  "draft names is taken as registered; any other leaves the answer conditional.",
    "R-MIXED-FIRST": "key_record_mixed_roles is checked before key_record_out_of_window. Table 3 lists them "
                     "the other way, but a mixed set always breaks the end rule, so in that order the mixed "
                     "reason could never be given.",
    "R-MAXSECS": "key_record_max_secs is not in the draft; the upper bound of the end rule is not checked.",
    "R-VU-GENERAL": "valid_until_not_after_asserted_at applies to every row (Table 3, step 4), though the CDDL "
                    "comment states it for accord rows.",
    "R-RAW-WAIT": "A verifier holding bare keys only (directory raw) cannot show ways 2 to 4 of Section 6.2; "
                  "kid other than the thumbprint in iss is Waiting on the key record those ways need.",
    "R-KID-BY-SUB": "A held key record is found by the key its sub names; kid_mismatch is a record whose key "
                    "member does not have the thumbprint its sub names.",
    "R-ROTATION": "A rotation record names its predecessor's record in refs.prev and is carried by a "
                  "statement of the predecessor key over the same payload.",
    "R-STEP9-AUTHOR": "Where the draft does not say whether a family is authored, an author member present "
                      "is read as authored and iss must equal it; roles are not known.",
    "R-IDTYPE-SET": "identity_type is a set (Section 6.2); one out of order is malformed:identity_type, since "
                    "Table 3 names set_order only for sets in refs.",
}


def thumb(pub):
    return hashlib.sha256(C.encode({1: 7, 3: ALG, -1: pub})).digest()


def idref(tp):
    return IDREF_PREFIX + base64.urlsafe_b64encode(tp).rstrip(b"=").decode()


def idref_thumb(ref):
    s = ref[len(IDREF_PREFIX):]
    raw = base64.urlsafe_b64decode(s + "=")
    return raw


def key_from_seed(n):
    ml = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes([n]) * 32).public_key().public_bytes_raw()
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([n + 100]) * 32).public_key().public_bytes_raw()
    return ml + ed


def digest_obj(data):
    return hashlib.sha256(C.encode(data)).hexdigest()


class Answer(dict):
    @staticmethod
    def valid(**kw):
        a = Answer(answer="valid")
        a.update(kw)
        return a

    @staticmethod
    def invalid(reason, step, readings=()):
        return Answer(answer="invalid", reason=reason, step=step, readings=list(readings))

    @staticmethod
    def waiting(missing, step, readings=()):
        return Answer(answer="waiting", missing=missing, step=step, readings=list(readings))


class Refuse(Exception):
    def __init__(self, reason, step, readings=()):
        self.reason, self.step, self.readings = reason, step, list(readings)


class Wait(Exception):
    def __init__(self, missing, step, readings=()):
        self.missing, self.step, self.readings = missing, step, list(readings)


def is_text(x):
    return isinstance(x, str)


def is_bytes(x):
    return isinstance(x, (bytes, bytearray))


def is_uint(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def is_hash_digest(x):
    return isinstance(x, list) and len(x) == 2 and x[0] == -16 and is_int(x[0]) and is_bytes(x[1]) and len(x[1]) == 32


def is_row_ref(x):
    return isinstance(x, list) and len(x) == 2 and is_int(x[0]) and x[0] == 2 and is_hash_digest(x[1])


def set_ok(arr):
    enc = [C.encode(e) for e in arr]
    return all(enc[i] < enc[i + 1] for i in range(len(enc) - 1))


# ---------------------------------------------------------------- step 1
def decode_statement(raw):
    try:
        st = C.decode(raw)
    except C.DecodeError:
        raise Refuse("not_cose_sign1", 1)
    if not isinstance(st, C.Tag) or st.tag != 18:
        raise Refuse("not_cose_sign1", 1)
    arr = st.value
    if not isinstance(arr, list) or len(arr) != 4:
        raise Refuse("not_cose_sign1", 1)
    prot_b, unprot, payload_b, sig = arr
    if not is_bytes(prot_b) or not isinstance(unprot, C.CMap) or not is_bytes(payload_b) or not is_bytes(sig):
        raise Refuse("not_cose_sign1", 1)
    # determinism: statement, protected, payload (R-DET-ORDER)
    ok, _ = C.is_deterministic(raw)
    if not ok:
        raise Refuse("not_deterministic:statement", 1, ["R-DET-ORDER"])
    okp, prot = C.is_deterministic(bytes(prot_b))
    if not okp:
        raise Refuse("not_deterministic:protected", 1, ["R-DET-ORDER"])
    okl, payload = C.is_deterministic(bytes(payload_b))
    if not okl:
        raise Refuse("not_deterministic:payload", 1, ["R-DET-ORDER"])
    return bytes(prot_b), prot, unprot, bytes(payload_b), payload, bytes(sig)


# ---------------------------------------------------------------- step 2
def check_header(prot, unprot):
    """Returns (kind, hdr) where kind is 'row' or 'object'."""
    readings = []
    if not isinstance(prot, C.CMap):
        raise Refuse("unexpected:protected", 2)
    labels = []
    for k in prot.keys():
        if not is_int(k):
            raise Refuse("unexpected:protected", 2)
        labels.append(k)
    typ = prot.get(16)
    if typ == ROW_TYP:
        kind, allowed = "row", ROW_LABELS
    elif is_text(typ) and typ in OBJECT_TYPS:
        kind, allowed = "object", OBJECT_LABELS
    else:
        kind, allowed = None, ROW_LABELS | OBJECT_LABELS
    if any(l not in allowed for l in labels):
        raise Refuse("unexpected:protected", 2)
    for k in unprot.keys():
        if not is_int(k):
            raise Refuse("unexpected:unprotected", 2)
    # members, in the order of Section 6.4 step 2
    if not is_text(typ) or kind is None:
        raise Refuse("malformed:typ", 2)
    if prot.get(1) != ALG or not is_int(prot.get(1)):
        raise Refuse("malformed:alg", 2, ["R-ALG"])
    claims = prot.get(15)
    if not isinstance(claims, C.CMap):
        raise Refuse("malformed:cwt_claims", 2, ["R-MISSING-MEMBER"])
    if claims.get(-70003) != 2 or not is_int(claims.get(-70003)):
        raise Refuse("malformed:edition", 2)
    if kind == "row":
        cty = prot.get(3)
        if not is_text(cty) or cty != ROW_CTY:
            raise Refuse("malformed:cty", 2)
        rt = prot.get(-70001)
        if not is_text(rt):
            raise Refuse("malformed:row-type", 2, ["R-MISSING-MEMBER", "R-ROWTYPE"])
        fam = prot.get(-70002)
        if not is_text(fam) or not FAMILY_RE.fullmatch(fam):
            raise Refuse("malformed:family-id", 2, ["R-MISSING-MEMBER"])
    iss = claims.get(1)
    if not is_text(iss) or not IDREF_RE.fullmatch(iss):
        raise Refuse("malformed:iss", 2)
    allowed_claims = CWT_ROW if kind == "row" else CWT_OBJECT
    for k in claims.keys():
        if not is_int(k) or k not in allowed_claims:
            raise Refuse("unexpected:cwt_claims", 2, ["R-MISSING-MEMBER"])
    if kind == "row":
        if not is_text(claims.get(2)):
            raise Refuse("malformed:sub", 2, ["R-MISSING-MEMBER"])
        if not is_uint(claims.get(6)):
            raise Refuse("malformed:iat", 2, ["R-MISSING-MEMBER"])
    for lab, name in ((5, "nbf"), (4, "exp"), (6, "iat")):
        if claims.has(lab) and not is_uint(claims.get(lab)):
            raise Refuse(f"malformed:{name}", 2)
    kid = prot.get(4)
    if not is_bytes(kid) or len(kid) != 32:
        raise Refuse("malformed:kid", 2, ["R-MISSING-MEMBER"])
    if kind == "row":
        fam = prot.get(-70002)
        if fam not in FAMILIES_NAMED_IN_DRAFT:
            readings.append("R-REGISTRY")
    return kind, claims, readings


# ---------------------------------------------------------------- step 3
FORBIDDEN = (C.Float, C.Simple)


def scan_value(v, in_body, member):
    """No float, null, undefined, tag or simple value, except simple(59) as a
    map key, tag 60 for an array element and tag 4 inside body."""
    if v is None or v is C.UNDEFINED or isinstance(v, C.Float):
        raise Refuse(f"malformed:{member}", 3)
    if isinstance(v, C.Simple):
        raise Refuse(f"malformed:{member}", 3)
    if isinstance(v, C.Tag):
        if v.tag == 60 and is_bytes(v.value) and len(v.value) == 32:
            return
        if v.tag == 4 and in_body:
            check_decimal(v)
            return
        raise Refuse(f"malformed:{member}", 3)
    if isinstance(v, list):
        for x in v:
            scan_value(x, in_body, member)
    elif isinstance(v, C.CMap):
        for k, x in v.pairs:
            if isinstance(k, C.Simple) and k.value == 59:
                if not isinstance(x, list) or not x or not all(is_bytes(d) and len(d) == 32 for d in x):
                    raise Refuse(f"malformed:{member}", 3)
                continue
            if not (is_text(k) or is_int(k)):
                raise Refuse(f"malformed:{member}", 3)
            scan_value(x, in_body, member)


def check_decimal(t):
    v = t.value
    if not (isinstance(v, list) and len(v) == 2 and is_int(v[0]) and is_int(v[1])):
        raise Refuse("body_number_unrepresentable", 3)
    e, m = v
    if e >= 0 or m % 10 == 0:
        raise Refuse("body_number_unrepresentable", 3)


def dimension_resolves(dimension, family):
    ds, fs = dimension.split(":"), family.split(":")
    if len(ds) <= len(fs):
        return False
    for d, f in zip(ds, fs):
        if f == ".":
            if not d:
                return False
        elif f.startswith("."):
            if not d:
                return False
        elif d != f:
            return False
    return True


def check_payload(payload, family, kind, unprot, disclosed):
    readings = []
    if not isinstance(payload, C.CMap):
        raise Refuse("malformed:payload", 3)
    # null and forbidden values, member by member in payload order
    for k, v in payload.pairs:
        if isinstance(k, C.Simple) and k.value == 59:
            name = "redacted_claim_keys"
        elif is_text(k):
            name = str(k)
        else:
            raise Refuse("malformed:payload", 3)
        scan_value(v, name == "body", name)
    if kind == "object":
        return readings
    if not is_uint(payload.get("asserted_at")):
        raise Refuse("malformed:asserted_at", 3)
    if payload.has("author") and (not is_text(payload.get("author")) or not IDREF_RE.fullmatch(payload.get("author"))):
        raise Refuse("malformed:author", 3)
    for name in ("valid_from", "valid_until", "expires_at", "reason"):
        if payload.has(name) and not is_uint(payload.get(name)):
            raise Refuse(f"malformed:{name}", 3)
    if payload.has("score"):
        s = payload.get("score")
        if not is_int(s) or not (-10**6 <= s <= 10**6):
            raise Refuse("malformed:score", 3)
    if payload.has("confidence"):
        s = payload.get("confidence")
        if not is_int(s) or not (0 <= s <= 10**6):
            raise Refuse("malformed:confidence", 3)
    if payload.has("weight"):
        s = payload.get("weight")
        if not is_int(s) or not (-2**63 <= s < 2**63):
            raise Refuse("malformed:weight", 3)
    if payload.has("salt"):
        s = payload.get("salt")
        if not is_bytes(s) or len(s) != 16:
            raise Refuse("malformed:salt", 3)
    if payload.has("evidence_refs"):
        e = payload.get("evidence_refs")
        if not isinstance(e, list) or not e or not all(is_hash_digest(x) for x in e):
            raise Refuse("malformed:evidence_refs", 3)
    if payload.has("dimension") and not is_text(payload.get("dimension")):
        raise Refuse("malformed:dimension", 3)
    if payload.has("body"):
        b = payload.get("body")
        if not isinstance(b, C.CMap):
            raise Refuse("malformed:body", 3)
        note = b.get("note")
        if b.has("note") and (not is_text(note) or len(note.encode()) > 2048):
            raise Refuse("malformed:body", 3)
    if payload.has("refs"):
        check_refs(payload.get("refs"))
    # selective disclosure
    digests = []
    for x in C.walk(payload):
        if isinstance(x, C.CMap):
            for k, v in x.pairs:
                if isinstance(k, C.Simple) and k.value == 59:
                    digests.extend(bytes(d) for d in v)
        if isinstance(x, C.Tag) and x.tag == 60:
            digests.append(bytes(x.value))
    if disclosed is not None:
        for d in disclosed:
            if digests.count(d) != 1:
                raise Refuse("disclosure_unmatched", 3)
    if len(set(digests)) != len(digests):
        raise Refuse("duplicate_digest", 3)
    if payload.has("dimension"):
        dim = payload.get("dimension")
        if family not in FAMILIES_NAMED_IN_DRAFT:
            readings.append("R-REGISTRY")
        if not dimension_resolves(dim, family):
            raise Refuse("dimension_family", 3, ["R-REGISTRY"])
    return readings


def check_refs(refs):
    if not isinstance(refs, C.CMap) or not refs.pairs:
        raise Refuse("malformed:refs", 3)
    for k, v in refs.pairs:
        if not is_text(k):
            raise Refuse("malformed:refs", 3)
        if k not in REFS_MEMBERS:
            raise Refuse("unexpected:refs", 3)
    for k, v in refs.pairs:
        if k in ("head", "prev", "answers", "target"):
            if not is_row_ref(v):
                raise Refuse("malformed:refs", 3)
        elif k in REFS_SETS:
            if not isinstance(v, list) or not v or not all(is_row_ref(x) for x in v):
                raise Refuse("malformed:refs", 3)
        elif k == "also":
            if not isinstance(v, C.CMap) or not v.pairs:
                raise Refuse("malformed:refs", 3)
            for role, s in v.pairs:
                if not is_text(role):
                    raise Refuse("malformed:refs", 3)
                if role not in ALSO_ROLES:
                    raise Refuse("unexpected:also", 3)
                if not isinstance(s, list) or not s or not all(is_row_ref(x) for x in s):
                    raise Refuse("malformed:refs", 3)
    for k, v in refs.pairs:
        if k in REFS_SETS and not set_ok(v):
            raise Refuse(f"set_order:{k}", 3)
        if k == "also":
            for role, s in v.pairs:
                if not set_ok(s):
                    raise Refuse(f"set_order:{role}", 3)


# ---------------------------------------------------------------- step 4
def check_times(claims, payload):
    at = payload.get("asserted_at")
    if claims.get(6) != at // 1000:
        raise Refuse("time:iat", 4)
    for lab, name, member in ((5, "nbf", "valid_from"), (4, "exp", "valid_until")):
        has_c, has_p = claims.has(lab), payload.has(member)
        if has_c != has_p or (has_c and claims.get(lab) != payload.get(member) // 1000):
            raise Refuse(f"time:{name}", 4)
    if payload.has("valid_until") and not payload.get("valid_until") > at:
        raise Refuse("valid_until_not_after_asserted_at", 4, ["R-VU-GENERAL"])


# ---------------------------------------------------------------- step 5
def check_key_record_payload(payload):
    """The static checks of a key:record payload (Section 6.2)."""
    readings = []
    key = payload.get("key")
    if not isinstance(key, C.CMap):
        raise Refuse("malformed:key", 5)
    for k in key.keys():
        if not is_int(k) or k not in (1, 3, -1):
            raise Refuse("unexpected:key", 5)
    if key.get(1) != 7 or key.get(3) != ALG or not is_bytes(key.get(-1)) or len(key.get(-1)) != 1984:
        raise Refuse("malformed:key", 5)
    it = payload.get("identity_type")
    if not isinstance(it, list) or not it or not all(is_text(x) for x in it):
        raise Refuse("malformed:identity_type", 5)
    if not set_ok(it):
        raise Refuse("malformed:identity_type", 5, ["R-IDTYPE-SET"])
    roles = set(it)
    person, machine = bool(roles & PERSON_ROLES), bool(roles & MACHINE_ROLES)
    if person and machine:
        raise Refuse("key_record_mixed_roles", 5, ["R-MIXED-FIRST"])
    at = payload.get("asserted_at")
    vu = payload.get("valid_until")
    if not is_uint(at):
        raise Refuse("malformed:asserted_at", 5)
    if person and payload.has("valid_until"):
        raise Refuse("key_record_out_of_window", 5)
    if machine and not payload.has("valid_until"):
        raise Refuse("key_record_out_of_window", 5)
    if payload.has("valid_until") and vu < at:
        raise Refuse("key_record_out_of_window", 5)
    readings.append("R-MAXSECS")
    return bytes(key.get(-1)), readings


# ---------------------------------------------------------------- step 7
def sig_ok(pub, prot_b, payload_b, sig):
    if len(sig) != 3373 or len(pub) != 1984:
        return False
    m = C.encode(["Signature1", prot_b, b"", payload_b])
    mp = PREFIX + LABEL + b"\x00" + hashlib.sha512(m).digest()
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pub[:1952]).verify(sig[:3309], mp, LABEL)
        ed25519.Ed25519PublicKey.from_public_bytes(pub[1952:]).verify(sig[3309:], mp)
    except (InvalidSignature, ValueError):
        return False
    return True


# ---------------------------------------------------------------- the verifier
class Verifier:
    def __init__(self, held_pubs=(), records=(), directory=None, disclosed=None, depth=0, own_key=None):
        self.own_key = own_key
        self.bare = {thumb(p): p for p in held_pubs}
        self.records_raw = list(records)
        self.directory = directory
        self.disclosed = disclosed
        self.depth = depth
        self._records = None

    # held key records, each parsed once
    def records(self):
        if self._records is None:
            out = []
            for raw in self.records_raw:
                info = {"raw": raw}
                try:
                    p_b, prot, unprot, pl_b, pl, sig = decode_statement(raw)
                    info.update(prot_b=p_b, prot=prot, payload_b=pl_b, payload=pl, sig=sig)
                    claims = prot.get(15)
                    info["iss"] = claims.get(1) if isinstance(claims, C.CMap) else None
                    info["sub"] = claims.get(2) if isinstance(claims, C.CMap) else None
                    info["kid"] = bytes(prot.get(4)) if is_bytes(prot.get(4)) else None
                    info["family"] = prot.get(-70002)
                    info["row_id"] = row_id(prot, pl, pl_b)
                except Refuse:
                    info["broken"] = True
                out.append(info)
            self._records = out
        return self._records

    def record_for_key(self, kid):
        """A held key:record whose sub names kid (R-KID-BY-SUB)."""
        for r in self.records():
            if r.get("broken") or r.get("family") != "key:record":
                continue
            sub = r.get("sub")
            if is_text(sub) and IDREF_RE.fullmatch(sub) and idref_thumb(sub) == kid:
                return r
        return None

    def verify_record(self, r, pub):
        # the record's own key is the key it records: a record signed by that key
        # resolves its kid to the payload key, not to itself again
        sub = Verifier(held_pubs=list(self.bare.values()), records=self.records_raw,
                       directory=self.directory, depth=self.depth + 1, own_key=(thumb(pub), pub))
        return sub.verify(r["raw"])

    def resolve_key(self, kid):
        """Step 6. Returns the composite public key, or raises."""
        if self.own_key is not None and kid == self.own_key[0]:
            return self.own_key[1], []
        if self.directory != "records" and kid in self.bare:
            return self.bare[kid], []
        if self.directory in ("records", None) or self.records_raw:
            r = self.record_for_key(kid)
            if r is not None:
                key = r["payload"].get("key") if isinstance(r["payload"], C.CMap) else None
                pub = bytes(key.get(-1)) if isinstance(key, C.CMap) and is_bytes(key.get(-1)) else None
                if pub is None or thumb(pub) != kid:
                    raise Refuse("kid_mismatch", 6, ["R-KID-BY-SUB"])
                if self.depth < 8:
                    a = self.verify_record(r, pub)
                    if a["answer"] == "invalid":
                        raise Refuse("key_not_valid", 6)
                    if a["answer"] == "waiting":
                        raise Wait(a["missing"], 6)
                return pub, ["R-KID-BY-SUB"]
        if kid in self.bare:
            return self.bare[kid], []
        raise Wait("kid:" + kid.hex(), 6)

    def key_of_iss(self, kid, iss):
        """Step 8, Section 6.2."""
        target = idref_thumb(iss)
        if kid == target:
            return []                                   # way 1
        if self.directory == "raw" or not self.records_raw:
            raise Wait("key-record-of:" + kid.hex() + "@" + iss, 8, ["R-RAW-WAIT"])
        r = self.record_for_key(kid)
        if r is None:
            raise Wait("key-record-of:" + kid.hex() + "@" + iss, 8)
        if r.get("iss") != iss:
            raise Refuse("kid_not_of_iss", 8)
        # walk rotation records back to the genesis key's record (R-ROTATION)
        seen = set()
        cur = r
        while True:
            ckey_thumb = idref_thumb(cur["sub"])
            if ckey_thumb == target:
                return ["R-ROTATION"]
            if cur["row_id"] in seen:
                raise Refuse("kid_not_of_iss", 8, ["R-ROTATION"])
            seen.add(cur["row_id"])
            refs = cur["payload"].get("refs") if isinstance(cur["payload"], C.CMap) else None
            prev = refs.get("prev") if isinstance(refs, C.CMap) else None
            if not is_row_ref(prev):
                raise Refuse("kid_not_of_iss", 8, ["R-ROTATION"])
            prev_id = bytes(prev[1][1])
            pred = next((x for x in self.records() if not x.get("broken") and x.get("row_id") == prev_id
                         and x.get("family") == "key:record" and x.get("payload_b") != cur["payload_b"]), None)
            if pred is None:
                raise Wait("row:" + prev_id.hex(), 8, ["R-ROTATION"])
            if pred.get("iss") != iss:
                raise Refuse("kid_not_of_iss", 8, ["R-ROTATION"])
            pred_kid = idref_thumb(pred["sub"])
            carried = [x for x in self.records() if not x.get("broken") and x.get("payload_b") == cur["payload_b"]
                       and x.get("kid") == pred_kid]
            if not carried:
                raise Wait("statement-of:" + pred_kid.hex() + "-over:" + cur["row_id"].hex(), 8, ["R-ROTATION"])
            pkey = pred["payload"].get("key")
            ppub = bytes(pkey.get(-1))
            c = carried[0]
            if not sig_ok(ppub, c["prot_b"], c["payload_b"], c["sig"]):
                raise Refuse("kid_not_of_iss", 8, ["R-ROTATION"])
            cur = pred

    def verify(self, raw):
        readings = []
        try:
            prot_b, prot, unprot, payload_b, payload, sig = decode_statement(raw)
            kind, claims, rd = check_header(prot, unprot)
            readings += rd
            family = prot.get(-70002) if kind == "row" else None
            readings += check_payload(payload, family, kind, unprot, self.disclosed)
            if kind == "row":
                check_times(claims, payload)
                if family == "key:record":
                    _, rd = check_key_record_payload(payload)
                    readings += rd
            kid = bytes(prot.get(4))
            pub, rd = self.resolve_key(kid)
            readings += rd
            if not sig_ok(pub, prot_b, payload_b, sig):
                raise Refuse("bad_signature", 7)
            iss = claims.get(1)
            readings += self.key_of_iss(kid, iss)
            if kind == "row":
                readings += self.step9(prot, claims, payload)
        except Refuse as r:
            return Answer.invalid(r.reason, r.step, sorted(set(readings + r.readings)))
        except Wait as w:
            return Answer.waiting(w.missing, w.step, sorted(set(readings + w.readings)))
        out = Answer.valid(kid=kid.hex(), iss=claims.get(1),
                           statement_id=statement_id(prot_b, payload_b),
                           readings=sorted(set(readings)))
        if kind == "row":
            out["row_id"] = row_id(prot, payload, payload_b).hex()
            adm = self.admission(prot, payload, payload_b)
            if adm:
                out["admission"] = adm
        else:
            out["object_id"] = object_id(prot.get(16), payload, payload_b)
        return out

    def step9(self, prot, claims, payload):
        fam = prot.get(-70002)
        facts = FAMILY_FACTS_FROM_DRAFT.get(fam)
        iss = claims.get(1)
        if facts is not None:
            if facts["authored"] and not payload.has("author"):
                raise Refuse("author_column", 9)
            if not facts["authored"] and payload.has("author"):
                raise Refuse("author_column", 9)
            if payload.has("author") and payload.get("author") != iss:
                raise Refuse("iss_not_in_role", 9)
            if facts["scores_dimension"] and not payload.has("dimension"):
                raise Refuse("dimension_missing", 9)
            return []
        if payload.has("author") and payload.get("author") != iss:
            raise Refuse("iss_not_in_role", 9, ["R-STEP9-AUTHOR"])
        return ["R-STEP9-AUTHOR"]

    def admission(self, prot, payload, payload_b):
        if len(payload_b) > 1048576:
            return "envelope_too_large"
        if prot.get(-70001) not in ROW_TYPES:
            return "attestation_type_unregistered"
        return None


def row_id(prot, payload, payload_b):
    claims = prot.get(15)
    author = payload.get("author") if isinstance(payload, C.CMap) and payload.has("author") else None
    arr = ["CEG-row/2", str(prot.get(-70001)), str(prot.get(-70002)), str(claims.get(2)),
           str(author) if author is not None else None, payload_b]
    return hashlib.sha256(C.encode(arr)).digest()


def statement_id(prot_b, payload_b):
    return hashlib.sha256(C.encode(["CEG-statement-id/2", prot_b, payload_b])).hexdigest()


def object_id(typ, payload, payload_b):
    author = payload.get("author") if isinstance(payload, C.CMap) and payload.has("author") else None
    return hashlib.sha256(C.encode(["CEG-object/2", str(typ), str(author) if author is not None else None,
                                    payload_b])).hexdigest()


# ---------------------------------------------------------------- the levels
def read_payload_case(c):
    """Level payload: a key record's payload against its end rule."""
    raw = bytes.fromhex(c["payload_hex"])
    ok, payload = C.is_deterministic(raw)
    if not ok:
        return Answer.invalid("not_deterministic:payload", 1)
    try:
        check_payload(payload, "key:record", "row", C.CMap([]), None)
        _, rd = check_key_record_payload(payload)
    except Refuse as r:
        return Answer.invalid(r.reason, r.step, r.readings)
    return Answer.valid(meets_end_rule=True, readings=rd)


def read_value_case(c):
    """Level value: the form of a reference and its digest."""
    raw = bytes.fromhex(c["cbor_hex"])
    ok, v = C.is_deterministic(raw)
    if not ok:
        return Answer(answer="invalid", form=None, reason="not_deterministic")
    if is_row_ref(v):
        return Answer(answer="valid", form="row-ref", digest=bytes(v[1][1]).hex())
    if is_hash_digest(v):
        return Answer(answer="valid", form="hash-digest", digest=bytes(v[1]).hex())
    if is_text(v) and IDREF_RE.fullmatch(v):
        out = Answer(answer="valid", form="identity-ref", digest=idref_thumb(v).hex())
        if "identity_ref" in c:
            out["matches_given_identity_ref"] = (str(v) == c["identity_ref"])
        return out
    # name what it is not
    if isinstance(v, list) and len(v) == 2 and v[0] == 2:
        return Answer(answer="invalid", form="row-ref?", reason="malformed:digest")
    if isinstance(v, list) and len(v) == 2:
        why = "alg" if v[0] != -16 else "length"
        return Answer(answer="invalid", form="hash-digest?", reason=f"malformed:{why}")
    if is_text(v) and str(v).startswith("urn:ietf:params:oauth:ckt:"):
        return Answer(answer="invalid", form="identity-ref?", reason="malformed:identity-ref")
    return Answer(answer="invalid", form=None, reason="malformed:not-a-reference")


def read_statement_case(c, keys_by_kid):
    held = [key_from_seed(n) for n in c.get("held_key_seeds", [])]
    records = [bytes.fromhex(h) for h in c.get("records_hex", [])]
    disclosed = [bytes.fromhex(h) for h in c["disclosed_digests_hex"]] if "disclosed_digests_hex" in c else None
    v = Verifier(held_pubs=held, records=records, directory=c.get("directory"), disclosed=disclosed)
    return v.verify(bytes.fromhex(c["statement_hex"]))


def main(cases_path, keys_path, out_path):
    cases = json.load(open(cases_path))
    keys = json.load(open(keys_path))["by_kid"]
    # the published keys must be the ones the seeds give
    seed_kids = {thumb(key_from_seed(n)).hex(): n for n in range(0, 16)}
    key_check = {kid: (kid in seed_kids and key_from_seed(seed_kids[kid]).hex() == pub and thumb(bytes.fromhex(pub)).hex() == kid)
                 for kid, pub in keys.items()}
    out = {"keys_match_seeds": key_check, "readings": READINGS, "answers": {}}
    for c in cases:
        lvl = c["level"]
        if lvl in ("statement", "object"):
            a = read_statement_case(c, keys)
        elif lvl == "payload":
            a = read_payload_case(c)
        elif lvl == "value":
            a = read_value_case(c)
        else:
            continue
        a["level"] = lvl
        out["answers"][c["id"]] = a
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main(*sys.argv[1:4])
