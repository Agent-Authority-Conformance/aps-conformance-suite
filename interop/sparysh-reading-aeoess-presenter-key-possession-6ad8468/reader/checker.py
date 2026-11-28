#!/usr/bin/env python3
"""Phase-1 checker for the aeoess-presenter-key-possession cases.

Written from the text of RFC 9449 (sections 4.2, 4.3, 6.1, 7.1, 11.1), RFC 7638,
RFC 8037, and the parts of RFC 7515, 7519, 3986 and 4648 that those sections
refer to. No JOSE, JWT or DPoP library is used; `cryptography` is used only for
Ed25519 signature verification.

Usage:
  python3 -I reader/checker.py <cases.json> <rfc-dir> <out-dir>

Writes <out-dir>/phase1.json and <out-dir>/phase1-sensitivity.json.
The output is deterministic: no timestamps, sorted keys.
"""
import base64
import hashlib
import itertools
import json
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# Citations. Each is checked verbatim (after whitespace normalisation) against
# the supplied RFC text at start-up; the checker stops if one is not found.
# ---------------------------------------------------------------------------
CITES = {
    # RFC 9449
    "9449-4.2-header": ("rfc9449", "The JOSE Header of a DPoP JWT MUST contain at least the following parameters:"),
    "9449-4.2-typ": ("rfc9449", "A field with the value dpop+jwt, which explicitly types the DPoP proof JWT as recommended in Section 3.11 of [RFC8725]."),
    "9449-4.2-alg": ("rfc9449", "It MUST NOT be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC))."),
    "9449-4.2-jwk": ("rfc9449", "It MUST NOT contain a private key."),
    "9449-4.2-claims": ("rfc9449", "The payload of a DPoP proof MUST contain at least the following claims:"),
    "9449-4.2-htm": ("rfc9449", "The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached."),
    "9449-4.2-htu": ("rfc9449", "The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts."),
    "9449-4.2-ath-req": ("rfc9449", "When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access (see Section 7), the DPoP proof MUST also contain the following claim:"),
    "9449-4.2-ath": ("rfc9449", "The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value."),
    "9449-4.2-nonce-req": ("rfc9449", "When the authentication server or resource server provides a DPoP- Nonce HTTP header in a response (see Sections 8 and 9), the DPoP proof MUST also contain the following claim:"),
    "9449-4.3-intro": ("rfc9449", "To validate a DPoP proof, the receiving server MUST ensure the following:"),
    "9449-4.3-1": ("rfc9449", "There is not more than one DPoP HTTP request header field."),
    "9449-4.3-2": ("rfc9449", "The DPoP HTTP request header field value is a single and well- formed JWT."),
    "9449-4.3-3": ("rfc9449", "All required claims per Section 4.2 are contained in the JWT."),
    "9449-4.3-4": ("rfc9449", "The typ JOSE Header Parameter has the value dpop+jwt."),
    "9449-4.3-5": ("rfc9449", "The alg JOSE Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is supported by the application, and is acceptable per local policy."),
    "9449-4.3-6": ("rfc9449", "The JWT signature verifies with the public key contained in the jwk JOSE Header Parameter."),
    "9449-4.3-7": ("rfc9449", "The jwk JOSE Header Parameter does not contain a private key."),
    "9449-4.3-8": ("rfc9449", "The htm claim matches the HTTP method of the current request."),
    "9449-4.3-9": ("rfc9449", "The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts."),
    "9449-4.3-10": ("rfc9449", "If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value."),
    "9449-4.3-11": ("rfc9449", "The creation time of the JWT, as determined by either the iat claim or a server managed timestamp via the nonce claim, is within an acceptable window (see Section 11.1)."),
    "9449-4.3-12a": ("rfc9449", "ensure that the value of the ath claim equals the hash of that access token, and"),
    "9449-4.3-12b": ("rfc9449", "confirm that the public key to which the access token is bound matches the public key from the DPoP proof."),
    "9449-4.3-norm": ("rfc9449", "servers SHOULD employ syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme- based normalization (Section 6.2.3 of [RFC3986]) before comparing the htu claim."),
    "9449-4.3-order": ("rfc9449", "These checks may be performed in any order."),
    "9449-6.1-jkt": ("rfc9449", "The value of the jkt member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK format) to which the access token is bound."),
    "9449-7.1-check": ("rfc9449", "For such an access token, a resource server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP request, check the DPoP proof according to the rules in Section 4.3, and check that the public key of the DPoP proof matches the public key to which the access token is bound per Section 6."),
    "9449-7.1-grant": ("rfc9449", "The resource server MUST NOT grant access to the resource unless all checks are successful."),
    "9449-11.1-limit": ("rfc9449", "To limit this, servers MUST only accept DPoP proofs for a limited time after their creation (preferably only for a relatively brief period on the order of seconds or minutes)."),
    "9449-11.1-store": ("rfc9449", "In the context of the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof."),
    "9449-11.1-declined": ("rfc9449", "HTTP requests to the same URI for which the jti value has been seen before would be declined."),
    "9449-11.1-future": ("rfc9449", "Note: To accommodate for clock offsets, the server MAY accept DPoP proofs that carry an iat time in the reasonably near future (on the order of seconds or minutes)."),
    # RFC 7638
    "7638-3-1": ("rfc7638", "Construct a JSON object [RFC7159] containing only the required members of a JWK representing the key and with no whitespace or line breaks before or after any syntactic elements and with the required members ordered lexicographically by the Unicode [UNICODE] code points of the member names."),
    "7638-3-2": ("rfc7638", "Hash the octets of the UTF-8 representation of this JSON object with a cryptographic hash function H."),
    "7638-3.3-esc": ("rfc7638", "Characters in member names and member values MUST be represented without being escaped."),
    # RFC 8037
    "8037-2-tp": ("rfc8037", 'When calculating JWK Thumbprints [RFC7638], the three public key fields are included in the hash input in lexicographic order: "crv", "kty", and "x".'),
    "8037-2-d": ("rfc8037", 'The parameter "d" MUST be present for private keys and contain the private key encoded using the base64url encoding.'),
    "8037-3.1-variant": ("rfc8037", 'The EdDSA variant used is determined by the subtype of the key (Ed25519 for "Ed25519" and Ed448 for "Ed448").'),
    "8037-3.1.2": ("rfc8037", "Verification is performed by applying the verification algorithm defined in [RFC8032] to the public key (as public key), the JWS Signing Input (as message), and the JWS Signature (as signature)."),
    # RFC 7515
    "7515-2-b64url": ("rfc7515", "Base64 encoding using the URL- and filename-safe character set defined in Section 5 of RFC 4648 [RFC4648], with all trailing '=' characters omitted (as permitted by Section 3.2) and without the inclusion of any line breaks, whitespace, or other additional characters."),
    "7515-5.2-1": ("rfc7515", "the JWS Protected Header, the JWS Payload, and the JWS Signature are represented as base64url-encoded values in that order, with each value being separated from the next by a single period ('.') character, resulting in exactly two delimiting period characters being used."),
    "7515-5.2-3": ("rfc7515", "Verify that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object conforming to RFC 7159 [RFC7159]; let the JWS Protected Header be this JSON object."),
    "7515-5.2-4": ("rfc7515", "During this step, verify that the resulting JOSE Header does not contain duplicate Header Parameter names."),
    "7515-5.2-8": ("rfc7515", "Validate the JWS Signature against the JWS Signing Input ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)) in the manner defined for the algorithm being used"),
    # RFC 7519
    "7519-4-dup": ("rfc7519", "The Claim Names within a JWT Claims Set MUST be unique; JWT parsers MUST either reject JWTs with duplicate Claim Names or use a JSON parser that returns only the lexically last duplicate member name"),
    "7519-4.1.6": ("rfc7519", "Its value MUST be a number containing a NumericDate value."),
    "7519-7.2-10": ("rfc7519", "Verify that the resulting octet sequence is a UTF-8-encoded representation of a completely valid JSON object conforming to RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object."),
    # RFC 3986
    "3986-6.2.2.1": ("rfc3986", "the scheme and host are case-insensitive and therefore should be normalized to lowercase."),
    "3986-6.2.2.1-hex": ("rfc3986", 'the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are case-insensitive and therefore should be normalized to use uppercase letters for the digits A-F.'),
    "3986-6.2.2.2": ("rfc3986", "These URIs should be normalized by decoding any percent-encoded octet that corresponds to an unreserved character, as described in Section 2.3."),
    "3986-6.2.2.3": ("rfc3986", "URI normalizers should remove dot-segments by applying the remove_dot_segments algorithm to the path, as described in Section 5.2.4."),
    "3986-6.2.3-path": ("rfc3986", 'In general, a URI that uses the generic syntax for authority with an empty path should be normalized to a path of "/".'),
    "3986-6.2.3-port": ("rfc3986", 'Likewise, an explicit ":port", for which the port is empty or the default for the scheme, is equivalent to one where the port and its ":" delimiter are elided and thus should be removed by scheme-based normalization.'),
}

PAGE_FOOTER = re.compile(r"^\S.*\[Page \d+\]\s*$")
PAGE_HEADER = re.compile(r"^RFC \d{4} .* \d{4}\s*$")


def norm_ws(s):
    return " ".join(s.split())


def load_rfc_text(path):
    raw = open(path, encoding="utf-8-sig").read().replace("\f", "\n")
    lines = [ln for ln in raw.split("\n") if not (PAGE_FOOTER.match(ln) or PAGE_HEADER.match(ln))]
    return norm_ws("\n".join(lines))


def verify_citations(rfc_dir):
    texts, missing = {}, []
    for cid, (doc, sentence) in sorted(CITES.items()):
        if doc not in texts:
            texts[doc] = load_rfc_text(os.path.join(rfc_dir, doc + ".txt"))
        if norm_ws(sentence) not in texts[doc]:
            missing.append(cid)
    if missing:
        sys.stderr.write("citation(s) not found verbatim in the supplied text: %s\n" % ", ".join(missing))
        sys.exit(4)
    return len(CITES)


# ---------------------------------------------------------------------------
# Encoding helpers (RFC 7515 section 2, RFC 4648 section 5)
# ---------------------------------------------------------------------------
B64URL_ALPHABET = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_decode(s):
    """Strict base64url: URL-safe alphabet, no '=' padding, no whitespace."""
    if not isinstance(s, str) or not B64URL_ALPHABET.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def json_object_no_dups(octets):
    def hook(pairs):
        names = [k for k, _ in pairs]
        if len(names) != len(set(names)):
            raise ValueError("duplicate member name")
        return dict(pairs)
    obj = json.loads(octets.decode("utf-8"), object_pairs_hook=hook)
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    return obj


# ---------------------------------------------------------------------------
# URI comparison for htu (RFC 9449 4.3 item 9 and the normalisation SHOULD)
# ---------------------------------------------------------------------------
UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
DEFAULT_PORTS = {"http": "80", "https": "443"}


def remove_dot_segments(path):
    inp, out = path, ""
    while inp:
        if inp.startswith("../"):
            inp = inp[3:]
        elif inp.startswith("./"):
            inp = inp[2:]
        elif inp.startswith("/./"):
            inp = "/" + inp[3:]
        elif inp == "/.":
            inp = "/"
        elif inp.startswith("/../"):
            inp = "/" + inp[4:]
            out = out[: out.rfind("/")] if "/" in out else ""
        elif inp == "/..":
            inp = "/"
            out = out[: out.rfind("/")] if "/" in out else ""
        elif inp in (".", ".."):
            inp = ""
        else:
            start = 1 if inp.startswith("/") else 0
            nxt = inp.find("/", start)
            seg = inp if nxt == -1 else inp[:nxt]
            out += seg
            inp = "" if nxt == -1 else inp[nxt:]
    return out


def pct_normalise(s):
    def fix(m):
        ch = chr(int(m.group(1), 16))
        return ch if ch in UNRESERVED else "%" + m.group(1).upper()
    return re.sub(r"%([0-9A-Fa-f]{2})", fix, s)


def normalise_uri_without_query(uri):
    """Drop query and fragment, then RFC 3986 6.2.2 and 6.2.3 normalisation."""
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):(?://([^/?#]*))?([^?#]*)(?:\?[^#]*)?(?:#.*)?$", uri)
    if not m:
        return None
    scheme, authority, path = m.group(1).lower(), m.group(2), m.group(3)
    if authority is not None:
        userinfo, _, hostport = authority.rpartition("@")
        host, port = hostport, None
        hp = re.match(r"^(\[[^\]]*\]|[^:]*)(?::(\d*))?$", hostport)
        if hp:
            host, port = hp.group(1), hp.group(2)
        host = pct_normalise(host).lower()
        if port == "" or port == DEFAULT_PORTS.get(scheme):
            port = None
        authority = (userinfo + "@" if userinfo else "") + host + (":" + port if port else "")
        if path == "":
            path = "/"
    path = remove_dot_segments(pct_normalise(path))
    return scheme + ":" + ("//" + authority if authority is not None else "") + path


# ---------------------------------------------------------------------------
# Facts: every RFC 9449 4.3 / 6.1 condition the input lets us evaluate
# ---------------------------------------------------------------------------
# Registered asymmetric JWS signature algorithms. The IANA JOSE registry is not
# among the supplied texts; this list is a fixed value (see Limits).
REGISTERED_ASYMMETRIC = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
                         "PS256", "PS384", "PS512", "EdDSA", "ES256K"}
# Algorithms this checker can verify ("supported by the application").
SUPPORTED_BY_CHECKER = {"EdDSA"}
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


def thumbprint_okp(jwk):
    """RFC 7638 section 3 with the OKP required members of RFC 8037 section 2."""
    members = {}
    for name in ("crv", "kty", "x"):
        v = jwk.get(name) if isinstance(jwk, dict) else None
        if not isinstance(v, str):
            return None, "required member %s missing or not a string" % name
        if any(c in v for c in '"\\') or any(ord(c) < 0x20 for c in v):
            return None, "member %s would need escaping (thumbprint undefined)" % name
        members[name] = v
    canon = "{" + ",".join('"%s":"%s"' % (k, members[k]) for k in sorted(members)) + "}"
    return b64url_encode(hashlib.sha256(canon.encode("utf-8")).digest()), canon


def compute_facts(inp):
    req, pol = inp["request"], inp["policy"]
    claims_tok = inp.get("token_claims") or {}
    f = {}

    def put(rule, value, cite, **detail):
        f[rule] = {"holds": value, "cite": cite, **detail}

    dpop = inp.get("dpop")
    # Item 1: not more than one DPoP header field. The input carries one string
    # per header field; a list stands for several fields.
    n_fields = len(dpop) if isinstance(dpop, list) else (1 if dpop is not None else 0)
    put("R01_single_header", n_fields == 1, ["9449-4.3-1"], header_fields=n_fields)
    value = dpop[0] if isinstance(dpop, list) and dpop else dpop

    header = payload = sig = None
    sinput = None
    wf_reason = None
    if not isinstance(value, str):
        wf_reason = "no DPoP value"
    else:
        parts = value.split(".")
        if len(parts) != 3:
            wf_reason = "%d dot-separated parts, compact JWS needs exactly 3" % len(parts)
        try:
            header = json_object_no_dups(b64url_decode(parts[0]))
        except Exception as e:  # noqa: BLE001
            wf_reason = wf_reason or "header: %s" % e
        if len(parts) >= 2:
            try:
                payload = json_object_no_dups(b64url_decode(parts[1]))
            except Exception as e:  # noqa: BLE001
                wf_reason = wf_reason or "payload: %s" % e
        if len(parts) == 3:
            try:
                sig = b64url_decode(parts[2])
            except Exception as e:  # noqa: BLE001
                wf_reason = wf_reason or "signature: %s" % e
            sinput = (parts[0] + "." + parts[1]).encode("ascii")
    put("R02_well_formed_jwt", wf_reason is None,
        ["9449-4.3-2", "7515-5.2-1", "7515-5.2-3", "7515-5.2-4", "7519-7.2-10", "7519-4-dup", "7515-2-b64url"],
        reason=wf_reason, header=header, payload=payload)

    header = header or {}
    payload = payload or {}
    jwk = header.get("jwk") if isinstance(header.get("jwk"), dict) else None

    # Item 3 split by claim group (see ambiguity log A1).
    missing_base = [c for c in ("jti", "htm", "htu", "iat") if c not in payload]
    bad_iat = "iat" in payload and (isinstance(payload["iat"], bool) or not isinstance(payload["iat"], (int, float)))
    put("R03a_claims_jti_htm_htu_iat", not missing_base and not bad_iat,
        ["9449-4.3-3", "9449-4.2-claims", "7519-4.1.6"], missing=missing_base, iat_not_number=bad_iat)
    put("R03b_claim_ath", "ath" in payload, ["9449-4.3-3", "9449-4.2-ath-req"],
        note="the case presents an access token to a protected resource")
    nonce_provided = req.get("server_nonce") is not None
    put("R03c_claim_nonce", (not nonce_provided) or ("nonce" in payload),
        ["9449-4.3-3", "9449-4.2-nonce-req"], server_nonce_provided=nonce_provided)

    put("R04_typ", header.get("typ") == "dpop+jwt", ["9449-4.3-4", "9449-4.2-typ"], typ=header.get("typ"))

    alg = header.get("alg")
    alg_parts = {
        "registered_asymmetric": alg in REGISTERED_ASYMMETRIC,
        "not_none": alg != "none",
        "supported_by_application": alg in SUPPORTED_BY_CHECKER,
        "acceptable_per_policy": alg in (pol.get("accepted_algs") or []),
    }
    put("R05_alg", all(alg_parts.values()), ["9449-4.3-5", "9449-4.2-alg"], alg=alg, parts=alg_parts)

    sig_ok, sig_reason = False, None
    if sinput is None or sig is None:
        sig_reason = "no signature to verify"
    elif jwk is None:
        sig_reason = "no jwk"
    elif alg != "EdDSA":
        sig_reason = "alg %r: no EdDSA verification applies" % (alg,)
    elif jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        sig_reason = "jwk is not an OKP Ed25519 key"
    else:
        try:
            pub = Ed25519PublicKey.from_public_bytes(b64url_decode(jwk.get("x", "")))
            pub.verify(sig, sinput)
            sig_ok = True
        except InvalidSignature:
            sig_reason = "Ed25519 verification failed"
        except Exception as e:  # noqa: BLE001
            sig_reason = "key error: %s" % e
    put("R06_signature", sig_ok, ["9449-4.3-6", "7515-5.2-8", "8037-3.1.2", "8037-3.1-variant"],
        reason=sig_reason, signing_input_sha256=hashlib.sha256(sinput).hexdigest() if sinput else None)

    priv = [m for m in PRIVATE_JWK_MEMBERS if jwk is not None and m in jwk]
    put("R07_no_private_key", jwk is not None and not priv, ["9449-4.3-7", "9449-4.2-jwk", "8037-2-d"],
        private_members=priv, jwk_present=jwk is not None)

    put("R08_htm", payload.get("htm") == req.get("method"), ["9449-4.3-8", "9449-4.2-htm"],
        htm=payload.get("htm"), method=req.get("method"))

    htu, uri = payload.get("htu"), req.get("uri")
    n_htu = normalise_uri_without_query(htu) if isinstance(htu, str) else None
    n_uri = normalise_uri_without_query(uri) if isinstance(uri, str) else None
    put("R09_htu", n_htu is not None and n_htu == n_uri,
        ["9449-4.3-9", "9449-4.2-htu", "9449-4.3-norm", "3986-6.2.2.1", "3986-6.2.2.1-hex", "3986-6.2.2.2",
         "3986-6.2.2.3", "3986-6.2.3-path", "3986-6.2.3-port"],
        htu=htu, uri=uri, htu_normalised=n_htu, uri_normalised=n_uri)

    put("R10_nonce", (not nonce_provided) or payload.get("nonce") == req.get("server_nonce"),
        ["9449-4.3-10"], server_nonce=req.get("server_nonce"), nonce=payload.get("nonce"))

    now = req.get("now")
    iat = payload.get("iat") if not bad_iat else None
    diff = (now - iat) if (isinstance(iat, (int, float)) and isinstance(now, (int, float))) else None
    window = pol.get("iat_window_s")
    past_ok = diff is not None and window is not None and diff <= window
    put("R11_iat_not_too_old", past_ok if diff is None or diff >= 0 else True,
        ["9449-4.3-11", "9449-11.1-limit"], now=now, iat=iat, now_minus_iat=diff, iat_window_s=window)
    skew = pol.get("future_skew_s")
    if diff is None or diff >= 0:
        fut_primary = fut_alt = diff is not None
    else:
        ahead = -diff
        fut_primary = skew is not None and ahead <= skew          # null = no allowance
        fut_alt = True if skew is None else ahead <= skew         # null = policy silent
    put("R11f_iat_future", fut_primary, ["9449-4.3-11", "9449-11.1-future"],
        iat_ahead_of_now=(-diff if diff is not None and diff < 0 else 0), future_skew_s=skew,
        holds_if_null_skew_is_silent=fut_alt)

    tracks = bool(pol.get("tracks_jti"))
    seen = [tuple(x) for x in (req.get("seen_jti") or [])]
    replay = False
    if tracks and "jti" in payload and n_uri is not None:
        replay = any(normalise_uri_without_query(u) == n_uri and j == payload["jti"] for u, j in seen)
    put("R13_jti_not_replayed", not replay, ["9449-11.1-store", "9449-11.1-declined"],
        tracks_jti=tracks, jti=payload.get("jti"), seen_jti=[list(s) for s in seen], replay=replay)

    at = inp.get("access_token")
    ath_calc = b64url_encode(hashlib.sha256(at.encode("ascii")).digest()) if isinstance(at, str) else None
    put("R12a_ath_matches", "ath" in payload and payload.get("ath") == ath_calc, ["9449-4.3-12a", "9449-4.2-ath"],
        ath_computed=ath_calc, ath_in_proof=payload.get("ath"))

    tp, canon = thumbprint_okp(jwk) if jwk is not None else (None, "no jwk")
    cnf = claims_tok.get("cnf") if isinstance(claims_tok.get("cnf"), dict) else None
    jkt = cnf.get("jkt") if cnf else None
    put("R12b_key_bound_matches", tp is not None and jkt is not None and tp == jkt,
        ["9449-4.3-12b", "9449-6.1-jkt", "9449-7.1-check", "7638-3-1", "7638-3-2", "7638-3.3-esc", "8037-2-tp"],
        thumbprint_computed=tp, thumbprint_input=canon, cnf_jkt=jkt, token_bound=jkt is not None)

    scope = claims_tok.get("scope")
    have = scope.split(" ") if isinstance(scope, str) else []
    put("RS_scope_contains_required", req.get("required_scope") in have, ["candidate-representation"],
        token_scope=scope, required_scope=req.get("required_scope"))
    return f


# ---------------------------------------------------------------------------
# Readings and the mapping of outcome fields to conditions
# ---------------------------------------------------------------------------
# Choice points that can change a verdict. "A" is the reading this run takes as
# primary; "B" the alternative. See ambiguity-log.md.
CHOICES = {
    "C1_item3_axis": ("A: a missing required claim is charged only to the axis whose later check uses it",
                      "B: a missing required claim is also charged to proof_signature (the proof as a JWT is incomplete)"),
    "C2_future_iat_null_skew": ("A: future_skew_s null means no allowance for an iat ahead of now",
                                "B: future_skew_s null means the policy is silent; an iat ahead of now is not a failure (RFC 9449 11.1 MAY)"),
    "C3_jti_replay": ("A: with tracks_jti, a seen (URI, jti) is a failed check (RFC 9449 11.1 'would be declined')",
                      "B: RFC 9449 11.1 says servers 'can' store jti; no MUST; a replay is not a failed check"),
    "C5_freshness_axis": ("A: nonce, iat window and jti replay (items 10, 11, 11.1) are reported by request_binding",
                          "B: nonce, iat window and jti replay are reported by proof_signature"),
}
AXES = ("proof_signature", "key_binding", "request_binding", "authority")


def rule_value(facts, rule, reading, override):
    if rule in override:
        return override[rule](facts[rule]["holds"])
    if rule == "R11f_iat_future" and reading["C2_future_iat_null_skew"] == "B":
        return facts[rule]["holds_if_null_skew_is_silent"]
    if rule == "R13_jti_not_replayed" and reading["C3_jti_replay"] == "B":
        return True
    return facts[rule]["holds"]


def axis_rules(reading):
    ps = ["R01_single_header", "R02_well_formed_jwt", "R04_typ", "R05_alg", "R06_signature", "R07_no_private_key"]
    kb = ["R03b_claim_ath", "R12a_ath_matches", "R12b_key_bound_matches"]
    rb = ["R03a_claims_jti_htm_htu_iat", "R08_htm", "R09_htu"]
    fresh = ["R03c_claim_nonce", "R10_nonce", "R11_iat_not_too_old", "R11f_iat_future", "R13_jti_not_replayed"]
    if reading["C5_freshness_axis"] == "A":
        rb = rb + fresh
    else:
        ps = ps + fresh
    if reading["C1_item3_axis"] == "B":
        ps = ps + [r for r in ("R03a_claims_jti_htm_htu_iat", "R03b_claim_ath", "R03c_claim_nonce") if r not in ps]
    return {"proof_signature": ps, "key_binding": kb, "request_binding": rb, "authority": ["RS_scope_contains_required"]}


RFC_RULES = ["R01_single_header", "R02_well_formed_jwt", "R03a_claims_jti_htm_htu_iat", "R03b_claim_ath",
             "R03c_claim_nonce", "R04_typ", "R05_alg", "R06_signature", "R07_no_private_key", "R08_htm", "R09_htu",
             "R10_nonce", "R11_iat_not_too_old", "R11f_iat_future", "R12a_ath_matches", "R12b_key_bound_matches",
             "R13_jti_not_replayed"]
ALL_RULES = RFC_RULES + ["RS_scope_contains_required"]


def evaluate(facts, outcome, reading, override):
    rv = {r: rule_value(facts, r, reading, override) for r in ALL_RULES}
    mapping = axis_rules(reading)
    axis_fact = {a: all(rv[r] for r in mapping[a]) for a in AXES}
    parts = {}
    for a in AXES:
        failing = [r for r in mapping[a] if not rv[r]]
        parts[a] = {"reported": outcome.get(a), "fact": axis_fact[a], "holds": outcome.get(a) == axis_fact[a],
                    "failing_conditions": failing,
                    "rests_on": "candidate representation (scope check)" if a == "authority"
                    else "mapping chosen in this run (axis -> RFC 9449 4.3 items)"}
    rfc_all = all(rv[r] for r in RFC_RULES)
    dec = outcome.get("decision")
    if dec == "accept":
        ok = rfc_all and rv["RS_scope_contains_required"]
        parts["decision"] = {"reported": dec, "holds": ok,
                             "rfc_checks_all_successful": rfc_all,
                             "scope_check": rv["RS_scope_contains_required"],
                             "failing_rfc_conditions": [r for r in RFC_RULES if not rv[r]],
                             "rests_on": "9449-7.1-grant (RFC checks); candidate representation (scope)"}
    elif dec == "reject":
        parts["decision"] = {"reported": dec, "holds": True, "rfc_checks_all_successful": rfc_all,
                             "rests_on": "RFC 9449 does not require granting access; a rejection is not contrary to the text"}
    else:
        parts["decision"] = {"reported": dec, "holds": False, "rests_on": "decision is neither accept nor reject"}
    ra = outcome.get("reject_axis")
    if dec == "accept":
        parts["reject_axis"] = {"reported": ra, "holds": ra is None, "rests_on": "mapping: an accept names no axis"}
    else:
        ok = ra in AXES and not axis_fact[ra] and outcome.get(ra) is False
        parts["reject_axis"] = {"reported": ra, "holds": ok,
                                "named_axis_fact": axis_fact.get(ra) if ra in AXES else None,
                                "failing_axes": [a for a in AXES if not axis_fact[a]],
                                "rests_on": "9449-4.3-order (any failing check may be the one reported); mapping chosen in this run"}
    verdict = "conformant" if all(p["holds"] for p in parts.values()) else "nonconformant"
    return verdict, parts


def readings_all():
    keys = sorted(CHOICES)
    for combo in itertools.product("AB", repeat=len(keys)):
        yield dict(zip(keys, combo))


PRIMARY = {k: "A" for k in CHOICES}


def judge(facts, outcome, override=None):
    override = override or {}
    primary_verdict, primary_parts = evaluate(facts, outcome, PRIMARY, override)
    by_reading = {}
    for rd in readings_all():
        v, _ = evaluate(facts, outcome, rd, override)
        by_reading["".join(rd[k] for k in sorted(rd))] = v
    verdicts = sorted(set(by_reading.values()))
    if len(verdicts) == 1:
        return verdicts[0], primary_verdict, primary_parts, None
    deciding = []
    for k in sorted(CHOICES):
        alt = dict(PRIMARY, **{k: "B"})
        v, p = evaluate(facts, outcome, alt, override)
        if v != primary_verdict:
            changed = sorted(n for n in p if p[n]["holds"] != primary_parts[n]["holds"])
            deciding.append({"choice": k, "reading_A": CHOICES[k][0], "verdict_A": primary_verdict,
                             "reading_B": CHOICES[k][1], "verdict_B": v, "parts_that_change": changed})
    amb = {"verdicts_over_all_readings": verdicts, "single_choices_that_flip_the_primary_verdict": deciding,
           "readings_order": sorted(CHOICES), "verdict_by_reading": by_reading}
    return "ambiguous", primary_verdict, primary_parts, amb


# ---------------------------------------------------------------------------
# Sensitivity: each rule removed (always holds) and inverted (negated)
# ---------------------------------------------------------------------------
def sensitivity(cases, facts_by_id, base):
    out = {}
    for rule in ALL_RULES:
        row = {}
        for variant, fn in (("removed", lambda v: True), ("inverted", lambda v: not v)):
            changed = []
            for c in cases:
                v, _, _, _ = judge(facts_by_id[c["id"]], c["outcome"], {rule: fn})
                if v != base[c["id"]]:
                    changed.append({"case": c["id"], "from": base[c["id"]], "to": v})
            row[variant] = changed
        row["no_case_depends_on_removal"] = not row["removed"]
        out[rule] = row
    # Readings fixed one way: each choice forced to A everywhere, then to B.
    for k in sorted(CHOICES):
        for side in "AB":
            changed = []
            for c in cases:
                rd = dict(PRIMARY, **{k: side})
                v, _ = evaluate(facts_by_id[c["id"]], c["outcome"], rd, {})
                if v != base[c["id"]]:
                    changed.append({"case": c["id"], "from": base[c["id"]], "to": v})
            out["reading %s fixed to %s" % (k, side)] = {"changed": changed}
    return out


def self_test():
    """RFC 8037 Appendix A.3 (thumbprint) and A.4/A.5 (Ed25519 JWS) examples."""
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    tp, _ = thumbprint_okp(jwk)
    jws = ("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
           "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
    h, p, s = jws.split(".")
    Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"])).verify(b64url_decode(s), (h + "." + p).encode("ascii"))
    checks = {"8037-A.3-thumbprint": tp == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
              "8037-A.5-verify": True,
              "3986-6.2.3-example": normalise_uri_without_query("http://example.com:80") == "http://example.com/",
              "3986-6.2.2-example": normalise_uri_without_query("eXAMPLE://a/./b/../b/%63/%7bfoo%7d")
              == normalise_uri_without_query("example://a/b/c/%7Bfoo%7D")}
    if not all(checks.values()):
        sys.stderr.write("self-test failed: %r\n" % checks)
        sys.exit(5)
    return checks


def main():
    cases_path, rfc_dir, out_dir = sys.argv[1:4]
    n_cites = verify_citations(rfc_dir)
    tests = self_test()
    data = json.load(open(cases_path, encoding="utf-8"))
    cases = data["cases"]
    results, facts_by_id, base = [], {}, {}
    for c in cases:
        facts = compute_facts(c["input"])
        facts_by_id[c["id"]] = facts
        verdict, primary, parts, amb = judge(facts, c["outcome"])
        base[c["id"]] = verdict
        results.append({"id": c["id"], "verdict": verdict, "verdict_under_primary_reading": primary,
                        "outcome": c["outcome"], "parts_under_primary_reading": parts,
                        "ambiguity": amb})
    tally = {}
    for r in results:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    doc = {"label": data.get("label"), "revision": data.get("revision"),
           "citations_verified_at_start_up": n_cites,
           "self_tests_from_rfc_examples": tests,
           "choices": {k: {"A": v[0], "B": v[1]} for k, v in CHOICES.items()},
           "primary_reading": PRIMARY,
           "axis_mapping_under_primary_reading": axis_rules(PRIMARY),
           "tally": tally,
           "facts": {cid: facts_by_id[cid] for cid in sorted(facts_by_id)},
           "results": results}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "phase1.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    with open(os.path.join(out_dir, "phase1-sensitivity.json"), "w", encoding="utf-8") as fh:
        json.dump(sensitivity(cases, facts_by_id, base), fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("citations verified: %d" % n_cites)
    print("self-tests: %s" % json.dumps(tests, sort_keys=True))
    print("tally: %s" % json.dumps(tally, sort_keys=True))
    for r in results:
        print("%s %s (primary reading: %s)" % (r["id"], r["verdict"], r["verdict_under_primary_reading"]))


if __name__ == "__main__":
    main()
