#!/usr/bin/env python3
"""Independent Python parity implementation for the accountability-record family.

Run as:  python3 fixtures/accountability-record/validate.py
Requires: jsonschema  (pip install jsonschema); Ed25519 signature checks also use
`cryptography` if present, otherwise they are deferred to verify.ts.

WHAT THIS IS, AND WHAT RUNS IT. This script is NOT the gate. The authoritative
hermetic gate is `npm test`, which runs the Node schema layer (ajv, pinned) and
computes the per-vector verdict in runners/ts/layered-gate.ts. This script is a
second, independent implementation of the same checks, in a different language
with a different JSON Schema library, run by the `schema-parity` job in
.github/workflows/tests.yml. It is not run by `npm test` -- adding a pip install
to the default command would make the gate non-hermetic and break the Windows
job -- and it is not a required check in this session.

Its value is disagreement: if ajv and Python jsonschema reach different verdicts
on the same vectors and the same schema, one of them is wrong, and the parity
job is what surfaces that.

The layer declaration is read from fixtures/manifest.json, the same single place
the Node gate reads, so the two implementations cannot be asserting different
things about the same family.

Checks, printed verbatim:
  0. Read the family's layer declaration from fixtures/manifest.json and confirm
     the schema file's bytes match the digest the manifest pins.
  1. Meta-validate the schema (Draft 2020-12).
  2. Validate every vector record against the schema, and apply the same verdict
     rules the Node gate applies: positives MUST be schema-valid; a vector whose
     rejection_kind the schema layer owns MUST be rejected, with an error whose
     instance path and keyword match the manifest's error_binding for its
     expected_error_code; for crypto/digest negatives the schema result is
     reported and not decisive.
  3. Cross-language JCS byte-parity: a Python canonicalizer reproduces
     signing_input_canonical and canonical byte-for-byte (proves the TS
     generator and an independent Python impl agree on RFC 8785 bytes).
  4. Detached-payload digest binding: for inline-action vectors, recompute
     sha256(JCS(action)) and compare to action_digest.sha256. The tampered
     negative MUST mismatch; positives MUST match.
  5. Ed25519 (if `cryptography` present): positives verify, wrong-key negative
     fails, against ed25519_pubkey_hex.
Exit 0 only if every required check passes.
"""
import json
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.dirname(HERE)
MANIFEST_PATH = os.path.join(FIXTURES_DIR, "manifest.json")
FIXTURE_PATH = os.path.join(HERE, "accountability-record-fixture-v1.json")
CATEGORY = "accountability-record"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

from jsonschema import Draft202012Validator


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def instance_path(err) -> str:
    """RFC 6901 pointer for a jsonschema error, matching ajv's instancePath."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in err.absolute_path)


def jcs(value) -> str:
    """RFC 8785 JCS for the ASCII/string/bool/null/array/object data used here.
    Byte-identical to agent-passport-system canonicalizeJCS for this domain:
    keys sorted, null preserved, no insignificant whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main() -> int:
    fx = json.load(open(FIXTURE_PATH))
    vectors = fx["vectors"]
    failures = 0

    print("== 0. layer declaration (fixtures/manifest.json) ==")
    manifest = json.load(open(MANIFEST_PATH))
    entry = next((e for e in manifest["fixtures"] if e.get("category") == CATEGORY), None)
    if entry is None:
        print(f"  FAIL no manifest entry for category {CATEGORY}")
        return 1
    required_layers = entry.get("required_layers")
    layers = entry.get("layers") or {}
    if not required_layers:
        print("  FAIL manifest entry declares no required_layers; the layers that decide this family are unstated")
        return 1
    decl = layers.get("schema")
    if not decl or not decl.get("schema_path"):
        print("  FAIL manifest declares no schema layer with a schema_path")
        return 1
    owned = set(decl.get("owns_rejection_kinds") or [])
    bindings = decl.get("error_bindings") or {}
    schema_path = os.path.join(FIXTURES_DIR, decl["schema_path"])
    print(f"  required layers: {', '.join(required_layers)}")
    print(f"  schema layer owns rejection_kind: {', '.join(sorted(owned)) or '<none>'}")

    if decl.get("dialect") != DRAFT_2020_12:
        failures += 1
        print(f"  FAIL schema layer declares dialect {decl.get('dialect')!r}, expected {DRAFT_2020_12}")
    if not os.path.isfile(schema_path):
        print(f"  FAIL schema file missing at {schema_path}")
        return 1
    actual_digest = sha256_file(schema_path)
    if decl.get("schema_sha256") != actual_digest:
        failures += 1
        print(f"  FAIL schema digest: manifest pins {str(decl.get('schema_sha256'))[:16]}…, file is {actual_digest[:16]}…")
    else:
        print(f"  OK   schema bytes match the manifest pin ({actual_digest[:16]}…)")

    schema = json.load(open(schema_path))

    print("\n== 1. meta-validate schema (Draft 2020-12) ==")
    if schema.get("$schema") != DRAFT_2020_12:
        print(f"  schema does not declare the {DRAFT_2020_12} dialect (found {schema.get('$schema')!r})")
        return 1
    try:
        Draft202012Validator.check_schema(schema)
        print("  schema is a valid Draft 2020-12 schema: OK")
    except Exception as e:  # noqa
        print(f"  schema INVALID: {e}")
        return 1
    validator = Draft202012Validator(schema)

    print("\n== 2. schema-validate each vector record ==")
    # Same verdict rules as runners/ts/layered-gate.ts. A negative owned by this
    # layer passes only when the schema actually produced the error the vector
    # declares -- not merely when it rejected. Weakening the constraint the
    # vector exercises therefore fails here too, exactly as it fails the Node
    # gate, which is what makes this an implementation of the same rules rather
    # than a looser cousin.
    for v in vectors:
        errs = sorted(validator.iter_errors(v["record"]), key=lambda e: list(e.path))
        observed = [(instance_path(e), e.validator) for e in errs]
        shown = ", ".join(f"{p or '<root>'} {k}" for p, k in observed) or "accept"
        rk = v.get("rejection_kind")
        code = v.get("expected_error_code")
        if rk in owned:
            if not errs:
                failures += 1
                print(f"  FAIL {v['name']:34} expected schema rejection ({rk}) was NOT observed; record is schema-valid")
                continue
            if code is None:
                print(f"  OK   {v['name']:34} schema-INVALID as required ({shown})")
                continue
            binding = bindings.get(code)
            if binding is None:
                failures += 1
                print(f"  FAIL {v['name']:34} expected_error_code {code} has no error_binding in the manifest")
                continue
            want = (binding.get("instance_path"), binding.get("keyword"))
            if want in observed:
                print(f"  OK   {v['name']:34} rejected with {code} ({want[0]} {want[1]})")
            else:
                failures += 1
                print(f"  FAIL {v['name']:34} rejected, but not with {code} ({want[0]} {want[1]}); observed: {shown}")
        elif v.get("expected_verification") is False:
            # A negative another layer owns. The schema result is reported and
            # is not decisive: negative-type-relabel is schema-invalid too, and
            # that is incidental to the signature rejection it declares.
            print(f"  --   {v['name']:34} {shown} ({rk} negative; schema not decisive)")
        else:
            # positive: MUST be schema-valid.
            if errs:
                failures += 1
                print(f"  FAIL {v['name']:34} positive is schema-invalid: {shown}")
            else:
                print(f"  OK   {v['name']:34} schema-valid (positive)")

    print("\n== 3. cross-language JCS byte-parity (Python vs stored TS bytes) ==")
    for v in vectors:
        rec = v["record"]
        rec_no_sig = {k: val for k, val in rec.items() if k != "sig"}
        si = jcs(rec_no_sig)
        canon = jcs(rec)
        ok = (si == v["signing_input_canonical"] and canon == v["canonical"]
              and sha256_hex(canon) == v["canonical_sha256"])
        if not ok:
            failures += 1
        print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:28} signing_input+canonical+sha256 parity")

    print("\n== 4. detached-payload digest binding ==")
    for v in vectors:
        rec = v["record"]
        if "action" in rec:
            recomputed = sha256_hex(jcs(rec["action"]))
            matches = recomputed == rec["action_digest"]["sha256"]
            if v["name"] == "negative-tampered-payload":
                ok = (matches is False)  # MUST mismatch
                print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:34} digest MISMATCH as required (bound={matches})")
            else:
                ok = (matches is True)  # everything else with an inline payload MUST bind
                print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:34} digest binds (bound={matches})")
            if not ok:
                failures += 1
        else:
            print(f"  --   {v['name']:34} detached (no inline action), digest binding deferred")

    print("\n== 5. Ed25519 signature verification ==")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        have_crypto = True
    except ImportError:
        have_crypto = False
        print("  `cryptography` not installed. Ed25519 verification was NOT performed here.")
        print("  Run `pip install cryptography`, or verify signatures with:")
        print("    npx tsx fixtures/accountability-record/verify.ts")

    if have_crypto:
        for v in vectors:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["ed25519_pubkey_hex"]))
            msg = v["signing_input_canonical"].encode("utf-8")
            sig = bytes.fromhex(v["record"]["sig"])
            try:
                pub.verify(sig, msg)
                verified = True
            except InvalidSignature:
                verified = False
            rk = v.get("rejection_kind")
            if rk == "signature":
                ok = (verified is False)  # wrong-key and type-relabel: sig MUST NOT verify
                note = "signature correctly rejected"
            else:
                # positives + schema/digest negatives: the signature is valid over its own bytes
                ok = (verified is True)
                note = "signature verifies" if v["expected_verification"] is True else "signature valid over bytes (fails elsewhere)"
            if not ok:
                failures += 1
            print(f"  {'OK  ' if ok else 'FAIL'} {v['name']:34} {note} (verified={verified})")

    # Honest exit: schema, byte-parity, and digest checks may pass, but if the
    # Ed25519 path was skipped this is NOT a full pass. Never print a green banner
    # or exit 0 when signatures went unverified.
    if failures:
        print(f"\n{failures} CHECK(S) FAILED")
        return 1
    if not have_crypto:
        print("\nINCOMPLETE: schema, byte-parity, and digest checks passed, but Ed25519")
        print("signatures were NOT verified (cryptography missing). Not a full pass.")
        return 2
    print("\nALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
