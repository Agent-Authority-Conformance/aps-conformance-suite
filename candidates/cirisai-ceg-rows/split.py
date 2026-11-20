#!/usr/bin/env python3
"""Split the two published vector files into sealed inputs and expected results.

Reads row_statements_v3.json and key_of_iss_v1.json from the directory given by --source (byte copies of
CIRISVerify at v23.3.0, commit ffd7af1f1b53, path src/ciris-verify-core/tests/vectors/edition2/; each is
checked against its SHA-256 below) and writes:

  inputs/cases.json   every case as an opaque id, its level and its bytes: no expectation, no description,
                      no source id, no section, sorted by the opaque id
  inputs/keys.json    the composite public key of each kid the cases use
  inputs/family_model.json   the family model the `family` level cases are read under
  expected.json       opaque id -> the source file, section and id, the expected answer and the description

The opaque id is "c-" and the first 12 hex digits of the SHA-256 of the case's input as written.
The source files carry the expected answers inline, so they are not copied here.

Run: python3 -I split.py --source DIR            (writes)
     python3 -I split.py --source DIR --check    (compares with the committed files; exits 1 on a difference)
Standard library only.
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = {"row_statements_v3.json": "0c072516dea1d89132567e0f343ca47a2183df79697651685aa557d739cdf920",
       "key_of_iss_v1.json": "bd584d9b31b7271dc86c05a29eec75044b5fe74aae8dd586701a227f09001333"}
HIDE = ("expect", "description", "family_vendored_expect")
SOURCE = sys.argv[sys.argv.index("--source") + 1] if "--source" in sys.argv else os.path.join(HERE, "source")


def load(name):
    raw = open(os.path.join(SOURCE, name), "rb").read()
    got = hashlib.sha256(raw).hexdigest()
    if got != SRC[name]:
        sys.exit(f"{name}: sha256 {got}, expected {SRC[name]}")
    return json.loads(raw)


def head(mt, n):
    if n < 24: return bytes([mt << 5 | n])
    if n < 256: return bytes([mt << 5 | 24, n])
    if n < 65536: return bytes([mt << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([mt << 5 | 26]) + n.to_bytes(4, "big")


def dec(b, i=0):
    """A CBOR item at b[i:], for the definite-length forms the vectors use."""
    ib = b[i]; mt, ai = ib >> 5, ib & 31; i += 1
    if ai < 24: n = ai
    elif ai in (24, 25, 26, 27):
        w = 1 << (ai - 24); n = int.from_bytes(b[i:i + w], "big"); i += w
    else: raise ValueError(ai)
    if mt == 0: return n, i
    if mt == 1: return -1 - n, i
    if mt == 2: return b[i:i + n], i + n
    if mt == 3: return b[i:i + n].decode(), i + n
    if mt == 4:
        out = []
        for _ in range(n):
            x, i = dec(b, i); out.append(x)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(n):
            k, i = dec(b, i); x, i = dec(b, i); out[k] = x
        return out, i
    if mt == 6: return dec(b, i)
    return {20: False, 21: True, 22: None}[ai], i


def thumbprint(pub):
    """RFC 9679 thumbprint of the composite COSE key {1: 7, 3: -70100, -1: pub}."""
    enc = head(5, 3) + b"\x01\x07" + b"\x03" + head(1, 70099) + b"\x20" + head(2, len(pub)) + pub
    return hashlib.sha256(enc).hexdigest()


def strip(case):
    return {k: v for k, v in case.items() if k not in HIDE}


def build():
    rows, koi = load("row_statements_v3.json"), load("key_of_iss_v1.json")
    expected, cases = {}, []
    ANSWERS = {"valid": ("row_id_hex", "statement_id_hex", "kid_hex", "iss", "key_seed"), "references": ("form", "digest_hex"),
               "objects": ("object_id_hex", "statement_id_hex"), "family_vendored_groups": ("row_id_hex", "act")}

    def add(source, section, c):
        exp = {k: c[k] for k in HIDE if k in c}
        exp.update({k: c[k] for k in ANSWERS.get(section, ()) if k in c})
        if section == "valid": exp["expect"] = "valid"
        given = {k: v for k, v in c.items() if k not in exp and k not in HIDE and k != "id"}
        if section == "valid": given["held_key_seeds"] = [c["key_seed"]]
        oid = "c-" + hashlib.sha256(json.dumps(given, sort_keys=True).encode()).hexdigest()[:12]
        assert oid not in expected, oid
        expected[oid] = dict(exp, source=source, section=section, id=c["id"])
        cases.append(dict(given, id=oid))

    for section in ("valid", "refusals", "key_directory", "key_records", "family", "family_vendored",
                    "family_vendored_groups", "objects", "references"):
        for c in rows[section]: add("row_statements_v3.json", section, c)
    for c in koi["cases"]: add("key_of_iss_v1.json", "cases", c)
    cases.sort(key=lambda c: c["id"])
    # the public keys, read from the key records the files carry
    pubs = {}
    def walk(v):
        if isinstance(v, dict):
            for x in v.values(): walk(x)
        elif isinstance(v, list):
            for x in v: walk(x)
        elif isinstance(v, bytes) and len(v) == 1984:
            pubs[thumbprint(v)] = v.hex()
        elif isinstance(v, bytes) and len(v) > 2000:
            try: walk(dec(v)[0])
            except Exception: pass
    def hexes(v):
        if isinstance(v, dict):
            for x in v.values(): yield from hexes(x)
        elif isinstance(v, list):
            for x in v: yield from hexes(x)
        elif isinstance(v, str) and len(v) > 3000 and all(ch in "0123456789abcdef" for ch in v[:64]):
            yield v
    for doc in (rows, koi):
        for h in hexes(doc):
            try: walk(dec(bytes.fromhex(h))[0])
            except Exception: pass
    keys = {"note": "Each key is one composite public key: the ML-DSA-65 public key followed by the Ed25519 public key, "
                    "1984 bytes. Its kid is the RFC 9679 thumbprint of {1: 7, 3: -70100, -1: pub}. Key seed n is "
                    "ML-DSA-65 seed [n]*32 and Ed25519 seed [n+100]*32; a key not listed here is derived from its seed.",
            "by_kid": dict(sorted(pubs.items()))}
    return {"inputs/cases.json": cases, "inputs/keys.json": keys, "inputs/family_model.json": rows["family_model"],
            "expected.json": dict(sorted(expected.items()))}


def main():
    out = build(); bad = 0
    for rel, obj in out.items():
        text = json.dumps(obj, indent=1, sort_keys=True) + "\n"; p = os.path.join(HERE, rel)
        if "--check" in sys.argv:
            if not os.path.exists(p) or open(p).read() != text:
                print(f"{rel}: differs from what split.py writes"); bad = 1
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(text)
    e = out["expected.json"]
    print(f"split: {len(e)} cases, {len(out['inputs/keys.json']['by_kid'])} public keys; "
          + ("compared" if "--check" in sys.argv else "written"))
    return bad


if __name__ == "__main__":
    sys.exit(main())
