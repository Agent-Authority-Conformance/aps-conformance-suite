#!/usr/bin/env python3
"""Clean-room recompute of the mcp-audit-gateway v0.6 conformance vectors.

Written from the documented rules only: the header blocks of
test/vectors/canonicalization.json and test/vectors/checkpoint.json, and
test/vectors/README.md, at commit a0f14a0418c2abe6135436f037f6b171735d1e73.
No implementation of this format was consulted.

Python 3 standard library only. No network.

Usage: python3 recompute.py canonicalization.json checkpoint.json

Outcome vocabulary
  PASS         documented rule derived, agrees with the published value
  FAIL         documented rule derived, disagrees; derived and published both shown
  DIVERGE      diagnostic comparison differs, rule documented only partially
  UNSPECIFIED  no documented rule; nothing derived
  NOT CHECKED  out of scope

Exit 1 only if any check is FAIL.
"""

import hashlib
import json
import sys

RESULTS = []


def record(name, status, derived=None, published=None, note=None):
    RESULTS.append({
        "name": name,
        "status": status,
        "derived": derived,
        "published": published,
        "note": note,
    })
    line = "%-11s %s" % (status, name)
    if status in ("FAIL", "DIVERGE"):
        line += "\n    derived  : %s" % (derived,)
        line += "\n    published: %s" % (published,)
    elif note:
        line += "  (%s)" % note
    print(line)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- serialization

def compact(value):
    """JSON with compact separators and no ASCII escaping.

    INFERRED: the headers give the tuple-array shape by example but do not state
    the separator or the non-ASCII escaping policy. Compact separators and
    unescaped non-ASCII are taken from the published `canonical` example in
    checkpoint.json extensions_digest.record_canonicalization.
    """
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def utf16_key(s):
    """Sort key: the UTF-16 code unit sequence of the string.

    Documented for aiInvocation ("Keys sort by UTF-16 code units"); applied to
    every canonicalizeValue object, since the constraints say "sorted keys"
    without naming a second ordering.
    """
    b = s.encode("utf-16-be", errors="surrogatepass")
    return [int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)]


class CanonError(ValueError):
    pass


def has_lone_surrogate(s):
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            return True
    return False


SAFE_MAX = 2 ** 53 - 1


def canonicalize_value(v):
    """canonicalizeValue() per checkpoint.json canonicalize_value.constraints."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        if not (-SAFE_MAX <= v <= SAFE_MAX):
            raise CanonError("integer outside the safe range: %r" % (v,))
        return v
    if isinstance(v, float):
        raise CanonError("float is not a safe integer: %r" % (v,))
    if isinstance(v, str):
        if has_lone_surrogate(v):
            raise CanonError("string contains a lone surrogate")
        return v
    if isinstance(v, list):
        return ["L", [canonicalize_value(x) for x in v]]
    if isinstance(v, dict):
        pairs = []
        for k in sorted(v.keys(), key=utf16_key):
            if has_lone_surrogate(k):
                raise CanonError("object key contains a lone surrogate")
            pairs.append([k, canonicalize_value(v[k])])
        return ["M", pairs]
    raise CanonError("unsupported type %s" % type(v).__name__)


BASE_ORDER = [
    "id", "timestamp", "method", "toolName", "namespace", "upstream",
    "principal", "durationMs", "success", "errorCode",
]


def record_tuple_array(rec, field_order):
    """Build the tuple-array for an audit record.

    Documented order:
      the 11 fields of field_order, with absent/undefined serialized as null
      (null_rule); decisionContextDigest at position 10, before previousHash,
      when present and non-null (canonicalization.json conditional_fields);
      extensionsDigest after previousHash, or after decisionContextDigest if
      present (checkpoint.json extensions_digest.record_canonicalization);
      aiInvocation after extensionsDigest, before parties
      (canonicalization.json ai_invocation_signing.description);
      parties last (canonicalization.json conditional_fields / party_attribution).
    """
    head = [f for f in field_order if f != "previousHash"]
    pairs = []
    for f in head:
        pairs.append([f, rec.get(f, None)])
    if rec.get("decisionContextDigest", None) is not None:
        pairs.append(["decisionContextDigest", rec["decisionContextDigest"]])
    pairs.append(["previousHash", rec.get("previousHash", None)])
    if rec.get("extensionsDigest", None) is not None:
        pairs.append(["extensionsDigest", rec["extensionsDigest"]])
    if rec.get("aiInvocation", None) is not None:
        pairs.append(["aiInvocation", canonicalize_value(rec["aiInvocation"])])
    if rec.get("parties", None) is not None:
        pairs.append(["parties", rec["parties"]])
    return pairs


def checkpoint_tuple_array(rec, field_order):
    pairs = [[f, rec.get(f, None)] for f in field_order]
    if rec.get("parties", None) is not None:
        pairs.append(["parties", rec["parties"]])
    return pairs


# ---------------------------------------------------------------- checks 1 + 2

def check_record_vector(label, entry, field_order, builder):
    if not isinstance(entry, dict) or "record" not in entry:
        return
    rec = entry["record"]

    if "canonical" in entry:
        try:
            derived = compact(builder(rec, field_order))
            if derived == entry["canonical"]:
                record(label + " :: canonical bytes", "PASS")
            else:
                record(label + " :: canonical bytes", "FAIL", derived, entry["canonical"])
        except CanonError as exc:
            record(label + " :: canonical bytes", "FAIL", "raised %s" % exc, entry["canonical"])

    if "sha256_canonical" in entry:
        try:
            derived_bytes = compact(builder(rec, field_order))
            h = sha256_hex(derived_bytes)
            if h == entry["sha256_canonical"]:
                record(label + " :: sha256_canonical", "PASS")
            else:
                record(label + " :: sha256_canonical", "FAIL", h, entry["sha256_canonical"])
        except CanonError as exc:
            record(label + " :: sha256_canonical", "FAIL", "raised %s" % exc,
                   entry["sha256_canonical"])

    if "full_record_json" in entry and "record_hash" in entry:
        h = sha256_hex(entry["full_record_json"])
        if h == entry["record_hash"]:
            record(label + " :: record_hash over full_record_json", "PASS")
        else:
            record(label + " :: record_hash over full_record_json", "FAIL", h, entry["record_hash"])


def check_chain_json_diagnostic(label, entry, chain_key_order):
    """DIAGNOSTIC ONLY. The header names the key order but not the escaping
    semantics of JSON.stringify, so a mismatch is DIVERGE, never FAIL."""
    if not isinstance(entry, dict) or "full_record_json" not in entry:
        return
    rec = entry.get("record")
    if rec is None:
        return
    ordered = {}
    for k in chain_key_order:
        if k in rec:
            ordered[k] = rec[k]
    for k in rec:
        if k not in ordered:
            ordered[k] = rec[k]
    derived = compact(ordered)
    if derived == entry["full_record_json"]:
        record(label + " :: full_record_json reserialized (diagnostic)", "PASS")
    else:
        record(label + " :: full_record_json reserialized (diagnostic)", "DIVERGE",
               derived, entry["full_record_json"])


# ---------------------------------------------------------------- check 3

def check_linkage(label, records, genesis_seed):
    prev_hash = None
    for i, entry in enumerate(records):
        rec = entry.get("record") if isinstance(entry, dict) else None
        if rec is None:
            continue
        got = rec.get("previousHash")
        if i == 0:
            if genesis_seed is None:
                record("%s :: record[0] previousHash" % label, "UNSPECIFIED",
                       got, None, note="no genesis_seed stated in this block")
            elif got == genesis_seed:
                record("%s :: record[0] previousHash == genesis_seed" % label, "PASS")
            else:
                record("%s :: record[0] previousHash == genesis_seed" % label,
                       "FAIL", got, genesis_seed)
        else:
            if prev_hash is None:
                record("%s :: record[%d] linkage" % (label, i), "UNSPECIFIED", got, None,
                       note="prior record published no record_hash")
            elif got == prev_hash:
                record("%s :: record[%d] previousHash == prior record_hash" % (label, i), "PASS")
            else:
                record("%s :: record[%d] previousHash == prior record_hash" % (label, i),
                       "FAIL", got, prev_hash)
        prev_hash = entry.get("record_hash", None)


# ---------------------------------------------------------------- main

def main():
    if len(sys.argv) != 3:
        print("usage: python3 recompute.py canonicalization.json checkpoint.json")
        return 2
    p_canon, p_ckpt = sys.argv[1], sys.argv[2]

    raw_canon = open(p_canon, "rb").read()
    raw_ckpt = open(p_ckpt, "rb").read()
    print("input %s sha256 %s" % (p_canon, hashlib.sha256(raw_canon).hexdigest()))
    print("input %s sha256 %s" % (p_ckpt, hashlib.sha256(raw_ckpt).hexdigest()))
    print("python %s" % sys.version.split()[0])
    print("")

    C = json.loads(raw_canon.decode("utf-8"))
    K = json.loads(raw_ckpt.decode("utf-8"))
    field_order = C["field_order"]
    chain_key_order = C["chain"]["chain_key_order"]
    ckpt_order = K["checkpoint_field_order"]

    # --- 1 + 2: canonicalization vectors -------------------------------------
    for i, v in enumerate(C["canonicalization"]):
        check_record_vector("canonicalization[%s]" % v.get("name", i), v,
                            field_order, record_tuple_array)

    # --- chain block ---------------------------------------------------------
    for i, v in enumerate(C["chain"]["records"]):
        lbl = "chain[%d]" % i
        check_record_vector(lbl, v, field_order, record_tuple_array)
        check_chain_json_diagnostic(lbl, v, chain_key_order)
    check_linkage("chain", C["chain"]["records"], C["chain"].get("genesis_seed"))

    # --- dual_hash_demo ------------------------------------------------------
    dh = C["dual_hash_demo"]
    for key in ("record_a", "record_b"):
        lbl = "dual_hash_demo.%s" % key
        check_record_vector(lbl, dh[key], field_order, record_tuple_array)
        check_chain_json_diagnostic(lbl, dh[key], chain_key_order)
    a, b = dh["record_a"], dh["record_b"]
    ca = sha256_hex(compact(record_tuple_array(a["record"], field_order)))
    cb = sha256_hex(compact(record_tuple_array(b["record"], field_order)))
    ha = sha256_hex(a["full_record_json"])
    hb = sha256_hex(b["full_record_json"])
    asserts = dh.get("assertions", {})
    if (ca == cb) == asserts.get("canonical_hashes_match"):
        record("dual_hash_demo :: canonical hashes match", "PASS")
    else:
        record("dual_hash_demo :: canonical hashes match", "FAIL", ca == cb,
               asserts.get("canonical_hashes_match"))
    if (ha != hb) == asserts.get("chain_hashes_differ"):
        record("dual_hash_demo :: chain hashes differ", "PASS")
    else:
        record("dual_hash_demo :: chain hashes differ", "FAIL", ha != hb,
               asserts.get("chain_hashes_differ"))

    # --- party_attribution ---------------------------------------------------
    pa = C["party_attribution"]
    for i, v in enumerate(pa["vectors"]):
        check_record_vector("party_attribution[%s]" % v.get("name", i), v,
                            field_order, record_tuple_array)
    cwp = pa["chain_with_parties"]
    for i, v in enumerate(cwp["records"]):
        check_record_vector("party_attribution.chain[%d]" % i, v, field_order,
                            record_tuple_array)
    check_linkage("party_attribution.chain", cwp["records"], cwp.get("genesis_seed"))

    # --- ai_invocation_signing ----------------------------------------------
    ai = C["ai_invocation_signing"]
    for i, v in enumerate(ai["vectors"]):
        check_record_vector("ai_invocation_signing[%s]" % v.get("name", i), v,
                            field_order, record_tuple_array)
    mut = ai.get("mutation_negative")
    if isinstance(mut, dict) and "original" in mut and "mutated" in mut:
        try:
            o = sha256_hex(compact(canonicalize_value(mut["original"])))
            m = sha256_hex(compact(canonicalize_value(mut["mutated"])))
            if (o != m) == mut.get("digests_differ", True):
                record("ai_invocation_signing :: mutation changes the digest", "PASS")
            else:
                record("ai_invocation_signing :: mutation changes the digest", "FAIL",
                       o != m, mut.get("digests_differ"))
        except CanonError as exc:
            record("ai_invocation_signing :: mutation changes the digest", "FAIL",
                   "raised %s" % exc, mut.get("digests_differ"))

    # --- extensions_digest_base ---------------------------------------------
    for i, v in enumerate(C["extensions_digest_base"]["vectors"]):
        check_record_vector("extensions_digest_base[%s]" % v.get("name", i), v,
                            field_order, record_tuple_array)

    # --- 4: checkpoint canonicalization -------------------------------------
    for i, v in enumerate(K["checkpoint_canonicalization"]):
        check_record_vector("checkpoint_canonicalization[%s]" % v.get("name", i), v,
                            ckpt_order, checkpoint_tuple_array)

    # checkpoint chain
    for i, v in enumerate(K["checkpoint_chain"]["records"]):
        rec = v.get("record", {})
        builder = checkpoint_tuple_array if rec.get("type") else record_tuple_array
        order = ckpt_order if rec.get("type") else field_order
        check_record_vector("checkpoint_chain[%d]" % i, v, order, builder)
    check_linkage("checkpoint_chain", K["checkpoint_chain"]["records"],
                  K["checkpoint_chain"].get("genesis_seed"))

    # --- extensions_digest record_canonicalization ---------------------------
    rc = K["extensions_digest"].get("record_canonicalization", {})
    for key in ("with_extensions_digest", "without_extensions_digest"):
        if key in rc:
            check_record_vector("extensions_digest.%s" % key, rc[key], field_order,
                                record_tuple_array)

    # --- 7: canonicalize_value + extensions_digest vectors -------------------
    # Vector shapes present in the file: {input, canonical_form, digest};
    # {input_a, input_b, canonical_form, digest} (both inputs must agree);
    # {input_a, input_b, canonical_a, digest_a, canonical_b, digest_b};
    # {construct, expected_error}; {input, expected_error}.

    def check_cv(lbl, value, want_canonical, want_digest):
        try:
            cv = canonicalize_value(value)
        except CanonError as exc:
            record(lbl, "FAIL", "raised %s" % exc, want_canonical)
            return
        d = compact(cv)
        if want_canonical is not None:
            if d == want_canonical:
                record(lbl + " :: canonical_form", "PASS")
            else:
                record(lbl + " :: canonical_form", "FAIL", d, want_canonical)
        if want_digest is not None:
            h = sha256_hex(d)
            if h == want_digest:
                record(lbl + " :: digest", "PASS")
            else:
                record(lbl + " :: digest", "FAIL", h, want_digest)

    for i, v in enumerate(K["canonicalize_value"]["vectors"]):
        lbl = "canonicalize_value[%s]" % v.get("name", i)

        if "expected_error" in v:
            if "construct" in v:
                # Documented construction: chr(0xD800), a lone HIGH surrogate.
                probe = chr(0xD800)
                what = "chr(0xD800) per the vector construct text"
            else:
                probe = v.get("input")
                what = "published input"
            try:
                canonicalize_value(probe)
                record(lbl + " :: rejects (%s)" % what, "FAIL", "accepted",
                       v["expected_error"])
            except CanonError as exc:
                record(lbl + " :: rejects (%s)" % what, "PASS", None,
                       v["expected_error"], note=str(exc))
            continue

        if "input_a" in v and "input_b" in v:
            if "canonical_a" in v or "digest_a" in v:
                check_cv(lbl + ".a", v["input_a"], v.get("canonical_a"), v.get("digest_a"))
                check_cv(lbl + ".b", v["input_b"], v.get("canonical_b"), v.get("digest_b"))
            else:
                check_cv(lbl + ".a", v["input_a"], v.get("canonical_form"), v.get("digest"))
                check_cv(lbl + ".b", v["input_b"], v.get("canonical_form"), v.get("digest"))
            continue

        if "input" in v:
            check_cv(lbl, v["input"], v.get("canonical_form"), v.get("digest"))
            continue

        record(lbl, "UNSPECIFIED", None, None, note="no recognised input field")

    for i, v in enumerate(K["extensions_digest"]["vectors"]):
        lbl = "extensions_digest[%s]" % v.get("name", i)
        if "expected_error" in v:
            try:
                canonicalize_value(v.get("extensions"))
                record(lbl + " :: rejects", "FAIL", "accepted", v["expected_error"])
            except CanonError as exc:
                record(lbl + " :: rejects", "PASS", None, v["expected_error"], note=str(exc))
            continue
        if "extensions" in v:
            check_cv(lbl, v["extensions"], v.get("canonical_form"), v.get("digest"))
        else:
            record(lbl, "UNSPECIFIED", None, None, note="no extensions field")

    # lone LOW surrogate, additional to the published vectors, which construct a
    # lone HIGH surrogate only.
    try:
        canonicalize_value(chr(0xDC00))
        record("canonicalize_value :: lone low surrogate U+DC00", "FAIL",
               "accepted", "rejection expected by the surrogate rule")
    except CanonError as exc:
        record("canonicalize_value :: lone low surrogate U+DC00", "PASS", None, None,
               note=str(exc))

    # --- 3 continued: rotation_boundary and chain_break ----------------------
    rb = K["rotation_boundary"]
    f1, f2 = rb["file_1_records"], rb["file_2_records"]
    last_f1 = f1[-1].get("record_hash") if f1 else None
    first_f2 = f2[0].get("record", {}).get("previousHash") if f2 else None
    if last_f1 is None or first_f2 is None:
        record("rotation_boundary :: file 2 chains to file 1", "UNSPECIFIED",
               first_f2, last_f1, note="a required published hash is absent")
    elif first_f2 == last_f1:
        record("rotation_boundary :: file 2 first previousHash == file 1 last record_hash",
               "PASS")
    else:
        record("rotation_boundary :: file 2 first previousHash == file 1 last record_hash",
               "FAIL", first_f2, last_f1)

    cb = K["chain_break"]
    cbrecs = cb["records"]
    for i, v in enumerate(cbrecs):
        rec = v.get("record", {})
        if rec.get("type") == "chain_break" and "canonical" in v:
            pairs = [[f, rec.get(f, None)] for f in cb["canonical_field_order"]]
            d = compact(pairs)
            if d == v["canonical"]:
                record("chain_break[%d] :: canonical bytes" % i, "PASS")
            else:
                record("chain_break[%d] :: canonical bytes" % i, "FAIL", d, v["canonical"])
            if "sha256_canonical" in v:
                h = sha256_hex(d)
                if h == v["sha256_canonical"]:
                    record("chain_break[%d] :: sha256_canonical" % i, "PASS")
                else:
                    record("chain_break[%d] :: sha256_canonical" % i, "FAIL", h,
                           v["sha256_canonical"])
        else:
            check_record_vector("chain_break[%d]" % i, v, field_order, record_tuple_array)
    if len(cbrecs) >= 2:
        base = cbrecs[0].get("record_hash")
        succ = cbrecs[1].get("record", {}).get("previousHash")
        if base is None or succ is None:
            record("chain_break :: successor chains from the break record", "UNSPECIFIED",
                   succ, base, note="a required published hash is absent")
        elif succ == base:
            record("chain_break :: successor previousHash == break record_hash", "PASS")
        else:
            record("chain_break :: successor previousHash == break record_hash", "FAIL",
                   succ, base)

    # --- 5: head_missing derived --------------------------------------------
    # Derived from truncation_detection: is the externalized checkpoint
    # (previousHash + sequence + recordCount) present in records_delivered, and
    # is any later checkpoint present? The published failureCode is NOT read to
    # decide; it is compared afterwards.
    td = K["truncation_detection"]
    ext = td["external_checkpoint"]
    tc = td["truncated_chain"]
    delivered = tc.get("records_delivered", [])

    def as_record(x):
        if isinstance(x, dict):
            return x["record"] if "record" in x and isinstance(x["record"], dict) else x
        return {}

    def is_the_checkpoint(r):
        return (r.get("previousHash") == ext.get("previousHash")
                and r.get("sequence") == ext.get("sequence")
                and r.get("recordCount") == ext.get("recordCount"))

    present = any(is_the_checkpoint(as_record(x)) for x in delivered)
    later = 0
    for x in delivered:
        r = as_record(x)
        if (r.get("type") == "checkpoint"
                and isinstance(r.get("sequence"), int)
                and isinstance(ext.get("sequence"), int)
                and r["sequence"] > ext["sequence"]):
            later += 1
    derived_truncated = (not present) and later == 0
    derived_code = "head_missing" if derived_truncated else None

    pub_result = tc.get("detection_result")
    pub_truncated = (pub_result == "truncated") if isinstance(pub_result, str) else None
    note = "checkpoint present=%s, later checkpoints=%d, delivered=%d" % (
        present, later, len(delivered))
    if pub_truncated is None:
        record("truncation_detection :: truncation derived", "UNSPECIFIED",
               derived_truncated, pub_result, note=note)
    elif derived_truncated == pub_truncated:
        record("truncation_detection :: truncation derived", "PASS",
               derived_truncated, pub_result, note=note)
    else:
        record("truncation_detection :: truncation derived", "FAIL",
               derived_truncated, pub_result)

    pub_code = tc.get("failureCode")
    if pub_code == derived_code:
        record("truncation_detection :: stated failure code agrees with derivation",
               "PASS", derived_code, pub_code)
    else:
        record("truncation_detection :: stated failure code agrees with derivation",
               "DIVERGE", derived_code, pub_code)

    cc = td.get("complete_chain_result", {})
    if isinstance(cc, dict) and "truncated" in cc:
        record("truncation_detection :: complete chain result", "UNSPECIFIED",
               None, cc.get("truncated"),
               note="the complete chain's records are not enumerated in the file, "
                    "so nothing can be derived for it")

    # --- 6: sequence_regression derived -------------------------------------
    sr = K["sequence_regression"]
    seqs = []
    for x in sr["chain"]:
        r = as_record(x)
        if r.get("type") == "checkpoint" and isinstance(r.get("sequence"), int):
            seqs.append(r["sequence"])
    regressed = any(seqs[i] <= seqs[i - 1] for i in range(1, len(seqs)))
    pub = sr.get("detection_result", {})
    if not isinstance(pub, dict):
        pub = {"truncated": pub == "truncated", "failureCode": sr.get("failure_code")}
    if pub.get("truncated") is None:
        record("sequence_regression :: derived", "UNSPECIFIED", regressed, None,
               note="checkpoint sequences %s" % seqs)
    elif regressed == pub.get("truncated"):
        record("sequence_regression :: derived", "PASS", regressed, pub.get("truncated"),
               note="checkpoint sequences %s" % seqs)
    else:
        record("sequence_regression :: derived", "FAIL", regressed, pub.get("truncated"))
    derived_code = "sequence_regression" if regressed else None
    if pub.get("failureCode") == derived_code:
        record("sequence_regression :: stated failure code agrees with derivation", "PASS")
    else:
        record("sequence_regression :: stated failure code agrees with derivation",
               "DIVERGE", derived_code, pub.get("failureCode"))

    # --- 8: count_mismatch ---------------------------------------------------
    record("count_mismatch", "NOT CHECKED", None, None,
           note="documented in failure_codes and not exercised by this verifier; out of scope")

    # --- summary -------------------------------------------------------------
    counts = {}
    for r in RESULTS:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("")
    print("checks: %d" % len(RESULTS))
    for k in ("PASS", "FAIL", "DIVERGE", "UNSPECIFIED", "NOT CHECKED"):
        if k in counts:
            print("  %-11s %d" % (k, counts[k]))
    with open("results.json", "w", encoding="utf-8") as fh:
        json.dump(RESULTS, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("wrote results.json")
    return 1 if counts.get("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())
