#!/usr/bin/env python3
"""Recompute each case's decision from the frame bytes and the declared facts,
compare with the expectation. Frame rules are derived from the pinned source
text (draft-li-rttp-iqa-addressing-02, sections 7.1, 7.1.1, 7.1.2, 4.1 and
4.3), not from any implementation. Standard library only. Exit 0 when every
case agrees, 1 otherwise."""
import json, os, sys

MAGIC = 0x52545450          # sec. 7.1 field row: 0x52545450 (ASCII "RTTP")
VERSION_ID = 130            # sec. 7.1 field row: 130 in this revision
KNOWN_SPEC_REVS = (0, 1)    # sec. 7.1.1: SPEC_REV 0 = pre-extension, 1 = this revision
URI_ANCHORED_BIT = 0x01     # sec. 7.1.1 FLAGS row: bit 0 = URI_ANCHORED
ACTION_ALPHABET = set("abcdefghijklmnopqrstuvwxyz0123456789-")  # sec. 4.1 action set


def parse_frame(raw):
    """Fixed comparisons per sec. 7.1/7.1.1. Returns None (accept) or a reason."""
    if len(raw) != 128:
        return "length"
    if int.from_bytes(raw[0x00:0x04], "big") != MAGIC:
        return "magic"
    if int.from_bytes(raw[0x04:0x14], "big") != VERSION_ID:
        return "version"
    spec_rev = raw[0x66]
    if spec_rev not in KNOWN_SPEC_REVS:  # "SPEC_REV is outside the known set"
        return "spec_rev"
    if spec_rev == 0:
        if any(raw[0x66:0x80]):  # "SPEC_REV is 0 and the extension block is not all zero"
            return "spec_rev0_block"
        return None
    if any(raw[0x79:0x80]):  # "SPEC_REV is 1 and RESERVED is not all zero"
        return "reserved"
    flags = raw[0x67]
    if flags & ~URI_ANCHORED_BIT:  # "unknown FLAGS bits are set"
        return "flags"
    action_len = raw[0x68]
    if action_len > 16:  # "A frame with ACTION_LEN greater than 16 MUST be rejected"
        return "action_len"
    action = raw[0x69:0x79]
    sig = action[:action_len]
    if any(b > 0x7F for b in sig) or any(
            chr(b) not in ACTION_ALPHABET for b in sig):
        # "the ACTION field contains characters outside the set of Section 4.1"
        return "action_charset"
    if any(action[action_len:]):  # "carries non-zero padding"
        return "action_padding"
    return None


def r_frame(case):
    got = parse_frame(bytes.fromhex(case["frame_hex"]))
    if case["expect"] == "reject":
        return "reject" if got == case["reject_reason"] else "accept"
    return "reject" if got is not None else "accept"


def r_anchored_routing(case):
    i, o = case["input"], case["outcome"]
    anchored = bytes.fromhex(i["frame_hex"])[0x67] & URI_ANCHORED_BIT
    if anchored:
        # URI_ANCHORED set: globally routable; both forwarding decisions conform
        return "conformant"
    if o.get("forwarded_globally"):
        # "implementations that route between nodes MUST require URI_ANCHORED
        # to be set" — global forwarding of an unanchored frame is excluded
        return "nonconformant"
    return "conformant"  # local dispatch is the licensed use


def r_unknown_verb(case):
    o = case["outcome"]
    if o.get("inferred_safe_from_default_operation"):
        # "MUST NOT infer safety from the default-operation statement"
        return "nonconformant"
    authorised = o.get("required_explicit_authorisation", False)
    rejected = o.get("rejected", False)
    # "either require explicit authorisation ... or be rejected"
    return "conformant" if (authorised or rejected) else "nonconformant"


def r_ttl(case):
    i, o = case["input"], case["outcome"]
    ttl = bytes.fromhex(i["frame_hex"])[0x34]
    if o.get("forwarded"):
        if ttl == 0:
            return "nonconformant"  # "MUST NOT forward a pulse received with TTL_PULSE 0"
        return "conformant" if o.get("forwarded_ttl") == ttl - 1 else "nonconformant"
    return "conformant"  # consuming where received places no trust in the field


def r_timestamp(case):
    i, o = case["input"], case["outcome"]
    ts = int.from_bytes(bytes.fromhex(i["frame_hex"])[0x24:0x34], "big")
    age = i["receiver_clock_ns"] - ts
    if o.get("computed_age_ns") != age:
        return "nonconformant"  # the age is derivable offline from the bytes alone
    return "nonconformant" if o.get("treated_age_as_standing_statement") else "conformant"


RULES = {"R-FRAME": r_frame, "R-ANCHORED-ROUTING": r_anchored_routing,
         "R-UNKNOWN-VERB": r_unknown_verb, "R-TTL": r_ttl,
         "R-TIMESTAMP": r_timestamp}


def evaluate(case, rules=RULES):
    return rules[case["rule"]](case)


def main(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")):
    doc = json.load(open(path, encoding="utf-8"))
    bad = 0
    for c in doc["cases"]:
        got = evaluate(c)
        flag = "BAD" if got != c["expect"] else "ok "
        bad += got != c["expect"]
        print(f"{flag} {c['id']:7} {c['rule']:17} expect={c['expect']:13} got={got}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
