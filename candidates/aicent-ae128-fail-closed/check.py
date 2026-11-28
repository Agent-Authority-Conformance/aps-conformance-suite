#!/usr/bin/env python3
"""Recompute each case's parse and verification decisions from the frame bytes,
compare with the declared expectations. Cases whose declared status is not
"normative" are marked in the output: their expectations are proposed behavior
that the pinned source text does not require (see vectors.json). The rules are derived from the pinned
source text (draft-li-rttp-iqa-addressing-02, sections 7.2 and 7.2.1), not from
any implementation. Standard library only. Exit 0 when every case agrees, 1
otherwise."""
import hashlib, hmac, json, os, sys

KEY = b"PLSF-TEST-ORG-KEY-00012345678901"  # published in sec. 7.2.1
STANDING_SET = (0x00, 0x01, 0x02, 0x03)  # sec. 7.2: closed set fixed in the document


def parse(frame):
    """Verification procedure step (1) of sec. 7.2, plus two field-row checks."""
    if len(frame) != 128:  # "(1) rejects the frame if its length is not 128"
        return "length"
    if frame[0:4] != b"IQAE":  # "its magic is not \"IQAE\""
        return "magic"
    if frame[4] != 1:  # "its version is not 1"
        return "version"
    if frame[5] != 1:  # "its algorithm is not 0x01"
        return "algorithm"
    if frame[6:8] != b"\x00\x00":
        # field row: "flags - unsigned, big-endian; unassigned; sent as 0x0000".
        # step (1) does not list this check; the -03 revision adds flags to the
        # MUST-reject list (author decision 2026-11-09, disclosed in vectors.json).
        return "flags"
    if frame[80] not in STANDING_SET:  # "its standing byte is outside the closed set"
        return "standing"
    if any(frame[81:96]):  # "its reserved ... fields are not all zero"
        return "reserved"
    if any(frame[96:128]):  # "its ... extension fields are not all zero"
        return "extension"
    if any(b > 0x7F for b in frame[64:72]):
        # field row: "organ - exactly 8 octets of US-ASCII". step (1) does not
        # list this check; the -03 revision adds it (author decision 2026-11-09).
        return "organ"
    return None


def verify(frame, key=KEY):
    """Canonical rule and step (3) of sec. 7.2: HMAC-SHA256 over the entire frame
    with the attestation field itself zeroed."""
    mac = hmac.new(key, frame[0:32] + b"\x00" * 32 + frame[64:128],
                   hashlib.sha256).digest()
    return hmac.compare_digest(mac, frame[32:64])


def evaluate(case, parse_fn=parse, verify_fn=verify):
    frame = bytes.fromhex(case["frame_hex"])
    reason = parse_fn(frame)
    if case["expect_parse"] == "reject":
        return reason == case["reject_reason"]
    if reason is not None:
        return False
    ok = verify_fn(frame)
    return ok if case["expect_verify"] == "pass" else not ok


def main(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")):
    doc = json.load(open(path, encoding="utf-8"))
    bad = 0
    for c in doc["cases"]:
        got = evaluate(c)
        flag = "BAD" if not got else "ok "
        bad += not got
        status = c.get("status", "normative")
        tag = "" if status == "normative" else " [%s]" % status
        print(f"{flag} {c['id']:7} {c['rule']:20}{tag} {c['name'][:44]}")
    n = len(doc["cases"])
    print(f"{n - bad}/{n} agree")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
