#!/usr/bin/env python3
"""Weaken or distort each rule in a plausible way and show that some case catches
it. Frame mutants replace parse_frame; behavior mutants replace one rule
function. Exit 0 when every mutant is killed."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check

PF = check.parse_frame


def drop(check_name):
    def fn(raw):
        got = PF(raw)
        return None if got == check_name else got
    return fn


FRAME_M = {
 "frame: ACTION_LEN cap removed": lambda r: None if r[0x68] > 16 else PF(r),
 "frame: action charset accepted": drop("action_charset"),
 "frame: padding accepted": drop("action_padding"),
 "frame: SPEC_REV set opened": lambda r: None if r[0x66] not in (0, 1) else PF(r),
 "frame: SPEC_REV0 block ignored": drop("spec_rev0_block"),
 "frame: RESERVED ignored": drop("reserved"),
 "frame: unknown FLAGS bits accepted": drop("flags"),
 "frame: VERSION_ID ignored": lambda r: None if int.from_bytes(r[0x04:0x14], "big") != 130 else PF(r),
 "frame: magic ignored": lambda r: None if int.from_bytes(r[0x00:0x04], "big") != check.MAGIC else PF(r),
 "frame: always accept": lambda r: None,
 "frame: always reject": lambda r: "length",
}

BEHAVIOR_M = {
 "R-ANCHORED-ROUTING: unanchored routed globally": lambda c:
    "conformant" if c["rule"] == "R-ANCHORED-ROUTING" else check.evaluate(c),
 "R-UNKNOWN-VERB: default operation read as safe": lambda c:
    "conformant" if c["rule"] == "R-UNKNOWN-VERB" else check.evaluate(c),
 "R-UNKNOWN-VERB: silent admission scored conformant": lambda c:
    ("conformant" if c["rule"] == "R-UNKNOWN-VERB"
     and c["outcome"].get("inferred_safe_from_default_operation") is False
     and not c["outcome"].get("required_explicit_authorisation")
     and not c["outcome"].get("rejected") else check.evaluate(c)),
 "R-TTL: zero-TTL forwarded": lambda c:
    "nonconformant" if c["rule"] == "R-TTL" else check.evaluate(c),
 "R-TTL: forwarding without decrement accepted": lambda c:
    ("conformant" if c["rule"] == "R-TTL" and c["outcome"].get("forwarded")
     and c["outcome"].get("forwarded_ttl") is not None else check.evaluate(c)),
 "R-TIMESTAMP: age read as standing": lambda c:
    "conformant" if c["rule"] == "R-TIMESTAMP" else check.evaluate(c),
 "behavior: always conformant": lambda c:
    "conformant" if c["stage"] == "behavior" else check.evaluate(c),
 "behavior: always nonconformant": lambda c:
    "nonconformant" if c["stage"] == "behavior" else check.evaluate(c),
}


def main():
    doc = json.load(open(os.path.join(HERE, "vectors.json"), encoding="utf-8"))
    cases = doc["cases"]
    killed = 0
    total = len(FRAME_M) + len(BEHAVIOR_M)
    for name, fn in FRAME_M.items():
        rules = dict(check.RULES)
        rules["R-FRAME"] = lambda c, _fn=fn: (
            ("reject" if _fn(bytes.fromhex(c["frame_hex"])) == c["reject_reason"]
             else "accept") if c["expect"] == "reject"
            else ("reject" if _fn(bytes.fromhex(c["frame_hex"])) is not None
                  else "accept"))
        hits = [c["id"] for c in cases if check.evaluate(c, rules) != c["expect"]]
        killed += bool(hits)
        print(("killed " if hits else "ALIVE  ") + f"{name:45} by {','.join(hits) or '-'}")
    for name, fn in BEHAVIOR_M.items():
        rules = {k: (fn if k != "R-FRAME" else check.RULES["R-FRAME"])
                 for k in check.RULES}
        hits = [c["id"] for c in cases if check.evaluate(c, rules) != c["expect"]]
        killed += bool(hits)
        print(("killed " if hits else "ALIVE  ") + f"{name:45} by {','.join(hits) or '-'}")
    print(f"{killed}/{total} mutants killed")
    return 0 if killed == total else 1

if __name__ == "__main__":
    sys.exit(main())
