#!/usr/bin/env python3
"""Checker for the aicent-lease-boundary cases.

Written from the text of draft-li-rttp-iqa-addressing-02, sections 6.1, 6.2,
6.3 and the verification procedure of 7.2, and from sections 8.1, 9.2 and the
terminology of section 2 where those sections refer to them. It reads the blind
case file (basis, input, outcome) and the draft. Standard library only.

Usage:
  python3 -B reader/checker.py --draft DRAFT --cases CASES --out OUT --sensitivity SENS
"""
import argparse
import hashlib
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Citations. Each is checked at start-up to occur verbatim in the draft after
# whitespace is normalised (every run of whitespace becomes one space).
# ---------------------------------------------------------------------------
CITES = {
    "C2-grant-ref": ("2", "*grant reference* — The structure by which an attestation response names the authorisation it relied on (Section 8.2)."),
    "C61-inband": ("6.1", "Every attestation answer produced under the iqa scheme carries its freshness window in-band: the answer states the instant until which it may be relied on, in a field of the answer itself (the lease_expiry field of Section 7.2), not in a cache header, a lookup result, or an out-of-band agreement."),
    "C61-clock": ("6.1", "A verifier checks the stated expiry against its own clock."),
    "C61-expired": ("6.1", "An answer whose lease has expired MUST be treated as expired; a verifier MUST NOT extend, renew, or reinterpret an expired lease except by obtaining a new answer."),
    "C61-120": ("6.1", "Current deployments use 120 seconds."),
    "C61-other-windows": ("6.1", "Operators MAY configure other window lengths; the mechanism does not depend on this value."),
    "C61-boundary": ("6.1", "Whether the lease instant itself counts as fresh or as expired is a deployment convention; implementations SHOULD declare which boundary they use, and conformance material MAY test both."),
    "C62-declare-mode": ("6.2", "A deployment declares one of two modes for standing reads, and each run or deployment SHOULD state which mode it operates in."),
    "C62-cached-def": ("6.2", "The verifier relies on a previously obtained answer whose lease (Section 6.1) has not expired, checked locally and offline: establishing that the evidence is fresh requires no network call, and this property is the design point of the mode, not a degradation."),
    "C62-as-of": ("6.2", "A cached answer is, however, as-of an earlier instant: it does not by itself establish the subject's current validity, and the mode makes no claim that it does."),
    "C62-policy": ("6.2", "Whether an action proceeds on lease-fresh evidence is decided by the calling layer's action policy, not by this document: a policy that demands a current observation refuses the call with authority_not_determined (Section 8.1); a policy that accepts lease-fresh evidence may admit it, with any exposure bounded by the lease itself."),
    "C62-live-def": ("6.2", "The verifier consults the named organ at the time of each request."),
    "C62-live-closed": ("6.2", "If the organ cannot be reached, the read fails closed: an organ that cannot be reached is not read as silent consent."),
    "C62-live-refused": ("6.2", "Every call in this mode is expected to be refused when the organ is unreachable, regardless of the age of any cached answer."),
    "C62-both": ("6.2", "In both modes the following rules are normative: an answer whose lease has expired MUST be refused; and an organ that cannot be reached MUST NOT be read as affirmative standing (Section 9.2)."),
    "C63-expired": ("6.3", "An answer read past its expiry MUST be answered as expired (Section 8.1), never replayed as fresh."),
    "C72-table": ("7.2", "the instant until which the answer counts as fresh (Section 6.1)"),
    "C72-step2": ("7.2", "(2) rejects the frame if lease_expiry is earlier than the current time, checked against the receiver's own clock (Section 6.1);"),
    "C81-null": ("8.1", "The refusal reason is null when there is no refusal: the response is a permit, and the answer may be relied on under the rules of Section 6."),
    "C81-first": ("8.1", "For a refusal, the reason is exactly one value from the following closed set, and it is the first value in the list whose condition applies (the priority order is part of this definition):"),
    "C81-ee": ("8.1", "*evidence_expired* — The lease of the presented evidence has expired (Section 6.1)."),
    "C81-and": ("8.1", "*authority_not_determined* — The authority for the subject could not be determined at answer time — because the organ or the authority source could not be reached, or because the only observation available predates the request and therefore establishes nothing about the present."),
    "C81-and-assent": ("8.1", "An unreachable source is refused under this value, never read as assent."),
    "C81-closed": ("8.1", "The set is closed: implementations MUST NOT emit values outside it, and MUST NOT reinterpret an emitted value to mean something else."),
    "C81-without-reason": ("8.1", "A response that reports an outcome without its reason is not conformant: the reason is what makes a refusal auditable."),
    "C81-facts": ("8.1", "For the same reason, a refusal reason MUST be computed over the authority facts the response carries — facts a third party can re- derive from pinned inputs."),
    "C92-silence": ("9.2", "An endpoint that is unreachable, times out, or returns an error MUST NOT be read as affirmative standing: absence of evidence is not evidence of compliance."),
}


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def verify_citations(text):
    t = norm(text)
    missing = [k for k, (_, s) in CITES.items() if norm(s) not in t]
    if missing:
        sys.stderr.write("citation not found verbatim in the draft: %s\n" % ", ".join(missing))
        sys.exit(3)
    return len(CITES)


def section_text(text, number, title):
    """Return the body of a numbered section, from its heading to the next heading."""
    m = re.search(r"^%s\.\s+%s\s*$" % (re.escape(number), re.escape(title)), text, re.M)
    if not m:
        sys.stderr.write("section %s not found\n" % number)
        sys.exit(3)
    nxt = re.search(r"^\d+(\.\d+)*\.\s+\S", text[m.end():], re.M)
    return text[m.end(): m.end() + nxt.start()] if nxt else text[m.end():]


def derive_from_text(text):
    """Values read out of the draft rather than written into the checker."""
    s81 = section_text(text, "8.1", "Refusal Reasons")
    order = re.findall(r"^\s+\*([a-z_]+)\* —", s81, re.M)
    s61 = section_text(text, "6.1", "The Lease")
    w = re.search(r"Current deployments use (\d+) seconds\.", norm(s61))
    if not order or not w:
        sys.stderr.write("could not derive the refusal set or window from the draft\n")
        sys.exit(3)
    return order, int(w.group(1))


# ---------------------------------------------------------------------------
# Mapping of the candidate's input field names to conditions of the text.
# Every entry is a choice of this run; see the ambiguity log.
# ---------------------------------------------------------------------------
FIELD_MAP = {
    "now_ms": "the verifier's own clock at answer time (C61-clock, C72-step2), in milliseconds",
    "lease_expiry_ms": "the stated lease_expiry of the answer (C61-inband, C72-table), in milliseconds rather than Unix seconds",
    "issued_at_ms": "the instant the answer was issued; the text has no such field in the envelope and the checker does not use it except in the R02 inverted variant (C61-120, C61-other-windows)",
    "grace_added": "true: the verifier extended the lease locally beyond the stated expiry (C61-expired, 'MUST NOT extend')",
    "declared_boundary": "the boundary convention the deployment declares under C61-boundary: 'fresh_at_instant', 'expired_at_instant', or null for not declared",
    "at_boundary": "true: the verifier's clock equals the stated lease instant",
    "frame_accepted_at_equality": "true: the envelope verification of 7.2 step (2) accepted the frame at equality (C72-step2)",
    "mode": "the declared answer mode of 6.2: 'live' = live-standing-read mode, 'cached' = cached-lease mode (C62-declare-mode)",
    "organ_unreachable": "true: the named organ cannot be reached at answer time (C62-live-closed, C62-both, C81-and, C92-silence)",
    "cache_fresh": "true: the lease of the cached answer has not expired (C62-cached-def); false: it has expired (C62-both)",
    "policy": "the calling layer's action policy of C62-policy: 'current' = demands a current observation; 'lease_fresh' = accepts lease-fresh evidence",
}
OUTCOME_MAP = {
    "reason": "the refusal reason of 8.1; null is a permit (C81-null); an absent key means no reason is reported (C81-without-reason)",
    "grant_ref": "taken as the authority facts the response carries (C81-facts); its members are defined in section 8.2, which was not read, so only its presence is scored",
    "lease_note": "part of the record the outcome presents; not scored as a string; the extension it describes is scored from the input fact grace_added",
}

RULES = {
    "R01-expired-refused": ("an expired lease requires a refusal with evidence_expired", ["C61-expired", "C62-both", "C63-expired", "C81-ee"], ["removed"]),
    "R02-stated-expiry": ("freshness is judged from the stated lease_expiry, not from issuance plus a fixed window", ["C61-inband", "C61-clock", "C61-other-windows"], ["inverted"]),
    "R03-strict-compare": ("expired iff the stated expiry is earlier than the clock (equality is decided by R05 to R07)", ["C72-step2"], ["inverted"]),
    "R04-no-extend": ("a local grace period does not change the lease", ["C61-expired"], ["removed"]),
    "R05-declared-boundary": ("at the lease instant the declared boundary convention decides fresh or expired", ["C61-boundary"], ["removed", "inverted"]),
    "R06-boundary-vs-7.2": ("declared expired_at_instant with the frame accepted at equality admits two readings", ["C61-boundary", "C72-step2", "C72-table"], ["removed", "inverted"]),
    "R07-undeclared-boundary": ("at the lease instant with no declared convention, fresh and expired are both readings", ["C61-boundary", "C72-step2"], ["removed", "inverted"]),
    "R08-live-fail-closed": ("live mode with the organ unreachable requires a refusal with authority_not_determined", ["C62-live-closed", "C62-live-refused", "C62-both", "C81-and", "C81-and-assent", "C92-silence"], ["removed"]),
    "R09-cached-policy": ("cached mode, lease fresh: policy 'current' requires authority_not_determined; policy 'lease_fresh' may admit", ["C62-policy"], ["removed", "inverted"]),
    "R10-cached-admit-specific": ("in cached mode the may-admit of C62-policy governs over the general unreachable rules", ["C62-policy", "C62-cached-def", "C62-both", "C81-and-assent"], ["inverted"]),
    "R11-priority": ("of the refusal conditions that apply, the first in the 8.1 list is the reason", ["C81-first"], ["removed", "inverted"]),
    "R12-condition-holds": ("a refusal reason may be emitted only where its condition applies", ["C81-first", "C81-closed"], ["removed"]),
    "R13-reason-present": ("the response carries the reason member", ["C81-without-reason"], ["removed"]),
    "R14-closed-set": ("the reason is null or a value of the closed set", ["C81-closed"], ["removed"]),
    "R15-grant-ref-present": ("the response carries the authority facts it was computed over (grant_ref)", ["C81-facts", "C2-grant-ref"], ["removed"]),
}


def lease_readings(inp, st, window_s):
    """Return a list of (reading label, expired) or [] when the input states no lease fact."""
    if "now_ms" in inp and "lease_expiry_ms" in inp:
        exp = inp["lease_expiry_ms"]
        if st["R02-stated-expiry"] == "inv" and "issued_at_ms" in inp:
            exp = inp["issued_at_ms"] + window_s * 1000
        if inp.get("grace_added") and st["R04-no-extend"] == "off":
            return [("grace period honoured", False)]
        now = inp["now_ms"]
        expired = (exp <= now) if st["R03-strict-compare"] == "inv" else (exp < now)
        return [("stated expiry against the clock", expired)]
    if inp.get("at_boundary"):
        decl = inp.get("declared_boundary")
        if st["R05-declared-boundary"] == "off":
            return [("7.2 step (2): not earlier, frame accepted, fresh", False)]
        if st["R05-declared-boundary"] == "inv" and decl in ("fresh_at_instant", "expired_at_instant"):
            decl = "expired_at_instant" if decl == "fresh_at_instant" else "fresh_at_instant"
        if decl == "fresh_at_instant":
            return [("declared fresh_at_instant", False)]
        if decl == "expired_at_instant":
            if inp.get("frame_accepted_at_equality"):
                r = st["R06-boundary-vs-7.2"]
                if r == "off":
                    return [("6.1 declared convention governs", True)]
                if r == "inv":
                    return [("7.2 step (2) acceptance at equality governs", False)]
                return [("6.1 declared convention governs: expired", True),
                        ("7.2 step (2) acceptance at equality governs: fresh", False)]
            return [("declared expired_at_instant", True)]
        r = st["R07-undeclared-boundary"]
        if r == "off":
            return [("7.2 step (2) as the default: fresh", False)]
        if r == "inv":
            return [("undeclared convention taken as expired", True)]
        return [("7.2 step (2) as the default: fresh", False),
                ("undeclared convention may be expired_at_instant: expired", True)]
    if "cache_fresh" in inp:
        return [("cached answer lease", not inp["cache_fresh"])]
    return []


def requirement(inp, expired, st, order):
    """Allowed reason values for one reading, and the citations they rest on."""
    applicable, required, rests = [], False, []
    if expired and st["R01-expired-refused"] == "on":
        applicable.append("evidence_expired"); required = True
        rests += RULES["R01-expired-refused"][1]
    mode, unreach = inp.get("mode"), inp.get("organ_unreachable")
    if unreach and mode == "live" and st["R08-live-fail-closed"] == "on":
        applicable.append("authority_not_determined"); required = True
        rests += RULES["R08-live-fail-closed"][1]
    if unreach and mode == "cached" and expired:
        # the organ cannot be reached, so the condition of authority_not_determined
        # applies as well; the refusal is already required by R01
        applicable.append("authority_not_determined")
        rests += ["C81-and"]
    if unreach and mode == "cached" and not expired:
        pol = inp.get("policy")
        if st["R09-cached-policy"] == "inv":
            pol = {"current": "lease_fresh", "lease_fresh": "current"}.get(pol, pol)
        if st["R10-cached-admit-specific"] == "inv":
            applicable.append("authority_not_determined"); required = True
            rests += RULES["R10-cached-admit-specific"][1]
        elif st["R09-cached-policy"] != "off":
            if pol == "current":
                applicable.append("authority_not_determined"); required = True
            elif pol == "lease_fresh":
                applicable.append("authority_not_determined")  # condition applies; admission allowed
            rests += RULES["R09-cached-policy"][1]
    prio = list(order)
    if st["R11-priority"] == "inv":
        prio = prio[::-1]
    applicable = sorted(set(applicable), key=prio.index)
    if applicable:
        if st["R11-priority"] == "off":
            refusals = applicable
        else:
            refusals = applicable[:1]
            if len(applicable) > 1:
                rests += RULES["R11-priority"][1]
    else:
        refusals = []
    allowed = list(refusals) + ([] if required else [None])
    if st["R12-condition-holds"] == "off":
        allowed += [v for v in order if v not in allowed]
    if not applicable:
        rests += ["C81-null"]
    return allowed, required, sorted(set(rests))


def judge(case, st, order, window_s):
    inp, out = case["input"], case["outcome"]
    readings = lease_readings(inp, st, window_s) or [("no lease fact stated", False)]
    per_reading = []
    for label, expired in readings:
        allowed, required, rests = requirement(inp, expired, st, order)
        checks = []
        if st["R13-reason-present"] == "on":
            checks.append({"check": "reason member present", "rests_on": ["C81-without-reason"], "held": "reason" in out})
        reason = out.get("reason")
        if st["R14-closed-set"] == "on":
            checks.append({"check": "reason is null or in the closed set", "rests_on": ["C81-closed"],
                           "held": reason is None or reason in order})
        checks.append({"check": "reason is one of %s" % json.dumps(allowed), "rests_on": rests,
                       "held": ("reason" in out or st["R13-reason-present"] == "off") and reason in allowed})
        if st["R15-grant-ref-present"] == "on":
            checks.append({"check": "grant_ref member present", "rests_on": ["C81-facts", "C2-grant-ref"],
                           "held": isinstance(out.get("grant_ref"), dict)})
        verdict = "conformant" if all(c["held"] for c in checks) else "nonconformant"
        per_reading.append({"reading": label, "lease_expired": expired, "allowed_reason": allowed,
                            "refusal_required": required, "checks": checks, "verdict": verdict})
    vs = {r["verdict"] for r in per_reading}
    verdict = vs.pop() if len(vs) == 1 else "ambiguous"
    return verdict, per_reading


def answer_mode(inp):
    return {"live": "live-standing-read", "cached": "cached-lease"}.get(inp.get("mode"), "not stated in the input")


def run(cases, order, window_s, st):
    res = {}
    for c in cases:
        res[c["id"]] = judge(c, st, order, window_s)
    return res


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--draft", required=True)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sensitivity", required=True)
    a = ap.parse_args()
    with open(a.draft, encoding="utf-8") as f:
        text = f.read()
    n_cites = verify_citations(text)
    order, window_s = derive_from_text(text)
    with open(a.cases, encoding="utf-8") as f:
        blind = json.load(f)
    cases = blind["cases"]

    base = {k: "on" for k in RULES}
    results = run(cases, order, window_s, base)

    out_cases = []
    for c in cases:
        verdict, per = results[c["id"]]
        entry = {
            "id": c["id"], "basis": c["basis"],
            "requires": {
                "answer_mode": answer_mode(c["input"]),
                "mode_rests_on": ["C62-declare-mode"] + (["C62-live-def"] if c["input"].get("mode") == "live" else ["C62-cached-def"] if c["input"].get("mode") == "cached" else []),
                "members": ["reason (C81-without-reason)", "grant_ref (C81-facts, C2-grant-ref; mapping chosen in this run)"],
                "readings": [{"reading": r["reading"], "lease_expired": r["lease_expired"],
                              "reason_allowed": r["allowed_reason"], "refusal_required": r["refusal_required"]} for r in per],
            },
            "checks": per,
            "verdict": verdict,
        }
        if verdict == "ambiguous":
            parts = {}
            for r in per:
                for ch in r["checks"]:
                    parts.setdefault(ch["check"].split(" is one of ")[0] if " is one of " in ch["check"] else ch["check"], []).append(ch["held"])
            scored = {k: ("held" if all(v) else "failed" if not any(v) else "ambiguous") for k, v in parts.items()}
            entry["ambiguous_detail"] = {
                "parts_scored": scored,
                "ambiguous_part": [k for k, v in scored.items() if v == "ambiguous"],
                "readings": [{"reading": r["reading"], "verdict": r["verdict"]} for r in per],
            }
        out_cases.append(entry)
    tally = {v: sum(1 for e in out_cases if e["verdict"] == v) for v in blind["verdicts"]}
    doc = {
        "record": "phase 1, blind",
        "inputs": {"draft": {"file": os.path.basename(a.draft), "sha256": sha(a.draft)},
                   "cases": {"file": os.path.basename(a.cases), "sha256": sha(a.cases)}},
        "citations_verified": n_cites,
        "citations": {k: {"section": s, "text": t} for k, (s, t) in CITES.items()},
        "derived_from_text": {"refusal_set_in_priority_order": order, "stated_deployment_window_seconds": window_s},
        "input_field_mapping": FIELD_MAP,
        "outcome_field_mapping": OUTCOME_MAP,
        "rules": {k: {"rule": v[0], "rests_on": v[1]} for k, v in RULES.items()},
        "cases": out_cases,
        "tally": tally,
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")

    base_v = {k: v[0] for k, v in results.items()}
    variants = []
    for rule, (desc, rests, kinds) in RULES.items():
        for kind in kinds:
            st = dict(base); st[rule] = "off" if kind == "removed" else "inv"
            vr = run(cases, order, window_s, st)
            changed = {cid: {"from": base_v[cid], "to": vr[cid][0]} for cid in sorted(vr) if vr[cid][0] != base_v[cid]}
            variants.append({"rule": rule, "variant": kind, "changed": changed, "n_changed": len(changed)})
    sens = {"record": "phase 1 sensitivity", "baseline": base_v, "variants": variants,
            "rules_no_case_depends_on": sorted({v["rule"] for v in variants} - {v["rule"] for v in variants if v["n_changed"]})}
    with open(a.sensitivity, "w", encoding="utf-8") as f:
        json.dump(sens, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    print("citations verified: %d" % n_cites)
    print("tally: " + ", ".join("%s %d" % (k, v) for k, v in tally.items()))
    for e in out_cases:
        print("%s %s" % (e["id"], e["verdict"]))


if __name__ == "__main__":
    main()
