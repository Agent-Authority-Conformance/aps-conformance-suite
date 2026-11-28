#!/usr/bin/env python3
"""Phase-1 reader for aicent-grant-ref, written from sections 8.1 and 8.2 of
draft-li-rttp-iqa-addressing-02 (with sections 2, 6, 6.1, 6.2, 6.3 where
8.1/8.2 refer to them).  Standard library only.  Deterministic output.

usage: python3 -I check_reader.py <draft.txt> <cases.json> <out.json> [--sensitivity <sens.json>]

Every check cites a sentence of the draft; the program verifies that each cited
sentence occurs in the draft text (whitespace-normalised) and exits 3 if not.
"""
import json
import re
import sys

# ---------------------------------------------------------------- citations
S = {
    "8-two-fields": ("8", "An attestation response — the outcome of the verification of Section 7.2 as consumed by clients of Section 5.5 — carries two fields: a refusal reason and a grant reference."),
    "8.1-null": ("8.1", "The refusal reason is null when there is no refusal: the response is a permit, and the answer may be relied on under the rules of Section 6."),
    "8.1-no-granted": ("8.1", "A null refusal reason is the only representation of \"permitted\"; there is no affirmative \"granted\" value."),
    "8.1-priority": ("8.1", "For a refusal, the reason is exactly one value from the following closed set, and it is the first value in the list whose condition applies (the priority order is part of this definition):"),
    "8.1-ebm": ("8.1", "*evidence_binding_mismatch* — The presented evidence is bound to a different grant or subject than the one in the request."),
    "8.1-ee": ("8.1", "*evidence_expired* — The lease of the presented evidence has expired (Section 6.1)."),
    "8.1-and": ("8.1", "*authority_not_determined* — The authority for the subject could not be determined at answer time — because the organ or the authority source could not be reached, or because the only observation available predates the request and therefore establishes nothing about the present."),
    "8.1-ar": ("8.1", "*authority_revoked* — The authority for the subject has been revoked."),
    "8.1-onp": ("8.1", "*operation_not_permitted* — The requested operation is not permitted for this subject or grant, for reasons other than the four above."),
    "8.1-closed": ("8.1", "The set is closed: implementations MUST NOT emit values outside it, and MUST NOT reinterpret an emitted value to mean something else."),
    "8.1-reason-required": ("8.1", "A response that reports an outcome without its reason is not conformant: the reason is what makes a refusal auditable."),
    "8.1-computed-over": ("8.1", "For the same reason, a refusal reason MUST be computed over the authority facts the response carries — facts a third party can re- derive from pinned inputs."),
    "8.1-not-target": ("8.1", "A refusal computed over labels, opinions, or unrecorded context alone is not auditable, and producing one is not a conformance target of this section."),
    "8.2-every": ("8.2", "Every response — permit or refusal — names the authorisation it relied on."),
    "8.2-members": ("8.2", "The grant reference is a structure with the following members:"),
    "8.2-expires": ("8.2", "expires_at_ms grant expiry instant, Unix milliseconds"),
    "8.2-obs-def": ("8.2", "observation_as_of_ms the as-of instant of the standing observation the answer relied on, or null"),
    "8.2-obs-null": ("8.2", "*observation_as_of_ms is null whenever the observation the answer relied on is absent or not fresh*, even if a later, successful observation is available at answer time."),
    "8.2-no-backfill": ("8.2", "A diagnostic or opportunistic read performed after the relied-on evidence expired does not backfill the member: diagnostic reads do not participate in authorisation and do not renew evidence."),
    "8.2-race": ("8.2", "A revocation arriving just before or just after an invocation ends is a boundary no protocol erases; what the response owes the relying party is a legible record of it: the members above state when the authority-side facts were effective (issued_at_ms, expires_at_ms) and when they were observed (observation_as_of_ms)."),
}

CLOSED = ["evidence_binding_mismatch", "evidence_expired", "authority_not_determined",
          "authority_revoked", "operation_not_permitted"]
MEMBERS = ["grant", "evidence_id", "issued_at_ms", "expires_at_ms", "observation_as_of_ms"]
FACTS_81 = ("binding_mismatch", "evidence_expired", "authority", "operation_permitted")

# Every rule the checker implements.  Sensitivity runs remove or invert one.
RULES = ["R1-reason-present", "R2-closed-set", "R3-no-granted", "R4-priority",
         "R5-null-when-no-condition", "R6-refuse-when-condition", "R7-computed-over-facts",
         "R8-members-present", "R9-obs-null-when-absent-or-stale", "R10-obs-equals-relied-on",
         "R11-expires-equals-grant", "R12-race-observation-vs-revocation"]


# Rules for which an inversion is meaningful.  For R7 and R12 'invert' resolves
# the ambiguity to reading A (nonconformant); 'remove' corresponds to not scoring
# the part at all.  Other rules: inversion not meaningful, not run.
INVERTIBLE = {"R1-reason-present", "R4-priority", "R5-null-when-no-condition",
              "R7-computed-over-facts", "R9-obs-null-when-absent-or-stale",
              "R11-expires-equals-grant", "R12-race-observation-vs-revocation"}


def norm(t):
    return re.sub(r"\s+", " ", t).strip()


def verify_citations(draft_text):
    d = norm(draft_text)
    missing = [k for k, (_, s) in S.items() if norm(s) not in d]
    return missing


def cite(k):
    sec, s = S[k]
    return {"section": sec, "sentence": s}


# --------------------------------------------------------- 8.1 conditions
def conditions(inp):
    """Map the candidate's input fields to the five 8.1 conditions, in order."""
    a = inp.get("authority")
    return [
        ("evidence_binding_mismatch", inp.get("binding_mismatch") is True, "8.1-ebm"),
        ("evidence_expired", inp.get("evidence_expired") is True, "8.1-ee"),
        ("authority_not_determined", a in ("unreachable", "stale_observation"), "8.1-and"),
        ("authority_revoked", a == "revoked", "8.1-ar"),
        ("operation_not_permitted", inp.get("operation_permitted") is False, "8.1-onp"),
    ]


def has_81_facts(inp):
    return all(k in inp for k in FACTS_81)


# ----------------------------------------------------------------- checker
def check_case(case, mode=None):
    """mode: None (all rules as read), or (rule, 'remove'|'invert')."""
    def off(r):
        return mode is not None and mode[0] == r and mode[1] == "remove"

    def inv(r):
        return mode is not None and mode[0] == r and mode[1] == "invert"

    inp, out = case["input"], case["outcome"]
    checks = []

    def add(rule, k, held, detail):
        checks.append({"rule": rule, "cites": cite(k), "held": held, "detail": detail})

    reason_present = "reason" in out
    reason = out.get("reason")

    # R1: the response carries its reason.
    if not off("R1-reason-present"):
        if inv("R1-reason-present"):
            # inverted: an absent reason is read as null (permit)
            if not reason_present:
                reason_present, reason = True, None
            add("R1-reason-present", "8.1-reason-required", True, "inverted: absent reason read as null")
        else:
            add("R1-reason-present", "8.1-reason-required", reason_present,
                "reason key present" if reason_present else "outcome carries no reason")

    # R2: closed set.
    if reason_present and reason is not None and not off("R2-closed-set"):
        inset = reason in CLOSED
        add("R2-closed-set", "8.1-closed", (not inset) if inv("R2-closed-set") else inset,
            f"reason {reason!r} {'in' if inset else 'not in'} the closed set")

    # R3: no affirmative 'granted' value.
    if reason_present and not off("R3-no-granted"):
        g = reason == "granted"
        add("R3-no-granted", "8.1-no-granted", g if inv("R3-no-granted") else not g,
            f"reason is {reason!r}")

    # Required reason from the input facts (only when the input carries them).
    required, required_cite, applicable = None, None, []
    facts = has_81_facts(inp)
    if facts:
        conds = conditions(inp)
        applicable = [v for v, ok, _ in conds if ok]
        if applicable:
            if inv("R4-priority"):
                required = applicable[-1]
            else:
                required = applicable[0]
            required_cite = cite("8.1-priority")
        else:
            required_cite = cite("8.1-null")

        if reason_present:
            if applicable:
                if reason is None:
                    if not off("R6-refuse-when-condition"):
                        held = inv("R6-refuse-when-condition")
                        add("R6-refuse-when-condition", "8.1-priority", held,
                            f"conditions {applicable} apply; reason is null")
                elif reason in applicable or not off("R4-priority"):
                    if off("R4-priority"):
                        add("R4-priority", "8.1-priority", reason in applicable,
                            f"priority removed: reason {reason!r} accepted if its condition applies {applicable}")
                    else:
                        add("R4-priority", "8.1-priority", reason == required,
                            f"applicable {applicable}; required {required!r}; reason {reason!r}")
                else:
                    add("R4-priority", "8.1-priority", False,
                        f"priority removed; reason {reason!r} not among applicable {applicable}")
            else:
                if not off("R5-null-when-no-condition"):
                    held = reason is None
                    if inv("R5-null-when-no-condition"):
                        held = not held
                    add("R5-null-when-no-condition", "8.1-null", held,
                        f"no condition applies; reason {reason!r}")

    # R7: computed over the authority facts the response carries.
    if "computed_over" in out or "computed_over" in inp:
        co_in = inp.get("computed_over")
        co_out = out.get("computed_over")
        label_only = co_in in ("label", "opinion", "unrecorded_context") or (
            isinstance(co_out, str) and "not re-derivable" in co_out)
        if not off("R7-computed-over-facts") and label_only:
            held = False if inv("R7-computed-over-facts") else "ambiguous"
            add("R7-computed-over-facts", "8.1-computed-over", held,
                {"scored": "the basis the refusal was computed over",
                 "presented": co_out,
                 "reading_A": "the MUST in 8.1 is violated: nonconformant",
                 "reading_B": "the next sentence places such a refusal outside the conformance target of 8.1: the section assigns no verdict",
                 "also_cites": cite("8.1-not-target")})

    # R8: grant reference with all five members (absent key != null).
    gr = out.get("grant_ref")
    if not off("R8-members-present"):
        if gr is None:
            add("R8-members-present", "8.2-every", False, "no grant_ref")
        else:
            miss = [m for m in MEMBERS if m not in gr]
            if inv("R8-members-present"):
                add("R8-members-present", "8.2-members", True, f"inverted: missing {miss} read as null")
            else:
                add("R8-members-present", "8.2-members", not miss,
                    "all five members present" if not miss else f"missing members {miss}")
    gr = gr or {}

    # R9/R10: observation_as_of_ms against the relied-on observation.
    ro = inp.get("relied_on_observation")
    if isinstance(ro, dict) and "observation_as_of_ms" in gr:
        obs = gr["observation_as_of_ms"]
        stale_or_absent = (ro.get("present") is not True) or (ro.get("fresh") is not True)
        if stale_or_absent:
            if not off("R9-obs-null-when-absent-or-stale"):
                if inv("R9-obs-null-when-absent-or-stale"):
                    # inverted: report the freshest observation seen
                    cands = [x.get("as_of_ms") for x in (ro, inp.get("diagnostic_read") or {})
                             if isinstance(x, dict) and x.get("as_of_ms") is not None]
                    exp = max(cands) if cands else None
                    add("R9-obs-null-when-absent-or-stale", "8.2-obs-null", obs == exp,
                        f"inverted: expect freshest seen {exp}; got {obs}")
                else:
                    add("R9-obs-null-when-absent-or-stale", "8.2-obs-null", obs is None,
                        f"relied-on observation present={ro.get('present')} fresh={ro.get('fresh')}; member={obs}")
        else:
            if not off("R10-obs-equals-relied-on"):
                exp = ro.get("as_of_ms")
                add("R10-obs-equals-relied-on", "8.2-obs-def", obs == exp,
                    f"relied-on fresh as_of {exp}; member={obs}")

    # R11: expires_at_ms is the grant expiry instant.
    if "grant_expires_at_ms" in inp and "expires_at_ms" in gr and not off("R11-expires-equals-grant"):
        exp, got = inp["grant_expires_at_ms"], gr["expires_at_ms"]
        held = (got == exp)
        if inv("R11-expires-equals-grant"):
            held = not held
        add("R11-expires-equals-grant", "8.2-expires", held, f"grant expiry {exp}; member={got}")

    # R12: a revocation refusal whose stated observation predates the revocation.
    if (reason == "authority_revoked" and isinstance(inp.get("revoked_at_ms"), int)
            and isinstance(gr.get("observation_as_of_ms"), int)
            and not off("R12-race-observation-vs-revocation")):
        o, r = gr["observation_as_of_ms"], inp["revoked_at_ms"]
        if o < r:
            held = False if inv("R12-race-observation-vs-revocation") else "ambiguous"
            add("R12-race-observation-vs-revocation", "8.2-race", held,
                {"scored": "observation_as_of_ms against the revocation instant",
                 "presented": {"observation_as_of_ms": o, "revoked_at_ms": r},
                 "reading_A": "8.2 race paragraph: the record states when facts were observed; an observation predating the revocation is the legible boundary record: conformant",
                 "reading_B": "8.2 defines the member as the observation the answer relied on, and 8.1 requires the reason to be computed over facts the response carries; an observation at 1100 cannot establish a revocation at 1101: nonconformant",
                 "also_cites": [cite("8.2-obs-def"), cite("8.1-computed-over")]})
        else:
            add("R12-race-observation-vs-revocation", "8.2-race", True, f"observation {o} >= revocation {r}")

    helds = [c["held"] for c in checks]
    if any(h is False for h in helds):
        verdict = "nonconformant"
    elif any(h == "ambiguous" for h in helds):
        verdict = "ambiguous"
    else:
        verdict = "conformant"

    res = {
        "id": case["id"],
        "basis": case["basis"],
        "input_carries_8.1_facts": facts,
        "applicable_conditions": applicable,
        "required_reason": required if facts else "not computed: input carries no 8.1 facts",
        "required_reason_rests_on": required_cite,
        "checks": checks,
        "verdict": verdict,
    }
    if verdict == "ambiguous":
        res["ambiguous_parts"] = [
            {"rule": c["rule"], **c["detail"]} for c in checks if c["held"] == "ambiguous"]
        res["parts_scored"] = {c["rule"]: c["held"] for c in checks}
    return res


def run(cases, mode=None):
    return [check_case(c, mode) for c in cases]


def main(argv):
    if len(argv) not in (4, 6):
        print(__doc__, file=sys.stderr)
        return 2
    draft = open(argv[1], encoding="utf-8").read()
    missing = verify_citations(draft)
    if missing:
        print("cited sentences not found in draft:", missing, file=sys.stderr)
        return 3
    data = json.load(open(argv[2], encoding="utf-8"))
    cases = data["cases"]
    results = run(cases)
    tally = {v: sum(1 for r in results if r["verdict"] == v)
             for v in ("conformant", "nonconformant", "ambiguous")}
    doc = {"reader": "check_reader.py", "phase": 1, "draft_citations_verified": len(S),
           "rules": RULES, "tally": tally, "cases": results}
    with open(argv[3], "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    if len(argv) == 6 and argv[4] == "--sensitivity":
        base = {r["id"]: r["verdict"] for r in results}
        sens = []
        for rule in RULES:
            for how in ("remove",) + (("invert",) if rule in INVERTIBLE else ()):
                v = {r["id"]: r["verdict"] for r in run(cases, (rule, how))}
                changed = sorted(k for k in v if v[k] != base[k])
                sens.append({"rule": rule, "variant": how,
                             "changed": [{"id": k, "from": base[k], "to": v[k]} for k in changed]})
        with open(argv[5], "w", encoding="utf-8") as f:
            json.dump({"baseline": base, "variants": sens}, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
    print(json.dumps(tally, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
