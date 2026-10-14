# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Writes vectors.json for the arap-reevaluation-context candidate family.
# Deterministic: no clock, no randomness, no network.
# Run: python3 fixtures/arap-reevaluation-context/generate.py
import json
from pathlib import Path

OUT = Path(__file__).with_name("vectors.json")
SUBJ = {"type": "user", "id": "alice@example.com"}
RES = {"type": "document", "id": "q4-plan"}
ACT = {"name": "can_read"}
APPROVAL = {"id": "apr_01HX4Y8E2NE3Y2X7P0K4JE6WVH", "approved_at": "2026-04-30T20:42:00Z", "approved_until": "2026-05-01T00:42:00Z"}
BASE_RULES = [{"member": "project", "input": "task.project"}, {"member": "time", "input": "now"}]
MFA_RULES = BASE_RULES + [{"member": "mfa_session", "input": "session.mfa", "when": "session.active"}]
T1 = "2026-04-30T20:43:00Z"


def record(context, bound):
    return {"id": APPROVAL["id"], "taskId": "task-001", "subject": SUBJ, "resource": RES, "action": ACT,
            "context": context, "boundContextMembers": bound,
            "approvedAt": APPROVAL["approved_at"], "approvedUntil": APPROVAL["approved_until"], "status": "active"}


REC = record({"project": "customer-renewal", "time": "2026-04-30T20:15:00Z"}, ["project"])
REC_MFA = record({"project": "customer-renewal", "time": "2026-04-30T20:15:00Z", "mfa_session": "mfa-7f3"}, ["project", "mfa_session"])


def case(id, label, section, pep, rules, inputs, rec, now, build, outcome, next_action, members, **extra):
    c = {"id": id, "label": label, "section": section, "pep": pep, "rules": rules, "inputs": inputs, "record": rec,
         "approval": APPROVAL, "now": now,
         "expected": {"build": build, "outcome": outcome, "next_action": next_action, "member_sets_match": members}}
    c["expected"].update(extra)
    return c


CASES = [
    case("R1", "ordinary rules: the bound project is kept and time is refreshed, the approval applies",
         "approval-reevaluation-request (822-824), approval-scope (976-982)", "ordinary-rules", BASE_RULES,
         {"task.project": "customer-renewal", "now": T1}, REC, T1, "request", "approval_applies", None, True),
    case("R2", "approval-only PEP, the shape #663 reported: project is dropped, out_of_scope",
         "approval-reevaluation-request (824), approval-scope (982)", "approval-only", BASE_RULES,
         {"task.project": "customer-renewal", "now": T1}, REC, T1, "request", "out_of_scope", "request", False),
    case("R3", "ordinary rules, the bound project changed in the task: not the approved request, out_of_scope",
         "approval-reevaluation-request (824)", "ordinary-rules", BASE_RULES,
         {"task.project": "other-project", "now": T1}, REC, T1, "request", "out_of_scope", "request", True),
    case("R4", "ordinary rules, a later re-evaluation: time is a current observation, obtained fresh, the approval applies",
         "approval-reevaluation-request (824), structural-comparison (737)", "ordinary-rules", BASE_RULES,
         {"task.project": "customer-renewal", "now": "2026-04-30T23:00:00Z"}, REC, "2026-04-30T23:00:00Z",
         "request", "approval_applies", None, True, time="2026-04-30T23:00:00Z"),
    case("R5", "ordinary rules, the task input for project is unreachable: the PEP stops and sends nothing",
         "approval-reevaluation-request (826)", "ordinary-rules", BASE_RULES,
         {"now": T1}, REC, T1, "stop", None, None, True, unreachable="task.project"),
    case("R5b", "approval-only PEP with the same unreachable input: it sends a request anyway, out_of_scope",
         "approval-reevaluation-request (826)", "approval-only", BASE_RULES,
         {"now": T1}, REC, T1, "request", "out_of_scope", "request", False),
    case("R6", "a conditional member the ordinary rules now omit (session ended), not bound: the omission is permitted, the approval applies",
         "approval-reevaluation-request (824)", "ordinary-rules", MFA_RULES,
         {"task.project": "customer-renewal", "now": T1, "session.active": False, "session.mfa": "mfa-7f3"},
         REC, T1, "request", "approval_applies", None, True),
    case("R7", "the same conditional member, bound: the ordinary rules omit it, so a bound member is absent, out_of_scope",
         "approval-reevaluation-request (824, 826), approval-scope (982)", "ordinary-rules", MFA_RULES,
         {"task.project": "customer-renewal", "now": T1, "session.active": False, "session.mfa": "mfa-7f3"},
         REC_MFA, T1, "request", "out_of_scope", "request", True),
]

VECTORS = {
    "family": "arap-reevaluation-context",
    "version": "0.1.0",
    "status": "candidate against a proposed, unmerged pull request",
    "source": {
        "repository": "openid/authzen",
        "pull_request": 745,
        "head": "9bd238a0c7c1a97e1c812de56c31755a4cdf5b12",
        "applied_locally_to_main": "4deba63afa25e8a1d99f888a85cb64951ac83e37",
        "file": "profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md",
        "head_file_sha256": "edd6316c922c5c6f4acef6e663bde8016d795602130202c317d55297df46e4ee",
        "locally_applied_file_sha256": "f4a51e500faaf90bab4329851a9f71e46b17ad93dc65805fd7a9ff15f92f02a6",
        "line_numbers": "the file with the pull request applied locally to main, a trial merge, not an upstream merge",
    },
    "pdp_id": "https://pdp.example.com",
    "cases": CASES,
    "negative_controls": {
        "present_only_pdp": {
            "applies_to": "the PDP outcome of every case that sends a request",
            "declared_to_fail": ["R2", "R5b", "R7"],
            "defect": "Skips a bound member that is absent from the request instead of comparing it, which 982 rules out.",
        },
        "approval_tampering_peps": {
            "applies_to": "every ordinary-rules case that sends a request, rerun with each of four PEPs: drop-approval, changed-approval-id, changed-approval-timestamp, in-place-approval-rewrite",
            "declared_to_fail": ["R1", "R3", "R4", "R6", "R7"],
            "defect": ("Leaves the approval out, changes its id, rewrites approved_until in a copy, or rewrites approved_at "
                       "in place on the object it was handed, which 822 rules out. The runner compares the emitted approval "
                       "with its own pristine copy and passes the emitted one to the PDP."),
        },
        "alternating_pep": {
            "applies_to": "every ordinary-rules case that sends a request, with a fresh alternating PEP per case",
            "declared_to_fail": ["R1", "R3", "R4", "R6", "R7"],
            "defect": ("Its first request carries a member no ordinary rule produces and its later requests are clean. "
                       "The member is unbound, so the PDP outcome does not change. The runner calls the PEP once and "
                       "runs the member-set test on that emitted request."),
        },
        "approval_only_pep": {
            "applies_to": "every ordinary-rules case, rerun with the approval-only PEP",
            "declared_to_fail": ["R1", "R3", "R4", "R5", "R6", "R7"],
            "defect": ("Builds re-evaluation Context from the approval and time only, which 824 rules out. "
                       "In R3 and R7 the PDP outcome is the same either way, and the member-set comparison still catches it."),
        },
    },
}

if __name__ == "__main__":
    OUT.write_text(json.dumps(VECTORS, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT.name}: {len(CASES)} cases")
