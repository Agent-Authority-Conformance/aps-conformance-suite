#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Independent Python runner for the conflicting-status-sources family.

Written from README.md and vectors.json rather than by porting harness.ts:
the decision procedure below is reimplemented from the family's stated rules,
and the canonicalizer is written against RFC 8785 rather than reused from the
TypeScript side. Agreement between the two runners is what the family is for.

Standard library only. No network, no wall-clock read, no third-party package.
It is a manual run, not part of `npm test`, following this suite's existing
convention that the hermetic gate stays Node only.

    python3 fixtures/conflicting-status-sources/verify.py

Exit 0 when every boundary matches and every control fails exactly its
declared set, 1 otherwise.

JCS subset. This canonicalizer covers objects, arrays, strings, booleans,
null and integers, which is every value shape a status-observation record
holds. A float or a non-finite number raises rather than being serialized,
because the record domain has none and guessing at ECMAScript number
formatting here would be a silent source of byte divergence.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------- JCS subset

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t",
            "\b": "\\b", "\f": "\\f"}


def _jcs_string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("this record domain holds no floats")
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(value[k]) for k in keys) + "}"
    raise TypeError(f"unsupported type {type(value)}")


def record_digest(record) -> str:
    return hashlib.sha256(jcs(record).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- the model

def parse_instant(value: str) -> int:
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def age_seconds(as_of: str, evaluated_at: str) -> int:
    delta = parse_instant(evaluated_at) - parse_instant(as_of)
    return 0 if delta < 0 else delta // 1000


REFERENCE = {
    "name": "reference-verifier",
    "disagreement": "conflict",
    "revoked_is_sticky": True,
    "coverage_basis": "declared",
    "records_snapshot_basis": True,
}
LATEST_ANSWER_WINS = {**REFERENCE, "name": "latest-answer-wins", "disagreement": "latest_wins"}
DROP_STALE_THEN_DECIDE = {
    **REFERENCE,
    "name": "drop-stale-then-decide",
    "revoked_is_sticky": False,
    "coverage_basis": "arrived",
}
OFFLINE_ADMIT_WITHOUT_RECORDING = {
    **REFERENCE,
    "name": "offline-admit-without-recording",
    "records_snapshot_basis": False,
}

POLICIES = {
    p["name"]: p
    for p in (LATEST_ANSWER_WINS, DROP_STALE_THEN_DECIDE, OFFLINE_ADMIT_WITHOUT_RECORDING)
}


def evaluate_boundary(boundary, delegation_ref, policy, prior_digest):
    tp = boundary["trust_policy"]
    declared = {s["source_id"]: s for s in tp["required_sources"]}
    snapshot_source = tp.get("snapshot_source")
    if snapshot_source:
        declared[snapshot_source["source_id"]] = snapshot_source

    recorded = []
    for obs in boundary["observations"]:
        source = declared.get(obs["source_id"])
        if source is None:
            raise ValueError(f"observation from undeclared source {obs['source_id']}")
        is_offline_snapshot = (
            tp["mode"] == "offline"
            and snapshot_source is not None
            and snapshot_source["source_id"] == obs["source_id"]
        )
        bound = (
            tp.get("declared_offline_bound_s", source["freshness_bound_s"])
            if is_offline_snapshot
            else source["freshness_bound_s"]
        )
        as_of = obs.get("as_of")
        age = None if as_of is None else age_seconds(as_of, boundary["evaluated_at"])
        within = age is not None and age <= bound

        if obs["answer"] == "unavailable":
            used, basis = False, "source_gave_no_answer"
        elif obs["answer"] == "revoked" and not within and policy["revoked_is_sticky"]:
            used, basis = True, "revocation_observed_outside_bound_still_used"
        elif within:
            used, basis = True, "within_freshness_bound"
        else:
            used, basis = False, "stale_beyond_bound"

        recorded.append({
            "source_id": obs["source_id"],
            "answer": obs["answer"],
            "as_of": as_of,
            "age_s": age,
            "freshness_bound_s": bound,
            "within_bound": within,
            "used": used,
            "use_basis": basis,
        })
    recorded.sort(key=lambda r: r["source_id"])

    used_determinate = [r for r in recorded if r["used"] and r["answer"] != "unavailable"]
    states = sorted({r["answer"] for r in used_determinate})

    required_ids = [s["source_id"] for s in tp["required_sources"]]
    usable_required = [
        sid for sid in required_ids
        if any(r["source_id"] == sid and r["used"] and r["answer"] != "unavailable"
               for r in recorded)
    ]
    if policy["coverage_basis"] == "declared":
        coverage = {
            "required": len(required_ids),
            "usable_determinate": len(usable_required),
            "complete": len(usable_required) == len(required_ids),
        }
    else:
        coverage = {
            "required": len(required_ids),
            "usable_determinate": len(used_determinate),
            "complete": len(used_determinate) > 0,
        }

    silent_required = [
        sid for sid in required_ids
        if not any(r["source_id"] == sid for r in recorded)
    ]
    stale_required = [
        sid for sid in required_ids
        if any(r["source_id"] == sid and not r["used"] and r["answer"] != "unavailable"
               for r in recorded)
    ]

    snapshot_line = None
    if tp["mode"] == "offline" and snapshot_source is not None:
        snapshot_line = next(
            (r for r in recorded if r["source_id"] == snapshot_source["source_id"]), None
        )

    state = {"snapshot": None}

    def write(decision, reason, conflict):
        return {
            "record_type": "aac.status-observation-record.v0",
            "boundary_id": boundary["boundary_id"],
            "delegation_ref": delegation_ref,
            "evaluated_at": boundary["evaluated_at"],
            "verifier_mode": tp["mode"],
            "decision": decision,
            "reason": reason,
            "required_sources": required_ids,
            "sources_consulted": recorded,
            "coverage": coverage,
            "conflict": conflict,
            "snapshot": state["snapshot"],
            "prior_record_sha256": prior_digest,
        }

    if len(states) > 1:
        if policy["disagreement"] == "conflict":
            return write("deny", "status_sources_conflict", {
                "states": states,
                "sources": sorted(r["source_id"] for r in used_determinate),
            })
        newest = sorted(
            (r for r in used_determinate if r["as_of"] is not None),
            key=lambda r: parse_instant(r["as_of"]),
            reverse=True,
        )
        if newest and newest[0]["answer"] == "revoked":
            return write("deny", "status_revoked", None)
        if newest and newest[0]["answer"] == "active":
            return write("admit", "status_active_all_sources_agree", None)

    if states == ["revoked"]:
        return write("deny", "status_revoked", None)

    if not states:
        if tp["mode"] == "offline" and snapshot_line is not None:
            return write("not_established", "status_stale_beyond_bound", None)
        return write("not_established", "status_no_usable_observation", None)

    if tp["mode"] == "offline" and snapshot_source is not None and snapshot_line \
            and snapshot_line["used"]:
        if policy["records_snapshot_basis"]:
            state["snapshot"] = {
                "source_id": snapshot_line["source_id"],
                "as_of": snapshot_line["as_of"],
                "age_s": snapshot_line["age_s"],
                "declared_bound_s": tp.get(
                    "declared_offline_bound_s", snapshot_line["freshness_bound_s"]
                ),
            }
        return write("admit", "admitted_on_snapshot_within_declared_bound", None)

    if not coverage["complete"]:
        if silent_required:
            return write("not_established", "status_coverage_incomplete", None)
        if stale_required:
            return write("not_established", "status_stale_beyond_bound", None)
        return write("not_established", "status_no_usable_observation", None)

    return write("admit", "status_active_all_sources_agree", None)


def evaluate_case(case, delegation_ref, policy):
    records = []
    for boundary in case["boundaries"]:
        prior = boundary["prior_record_sha256"]
        if prior == "PRIOR":
            prior = record_digest(records[-1])
        records.append(evaluate_boundary(boundary, delegation_ref, policy, prior))
    return records


# ---------------------------------------------------------------- the run

def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
    chain = json.loads((HERE / "chain.json").read_text(encoding="utf-8"))
    delegation_ref = vectors["delegation_ref"]
    failures = []

    if chain["chain"][0]["delegation_id"] != delegation_ref:
        failures.append("delegation_ref does not match chain.json root")

    def diverged(case, policy):
        try:
            records = evaluate_case(case, delegation_ref, policy)
        except Exception as err:  # a throw is a divergence, not a crash
            return [f"{case['id']}: threw under {policy['name']}: {err}"]
        out = []
        for boundary, record in zip(case["boundaries"], records):
            want = boundary["expected"]
            got_digest = record_digest(record)
            if (record["decision"] != want["decision"]
                    or record["reason"] != want["reason"]
                    or got_digest != want["canonical_sha256"]
                    or len(jcs(record).encode("utf-8")) != want["canonical_bytes_len"]):
                out.append(
                    f"{boundary['boundary_id']}: want {want['decision']}/{want['reason']} "
                    f"sha256={want['canonical_sha256'][:16]}, got "
                    f"{record['decision']}/{record['reason']} sha256={got_digest[:16]}"
                )
        return out

    boundary_count = 0
    for case in vectors["cases"]:
        if case["label"] != "candidate_against_proposed":
            failures.append(f"{case['id']}: label is {case['label']}")
        for line in diverged(case, REFERENCE):
            failures.append(f"reference-verifier {line}")

        records = evaluate_case(case, delegation_ref, REFERENCE)
        for index, (boundary, record) in enumerate(zip(case["boundaries"], records)):
            boundary_count += 1
            want = boundary["expected"]
            if want["decision"] != "admit" and record["decision"] == "admit":
                failures.append(
                    f"{boundary['boundary_id']}: admitted where the vector declares "
                    f"{want['decision']}"
                )
            if record["verifier_mode"] == "offline" and record["decision"] == "admit":
                snap = record["snapshot"]
                if not snap or not all(
                    k in snap for k in ("source_id", "as_of", "age_s", "declared_bound_s")
                ):
                    failures.append(
                        f"{boundary['boundary_id']}: offline admission without a recorded "
                        f"snapshot source, as_of, age and declared bound"
                    )
                elif snap["age_s"] > snap["declared_bound_s"]:
                    failures.append(
                        f"{boundary['boundary_id']}: offline admission on a snapshot past "
                        f"its declared bound"
                    )
            if record["reason"] == "status_sources_conflict":
                conflict = record["conflict"]
                if not conflict or len(conflict["states"]) < 2 or len(conflict["sources"]) < 2:
                    failures.append(
                        f"{boundary['boundary_id']}: conflict deny without both states and "
                        f"sources named"
                    )
            if index > 0:
                prior = record_digest(records[index - 1])
                if record["prior_record_sha256"] != prior:
                    failures.append(
                        f"{boundary['boundary_id']}: prior_record_sha256 is not the digest of "
                        f"the earlier record"
                    )
                if prior != case["boundaries"][index - 1]["expected"]["canonical_sha256"]:
                    failures.append(
                        f"{case['boundaries'][index - 1]['boundary_id']}: record changed after "
                        f"a later boundary ran"
                    )

    control_lines = []
    for control in vectors["controls"]:
        policy = POLICIES.get(control["name"])
        if policy is None:
            failures.append(f"control {control['name']} has no policy in verify.py")
            continue
        scope = [c for c in vectors["cases"] if c["id"] in control["scope"]]
        if len(scope) != len(control["scope"]):
            failures.append(f"control {control['name']}: scope names an unknown case id")
        observed = sorted(c["id"] for c in scope if diverged(c, policy))
        declared = sorted(control["must_fail"])
        if observed != declared:
            failures.append(
                f"control {control['name']}: declared fail set {declared}, observed {observed}"
            )
        control_lines.append(
            f"  {control['name']} ({control['axis']}): ran {len(scope)} case(s), "
            f"failed {len(observed)}, declared {len(declared)}"
        )

    for case in vectors["cases"]:
        ok = not diverged(case, REFERENCE)
        print(f"{'PASS' if ok else 'FAIL'} {case['id']} (python)")
    print("controls:")
    for line in control_lines:
        print(line)

    if failures:
        print("", file=sys.stderr)
        for item in failures:
            print(f"FAIL {item}", file=sys.stderr)
        print(
            f"\nconflicting-status-sources Python: {len(failures)} failure(s)",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nPASSED: conflicting-status-sources Python, {len(vectors['cases'])} cases, "
        f"{boundary_count} boundaries, reference verifier matched every pinned record, "
        f"each control failed exactly its declared set"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
