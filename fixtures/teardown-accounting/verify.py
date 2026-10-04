#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# Independent Python runner for the teardown-accounting candidate family.
#
# Written from PROPOSED.md and the case files, not by porting or transpiling
# harness.ts. Validation here walks a declarative schema table; instants are
# checked with the standard library's calendar through datetime rather than with
# hand-written day arithmetic; the rules are an ordered list of
# (predicate, verdict, reason) entries evaluated lazily rather than early
# returns. Agreement between the two runners is evidence about the text, not
# about one file having been copied.
#
# Standard library only.
#
# Case files. dev-cases.json always runs. vectors.json runs too when present,
# under the same checks, and a present but malformed vectors.json is a failure,
# never a skip.
#
# Run:  python3 fixtures/teardown-accounting/verify.py
# Options:
#   --dev-cases PATH   read the dev cases from PATH (used by the mutation check)
#   --vectors PATH     read vectors from PATH instead of the default location
#   --results-only     print only one result line per case, for the parity diff
# Exit 0 on success, 1 on any failure.

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FAMILY = "teardown-accounting"
PROPOSED_PATH = "fixtures/teardown-accounting/PROPOSED.md"
DEV_PROVENANCE = "author development cases, not contributed vectors and not independent evidence"
CONTROL_ID = "C1-ordering-taken-as-given"
MAX_SAFE = 2**53 - 1

REASON_VERDICT = {
    "sink_configuration_not_established": "not_established",
    "runtime_binding_not_established": "not_established",
    "stop_admitting_not_established": "not_established",
    "cutoff_ordering_not_established": "not_established",
    "cutoff_ordering_independence_not_established": "not_established",
    "accepted_set_not_committed": "not_established",
    "accepted_descendant_missing_from_teardown": "invalid",
    "teardown_accounts_for_accepted_set_under_stipulated_basis": "valid",
}
VERDICTS = {"valid", "invalid", "not_established"}
STIPULATIONS = (
    "sink configurations and runtime bindings are authentic",
    "admission sequence is append only",
    "distinct attestor identifiers denote distinct parties",
)

args = sys.argv[1:]
RESULTS_ONLY = "--results-only" in args


def option(name: str) -> str | None:
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else None


problems: list[str] = []


def fail(message: str) -> None:
    problems.append(message)
    print(f"  FAIL {message}", file=sys.stderr)


def say(message: str) -> None:
    if not RESULTS_ONLY:
        print(message)


# --------------------------------------------------------------------------
# Instants
# --------------------------------------------------------------------------

INSTANT_RE = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<frac>[0-9]+))?(?:Z|(?P<sign>[+-])(?P<oh>[0-9]{2}):(?P<om>[0-9]{2}))"
)
EPOCH = datetime(1970, 1, 1)


def instant(value) -> tuple[int, str] | None:
    """(UTC seconds since 1970, fraction digits without trailing zeros), or None."""
    if not isinstance(value, str):
        return None
    m = INSTANT_RE.fullmatch(value)
    if m is None:
        return None
    try:
        # strptime enforces month, day-of-month for the year, hour, minute and
        # second ranges. %S would accept 60 or 61 on some platforms, so the
        # second field is bounded explicitly as well.
        local = datetime.strptime(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if int(m["time"][6:8]) > 59 or local.year < 1:
        return None
    shift = 0
    if m["sign"] is not None:
        oh, om = int(m["oh"]), int(m["om"])
        if oh > 23 or om > 59:
            return None
        shift = (oh * 60 + om) * 60 * (1 if m["sign"] == "+" else -1)
    seconds = (local - EPOCH) // timedelta(seconds=1) - shift
    return seconds, (m["frac"] or "").rstrip("0")


def instant_key(value: str) -> tuple[int, str]:
    parsed = instant(value)
    if parsed is None:
        raise ValueError(f"instant not validated: {value!r}")
    return parsed


def before_or_at(a: str, b: str) -> bool:
    return _cmp(a, b) <= 0


def strictly_before(a: str, b: str) -> bool:
    return _cmp(a, b) < 0


def _cmp(a: str, b: str) -> int:
    (sa, fa), (sb, fb) = instant_key(a), instant_key(b)
    if sa != sb:
        return -1 if sa < sb else 1
    width = max(len(fa), len(fb))
    fa, fb = fa.ljust(width, "0"), fb.ljust(width, "0")
    return 0 if fa == fb else (-1 if fa < fb else 1)


# --------------------------------------------------------------------------
# Validation: a schema table walked by one function
# --------------------------------------------------------------------------

ID = ("id",)
INSTANT = ("instant",)
BOOL = ("bool",)


def INT(minimum: int):
    return ("int", minimum)


def LIST(item):
    return ("list", item)


def OBJ(**members):
    return ("obj", members)


def MAP(entry):
    return ("map", entry)


def NULLABLE(inner):
    return ("nullable", inner)


SCHEMA = OBJ(
    stipulations=LIST(ID),
    scope=OBJ(declared_sinks=LIST(ID), epoch=ID, boundary=ID),
    sink_configurations=MAP(OBJ(epoch=ID, accepts_only_through=ID, digest=ID)),
    runtime_bindings=MAP(OBJ(config_digest=ID, **{"from": INSTANT, "to": INSTANT})),
    admissions=LIST(OBJ(seq=INT(1), descendant_id=ID)),
    cutoff=OBJ(at=INSTANT, committed_final_seq=INT(0), committed_members=LIST(ID)),
    cutoff_ordering_evidence=NULLABLE(OBJ(attestor=ID, covers_from=INSTANT, covers_to=INSTANT)),
    stop_admitting=OBJ(boundary=ID, epoch=ID, admits_epoch=BOOL, asserted_by=ID, observed_at=INSTANT),
    teardown=OBJ(processed=LIST(ID)),
)


def ptr(base: str, token) -> str:
    return base + "/" + str(token).replace("~", "~0").replace("/", "~1")


def is_identifier(v) -> bool:
    return isinstance(v, str) and len(v) > 0


def is_integer(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= MAX_SAFE
    if isinstance(v, float):
        return v.is_integer() and abs(v) <= MAX_SAFE
    return False


def walk(node, value, path: str, out: set[str]) -> None:
    kind = node[0]
    if kind == "id":
        if not is_identifier(value):
            out.add(path)
    elif kind == "instant":
        if instant(value) is None:
            out.add(path)
    elif kind == "bool":
        if not isinstance(value, bool):
            out.add(path)
    elif kind == "int":
        if not is_integer(value) or value < node[1]:
            out.add(path)
    elif kind == "list":
        if not isinstance(value, list):
            out.add(path)
        else:
            for k, item in enumerate(value):
                walk(node[1], item, ptr(path, k), out)
    elif kind == "obj":
        if not isinstance(value, dict):
            out.add(path)
            return
        members = node[1]
        for name in set(members) | set(value):
            if name not in value or name not in members:
                out.add(ptr(path, name))
            else:
                walk(members[name], value[name], ptr(path, name), out)
    elif kind == "map":
        if not isinstance(value, dict):
            out.add(path)
            return
        for key, entry in value.items():
            if is_identifier(key):
                walk(node[1], entry, ptr(path, key), out)
            else:
                out.add(ptr(path, key))
    elif kind == "nullable":
        if value is not None:
            walk(node[1], value, path, out)
    else:
        raise AssertionError(kind)


def validate(inp) -> list[str]:
    out: set[str] = set()
    walk(SCHEMA, inp, "", out)
    if isinstance(inp, dict):
        stip = inp.get("stipulations")
        if isinstance(stip, list) and not all(s in stip for s in STIPULATIONS):
            out.add("/stipulations")
        scope = inp.get("scope")
        if isinstance(scope, dict) and isinstance(scope.get("declared_sinks"), list):
            sinks = scope["declared_sinks"]
            if not sinks:
                out.add("/scope/declared_sinks")
            first: dict[str, int] = {}
            for k, s in enumerate(sinks):
                if is_identifier(s):
                    if s in first:
                        out.add(f"/scope/declared_sinks/{k}")
                    else:
                        first[s] = k
        adm = inp.get("admissions")
        if isinstance(adm, list):
            met: set[str] = set()
            for k, a in enumerate(adm):
                if isinstance(a, dict) and is_identifier(a.get("descendant_id")):
                    if a["descendant_id"] in met:
                        out.add(f"/admissions/{k}/descendant_id")
                    met.add(a["descendant_id"])
    return sorted(out)


# --------------------------------------------------------------------------
# Rules, as an ordered table
# --------------------------------------------------------------------------


def basis_rules(inp: dict, *, honour_ordering: bool):
    """Yields (holds, verdict, reason) thunks in PROPOSED.md order."""
    scope, cut, st = inp["scope"], inp["cutoff"]["at"], inp["stop_admitting"]
    confs, binds = inp["sink_configurations"], inp["runtime_bindings"]

    for sink in scope["declared_sinks"]:
        conf = confs.get(sink)
        yield (
            lambda conf=conf: conf is None
            or conf["epoch"] != scope["epoch"]
            or conf["accepts_only_through"] != scope["boundary"],
            "not_established",
            "sink_configuration_not_established",
        )
        bind = binds.get(sink)
        yield (
            lambda conf=conf, bind=bind: bind is None
            or bind["config_digest"] != conf["digest"]
            or not (before_or_at(bind["from"], cut) and before_or_at(cut, bind["to"])),
            "not_established",
            "runtime_binding_not_established",
        )

    yield (
        lambda: st["boundary"] != scope["boundary"]
        or st["epoch"] != scope["epoch"]
        or st["admits_epoch"] is not False
        or not strictly_before(cut, st["observed_at"]),
        "not_established",
        "stop_admitting_not_established",
    )

    ev = inp["cutoff_ordering_evidence"]
    yield (lambda: ev is None, "not_established", "cutoff_ordering_not_established")
    if honour_ordering:
        yield (
            lambda: not (before_or_at(ev["covers_from"], cut) and before_or_at(cut, ev["covers_to"]))
            or not strictly_before(ev["covers_to"], st["observed_at"]),
            "not_established",
            "cutoff_ordering_not_established",
        )
        yield (lambda: ev["attestor"] == st["asserted_by"], "not_established", "cutoff_ordering_independence_not_established")

    admitted = [a["descendant_id"] for a in inp["admissions"]]
    committed = inp["cutoff"]
    yield (
        lambda: [a["seq"] for a in inp["admissions"]] != list(range(1, len(admitted) + 1))
        or committed["committed_final_seq"] != len(admitted)
        or not same_sequence(committed["committed_members"], admitted),
        "not_established",
        "accepted_set_not_committed",
    )
    processed = set(inp["teardown"]["processed"])
    yield (lambda: any(d not in processed for d in admitted), "invalid", "accepted_descendant_missing_from_teardown")


def same_sequence(a: list, b: list) -> bool:
    if len(a) != len(b):
        return False
    return all(x == y for x, y in zip(a, b))


def evaluate(inp, *, honour_ordering: bool) -> str:
    """Result line: verdict/reason or fixture_error[pointers]."""
    errors = validate(inp)
    if errors:
        return "fixture_error[" + ",".join(errors) + "]"
    for holds, verdict, reason in basis_rules(inp, honour_ordering=honour_ordering):
        if holds():
            return f"{verdict}/{reason}"
    return "valid/teardown_accounts_for_accepted_set_under_stipulated_basis"


def reference(inp) -> str:
    return evaluate(inp, honour_ordering=True)


def control(inp) -> str:
    return evaluate(inp, honour_ordering=False)


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


def _reject_constant(name: str):
    raise ValueError(f"non-JSON constant {name}")


def expected_line(case_id: str, e) -> str | None:
    if not isinstance(e, dict):
        fail(f"{case_id}: expected is not an object")
        return None
    if set(e) == {"verdict", "reason"}:
        v, r = e["verdict"], e["reason"]
        if v not in VERDICTS:
            fail(f"{case_id}: verdict {v!r} is outside the settled vocabulary")
            return None
        if r not in REASON_VERDICT:
            fail(f"{case_id}: reason {r!r} is not a published reason code")
            return None
        if REASON_VERDICT[r] != v:
            fail(f"{case_id}: reason {r} does not accompany verdict {v}")
            return None
        return f"{v}/{r}"
    if set(e) == {"fixture_error"}:
        p = e["fixture_error"]
        if not isinstance(p, list) or not p or not all(isinstance(x, str) for x in p):
            fail(f"{case_id}: fixture_error must be a non-empty array of JSON Pointers")
            return None
        if p != sorted(set(p)):
            fail(f"{case_id}: fixture_error pointers must be sorted and unique")
            return None
        return "fixture_error[" + ",".join(p) + "]"
    fail(f"{case_id}: expected must be exactly {{verdict, reason}} or exactly {{fixture_error}}")
    return None


def run_file(label: str, path: Path, is_dev: bool) -> None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_constant)
    except (OSError, ValueError) as exc:
        fail(f"{label}: cannot read or parse {path}: {exc}")
        return
    say(f"{label}: Python runner")
    top = {"family", "status", "provenance", "proposed_text", "negative_control", "cases"}
    if not isinstance(doc, dict) or set(doc) != top:
        fail(f"{label}: top-level members must be exactly {sorted(top)}")
        return
    if doc["family"] != FAMILY:
        fail(f"{label}: family is {doc['family']!r}")
    if doc["status"] != "candidate_against_proposed":
        fail(f"{label}: status is {doc['status']!r}")
    if is_dev and doc["provenance"] != DEV_PROVENANCE:
        fail(f"{label}: provenance is {doc['provenance']!r}")
    if not is_dev and not is_identifier(doc["provenance"]):
        fail(f"{label}: provenance must be a non-empty string")

    pin = doc["proposed_text"]
    if not isinstance(pin, dict) or set(pin) != {"path", "sha256"} or pin["path"] != PROPOSED_PATH or not isinstance(pin["sha256"], str):
        fail(f"{label}: proposed_text must be exactly {{path: {PROPOSED_PATH!r}, sha256}}")
    else:
        got = hashlib.sha256((ROOT / PROPOSED_PATH).read_bytes()).hexdigest()
        if got != pin["sha256"]:
            fail(f"{label}: PROPOSED.md sha256 is {got}, pinned {pin['sha256']}")
        else:
            say(f"  ok   proposed text: PROPOSED.md matches the pin {got}")

    cases = doc["cases"]
    if not isinstance(cases, list) or not cases:
        fail(f"{label}: cases must be a non-empty array")
        return
    well_formed: list[tuple[str, object, str]] = []
    ids: set[str] = set()
    for k, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) != {"id", "group", "label", "title", "input", "expected"}:
            fail(f"{label}: case {k} must have exactly id, group, label, title, input, expected")
            continue
        cid = case["id"] if is_identifier(case["id"]) else f"#{k}"
        if cid != case["id"]:
            fail(f"{label}: case {k} has no id")
        if cid in ids:
            fail(f"{cid}: duplicate case id")
        ids.add(cid)
        if case["label"] != "candidate_against_proposed":
            fail(f"{cid}: label is {case['label']!r}")
        if case["group"] != "teardown_accounting":
            fail(f"{cid}: group is {case['group']!r}")
        if not is_identifier(case["title"]):
            fail(f"{cid}: title missing")
        want = expected_line(cid, case["expected"])
        if want is not None:
            well_formed.append((cid, case["input"], want))
    if len(well_formed) == len(cases):
        say(f"  ok   labelling: {len(cases)} cases carry candidate_against_proposed, group teardown_accounting and a well-formed expectation")

    matched = 0
    for cid, inp, want in well_formed:
        got, ctl = reference(inp), control(inp)
        if RESULTS_ONLY:
            print(f"{label}\t{cid}\treference {got}\tcontrol {ctl}")
        if got != want:
            fail(f"{cid}: reference gave {got}, expected {want}")
        else:
            matched += 1
            say(f"  ok   {cid:<10} {got}")
    say(f"  ok   reference model: {matched}/{len(well_formed)} matched")

    nc = doc["negative_control"]
    if (
        not isinstance(nc, dict)
        or set(nc) != {"id", "defect", "declared_fail_set"}
        or nc["id"] != CONTROL_ID
        or not isinstance(nc["declared_fail_set"], list)
        or not all(isinstance(x, str) for x in nc["declared_fail_set"])
    ):
        fail(f"{label}: negative_control must be exactly {{id: {CONTROL_ID!r}, defect, declared_fail_set: [str]}}")
        return
    declared = sorted(nc["declared_fail_set"])
    if not declared:
        fail(f"{CONTROL_ID}: a negative control with an empty declared fail set is not a control")
    for d in declared:
        if d not in ids:
            fail(f"{CONTROL_ID}: declared fail set names unknown case {d}")
    observed, refused = [], 0
    for cid, inp, want in well_formed:
        got = control(inp)
        if want.startswith("fixture_error["):
            if got != want:
                fail(f"{cid}: control gave {got} on a fixture-error case")
            else:
                refused += 1
        elif got != want:
            observed.append(cid)
    observed.sort()
    if observed != declared:
        fail(f"{CONTROL_ID}: declared fail set {declared}, observed {observed}")
    else:
        say(
            f"  ok   {CONTROL_ID}: ran {len(well_formed)} cases, refused the same {refused} fixture-error cases, "
            f"failed exactly the declared {len(declared)} ({', '.join(declared)})"
        )


def main() -> int:
    dev = Path(option("--dev-cases") or HERE / "dev-cases.json")
    vectors = Path(option("--vectors") or HERE / "vectors.json")
    run_file("dev-cases.json", dev, True)
    if vectors.exists():
        run_file("vectors.json", vectors, False)
    else:
        say("vectors.json: not present")

    for a, b, want in ((["a,b", "c"], ["a", "b,c"], False), (["a", "b"], ["a,b"], False), (["d1", "d2"], ["d1", "d2"], True), ([], [], True)):
        got = same_sequence(a, b)
        if got is not want:
            fail(f"same_sequence({a}, {b}) is {got}, expected {want}")
        else:
            say(f"  ok   same_sequence({json.dumps(a)}, {json.dumps(b)}) is {got}")

    if problems:
        print(f"\nteardown-accounting Python: FAILED, {len(problems)} problem(s)", file=sys.stderr)
        return 1
    say("\nteardown-accounting Python: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
