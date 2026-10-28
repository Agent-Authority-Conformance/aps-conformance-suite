#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Second runner for the argument-designated-resources candidate family.

Written against README.md and vectors.json. It imports nothing from the
TypeScript side and uses the standard library only. It was written in the same
session as harness.ts by the same author, so agreement between the two is
agreement between two implementations by one author, not an independent check.

Checks:
  1. labels: every presentation is candidate_against_proposed and names only
     known proposed text (exit 2 if not)
  2. structure: required roster, expected-block fields, policy declarations
  3. determinism: vectors.json re-serializes to its own bytes (a formatting
     stability check, not regeneration), every identifier in trusted state is
     canonical, every decision call_ref recomputes
  4. the reference boundary matches every expected decision, execution, trace
     and final store, and refused calls touch nothing
  5. invariance of the reference under three trusted-state mutations
  6. every defective policy falls in exactly its declared category per vector

Run:
    python3 fixtures/argument-designated-resources/verify.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

ROSTER = [
    "ADR-01-admit-copy-source-and-destination-covered",
    "ADR-02-refuse-destination-not-covered",
    "ADR-03-refuse-deputy-holds-destination-caller-does-not",
    "ADR-04-refuse-nested-designation-not-covered",
    "ADR-04b-admit-nested-designation-covered",
    "ADR-04c-refuse-literal-dotted-key",
    "ADR-05-refuse-one-array-element-not-covered",
    "ADR-05b-admit-every-array-element-covered",
    "ADR-05c-admit-then-second-write-fails",
    "ADR-06-admit-resource-shaped-label-declared-data",
    "ADR-06b-admit-identifier-passed-by-value",
    "ADR-06c-refuse-identifier-passed-by-reference",
    "ADR-07-refuse-argument-not-classified-by-contract",
    "ADR-07b-refuse-empty-container-not-classified",
    "ADR-07c-refuse-required-operand-missing",
    "ADR-07d-refuse-resource-operand-not-a-string",
    "ADR-08-refuse-traversal-resolves-outside-credential",
    "ADR-08b-admit-cased-alias-resolves-inside-credential",
    "ADR-08c-refuse-traversal-above-root",
    "ADR-09-refuse-operation-not-granted-on-resource",
    "ADR-10-admit-capability-held-by-requester",
    "ADR-10b-refuse-capability-held-by-another-party",
    "ADR-10c-refuse-capability-wider-than-issuer-authority",
    "ADR-10d-refuse-capability-operation-narrower-than-tool-operation",
    "ADR-10e-admit-equal-authority-delegation",
    "ADR-10f-refuse-issuer-may-exercise-but-not-delegate",
    "ADR-10g-refuse-root-issuer-without-standing",
    "ADR-11-refuse-argument-changed-after-decision",
    "ADR-11b-admit-unchanged-call-under-decision",
    "ADR-12-refuse-read-credential-selected-for-destination",
    "ADR-12b-admit-write-credential-selected-for-destination",
    "ADR-12c-refuse-no-credential-selected-for-destination",
    "ADR-13-refuse-repeated-resource-sources-swapped",
    "ADR-13b-admit-repeated-resource-each-source-selected",
    "ADR-13c-refuse-repeated-resource-second-operation-uncovered",
    "ADR-14-admit-service-writes-own-statistics",
    "ADR-14b-refuse-destination-in-service-home",
    "ADR-14c-refuse-caller-selects-service-effect-credential",
]

PROPOSED_KEYS = {
    "csr-closed-arguments", "csr-exact-call", "csr-holder-bound-credentials",
    "csr-operands", "csr-selected-authority", "csr-service-effects", "target-binding",
}

CATEGORIES = [
    "unsafe_admission", "admission_without_forbidden_access", "false_refusal",
    "wrong_diagnosis", "wrong_effect", "wrong_attribution",
]

KEY = re.compile(r"[a-z][a-z0-9_]*")


class Refuse(Exception):
    def __init__(self, reason: str, **detail: str) -> None:
        super().__init__(reason)
        self.decision = {"verdict": "refused", "reason": reason, **detail}


class Halt(Exception):
    def __init__(self, path: str, cause: str) -> None:
        super().__init__(cause)
        self.path, self.cause = path, cause


# --- identifiers, README "Identifier grammar" ---------------------------------

def canonical(raw: str) -> str | None:
    if not (len(raw) >= 5 and raw[:4].lower() == "res:" and raw[4] == "/"):
        return None
    kept: list[str] = []
    for part in raw[5:].split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not kept:
                return None
            kept.pop()
            continue
        lowered = "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in part)
        if re.fullmatch(r"[a-z0-9_-]+", lowered) is None:
            return None
        kept.append(lowered)
    return "res:/" + "/".join(kept) if kept else None


def under(entry: str, resource: str) -> bool:
    return resource == entry or resource.startswith(entry + "/")


# --- call reference ------------------------------------------------------------

def jcs(value) -> str:
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, str):
        if re.fullmatch(r"[\x20-\x7e]*", value) is None:
            raise ValueError(f"jcs: non-printable-ASCII string {value!r}")
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(jcs(k) + ":" + jcs(value[k]) for k in sorted(value)) + "}"
    raise ValueError(f"jcs: unsupported {type(value).__name__}")


def call_ref(call: dict, domain: str) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\x00" + jcs(call).encode("utf-8")).hexdigest()


# --- policies ------------------------------------------------------------------
#
# The reference rule set, and for each defective policy the one rule it
# replaces. README "Defective policies" defines each change.

REFERENCE = {
    "name": "reference-boundary",
    "bind": True,
    "visit": "nodes",
    "unknown": "refuse",
    "required": True,
    "designate": "contract",
    "dedup": False,
    "resolve": True,
    "substitute": None,
    "holder": True,
    "roots": "records",
    "delegable": True,
    "narrowing": "within",
    "operation": True,
    "effects": "declared",
}

DEFECTIVE = {
    "no-call-binding": {"bind": False},
    "leaf-walk": {"visit": "leaves"},
    "open-schema": {"unknown": "ignore"},
    "no-required-check": {"required": False},
    "target-only": {"designate": "target"},
    "shallow-args": {"designate": "top"},
    "shape-guessing": {"designate": "shape"},
    "dedup-by-resource": {"dedup": True},
    "no-canonicalization": {"resolve": False},
    "wallet-search": {"substitute": "wallet"},
    "pooled-selection": {"substitute": "pooled"},
    "deputy-authority": {"substitute": "service"},
    "holder-unchecked": {"holder": False},
    "self-asserted-issuer": {"roots": "self"},
    "delegation-equals-exercise": {"delegable": False},
    "no-attenuation-check": {"narrowing": "none"},
    "strict-attenuation": {"narrowing": "strict"},
    "resource-not-operation": {"operation": False},
    "caller-authority-for-service-effects": {"effects": "caller"},
}


def pattern_of(path: str) -> str:
    return re.sub(r"\[\d+\]", "[]", path)


def join(parent: str, key: str) -> str:
    return f"{parent}.{key}" if parent else key


def container_for(declared: dict, pattern: str) -> str | None:
    for name in declared:
        if name.startswith(pattern + "."):
            return "object"
        if name.startswith(pattern + "[]"):
            return "array"
    return None


def is_cap(value) -> bool:
    return isinstance(value, dict) and list(value) == ["capability"] and isinstance(value["capability"], str)


def nodes(policy: dict, declared: dict, args: dict) -> list[tuple[str, object, dict]]:
    """Declared nodes in walk order, as (path, value, spec)."""
    found: list[tuple[str, object, dict]] = []

    def check_key(parent: str, key: str) -> None:
        if KEY.fullmatch(key) is None:
            raise Refuse("argument_key_invalid", path=f"{parent}[{json.dumps(key)}]")

    if policy["visit"] == "nodes":
        def child(value, path: str) -> None:
            pat = pattern_of(path)
            if pat in declared:
                found.append((path, value, declared[pat]))
                return
            shape = container_for(declared, pat)
            if shape == "object":
                if isinstance(value, dict):
                    obj(value, path)
            elif shape == "array":
                if isinstance(value, list):
                    for i, item in enumerate(value):
                        child(item, f"{path}[{i}]")
            elif policy["unknown"] == "refuse":
                raise Refuse("argument_designation_unknown", path=path)

        def obj(value: dict, path: str) -> None:
            for key in sorted(value):
                check_key(path, key)
                child(value[key], join(path, key))

        obj(args, "")
        return found

    def leaf(value, path: str) -> None:
        spec = declared.get(pattern_of(path))
        if path and spec is not None and spec["kind"] == "capability":
            found.append((path, value, spec))
        elif isinstance(value, dict):
            for key in sorted(value):
                check_key(path, key)
                leaf(value[key], join(path, key))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                leaf(item, f"{path}[{i}]")
        elif spec is not None:
            found.append((path, value, spec))
        elif policy["unknown"] == "refuse":
            raise Refuse("argument_designation_unknown", path=path)

    leaf(args, "")
    return found


def has(args: dict, pattern: str) -> bool:
    cur = args
    for segment in pattern.split("."):
        name = segment[:-2] if segment.endswith("[]") else segment
        if not isinstance(cur, dict) or name not in cur:
            return False
        cur = cur[name]
        if segment.endswith("[]"):
            return isinstance(cur, list)
    return True


def lookup(args: dict, path: str):
    cur = args
    for name, index in re.findall(r"([^.\[\]]+)|\[(\d+)\]", path):
        if index:
            if not isinstance(cur, list) or int(index) >= len(cur):
                return None
            cur = cur[int(index)]
        else:
            if not isinstance(cur, dict) or name not in cur:
                return None
            cur = cur[name]
    return cur


class Boundary:
    def __init__(self, policy: dict, vectors: dict, presentation: dict) -> None:
        self.p = policy
        self.v = vectors
        self.pres = presentation
        self.creds = {c["id"]: c for c in presentation["trusted_state"]["credentials"]}

    def cred(self, cid: str) -> dict:
        if cid not in self.creds:
            raise ValueError(f"harness input error: credential {cid} not in trusted state")
        return self.creds[cid]

    def chain(self, c: dict) -> str | None:
        while True:
            if c["parent"] is None:
                if self.p["roots"] == "records":
                    owned = self.v["issuer_records"].get(c["issuer"], [])
                    if not any(under(r, c["resource"]) for r in owned):
                        return "authority_issuer_without_standing"
                return None
            parent = self.cred(c["parent"])
            if parent["holder"] != c["issuer"]:
                return "authority_issuer_without_standing"
            if self.p["delegable"] and not parent["delegable"]:
                return "authority_issuer_cannot_delegate"
            if self.p["narrowing"] != "none":
                within = under(parent["resource"], c["resource"]) and set(c["operations"]) <= set(parent["operations"])
                equal = c["resource"] == parent["resource"] and set(c["operations"]) == set(parent["operations"])
                if not within or (self.p["narrowing"] == "strict" and equal):
                    return "authority_exceeds_issuer_authority"
            c = parent

    def problem(self, c: dict, holder: str, resource: str, operation: str, path: str) -> dict | None:
        if self.p["holder"] and c["holder"] != holder:
            return {"verdict": "refused", "reason": "authority_not_held_by_requester", "path": path}
        reason = self.chain(c)
        if reason:
            return {"verdict": "refused", "reason": reason, "path": path}
        if not under(c["resource"], resource) or (self.p["operation"] and operation not in c["operations"]):
            return {"verdict": "refused", "reason": "argument_resource_not_authorized", "path": path, "resource": resource, "operation": operation}
        return None

    def designations(self, tool: dict, found: list) -> list[tuple[str, str, str, object]]:
        out = []
        mode = self.p["designate"]
        for path, value, spec in found:
            kind = spec["kind"]
            if mode == "shape":
                if kind == "capability":
                    out.append((path, "capability", spec["operation"], value))
                elif isinstance(value, str) and value[:4].lower() == "res:":
                    out.append((path, "resource", spec["operation"] if kind == "resource" else "read", value))
                continue
            if kind == "data":
                continue
            if mode == "target" and path != tool["target"]:
                continue
            if mode == "top" and ("." in pattern_of(path) or "[" in pattern_of(path)):
                continue
            out.append((path, kind, spec["operation"], value))
        return out

    def decide(self) -> tuple[dict, dict]:
        call = self.pres["call"]
        requester = call["requester"]
        chosen: dict[str, str] = {}
        try:
            decision = self.pres["decision"]
            if self.p["bind"] and decision is not None and call_ref(call, self.v["call_ref"]["domain"]) != decision["call_ref"]:
                raise Refuse("call_does_not_match_decision")
            tool = self.v["tools"][call["tool"]]
            declared = tool["arguments"]
            found = nodes(self.p, declared, call["arguments"])
            if self.p["required"]:
                for pat in sorted(declared):
                    if declared[pat]["required"] and not has(call["arguments"], pat):
                        raise Refuse("argument_operand_missing", path=pat)

            already: set[str] = set()
            for path, kind, operation, value in self.designations(tool, found):
                if kind == "capability":
                    if not is_cap(value):
                        raise Refuse("argument_resource_identifier_invalid", path=path)
                    c = self.cred(value["capability"])
                    bad = self.problem(c, requester, c["resource"], operation, path)
                    if bad:
                        raise Refuse(bad.pop("reason"), **{k: v for k, v in bad.items() if k != "verdict"})
                    chosen[path] = c["id"]
                    continue
                if not isinstance(value, str):
                    raise Refuse("argument_resource_identifier_invalid", path=path)
                resource = canonical(value) if self.p["resolve"] else value
                if resource is None:
                    raise Refuse("argument_resource_identifier_invalid", path=path)
                if self.p["dedup"]:
                    if resource in already:
                        continue
                    already.add(resource)
                selected = call["authority"].get(path)
                if selected is None:
                    bad = {"verdict": "refused", "reason": "argument_authority_not_selected", "path": path}
                else:
                    bad = self.problem(self.cred(selected), requester, resource, operation, path)
                if bad is None:
                    chosen[path] = selected
                    continue
                substitute = self.substitute(tool, requester, resource, operation, path)
                if substitute is not None:
                    chosen[path] = substitute
                    continue
                raise Refuse(bad["reason"], **{k: v for k, v in bad.items() if k not in ("verdict", "reason")})

            for i, effect in enumerate(tool["service_effects"]):
                path = f"service_effects[{i}]"
                detail = {"path": path, "resource": effect["resource"], "operation": effect["operation"]}
                if self.p["effects"] == "declared":
                    c, holder = self.cred(effect["authority"]), tool["service_identity"]
                else:
                    if path not in call["authority"]:
                        raise Refuse("service_effect_not_authorized", **detail)
                    c, holder = self.cred(call["authority"][path]), requester
                if self.problem(c, holder, effect["resource"], effect["operation"], path):
                    raise Refuse("service_effect_not_authorized", **detail)
                chosen[path] = c["id"]
        except Refuse as r:
            return r.decision, {}
        return {"verdict": "admitted", "reason": "all_designations_authorized"}, chosen

    def substitute(self, tool: dict, requester: str, resource: str, operation: str, path: str) -> str | None:
        mode = self.p["substitute"]
        if mode is None:
            return None
        holder = requester
        if mode == "wallet":
            pool = [c for c in self.creds.values() if c["holder"] == requester]
        elif mode == "pooled":
            pool = [self.cred(cid) for cid in set(self.pres["call"]["authority"].values())]
        else:
            holder = tool["service_identity"]
            pool = [c for c in self.creds.values() if c["holder"] == holder]
        for c in sorted(pool, key=lambda c: c["id"]):
            if self.problem(c, holder, resource, operation, path) is None:
                return c["id"]
        return None


def run_tool(vectors: dict, pres: dict, chosen: dict) -> tuple[dict, list, dict]:
    call = pres["call"]
    args = call["arguments"]
    tool = vectors["tools"][call["tool"]]
    creds = {c["id"]: c for c in pres["trusted_state"]["credentials"]}
    store = dict(vectors["initial_store"])
    trace: list[dict] = []
    inject = (pres["inject_failure"] or {}).get("path")

    def where(path: str) -> str | None:
        value = lookup(args, path)
        spec = tool["arguments"].get(pattern_of(path), {})
        if spec.get("kind") == "capability":
            return creds[value["capability"]]["resource"] if is_cap(value) and value["capability"] in creds else None
        return canonical(value) if isinstance(value, str) else None

    def note(op: str, resource: str, path: str) -> None:
        auth = chosen.get(path)
        trace.append({"operation": op, "resource": resource, "path": path, "authority": auth,
                      "holder": creds[auth]["holder"] if auth else None})

    def get(path: str) -> str:
        if path == inject:
            raise Halt(path, "injected_failure")
        r = where(path)
        if r is None:
            raise Halt(path, "operand_unresolvable")
        if r not in store:
            raise Halt(path, "resource_absent")
        note("read", r, path)
        return store[r]

    def put(path: str, value: str) -> None:
        if path == inject:
            raise Halt(path, "injected_failure")
        r = where(path)
        if r is None:
            raise Halt(path, "operand_unresolvable")
        store[r] = value
        note("write", r, path)

    def put_service(i: int, value: str) -> None:
        path = f"service_effects[{i}]"
        if path == inject:
            raise Halt(path, "injected_failure")
        r = tool["service_effects"][i]["resource"]
        store[r] = value
        note("write", r, path)

    def text(path: str) -> str:
        value = lookup(args, path)
        if not isinstance(value, str):
            raise ValueError(f"harness input error: data {path} is not a string")
        return value

    execution: dict = {"status": "completed"}
    name = call["tool"]
    try:
        if name in ("copy", "copy_with_capability"):
            put("dst", get("src"))
        elif name == "copy_audited":
            put("dst", get("src"))
            put_service(0, f"copy {where('src')} -> {where('dst')}")
        elif name == "export":
            content = get("src")
            put("options.output.path", text("options.output.format") + ":" + content)
        elif name == "replicate":
            content = get("src")
            targets = args.get("dsts")
            if not isinstance(targets, list):
                raise Halt("dsts[]", "operand_unresolvable")
            for i in range(len(targets)):
                put(f"dsts[{i}]", content)
        elif name == "overwrite":
            put("target", text("content"))
        elif name == "normalize":
            put("dst", "".join(chr(ord(c) - 32) if "a" <= c <= "z" else c for c in get("src")))
        else:
            raise ValueError(f"harness input error: no program for {name}")
    except Halt as h:
        execution = {"status": "partial", "stopped_at": h.path, "cause": h.cause}
    return execution, trace, dict(sorted(store.items()))


def evaluate(policy: dict, vectors: dict, pres: dict) -> dict:
    decision, chosen = Boundary(policy, vectors, pres).decide()
    if decision["verdict"] == "refused":
        return {"decision": decision, "execution": {"status": "not_run"}, "trace": [],
                "store": dict(sorted(vectors["initial_store"].items()))}
    execution, trace, store = run_tool(vectors, pres, chosen)
    return {"decision": decision, "execution": execution, "trace": trace, "store": store}


# --- the runner ----------------------------------------------------------------

def expected_outcome(vectors: dict, p: dict) -> dict:
    e = p["expected"]
    store = dict(vectors["initial_store"])
    store.update(e["store_changes"])
    return {"decision": e["decision"], "execution": e["execution"], "trace": e["trace"], "store": dict(sorted(store.items()))}


def bare(trace: list) -> list:
    return [(a["operation"], a["resource"], a["path"]) for a in trace]


def category(vectors: dict, actual: dict, p: dict) -> str:
    want = expected_outcome(vectors, p)
    if actual["decision"]["verdict"] != want["decision"]["verdict"]:
        if actual["decision"]["verdict"] == "admitted":
            f = p["expected"]["forbidden_access"]
            hit = f is not None and (f["operation"], f["resource"], f["path"]) in bare(actual["trace"])
            return "unsafe_admission" if hit else "admission_without_forbidden_access"
        return "false_refusal"
    if actual["decision"] != want["decision"]:
        return "wrong_diagnosis"
    if actual["execution"] != want["execution"] or bare(actual["trace"]) != bare(want["trace"]) or actual["store"] != want["store"]:
        return "wrong_effect"
    if actual["trace"] != want["trace"]:
        return "wrong_attribution"
    return "match"


def show(o: dict) -> str:
    d = o["decision"]
    head = " ".join(d[k] for k in ("verdict", "reason", "path", "resource", "operation") if k in d)
    ex = o["execution"]
    tail = f" partial@{ex['stopped_at']}:{ex['cause']}" if ex["status"] == "partial" else ""
    trace = ", ".join(f"{a['operation']} {a['resource']} {a['path']}@{a['authority'] or 'unchecked'}" for a in o["trace"])
    return head + tail + (f" | {trace}" if trace else "")


def main() -> int:
    raw = (HERE / "vectors.json").read_text(encoding="utf-8")
    vectors = json.loads(raw)
    presentations = vectors["presentations"]

    def label_error(message: str) -> int:
        print(f"argument-designated-resources: {message}", file=sys.stderr)
        return 2

    if vectors.get("status") != "candidate_against_proposed":
        return label_error("vectors.json is not labelled candidate_against_proposed")
    if set(vectors["proposed_text"]) != PROPOSED_KEYS:
        return label_error(f"proposed_text keys are {sorted(vectors['proposed_text'])}")
    for p in presentations:
        if p.get("status") != "candidate_against_proposed":
            return label_error(f"{p['id']} is not labelled candidate_against_proposed")
        named = p.get("tests_proposed_text") or []
        if not named:
            return label_error(f"{p['id']} names no proposed text")
        for key in named:
            if key not in PROPOSED_KEYS:
                return label_error(f"{p['id']} names unknown proposed text \"{key}\"")

    print(f"argument-designated-resources: {len(presentations)} presentations, status {vectors['status']} (python)")
    print()
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)
        print(f"FAIL {message}")

    def ok(message: str) -> None:
        print(f"ok   {message}")

    # 2. Structure.
    ids = [p["id"] for p in presentations]
    if sorted(ids) != sorted(ROSTER) or len(set(ids)) != len(ids):
        fail(f"roster mismatch: missing {sorted(set(ROSTER) - set(ids))} unexpected {sorted(set(ids) - set(ROSTER))} count {len(ids)}")
    else:
        ok(f"roster: all {len(ROSTER)} required cases present exactly once")
    malformed = [p["id"] for p in presentations
                 if sorted(p["expected"]) != ["decision", "execution", "forbidden_access", "store_changes", "trace"]
                 or (p["expected"]["decision"]["verdict"] == "admitted" and p["expected"]["forbidden_access"] is not None)]
    if malformed:
        fail(f"expected blocks malformed: {malformed}")
    else:
        ok("every expected block has exactly decision, execution, trace, store_changes and forbidden_access")
    if vectors["categories"] != CATEGORIES:
        fail(f"categories are {vectors['categories']}")
    declarations = {d["name"]: d for d in vectors["defective_policies"]}
    if set(declarations) != set(DEFECTIVE) or len(declarations) != len(vectors["defective_policies"]):
        fail(f"declared policies {sorted(declarations)} differ from implemented {sorted(DEFECTIVE)}")
    else:
        ok(f"all {len(DEFECTIVE)} defective policies declared and implemented")
    for name, d in declarations.items():
        if sorted(d["declared"]) != sorted(CATEGORIES):
            fail(f"{name} declares categories {sorted(d['declared'])}")
        listed = [i for cat in d["declared"].values() for i in cat]
        if set(listed + d["characteristic_cases"]) - set(ROSTER):
            fail(f"{name} names unknown cases")
        if len(set(listed)) != len(listed):
            fail(f"{name} declares a case in more than one category")
        if set(d["characteristic_cases"]) - set(listed):
            fail(f"{name} characteristic cases not declared")
    print()

    # 3. Determinism.
    if json.dumps(vectors, indent=2, ensure_ascii=False) + "\n" != raw:
        fail("vectors.json does not re-serialize to its own bytes")
    else:
        ok("vectors.json re-serializes to its own bytes")
    idents = [r for roots in vectors["issuer_records"].values() for r in roots] + list(vectors["initial_store"])
    idents += [e["resource"] for t in vectors["tools"].values() for e in t["service_effects"]]
    idents += [c["resource"] for p in presentations for c in p["trusted_state"]["credentials"]]
    bad = sorted({i for i in idents if canonical(i) != i})
    if bad:
        fail(f"identifiers not canonical: {bad}")
    else:
        ok(f"all {len(idents)} identifiers in trusted state are canonical")
    domain = vectors["call_ref"]["domain"]
    bad_refs = [p["id"] for p in presentations if p["decision"] and call_ref(p["decision"]["call"], domain) != p["decision"]["call_ref"]]
    if bad_refs:
        fail(f"decision call_ref does not recompute: {bad_refs}")
    else:
        ok("every decision call_ref recomputes from its call")
    print()

    # 4. Reference.
    print(f"policy: {REFERENCE['name']}")
    reference = {p["id"]: evaluate(REFERENCE, vectors, p) for p in presentations}
    matched, touched = 0, []
    for p in presentations:
        actual = reference[p["id"]]
        good = category(vectors, actual, p) == "match"
        matched += good
        print(f"  {'MATCH   ' if good else 'MISMATCH'} {p['id']}  {show(actual)}")
        if not good:
            print(f"             expected {show(expected_outcome(vectors, p))}")
        if actual["decision"]["verdict"] == "refused" and (actual["trace"] or actual["store"] != dict(sorted(vectors["initial_store"].items()))):
            touched.append(p["id"])
    if matched != len(presentations):
        fail(f"reference-boundary matched {matched}/{len(presentations)}")
    else:
        ok(f"reference-boundary matched {matched}/{len(presentations)} on decision, execution, trace and store")
    refused = sum(1 for o in reference.values() if o["decision"]["verdict"] == "refused")
    if touched:
        fail(f"refused calls touched the store: {touched}")
    else:
        ok(f"all {refused} refused calls performed no access and left the store unchanged")
    print()

    # 5. Invariance.
    svc = "party:svc-tools"
    effect_creds = {e["authority"] for t in vectors["tools"].values() for e in t["service_effects"]}

    def made(cid: str, holder: str, issuer: str, resource: str) -> dict:
        return {"id": cid, "holder": holder, "issuer": issuer, "resource": resource,
                "operations": ["read", "write"], "delegable": False, "parent": None}

    def replaced(p: dict, creds: list) -> dict:
        q = copy.deepcopy(p)
        q["trusted_state"]["credentials"] = creds
        return q

    mutations = [
        ("the service holds every resource",
         lambda p: replaced(p, p["trusted_state"]["credentials"] + [made("cred:zz-svc-store", svc, "party:store-admin", "res:/store")])),
        ("the service holds only its declared effect credentials",
         lambda p: replaced(p, [c for c in p["trusted_state"]["credentials"] if c["holder"] != svc or c["id"] in effect_creds])),
        ("the requester holds unselected credentials over everything",
         lambda p: replaced(p, p["trusted_state"]["credentials"] + [
             made("cred:zz-requester-store", p["call"]["requester"], "party:store-admin", "res:/store"),
             made("cred:zz-requester-svc", p["call"]["requester"], svc, "res:/svc")])),
    ]
    for label, mutate in mutations:
        changed = [p["id"] for p in presentations if evaluate(REFERENCE, vectors, mutate(p)) != reference[p["id"]]]
        if changed:
            fail(f"reference-boundary changed when {label}: {changed}")
        else:
            ok(f"reference-boundary unchanged when {label}")
    print()

    # 6. Defective policies.
    rows = []
    for name, change in DEFECTIVE.items():
        if name not in declarations:
            continue
        d = declarations[name]
        policy = {**REFERENCE, **change, "name": name}
        print(f"policy: {name} (stage {d['stage']})")
        seen = {c: [] for c in CATEGORIES}
        for p in presentations:
            actual = evaluate(policy, vectors, p)
            c = category(vectors, actual, p)
            if c != "match":
                seen[c].append(p["id"])
            print(f"  {c:<34} {p['id']}  {show(actual)}")
        problems = 0
        for c in CATEGORIES:
            if sorted(d["declared"][c]) != sorted(seen[c]):
                problems += 1
                fail(f"{name} {c}: declared {sorted(d['declared'][c])} observed {sorted(seen[c])}")
        rows.append(f"{name:<38} " + " ".join(f"{len(seen[c]):>3}" for c in CATEGORIES))
        if not problems:
            ok(f"{name} matches its declaration in every category")
        print()
    print(f"summary {'':<30} " + " ".join(f"{s:>3}" for s in ("uns", "awf", "fr", "dia", "eff", "att")))
    for row in rows:
        print(f"  {row}")
    print()

    if failures:
        print("FAILED")
        return 1
    print("PASSED: reference-boundary matched every presentation, every defective policy matched its declared categories (python)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
