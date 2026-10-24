#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RTTP/IQA independent runner — aps-conformance-suite lease-revocation-axes (revision 2).

Independently authored Python implementation of the verifier contract declared by
the lease-revocation-axes family spec (README.md / ORACLE.md), replaying the
frozen revision-2 vectors against their pinned expected values.

Provenance: implementation authored by the RTTP & IQA side (Aicent Stack); the
lab's TypeScript model was reviewed as the interface contract; no lab code was
reused; all pass/fail comparisons are against the frozen vectors file, never
against lab model output.

Usage:
  python lra_runner.py                       # human summary
  python lra_runner.py --json                # full JSON report
  python lra_runner.py --vectors <path>      # alternate vectors file

Exit status: 0 when the run status is independent_run_matched, 1 otherwise
(including digest-gate refusal). Callers must not have to parse stdout to
learn whether the run matched.
"""

import argparse
import copy
import hashlib
import json
import os
import sys

AXES = ("evidence_freshness", "authority_validity", "action_authorization")
ALL_CLAIMED = list(AXES)
DEFAULT_POLICY = "P1-current-observation"
DIAGNOSTIC_CASES = ("LRA-04", "LRA-05", "LRA-07", "LRA-08", "LRA-10")
MODES = ("cached_lease", "live_standing_read")
BOUNDARIES = ("exclusive", "inclusive")

# --- oracle-inputs guard (reporting check "oracle_inputs_not_read") ---------------
# While the scoring phases run (baselines, mutations, diagnostics), builtins.open
# is wrapped so that any attempt to open a file whose name contains "oracle" is
# recorded. The reporting check is then the measured result of the run, not an
# asserted constant: an implementation that peeks at oracle inputs during
# scoring flips the check to False.
_ORACLE_GUARD = {"active": False, "touched": False}
_real_open = open


def _guarded_open(file, *args, **kwargs):
    if _ORACLE_GUARD["active"] and "oracle" in str(file).lower():
        _ORACLE_GUARD["touched"] = True
    return _real_open(file, *args, **kwargs)


def _oracle_guard_on():
    _ORACLE_GUARD["active"] = True
    _ORACLE_GUARD["touched"] = False


def _oracle_guard_off():
    _ORACLE_GUARD["active"] = False


import builtins as _builtins
_builtins.open = _guarded_open


class HostileField:
    """A field that must never be touched by an implementation under test."""

    def __init__(self, name):
        self._name = name

    def __get__(self, obj, objtype=None):
        raise AssertionError("implementation read forbidden field: %s" % self._name)


def make_hostile_call(call):
    """Wrap a call so that touching expected/truth raises (input-boundary check)."""
    body = dict(call)

    class HostileCall(dict):
        expected = HostileField("expected")
        truth = HostileField("truth")

        def __getitem__(self, key):
            if key in ("expected", "truth"):
                raise AssertionError("implementation read forbidden field: %s" % key)
            return body[key]

        def __getattr__(self, key):
            if key in ("expected", "truth"):
                raise AssertionError("implementation read forbidden field: %s" % key)
            return body[key]

        def get(self, key, default=None):
            if key in ("expected", "truth"):
                raise AssertionError("implementation read forbidden field: %s" % key)
            return body.get(key, default)

    hc = HostileCall()
    hc.update(body)
    return hc


class Downstream:
    def __init__(self):
        self._attempts = set()

    def execute(self, call_id):
        self._attempts.add(call_id)

    def reached(self, call_id):
        return call_id in self._attempts


class SourceAuthority:
    """The authoritative status source, instrumented per the family spec.

    - answers atomically at call time from the timeline state
    - an outage (availability=False) returns no observation but the attempt
      is still recorded
    - records call, worker, grant, time, purpose and observation per read
    """

    def __init__(self, states):
        self._states = states          # grant -> 'active' | 'revoked'
        self.available = True
        self.reads = []                # list of ReadEvent dicts
        self._current = None           # {input, rejected} while inside a call

    def begin_call(self, call, rejected):
        assert self._current is None, "overlapping calls"
        self._current = {"input": call, "rejected": rejected}

    def end_call(self):
        self._current = None

    def read(self, grant, at_ms):
        assert self._current is not None, "read outside a call"
        assert grant in self._states, "unknown source grant"
        observation = None
        if self.available:
            observation = {
                "status": self._states[grant],
                "as_of_ms": at_ms,
                "retrieved_at_ms": at_ms,
            }
        self.reads.append({
            "call": self._current["input"]["id"],
            "worker": self._current["input"]["worker"],
            "grant": grant,
            "at_ms": at_ms,
            "purpose": "rejected_input_diagnostic" if self._current["rejected"] else "verification",
            "observation": observation,
        })
        return observation


class Verifier:
    """Independent implementation of the lease-revocation-axes verifier contract.

    One instance per worker per run. Private caches only; the source is shared.
    """

    def __init__(self, declaration, authority, downstream, mutant="correct"):
        self.declaration = {
            "mode": declaration["mode"],
            "boundary": declaration["boundary"],
            "claimed_axes": list(declaration["claimed_axes"]),
            "action_policy": declaration["action_policy"],
        }
        self._authority = authority
        self._downstream = downstream
        self._mutant = mutant
        self._previous_use = {}    # evidence_id -> at_ms (private per instance)
        self._first_reads = {}     # grant -> observation (private per instance)
        self._ever_failed = False  # an outage was seen on a previous read

    def _lease_len(self, evidence):
        return evidence["expires_at_ms"] - evidence["issued_at_ms"]

    def call(self, c, e):
        decl = self.declaration
        mode, boundary = decl["mode"], decl["boundary"]
        lease_len = self._lease_len(e)

        # --- evidence-to-grant binding (prerequisite) ---
        bound = (c["grant"] == e["grant"]) or self._mutant == "ignore-evidence-binding"

        # --- original evidence lease ---
        expiry = e["expires_at_ms"]
        previous = self._previous_use.get(e["id"])
        if self._mutant == "sliding-lease" and previous is not None:
            expiry = previous + lease_len
        fresh = c["at_ms"] < expiry if boundary == "exclusive" else c["at_ms"] <= expiry
        if self._mutant == "lease-ignores-expiry":
            fresh = True

        # --- observation ---
        observation = None
        _UNSET = object()   # sentinel: prefetch not attempted (null outcome still counts as attempted)
        prefetched = _UNSET
        if bound and self._mutant == "retrieval-renews-evidence" and mode == "live_standing_read":
            prefetched = self._authority.read(c["grant"], c["at_ms"])
            if prefetched is not None:
                fresh = c["at_ms"] < prefetched["retrieved_at_ms"] + lease_len

        if fresh and bound:
            if mode == "cached_lease":
                # cached lease answers from the original observation; no source read
                observation = {"status": e["status"], "as_of_ms": e["issued_at_ms"],
                               "retrieved_at_ms": e["issued_at_ms"]}
            elif prefetched is not _UNSET:
                observation = prefetched
            elif self._mutant == "fabricated-live-read":
                # plausible canned answers without any source read (bypass control)
                cid = c["id"].split("-r")[0]
                outage = (cid in ("LRA-03", "LRA-07") and c["at_ms"] >= 5000) or \
                         (cid == "LRA-11" and c["at_ms"] == 30000)
                revoked = cid in ("LRA-02", "LRA-03", "LRA-04", "LRA-06", "LRA-08",
                                  "LRA-11", "LRA-12") and c["grant"] == "g1" and c["at_ms"] >= 10000
                observation = None if outage else {
                    "status": "revoked" if revoked else "active",
                    "as_of_ms": c["at_ms"], "retrieved_at_ms": c["at_ms"]}
            elif self._mutant == "sticky-unavailable" and self._ever_failed:
                observation = None
            elif (self._mutant == "live-first-read-only" or
                  (self._mutant == "second-worker-stale" and c["worker"] == "w2")) and \
                    c["grant"] in self._first_reads:
                observation = self._first_reads.get(c["grant"])
            else:
                observation = self._authority.read(c["grant"], c["at_ms"])
                self._first_reads[c["grant"]] = observation
                if observation is None:
                    self._ever_failed = True
            if self._mutant == "live-fail-open" and observation is None:
                observation = {"status": "active", "as_of_ms": c["at_ms"],
                               "retrieved_at_ms": c["at_ms"]}

        # a permissible diagnostic read never renews expired original evidence
        if (not fresh) and bound and self._mutant == "post-expiry-diagnostic":
            observation = self._authority.read(c["grant"], c["at_ms"])

        self._previous_use[e["id"]] = c["at_ms"]

        # --- scoped answers ---
        current = observation is not None and observation["as_of_ms"] == c["at_ms"]
        if current:
            current_validity = "valid" if observation["status"] == "active" else "revoked"
        else:
            current_validity = "not_established"
        if observation is None:
            authority_answer = "not_established"
        else:
            authority_answer = "valid" if observation["status"] == "active" else "revoked"

        # --- action decision under the declared policy ---
        action = "not_claimed"
        if "action_authorization" in decl["claimed_axes"]:
            if decl["action_policy"] != DEFAULT_POLICY:
                action = "not_supported"
            else:
                allowed = (bound and fresh and current_validity == "valid"
                           and c["operation"] in e["allowed_operations"])
                action = "permit" if allowed else "deny"

        if self._mutant == "deny-everything" and action == "permit":
            action = "deny"
        if self._mutant == "selective-not-supported" and action == "deny":
            action = "not_supported"
        if action == "permit" or (self._mutant == "deny-but-dispatch" and action == "deny"):
            self._downstream.execute(c["id"])

        return {
            "evidence_binding": "matched" if bound else "mismatch",
            "evidence_freshness": "fresh" if fresh else "expired",
            "observation": copy.deepcopy(observation),
            "authority_answer": authority_answer,
            "current_validity": current_validity,
            "verification_accepted": bool(bound and fresh and authority_answer == "valid"),
            "action_decision": action,
        }


class CheckSponge:
    """Collects failures instead of raising, mirroring the lab's check() shape."""

    def __init__(self):
        self.failures = []

    def check(self, call_id, label, actual, expected):
        if actual != expected:
            self.failures.append("%s %s: expected %s, got %s"
                                 % (call_id, label, json.dumps(expected), json.dumps(actual)))


def run_case(vectors, case, mode, boundary, mutant="correct",
             claimed=None, policy=DEFAULT_POLICY):
    """Replay one frozen timeline under one declared profile; score per axes."""
    claimed = ALL_CLAIMED if claimed is None else list(claimed)
    profile = vectors["profile"]

    # All support decisions are frozen before any implementation is constructed.
    mapping = {}
    for axis in AXES:
        if axis not in claimed:
            mapping[axis] = "not_claimed"
        elif axis == "action_authorization" and policy != DEFAULT_POLICY:
            mapping[axis] = "not_supported"
        else:
            mapping[axis] = "supported"

    states = {e["grant"]: "active" for e in profile["initial_evidence"]}
    downstream = Downstream()
    workers = {}
    source = SourceAuthority(states)
    sponge = CheckSponge()
    records = []
    scored = composite_scored = not_claimed = not_supported = 0
    last_ms = -1

    for event in case["timeline"]:
        at = event["at_ms"]
        assert isinstance(at, int) and at >= last_ms, "nonmonotonic clock"
        last_ms = at

        if event["event"] == "revoke":
            assert event["grant"] in states
            states[event["grant"]] = "revoked"
            continue
        if event["event"] == "availability":
            source.available = event["available"]
            continue

        # --- assemble the call (the implementation never sees expected/truth) ---
        call = {k: event[k] for k in ("event", "id", "at_ms", "worker", "grant", "operation")}
        call["event"] = "call"
        evidence = None
        for cand in profile["initial_evidence"]:
            if event.get("evidence_id"):
                if cand["id"] == event["evidence_id"]:
                    evidence = copy.deepcopy(cand)
                    break
            elif cand["grant"] == event["grant"]:
                evidence = copy.deepcopy(cand)
                break
        assert evidence is not None, "no evidence for call %s" % event["id"]
        evidence["allowed_operations"] = list(evidence["allowed_operations"])

        expired = (at >= evidence["expires_at_ms"]) if boundary == "exclusive" \
            else (at > evidence["expires_at_ms"])
        bound = event["grant"] == evidence["grant"]
        rejected_input = expired or not bound

        if event["worker"] not in workers:
            workers[event["worker"]] = Verifier(
                {"mode": mode, "boundary": boundary, "claimed_axes": claimed,
                 "action_policy": policy},
                source, downstream, mutant)
        verifier = workers[event["worker"]]

        before_reads = len(source.reads)
        source.begin_call(call, rejected_input)
        try:
            answer = verifier.call(make_hostile_call(call), evidence)
        finally:
            source.end_call()
        reads = source.reads[before_reads:]

        truth = states[event["grant"]]
        assert event["truth"] == truth, "authored truth disagrees with timeline"
        mismatch = answer["observation"] is not None and answer["observation"]["status"] != truth
        expected = event["expected"]["by_mode"][mode][boundary]

        # --- source-read contract (transport layer audit) ---
        pre_source = len(sponge.failures)
        if not expired and bound:
            sponge.check(event["id"], "source_read_contract", len(reads),
                         1 if mode == "live_standing_read" else 0)
            if mode == "live_standing_read" and len(reads) == 1:
                sponge.check(event["id"], "source_observation_binding",
                             answer["observation"], reads[0]["observation"])
        for r in reads:
            sponge.check(event["id"], "source_read_worker", r["worker"], event["worker"])
            sponge.check(event["id"], "source_read_grant", r["grant"], event["grant"])
            sponge.check(event["id"], "source_read_time", r["at_ms"], event["at_ms"])
        diagnostic = rejected_input and answer["observation"] is not None
        if diagnostic:
            sponge.check(event["id"], "diagnostic_observation_provenance",
                         any(json.dumps(r["observation"], sort_keys=True) ==
                             json.dumps(answer["observation"], sort_keys=True)
                             for r in reads), True)
        assessment = {}
        assessment["source_contract"] = "failed" if len(sponge.failures) != pre_source else "matched"

        # --- binding prerequisite ---
        pre_binding = len(sponge.failures)
        sponge.check(event["id"], "evidence_binding", answer["evidence_binding"],
                     expected["evidence_binding"])
        assessment["evidence_binding"] = "failed" if len(sponge.failures) != pre_binding else "matched"

        # --- three axes ---
        for axis in AXES:
            if mapping[axis] == "not_claimed":
                not_claimed += 1
                assessment[axis] = "not_claimed"
                if axis == "action_authorization":
                    sponge.check(event["id"], "unclaimed_action",
                                 answer["action_decision"], "not_claimed")
                    sponge.check(event["id"], "unclaimed_dispatch",
                                 downstream.reached(event["id"]), False)
                continue
            if mapping[axis] == "not_supported":
                not_supported += 1
                assessment[axis] = "not_supported"
                sponge.check(event["id"], "unsupported_mapping_answer",
                             answer["action_decision"], "not_supported")
                sponge.check(event["id"], "unsupported_dispatch",
                             downstream.reached(event["id"]), False)
                continue
            before = len(sponge.failures)
            scored += 1
            if axis == "evidence_freshness":
                sponge.check(event["id"], axis, answer["evidence_freshness"],
                             expected["evidence_freshness"])
            elif axis == "authority_validity":
                if diagnostic:
                    state = "valid" if answer["observation"]["status"] == "active" else "revoked"
                    sponge.check(event["id"], "diagnostic_scoped_answer",
                                 answer["authority_answer"], state)
                    sponge.check(event["id"], "diagnostic_current_validity",
                                 answer["current_validity"],
                                 state if answer["observation"]["as_of_ms"] == event["at_ms"]
                                 else "not_established")
                else:
                    sponge.check(event["id"], "observation", answer["observation"],
                                 expected["observation"])
                    sponge.check(event["id"], "scoped_answer", answer["authority_answer"],
                                 expected["authority_answer"])
                    sponge.check(event["id"], "current_validity", answer["current_validity"],
                                 expected["current_validity"])
                    sponge.check(event["id"], "answer_differs_from_truth", mismatch,
                                 expected["observation_differs_from_truth"])
            elif axis == "action_authorization":
                sponge.check(event["id"], "action_decision", answer["action_decision"],
                             expected["action_decision"])
                sponge.check(event["id"], "downstream_reached",
                             downstream.reached(event["id"]), expected["downstream_reached"])
            failed_axis = (len(sponge.failures) != before)
            if axis == "authority_validity" and assessment["source_contract"] == "failed":
                failed_axis = True
            assessment[axis] = "failed" if failed_axis else "matched"

        # --- composite verification outcome (separately graded) ---
        if "evidence_freshness" in claimed and "authority_validity" in claimed:
            before = len(sponge.failures)
            composite_scored += 1
            sponge.check(event["id"], "verification_accepted",
                         answer["verification_accepted"], expected["verification_accepted"])
            assessment["verification_outcome"] = \
                "failed" if len(sponge.failures) != before else "matched"
        else:
            assessment["verification_outcome"] = "not_claimed"

        obs = answer["observation"]
        records.append({
            "case": case["id"], "call": event["id"], "at_ms": event["at_ms"],
            "worker": event["worker"], "evidence_id": evidence["id"],
            "evidence_grant": evidence["grant"],
            "evidence_issued_at_ms": evidence["issued_at_ms"],
            "evidence_expires_at_ms": evidence["expires_at_ms"],
            "mode": mode, "boundary": boundary,
            "authority_claim_scope": (
                {"kind": "bounded_observation", "max_observation_age_ms": profile["lease_ms"],
                 "anchor": profile["lease_anchor"]}
                if mode == "cached_lease" and not diagnostic
                else {"kind": "current_observation",
                      "max_observation_age_ms": profile["current_observation_max_age_ms"]}),
            "truth": truth, "answer": answer,
            "observation_age_ms": None if obs is None else event["at_ms"] - obs["as_of_ms"],
            "observation_differs_from_truth": mismatch,
            "downstream_reached": downstream.reached(event["id"]),
            "source_reads": reads, "assessment": assessment,
        })

    if sponge.failures:
        status = "failed"
    elif scored == 0:
        # scored is incremented inside the axis loop below; recompute
        pass
    status = "failed" if sponge.failures else None
    if status is None:
        if scored == 0:
            status = "no_scored_coverage"
        elif not_supported > 0:
            status = "partial_coverage"
        else:
            status = "matched"

    return {
        "case": case["id"], "mode": mode, "boundary": boundary,
        "claimed_axes": claimed, "action_policy": policy, "mapping": mapping,
        "status": status, "mutant": mutant,
        "worker_instances": len(workers), "reads": len(source.reads),
        "scored": scored, "composite_scored": composite_scored,
        "not_claimed": not_claimed, "not_supported": not_supported,
        "failures": sponge.failures, "records": records,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--vectors", default=None)
    args = ap.parse_args()

    default_vectors = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "vectors.json")
    path = args.vectors or default_vectors
    raw = open(path, "rb").read()
    vectors = json.loads(raw.decode("utf-8"))
    digest = hashlib.sha256(raw).hexdigest()

    # --- manifest digest gate (hard): only frozen vectors may be scored ---
    manifest = open(os.path.join(os.path.dirname(os.path.abspath(path)), "SHA256SUMS.txt"), encoding="utf-8").read()
    digest_gate = any(line.split()[0] == digest for line in manifest.strip().splitlines()
                      if line.strip() and "vectors.json" in line)
    if not digest_gate:
        sys.exit("DIGEST GATE FAILED: vectors sha256 %s not pinned in SHA256SUMS.txt - refusing to score" % digest)

    assert vectors["family"] == "lease-revocation-axes"
    assert vectors["status"] == "candidate" and vectors["version"] == 2
    assert vectors["profile"]["lease_ms"] == 120000
    assert vectors["profile"]["lease_anchor"] == "evidence_issued_at_ms"
    assert vectors["profile"]["action_policy"] == DEFAULT_POLICY
    assert vectors["profile"]["current_observation_max_age_ms"] == 0
    assert len(vectors["cases"]) == 12
    assert len({c["id"] for c in vectors["cases"]}) == 12
    total_calls = sum(1 for c in vectors["cases"] for e in c["timeline"] if e["event"] == "call")
    assert total_calls == 44, "frozen call inventory changed"

    # --- baseline runs: 4 profiles x 12 cases (scoring begins: oracle guard on) ---
    _oracle_guard_on()
    baselines = []
    for mode in MODES:
        for boundary in BOUNDARIES:
            for case in vectors["cases"]:
                r = run_case(vectors, case, mode, boundary)
                baselines.append(r)
    baseline_failures = [r for r in baselines if r["failures"]]
    for r in baselines:
        if r["case"] == "LRA-08":
            assert r["worker_instances"] == 2, "worker isolation broken"

    # --- mutation observation: 12 defective variants, pinned failure sets ---
    mutations = []
    for name, params in vectors["mutants"].items():
        runs = [run_case(vectors, c, params["mode"], params["boundary"], mutant=name)
                for c in vectors["cases"]]
        failed = [r["case"] for r in runs if r["failures"]]
        ok = (failed == params["expected_failed_cases"])
        detail = None
        if name == "second-worker-stale":
            lra08 = next(r for r in runs if r["case"] == "LRA-08")
            w2_only = all(rec["worker"] == "w2" for f in lra08["failures"]
                          for rec in lra08["records"] if rec["call"] == f.split(" ")[0])
            detail = "w2-only: %s" % w2_only
            ok = ok and w2_only
        if name == "fabricated-live-read":
            all_source = all(all("source_read_contract" in f for f in r["failures"])
                             for r in runs if r["failures"])
            detail = "fails on read provenance only: %s" % all_source
            ok = ok and all_source
        mutations.append({"name": name, "mode": params["mode"], "boundary": params["boundary"],
                          "failed_cases": failed, "expected": params["expected_failed_cases"],
                          "match": ok, "detail": detail})

    # --- optional post-expiry diagnostics: 5 cases x 4 profiles ---
    diagnostic_runs = []
    for mode in MODES:
        for boundary in BOUNDARIES:
            for case in vectors["cases"]:
                if case["id"] in DIAGNOSTIC_CASES:
                    r = run_case(vectors, case, mode, boundary, mutant="post-expiry-diagnostic")
                    diagnostic_runs.append(r)

    # --- reporting checks (declaration semantics; still under the oracle guard) ---
    none_run = run_case(vectors, vectors["cases"][0], "cached_lease", "exclusive", claimed=[])
    statement_run = run_case(vectors, vectors["cases"][1], "cached_lease", "exclusive",
                             claimed=["evidence_freshness", "authority_validity"])
    unmapped_run = run_case(vectors, vectors["cases"][0], "cached_lease", "exclusive",
                            policy="different-policy")
    action_only = run_case(vectors, vectors["cases"][0], "cached_lease", "exclusive",
                           claimed=["action_authorization"], policy="different-policy")
    oracle_inputs_not_read = not _ORACLE_GUARD["touched"]

    # --- oracle checkpoints (hand-reasoned table; frozen sibling of canonical vectors) ---
    # all scoring is complete at this point: turn the oracle guard off, then read
    # the oracle file for the separate checkpoint-comparison section only.
    _oracle_guard_off()
    candidate_oracle = path.replace("vectors.json", "oracle-checkpoints.json")
    if candidate_oracle != path and os.path.exists(candidate_oracle):
        oracle_path = candidate_oracle
    else:
        oracle_path = os.path.join(os.path.dirname(default_vectors), "oracle-checkpoints.json")
    oracle = json.load(open(oracle_path, encoding="utf-8"))
    oracle_failures = []
    for row in oracle:
        pool = diagnostic_runs if row.get("diagnostic") else baselines
        run = next((r for r in pool if r["case"] == row["case"] and r["mode"] == row["mode"]
                    and r["boundary"] == row["boundary"]), None)
        if run is None:
            oracle_failures.append("%s: no run" % row["case"])
            continue
        rec = next((r for r in run["records"] if r["call"] == row["call"]), None)
        if rec is None:
            oracle_failures.append("%s: no record" % row["call"])
            continue
        if rec["truth"] != row["truth"]:
            oracle_failures.append("%s truth" % row["call"])
        for key, value in row["answer"].items():
            if rec["answer"][key] != value:
                oracle_failures.append("%s %s" % (row["call"], key))
        if rec["downstream_reached"] != row["downstream_reached"]:
            oracle_failures.append("%s downstream" % row["call"])

    reporting_checks = {
        "no_scored_coverage": none_run["status"] == "no_scored_coverage" and none_run["scored"] == 0,
        "statement_only_matched": statement_run["status"] == "matched" and statement_run["not_claimed"] > 0,
        "policy_mismatch_partial": unmapped_run["status"] == "partial_coverage" and unmapped_run["not_supported"] > 0,
        "unsupported_only_no_coverage": action_only["status"] == "no_scored_coverage" and action_only["scored"] == 0,
        "oracle_inputs_not_read": oracle_inputs_not_read,
    }

    # (digest gate is enforced hard at load time, before any scoring)

    result = {
        "family": vectors["family"], "revision": 2,
        "vectors_sha256": digest, "digest_gate": digest_gate,
        "implementation": "RTTP & IQA independent Python runner (lra_runner.py)",
        "provenance": "independent implementation; comparisons against frozen revision-2 vectors only",
        "declaration": {"claimed_axes": ALL_CLAIMED, "action_policy": DEFAULT_POLICY,
                        "note": "action-time authorization is not claimed (by design)"},
        "baseline_runs": len(baselines),
        "baseline_failures": len(baseline_failures),
        "baseline_calls": sum(len(r["records"]) for r in baselines),
        "baseline_scored_axes": sum(r["scored"] for r in baselines),
        "composite_comparisons": sum(r["composite_scored"] for r in baselines),
        "mutations": mutations,
        "mutation_matches": all(m["match"] for m in mutations),
        "diagnostic_runs": len(diagnostic_runs),
        "diagnostic_failures": sum(1 for r in diagnostic_runs if r["failures"]),
        "oracle_checkpoints": len(oracle),
        "oracle_failures": oracle_failures,
        "reporting_checks": reporting_checks,
        "status": ("independent_run_matched"
                   if not baseline_failures and all(m["match"] for m in mutations)
                   and not oracle_failures and all(reporting_checks.values())
                   and digest_gate and not any(r["failures"] for r in diagnostic_runs)
                   else "independent_run_diverged"),
    }
    result["baselines"] = baselines
    result["diagnostic_run_records"] = diagnostic_runs

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("candidate %s revision 2, vectors sha256 %s" % (vectors["family"], digest[:16]))
        print("digest gate vs pinned manifest: %s" % ("OK" if digest_gate else "FAIL"))
        print("%d independent baseline runs, %d calls, %d axis comparisons; %d composite comparisons"
              % (result["baseline_runs"], result["baseline_calls"],
                 result["baseline_scored_axes"], result["composite_comparisons"]))
        print("baseline failures: %d | statuses: %s" % (
            result["baseline_failures"],
            sorted({r["status"] for r in baselines})))
        for m in mutations:
            print("  mutant %-28s %s  failed=%s" % (
                m["name"], "MATCH" if m["match"] else "DIVERGE", ",".join(m["failed_cases"]) or "-"))
        print("diagnostic runs: %d (failures: %d)"
              % (result["diagnostic_runs"], result["diagnostic_failures"]))
        print("oracle checkpoints: %d (failures: %s)"
              % (result["oracle_checkpoints"], oracle_failures or "none"))
        print("reporting checks: %s" % reporting_checks)
        print("RESULT: %s" % result["status"])

    sys.exit(0 if result["status"] == "independent_run_matched" else 1)


if __name__ == "__main__":
    main()
