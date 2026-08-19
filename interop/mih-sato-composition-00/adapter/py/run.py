#!/usr/bin/env python3
"""Independent adapter for the EMILIA cross-slot composition conformance pack.

Written from scratch against the published bytes in ../../corpus/. Python
standard library only: no third-party packages, and no code from the upstream
runner. This is the second of two independent adapters in this directory; the
TypeScript one is at ../ts/run.ts. Their results files must agree.

The pack's runner performs fourteen named join checks per case. Their semantics
are reimplemented here from the published bundle and the pack's mechanism
document. Nothing profile-native is evaluated; see SCOPE.md.
"""

import base64
import datetime
import hashlib
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PACK = ROOT / "corpus" / "examples" / "composition" / "cross-slot-conformance-v1"
OUT = pathlib.Path(os.environ["OUT_DIR"]).resolve() if os.environ.get("OUT_DIR") else ROOT

VOCABULARY = {"pass", "fail", "not_evaluated", "unsupported", "indeterminate"}


def canonical(value):
    """Recursive key sort then compact JSON.

    ensure_ascii MUST be False. The default True would escape non-ASCII
    characters and change the digest, which is the one trap that silently
    breaks agreement with the TypeScript adapter.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64u(value):
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def check(cid, status, detail):
    return {"id": cid, "status": status, "detail": detail}


# ---- the fourteen join checks ----

def artifact_bytes(b):
    failures = [n for n, e in b["slots"].items()
                if sha256(b64u(e["artifact"]["bytes_b64u"])) != e["artifact"]["sha256"]]
    return check("bundle.artifact_bytes", "pass" if not failures else "fail",
                 "all native artifact bytes match their pinned digests" if not failures
                 else "artifact digest mismatch: " + ",".join(failures))


def subject_bytes(b):
    raw = b64u(b["subject"]["action_artifact"]["bytes_b64u"])
    digest_ok = sha256(raw) == b["subject"]["action_digest"]
    content_ok = raw == canonical(b["subject"]["action"]).encode("utf-8")
    return check("subject.action_bytes", "pass" if digest_ok and content_ok else "fail",
                 "supplied action bytes must match both the visible action and pinned digest")


def digest_context(b):
    def compatible(v):
        copy = dict(v)
        copy.pop("representation", None)
        return canonical(copy)
    expected = compatible(b["subject"]["digest_context"])
    bad = [e for e in b["slots"].values()
           if compatible(e["subject"]["digest_context"]) != expected]
    return check("join.digest_context", "pass" if not bad else "indeterminate",
                 "all slots declare the same digest context" if not bad
                 else "at least one slot uses an incompatible profile or action projection")


def representation(b):
    expected = b["subject"]["digest_context"]["representation"]
    mismatch = any(e["subject"]["digest_context"]["representation"] != expected
                   for e in b["slots"].values())
    return check("join.digest_representation", "fail" if mismatch else "pass",
                 "declared digest representations differ" if mismatch
                 else "digest representation matches")


def cross_references(b):
    mismatch = False
    for entry in b["slots"].values():
        ref = entry["protected_cross_reference"]
        target = b["slots"].get(ref["target_slot"])
        if target is None or target["artifact"]["sha256"] != ref["artifact_digest"]:
            mismatch = True
    return check("join.protected_cross_reference", "fail" if mismatch else "pass",
                 "protected cross-reference does not identify supplied target bytes" if mismatch
                 else "all protected cross-references match supplied target bytes")


def additional_binding_context(b):
    bindings = [x for e in b["slots"].values() for x in e["additional_bindings"]]
    incomplete = any(not isinstance(x.get("purpose"), str)
                     or not isinstance(x.get("context"), str)
                     or not isinstance(x.get("digest"), str)
                     for x in bindings)
    return check("join.additional_binding_context", "fail" if incomplete else "pass",
                 "an additional binding is missing purpose, context, or digest" if incomplete
                 else "additional bindings carry complete declared context")


def binding_semantics(b):
    bindings = [x for e in b["slots"].values() for x in e["additional_bindings"]]
    unmet = False
    for purpose in b["policy"]["required_binding_purposes"]:
        matches = [x for x in bindings if x.get("purpose") == purpose]
        if not matches or all(x.get("understood") is not True for x in matches):
            unmet = True
    out = check("policy.binding_semantics", "unsupported" if unmet else "pass",
                "binding is structurally readable but cannot satisfy policy requiring understood semantics"
                if unmet else "every policy-required binding purpose has understood semantics")
    out["binding_state"] = "present_uninterpreted" if unmet else "understood"
    return out


def field_basis(b):
    missing = any(not isinstance(f.get("basis"), str) or len(f["basis"]) == 0
                  for e in b["slots"].values() for f in e["fields"].values())
    return check("join.field_basis", "indeterminate" if missing else "pass",
                 "joined field basis is absent" if missing
                 else "joined fields declare their bases")


def field_mapping(b, basis):
    if basis["status"] != "pass":
        return check("join.field_mapping", "not_evaluated",
                     "field mapping was not evaluated because a joined field lacks a declared basis")
    bases = []
    for e in b["slots"].values():
        v = e["fields"]["amount"]["basis"]
        if v not in bases:
            bases.append(v)
    if len(bases) <= 1:
        return check("join.field_mapping", "pass", "joined amount bases match")
    mapped = any({m["from_basis"], m["to_basis"]}.issuperset(set(bases))
                 for m in b["mappings"])
    return check("join.field_mapping", "pass" if mapped else "indeterminate",
                 "incompatible bases have a pinned mapping" if mapped
                 else "incompatible bases lack a pinned mapping")


def result_separation(b):
    return check("report.result_separation",
                 "pass" if b["reporting"]["native_results_separate"] is True else "fail",
                 "native slot and cross-slot results must remain separately named")


def result_preservation(b):
    return check("report.result_preservation",
                 "pass" if b["reporting"]["composition_overrides_native"] is False else "fail",
                 "composition must not upgrade, weaken, or overwrite a native result")


def exact_action(b):
    mismatch = any(e["subject"]["action_digest"] != b["subject"]["action_digest"]
                   for e in b["slots"].values())
    return check("join.exact_action", "fail" if mismatch else "pass",
                 "populated slots do not identify the same exact action" if mismatch
                 else "all populated slots identify the same exact action")


def not_evaluated_preservation(b):
    mismatch = any(e["native_result"] == "not_evaluated"
                   and b["reporting"]["reported_native_results"].get(name) != "not_evaluated"
                   for name, e in b["slots"].items())
    return check("report.not_evaluated_preservation", "fail" if mismatch else "pass",
                 "not_evaluated native result was relabeled as a verifier failure" if mismatch
                 else "not_evaluated native results remain not_evaluated")


def required_profiles(b):
    supported = set(b["policy"]["supported_profiles"])
    unknown = [p for p in b["policy"]["required_profiles"] if p not in supported]
    return check("policy.required_profile", "pass" if not unknown else "unsupported",
                 "all required profiles are supported" if not unknown
                 else "unsupported required profiles: " + ",".join(unknown))


def terminal_status(results):
    seen = [r["status"] for r in results]
    for candidate in ("fail", "unsupported", "indeterminate", "not_evaluated"):
        if candidate in seen:
            return candidate
    return "pass"


# ---- evaluation ----

def evaluate_case(item):
    b = item["input"]
    basis = field_basis(b)
    results = [
        artifact_bytes(b),
        subject_bytes(b),
        digest_context(b),
        representation(b),
        cross_references(b),
        additional_binding_context(b),
        binding_semantics(b),
        basis,
        field_mapping(b, basis),
        result_separation(b),
        result_preservation(b),
        exact_action(b),
        not_evaluated_preservation(b),
        required_profiles(b),
    ]
    for r in results:
        if r["status"] not in VOCABULARY:
            raise ValueError("invalid result vocabulary: " + str(r["status"]))
    primary = next((r for r in results if r["status"] != "pass"), None)
    native_results = [
        {
            "slot": name,
            "profile": e["profile"],
            "artifact_digest": e["artifact"]["sha256"],
            "native_result": e["native_result"],
            "reported_result": b["reporting"]["reported_native_results"].get(name),
        }
        for name, e in b["slots"].items()
    ]
    binding = next((r for r in results if r["id"] == "policy.binding_semantics"), None)
    return {
        "case_id": item["id"],
        "pair_id": item["pair_id"],
        "variant": item["variant"],
        "native_results": native_results,
        "join_results": results,
        "primary_check": primary["id"] if primary else "composition.complete",
        "terminal": terminal_status(results),
        "binding_state": binding["binding_state"] if binding else None,
        "crashed": False,
    }


def compare(item, observed):
    join_observed = {r["id"]: r["status"] for r in observed["join_results"]}
    native_observed = {r["slot"]: r["native_result"] for r in observed["native_results"]}
    terminal_match = observed["terminal"] == item["expected_terminal"]
    check_match = observed["primary_check"] == item["expected_check"]
    native_match = canonical(native_observed) == canonical(item["expected_native_results"])
    join_match = canonical(join_observed) == canonical(item["expected_join_results"])
    return {
        "id": item["id"],
        "pair_id": item["pair_id"],
        "variant": item["variant"],
        "expected_terminal": item["expected_terminal"],
        "expected_check": item["expected_check"],
        "actual_terminal": observed["terminal"],
        "actual_check": observed["primary_check"],
        "terminal_match": terminal_match,
        "check_match": check_match,
        "native_results_match": native_match,
        "join_results_match": join_match,
        "no_crash": observed["crashed"] is False,
        "passed": terminal_match and check_match and native_match and join_match
        and observed["crashed"] is False,
    }


def main():
    bundle_bytes = (PACK / "bundle.json").read_bytes()
    manifest_bytes = (PACK / "manifest.json").read_bytes()
    bundle = json.loads(bundle_bytes.decode("utf-8"))
    manifest = json.loads(manifest_bytes.decode("utf-8"))

    evaluated = [evaluate_case(item) for item in bundle["cases"]]
    checks = [compare(item, evaluated[i]) for i, item in enumerate(bundle["cases"])]
    passed_all = all(c["passed"] for c in checks)

    toolchain = "python " + sys.version.split()[0]

    results = {
        "@version": "AAC-COMPOSITION-CROSS-SLOT-RUN-v1",
        "adapter": "py",
        "toolchain": toolchain,
        "composition_pin": manifest["composition"]["revision"],
        "manifest_digest": sha256(canonical(manifest)),
        "bundle_digest": sha256(canonical(bundle)),
        "manifest_file_digest": sha256(manifest_bytes),
        "bundle_file_digest": sha256(bundle_bytes),
        "case_count": len(bundle["cases"]),
        "passed": passed_all,
        "reproduced": sum(1 for c in checks if c["passed"]),
        "checks": checks,
        "results": evaluated,
    }
    (OUT / "results-py.json").write_text(
        json.dumps(results, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    # Adapter-neutral canonical record. Both adapters write this file and the
    # bytes must be identical, so it carries no toolchain and no adapter name.
    canonical_results = {
        "@version": "AAC-COMPOSITION-CROSS-SLOT-RESULTS-v1",
        "composition_pin": manifest["composition"]["revision"],
        "manifest_digest": sha256(canonical(manifest)),
        "bundle_digest": sha256(canonical(bundle)),
        "case_count": len(bundle["cases"]),
        "reproduced": sum(1 for c in checks if c["passed"]),
        "vocabulary": bundle["result_vocabulary"],
        "rows": [
            {
                "id": c["id"],
                "variant": c["variant"],
                "expected_terminal": c["expected_terminal"],
                "expected_check": c["expected_check"],
                "observed_terminal": c["actual_terminal"],
                "observed_check": c["actual_check"],
                "result": "reproduced" if c["passed"] else "divergent",
            }
            for c in checks
        ],
    }
    (OUT / "results.json").write_text(
        json.dumps(canonical_results, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    adapter_digest = sha256((HERE / "run.py").read_bytes())
    report = {
        "@version": "EP-COMPOSITION-CROSS-SLOT-EXTERNAL-REPORT-v1",
        "status": "AWAITING_INDEPENDENT_RUN",
        "implementation": "Agent Authority Conformance lab adapter (Python)",
        "implementation_owner": "Agent Authority Conformance, LF Decentralized Trust lab",
        "implementation_revision": adapter_digest,
        "manifest_digest": sha256(canonical(manifest)),
        "bundle_digest": sha256(canonical(bundle)),
        "report_digest": None,
        "per_case_results": checks,
        "known_shared_dependencies": [],
        "execution_date": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "toolchain": toolchain,
        "signed_by": None,
    }
    without = {k: v for k, v in report.items() if k != "report_digest"}
    report["report_digest"] = sha256(canonical(without))
    (OUT / "external-report-py.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    sys.stdout.write(
        "cases %d, reproduced %d, passed %s\n"
        % (len(bundle["cases"]), results["reproduced"], passed_all))


if __name__ == "__main__":
    main()
