#!/usr/bin/env python3
"""replay_runner.py -- generic thin wrapper that replays a sealed external run
record through our own pipeline: verify the vendor pins, execute the recorded
commands exactly as the record specifies, and compare every produced output
against the recorded bytes (byte-identical modulo line endings, plus canonical
JSON equality).

Operator: ShaoBao Li (Lee) / Aicent Stack (RTTP CRI 27 / IQA CRI 28).

The wrapper executes the external record's own checker as code-as-run; it adds
no verdict logic of its own. It fails closed: any vendor-pin mismatch, any
stdout deviation, or any output mismatch aborts with a nonzero exit before the
record can claim a match. A record directory is replayable when it carries a
"profile.json" describing the commands, the vendor pins, the recorded outputs
and the expected summary; nothing in this wrapper knows the family, the
candidate, or the external operator.

Usage:
    python -I replay_runner.py <record-dir> [output.json]

Output (when given) is the machine-readable replay record: deterministic, no
timestamps, no paths, byte-replayable.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PROFILE_NAME = "profile.json"


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def to_lf(data):
    return data.replace(b"\r\n", b"\n")


def canonical_sha256(path):
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_pins(record_dir, pins, kind):
    failures = []
    for rel, expected in sorted(pins.items()):
        path = Path(record_dir) / rel
        if not path.is_file():
            failures.append("missing %s file: %s" % (kind, rel))
            continue
        actual = sha256_file(path)
        if actual != expected:
            failures.append("%s pin mismatch: %s (expected %s..., got %s...)"
                            % (kind, rel, expected[:16], actual[:16]))
    return failures


def run_command(record_dir, cmd, out_dir):
    argv = [sys.executable, "-I"] + [token.replace("{out}", out_dir) for token in cmd["argv"]]
    proc = subprocess.run(argv, cwd=str(record_dir), capture_output=True, text=True)
    stdout = to_lf(proc.stdout.encode("utf-8", errors="replace")).decode("utf-8")
    expected = cmd.get("expected_stdout")
    stdout_match = True
    if expected is not None:
        stdout_match = stdout.strip() == expected.strip()
    step = {
        "name": cmd["name"],
        "argv": cmd["argv"],
        "exit_code": proc.returncode,
        "stdout_expected": expected,
        "stdout_match": stdout_match,
        "produced": [],
    }
    return step, proc


def compare_outputs(record_dir, cmd, out_dir, step):
    all_ok = True
    for spec in cmd.get("produces", []):
        produced = Path(spec["path"].replace("{out}", out_dir))
        recorded = Path(record_dir) / spec["recorded"]
        entry = {"produced": spec["recorded"], "recorded_from": spec["path"]}
        if not produced.is_file():
            entry["error"] = "produced file missing"
            all_ok = False
        elif not recorded.is_file():
            entry["error"] = "recorded file missing"
            all_ok = False
        else:
            prod_raw = produced.read_bytes()
            rec_raw = recorded.read_bytes()
            prod_lf = sha256_bytes(to_lf(prod_raw))
            rec_lf = sha256_bytes(rec_raw)
            entry["sha256_recorded_lf"] = rec_lf
            entry["sha256_produced_lf"] = prod_lf
            entry["byte_match_lf"] = prod_lf == rec_lf
            entry["canonical_match"] = canonical_sha256(produced) == canonical_sha256(recorded)
            # environment-dependent detail (raw byte equality vs line endings):
            # reported on the console only, never stored in the JSON payload --
            # the recorded bytes are pinned LF, so raw equality differs by OS
            raw_match = sha256_bytes(prod_raw) == sha256_bytes(rec_raw)
            print("OUTPUT %-28s lf=%s canonical=%s raw=%s (%s...)" % (
                spec["recorded"],
                "match" if entry["byte_match_lf"] else "MISMATCH",
                "match" if entry["canonical_match"] else "MISMATCH",
                "match" if raw_match else "eol-only-diff",
                rec_lf[:16]))
            if not (entry["byte_match_lf"] and entry["canonical_match"]):
                all_ok = False
        step["produced"].append(entry)
    return all_ok


def main(argv):
    if len(argv) < 2:
        print("usage: replay_runner.py <record-dir> [output.json]")
        return 2
    record_dir = Path(argv[1])
    out_path = argv[2] if len(argv) > 2 else None
    profile = json.loads((record_dir / PROFILE_NAME).read_text(encoding="utf-8"))

    failures = verify_pins(record_dir, profile["vendor_pins"], "vendor")
    failures += verify_pins(record_dir, profile["recorded_pins"], "recorded")
    if failures:
        for line in failures:
            print("PIN FAIL:", line)
        print("REPLAY FAIL: %d pin failure(s); nothing was executed" % len(failures))
        return 1
    pins = profile["vendor_pins"]
    print("VENDOR PIN OK %d/%d (profile.json vendor_pins)" % (len(pins), len(pins)))
    rec_pins = profile["recorded_pins"]
    print("RECORDED PIN OK %d/%d (profile.json recorded_pins)" % (len(rec_pins), len(rec_pins)))

    steps = []
    outputs_ok = True
    commands_ok = True
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = str(Path(tmp))
        for cmd in profile["commands"]:
            step, proc = run_command(record_dir, cmd, out_dir)
            commands_ok &= (proc.returncode == 0 and step["stdout_match"])
            steps.append(step)
            print("COMMAND %-8s exit=%d stdout=%s" % (
                cmd["name"], proc.returncode, "match" if step["stdout_match"] else "MISMATCH"))
            if proc.returncode == 0 and step["stdout_match"]:
                outputs_ok &= compare_outputs(record_dir, cmd, out_dir, step)
            for entry in step["produced"]:
                if "error" in entry:
                    print("OUTPUT %-28s %s" % (entry["produced"], entry["error"]))

    # expected summary, checked against the recorded comparison output itself
    final_spec = None
    for cmd in profile["commands"]:
        for spec in cmd.get("produces", []):
            if spec["recorded"].endswith("final.json"):
                final_spec = spec
    summary = None
    if final_spec is not None:
        final = json.loads((record_dir / final_spec["recorded"]).read_text(encoding="utf-8"))
        summary = {
            "verdict_agreement": final.get("verdict_agreement"),
            "part_divergences": len(final.get("part_divergences") or []),
            "tally": final.get("tally"),
        }
    expected = profile.get("expected", {})
    summary_ok = True
    if summary is not None and expected:
        for key, want in expected.items():
            got = summary.get(key)
            if key == "part_divergences":
                summary_ok &= (got == want)
            else:
                summary_ok &= (got == want)
        if not summary_ok:
            print("EXPECTED MISMATCH: recorded summary %r vs profile expected %r"
                  % (summary, expected))
    elif summary is None and expected:
        summary_ok = False

    ok = commands_ok and outputs_ok and summary_ok
    payload = {
        "runner": "replay-runner",
        "runner_path": "replay/replay-runner/replay_runner.py",
        "operator": profile["operator"],
        "mode": profile["mode"],
        "record": profile["record"],
        "corpus": profile["corpus"],
        "profile_version": profile["profile_version"],
        "vendor_pins": profile["vendor_pins"],
        "recorded_pins": profile["recorded_pins"],
        "commands": steps,
        "summary": summary,
        "expected": expected,
        "status": "replay_matched" if ok else "replay_mismatch",
    }
    text = json.dumps(payload, indent=1, sort_keys=True) + "\n"
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8", newline="")
        print("run output written:", out_path)
    else:
        print(text, end="")
    if ok:
        print("REPLAY ok: %s reproduced (pins %d, commands %d, outputs %d)"
              % (profile["record"]["name"], len(pins), len(profile["commands"]),
                 sum(len(c.get("produces", [])) for c in profile["commands"])))
    else:
        print("REPLAY FAIL: record did not reproduce")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
