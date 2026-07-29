#!/usr/bin/env python3
"""Regression oracle for runners/aat_runner.py.

The point of this suite is the last class. A runner that checks only the upper
window bound cannot detect a not-yet-valid token, and a runner that cannot
detect that is worthless. The property is asserted by re-running the synthetic
oracle with the lower-bound check disabled and confirming it stops holding.

The oracle is synthetic and self-contained: its key is derived from a fixed
published seed and verified inline, so it never depends on a third party's DNS.
The issuer-sourced fixtures do require network access for the JWKS.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNNERS = REPO / "runners"
FIXTURES = REPO / "fixtures" / "cross-stack" / "aat-amdal"
sys.path.insert(0, str(RUNNERS))

from aat_runner import run_fixture  # noqa: E402

ISSUER = "agentlair"
SYNTHETIC = FIXTURES.parent / "synthetic" / "aat-synthetic-regression.json"
CORRECTED = FIXTURES / "aat-amdal-2026-07-29b.json"
HISTORICAL = [
    FIXTURES / "aat-amdal-2026-06-12.json",
    FIXTURES / "aat-amdal-2026-06-17.json",
    FIXTURES / "aat-amdal-2026-06-24.json",
    FIXTURES / "aat-amdal-2026-07-01.json",
    FIXTURES / "aat-amdal-2026-07-08.json",
    FIXTURES / "aat-amdal-2026-07-15.json",
    FIXTURES / "aat-amdal-2026-07-22.json",
    FIXTURES / "aat-amdal-2026-07-29-CORRECTED-1006.json",
]


ALL_FIXTURES = [(p, ISSUER) for p in HISTORICAL] + [
    (CORRECTED, ISSUER),
    (SYNTHETIC, "synthetic"),
]


def run(path: Path, check_lower_bound: bool = True, issuer: str = ISSUER):
    return run_fixture(path, issuer, RUNNERS, check_lower_bound=check_lower_bound)


def run_synthetic(check_lower_bound: bool = True):
    return run(SYNTHETIC, check_lower_bound=check_lower_bound, issuer="synthetic")


class TestSyntheticOracle(unittest.TestCase):
    """A fixture we own, whose lower-bound vector is the thing being asserted.

    This replaced a reconstruction of the issuer's 2026-07-29 first send. He
    corrected that send 57 minutes later, so publishing it as a permanent
    artifact pinned a mistake he had already fixed. A synthetic token we control
    can be regenerated and explained without a reader having to work out which
    of two mails was canonical.
    """

    def test_all_three_pass_with_both_bounds(self):
        result = run_synthetic()
        self.assertEqual(result["summary"]["failed"], 0, result["summary"])

    def test_the_lower_bound_vector_is_classified_as_such(self):
        result = run_synthetic()
        record = next(
            r for r in result["vectors"] if r["id"] == "syn-regression-not-yet-valid"
        )
        self.assertEqual(record["window"], "NOT_YET_VALID")
        self.assertEqual(record["computed_result"], "nbf_reject")

    def test_it_needs_no_network(self):
        result = run_synthetic()
        self.assertEqual(result["run"]["key_source"], "inline (no network)")

    def test_signatures_are_all_valid(self):
        result = run_synthetic()
        for record in result["vectors"]:
            with self.subTest(vector=record["id"]):
                self.assertEqual(record["signature"], "VALID")


class TestCorrectedDrop(unittest.TestCase):
    def test_zero_failures(self):
        result = run(CORRECTED)
        self.assertEqual(result["summary"]["failed"], 0, result["summary"]["failing_ids"])
        self.assertEqual(result["summary"]["vector_count"], 4)

    def test_not_yet_valid_vector_is_classified_as_such(self):
        result = run(CORRECTED)
        record = next(
            r for r in result["vectors"] if r["id"] == "aat-2026-07-29b-not-yet-valid"
        )
        self.assertEqual(record["window"], "NOT_YET_VALID")
        self.assertEqual(record["computed_result"], "nbf_reject")

    def test_act_binding_digest_matches(self):
        result = run(CORRECTED)
        record = next(
            r for r in result["vectors"] if r["id"] == "aat-2026-07-29b-act-binding"
        )
        self.assertEqual(record["act_binding"], "MATCH", record)

    def test_repeated_jti_is_observed_and_not_skipped(self):
        """The not-yet-valid vector reuses the live token, so its jti repeats."""
        result = run(CORRECTED)
        observations = result["observations"]
        self.assertEqual(observations["jti_total"], 4)
        self.assertEqual(observations["jti_distinct"], 3)
        self.assertEqual(len(observations["jti_repeated"]), 1)
        # every vector is still evaluated, none dropped for repeating a jti
        self.assertEqual(len(result["vectors"]), 4)

    def test_subject_consistency_is_an_observation(self):
        result = run(CORRECTED)
        self.assertTrue(result["observations"]["single_subject"])
        self.assertEqual(result["summary"]["failed"], 0)


class TestHistoricalCorpus(unittest.TestCase):
    def test_all_historical_fixtures_pass(self):
        for path in HISTORICAL:
            with self.subTest(fixture=path.name):
                result = run(path)
                self.assertEqual(
                    result["summary"]["failed"], 0, result["summary"]["failing_ids"]
                )


class TestCorpusIntegrity(unittest.TestCase):
    """The 2026-06-24 repair, and the detector that would have caught it.

    Our local copy of aat-2026-06-24-expired lost one character from al_nid at
    the write boundary in June. It still parsed, still decoded, and failed only
    the signature, so it read as an ordinary expired vector for six weeks. The
    issuer resent the bytes on 2026-07-29 and the fixture is repaired.
    """

    def test_no_signature_anomalies_anywhere(self):
        for path, issuer in ALL_FIXTURES:
            with self.subTest(fixture=path.name):
                result = run(path, issuer=issuer)
                self.assertEqual(result["summary"]["signature_anomalies"], [])

    def test_no_integrity_anomalies_anywhere(self):
        for path, issuer in ALL_FIXTURES:
            with self.subTest(fixture=path.name):
                result = run(path, issuer=issuer)
                self.assertEqual(result["summary"]["integrity_anomalies"], [])

    def test_the_repaired_vector_now_verifies(self):
        result = run(FIXTURES / "aat-amdal-2026-06-24.json")
        record = next(
            r for r in result["vectors"] if r["id"] == "aat-2026-06-24-expired"
        )
        self.assertEqual(record["signature"], "VALID")
        self.assertEqual(record["computed_result"], "exp_reject")
        self.assertTrue(record["match"])
        self.assertEqual(record["token_len"], 870)
        self.assertEqual(
            record["token_sha256"],
            "560da7b4e38fd0590dc92046f5b69d931c81c9629bff3177e2ddd17102d11bee",
        )

    def test_the_malformed_al_nid_detector_catches_the_june_corruption(self):
        """The cheap check that would have localised it without any signature."""
        import aat_runner
        good = "did:key:z6MkgRmUXtGdTkXhAcfpoabEyvZEjsdvTnGw6gaX3LcSdhhj"
        corrupt = "did:key:z6MkgRmUXtGdTkXhAcfpoabEyZEjsdvTnGw6gaX3LcSdhhj"
        self.assertTrue(aat_runner.did_key_wellformed(good))
        self.assertFalse(aat_runner.did_key_wellformed(corrupt))

    def test_every_vector_carries_a_declared_fingerprint_that_matches(self):
        for path, issuer in ALL_FIXTURES:
            with self.subTest(fixture=path.name):
                result = run(path, issuer=issuer)
                for record in result["vectors"]:
                    self.assertIs(record.get("fingerprint_match"), True, record["id"])


class TestReconstructedDrops(unittest.TestCase):
    """Three drops were verified in correspondence and never ingested."""

    RECONSTRUCTED = [
        FIXTURES / "aat-amdal-2026-06-17.json",
        FIXTURES / "aat-amdal-2026-07-15.json",
        FIXTURES / "aat-amdal-2026-07-22.json",
    ]

    def test_all_reconstructed_drops_pass(self):
        for path in self.RECONSTRUCTED:
            with self.subTest(fixture=path.name):
                result = run(path)
                self.assertEqual(result["summary"]["failed"], 0, result["summary"])

    def test_rotation_holds_from_07_01_onward(self):
        """Two seams broke early. 06-17 and 06-24 are recorded, not hidden."""
        import json as _json, base64 as _b64
        def jti(path, vid):
            with open(path, encoding="utf-8") as fh:
                d = _json.load(fh)
            v = [x for x in d["vectors"] if x["id"] == vid][0]
            pad = lambda t: t + "=" * (-len(t) % 4)
            return _json.loads(_b64.urlsafe_b64decode(pad(v["aat"].split(".")[1])))["jti"]
        pairs = [
            ("aat-amdal-2026-07-01.json", "aat-2026-07-01-expired",
             "aat-amdal-2026-06-24.json", "aat-2026-06-24-live"),
            ("aat-amdal-2026-07-08.json", "aat-2026-07-08-expired",
             "aat-amdal-2026-07-01.json", "aat-2026-07-01-live"),
            ("aat-amdal-2026-07-15.json", "aat-2026-07-15-expired",
             "aat-amdal-2026-07-08.json", "aat-2026-07-08-live"),
            ("aat-amdal-2026-07-22.json", "aat-2026-07-22-expired",
             "aat-amdal-2026-07-15.json", "aat-2026-07-15-live"),
            ("aat-amdal-2026-07-29b.json", "aat-2026-07-29b-expired",
             "aat-amdal-2026-07-22.json", "aat-2026-07-22-live"),
        ]
        for ef, ev, lf, lv in pairs:
            with self.subTest(drop=ef):
                self.assertEqual(jti(FIXTURES / ef, ev), jti(FIXTURES / lf, lv))


class TestUpperBoundOnlyRunnerFailsThisSuite(unittest.TestCase):
    """The acceptance gate. Remove the lower bound and the oracle must go red."""

    def test_upper_bound_only_misses_the_lower_bound_vector(self):
        result = run_synthetic(check_lower_bound=False)
        self.assertEqual(result["summary"]["failing_ids"], ["syn-regression-not-yet-valid"])

    def test_that_vector_reads_valid_without_the_lower_bound(self):
        result = run_synthetic(check_lower_bound=False)
        record = next(
            r for r in result["vectors"] if r["id"] == "syn-regression-not-yet-valid"
        )
        self.assertEqual(record["window"], "INSIDE")
        self.assertEqual(record["computed_result"], "valid")
        self.assertFalse(record["match"])

    def test_both_bounds_and_upper_only_disagree(self):
        self.assertEqual(run_synthetic()["summary"]["failed"], 0)
        self.assertEqual(run_synthetic(check_lower_bound=False)["summary"]["failed"], 1)
