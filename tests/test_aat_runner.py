#!/usr/bin/env python3
"""Regression oracle for runners/aat_runner.py.

The point of this suite is the last test. A runner that checks only the upper
window bound cannot detect the defect in the 2026-07-29 drop as received, and a
runner that cannot detect that defect is worthless. That property is asserted
directly by re-running the AS-RECEIVED fixture with the lower-bound check
disabled and confirming the assertions below stop holding.

Requires network access to fetch the issuer JWKS.
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
AS_RECEIVED = FIXTURES / "aat-amdal-2026-07-29-AS-RECEIVED.json"
CORRECTED = FIXTURES / "aat-amdal-2026-07-29b.json"
HISTORICAL = [
    FIXTURES / "aat-amdal-2026-06-12.json",
    FIXTURES / "aat-amdal-2026-06-24.json",
    FIXTURES / "aat-amdal-2026-07-01.json",
    FIXTURES / "aat-amdal-2026-07-08.json",
]


def run(path: Path, check_lower_bound: bool = True):
    return run_fixture(path, ISSUER, RUNNERS, check_lower_bound=check_lower_bound)


class TestAsReceivedIsKnownBroken(unittest.TestCase):
    """The 2026-07-29 drop as shipped declares two vectors valid that are not."""

    def test_exactly_two_failures(self):
        result = run(AS_RECEIVED)
        self.assertEqual(result["summary"]["failed"], 2, result["summary"])

    def test_both_failures_are_not_yet_valid_on_live_and_act_binding(self):
        result = run(AS_RECEIVED)
        failed = {r["id"]: r for r in result["vectors"] if not r["match"]}
        self.assertEqual(
            sorted(failed),
            ["aat-2026-07-29-act-binding", "aat-2026-07-29-live"],
            sorted(failed),
        )
        for vector_id, record in failed.items():
            self.assertEqual(record["window"], "NOT_YET_VALID", vector_id)
            self.assertEqual(record["computed_result"], "nbf_reject", vector_id)
            self.assertEqual(record["expected_result"], "valid", vector_id)

    def test_the_expired_vector_still_matches(self):
        result = run(AS_RECEIVED)
        expired = next(
            r for r in result["vectors"] if r["id"] == "aat-2026-07-29-expired"
        )
        self.assertTrue(expired["match"])
        self.assertEqual(expired["window"], "EXPIRED")

    def test_signatures_are_all_valid(self):
        """The defect is in the window, not the signatures."""
        result = run(AS_RECEIVED)
        for record in result["vectors"]:
            self.assertEqual(record["signature"], "VALID", record["id"])


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
    def test_all_four_historical_fixtures_pass(self):
        for path in HISTORICAL:
            with self.subTest(fixture=path.name):
                result = run(path)
                self.assertEqual(
                    result["summary"]["failed"], 0, result["summary"]["failing_ids"]
                )


class TestSignatureAnomalyIsPinned(unittest.TestCase):
    """One historical vector does not verify, and that must stay visible.

    aat-2026-06-24-expired is the only vector in the corpus whose signature
    fails. Under signature-first precedence it now scores sig_reject against a
    declared exp_reject, so it no longer matches. The issuer's expectation is
    correct for the token that was sent; our local copy is corrupt. It is
    therefore quarantined rather than rescored, and excluded from the pass
    count until the issuer resends.
    """

    def test_the_one_known_bad_signature_is_reported(self):
        result = run(FIXTURES / "aat-amdal-2026-06-24.json")
        anomalies = result["summary"]["signature_anomalies"]
        self.assertEqual(len(anomalies), 1, anomalies)
        self.assertEqual(anomalies[0]["id"], "aat-2026-06-24-expired")
        self.assertEqual(anomalies[0]["signature"], "INVALID")

    def test_signature_precedence_beats_window(self):
        """The invariant that hid this vector for six weeks."""
        result = run(FIXTURES / "aat-amdal-2026-06-24.json")
        record = next(
            r for r in result["vectors"] if r["id"] == "aat-2026-06-24-expired"
        )
        self.assertEqual(record["signature"], "INVALID")
        self.assertEqual(record["window"], "EXPIRED")
        self.assertEqual(record["computed_result"], "sig_reject")
        self.assertFalse(record["match"])

    def test_that_vector_is_quarantined_not_rescored(self):
        result = run(FIXTURES / "aat-amdal-2026-06-24.json")
        record = next(
            r for r in result["vectors"] if r["id"] == "aat-2026-06-24-expired"
        )
        self.assertTrue(record["quarantined"])
        self.assertEqual(record["quarantine_state"], "local_integrity_anomaly")
        self.assertEqual(record["quarantine_pending"], "issuer_resend")
        self.assertEqual(record["expected_result"], "exp_reject")

    def test_quarantine_keeps_it_out_of_the_failure_count(self):
        result = run(FIXTURES / "aat-amdal-2026-06-24.json")
        self.assertEqual(result["summary"]["failed"], 0)
        self.assertEqual(len(result["summary"]["quarantined"]), 1)

    def test_every_other_corpus_vector_verifies(self):
        for path in HISTORICAL + [AS_RECEIVED, CORRECTED]:
            with self.subTest(fixture=path.name):
                result = run(path)
                anomalies = result["summary"]["signature_anomalies"]
                expected = 1 if path.name == "aat-amdal-2026-06-24.json" else 0
                self.assertEqual(len(anomalies), expected, anomalies)


class TestUpperBoundOnlyRunnerFailsThisSuite(unittest.TestCase):
    """The acceptance gate.

    Disabling the lower-bound check simulates a runner that only asks whether a
    token has expired. Against the AS-RECEIVED fixture such a runner reports
    zero failures, so every assertion in TestAsReceivedIsKnownBroken stops
    holding. That is the defect this corpus exists to catch.
    """

    def test_upper_bound_only_reports_no_failures_on_a_broken_fixture(self):
        result = run(AS_RECEIVED, check_lower_bound=False)
        self.assertEqual(
            result["summary"]["failed"],
            0,
            "expected an upper-bound-only runner to miss the defect entirely",
        )

    def test_the_two_bad_vectors_look_valid_without_the_lower_bound(self):
        result = run(AS_RECEIVED, check_lower_bound=False)
        for vector_id in ("aat-2026-07-29-live", "aat-2026-07-29-act-binding"):
            record = next(r for r in result["vectors"] if r["id"] == vector_id)
            self.assertEqual(record["window"], "INSIDE", vector_id)
            self.assertEqual(record["computed_result"], "valid", vector_id)
            self.assertTrue(record["match"], vector_id)

    def test_both_bounds_and_upper_only_disagree(self):
        """Pin the disagreement itself, so neither side can drift silently."""
        both = run(AS_RECEIVED, check_lower_bound=True)
        upper = run(AS_RECEIVED, check_lower_bound=False)
        self.assertEqual(both["summary"]["failed"], 2)
        self.assertEqual(upper["summary"]["failed"], 0)
        self.assertNotEqual(both["summary"]["failed"], upper["summary"]["failed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
