"""History presentation contracts; no experiment execution or evidence changes."""
from pathlib import Path
import unittest
from dashboard.evidence import LoadedEvidence
from dashboard.views.history import history_row, filter_rows, saved_health


class HistoryPresentationTests(unittest.TestCase):
    def item(self, data, status="verified"):
        return LoadedEvidence("history.example", status, data if status == "verified" else None,
                              Path("/explicit/summary.json"), "a" * 64, "fixture",
                              {"id": "example", "run_id": "20261008T223313Z_original", "category": "Performance", "mode": "forwarding", "target_pps": 1000})

    def test_completed_does_not_inherit_clock_qualification(self):
        row = history_row(self.item({"status": "completed", "execution_completed": True,
                                   "raw_rate_qualified": False, "independent_raw_qualification": "INCONCLUSIVE"}))
        self.assertEqual(row["Saved execution status"], "completed")
        self.assertEqual(row["Independent RAW clock"], "INCONCLUSIVE")
        self.assertEqual(row["Measurement integrity"], "UNAVAILABLE")
        self.assertEqual(row["Date (UTC)"], "2026-10-08")

    def test_original_failed_verdict_retained(self):
        row = history_row(self.item({"status": "incomplete", "verdicts": {"measurement_integrity": "FAIL", "sender_pacing_conformance": {"status": "WARNING"}}}))
        self.assertEqual(row["Measurement integrity"], "FAIL")
        self.assertEqual(row["Pacing"], "WARNING")
        self.assertEqual(len(filter_rows([row], statuses=["FAIL"])), 1)

    def test_recovery_not_reported_as_successful_original_run(self):
        row = history_row(self.item({"historical_final_summary_absent": True, "passed": False}))
        self.assertIn("RECOVERED", row["Saved execution status"])
        self.assertEqual(row["Independent RAW clock"], "UNAVAILABLE")

    def test_corrupt_evidence_values_withheld(self):
        row = history_row(self.item({"status": "passed"}, "corrupt"))
        self.assertEqual(row["Saved execution status"], "CORRUPT")
        self.assertEqual(row["Measurement integrity"], "UNAVAILABLE")

    def test_filters_match_separate_status_fields_and_query(self):
        row = history_row(self.item({"status": "completed", "verdicts": {"measurement_integrity": "PASS", "sender_pacing_conformance": "WARNING"}}))
        self.assertEqual(filter_rows([row], categories=["Performance"], configurations=["forwarding"], statuses=["WARNING"], query="1000", dates=["2026-10-08"]), [row])
        self.assertEqual(filter_rows([row], statuses=["FAIL"]), [])
        self.assertEqual(filter_rows([row], dates=["2026-10-09"]), [])

    def test_mixed_live_trial_health_remains_mixed(self):
        self.assertEqual(saved_health({"trials": [{"verdicts": {"measurement_integrity": "PASS"}}, {"verdicts": {"measurement_integrity": "FAIL"}}]}, "measurement_integrity"), "MIXED: FAIL, PASS")

    def test_saved_history_page_is_substantive(self):
        from streamlit.testing.v1 import AppTest
        script = "from dashboard.evidence import EvidenceStore\nfrom dashboard.views.history import render\nrender(EvidenceStore())"
        result = AppTest.from_string(script, default_timeout=60).run()
        self.assertFalse(result.exception, [value.value for value in result.exception])
        self.assertTrue(result.dataframe)
        self.assertTrue(result.selectbox)
        text = " ".join(element.value for element in result.markdown)
        self.assertIn("Saved experiment catalogue", text)
        self.assertNotIn("PAGE FOUNDATION", text)


if __name__ == "__main__":
    unittest.main()
