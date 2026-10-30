"""Presentation-only Live Monitor regressions; fixtures are not research evidence.

These tests never launch a switch, send traffic, fit a model or write live state.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from dashboard.live_presentation import (
    LIVE_STYLE, health_explanation, render_journey, synthetic_journey,
)
from dashboard.views.live import observation_figure, sample_rows
from tools.test_live_dashboard import fixture


def stage(rows, label):
    return next(row for row in rows if row["label"] == label)


def text_of(app):
    return "\n".join(str(row.value) for row in app.markdown)


def completed_fixture(packet_valid=True, decision_valid=True):
    value = fixture("completed")
    value.snapshot["phase"] = "completed"
    value.snapshot["final_summary"] = {
        "trials": [{
            "mode": "rf_c",
            "metrics": {
                "packets_sent": 5000, "packets_received": 5000,
                "expected_decisions": 624, "decisions": 624,
            },
            "metric_validity": {
                "packet_accounting": packet_valid,
                "classification_counts": decision_valid,
            },
            "verdicts": {
                "measurement_integrity": {"status": "PASS"},
                "independent_raw_qualification": {"status": "INCONCLUSIVE"},
                "sender_pacing_conformance": {"status": "WARNING"},
            },
        }],
    }
    return value


class JourneyTests(unittest.TestCase):
    def test_measurement_does_not_invent_prior_milestones(self):
        value = fixture()
        rows = synthetic_journey(value.snapshot, value.events, value.status)
        self.assertEqual(len(rows), 6)
        self.assertEqual(stage(rows, "Measurement")["state"], "active")
        self.assertEqual(stage(rows, "Warm-up")["state"], "pending")
        self.assertEqual(stage(rows, "Switch startup")["state"], "pending")
        self.assertEqual(stage(rows, "Acquisition complete")["state"], "pending")

    def test_retained_events_can_establish_observed_prior_stage(self):
        value = fixture()
        value.events.insert(0, {"event": "warmup_started", "phase": "warmup"})
        rows = synthetic_journey(value.snapshot, value.events, value.status)
        self.assertEqual(stage(rows, "Warm-up")["state"], "observed")
        self.assertEqual(stage(rows, "Measurement")["state"], "active")

    def test_switch_ready_is_more_specific_than_preparing_wrapper(self):
        rows = synthetic_journey(
            {"phase": "preparing"}, [{"event": "switch_ready"}], "running"
        )
        self.assertEqual(stage(rows, "Switch startup")["state"], "active")
        self.assertEqual(stage(rows, "Warm-up")["state"], "pending")

    def test_completed_acquisition_does_not_establish_metric_pass(self):
        value = completed_fixture()
        rows = synthetic_journey(value.snapshot, value.events, value.status)
        final = stage(rows, "Acquisition complete")
        self.assertEqual(final["state"], "observed")
        self.assertIn("verdicts remain separate", final["detail"])
        self.assertFalse(any(row["state"] == "active" for row in rows))

    def test_failed_measurement_has_no_inferred_completed_acquisition(self):
        value = fixture("failed")
        rows = synthetic_journey(value.snapshot, value.events, value.status)
        self.assertEqual(stage(rows, "Measurement")["state"], "failed")
        self.assertEqual(stage(rows, "Acquisition complete")["state"], "pending")

    def test_stale_interrupted_cancelled_are_last_observed_not_active(self):
        for state in ("stale", "interrupted", "cancelled"):
            with self.subTest(state=state):
                value = fixture(state)
                rows = synthetic_journey(value.snapshot, value.events, value.status)
                self.assertEqual(stage(rows, "Measurement")["state"], "warning")
                self.assertFalse(any(row["state"] == "active" for row in rows))
                self.assertEqual(stage(rows, "Acquisition complete")["state"], "pending")

    def test_unknown_phase_and_empty_history_are_not_reported_as_success(self):
        rows = synthetic_journey({"phase": "not-a-recorded-stage"}, [], "running")
        self.assertTrue(all(row["state"] == "pending" for row in rows))

    def test_helpers_do_not_mutate_evidence_or_events(self):
        value = completed_fixture()
        before = copy.deepcopy((value.snapshot, value.events))
        synthetic_journey(value.snapshot, value.events, value.status)
        self.assertEqual((value.snapshot, value.events), before)


class ExplanationTests(unittest.TestCase):
    def test_clock_inconclusive_is_not_a_classifier_failure_verdict(self):
        message = health_explanation("independent_raw_qualification", "INCONCLUSIVE")
        self.assertIn("insufficient", message)
        self.assertIn("does not itself mean the classifier failed", message)

    def test_pacing_warning_preserves_separately_valid_counts(self):
        message = health_explanation("sender_pacing_conformance", "WARNING")
        self.assertIn("counts can remain valid", message)
        self.assertIn("uniform-load", message)

    def test_integrity_pass_does_not_inherit_independent_clock_qualification(self):
        message = health_explanation("measurement_integrity", "PASS")
        self.assertIn("not independent clock qualification", message)

    def test_clock_pass_does_not_qualify_kernel_latency(self):
        message = health_explanation("independent_raw_qualification", "PASS")
        self.assertIn("kernel latency is still separate", message)

    def test_unknown_status_is_not_replaced_by_pass_or_zero(self):
        for check, status in (("unknown-check", "PASS"),
                              ("measurement_integrity", None),
                              ("sender_pacing_conformance", "NOT FINALIZED")):
            with self.subTest(check=check, status=status):
                self.assertIn("no PASS or zero value is assumed", health_explanation(check, status))

    def test_styles_are_local_to_live_monitor_classes(self):
        self.assertIn(".etc-live-journey", LIVE_STYLE)
        for global_selector in (".stApp", "body {", "html {", '[data-testid="stSidebar"]'):
            self.assertNotIn(global_selector, LIVE_STYLE)


class TrafficPlotTests(unittest.TestCase):
    def test_nominal_target_line_does_not_change_observed_series(self):
        rows = sample_rows(fixture().snapshot)
        before = copy.deepcopy(rows)
        figure = observation_figure(rows, "traffic", target_rate=250)
        self.assertEqual(rows, before)
        self.assertEqual(list(figure.data[0].y), [250., 250.])
        self.assertEqual(list(figure.data[1].y), [249., 249.])
        targets = [shape for shape in figure.layout.shapes
                   if shape.type == "line" and shape.y0 == 250 and shape.y1 == 250]
        self.assertEqual(len(targets), 1)
        self.assertTrue(any("not achieved rate" in (annotation.text or "")
                            for annotation in figure.layout.annotations))

    def test_invalid_or_missing_target_does_not_create_a_zero_target(self):
        rows = sample_rows(fixture().snapshot)
        for target in (None, True, -1, 0, float("nan")):
            with self.subTest(target=target):
                figure = observation_figure(rows, "traffic", target_rate=target)
                self.assertFalse(any(shape.type == "line" for shape in figure.layout.shapes))

    def test_target_is_not_drawn_on_cpu_or_memory_axes(self):
        rows = sample_rows(fixture().snapshot)
        for kind in ("cpu", "memory"):
            with self.subTest(kind=kind):
                figure = observation_figure(rows, kind, target_rate=250)
                self.assertFalse(any(shape.type == "line" and shape.y0 == 250
                                     for shape in figure.layout.shapes))

    def test_phase_bands_do_not_extend_beyond_real_observations(self):
        rows = sample_rows(fixture().snapshot)
        figure = observation_figure(rows, "traffic", target_rate=250)
        minimum = min(row["seconds"] for row in rows)
        maximum = max(row["seconds"] for row in rows)
        for shape in figure.layout.shapes:
            if shape.type == "rect":
                self.assertGreaterEqual(shape.x0, minimum)
                self.assertLessEqual(shape.x1, maximum)


class PresentationRenderingTests(unittest.TestCase):
    def render(self, evidence):
        from streamlit.testing.v1 import AppTest
        script = "import sys\n" + f"sys.path.insert(0,{str(REPO)!r})\n" + \
            "from types import SimpleNamespace\nfrom dashboard.views.live import render_evidence\n" + \
            f"render_evidence(SimpleNamespace(**{vars(evidence)!r}))\n"
        app = AppTest.from_string(script, default_timeout=30).run()
        self.assertEqual(len(app.exception), 0, [row.value for row in app.exception])
        self.assertEqual(len(app.button), 0)
        return app

    def test_completed_outcome_is_before_observed_traffic(self):
        app = self.render(completed_fixture())
        text = text_of(app)
        self.assertLess(text.index("Recorded trial outcome"), text.index("Observed traffic"))
        self.assertIn("INCONCLUSIVE", text)
        self.assertIn("WARNING", text)
        self.assertIn("100.0%", text)
        self.assertEqual(len(app.get("plotly_chart")), 3)

    def test_invalid_accounting_stays_explicit_and_completion_unavailable(self):
        app = self.render(completed_fixture(packet_valid=False, decision_valid=False))
        text = text_of(app)
        self.assertIn("packet accounting INVALID or unverified", text)
        self.assertNotIn("100.0%", text)
        self.assertIn("Not available", text)

    def test_known_zero_counts_are_not_replaced_by_unavailable_or_success(self):
        value = completed_fixture()
        value.snapshot["final_summary"]["trials"][0]["metrics"].update(
            packets_sent=0, packets_received=0, decisions=0, expected_decisions=0
        )
        text = text_of(self.render(value))
        self.assertIn("0 / 0", text)
        self.assertNotIn("100.0%", text)

    def test_missing_final_counts_remain_unavailable(self):
        value = completed_fixture()
        value.snapshot["final_summary"]["trials"][0]["metrics"] = {}
        text = text_of(self.render(value))
        self.assertIn("Not available / Not available", text)
        self.assertNotIn("100.0%", text)

    def test_journey_escapes_evidence_derived_labels_and_details(self):
        from streamlit.testing.v1 import AppTest
        steps = [{"label": "<script>example</script>", "state": "observed",
                  "detail": '<img src=x onerror="example">'}]
        script = "import sys\n" + f"sys.path.insert(0,{str(REPO)!r})\n" + \
            "from dashboard.live_presentation import render_journey\n" + \
            f"render_journey({steps!r})\n"
        app = AppTest.from_string(script, default_timeout=30).run()
        self.assertEqual(len(app.exception), 0)
        text = text_of(app)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("&lt;img", text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("<img", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
