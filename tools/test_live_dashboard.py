"""Bounded read-only Live UI tests. Fixtures are labelled test data, never demos."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0,str(REPO))
from dashboard.views.live import (
    finite, fmt, resource_point, counter_completion, elapsed_seconds,
    sample_rows, observation_figure,
)


def fixture(status="running"):
    start = 1_000_000_000
    samples = [{"raw_ns":start + index * 1_000_000_000, "phase":"measurement",
                "phase_elapsed_seconds":index,"trial":1,
                "traffic":{"input_unique":index*250,"output_unique":index*250-1,
                    "pending":1,"input_observed_pps":250.,"output_observed_pps":249.},
                "resources":{"bmv2":{"cpu_percent_one_core":125.,"rss_mib":100.},
                    "runner":{"cpu_percent_one_core":10.,"rss_mib":75.}}}
               for index in (1,2)]
    snapshot = {"status":status,"phase":"measurement","run_id":"ui-test-only",
        "session_id":"test-session", "started_raw_ns":start,
        "heartbeat_raw_ns":3_000_000_000,"trial":1,"total_trials":1,
        "metadata":{"mode":"rf_c","workload":"classification-heavy","rate_pps":250,
            "warmup_seconds":5,"measurement_seconds":20},
        "sample":samples[-1],"samples":samples,"telemetry":{"dropped_events":0,"errors":[]}}
    return SimpleNamespace(status=status,snapshot=snapshot,messages=[],run_id="ui-test-only",
                           events=[{"seq":1,"event":"measurement_started","phase":"measurement"}])


class LiveMetricTests(unittest.TestCase):
    def test_unavailable_is_not_zero(self):
        self.assertEqual(fmt(None),"Not available")
        self.assertEqual(fmt(0),"0")
        self.assertIsNone(finite(True))
        self.assertIsNone(finite(float("nan")))

    def test_one_core_cpu_can_exceed_100(self):
        self.assertEqual(resource_point(fixture().snapshot["sample"],"bmv2"),(125.,100.))

    def test_missing_resources_not_invented_in_warmup(self):
        self.assertEqual(resource_point({"phase":"warmup"},"runner"),(None,None))

    def test_negative_resource_observation_is_unavailable(self):
        self.assertEqual(resource_point({"resources":{"bmv2":{"rss_mib":-1,"cpu_percent_one_core":-1}}},"bmv2"),(None,None))

    def test_decision_completion_requires_accounting_gate(self):
        trial={"metrics":{"expected_decisions":10,"decisions":10},"metric_validity":{}}
        self.assertIsNone(counter_completion(trial))
        trial["metric_validity"]["classification_counts"]=True
        self.assertEqual(counter_completion(trial),100)

    def test_no_decision_metric_for_forwarding_or_zero_denominator(self):
        self.assertIsNone(counter_completion({}))
        self.assertIsNone(counter_completion({"metric_validity":{"classification_counts":True},"metrics":{"expected_decisions":0,"decisions":0}}))

    def test_elapsed_is_saved_and_terminal_graphs_do_not_extend(self):
        snap=fixture("completed").snapshot
        self.assertEqual(elapsed_seconds(snap),2)
        self.assertEqual(sample_rows(snap)[-1]["seconds"],2)
        self.assertIsNone(elapsed_seconds({"started_raw_ns":3,"heartbeat_raw_ns":2}))

    def test_missing_points_are_omitted_not_zero(self):
        snapshot=fixture().snapshot
        snapshot["samples"][0]["resources"]={}
        rows=sample_rows(snapshot)
        fig=observation_figure(rows,"cpu")
        self.assertTrue(all(list(trace.x)==[2.] for trace in fig.data))

    def test_actual_writer_wrapped_samples_render_exact_values(self):
        snapshot=fixture().snapshot
        snapshot["samples"]=[{"seq":i+1,"raw_ns":row["raw_ns"]+1,"phase":row["phase"],"trial":1,"sample":row}
                              for i,row in enumerate(snapshot["samples"])]
        self.assertEqual(sample_rows(snapshot)[0]["seconds"],1.)
        self.assertEqual(sample_rows(snapshot)[-1]["bmv2_cpu"],125.)

    def test_no_line_interpolates_warmup_to_measurement(self):
        snapshot=fixture().snapshot
        snapshot["samples"][0]["phase"]="warmup"
        fig=observation_figure(sample_rows(snapshot),"traffic")
        self.assertEqual(len(fig.data),4)
        self.assertTrue(all(len(trace.x)==1 for trace in fig.data))

    def test_retained_resources_do_not_create_new_drain_points(self):
        snapshot=fixture().snapshot
        for sample in snapshot["samples"]:
            for role in ("bmv2","runner"):
                sample["resources"][role]["sample_raw_ns"]=2_000_000_000
        snapshot["samples"][-1]["phase"]="draining"
        fig=observation_figure(sample_rows(snapshot),"cpu")
        self.assertEqual(len(fig.data),2)
        self.assertTrue(all(list(trace.x)==[1.] for trace in fig.data))

    def test_no_hidden_latency_plot(self):
        text=(REPO/"dashboard/views/live.py").read_text()
        self.assertNotIn("subprocess",text)
        self.assertNotIn("os.system",text)
        self.assertIn("@st.fragment(run_every=1.0)",text)
        self.assertIn("not established",text)


class LiveRenderingTests(unittest.TestCase):
    def render(self,evidence):
        from streamlit.testing.v1 import AppTest
        # The browser-visible production root is never changed; this fixture is local to AppTest.
        script="import sys\n" + f"sys.path.insert(0,{str(REPO)!r})\n" + \
            "from types import SimpleNamespace\nfrom dashboard.views.live import render_evidence\n" + \
            f"render_evidence(SimpleNamespace(**{vars(evidence)!r}))\n"
        result=AppTest.from_string(script,default_timeout=30).run()
        self.assertEqual(len(result.exception),0,[row.value for row in result.exception])
        self.assertEqual(len(result.button),0,"No privileged browser launch buttons")
        return result

    def test_inactive_no_fake_observations(self):
        app=self.render(SimpleNamespace(status="inactive",snapshot={},events=[],run_id=None,messages=[]))
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("No active experiment",text)
        self.assertEqual(len(app.get("plotly_chart")),0)

    def test_running_has_three_real_sample_charts(self):
        app=self.render(fixture())
        self.assertEqual(len(app.get("plotly_chart")),3)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("125.0%",text)
        self.assertIn("Pending",text)

    def test_stale_retains_graphs_and_warning(self):
        app=self.render(fixture("stale"))
        self.assertEqual(len(app.get("plotly_chart")),3)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Experiment stale",text)

    def test_corrupt_snapshot_never_exposes_metrics(self):
        app=self.render(fixture("corrupt"))
        self.assertEqual(len(app.get("plotly_chart")),0)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Telemetry integrity failure",text)
        self.assertNotIn("125.0%",text)

    def test_completed_does_not_inherit_clock_certificate(self):
        value=fixture("completed")
        value.snapshot["final_summary"]={"trials":[{
            "mode":"rf_c", "metrics":{"packets_sent":5000,"packets_received":5000,"expected_decisions":624,"decisions":624},
            "metric_validity":{"packet_accounting":True,"classification_counts":True},
            "verdicts":{"measurement_integrity":{"status":"PASS"},
                "independent_raw_qualification":{"status":"INCONCLUSIVE"},
                "sender_pacing_conformance":{"status":"PASS"}}}]}
        app=self.render(value)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("INCONCLUSIVE",text)
        self.assertIn("100.0%",text)
        self.assertEqual(len(app.get("plotly_chart")),3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
