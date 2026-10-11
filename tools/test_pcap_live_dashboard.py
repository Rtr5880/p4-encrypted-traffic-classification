"""Read-only Stage 3 UI tests; fixtures never enter production live evidence."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

REPO=Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0,str(REPO))
from dashboard.views.pcap_live import (
    B_FEATURES,C_FEATURES,CLASSES,number,result_issues,score_figure,
    feature_comparison,timing_rows,comparison_interpretation,
    monitoring_counts,monitoring_health,resource_rows,resource_figure,
)


def result(model):
    values={name:value for name,value in zip(C_FEATURES,(120,160,1100,50,70,400,4,7))}
    return {
        "feature_set":model,"status":"verified","class_order":list(CLASSES),
        "features_used":{name:values[name] for name in (B_FEATURES if model=="B" else C_FEATURES)},
        "leaf_ids":list(range(10)),"python_leaf_ids":list(range(10)),
        "scores":[10,20,30,40,90,50],"p4_prediction":"STREAMING","python_prediction":"STREAMING",
        "parity":dict(feature=True,leaf=True,score=True,prediction=True),
        "native_times_us":[1000+60*i for i in range(8)],"native_iats_us":[60]*7,
        "clock_quality":{"clean":True},
        "decision_counters":[{"bytes":140 if i==4 else 0,"packets":1 if i==4 else 0} for i in range(6)],
        "capture_time_prediction":"STREAMING",
    }


def evidence(mode="compare",status="completed"):
    models="BC" if mode=="compare" else "B" if mode=="rf_b" else "C"
    source={
        "capture_id":"test-fixture/example.pcap","capture_name":"test-fixture.pcap",
        "record_id":"test-record","capture_activity_hint":"VOIP","relative_us":[60*i for i in range(8)],
        "wire_key":[17,["10.0.0.1",10000],["10.0.0.2",443]],
        "packet_summary":[{"position":i+1,"original_frame":100+i,"ip_size_bytes":140,
            "direction":"F" if i%2==0 else "R","capture_offset_us":60*i} for i in range(8)],
    }
    snapshot={"metadata":{"demo_kind":"pcap","mode":mode,"source_example":source},
        "phase":"completed","classification_results":{model:result(model) for model in models},
        "packet_progress":{},"final_summary":{"evidence":"/test-fixture-only"}}
    return SimpleNamespace(status=status,snapshot=snapshot,run_id="test-only",messages=[],
        events=[{"seq":1,"event":"pcap_classification_verified"}])


def monitoring(model="B",phases=("replay","replay","drain")):
    return {
        "model":model,"phase":"verification","window_label":"Replay/capture window including socket setup and idle drain; excludes process startup and CLI",
        "traffic":{"input_observed":8,"output_observed":8,"pending_output":0},
        "completed_accounting":{"sent_packets":8,"input_observed":8,"output_observed":8,
            "transport_passed":True,"counters_verified":True,"decisions":1,"expected_decisions":1,
            "missing_output_indices":[],"capture_socket_drops":None,"errors":[]},
        "resources":{"bmv2":{"cpu_percent_one_core":125.,"rss_mib":150.,"sample_raw_ns":3_000_000_000},
                     "runner":{"cpu_percent_one_core":10.,"rss_mib":75.,"sample_raw_ns":3_000_000_000}},
        "resource_samples":[{"raw_ns":(i+1)*1_000_000_000,"phase":phase,"resources":{
            role:{"cpu_percent_one_core":value,"rss_mib":150. if role=="bmv2" else 75.,
                  "sample_raw_ns":(i+1)*1_000_000_000,"cpu_interval_phase":phase}
            for role,value in (("bmv2",125.),("runner",10.))}} for i,phase in enumerate(phases)],
        "monitoring_errors":[],
    }


class PcapHelpersTests(unittest.TestCase):
    def test_missing_numeric_is_not_zero_or_nan(self):
        for value in (None,True,float("nan"),float("inf")):
            self.assertEqual(number(value),"Not available")
        self.assertEqual(number(0),"0")

    def test_frozen_vectors_match_expected_dimensions(self):
        for model in "BC":
            self.assertEqual(result_issues(result(model),model),[])

    def test_intermediate_counts_and_identity_required(self):
        value=result("B")
        value["leaf_ids"]=[1]
        value["scores"]=[1]
        value["class_order"]=list(reversed(CLASSES))
        value["feature_set"]="C"
        self.assertEqual(len(result_issues(value,"B")),4)

    def test_features_must_not_be_boolean_negative_or_nan(self):
        for invalid in (True,-1,float("nan")):
            value=result("C");value["features_used"]["iat_min"]=invalid
            self.assertTrue(result_issues(value,"C"))

    def test_argmax_ties_keep_lowest_class_index(self):
        value=result("B");value["scores"]=[100]*6;value["p4_prediction"]="CHAT"
        self.assertEqual(result_issues(value,"B"),[])
        value["p4_prediction"]="VOIP"
        self.assertTrue(result_issues(value,"B"))

    def test_class_score_plot_contains_actual_six_integer_scores(self):
        value=result("C");figure=score_figure(value,"C")
        self.assertEqual(list(figure.data[0].x),value["scores"])
        self.assertEqual(list(figure.data[0].y),list(CLASSES))

    def test_direction_columns_are_unavailable_for_b_not_zero(self):
        rows=feature_comparison({"B":result("B"),"C":result("C")})
        self.assertEqual(len(rows),8)
        self.assertTrue(all(row["RF-B native"] is None for row in rows[-2:]))
        self.assertTrue(all(row["Role"]=="C-only model input" for row in rows[-2:]))

    def test_native_timing_difference_is_not_hidden(self):
        values={"B":result("B"),"C":result("C")}
        values["C"]["native_iats_us"]=[61]*7
        rows=timing_rows(values,{"relative_us":[60*i for i in range(8)]})
        self.assertEqual(len(rows),7)
        self.assertTrue(all(row["C minus B (us)"]==1 for row in rows))
        self.assertTrue(all(row["Source capture (us)"]==60 for row in rows))

    def test_missing_timing_not_invented(self):
        rows=timing_rows({}, {})
        self.assertTrue(all(row["RF-B native (us)"] is None and row["Source capture (us)"] is None for row in rows))

    def test_same_class_can_have_different_iat_features(self):
        values={"B":result("B"),"C":result("C")}
        values["C"]["features_used"]["iat_sum"]=401
        title,text=comparison_interpretation(values)
        self.assertEqual(title,"Models agree")
        self.assertIn("not a direction-only",text)

    def test_prediction_disagreement_does_not_prove_direction_effect(self):
        values={"B":result("B"),"C":result("C")}
        values["C"]["scores"]=[10,20,30,40,50,90]
        values["C"]["p4_prediction"]="VOIP"
        title,text=comparison_interpretation(values)
        self.assertEqual(title,"Models disagree")
        self.assertIn("does not establish identical",text)

    def test_incomplete_pair_does_not_infer_second_prediction(self):
        self.assertEqual(comparison_interpretation({"B":result("B")})[0],"Pair incomplete")

    def test_browser_controls_remain_read_only(self):
        source=(REPO/"dashboard/views/pcap_live.py").read_text()
        for unsafe in ("subprocess","os.system","st.button(","st.download_button("):
            self.assertNotIn(unsafe,source)
        self.assertIn("never launch BMv2",source)

    def test_missing_monitoring_not_invented_zero(self):
        self.assertTrue(all(value is None for value in monitoring_counts({},{}).values()))
        self.assertEqual(monitoring_health({},None)["Tagged packet accounting"],"PENDING")
        self.assertIsNone(resource_figure({},"cpu"))

    def test_counts_keep_sender_observation_and_verified_decisions_distinct(self):
        row=monitoring()
        self.assertEqual(monitoring_counts(row,{})["sent"],8)
        self.assertEqual(monitoring_counts(row,{})["decisions"],1)
        row["completed_accounting"]["counters_verified"]=False
        self.assertIsNone(monitoring_counts(row,{})["decisions"])
        row["traffic"]["pending_output"]=2
        self.assertEqual(monitoring_counts(row,{})["pending"],2)

    def test_one_resource_sample_never_creates_time_series(self):
        for kind in ("cpu","memory"):
            self.assertIsNone(resource_figure(monitoring(phases=("replay",)),kind))

    def test_distinct_start_and_drain_points_do_not_create_common_phase_curve(self):
        self.assertIsNone(resource_figure(monitoring(phases=("replay","drain")),"memory"))

    def test_two_real_common_phase_points_are_markers_only(self):
        figure=resource_figure(monitoring(),"cpu")
        self.assertTrue(figure.data)
        self.assertTrue(all(len(trace.x)==2 and trace.mode=="markers" and trace.connectgaps is False for trace in figure.data))
        self.assertTrue(all(125. in trace.y for trace in figure.data if trace.name.startswith("BMv2")))

    def test_retained_resource_sample_does_not_make_two_points(self):
        row=monitoring(phases=("replay","replay"))
        for role in ("bmv2","runner"):
            row["resource_samples"][1]["resources"][role]["sample_raw_ns"]=1_000_000_000
        self.assertIsNone(resource_figure(row,"memory"))

    def test_mixed_phase_cpu_not_attributed_to_replay_or_drain(self):
        row=monitoring(phases=("replay","replay"))
        for role in ("bmv2","runner"):
            row["resource_samples"][1]["resources"][role]["cpu_interval_phase"]="mixed"
        self.assertIsNone(resource_figure(row,"cpu"))
        self.assertIsNotNone(resource_figure(row,"memory"))

    def test_actual_resource_time_not_publisher_heartbeat_time(self):
        row=monitoring(phases=("replay","replay"))
        for i,entry in enumerate(row["resource_samples"]):
            entry["raw_ns"]=(i+2)*10_000_000_000
        rows=resource_rows(row)
        self.assertEqual([entry["bmv2_seconds"] for entry in rows],[0.,1.])

    def test_invalid_resource_identity_never_promotes_numeric_values(self):
        row=monitoring(phases=("replay","replay"))
        for entry in row["resource_samples"]:
            for current in entry["resources"].values():
                current["valid"]=False
        self.assertIsNone(resource_figure(row,"cpu"))
        self.assertIsNone(resource_figure(row,"memory"))

    def test_final_invalid_identity_also_hides_earlier_resource_curves(self):
        row=monitoring(phases=("replay","replay"))
        for current in row["resources"].values():
            current["valid"]=False
        self.assertIsNone(resource_figure(row,"cpu"))
        self.assertIsNone(resource_figure(row,"memory"))

    def test_health_has_separate_telemetry_and_native_clock_verdicts(self):
        row=monitoring();row["monitoring_errors"]=["sampler failed"]
        health=monitoring_health(row,result("B"))
        self.assertEqual(health["Tagged packet accounting"],"PASS")
        self.assertEqual(health["Resource observations"],"WARNING")
        self.assertEqual(health["Native ingress sequence"],"CLEAN")


class PcapRenderingTests(unittest.TestCase):
    def render(self,value):
        from streamlit.testing.v1 import AppTest
        script="import sys\n"+f"sys.path.insert(0,{str(REPO)!r})\n"+\
            "from types import SimpleNamespace\nfrom dashboard.views.pcap_live import render_pcap_evidence\n"+\
            f"render_pcap_evidence(SimpleNamespace(**{vars(value)!r}))\n"
        app=AppTest.from_string(script,default_timeout=30).run()
        self.assertEqual(len(app.exception),0,[row.value for row in app.exception])
        self.assertEqual(len(app.button),0)
        return app

    def test_paired_render_has_actual_scores_and_timing_three_charts(self):
        app=self.render(evidence())
        self.assertEqual(len(app.get("plotly_chart")),3)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Models agree",text)
        self.assertLess(text.index("Models agree"),text.index("Traffic & resources"))
        self.assertIn("not independently verified","\n".join(row.value for row in app.caption))
        self.assertIn("separately executed",text)
        self.assertIn("not a controlled BMv2 run", "\n".join(row.value for row in app.caption))

    def test_single_model_does_not_create_comparison(self):
        for mode in ("rf_b","rf_c"):
            app=self.render(evidence(mode))
            self.assertEqual(len(app.get("plotly_chart")),1)
            self.assertNotIn("Models agree","\n".join(row.value for row in app.markdown))

    def test_collecting_has_progress_but_no_invented_class_or_scores(self):
        value=evidence(status="running")
        value.snapshot["classification_results"]={"B":{"status":"collecting","feature_set":"B"}}
        value.snapshot["packet_progress"]={"B":{"eligible_packets":4}}
        app=self.render(value)
        self.assertEqual(len(app.get("plotly_chart")),0)
        self.assertIn("4/8",app.get("progress")[0].proto.text)
        self.assertIn("Pair incomplete","\n".join(row.value for row in app.markdown))

    def test_stale_preserves_real_comparison_with_status(self):
        app=self.render(evidence(status="stale"))
        self.assertEqual(len(app.get("plotly_chart")),3)
        self.assertIn("STALE","\n".join(row.value for row in app.markdown))

    def test_corrupt_hides_all_scores_and_predictions(self):
        app=self.render(evidence(status="corrupt"))
        self.assertEqual(len(app.get("plotly_chart")),0)
        self.assertIn("integrity failure","\n".join(row.value for row in app.markdown))

    def test_actual_parity_failure_never_becomes_pass(self):
        value=evidence("rf_c");value.snapshot["classification_results"]["C"]["parity"]["score"]=False
        app=self.render(value)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Parity incomplete or failed",text)
        self.assertNotIn("Python / P4 parity PASS",text)

    def test_synthetic_evidence_never_presented_as_pcap(self):
        value=evidence();value.snapshot["metadata"]["demo_kind"]="synthetic"
        app=self.render(value)
        self.assertEqual(len(app.get("plotly_chart")),0)
        self.assertIn("No PCAP demonstration attached","\n".join(row.value for row in app.markdown))

    def test_missing_progress_not_presented_as_reported_zero(self):
        value=evidence(status="running");value.snapshot["classification_results"]={}
        app=self.render(value)
        self.assertEqual(len(app.get("progress")),0)
        self.assertIn("not yet available","\n".join(row.value for row in app.caption))

    def test_observed_classification_pending_verification_is_not_waiting_for_packet_eight(self):
        value=evidence("rf_c","running")
        value.snapshot["classification_results"]={"C":{"status":"classified_unverified"}}
        value.snapshot["packet_progress"]={"C":{"eligible_packets":8}}
        app=self.render(value)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Packet-eight classification observed",text)
        self.assertIn("verification is pending",text)
        self.assertEqual(len(app.get("plotly_chart")),0)

    def test_clock_failure_retains_parity_but_is_prominent(self):
        value=evidence("rf_b")
        value.snapshot["classification_results"]["B"]["clock_quality"]={"clean":False,"raw_backward_steps":1}
        app=self.render(value)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Python / P4 parity PASS",text)
        self.assertIn("Native ingress clock quality not verified",text)
        self.assertEqual(len(app.get("plotly_chart")),1)

    def test_authoritative_final_result_overrides_stale_partial_presentation(self):
        value=evidence("rf_b","failed")
        value.snapshot["classification_results"]={"B":{"status":"collecting"}}
        value.snapshot["final_summary"]["classification_results"]={"B":result("B")}
        value.snapshot["final_summary"]["error"]="Observer queue did not drain"
        app=self.render(value)
        self.assertEqual(len(app.get("plotly_chart")),1)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("FAILED",text)
        self.assertIn("Observer queue did not drain",text)
        self.assertIn("Python / P4 parity PASS",text)

    def test_integrated_monitor_preserves_classification_and_separate_model_resources(self):
        value=evidence()
        value.snapshot["pcap_monitoring"]={"B":monitoring("B"),"C":monitoring("C",phases=("replay",))}
        value.snapshot["pcap_monitoring"]["C"]["resources"]["bmv2"]["rss_mib"]=180.
        app=self.render(value)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Live observations - not benchmark-qualified", "\n".join(row.value for row in app.caption))
        self.assertIn("Models agree",text)
        self.assertEqual(len(app.get("plotly_chart")),5) # B CPU/RSS only; original score/timing charts intact.
        self.assertTrue(any(row.value=="150.0 MiB" for row in app.metric))
        self.assertTrue(any(row.value=="180.0 MiB" for row in app.metric))
        self.assertTrue(any(row.value=="125.0%" for row in app.metric))

    def test_sampler_warning_keeps_valid_class_prediction_and_packet_counts(self):
        value=evidence("rf_b");row=monitoring()
        row["monitoring_errors"]=["Process identity changed"]
        row["resources"]["bmv2"]["valid"]=False
        value.snapshot["pcap_monitoring"]={"B":row}
        app=self.render(value)
        text="\n".join(row.value for row in app.markdown)
        self.assertIn("Python / P4 parity PASS",text)
        self.assertIn("Process identity changed",text)
        self.assertIn("Input observed",text)

    def test_final_monitoring_overrides_stale_partial_counts_without_clock_promotion(self):
        value=evidence("rf_b")
        value.snapshot["pcap_monitoring"]={"B":{"traffic":{"input_observed":2,"output_observed":1}}}
        value.snapshot["final_summary"]["pcap_monitoring"]={"B":monitoring()}
        app=self.render(value)
        captions="\n".join(row.value for row in app.caption)
        self.assertIn("Final sender count: 8",captions)
        self.assertIn("socket-drop statistics: not available",captions)
        self.assertIn("not independent clock-rate qualification",captions)

    def test_final_cpu_card_uses_recorded_whole_window_value_with_scope(self):
        value=evidence("rf_b");row=monitoring()
        row["resources"]["bmv2"]["window_cpu_percent_one_core"]=33.5
        value.snapshot["pcap_monitoring"]={"B":row}
        app=self.render(value)
        self.assertTrue(any(metric.value=="33.5%" for metric in app.metric))
        self.assertIn("CPU scope: whole replay/capture window","\n".join(entry.value for entry in app.caption))


if __name__=="__main__":
    unittest.main(verbosity=2)
