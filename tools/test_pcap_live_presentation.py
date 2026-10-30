"""UI-only PCAP presentation regressions; no switch or interface activity."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

REPO=Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0,str(REPO))

from dashboard.views.pcap_live import (
    RF_SCORE_MAX,packet_strip_rows,parity_status,pcap_journey,score_figure,result_issues,
)
from tools import test_pcap_live_dashboard as previous

evidence,result=previous.evidence,previous.result


class PcapPresentationHelpersTests(unittest.TestCase):
    def test_shared_score_scale_keeps_actual_integer_values(self):
        for model in "BC":
            saved=result(model)
            before=copy.deepcopy(saved)
            figure=score_figure(saved,model)
            self.assertEqual(list(figure.data[0].x),saved["scores"])
            self.assertEqual(list(figure.layout.xaxis.range),[0,RF_SCORE_MAX])
            self.assertEqual(saved,before)

    def test_out_of_range_score_is_rejected_not_clipped_or_promoted(self):
        saved=result("C")
        saved["scores"][4]=RF_SCORE_MAX+1
        before=copy.deepcopy(saved)
        self.assertIn("Six actual integer class-score totals are unavailable or invalid",result_issues(saved,"C"))
        self.assertEqual(parity_status(saved,"C"),"INCOMPLETE")
        self.assertEqual(saved,before)

    def test_source_strip_is_metadata_not_observed_progress(self):
        source=evidence().snapshot["metadata"]["source_example"]
        before=copy.deepcopy(source)
        rows=packet_strip_rows(source)
        self.assertEqual(len(rows),8)
        self.assertEqual([row["direction"] for row in rows],["F","R"]*4)
        self.assertEqual(rows[0]["capture_offset_us"],0)
        self.assertEqual([row["trigger"] for row in rows],[False]*7+[True])
        self.assertEqual(source,before)

    def test_missing_source_values_do_not_become_zero(self):
        rows=packet_strip_rows({})
        self.assertEqual(len(rows),8)
        self.assertTrue(all(row["ip_size_bytes"] is None for row in rows))
        self.assertTrue(all(row["direction"] is None for row in rows))
        self.assertTrue(all(row["original_frame"] is None for row in rows))

    def test_numeric_direction_is_supported_but_boolean_is_not(self):
        rows=packet_strip_rows({"packet_summary":[
            {"position":1,"direction":0},{"position":2,"direction":1},
            {"position":3,"direction":True}]})
        self.assertEqual([row["direction"] for row in rows[:3]],["F","R",None])

    def test_completion_alone_does_not_promote_journey_or_parity(self):
        steps=pcap_journey({}, {}, {}, "BC", "completed")
        self.assertEqual(len(steps),6)
        self.assertTrue(all(step["state"]=="pending" for step in steps))
        self.assertEqual(parity_status({},"B"),"PENDING")

    def test_journey_keeps_separate_sequential_models(self):
        steps=pcap_journey({"B":result("B")},{},{},"BC","running")
        self.assertTrue(all(step["state"]=="observed" for step in steps[:3]))
        self.assertTrue(all(step["state"]=="pending" for step in steps[3:]))

    def test_decision_pending_verification_does_not_pass(self):
        saved={"status":"classified_unverified"}
        steps=pcap_journey({"C":saved},{"C":{"eligible_packets":8}},{},"C","running")
        self.assertEqual([step["state"] for step in steps],["observed","observed","active"])
        self.assertEqual(parity_status(saved,"C"),"PENDING")

    def test_failed_parity_is_not_a_successful_stage(self):
        saved=result("C");saved["parity"]["score"]=False
        steps=pcap_journey({"C":saved},{},{},"C","completed")
        self.assertEqual(parity_status(saved,"C"),"FAIL")
        self.assertEqual(steps[-1]["state"],"failed")

    def test_unknown_or_invalid_counts_are_not_fabricated(self):
        for value in (None,True,-1,9):
            steps=pcap_journey({}, {"C":{"eligible_packets":value}}, {}, "C", "running")
            self.assertEqual(steps[0]["state"],"pending")
            self.assertIn("No packet count assumed",steps[0]["detail"])


class PcapPresentationRenderingTests(unittest.TestCase):
    def test_summary_and_packet_strip_are_visible_before_model_details(self):
        app=previous.PcapRenderingTests().render(evidence())
        text="\n".join([row.value for row in app.markdown]+[row.value for row in app.caption])
        self.assertLess(text.index("Models agree"),text.index("The eight-packet observation window"))
        self.assertIn("Source packet metadata, not an animated arrival timeline",text)
        self.assertIn("Packet 8",text)
        self.assertIn("Inference trigger",text)
        for label in ("Features PASS","Leaves PASS","Scores PASS","Class PASS"):
            self.assertIn(label,text)
        self.assertEqual(len(app.get("plotly_chart")),3)

    def test_missing_progress_does_not_colour_source_strip_as_observed(self):
        value=evidence(status="running")
        value.snapshot["classification_results"]={}
        app=previous.PcapRenderingTests().render(value)
        text="\n".join([row.value for row in app.markdown]+[row.value for row in app.caption])
        self.assertIn("switch progress not yet available",text)
        self.assertNotIn("0/8 switch-reported",text)
        self.assertNotIn("Features PASS",text)

    def test_failed_score_parity_is_prominent_without_class_accuracy_claim(self):
        value=evidence(mode="rf_c")
        value.snapshot["classification_results"]["C"]["parity"]["score"]=False
        app=previous.PcapRenderingTests().render(value)
        text="\n".join([row.value for row in app.markdown]+[row.value for row in app.caption])
        self.assertIn("Scores FAIL",text)
        self.assertIn("Python-P4 parity FAIL",text)
        self.assertIn("Hint agreement is not independently verified",text)


if __name__=="__main__":
    unittest.main(verbosity=2)
