"""Scientific presentation gates for the historical Performance page."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from dashboard.views.performance import (calibration_rows,completion_points,failed_trial_rows,higher_attempt_rows,
                                         number,repeated_rows,resource_rows,selected_cells)


def evidence(gates=None,clock="PASS",local="PASS",status="verified"):
    flags={"offered_load":True,"delivered_throughput":True,"cpu":True,
           "classification_rate":True,"classification_counts":True,"packet_accounting":True,"memory":True}
    flags.update(gates or {})
    return SimpleNamespace(status=status,path=Path("/evidence/trial.json"),data={
        "mode":"rf_c","workload":"classification-heavy","rate_pps":1000,"raw_rate_qualified":True,"valid":True,
        "metric_validity":flags,"metrics":{"offered_pps":999.99,"delivered_pps":999.98,
        "delivered_ethernet_mbps":1.0239,"bmv2_cpu_one_core_percent":27.3,
        "runner_cpu_one_core_percent":25.0,"decision_rate_pps":124.8,"packets_sent":20000,
        "packets_received":20000,"decisions":2496,"bmv2_rss_peak_mib":155.4},
        "verdicts":{"measurement_integrity":{"status":local},
        "independent_raw_qualification":{"status":clock,"absolute_rate_claims_qualified":clock=="PASS"},
        "sender_pacing_conformance":{"status":"PASS"}}})


class PerformancePresentationTests(unittest.TestCase):
    def test_verified_qualified_trial_retains_exact_saved_values(self):
        row=calibration_rows([evidence()])[0]
        self.assertEqual(row["Delivered (pps)"],999.98)
        self.assertEqual(row["BMv2 CPU (% of one core)"],27.3)
        self.assertEqual(row["Verified decisions"],2496)

    def test_inconclusive_clock_never_promotes_rate_or_cpu(self):
        row=calibration_rows([evidence(clock="INCONCLUSIVE")])[0]
        for key in ("Offered (pps)","Delivered (pps)","Ethernet throughput (Mb/s)",
                    "BMv2 CPU (% of one core)","Runner CPU (% of one core)","Classification decisions/s"):
            self.assertIsNone(row[key],key)
        self.assertEqual(row["Sent"],20000)
        self.assertEqual(row["BMv2 sampled RSS (MiB)"],155.4)

    def test_local_failure_with_clock_pass_still_hides_rates(self):
        row=calibration_rows([evidence(local="FAIL")])[0]
        self.assertIsNone(row["Delivered (pps)"])
        self.assertIsNone(row["BMv2 CPU (% of one core)"])
        self.assertEqual(row["Verified decisions"],2496)

    def test_each_metric_uses_own_gate(self):
        row=calibration_rows([evidence(gates={"offered_load":False,"cpu":False,"classification_counts":False})])[0]
        self.assertIsNone(row["Offered (pps)"])
        self.assertIsNone(row["BMv2 CPU (% of one core)"])
        self.assertIsNone(row["Verified decisions"])
        self.assertEqual(row["Delivered (pps)"],999.98)

    def test_capture_invalid_counts_not_presented_as_supported(self):
        row=calibration_rows([evidence(gates={"packet_accounting":False,"memory":False})])[0]
        self.assertIsNone(row["Sent"])
        self.assertIsNone(row["Delivered"])
        self.assertIsNone(row["BMv2 sampled RSS (MiB)"])

    def test_unverified_child_is_omitted_not_zero(self):
        for status in ("unavailable","corrupt","unsupported"):
            self.assertEqual(calibration_rows([evidence(status=status)]),[])

    def test_clock_pass_without_claim_flag_is_insufficient(self):
        item=evidence();item.data["verdicts"]["independent_raw_qualification"]["absolute_rate_claims_qualified"]=False
        self.assertIsNone(calibration_rows([item])[0]["Offered (pps)"])

    def test_inconsistent_false_saved_certificate_is_not_promoted(self):
        item=evidence();item.data["raw_rate_qualified"]=False
        self.assertIsNone(calibration_rows([item])[0]["Delivered (pps)"])
        item=evidence();item.data["valid"]=False
        self.assertIsNone(calibration_rows([item])[0]["BMv2 CPU (% of one core)"])

    def test_unavailable_number_is_not_zero(self):
        for value in (None,float("nan"),float("inf"),True,"100"):
            self.assertEqual(number(value),"Unavailable")
        self.assertEqual(number(0,1,"%"),"0.0%")

    def test_repeated_rows_never_include_absolute_rate_diagnostics(self):
        cell={"mode":"rf_b","nominal_target_pps":1000,"acquired_repetitions":5,
            "planned_repetitions":5,"quality":{"local_pass":4,"local_fail":1,"clock_qualified":0},
            "supported_delivery":{"eligible_trials":4,"sent":80000,"output_unique":80000,
                                  "path_non_delivery":0,"delivery_fraction":1.0},
            "classification_counts":{"eligible_trials":4,"observed":9984,"expected":9984},
            "diagnostic_rate_statistics_UNQUALIFIED":{"delivered_pps":{"median":999.99}}}
        row=repeated_rows([cell])[0]
        self.assertEqual(row["Packet-accounting n"],4)
        self.assertEqual(row["Clock-qualified n"],0)
        self.assertFalse(any("throughput" in k.lower() or "cpu" in k.lower() for k in row))
        self.assertEqual(row["Supported delivery (%)"],100.0)

    def test_saved_resource_statistics_are_preserved(self):
        cell={"mode":"features","nominal_target_pps":500,
              "resource_statistics":{"bmv2_cpu_seconds":{"n":5,"median":3.2,"minimum":2.9,
                "maximum":3.5,"mean":3.21,"sample_sd":0.2,"iqr":0.15}}}
        row=resource_rows([cell],"bmv2_cpu_seconds")[0]
        self.assertEqual((row["Eligible n"],row["Median"],row["Sample SD"],row["IQR"]),(5,3.2,0.2,0.15))
        self.assertIsNone(resource_rows([cell],"runner_cpu_seconds")[0]["Median"])

    def test_selection_respects_all_filters(self):
        c1={"workload":"classification-heavy","mode":"rf_c","nominal_target_pps":100}
        c2={"workload":"cached-forwarding","mode":"rf_c","nominal_target_pps":100}
        c3={"workload":"classification-heavy","mode":"rf_b","nominal_target_pps":1000}
        self.assertEqual(selected_cells({"cells":[c1,c2,c3]},"classification-heavy",["rf_c"],[100]),[c1])

    def test_failures_and_pacing_warnings_are_preserved_separately(self):
        def trial(integrity,pacing,reason):
            return {"identity":{"trial_directory":reason,"mode":"forwarding","rate_pps":1000},
                "verdicts":{"local_integrity":integrity,"pacing":pacing},
                "measurement":{"missing_output":50,"path_non_delivery_valid":True},
                "saved_local_failure_reasons":[reason] if reason else []}
        rows=failed_trial_rows({"trials":[trial("FAIL","WARNING","raw_clock_sample_gap_over_25ms"),
                                           trial("PASS","WARNING","pacing_warning"),trial("PASS","PASS","")]})
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]["Observed missing outputs"],50)
        self.assertEqual(rows[0]["Original failure reasons"],"raw_clock_sample_gap_over_25ms")
        self.assertEqual(rows[1]["Local integrity"],"PASS")

    def test_count_completion_uses_saved_supported_denominator(self):
        cell={"mode":"rf_c","nominal_target_pps":1000,
              "supported_delivery":{"eligible_trials":4,"sent":80000,"output_unique":79950},
              "classification_counts":{"eligible_trials":4,"expected":9984,"observed":9984}}
        packet=completion_points([cell],"delivery")[0]
        self.assertEqual((packet["eligible_trials"],packet["numerator"],packet["denominator"]),(4,79950,80000))
        self.assertEqual(packet["percentage"],99.9375)
        self.assertEqual(completion_points([cell],"rf_completion")[0]["percentage"],100.0)

    def test_no_count_percentage_for_missing_zero_or_ineligible_denominator(self):
        for block in ({},{"eligible_trials":0,"sent":100,"output_unique":100},
                      {"eligible_trials":1,"sent":0,"output_unique":0},
                      {"eligible_trials":1,"sent":100,"output_unique":None},
                      {"eligible_trials":1,"sent":100,"output_unique":101}):
            self.assertEqual(completion_points([{"mode":"rf_b","supported_delivery":block}],"delivery"),[])
        point=completion_points([{"mode":"rf_b","supported_delivery":{"eligible_trials":1,"sent":100,"output_unique":0}}],"delivery")
        self.assertEqual(point[0]["percentage"],0.0)

    def test_non_rf_modes_are_not_zero_classifier_completion(self):
        cells=[{"mode":mode,"classification_counts":{"eligible_trials":5,"expected":100,"observed":100}}
               for mode in ("forwarding","features")]
        self.assertEqual(completion_points(cells,"rf_completion"),[])
        with self.assertRaises(ValueError):
            completion_points([],"accuracy")

    def test_higher_identity_table_does_not_invent_qualification(self):
        rows=higher_attempt_rows({"attempts":[{"ordinal":1,"mode":"features","rate_pps":250,
            "workload":"cached-forwarding","status":"completed","trial_directory":"original_trial"}]})
        self.assertEqual(rows[0]["Acquisition status"],"completed")
        self.assertEqual(rows[0]["Individual metric/verdict scope"],"Not individually loaded here")
        self.assertNotIn("PASS",str(rows))


if __name__=="__main__":
    unittest.main()
