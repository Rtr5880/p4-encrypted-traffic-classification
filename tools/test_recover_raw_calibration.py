"""Synthetic recovery tests; local UNIX fixture only, no BMv2/network traffic."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import socket
import unittest
from unittest.mock import patch

import recover_raw_calibration as recovery


def write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def fixture(root, local_fail=False, qualified=False):
    root.mkdir()
    write(root / "provenance.json", {"prepared_directory": "/historical/preparation", "synchronization_changed": False})
    qualification = {"status": "PASS" if qualified else "INCONCLUSIVE", "passed": qualified,
                     "criterion_ppm": 1000, "providers": {"example.org": {
                         "status": "PASS" if qualified else "INCONCLUSIVE", "representative_load_queries": 1 if qualified else 0,
                         "raw_rate": {"midpoint_estimate_ppm": 10, "lower_ppm": -600, "upper_ppm": 620},
                         "reasons": [] if qualified else ["no_valid_query_bracketed_inside_a_measured_load_window"]}}}
    write(root / "clock_rate_qualification.json", qualification)
    folder = root / "trial_001_classification-heavy_01000pps_r01_rf_b"
    folder.mkdir()
    count, warm_count, duration, frame_bytes = 20000, 5000, 20.0, 128
    plan = {"packet_count": count, "frame_bytes": frame_bytes, "expected_classifications": 2496,
            "flow_tuples": [{"slot": 2}]}
    warm = {"packet_count": warm_count, "frame_bytes": frame_bytes, "expected_classifications": 624,
            "flow_tuples": [{"slot": 1}]}
    def counters(expected, before):
        left = [{"packets": 0, "bytes": 0} for _ in range(6)]
        left[0] = {"packets": before, "bytes": before * frame_bytes}
        right = deepcopy(left)
        right[0] = {"packets": before + expected, "bytes": (before + expected) * frame_bytes}
        deltas = [{"packets": 0, "bytes": 0} for _ in range(6)]
        deltas[0] = {"packets": expected, "bytes": expected * frame_bytes}
        return {"rf_inference_present": True, "class_counter_deltas": deltas,
                "before": left, "after": right, "packets": expected, "bytes": expected * frame_bytes,
                "expected_packets": expected, "capacity_accounting_passed": True}
    measured_counts, warm_counts = counters(2496, 624), counters(624, 0)
    def observation(n, seconds, failed):
        return {"planned_packets": n, "sent_packets": n, "captured_input_unique": n,
                "captured_output_unique": n, "missing_input_sequences": [], "missing_output_sequences": [],
                "per_packet": {"input_occurrences": [1] * n, "output_occurrences": [1] * n,
                               "send_start_raw_ns": list(range(n)), "send_finish_raw_ns": list(range(1, n + 1))},
                "capture_counters": {endpoint: {"duplicates": 0, "sequence_regressions": 0} for endpoint in ("input", "output")},
                "capture_statistics": {endpoint: {"socket_drops": 0} for endpoint in ("input", "output")},
                "reduced_quality_valid": not failed,
                "reduced_quality_reasons": ["send completion maximum above limit"] if failed else [],
                "kernel_timestamp_diagnostics": {"qualified_for_performance_claims": False, "reasons": ["unqualified realtime"]},
                "pacing_quality": {"nominal_interval_ns": 1_000_000,
                    "maximum_send_lateness_limit_ns": 5_000_000,
                    "send_completion_lateness_summary_ns": {"maximum": 5_113_093 if failed else 1_090_501}},
                "raw_clock_audit": {"valid": True, "raw_regressions": 0},
                "throughput": {"raw_sender_window_seconds": seconds}}
    measured, warming = observation(count, duration, False), observation(warm_count, 5., local_fail)
    cpu = {"valid": True, "seconds": 5., "user_ticks_delta": 400, "system_ticks_delta": 100,
           "clock_ticks_per_second": 100, "percent_one_core": 25.}
    memory = {"valid": True, "rss_max_sampled_kib": 129024, "rss_max_sampled_mib": 126.,
              "vmhwm_lifetime_kib": 129024, "vmhwm_lifetime_mib": 126.}
    resources = {who: {"clock_domain": "CLOCK_MONOTONIC_RAW", "raw_duration_seconds": duration,
                        "cpu": deepcopy(cpu), "memory": deepcopy(memory), "samples": []} for who in ("bmv2", "runner")}
    metrics = {"packets_sent": count, "packets_received": count, "packets_lost": 0,
               "packets_duplicated": 0, "packets_reordered": 0, "raw_window_seconds": duration,
               "decisions": 2496, "target_pps": 1000, "offered_pps": 1000., "delivered_pps": 1000.,
               "delivered_ethernet_mbps": 1.024, "decision_rate_pps": 124.8,
               "bmv2_cpu_seconds": 5., "runner_cpu_seconds": 5., "bmv2_cpu_one_core_percent": 25.,
               "runner_cpu_one_core_percent": 25., "bmv2_rss_peak_mib": 126., "bmv2_hwm_mib": 126.}
    gates = {key: True for key in (*recovery.RATE_GATES, "packet_accounting", "classification_counts", "cpu_accounting", "memory")}
    gates["kernel_forwarding_latency"] = False
    row = {"mode": "rf_b", "workload": "classification-heavy", "rate_pps": 1000,
           "block_id": "classification-heavy_01000pps_r01", "valid": not local_fail,
           "instrument_valid_before_rate_qualification": not local_fail,
           "kernel_forwarding_latency_qualified": False, "accuracy_scored": False,
           "failures": ["Disjoint warm-up quality/counter accounting failed"] if local_fail else [],
           "metric_validity": gates, "metrics": metrics}
    provenance = {"mode": row["mode"], "block": {key: row[key] for key in ("rate_pps", "block_id", "workload")},
                  "measurement": plan, "warmup": warm}
    for name, data in (("trial_summary.json", row), ("measurement.json", measured), ("warmup_measurement.json", warming),
                       ("provenance.json", provenance), ("resources.json", resources), ("counter_check.json", measured_counts),
                       ("warmup_counter_check.json", warm_counts), ("counter_before.json", measured_counts["before"]),
                       ("counter_after.json", measured_counts["after"])):
        write(folder / name, data)
    return folder


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        self.run = self.parent / "historical_run"

    def test_successful_separate_recovery_never_modifies_originals(self):
        fixture(self.run, qualified=True)
        before = recovery.snapshot(self.run)
        result = recovery.recover(self.run)
        self.assertEqual(result.parent, self.run.parent)
        self.assertNotEqual(result, self.run)
        self.assertEqual(recovery.snapshot(self.run), before)
        self.assertFalse((self.run / "summary.json").exists())
        report = recovery.read_json(result / "report.json")
        self.assertTrue(report["raw_rate_qualified"])
        self.assertFalse(report["passed"])
        self.assertEqual(report["trials"][0]["qualified_rate_claims"]["offered_pps"], 1000.)

    def test_local_failure_and_inconclusive_qualification_preserved(self):
        fixture(self.run, local_fail=True)
        result = recovery.recover(self.run)
        report = recovery.read_json(result / "report.json")
        self.assertEqual(report["local_failed_trials"], 1)
        self.assertEqual(report["clock_rate_qualification"]["status"], "INCONCLUSIVE")
        trial = report["trials"][0]
        self.assertFalse(trial["original_trial_summary"]["valid"])
        self.assertEqual(trial["original_trial_summary"]["metrics"]["offered_pps"], 1000.)
        self.assertFalse(trial["effective_metric_validity"]["delivered_throughput"])
        self.assertTrue(trial["effective_metric_validity"]["packet_accounting"])
        self.assertTrue(trial["effective_metric_validity"]["cpu_accounting"])
        self.assertTrue(all(value is None for value in trial["qualified_rate_claims"].values()))
        text = (result / "report.md").read_text()
        self.assertIn("5.113093 ms", text)
        self.assertIn("5.000000 ms", text)
        self.assertIn("0.113093 ms", text)
        self.assertIn("unqualified diagnostic estimates", text)

    def test_existing_output_never_overwritten(self):
        fixture(self.run)
        output = self.parent / "already_there"
        output.mkdir()
        (output / "keep.txt").write_text("keep")
        before = recovery.snapshot(self.run)
        with self.assertRaisesRegex(recovery.RecoveryError, "already exists"):
            recovery.recover(self.run, output)
        self.assertEqual((output / "keep.txt").read_text(), "keep")
        self.assertEqual(recovery.snapshot(self.run), before)

    def test_real_saved_cli_counter_schema_is_parsed_without_running_cli(self):
        trial = fixture(self.run)
        for filename in ('counter_before.json', 'counter_after.json'):
            values = json.loads((trial / filename).read_text())
            saved = dict(returncode=0, stderr='', command=['stored-cli'], input='stored-commands',
                stdout='Obtaining JSON from switch...\n' + ''.join(
                    f'RuntimeCmd: FeatureIngress.rf_decisions[{index}]= ({row["bytes"]} bytes, {row["packets"]} packets)\n'
                    for index, row in enumerate(values)))
            write(trial / filename, saved)
        output = recovery.recover(self.run)
        self.assertTrue((output / 'report.md').is_file())

    def test_clean_measurement_quarantined_after_warmup_failure_even_with_qualified_clock(self):
        fixture(self.run, local_fail=True, qualified=True)
        report = recovery.read_json(recovery.recover(self.run) / "report.json")
        trial = report["trials"][0]
        self.assertTrue(trial["phase_quality"]["measurement"]["local_quality_valid"])
        self.assertFalse(trial["phase_quality"]["warmup"]["local_quality_valid"])
        self.assertTrue(report["raw_rate_qualified"])
        self.assertTrue(all(value is None for value in trial["qualified_rate_claims"].values()))
        self.assertTrue(trial["effective_metric_validity"]["classification_counts"])

    def test_output_inside_source_refused(self):
        fixture(self.run)
        with self.assertRaisesRegex(recovery.RecoveryError, "must be separate"):
            recovery.recover(self.run, self.run / "recovery")
        self.assertFalse((self.run / "recovery").exists())

    def test_separate_writable_output_parent_allowed_without_changing_source(self):
        fixture(self.run)
        writable = self.parent / 'separate_reports'
        writable.mkdir()
        before = recovery.snapshot(self.run)
        result = recovery.recover(self.run, writable / 'recovered')
        self.assertTrue((result / 'report.md').is_file())
        self.assertEqual(recovery.snapshot(self.run), before)

    @unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'UNIX endpoints require AF_UNIX')
    def test_original_bmv2_notification_endpoint_is_preserved_as_metadata(self):
        trial = fixture(self.run)
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            endpoint.bind(str(trial / 'notifications.ipc'))
            before = recovery.notification_metadata(self.run)
            output = recovery.recover(self.run)
            report = recovery.read_json(output / 'report.json')
            self.assertEqual(report['preservation']['original_notification_endpoint_metadata'], before)
            self.assertEqual(recovery.notification_metadata(self.run), before)
            self.assertTrue((trial / 'notifications.ipc').exists())
            self.assertFalse(next(iter(before.values()))['endpoint_accessed'])
        finally:
            endpoint.close()

    def test_inconsistent_packet_accounting_refused_without_output(self):
        trial = fixture(self.run)
        summary = recovery.read_json(trial / "trial_summary.json")
        summary["metrics"]["packets_received"] -= 1
        write(trial / "trial_summary.json", summary)
        before = recovery.snapshot(self.run)
        with self.assertRaisesRegex(recovery.RecoveryError, "Inconsistent trial metric packets_received"):
            recovery.recover(self.run, self.parent / "refused")
        self.assertFalse((self.parent / "refused").exists())
        self.assertEqual(recovery.snapshot(self.run), before)

    def test_evidence_changed_during_read_is_refused(self):
        fixture(self.run)
        real_snapshot = recovery.snapshot
        calls = 0
        def changed_snapshot(path):
            nonlocal calls
            calls += 1
            value = real_snapshot(path)
            if calls > 1:
                value["provenance.json"] = "0" * 64
            return value
        with patch.object(recovery, "snapshot", side_effect=changed_snapshot):
            with self.assertRaisesRegex(recovery.RecoveryError, "changed while being read"):
                recovery.recover(self.run, self.parent / "refused")
        self.assertFalse((self.parent / "refused").exists())

    def test_malformed_arrays_refused(self):
        trial = fixture(self.run)
        observation = recovery.read_json(trial / "measurement.json")
        observation["per_packet"]["output_occurrences"].pop()
        write(trial / "measurement.json", observation)
        with self.assertRaisesRegex(recovery.RecoveryError, "Invalid per-packet array"):
            recovery.recover(self.run)

    def test_changed_pacing_gate_refused(self):
        trial = fixture(self.run)
        observation = recovery.read_json(trial / "warmup_measurement.json")
        observation["pacing_quality"]["maximum_send_lateness_limit_ns"] = 6_000_000
        write(trial / "warmup_measurement.json", observation)
        with self.assertRaisesRegex(recovery.RecoveryError, "unchanged pacing maximum"):
            recovery.recover(self.run)


if __name__ == "__main__":
    unittest.main()
