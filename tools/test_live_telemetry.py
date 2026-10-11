"""Nonprivileged live writer/reader tests using disposable temporary evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import stat
import threading
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.live_evidence import read_live
from tools.live_telemetry import TelemetryWriter


class LiveTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="live-telemetry-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run_id = "test-live-001"
        self.directory = self.root / self.run_id
        self.metadata = {"mode": "rf_c", "workload": "classification-heavy",
                         "rate_pps": 250, "warmup_seconds": 5,
                         "measurement_seconds": 20, "total_trials": 1,
                         "observer_effect": "dashboard is running"}
        self.writers = []
        self.addCleanup(self.close_writers)

    def close_writers(self):
        for writer in self.writers:
            try:
                writer.close("interrupted")
            except RuntimeError:
                pass

    def writer(self, **kwargs):
        writer = TelemetryWriter(self.directory, self.run_id, self.metadata, **kwargs)
        self.writers.append(writer)
        return writer

    def finish(self, **kwargs):
        writer = self.writer()
        writer.emit("measurement_started", phase="measuring", trial=1)
        writer.emit("sample", phase="measuring", sample={
            "traffic": {"input_unique": 100, "output_unique": 95, "pending": 5,
                        "input_observed_pps": 249.8, "output_observed_pps": 247.2},
            "resources": {"bmv2": {"cpu_percent_one_core": 101.2, "rss_mib": 22.5},
                          "runner": {"cpu_percent_one_core": 3.4, "rss_mib": 13.2}}})
        writer.close(final_summary={"delivery": {"sent": 100, "received": 100},
                                    "independent_clock_qualification": "INCONCLUSIVE",
                                    "kernel_forwarding_latency_qualified": False}, **kwargs)
        return writer

    def snapshot(self):
        return json.loads((self.directory / "snapshot.json").read_text())

    def save_snapshot(self, value):
        (self.directory / "snapshot.json").write_text(json.dumps(value))

    def events(self):
        return [json.loads(line) for line in (self.directory / "events.jsonl").read_text().splitlines()]

    def save_events(self, values, suffix=""):
        (self.directory / "events.jsonl").write_text(
            "".join(json.dumps(value) + "\n" for value in values) + suffix)

    def test_completed_round_trip_preserves_actual_samples_and_final_gates(self):
        self.finish()
        result = read_live(self.root)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(result.data, result.snapshot)
        self.assertEqual(result.snapshot["sample"]["traffic"]["pending"], 5)
        self.assertEqual(result.snapshot["sample"]["resources"]["bmv2"]["cpu_percent_one_core"], 101.2)
        self.assertEqual(result.snapshot["final_summary"]["delivery"]["received"], 100)
        self.assertEqual(result.snapshot["final_summary"]["independent_clock_qualification"], "INCONCLUSIVE")
        self.assertFalse(result.snapshot["final_summary"]["kernel_forwarding_latency_qualified"])
        self.assertEqual(result.events[-1]["event"], "experiment_completed")
        self.assertEqual(result.as_dict()["path"], str(self.directory / "snapshot.json"))

    def test_sequence_identity_and_clock_domains_are_writer_owned(self):
        self.finish()
        values = self.events()
        self.assertEqual([item["seq"] for item in values], list(range(1, len(values) + 1)))
        self.assertEqual(len({item["session_id"] for item in values}), 1)
        self.assertTrue(all(item["boot_id"] for item in values))
        self.assertTrue(all(item["event_raw_ns"] >= item["produced_raw_ns"] for item in values))
        self.assertEqual(self.snapshot()["clock_domain"], "CLOCK_MONOTONIC_RAW")

    def test_emit_rejects_identity_override_nonfinite_and_oversize(self):
        writer = self.writer()
        for fields in ({"seq": 99}, {"sample": {"cpu": float("nan")}},
                       {"sample": {"text": "x" * 70000}}, {"final_summary": {}}):
            with self.assertRaises(ValueError):
                writer.emit("sample", **fields)

    def test_queue_overflow_never_blocks_and_is_explicit(self):
        writer = self.writer(queue_capacity=1)
        entered = threading.Event()
        release = threading.Event()
        original = writer._record

        def held(output, event, fields, produced):
            if event == "hold":
                entered.set()
                release.wait(2)
            original(output, event, fields, produced)

        writer._record = held
        self.assertTrue(writer.emit("hold"))
        self.assertTrue(entered.wait(1))
        self.assertTrue(writer.emit("queued"))
        started = time.perf_counter()
        self.assertFalse(writer.emit("overflow"))
        self.assertLess(time.perf_counter() - started, 0.05)
        release.set()
        writer.close(final_summary={})
        result = read_live(self.root)
        self.assertEqual(result.snapshot["telemetry"]["dropped_events"], 1)
        self.assertTrue(any("dropped 1" in message for message in result.messages))
        self.assertNotIn("overflow", [item["event"] for item in result.events])

    def test_atomic_snapshot_replacements_keep_valid_json_and_no_temp_files(self):
        from tools import live_telemetry
        replacements = []
        original = live_telemetry.os.replace

        def observed(source, target):
            replacements.append((Path(source), Path(target)))
            self.assertIsInstance(json.loads(Path(source).read_text()), dict)
            original(source, target)

        with patch.object(live_telemetry.os, "replace", side_effect=observed):
            self.finish()
        self.assertTrue(any(target.name == "snapshot.json" for _, target in replacements))
        self.assertTrue(any(target.name == "current.json" for _, target in replacements))
        self.assertFalse(list(self.root.rglob("*.tmp")))
        self.assertTrue(all(source != target for source, target in replacements))

    def test_heartbeat_updates_without_fabricating_samples(self):
        writer = self.writer(heartbeat_seconds=0.05)
        time.sleep(0.12)
        writer.close(final_summary={})
        self.assertIn("heartbeat", [item["event"] for item in self.events()])
        self.assertEqual(self.snapshot()["samples"], [])
        self.assertNotIn("sample", self.snapshot())

    def test_history_bounds_are_enforced(self):
        writer = self.writer(sample_limit=3, event_limit=5)
        for index in range(9):
            writer.emit("sample", sample={"traffic": {"input_unique": index}})
        writer.close(final_summary={})
        self.assertEqual(len(self.snapshot()["samples"]), 3)
        self.assertEqual(len(self.snapshot()["recent_events"]), 5)
        self.assertEqual(self.snapshot()["samples"][-1]["sample"]["traffic"]["input_unique"], 8)

    def test_large_payload_history_cannot_exceed_reader_snapshot_bound(self):
        writer = self.writer(queue_capacity=128)
        for index in range(45):
            writer.emit("sample", sample={"traffic": {"input_unique": index}, "diagnostic": "x" * 55000})
        writer.close(final_summary={"status": "complete"})
        self.assertLessEqual((self.directory / "snapshot.json").stat().st_size, 4 * 1024 * 1024)
        result = read_live(self.root)
        self.assertEqual(result.status, "completed")
        self.assertTrue(any("history was bounded" in message for message in result.messages))
        self.assertEqual(len(self.events()), 47)

    def test_existing_live_evidence_is_never_overwritten(self):
        self.finish()
        original = (self.directory / "events.jsonl").read_bytes()
        with self.assertRaises(FileExistsError):
            self.writer()
        self.assertEqual((self.directory / "events.jsonl").read_bytes(), original)

    def test_restrictive_worker_umask_keeps_new_telemetry_readable(self):
        previous = os.umask(0o077)
        try:
            self.finish()
        finally:
            os.umask(previous)
        for path in (self.directory / "snapshot.json", self.directory / "events.jsonl",
                     self.root / "current.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o755)
        self.assertEqual(read_live(self.root).status, "completed")

    def test_context_interrupt_preserves_partial_terminal_evidence(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.writer() as writer:
                writer.emit("warmup_started", phase="warmup")
                raise KeyboardInterrupt()
        result = read_live(self.root)
        self.assertEqual(result.status, "interrupted")
        self.assertTrue(any("no final summary" in message for message in result.messages))

    def test_terminal_session_does_not_become_stale(self):
        self.finish()
        result = read_live(self.root, now_raw_ns=10 ** 20, boot_id="other-boot")
        self.assertEqual(result.status, "completed")

    def test_active_stale_heartbeat_keeps_last_observations(self):
        self.finish()
        snapshot = self.snapshot()
        snapshot["status"] = "running"
        self.save_snapshot(snapshot)
        result = read_live(self.root, now_raw_ns=snapshot["heartbeat_raw_ns"] + 6_000_000_000,
                           boot_id=snapshot["boot_id"])
        self.assertEqual(result.status, "stale")
        self.assertEqual(result.snapshot["sample"]["traffic"]["input_unique"], 100)

    def test_changed_boot_marks_active_session_interrupted(self):
        self.finish()
        snapshot = self.snapshot()
        snapshot["status"] = "running"
        self.save_snapshot(snapshot)
        result = read_live(self.root, boot_id="different", now_raw_ns=0)
        self.assertEqual(result.status, "interrupted")
        self.assertTrue(any("boot identity changed" in message for message in result.messages))

    def test_future_raw_heartbeat_is_not_negative_elapsed_time(self):
        self.finish()
        snapshot = self.snapshot()
        snapshot["status"] = "running"
        self.save_snapshot(snapshot)
        result = read_live(self.root, boot_id=snapshot["boot_id"], now_raw_ns=0)
        self.assertEqual(result.status, "stale")
        self.assertTrue(any("ahead" in message for message in result.messages))

    def test_incomplete_final_jsonl_record_is_ignored_and_diagnosed(self):
        self.finish()
        original = self.events()
        self.save_events(original, '{"seq":')
        result = read_live(self.root)
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.events), len(original))
        self.assertTrue(any("Incomplete final" in message for message in result.messages))

    def test_exact_duplicate_event_is_deduplicated(self):
        self.finish()
        values = self.events()
        self.save_events(values + [values[-1]])
        result = read_live(self.root)
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.events), len(values))
        self.assertTrue(any("deduplicated" in message for message in result.messages))

    def test_contradictory_duplicate_event_is_corrupt(self):
        self.finish()
        values = self.events()
        contradictory = {**values[-1], "event": "different"}
        self.save_events(values + [contradictory])
        result = read_live(self.root)
        self.assertEqual(result.status, "corrupt")
        self.assertTrue(any("Contradictory" in message for message in result.messages))

    def test_out_of_order_event_is_corrupt(self):
        self.finish()
        values = self.events()
        self.save_events([values[1], values[0], *values[2:]])
        self.assertEqual(read_live(self.root).status, "corrupt")

    def test_event_identity_mismatch_is_corrupt(self):
        self.finish()
        values = self.events()
        values[-1]["session_id"] = "other"
        self.save_events(values)
        self.assertEqual(read_live(self.root).status, "corrupt")

    def test_event_ahead_of_atomic_snapshot_is_not_invented(self):
        self.finish()
        values = self.events()
        future = {**values[-1], "seq": values[-1]["seq"] + 1, "event": "sample"}
        self.save_events(values + [future])
        result = read_live(self.root)
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.events), len(values))

    def test_missing_final_summary_is_explicit(self):
        writer = self.writer()
        writer.close("failed", error="sender stopped")
        result = read_live(self.root)
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.snapshot["final_summary"])
        self.assertEqual(result.snapshot["error"], "sender stopped")
        self.assertTrue(any("no final summary" in message for message in result.messages))

    def test_final_summary_file_is_relative_and_hash_verified(self):
        writer = self.writer()
        final = self.directory / "trial_summary.json"
        summary = {"verdict": "PASS", "rates_qualified": False}
        final.write_text(json.dumps(summary))
        writer.close(final_summary=summary, final_summary_file=final.name)
        self.assertEqual(read_live(self.root).status, "completed")
        final.write_text('{}')
        result = read_live(self.root)
        self.assertEqual(result.status, "corrupt")
        self.assertTrue(any("SHA-256 mismatch" in message for message in result.messages))

    def test_hash_verified_file_does_not_validate_different_inline_summary(self):
        writer = self.writer()
        final = self.directory / "trial_summary.json"
        final.write_text(json.dumps({"rates_qualified": False}))
        writer.close(final_summary={"rates_qualified": True}, final_summary_file=final.name)
        result = read_live(self.root)
        self.assertEqual(result.status, "corrupt")
        self.assertTrue(any("Inline final summary disagrees" in message for message in result.messages))

    def test_sender_phase_and_sampler_errors_are_retained_explicitly(self):
        writer = self.writer()
        writer.emit("measurement_completed", phase="draining", phase_started_raw_ns=writer._started,
                    phase_duration_seconds=2, sender_statistics={"sent": 100, "actual_pps": 249.9})
        writer.emit("producer_error", phase="draining", error="resource sampler interrupted")
        writer.close("failed", final_summary={"status": "partial"})
        result = read_live(self.root)
        self.assertEqual(result.snapshot["sender_statistics"]["sent"], 100)
        self.assertEqual(result.snapshot["phase_duration_seconds"], 2)
        self.assertIn("resource sampler interrupted", result.snapshot["telemetry"]["errors"])
        self.assertIn("publisher liveness", result.snapshot["publisher"]["heartbeat_definition"])

    def test_pcap_demo_fields_preserve_stage2_sample_and_reference_distinction(self):
        writer = self.writer()
        source = {"slug": "voip", "label_basis": "capture_activity_hint", "eligible_packets": 8}
        observed = {"model": "C", "predicted_class": "VOIP", "parity_passed": True,
                    "accuracy_scored": False}
        writer.emit("source_selected", source_example=source)
        writer.emit("packet_observed", packet_progress={"eligible_packets": 7})
        writer.emit("classification_completed", classification_results=[observed])
        writer.close(final_summary={"demo_only": True})
        result = read_live(self.root)
        self.assertEqual(result.snapshot["source_example"], source)
        self.assertEqual(result.snapshot["packet_progress"]["eligible_packets"], 7)
        self.assertEqual(result.snapshot["classification_results"], [observed])
        self.assertFalse(result.snapshot["classification_results"][0]["accuracy_scored"])

    def test_pcap_monitoring_preserves_separate_model_windows_and_missing_values(self):
        writer = self.writer()
        classification = {"B": {"p4_prediction": "VOIP", "accuracy_scored": False},
                          "C": {"p4_prediction": "VOIP", "accuracy_scored": False}}
        monitoring = {
            "B": {"model": "B", "phase": "completed", "window_label": "setup + replay + drain + final CLI; not RF inference overhead",
                  "traffic": {"input_unique": 8, "output_unique": 8, "pending": 0,
                              "input_observed_pps": None, "output_observed_pps": None, "qualified": False},
                  "resources": {"bmv2": {"cpu_percent_one_core": 12.3, "rss_mib": 155.2,
                                              "sample_raw_ns": 1001, "phase": "replaying", "qualified": False}},
                  "resource_samples": [{"model": "B", "role": "bmv2", "raw_ns": 1001,
                                        "phase": "replaying", "cpu_percent_one_core": 12.3, "rss_mib": 155.2}],
                  "final_accounting": {"sent_packets": 8, "input_unique": 8, "output_unique": 8,
                                        "transport_passed": True, "decision_counters": None}},
            "C": {"model": "C", "phase": "setup", "window_label": "fresh model switch; not an inference measurement",
                  "traffic": {"input_unique": None, "output_unique": None, "pending": None, "qualified": False},
                  "resources": {}, "resource_samples": [], "final_accounting": None}}
        writer.emit("sample", phase="measurement", sample={"traffic": {"input_unique": 1}})
        writer.emit("pcap_classification_verified", classification_results=classification)
        writer.emit("pcap_monitoring_sample", pcap_monitoring=monitoring)
        writer.close(final_summary={"demo_only": True})
        result = read_live(self.root)
        self.assertEqual(result.snapshot["pcap_monitoring"], monitoring)
        self.assertEqual(result.snapshot["classification_results"], classification)
        self.assertEqual(result.snapshot["sample"]["traffic"]["input_unique"], 1)
        self.assertIsNone(result.snapshot["pcap_monitoring"]["C"]["traffic"]["pending"])
        self.assertIsNone(result.snapshot["pcap_monitoring"]["B"]["traffic"]["input_observed_pps"])
        self.assertFalse(result.snapshot["pcap_monitoring"]["B"]["resources"]["bmv2"]["qualified"])

    def test_reader_rejects_path_escape_and_symlink(self):
        self.finish()
        pointer = json.loads((self.root / "current.json").read_text())
        pointer["snapshot_path"] = "../research/summary.json"
        (self.root / "current.json").write_text(json.dumps(pointer))
        self.assertEqual(read_live(self.root).status, "corrupt")
        (self.root / "current.json").unlink()
        (self.root / "current.json").symlink_to(self.directory / "snapshot.json")
        self.assertEqual(read_live(self.root).status, "corrupt")

    def test_snapshot_corruption_and_duplicate_keys_are_not_data(self):
        self.finish()
        (self.directory / "snapshot.json").write_text('{"seq":1,"seq":2}')
        result = read_live(self.root)
        self.assertEqual(result.status, "corrupt")
        self.assertTrue(any("Duplicate JSON key" in message for message in result.messages))

    def test_reader_bounds_large_snapshot_and_event_tail(self):
        self.finish()
        with patch("dashboard.live_evidence.MAX_SNAPSHOT_BYTES", 100):
            self.assertEqual(read_live(self.root).status, "corrupt")
        values = self.events()
        self.save_events(values * 50)
        # A small bounded tail cuts only to complete record boundaries.
        with patch("dashboard.live_evidence.MAX_EVENT_TAIL_BYTES", 1400):
            result = read_live(self.root)
        self.assertLessEqual(len(result.events), 200)
        self.assertTrue(any("bounded event-stream tail" in message for message in result.messages))

    def test_idle_and_missing_snapshot_do_not_fabricate_zeros(self):
        result = read_live(self.root)
        self.assertEqual(result.status, "idle")
        self.assertIsNone(result.snapshot)
        result = read_live(self.root, run_id="missing")
        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.snapshot)

    def test_writer_rejects_invalid_directory_and_run_identity(self):
        with self.assertRaises(ValueError):
            TelemetryWriter(self.root / "other", self.run_id, self.metadata)
        with self.assertRaises(ValueError):
            TelemetryWriter(self.root / "control", "control", self.metadata)

    def test_raw_clock_is_never_silently_replaced(self):
        with patch("tools.live_telemetry.time.clock_gettime_ns", side_effect=OSError("RAW unavailable")):
            with self.assertRaises(OSError):
                self.writer()

    def test_worker_failure_is_explicit_and_close_raises(self):
        writer = self.writer()
        with patch.object(writer, "_record", side_effect=OSError("fixture disk error")):
            writer.emit("sample", sample={"traffic": {"input_unique": 1}})
            writer._thread.join(1)
        with self.assertRaisesRegex(RuntimeError, "fixture disk error"):
            writer.close("failed")
        result = read_live(self.root)
        self.assertEqual(result.status, "failed")
        self.assertTrue(any("fixture disk error" in message for message in result.messages))


if __name__ == "__main__":
    unittest.main()
