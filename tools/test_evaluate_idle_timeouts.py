"""Synthetic timeout semantics and failure-path tests; never read real PCAPs."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import evaluate_idle_timeouts as evaluator
import extract_feature_pilot as pilot
import test_extract_feature_pilot as fixtures
from test_extract_feature_pilot import packet, accumulate, oracle_packets
from test_extract_feature_pilot_runner import FakeProcess


CAPTURE = {"filename": "synthetic.pcap", "capture_id": "synthetic/synthetic.pcap",
           "sha256": "a" * 64, "initial_class": "MAIL"}


def run_audit(packets, seconds=(30, 60, 120)):
    stream = io.StringIO()
    audit = evaluator.Audit(CAPTURE, seconds, stream)
    for value in packets:
        audit.add(value)
    result = audit.finish()
    return result, [json.loads(line) for line in stream.getvalue().splitlines()]


class TimeoutTests(unittest.TestCase):
    def test_no_timeout_counts_short_prefixes_independently(self):
        result, records = run_audit([packet(i + 1, i) for i in range(4)])
        for stats in result["policies"].values():
            self.assertEqual(stats["instances"], 1)
            self.assertEqual(stats["windows"]["4"]["records"], 1)
            self.assertEqual(stats["windows"]["8"]["short_instances"], 1)
            self.assertEqual(stats["windows"]["8"]["short_instances_at_capture_end"], 1)
        self.assertTrue(all(r["close_reason"] == "capture_end" for r in records))

    def test_equality_expires_before_arriving_packet_is_added(self):
        for delta, expected in ((29_999_999, 1), (30_000_000, 2), (30_000_001, 2)):
            with self.subTest(delta=delta):
                result, records = run_audit([packet(1, 0), packet(2, delta)])
                self.assertEqual(result["policies"]["idle_30s"]["instances"], expected)
                if expected == 2:
                    split = [r for r in records if r["policy"] == "idle_30s"]
                    self.assertEqual([r["eligible_packets"] for r in split], [1, 1])
                    self.assertEqual([r["first_frame"] for r in split], [1, 2])

    def test_first_n_windows_are_not_rolling(self):
        result, records = run_audit([packet(i + 1, i) for i in range(16)])
        for stats in result["policies"].values():
            self.assertEqual(stats["instances"], 1)
            self.assertEqual(stats["windows"]["8"]["records"], 1)
        self.assertTrue(all(r["windows"]["8"]["decision_frame"] == 8 for r in records))

    def test_packets_after_n_refresh_last_seen_and_no_hard_timeout(self):
        result, _ = run_audit([packet(i + 1, i * 20_000_000) for i in range(20)])
        for stats in result["policies"].values():
            self.assertEqual(stats["instances"], 1)
            self.assertEqual(stats["idle_boundaries"], 0)
            self.assertEqual(stats["packets_accounted_for"], 20)

    def test_idle_after_eight_creates_new_instance_not_new_rolling_window(self):
        values = [packet(i + 1, i * 1_000_000) for i in range(8)]
        values += [packet(i + 9, 70_000_000 + i * 1_000_000) for i in range(8)]
        result, _ = run_audit(values)
        self.assertEqual(result["policies"]["idle_60s"]["windows"]["8"]["records"], 2)
        self.assertEqual(result["policies"]["idle_60s"]["windows"]["8"]["original_prefixes_retained"], 1)
        self.assertEqual(result["policies"]["idle_120s"]["windows"]["8"]["records"], 1)

    def test_split_original_n8_can_produce_two_n4_records(self):
        times = [0, 1, 2, 3, 65, 66, 67, 68]
        result, records = run_audit([packet(i + 1, t * 1_000_000) for i, t in enumerate(times)])
        stats = result["policies"]["idle_60s"]
        self.assertEqual(stats["windows"]["4"]["records"], 2)
        self.assertEqual(stats["windows"]["8"]["records"], 0)
        self.assertEqual(stats["windows"]["8"]["short_instances"], 2)
        self.assertEqual(stats["windows"]["8"]["short_instances_closed_by_idle"], 1)
        self.assertEqual(stats["windows"]["8"]["original_prefixes_split"], 1)
        self.assertEqual(stats["windows"]["4"]["original_prefixes_retained"], 1)
        ids = [r["instance_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len({r["parent_candidate_conversation_id"] for r in records}), 1)

    def test_true_reverse_direction_is_same_parent(self):
        result, _ = run_audit([packet(i + 1, i, reverse=bool(i % 2)) for i in range(8)])
        self.assertEqual(result["candidate_conversations"], 1)

    def test_different_ports_or_protocols_are_separate(self):
        values = [packet(1, 0), packet(2, 1, sport=1000), packet(3, 2, protocol=17)]
        result, _ = run_audit(values)
        self.assertEqual(result["candidate_conversations"], 3)

    def test_unrelated_tuple_clock_does_not_create_backward_step(self):
        result, _ = run_audit([packet(1, 90_000_000), packet(2, 0, sport=1000), packet(3, 90_000_001)])
        self.assertEqual(result["timing"]["raw_backward_steps"], 0)

    def test_timing_and_parent_identity_match_unchanged_pilot(self):
        values = oracle_packets()
        original = accumulate(values, capture_id=CAPTURE["capture_id"], capture_sha256=CAPTURE["sha256"])
        result, records = run_audit(values)
        self.assertEqual(result["timing"]["raw_backward_steps"], original.raw_backward_steps)
        self.assertEqual(result["timing"]["timestamp_adjustments"], original.timestamp_adjustments)
        self.assertEqual(result["timing"]["max_timestamp_adjustment_ns"], original.max_timestamp_adjustment_ns)
        for record in records:
            self.assertEqual(record["parent_candidate_conversation_id"], original.conversation_id)
            for n in (4, 8):
                self.assertEqual(record["windows"][str(n)]["observation_delay_us"],
                                 original.snapshots[n]["features"]["iat_sum"])
            self.assertNotIn("features", record)
            self.assertFalse(record["training_ready"])

    def test_floor_timestamps_then_difference_not_floor_gap(self):
        first = replace(packet(1, 0), timestamp_ns=999)
        second = replace(packet(2, 0), timestamp_ns=1_000_000_001)
        result, _ = run_audit([first, second], seconds=(1,))
        self.assertEqual(result["policies"]["idle_1s"]["instances"], 2)

    def test_running_max_not_previous_raw_timestamp(self):
        times = [100_000_000, 90_000_000, 125_000_000]
        result, _ = run_audit([packet(i + 1, t) for i, t in enumerate(times)])
        self.assertEqual(result["policies"]["idle_30s"]["instances"], 1)
        self.assertEqual(result["timing"]["timestamp_adjustments"], 1)

    def test_histogram_counts_only_completed_prefixes(self):
        result, _ = run_audit([packet(i + 1, i * 1000) for i in range(8)])
        window = result["policies"]["no_timeout"]["windows"]["8"]
        self.assertEqual(window["observation_delay_us_max"], 7000)
        self.assertEqual(window["observation_delay_histogram"]["counts"], [0, 1, 0, 0, 0, 0, 0, 0])

    def test_memory_guard_and_finished_state(self):
        audit = evaluator.Audit(CAPTURE, (30,), io.StringIO(), max_conversations=1)
        audit.add(packet(1, 0))
        with self.assertRaisesRegex(ValueError, "memory guard"):
            audit.add(packet(2, 1, sport=1))
        audit.finish()
        with self.assertRaises(ValueError):
            audit.finish()
        with self.assertRaises(ValueError):
            audit.add(packet(3, 2))

    def test_invalid_thresholds_rejected(self):
        for seconds in ((), (0,), (-1,), (1, 1), (1.5,), tuple(range(1, 10))):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                evaluator.Audit(CAPTURE, seconds, io.StringIO())


class RunnerTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / "tmp/idle_timeout_tests"
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.capture = self.root / "synthetic.pcap"
        self.capture.write_bytes(b"Synthetic placeholder, not a real PCAP")
        self.entry = dict(CAPTURE, path=str(self.capture), include_in_baseline=True,
                          size_bytes=self.capture.stat().st_size,
                          sha256=hashlib.sha256(self.capture.read_bytes()).hexdigest())
        self.manifest = self.root / "inventory.json"
        self.manifest.write_text(json.dumps({"schema_version": 1, "captures": [self.entry]}))
        self.output = self.root / "output"

    def lines(self, count=8, **overrides):
        rows = []
        for i in range(count):
            fields = {"frame.number": str(i + 1), "frame.time_epoch": f"1.{i:06d}"}
            fields.update(overrides)
            rows.append("\t".join(fixtures.DecoderTests().fields(**fields)))
        return "\n".join(rows) + "\n"

    def run_main(self, lines=None, returncode=0, selection=None):
        arguments = ["--manifest", str(self.manifest), "--output-root", str(self.output)]
        arguments += selection or ["--capture", self.capture.name]
        version = type("Version", (), {"stdout": "Fake TShark unit test"})()
        with patch.object(evaluator.subprocess, "run", return_value=version), \
                patch.object(evaluator.subprocess, "Popen", return_value=FakeProcess(self.lines() if lines is None else lines, returncode)), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return evaluator.main(arguments)

    def run_dir(self):
        return next(self.output.iterdir())

    def test_success_manifest_and_source_provenance_no_feature_files(self):
        before = self.capture.read_bytes()
        self.assertEqual(self.run_main(), 0)
        directory = self.run_dir()
        summary = json.loads((directory / "summary.json").read_text())
        self.assertEqual(summary["status"], "evaluation_complete")
        self.assertFalse(summary["training_ready"])
        self.assertEqual(summary["captures"][0]["eligible_packets"], 8)
        self.assertEqual(list(directory.rglob("features*")), [])
        self.assertEqual(self.capture.read_bytes(), before)
        self.assertTrue((directory / "capture_001/source.json").exists())
        self.assertFalse((directory / "failure.json").exists())

    def test_textual_booleans_and_filter_reused(self):
        rows = self.lines(**{"ip.flags.mf": "False"}) + self.lines(count=2, **{"tcp.dstport": "53"})
        self.assertEqual(self.run_main(rows), 0)
        capture = json.loads((self.run_dir() / "summary.json").read_text())["captures"][0]
        self.assertEqual(capture["frames_read"], 10)
        self.assertEqual(capture["eligible_packets"], 8)
        self.assertEqual(capture["rejected_frames_by_first_reason"], {"port_53_baseline_exclusion": 2})

    def test_failed_tshark_leaves_failure_not_success(self):
        self.assertEqual(self.run_main(returncode=2), 1)
        self.assertTrue((self.run_dir() / "failure.json").exists())
        self.assertFalse((self.run_dir() / "summary.json").exists())

    def test_bad_schema_is_fatal(self):
        self.assertEqual(self.run_main("1\t2\n"), 1)
        self.assertFalse((self.run_dir() / "summary.json").exists())

    def test_empty_or_all_rejected_capture_is_fatal(self):
        self.assertEqual(self.run_main(self.lines(**{"tcp.dstport": "53"})), 1)
        self.assertFalse((self.run_dir() / "summary.json").exists())

    def test_bad_fields_keep_bounded_diagnostics(self):
        self.assertEqual(self.run_main(self.lines() + self.lines(count=10, **{"ip.flags.mf": "unknown"})), 0)
        diagnostics = (self.run_dir() / "capture_001/field_parse_errors.jsonl").read_text().splitlines()
        self.assertEqual(len(diagnostics), 3)

    def test_hash_mismatch_has_no_success_output(self):
        self.capture.write_bytes(b"Changed")
        self.assertEqual(self.run_main(), 1)
        self.assertFalse((self.run_dir() / "summary.json").exists())
        self.assertTrue((self.run_dir() / "failure.json").exists())

    def test_repeated_runs_do_not_overwrite(self):
        self.assertEqual(self.run_main(), 0)
        directory = self.run_dir()
        before = (directory / "summary.json").read_bytes()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(list(self.output.iterdir())), 2)
        self.assertEqual((directory / "summary.json").read_bytes(), before)

    def test_all_included_selects_only_included(self):
        excluded = dict(self.entry, filename="excluded.pcap", include_in_baseline=False)
        self.manifest.write_text(json.dumps({"schema_version": 1, "captures": [self.entry, excluded]}))
        self.assertEqual(self.run_main(selection=["--all-included"]), 0)
        summary = json.loads((self.run_dir() / "summary.json").read_text())
        self.assertEqual(summary["captures_evaluated"], 1)

    def test_excluded_and_duplicate_selection_fail(self):
        for names in (["absent.pcap"], [self.capture.name, self.capture.name]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                evaluator.select_names({"schema_version": 1, "captures": [self.entry]}, names, False)
        excluded = dict(self.entry, include_in_baseline=False)
        with self.assertRaises(ValueError):
            evaluator.select_names({"schema_version": 1, "captures": [excluded]}, [self.capture.name], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
