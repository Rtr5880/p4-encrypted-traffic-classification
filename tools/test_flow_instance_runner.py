"""Synthetic runner and independent output-checker tests; no real PCAP reads."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import extract_flow_instances as extractor
import test_extract_flow_instances as fixtures
from test_extract_feature_pilot_runner import FakeProcess
import validate_instance_output as validator


class RunnerTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / "tmp/flow_instance_tests"
        root.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.capture = self.root / "synthetic.pcap"
        self.capture.write_bytes(b"Synthetic placeholder, not an actual packet capture")
        self.entry = dict(fixtures.CAPTURE, path=str(self.capture), include_in_baseline=True,
                          size_bytes=self.capture.stat().st_size,
                          sha256=hashlib.sha256(self.capture.read_bytes()).hexdigest())
        self.manifest = self.root / "inventory.json"
        self.write_manifest([self.entry])
        self.output = self.root / "output"

    def write_manifest(self, entries):
        self.manifest.write_text(json.dumps({"schema_version": 1, "captures": entries}), encoding="utf-8")

    def lines(self, count=8, **overrides):
        lines = []
        for i in range(count):
            changes = {"frame.number": str(i + 1), "frame.time_epoch": f"1.{i:06d}"}
            changes.update(overrides)
            lines.append("\t".join(fixtures.DecoderTests.fields(**changes)))
        return "\n".join(lines) + "\n"

    def run_main(self, lines=None, returncode=0, options=None):
        args = ["--manifest", str(self.manifest), "--output-root", str(self.output)]
        args += options or ["--capture", "synthetic.pcap"]
        version = type("Version", (), {"stdout": "Fake TShark for controlled tests"})()
        with patch.object(extractor.subprocess, "run", return_value=version), \
                patch.object(extractor.subprocess, "Popen", side_effect=lambda *a, **k: FakeProcess(self.lines() if lines is None else lines, returncode)), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return extractor.main(args)

    def directory(self):
        return next(self.output.iterdir())

    def test_success_paired_records_validate_and_source_unchanged(self):
        before = self.capture.read_bytes()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(validator.validate_run(self.directory()),
                         {"captures": 1, "instances": 1, "n4_records": 1, "n8_records": 1})
        policy = json.loads((self.directory() / "policy.json").read_text())
        self.assertEqual(policy["idle_seconds"], 60)
        self.assertEqual(policy["boundary_policy"], "idle-tcp")
        self.assertIsNone(policy["hard_timeout"])
        self.assertFalse(policy["p4_semantics_verified"])
        self.assertEqual(self.capture.read_bytes(), before)

    def test_short_capture_is_success_with_empty_feature_files(self):
        self.assertEqual(self.run_main(self.lines(count=3)), 0)
        self.assertEqual(validator.validate_run(self.directory())["n4_records"], 0)

    def test_tshark_nonzero_marks_run_failed_and_validator_rejects(self):
        self.assertEqual(self.run_main(returncode=2), 1)
        self.assertTrue((self.directory() / "failure.json").exists())
        self.assertFalse((self.directory() / "summary.json").exists())
        with self.assertRaisesRegex(ValueError, "failed"):
            validator.validate_run(self.directory())

    def test_bad_row_schema_fails_not_success(self):
        self.assertEqual(self.run_main("1\t2\n"), 1)
        self.assertFalse((self.directory() / "summary.json").exists())

    def test_all_rejected_is_failure(self):
        self.assertEqual(self.run_main(self.lines(**{"tcp.dstport": "53"})), 1)
        self.assertFalse((self.directory() / "summary.json").exists())

    def test_field_diagnostics_bounded_and_rejections_accounted(self):
        lines = self.lines() + self.lines(count=10, **{"tcp.flags.syn": "unknown"})
        self.assertEqual(self.run_main(lines), 0)
        path = self.directory() / "capture_001/field_parse_errors.jsonl"
        self.assertEqual(len(path.read_text().splitlines()), 3)
        validator.validate_run(self.directory())

    def test_hash_mismatch_blocks_extraction(self):
        self.capture.write_bytes(b"Modified")
        self.assertEqual(self.run_main(), 1)
        self.assertFalse((self.directory() / "summary.json").exists())

    def test_repeated_runs_never_overwrite(self):
        self.assertEqual(self.run_main(), 0)
        directory = self.directory()
        before = (directory / "summary.json").read_bytes()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(list(self.output.iterdir())), 2)
        self.assertEqual((directory / "summary.json").read_bytes(), before)

    def test_excluded_capture_not_selected(self):
        excluded = dict(self.entry, filename="excluded.pcap", capture_id="excluded", include_in_baseline=False)
        self.write_manifest([self.entry, excluded])
        self.assertEqual(self.run_main(options=["--all-included"]), 0)
        self.assertEqual(validator.validate_run(self.directory())["captures"], 1)

    def test_duplicate_content_across_names_rejected(self):
        self.write_manifest([self.entry, dict(self.entry, filename="copy.pcap", capture_id="copy")])
        self.assertEqual(self.run_main(options=["--all-included"]), 1)
        self.assertFalse(self.output.exists())

    def test_bad_options_rejected_before_output(self):
        self.assertEqual(self.run_main(options=["--all-included", "--idle-seconds", "0"]), 1)
        self.assertFalse(self.output.exists())

    def test_two_captures_get_separate_parent_ids(self):
        other = self.root / "second.pcap"
        other.write_bytes(b"Second synthetic placeholder")
        self.write_manifest([self.entry, dict(self.entry, path=str(other), filename=other.name,
            capture_id="second", size_bytes=other.stat().st_size,
            sha256=hashlib.sha256(other.read_bytes()).hexdigest())])
        self.assertEqual(self.run_main(options=["--all-included"]), 0)
        self.assertEqual(validator.validate_run(self.directory())["captures"], 2)

    def corrupt_record(self, mutation, n=8):
        self.assertEqual(self.run_main(), 0)
        path = self.directory() / f"capture_001/features_n{n}.jsonl"
        record = json.loads(path.read_text())
        mutation(record)
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            validator.validate_run(self.directory())

    def test_validator_rejects_bad_feature_arithmetic(self):
        self.corrupt_record(lambda r: r["features_C"].update(size_sum=1))

    def test_validator_rejects_wrong_b_pair(self):
        self.corrupt_record(lambda r: r["features_B"].update(iat_min=100))

    def test_validator_rejects_boolean_disguised_as_integer(self):
        self.corrupt_record(lambda r: r["features_B"].update(iat_min=True))

    def test_validator_rejects_artificial_initial_gap(self):
        self.corrupt_record(lambda r: r["debug_metadata_not_model_inputs"]["trace"][0].update(iat_us=0))

    def test_validator_rejects_direction_not_reset(self):
        self.corrupt_record(lambda r: r["debug_metadata_not_model_inputs"]["trace"][0].update(direction="R"))

    def test_validator_rejects_cross_capture_identity(self):
        self.corrupt_record(lambda r: r.update(capture_id="wrong"))

    def test_validator_rejects_missing_feature_record(self):
        self.assertEqual(self.run_main(), 0)
        (self.directory() / "capture_001/features_n8.jsonl").write_text("")
        with self.assertRaisesRegex(ValueError, "Missing"):
            validator.validate_run(self.directory())

    def test_validator_rejects_duplicate_feature_record(self):
        self.assertEqual(self.run_main(), 0)
        path = self.directory() / "capture_001/features_n8.jsonl"
        path.write_text(path.read_text() * 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validator.validate_run(self.directory())

    def test_validator_rejects_incomplete_directory(self):
        with self.assertRaises(OSError):
            validator.validate_run(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
