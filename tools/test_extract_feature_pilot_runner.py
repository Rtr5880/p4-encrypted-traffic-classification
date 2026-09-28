"""Runner tests using fake TShark output and tiny synthetic input files only."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import extract_feature_pilot as pilot
import test_extract_feature_pilot as fixtures


class FakeProcess:
    def __init__(self, lines, returncode=0):
        self.stdout = io.StringIO(lines)
        self.returncode = returncode
        self.killed = False

    def wait(self):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True


class RunnerTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / "tmp/pilot_feature_tests"
        root.mkdir(parents=True, exist_ok=True)
        self.sandbox = tempfile.TemporaryDirectory(prefix="runner_", dir=root)
        self.addCleanup(self.sandbox.cleanup)
        self.root = Path(self.sandbox.name)
        self.capture = self.root / "synthetic.pcap"
        self.original = b"Synthetic placeholder; not a real PCAP; decoder is mocked."
        self.capture.write_bytes(self.original)
        self.manifest = self.root / "inventory.json"
        self.entry = {
            "filename": self.capture.name, "capture_id": "synthetic/synthetic.pcap",
            "path": str(self.capture), "size_bytes": len(self.original),
            "sha256": hashlib.sha256(self.original).hexdigest(),
            "include_in_baseline": True, "initial_class": "MAIL",
        }
        self.manifest.write_text(json.dumps({"schema_version": 1, "captures": [self.entry]}), encoding="utf-8")
        self.output = self.root / "results"

    def lines(self, count=8, **overrides):
        rows = []
        for index in range(count):
            values = {"frame.number": str(index + 1), "frame.time_epoch": f"1.{index:06d}"}
            values.update(overrides)
            rows.append("\t".join(fixtures.DecoderTests().fields(**values)))
        return "\n".join(rows) + "\n"

    def run_main(self, lines=None, returncode=0, **options):
        arguments = ["--manifest", str(self.manifest), "--capture", self.capture.name,
                     "--output-root", str(self.output)]
        for key, value in options.items():
            arguments.extend(["--" + key.replace("_", "-"), str(value)])
        version = type("Version", (), {"stdout": "Fake TShark for runner unit test"})()
        process = FakeProcess(self.lines() if lines is None else lines, returncode)
        with patch.object(pilot.subprocess, "run", return_value=version), \
                patch.object(pilot.subprocess, "Popen", return_value=process), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = pilot.main(arguments)
        return code

    def only_run_dir(self):
        runs = list(self.output.iterdir())
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_success_produces_paired_prefixes_and_preserves_original(self):
        self.assertEqual(self.run_main(), 0)
        run = self.only_run_dir()
        summary = json.loads((run / "summary.json").read_text())
        self.assertEqual(summary["status"], "pilot_complete")
        self.assertFalse(summary["training_ready"])
        self.assertEqual(summary["eligible_packets"], 8)
        records = [json.loads((run / f"features_n{n}.jsonl").read_text()) for n in (4, 8)]
        self.assertEqual(records[0]["candidate_conversation_id"], records[1]["candidate_conversation_id"])
        self.assertNotEqual(records[0]["record_id"], records[1]["record_id"])
        self.assertEqual(records[0]["features"]["iat_sum"], 3)
        self.assertEqual(records[1]["features"]["iat_sum"], 7)
        self.assertEqual(self.capture.read_bytes(), self.original)
        self.assertFalse((run / "failure.json").exists())

    def test_failed_tshark_never_produces_success_summary_or_features(self):
        self.assertEqual(self.run_main(returncode=2), 1)
        run = self.only_run_dir()
        self.assertTrue((run / "failure.json").exists())
        self.assertFalse((run / "summary.json").exists())
        self.assertEqual(list(run.glob("features*")), [])
        self.assertEqual(self.capture.read_bytes(), self.original)

    def test_textual_false_runs_through_to_feature_output(self):
        self.assertEqual(self.run_main(lines=self.lines(**{"ip.flags.mf": "False"})), 0)
        run = self.only_run_dir()
        summary = json.loads((run / "summary.json").read_text())
        self.assertEqual(summary["eligible_packets"], 8)
        self.assertEqual(summary["windows"]["8"]["records"], 1)
        self.assertEqual(summary["rejected_frames_by_first_reason"], {})
        self.assertEqual((run / "field_parse_errors.jsonl").read_text(), "")

    def test_textual_true_remains_excluded_as_fragment(self):
        rows = self.lines(**{"ip.flags.mf": "False"}) + self.lines(count=4, **{"ip.flags.mf": "True"})
        self.assertEqual(self.run_main(lines=rows), 0)
        summary = json.loads((self.only_run_dir() / "summary.json").read_text())
        self.assertEqual(summary["eligible_packets"], 8)
        self.assertEqual(summary["rejected_frames_by_first_reason"], {"ipv4_fragment": 4})

    def test_conversion_diagnostics_are_bounded_and_field_specific(self):
        rows = (self.lines() + self.lines(count=10, **{"ip.flags.mf": "unknown"})
                + self.lines(count=5, **{"ip.proto": "six"}))
        self.assertEqual(self.run_main(lines=rows), 0)
        run = self.only_run_dir()
        summary = json.loads((run / "summary.json").read_text())
        self.assertEqual(summary["rejected_frames_by_first_reason"], {
            "missing_or_invalid_header_field:ip.flags.mf": 10,
            "missing_or_invalid_header_field:ip.proto": 5,
        })
        examples = [json.loads(line) for line in (run / "field_parse_errors.jsonl").read_text().splitlines()]
        self.assertEqual(len(examples), 6)
        self.assertEqual([item["raw_value"] for item in examples], ["unknown"] * 3 + ["six"] * 3)
        self.assertTrue(all(set(item) == {"frame", "field", "raw_value", "reason"} for item in examples))

    def test_failed_all_invalid_run_still_preserves_field_diagnostics(self):
        self.assertEqual(self.run_main(lines=self.lines(**{"ip.flags.mf": "unknown"})), 1)
        run = self.only_run_dir()
        failure = json.loads((run / "failure.json").read_text())
        self.assertIn("missing_or_invalid_header_field:ip.flags.mf", failure["error"])
        self.assertEqual(len((run / "field_parse_errors.jsonl").read_text().splitlines()), 3)
        self.assertFalse((run / "summary.json").exists())

    def test_bad_tshark_schema_fails_instead_of_silently_filtering(self):
        self.assertEqual(self.run_main(lines="1\t2\n"), 1)
        run = self.only_run_dir()
        self.assertTrue((run / "failure.json").exists())
        self.assertFalse((run / "summary.json").exists())

    def test_inventory_hash_mismatch_fails_before_output_creation(self):
        self.capture.write_bytes(b"Different synthetic content")
        self.assertEqual(self.run_main(), 1)
        self.assertFalse(self.output.exists())

    def test_repeated_runs_use_unique_directories_without_overwrite(self):
        self.assertEqual(self.run_main(), 0)
        first = self.only_run_dir()
        initial_summary = (first / "summary.json").read_bytes()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(list(self.output.iterdir())), 2)
        self.assertEqual((first / "summary.json").read_bytes(), initial_summary)

    def test_short_conversations_reported_separately_per_n(self):
        self.assertEqual(self.run_main(lines=self.lines(count=4)), 0)
        summary = json.loads((self.only_run_dir() / "summary.json").read_text())
        self.assertEqual(summary["windows"]["4"]["records"], 1)
        self.assertEqual(summary["windows"]["8"]["records"], 0)
        self.assertEqual(summary["windows"]["8"]["short_by_provisional_class"], {"MAIL": 1})

    def test_memory_guard_fails_instead_of_dropping_extra_conversations(self):
        rows = self.lines(count=4) + self.lines(count=4, **{"tcp.srcport": "2222"})
        self.assertEqual(self.run_main(lines=rows, max_conversations=1), 1)
        run = self.only_run_dir()
        self.assertTrue((run / "failure.json").exists())
        self.assertFalse((run / "summary.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
