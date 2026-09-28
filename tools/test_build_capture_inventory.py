"""Tests use tiny synthetic byte files, never the student's real PCAPs."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import build_capture_inventory as inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        test_root = Path(__file__).resolve().parents[1] / "tmp" / "inventory_tests"
        test_root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="fixture-", dir=test_root)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for folder in inventory.FOLDERS:
            (self.root / folder).mkdir()
        self.paths = {}
        for index, name in enumerate(sorted(inventory.EXPECTED)):
            # Deliberately alternate folder assignment; it is not hard-coded.
            path = self.root / inventory.FOLDERS[index % 2] / name
            path.write_bytes(("synthetic test fixture: " + name).encode("utf-8"))
            self.paths[name] = path
        self.output = self.root / "metadata" / "capture_inventory.json"

    def invoke(self, output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = inventory.main([
                "--data-root", str(self.root),
                "--output", str(output or self.output),
            ])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_complete_manifest_and_unchanged_inputs(self):
        original = {name: path.read_bytes() for name, path in self.paths.items()}
        result, stdout, stderr = self.invoke()
        self.assertEqual(result, 0, stderr)
        document = json.loads(self.output.read_text(encoding="utf-8"))
        summary = document["summary"]
        self.assertEqual(summary["total_captures"], 31)
        self.assertEqual(summary["included_captures"], 29)
        self.assertEqual(summary["excluded_captures"], 2)
        self.assertEqual(summary["included_captures_by_initial_class"], {
            "CHAT": 10, "FT": 6, "MAIL": 2, "P2P": 1, "STREAMING": 5, "VOIP": 5,
        })
        self.assertEqual(summary["total_size_bytes"], sum(map(len, original.values())))
        for record in document["captures"]:
            name = record["filename"]
            self.assertEqual(record["sha256"], hashlib.sha256(original[name]).hexdigest())
            self.assertEqual(self.paths[name].read_bytes(), original[name])
            if name in inventory.EXCLUDED:
                self.assertFalse(record["include_in_baseline"])
                self.assertIsNone(record["initial_class"])
        self.assertFalse(document["policy"]["timestamp_correction_applied"])
        self.assertFalse(document["policy"]["flow_extraction_applied"])
        self.assertFalse(document["policy"]["train_test_split_assigned"])
        self.assertIn("INVENTORY CREATED", stdout)

    def test_existing_output_is_preserved(self):
        self.output.parent.mkdir()
        self.output.write_text("original contents", encoding="utf-8")
        result, _, stderr = self.invoke()
        self.assertEqual(result, 1)
        self.assertIn("nothing overwritten", stderr)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "original contents")

    def test_missing_file_is_not_silently_ignored(self):
        self.paths["vpn_bittorrent.pcap"].rename(self.root / "held-aside.bin")
        result, _, stderr = self.invoke()
        self.assertEqual(result, 1)
        self.assertIn("Missing expected captures: vpn_bittorrent.pcap", stderr)
        self.assertFalse(self.output.exists())

    def test_unknown_file_is_not_given_a_guessed_label(self):
        (self.root / inventory.FOLDERS[0] / "vpn_unknown.pcap").write_bytes(b"test")
        result, _, stderr = self.invoke()
        self.assertEqual(result, 1)
        self.assertIn("Unrecognised captures", stderr)
        self.assertFalse(self.output.exists())

    def test_duplicate_names_are_rejected(self):
        path = self.paths["vpn_bittorrent.pcap"]
        other_folder = next(folder for folder in inventory.FOLDERS if folder != path.parent.name)
        (self.root / other_folder / path.name).write_bytes(b"another fixture")
        result, _, stderr = self.invoke()
        self.assertEqual(result, 1)
        self.assertIn("Duplicate capture names", stderr)
        self.assertFalse(self.output.exists())

    def test_identical_contents_are_flagged(self):
        self.paths["vpn_email2a.pcap"].write_bytes(self.paths["vpn_email2b.pcap"].read_bytes())
        result, _, stderr = self.invoke()
        self.assertEqual(result, 1)
        self.assertIn("Identical included captures need review", stderr)
        self.assertFalse(self.output.exists())

    def test_empty_capture_is_rejected(self):
        self.paths["vpn_bittorrent.pcap"].write_bytes(b"")
        result, _, stderr = self.invoke()
        self.assertEqual(result, 1)
        self.assertIn("Empty capture", stderr)
        self.assertFalse(self.output.exists())

    def test_capture_cannot_be_an_output_target(self):
        path = self.paths["vpn_bittorrent.pcap"]
        original = path.read_bytes()
        result, _, stderr = self.invoke(output=path)
        self.assertEqual(result, 1)
        self.assertIn("Output must end in .json", stderr)
        self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
