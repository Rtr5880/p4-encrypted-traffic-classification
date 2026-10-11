"""Nonprivileged fixture regressions for sealed detail/history presentation loads."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dashboard.evidence import EvidenceStore, CLASS_ORDER


def encoded(value):
    return json.dumps(value).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def features(direction=False):
    values = dict(size_min=40, size_max=100, size_sum=500,
                  iat_min=1, iat_max=10, iat_sum=30)
    if direction:
        values.update(reverse_packet_count=3, direction_change_count=4)
    return values


def report(valid=1):
    return {"valid": valid, "prediction": 1 if valid else 255,
            "leaves": [1 if valid else 0] * 10,
            "scores": [1 if valid else 0] * 6}


class DetailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "run").mkdir()
        self.entry = {"root": "project", "path": "run/summary.json",
                      "adapter": "controlled_replay", "run_id": "fixture"}
        self.parent = {"status": "controlled_real_pcap_parity_pass", "captures": [],
                       "captures_checked": 0, "accuracy_scored": False,
                       "native_clock_replay": False, "performance_measured": False,
                       "output_sha256": {}}
        self.write_parent()

    def write_parent(self):
        raw = encoded(self.parent)
        (self.root / "run/summary.json").write_bytes(raw)
        self.entry["sha256"] = sha(raw)
        (self.root / "config/dashboard-evidence.json").write_bytes(encoded({
            "schema_version": "dashboard-evidence-registry-v1", "entries": {"parent": self.entry}
        }))

    def child(self, name="details.jsonl", raw=b'{"number":1}\n'):
        path = self.root / "run" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.parent["output_sha256"][name] = sha(raw)
        self.write_parent()
        return path

    def store(self):
        return EvidenceStore(project_root=self.root)

    def test_sealed_json_and_jsonl_load(self):
        self.child("detail.json", encoded({"value": 7}))
        self.child(raw=b'{"number":1}\n\n{"number":2}\n')
        store = self.store()
        result = store.load_child("parent", "detail.json")
        self.assertTrue(result.verified)
        self.assertEqual(result.data, {"value": 7})
        self.assertEqual(store.load_child("parent", "details.jsonl", format="jsonl").data,
                         [{"number": 1}, {"number": 2}])

    def test_child_content_change_never_leaks_cached_data(self):
        path = self.child()
        store = self.store()
        self.assertTrue(store.load_child("parent", "details.jsonl", "jsonl").verified)
        path.write_bytes(b'{"number":999}\n')
        result = store.load_child("parent", "details.jsonl", "jsonl")
        self.assertEqual(result.status, "corrupt")
        self.assertIsNone(result.data)

    def test_changed_parent_blocks_even_unchanged_child(self):
        self.child()
        store = self.store()
        (self.root / "run/summary.json").write_bytes(b'{}')
        self.assertEqual(store.load_child("parent", "details.jsonl", "jsonl").status, "corrupt")

    def test_parent_change_during_child_read_is_rejected(self):
        self.child()
        store = self.store()
        original = store.load
        calls = 0

        def mutate_on_second_load(role):
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.root / "run/summary.json").write_bytes(b'{}')
            return original(role)

        with patch.object(store, "load", side_effect=mutate_on_second_load):
            self.assertEqual(store.load_child("parent", "details.jsonl", "jsonl").status, "corrupt")

    def test_unsealed_child_is_rejected(self):
        (self.root / "run/unsealed.json").write_bytes(b'{}')
        self.assertEqual(self.store().load_child("parent", "unsealed.json").status, "corrupt")

    def test_missing_sealed_child_remains_unavailable(self):
        path = self.child()
        path.unlink()
        self.assertEqual(self.store().load_child("parent", "details.jsonl", "jsonl").status, "unavailable")

    def test_path_escape_and_platform_aliases_rejected(self):
        for name in ("../outside.json", "/absolute.json", "a/../../outside.json", "..\\outside.json", "C:/outside.json", "."):
            with self.subTest(name=name):
                self.assertEqual(self.store().load_child("parent", name).status, "corrupt")

    def test_symlink_escape_rejected(self):
        outside = self.root / "outside.json"
        outside.write_bytes(b'{}')
        link = self.root / "run/link.json"
        link.symlink_to(outside)
        self.parent["output_sha256"]["link.json"] = sha(b'{}')
        self.write_parent()
        self.assertEqual(self.store().load_child("parent", "link.json").status, "corrupt")

    def test_format_mismatch_and_nonjson_formats_unsupported(self):
        self.child()
        self.assertEqual(self.store().load_child("parent", "details.jsonl", "pickle").status, "unsupported")
        self.assertEqual(self.store().load_child("parent", "details.jsonl", "json").status, "unsupported")

    def test_jsonl_duplicate_keys_nonfinite_and_partial_rejected(self):
        for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":1e400}\n', b'{"x":1}\n{"x":', b'[1,2]\n'):
            with self.subTest(raw=raw):
                self.child(raw=raw)
                self.assertEqual(self.store().load_child("parent", "details.jsonl", "jsonl").status, "corrupt")

    def test_jsonl_rows_lines_and_bytes_are_bounded(self):
        self.child(raw=b'{"number":1}\n{"number":2}\n')
        with patch("dashboard.evidence.MAX_JSONL_ROWS", 1):
            self.assertEqual(self.store().load_child("parent", "details.jsonl", "jsonl").status, "corrupt")
        with patch("dashboard.evidence.MAX_JSONL_LINE_BYTES", 5):
            self.assertEqual(self.store().load_child("parent", "details.jsonl", "jsonl").status, "corrupt")
        self.child("large.json", encoded({"payload": "x" * 2000}))
        with patch("dashboard.evidence.MAX_JSON_BYTES", 1500):
            self.assertEqual(self.store().load_child("parent", "large.json").status, "corrupt")

    def native(self, rows):
        self.entry["adapter"] = "native_run"
        self.parent = {"status": "native_evaluation_passed", "output_sha256": {},
                       "expected_cases_per_model": 1, "expected_model_case_evaluations": 2,
                       "verified_classified_evaluations": 2, "native_clock": True,
                       "raw_clock_clean": True, "passed": True}
        self.child("outcomes.jsonl", b"\n".join(encoded(row) for row in rows) + b"\n")

    def outcome(self, model):
        return {"case_id": "case", "record_id": "case:n8", "model": model, "label": "CHAT",
                "status": "verified_classified", "timing": {}, "clock_quality": {},
                "features_B": features(), "features_C": features(True),
                "packet_checks": [{"rf_report": report(0)}] * 7 + [{"rf_report": report()}]}

    def test_native_no_decision_sentinel_preserved(self):
        self.native([self.outcome("B"), self.outcome("C")])
        result = self.store().load_child("parent", "outcomes.jsonl", "jsonl")
        self.assertTrue(result.verified, result.message)
        self.assertEqual(result.data[0]["packet_checks"][0]["rf_report"]["prediction"], 255)

    def test_invalid_native_sentinel_and_valid_out_of_range_rejected(self):
        for valid, prediction in ((0, 1), (1, 255)):
            a, b = self.outcome("B"), self.outcome("C")
            a["packet_checks"] = [{"rf_report": report(0)} for _ in range(7)] + [{"rf_report": report()}]
            a["packet_checks"][0]["rf_report"]["valid"] = valid
            a["packet_checks"][0]["rf_report"]["prediction"] = prediction
            self.native([a, b])
            self.assertEqual(self.store().load_child("parent", "outcomes.jsonl", "jsonl").status, "corrupt")

    def test_native_duplicate_identity_wrong_count_and_boolean_features_rejected(self):
        for variant in ("duplicate", "count", "feature"):
            a, b = self.outcome("B"), self.outcome("C")
            if variant == "duplicate":
                b["model"] = "B"
            if variant == "feature":
                a["features_B"]["size_min"] = True
            self.native([a] if variant == "count" else [a, b])
            self.assertEqual(self.store().load_child("parent", "outcomes.jsonl", "jsonl").status, "corrupt")

    def test_controlled_rows_must_match_record_schema(self):
        row = {"record_id": "r", "instance_id": "i", "packet_id": 8, "collision_excluded": False,
               "features_B": features(), "features_C": features(True), "feature_report": {}, "rf_report": report()}
        self.child("capture_001/RF_B/decisions.jsonl", encoded(row) + b"\n")
        self.assertTrue(self.store().load_child("parent", "capture_001/RF_B/decisions.jsonl", "jsonl").verified)
        row["rf_report"]["scores"] = [1]
        self.child("capture_001/RF_B/decisions.jsonl", encoded(row) + b"\n")
        self.assertEqual(self.store().load_child("parent", "capture_001/RF_B/decisions.jsonl", "jsonl").status, "corrupt")

    def history(self, rows=None):
        raw = encoded({"status": "failed", "passed": False, "verdicts": {"measurement_integrity": "FAIL"}})
        (self.root / "run/failed.json").write_bytes(raw)
        entry = {"id": "failed", "family": "performance", "category": "historical-failure",
                 "label": "Preserved failure", "scope": "Diagnostic only", "run_id": "r",
                 "root": "project", "path": "run/failed.json", "sha256": sha(raw), "adapter": "history_summary"}
        path = self.root / "config/dashboard-history.json"
        path.write_bytes(encoded({"schema_version": "dashboard-history-registry-v1", "entries": rows if rows is not None else [entry]}))
        return entry, path

    def test_history_verified_failure_is_not_a_pass(self):
        self.history()
        store = self.store()
        self.assertEqual(len(store.history_entries()), 1)
        result = store.load_history("failed")[0]
        self.assertTrue(result.verified)
        self.assertFalse(result.data["passed"])
        self.assertEqual(result.data["status"], "failed")
        self.assertEqual(result.entry["category"], "historical-failure")

    def test_history_missing_unknown_changed_and_unsupported(self):
        self.assertEqual(self.store().load_history()[0].status, "unavailable")
        _, path = self.history()
        store = self.store()
        self.assertEqual(store.load_history("unknown")[0].status, "unavailable")
        (self.root / "run/failed.json").write_bytes(b'{}')
        self.assertEqual(store.load_history("failed")[0].status, "corrupt")
        path.write_bytes(encoded({"schema_version": "future", "entries": []}))
        self.assertEqual(store.load_history()[0].status, "unsupported")

    def test_history_duplicate_unsafe_or_unpinned_entries_rejected(self):
        entry, _ = self.history()
        self.history([entry, entry])
        self.assertEqual(self.store().load_history()[0].status, "corrupt")
        entry["path"] = "../escaped.json"
        self.history([entry])
        self.assertEqual(self.store().load_history()[0].status, "corrupt")
        entry["path"] = "run/failed.json"
        entry["sha256"] = None
        self.history([entry])
        self.assertEqual(self.store().load_history()[0].status, "corrupt")

    def test_history_registry_override_and_entry_limit(self):
        entry, path = self.history()
        with patch.dict(os.environ, {"ETC_DASHBOARD_HISTORY_REGISTRY": str(path)}):
            self.assertEqual(self.store().history_path, path)
        with patch("dashboard.evidence.MAX_HISTORY_ENTRIES", 0):
            self.assertEqual(self.store().load_history()[0].status, "corrupt")


if __name__ == "__main__":
    unittest.main()
