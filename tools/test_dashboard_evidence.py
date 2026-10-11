"""Nonprivileged temporary-fixture tests; historical project evidence is read-only."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.evidence import CLASS_ORDER, EvidenceStore, REGISTRY_SCHEMA
from tools.dashboard_status import main


def forest() -> dict:
    return {"schema_version": "rf-integer-reference-v1", "classes": CLASS_ORDER,
            "feature_order": ["size_min"], "feature_set": "B",
            "parameters": {"n_estimators": 1}, "score_scale": 16777216,
            "trees": [{"nodes": [{"kind": "leaf", "scores": [1, 0, 0, 0, 0, 0]}]}],
            "domains": {}}


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="dashboard-evidence-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry_path = self.root / "config/dashboard-evidence.json"
        self.registry_path.parent.mkdir()
        self.registry = {"schema_version": REGISTRY_SCHEMA, "entries": {}}
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {}, clear=True).start()

    def save_registry(self) -> None:
        self.registry_path.write_text(json.dumps(self.registry), encoding="utf-8")

    def add(self, role="rf_b", data=None, path="results/forest.json", **extra) -> dict:
        data = forest() if data is None else data
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data), encoding="utf-8")
        entry = {"path": path, "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                 "adapter": "forest", "schema_value": "rf-integer-reference-v1",
                 "feature_set": "B", **extra}
        self.registry["entries"][role] = entry
        self.save_registry()
        return entry

    def store(self) -> EvidenceStore:
        return EvidenceStore(self.registry_path, self.root)

    def calibration(self) -> None:
        children = []
        seal = {}
        names = []
        for index, mode in enumerate(("forwarding", "rf_b"), 1):
            name = f"trial_{index:03d}_{mode}"
            names.append(name)
            rel = f"results/calibration/{name}/qualified_trial_summary.json"
            data = {"mode": mode, "workload": "classification-heavy", "rate_pps": 100,
                    "repetition": 1, "metrics": {"decisions": None if index == 1 else 1},
                    "metric_validity": {"cpu": True}, "verdicts": {},
                    "raw_rate_qualified": True, "valid": True,
                    "kernel_forwarding_latency_qualified": False}
            entry = self.add(f"fixture_child_{index}", data, rel,
                             adapter="calibration_trial", identity={"mode": mode})
            entry.pop("schema_value")
            entry.pop("feature_set")
            children.append(entry)
            seal[f"{name}/qualified_trial_summary.json"] = entry["sha256"]
            del self.registry["entries"][f"fixture_child_{index}"]
        summary = {"schema_version": "raw-performance-calibration-v3", "status": "passed",
                   "trials": names, "verdicts": {}, "protocol": {},
                   "raw_rate_qualified": True, "expected_trials": 2,
                   "attempted_trials": 2, "valid_trials": 2,
                   "artifact_hashes": seal, "kernel_forwarding_latency_qualified": False}
        self.add("raw_calibration", summary, "results/calibration/summary.json",
                 adapter="calibration_summary", schema_value="raw-performance-calibration-v3",
                 expected_trial_count=2, children=children)

    def test_valid_forest_returns_unchanged_payload(self):
        self.add()
        result = self.store().load("rf_b")
        self.assertTrue(result.verified)
        self.assertEqual(result.data, forest())
        self.assertTrue(result.path.is_absolute())

    def test_missing_file_never_becomes_zero_data(self):
        entry = self.add()
        (self.root / entry["path"]).unlink()
        result = self.store().load("rf_b")
        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.data)

    def test_wrong_hash_is_corrupt(self):
        entry = self.add()
        (self.root / entry["path"]).write_text("{}", encoding="utf-8")
        result = self.store().load("rf_b")
        self.assertEqual(result.status, "corrupt")
        self.assertIsNone(result.data)
        self.assertIn("SHA-256", result.message)

    def test_matching_hash_malformed_json_is_corrupt(self):
        entry = self.add()
        target = self.root / entry["path"]
        target.write_bytes(b"{no-json}")
        entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        self.save_registry()
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_unknown_payload_schema_is_unsupported(self):
        data = forest()
        data["schema_version"] = "future-schema"
        self.add(data=data)
        self.assertEqual(self.store().load("rf_b").status, "unsupported")

    def test_missing_required_field_is_corrupt(self):
        data = forest()
        del data["trees"]
        self.add(data=data)
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_unknown_role_is_unavailable(self):
        self.add()
        self.assertEqual(self.store().load("not_registered").status, "unavailable")

    def test_invalid_registry_entry_does_not_crash_status_rows(self):
        self.registry["entries"]["rf_b"] = "not-an-entry"
        self.save_registry()
        self.assertEqual(self.store().status_rows()[0]["status"], "corrupt")

    def test_missing_registry_is_reported(self):
        self.assertEqual(self.store().load("rf_b").status, "unavailable")

    def test_unknown_registry_version_is_unsupported(self):
        self.registry["schema_version"] = "future-registry"
        self.save_registry()
        self.assertEqual(self.store().load("rf_b").status, "unsupported")

    def test_malformed_registry_is_corrupt(self):
        self.registry_path.write_text("bad-json", encoding="utf-8")
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_parent_path_traversal_is_rejected(self):
        self.add(path="results/forest.json")
        self.registry["entries"]["rf_b"]["path"] = "../forest.json"
        self.save_registry()
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_absolute_entry_path_is_rejected(self):
        self.add()
        self.registry["entries"]["rf_b"]["path"] = str(self.root / "results/forest.json")
        self.save_registry()
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_symlink_escape_is_rejected(self):
        entry = self.add()
        target = self.root / entry["path"]
        target.unlink()
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "forest.json"
            outside.write_text(json.dumps(forest()), encoding="utf-8")
            try:
                target.symlink_to(outside)
            except OSError:
                self.skipTest("Symlinks unavailable")
            self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_invalid_hash_pin_is_rejected(self):
        self.add(sha256="")
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_duplicate_json_keys_are_rejected(self):
        entry = self.add()
        target = self.root / entry["path"]
        target.write_bytes(b'{"schema_version":1,"schema_version":2}')
        entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        self.save_registry()
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_non_finite_json_is_rejected(self):
        data = forest()
        data["score_scale"] = float("nan")
        self.add(data=data)
        self.assertEqual(self.store().load("rf_b").status, "corrupt")

    def test_project_root_environment_override(self):
        self.add()
        with patch.dict(os.environ, {"ETC_PROJECT_ROOT": str(self.root)}):
            self.assertTrue(EvidenceStore().load("rf_b").verified)

    def test_registry_environment_override(self):
        self.add()
        with patch.dict(os.environ, {"ETC_DASHBOARD_REGISTRY": str(self.registry_path)}):
            self.assertTrue(EvidenceStore(project_root=self.root).load("rf_b").verified)

    def test_external_root_environment_override(self):
        self.add(root="external")
        self.registry["external_root"] = "/missing/path"
        self.save_registry()
        with patch.dict(os.environ, {"ETC_EXTERNAL_EVIDENCE_ROOT": str(self.root)}):
            self.assertTrue(self.store().load("rf_b").verified)

    def test_no_newest_file_promotion(self):
        self.add()
        other = self.root / "results/newest.json"
        data = forest()
        data["feature_set"] = "C"
        other.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(self.store().load("rf_b").data["feature_set"], "B")

    def test_loading_does_not_modify_files_or_create_outputs(self):
        self.add()
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in self.root.rglob("*") if p.is_file()}
        self.store().load("rf_b")
        self.store().status_rows()
        after = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                 for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_pinned_children_all_verify_and_preserve_null(self):
        self.calibration()
        trials = self.store().calibration_trials()
        self.assertEqual(len(trials), 2)
        self.assertTrue(all(row.verified for row in trials))
        self.assertIsNone(trials[0].data["metrics"]["decisions"])

    def test_child_hash_mismatch_not_overridden_by_parent(self):
        self.calibration()
        child = self.registry["entries"]["raw_calibration"]["children"][0]
        (self.root / child["path"]).write_text("{}", encoding="utf-8")
        trials = self.store().calibration_trials()
        self.assertEqual(trials[0].status, "corrupt")
        self.assertTrue(trials[1].verified)

    def test_parent_not_verified_blocks_child_exposure(self):
        self.calibration()
        parent = self.registry["entries"]["raw_calibration"]
        (self.root / parent["path"]).write_text("{}", encoding="utf-8")
        self.assertTrue(all(row.status == "corrupt" and row.data is None
                            for row in self.store().calibration_trials()))

    def test_malformed_child_with_missing_parent_does_not_crash_status(self):
        self.calibration()
        entry = self.registry["entries"]["raw_calibration"]
        (self.root / entry["path"]).unlink()
        entry["children"] = ["invalid-child"]
        self.save_registry()
        self.assertTrue(all(row["status"] == "unavailable" for row in self.store().status_rows()))

    def test_child_order_must_match_parent(self):
        self.calibration()
        self.registry["entries"]["raw_calibration"]["children"].reverse()
        self.save_registry()
        self.assertEqual(self.store().calibration_trials()[0].status, "corrupt")

    def test_unchecked_arbitrary_child_is_not_loaded(self):
        self.calibration()
        child = self.registry["entries"]["raw_calibration"]["children"][0]
        child["path"] = "results/unrelated/qualified_trial_summary.json"
        self.save_registry()
        result = self.store().calibration_trials()
        self.assertEqual(result[0].status, "corrupt")
        self.assertIsNone(result[0].data)

    def test_child_registry_hash_must_match_parent_seal(self):
        self.calibration()
        self.registry["entries"]["raw_calibration"]["children"][0]["sha256"] = "0" * 64
        self.save_registry()
        self.assertEqual(self.store().calibration_trials()[0].status, "corrupt")

    def test_child_saved_identity_is_checked(self):
        self.calibration()
        child = self.registry["entries"]["raw_calibration"]["children"][0]
        child["identity"]["mode"] = "rf_c"
        self.save_registry()
        self.assertEqual(self.store().calibration_trials()[0].status, "corrupt")

    def test_scientific_failure_is_preserved_not_hidden(self):
        self.calibration()
        entry = self.registry["entries"]["raw_calibration"]
        target = self.root / entry["path"]
        data = json.loads(target.read_text())
        data["raw_rate_qualified"] = False
        data["status"] = "incomplete"
        data["verdicts"] = {"independent_raw_qualification": "INCONCLUSIVE"}
        target.write_text(json.dumps(data), encoding="utf-8")
        entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
        self.save_registry()
        result = self.store().load("raw_calibration")
        self.assertTrue(result.verified)
        self.assertFalse(result.data["raw_rate_qualified"])
        self.assertEqual(result.data["verdicts"]["independent_raw_qualification"], "INCONCLUSIVE")

    def test_native_shape_validates_without_recomputing_metric(self):
        matrix = [[1 if row == column else 0 for column in range(6)] for row in range(6)]
        block = {"accuracy": 1.0, "macro_f1": 1.0, "macro_precision": 1.0,
                 "macro_recall": 1.0, "confusion_matrix": matrix, "records": 6,
                 "class_order": CLASS_ORDER,
                 "per_class": {c: {"precision": 1.0, "recall": 1.0, "f1": 1.0, "support": 1}
                               for c in CLASS_ORDER}}
        data = {"schema_version": 1, "class_order": CLASS_ORDER, "models": {"B": {}, "C": {}},
                "common_paired_population": {"capture_time_metrics_on_same_records": {"B": block, "C": block},
                                             "native_metrics": {"B": block, "C": block},
                                             "records": 6, "coverage": 1.0,
                                             "case_ids": [f"case_{i}" for i in range(6)]},
                "timing_deviation": {}, "clock_quality": {}, "limitations": [],
                "expected_records_per_model": 6, "labels_verified_per_flow": False}
        self.add("native_metrics", data, adapter="native_metrics", schema_value=1)
        result = self.store().load("native_metrics")
        self.assertTrue(result.verified)
        self.assertEqual(result.data, data)

    def test_cli_json_and_exit_code(self):
        self.add()
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--registry", str(self.registry_path), "--project-root", str(self.root), "--json"])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["read_only"])
        self.assertEqual(result["evidence"][0]["status"], "verified")

    def test_cli_failure_exit_code(self):
        self.add(sha256="0" * 64)
        with redirect_stdout(io.StringIO()):
            code = main(["--registry", str(self.registry_path), "--project-root", str(self.root)])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
