#!/usr/bin/env python3
"""Offline tests only; every synthetic run exists in a TemporaryDirectory.

These fixtures are statistical/integrity test inputs, not benchmark evidence.
No socket, live interface, real model, or existing run is used or modified.
"""

import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import analyze_performance_benchmark as analysis


def synthetic_trial(mode="rf_b", workload="classification-heavy", *, block="block-1",
                    rate=5000, repetition=1, valid=True, failures=None, metrics=None):
    """Clearly synthetic, internally complete test-only trial summary."""
    measured = {
        "offered_pps": rate, "received_pps": rate,
        "ethernet_mbps": rate * 128 * 8 / 1_000_000, "loss_fraction": 0,
        "packets_sent": rate * 10, "packets_received": rate * 10,
        "packets_lost": 0, "packets_duplicated": 0, "packets_reordered": 0,
        "delay_min_us": 10, "delay_mean_us": 30, "delay_median_us": 25,
        "delay_p95_us": 50, "delay_p99_us": 70, "delay_max_us": 100,
        "bmv2_cpu_one_core_percent": 20, "bmv2_cpu_seconds": 2,
        "bmv2_rss_peak_mib": 32, "bmv2_hwm_mib": 36,
        "runner_cpu_one_core_percent": 40, "runner_cpu_seconds": 4,
        "decisions": rate * 10 if mode in ("rf_b", "rf_c") else None,
        "decision_rate_pps": rate if mode in ("rf_b", "rf_c") else None,
        "pacing_valid": True, "clock_valid": True,
        "output_kernel_interarrival_pps": rate,
    }
    measured.update(metrics or {})
    return {"fixture_kind": "TEST-ONLY SYNTHETIC; NOT BENCHMARK EVIDENCE",
            "trial_directory": "test-only-placeholder", "mode": mode, "workload": workload,
            "rate_pps": rate, "repetition": repetition, "block_id": block,
            "valid": valid, "failures": failures if failures is not None else [],
            "metrics": measured, "data_warnings": []}


class SyntheticRun:
    """Fixture writer restricted to its caller's temporary test directory."""
    def __init__(self, parent: Path, trials: list[dict], rates=None):
        self.root = parent / "TEST-ONLY-synthetic-raw-run"
        self.root.mkdir()
        self.summary = {"schema_version": analysis.SCHEMA_VERSION,
            "status": "TEST-ONLY-SYNTHETIC-NOT-BENCHMARK-EVIDENCE",
            "prepared_directory": "TEST-ONLY-NO-PREPARED-MODELS",
            "protocol": {"rates_pps": rates or [5000], "duration_seconds": 10,
                         "warmup_seconds": 1, "repetitions": 5, "seed": 731},
            "trials": [], "artifact_hashes": {}}
        marker = self.root / "TEST-ONLY.txt"
        marker.write_text("SYNTHETIC UNIT TEST FIXTURE, NOT PERFORMANCE EVIDENCE.\n", encoding="utf-8")
        self.summary["artifact_hashes"][marker.name] = analysis._sha256(marker)
        for index, trial in enumerate(trials, 1):
            name = f"test-only-trial-{index:04d}"
            folder = self.root / name
            folder.mkdir()
            artifact = folder / "trial_summary.json"
            artifact.write_text(json.dumps(trial, indent=2), encoding="utf-8")
            self.summary["trials"].append(name)
            self.summary["artifact_hashes"][f"{name}/trial_summary.json"] = analysis._sha256(artifact)
        self.commit_summary()

    def commit_summary(self):
        (self.root / "summary.json").write_text(json.dumps(self.summary, indent=2), encoding="utf-8")


class TrialStatisticsTests(unittest.TestCase):
    def test_zero_and_one_trial(self):
        empty = analysis.summarize_trials([], seed=5, bootstrap_samples=200)
        self.assertEqual(empty["n_metric"], 0)
        self.assertTrue(empty["exploratory"])
        self.assertIsNone(empty["mean"])
        self.assertIsNone(empty["mean_ci95_low"])
        single = analysis.summarize_trials([7], seed=5, bootstrap_samples=200)
        self.assertEqual(single["mean"], 7)
        self.assertEqual(single["median_ci95_low"], 7)
        self.assertEqual(single["mean_ci95_high"], 7)
        self.assertIsNone(single["std"])
        self.assertTrue(single["exploratory"])

    def test_nonfinite_and_boolean_values_do_not_enter_statistics(self):
        result = analysis.summarize_trials([None, float("nan"), float("inf"), -float("inf"), True, "5", 2, 4],
                                          seed=5, bootstrap_samples=100)
        self.assertEqual(result["n_metric"], 2)
        self.assertEqual(result["mean"], 3)
        self.assertAlmostEqual(result["std"], 2 ** .5)

    def test_bootstrap_is_reproducible_and_five_trial_result_not_exploratory(self):
        values = [1, 2, 3, 4, 20]
        first = analysis.summarize_trials(values, seed=101, bootstrap_samples=1000)
        second = analysis.summarize_trials(values, seed=101, bootstrap_samples=1000)
        self.assertEqual(first, second)
        self.assertFalse(first["exploratory"])
        self.assertLess(first["mean_ci95_low"], first["mean"])
        self.assertGreater(first["mean_ci95_high"], first["mean"])
        self.assertEqual(first["median"], 3)

    def test_bootstrap_uses_trials_not_packet_observations(self):
        trials = [synthetic_trial(block="b1", metrics={"delay_p99_us": 20, "packets_sent": 100}),
                  synthetic_trial(block="b2", metrics={"delay_p99_us": 100, "packets_sent": 1_000_000})]
        groups = analysis.aggregate_groups(trials, {"rates_pps": [5000], "seed": 12}, bootstrap_samples=300)
        group = next(group for group in groups if group["mode"] == "rf_b" and group["workload"] == "classification-heavy")
        self.assertEqual(group["metrics"]["delay_p99_us"]["n_metric"], 2)
        self.assertEqual(group["metrics"]["delay_p99_us"]["mean"], 60)

    def test_zero_groups_exist_and_invalid_trials_remain_in_attempted_count(self):
        rows = [synthetic_trial(block="b1"), synthetic_trial(block="b2", valid=False,
                 failures=["Capture drops"], metrics={"received_pps": 12345})]
        groups = analysis.aggregate_groups(rows, {"rates_pps": [5000], "seed": 2}, bootstrap_samples=200)
        self.assertEqual(len(groups), 8)
        selected = next(group for group in groups if group["mode"] == "rf_b" and group["workload"] == "classification-heavy")
        self.assertEqual((selected["n_attempted"], selected["n_valid"]), (2, 1))
        self.assertEqual(selected["metrics"]["received_pps"]["mean"], 5000)
        empty = next(group for group in groups if group["mode"] == "forwarding")
        self.assertEqual(empty["n_valid"], 0)
        self.assertIsNone(empty["metrics"]["received_pps"]["mean"])

    def test_trustworthy_observed_capacity_loss_is_not_excluded(self):
        rows = [synthetic_trial(metrics={"received_pps": 4000, "loss_fraction": .2,
                                        "packets_lost": 10000, "packets_received": 40000})]
        groups = analysis.aggregate_groups(rows, {"rates_pps": [5000], "seed": 2}, bootstrap_samples=100)
        group = next(group for group in groups if group["mode"] == "rf_b" and group["workload"] == "classification-heavy")
        self.assertEqual(group["n_valid"], 1)
        self.assertEqual(group["metrics"]["loss_fraction"]["mean"], .2)

    def test_bad_bootstrap_count_rejected(self):
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                analysis.summarize_trials([1], seed=2, bootstrap_samples=value)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="test-only-performance-benchmark-")
        self.parent = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_load_empty_and_single_run(self):
        fixture = SyntheticRun(self.parent, [])
        summary, rows = analysis.load_run(fixture.root)
        self.assertEqual(rows, [])
        self.assertEqual(summary["schema_version"], analysis.SCHEMA_VERSION)

    def test_tampering_fails_before_output_creation(self):
        fixture = SyntheticRun(self.parent, [synthetic_trial()])
        path = fixture.root / fixture.summary["trials"][0] / "trial_summary.json"
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        output_root = self.parent / "analysis-output"
        with self.assertRaisesRegex(analysis.BenchmarkAnalysisError, "SHA256 mismatch"):
            analysis.analyze_run(fixture.root, output_root, bootstrap_samples=100)
        self.assertFalse(output_root.exists())

    def test_undeclared_trial_summary_rejected(self):
        fixture = SyntheticRun(self.parent, [synthetic_trial()])
        name = f"{fixture.summary['trials'][0]}/trial_summary.json"
        del fixture.summary["artifact_hashes"][name]
        fixture.commit_summary()
        with self.assertRaisesRegex(analysis.BenchmarkAnalysisError, "not hash-declared"):
            analysis.load_run(fixture.root)

    def test_traversal_absolute_drive_backslash_and_symlink_paths_rejected(self):
        fixture = SyntheticRun(self.parent, [])
        outside = self.parent / "outside.txt"
        outside.write_text("test-only", encoding="utf-8")
        for unsafe in ("../outside.txt", "/outside.txt", "C:/outside.txt", "a\\b", "a/./b", "a//b"):
            fixture.summary["artifact_hashes"] = {unsafe: hashlib.sha256(b"test-only").hexdigest()}
            fixture.commit_summary()
            with self.subTest(path=unsafe), self.assertRaises(analysis.BenchmarkAnalysisError):
                analysis.load_run(fixture.root)
        link = fixture.root / "outside-link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Host cannot create test-only symlink")
        fixture.summary["artifact_hashes"] = {link.name: analysis._sha256(outside)}
        fixture.commit_summary()
        with self.assertRaisesRegex(analysis.BenchmarkAnalysisError, "Symlink"):
            analysis.load_run(fixture.root)

    def test_output_cannot_be_raw_run_or_descendant(self):
        fixture = SyntheticRun(self.parent, [])
        for output in (fixture.root, fixture.root / "analysis"):
            with self.subTest(output=output), self.assertRaisesRegex(analysis.BenchmarkAnalysisError, "outside the raw run"):
                analysis.analyze_run(fixture.root, output, bootstrap_samples=100)

    def test_nan_metric_and_invalid_clock_are_masked_only_per_metric(self):
        fixture = SyntheticRun(self.parent, [synthetic_trial(metrics={"bmv2_hwm_mib": float("nan"),
                      "clock_valid": False, "delay_p99_us": 42, "output_kernel_interarrival_pps": 5000})])
        _, rows = analysis.load_run(fixture.root)
        self.assertTrue(rows[0]["valid"])
        self.assertIsNone(rows[0]["metrics"]["bmv2_hwm_mib"])
        self.assertIsNone(rows[0]["metrics"]["delay_p99_us"])
        self.assertIsNone(rows[0]["metrics"]["output_kernel_interarrival_pps"])
        self.assertTrue(rows[0]["data_warnings"])
        self.assertEqual(rows[0]["metrics"]["received_pps"], 5000)

    def test_duplicate_pair_mode_and_malformed_schema_rejected(self):
        fixture = SyntheticRun(self.parent, [synthetic_trial(), synthetic_trial()])
        with self.assertRaisesRegex(analysis.BenchmarkAnalysisError, "Duplicate mode"):
            analysis.load_run(fixture.root)
        fixture.summary["trials"] = [{"bad": "not a string"}]
        fixture.commit_summary()
        with self.assertRaises(analysis.BenchmarkAnalysisError):
            analysis.load_run(fixture.root)


class PairingTests(unittest.TestCase):
    def test_exact_blocks_both_valid_and_metric_specific_denominators(self):
        rows = [synthetic_trial("rf_b", block="b1", metrics={"bmv2_cpu_one_core_percent": 20}),
                synthetic_trial("rf_c", block="b1", metrics={"bmv2_cpu_one_core_percent": 30}),
                synthetic_trial("rf_b", block="b2", metrics={"bmv2_cpu_one_core_percent": 50}),
                synthetic_trial("rf_c", block="b2", metrics={"bmv2_cpu_one_core_percent": 40,
                                                             "delay_p99_us": None}),
                synthetic_trial("rf_b", block="b3"),
                synthetic_trial("rf_c", block="b3", valid=False, failures=["Invalid pacing"]),
                synthetic_trial("rf_b", block="unmatched-b"),
                synthetic_trial("rf_c", block="unmatched-c")]
        pairs = analysis.paired_comparisons(rows, {"rates_pps": [5000], "seed": 100}, bootstrap_samples=500)
        selected = pairs[0]
        self.assertEqual(selected["n_attempted_blocks"], 5)
        self.assertEqual(selected["n_valid_pairs"], 2)
        self.assertEqual(selected["n_excluded_blocks"], 3)
        absolute = selected["metrics"]["bmv2_cpu_one_core_percent"]["absolute_c_minus_b"]
        percent = selected["metrics"]["bmv2_cpu_one_core_percent"]["percent_c_minus_b_over_b"]
        self.assertEqual(absolute["n_metric"], 2)
        self.assertEqual(absolute["mean"], 0)
        self.assertEqual(percent["mean"], 15)  # mean of +50% and -20%, not change of means
        self.assertEqual(selected["metrics"]["delay_p99_us"]["absolute_c_minus_b"]["n_metric"], 1)
        self.assertEqual(pairs, analysis.paired_comparisons(rows, {"rates_pps": [5000], "seed": 100}, bootstrap_samples=500))

    def test_zero_baseline_excludes_only_percentage_and_workload_rate_do_not_cross_pair(self):
        rows = [synthetic_trial("rf_b", metrics={"bmv2_cpu_one_core_percent": 0}),
                synthetic_trial("rf_c", metrics={"bmv2_cpu_one_core_percent": 2}),
                synthetic_trial("rf_b", workload="cached-forwarding", block="other"),
                synthetic_trial("rf_c", rate=1000, block="other")]
        pairs = analysis.paired_comparisons(rows, {"rates_pps": [1000, 5000], "seed": 7}, bootstrap_samples=100)
        selected = next(pair for pair in pairs if pair["workload"] == "classification-heavy" and pair["rate_pps"] == 5000)
        stats = selected["metrics"]["bmv2_cpu_one_core_percent"]
        self.assertEqual(stats["absolute_c_minus_b"]["n_metric"], 1)
        self.assertEqual(stats["absolute_c_minus_b"]["mean"], 2)
        self.assertEqual(stats["percent_c_minus_b_over_b"]["n_metric"], 0)
        self.assertIsNone(stats["percent_c_minus_b_over_b"]["mean"])
        self.assertEqual(sum(pair["n_valid_pairs"] for pair in pairs), 1)


class ExtensionTests(unittest.TestCase):
    @staticmethod
    def full_rows():
        return [synthetic_trial(mode, workload, block=f"block-{repetition}", repetition=repetition)
                for workload in analysis.WORKLOADS for mode in analysis.MODES for repetition in range(1, 6)]

    def test_requires_five_valid_trials_for_every_mode_and_workload(self):
        rows = self.full_rows()
        result = analysis.extension_eligibility(rows)
        self.assertTrue(result["eligible"])
        self.assertFalse(result["automated_extension"])
        self.assertFalse(analysis.extension_eligibility(rows[1:])["eligible"])
        self.assertFalse(analysis.extension_eligibility([])["eligible"])
        rows[0]["valid"] = False
        self.assertFalse(analysis.extension_eligibility(rows)["eligible"])

    def test_loss_duplication_reordering_throughput_pacing_clock_each_prevents_extension(self):
        for metric, value in (("loss_fraction", .001), ("packets_lost", 1),
                              ("packets_duplicated", 1), ("packets_reordered", 1),
                              ("received_pps", 4899), ("pacing_valid", False),
                              ("clock_valid", False), ("received_pps", None)):
            rows = self.full_rows()
            rows[0]["metrics"][metric] = value
            with self.subTest(metric=metric):
                self.assertFalse(analysis.extension_eligibility(rows)["eligible"])

    def test_exact_98_percent_boundary_and_low_cpu_not_saturation_proof(self):
        rows = self.full_rows()
        for row in rows:
            row["metrics"]["received_pps"] = 4900
            row["metrics"]["bmv2_cpu_one_core_percent"] = 0
        result = analysis.extension_eligibility(rows)
        self.assertTrue(result["eligible"])
        self.assertIn("not proof of saturation", result["meaning"])
        rows[0]["metrics"]["packets_lost"] = 1
        self.assertFalse(analysis.extension_eligibility(rows)["eligible"])

    def test_only_initial_5000_rate_can_establish_eligibility(self):
        rows = self.full_rows()
        for row in rows:
            row["rate_pps"] = 1000
        self.assertFalse(analysis.extension_eligibility(rows)["eligible"])

    def test_recorded_failed_trial_is_not_hidden_by_successful_repetitions(self):
        rows = self.full_rows()
        rows.append(synthetic_trial(block="extra-invalid", valid=False,
                    failures=["Invalid pacing"], metrics={"pacing_valid": False}))
        self.assertFalse(analysis.extension_eligibility(rows)["eligible"])


class ArtifactTests(unittest.TestCase):
    def test_creates_complete_new_analysis_with_300_dpi_pngs_and_pdfs_without_changing_raw_run(self):
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            self.skipTest("Matplotlib is required for the standalone static artifact test")
        with tempfile.TemporaryDirectory(prefix="test-only-performance-benchmark-") as temporary:
            parent = Path(temporary)
            rows = [synthetic_trial("rf_b"), synthetic_trial("rf_c", metrics={"delay_p99_us": 80}),
                    synthetic_trial("forwarding", workload="cached-forwarding", block="bad", valid=False,
                                    failures=["Test-only capture drop"], metrics={"delay_p99_us": None})]
            fixture = SyntheticRun(parent, rows)
            before = {path.relative_to(fixture.root).as_posix(): analysis._sha256(path)
                      for path in fixture.root.rglob("*") if path.is_file()}
            output = analysis.analyze_run(fixture.root, parent / "TEST-ONLY-analysis-output", bootstrap_samples=100)
            payload = json.loads((output / "analysis.json").read_text(encoding="utf-8"))
            self.assertIn("TEST-ONLY", payload["run_status"])
            self.assertEqual(payload["bootstrap"]["unit"], "trial or within-block paired trial difference")
            self.assertEqual(len(payload["trials"]), 3)
            self.assertEqual(len(payload["figure_artifacts"]), 12)
            for artifact in payload["figure_artifacts"]:
                self.assertGreater((output / artifact).stat().st_size, 100)
                if artifact.endswith(".png"):
                    from PIL import Image
                    with Image.open(output / artifact) as picture:
                        self.assertAlmostEqual(picture.info["dpi"][0], 300, delta=1)
                else:
                    self.assertTrue((output / artifact).read_bytes().startswith(b"%PDF"))
            for name in ("per_trial.csv", "group_statistics.csv", "paired_statistics.csv", "invalid_trials.csv", "report.md"):
                self.assertTrue((output / name).is_file())
            with (output / "invalid_trials.csv").open(encoding="utf-8", newline="") as handle:
                invalid = list(csv.DictReader(handle))
            self.assertEqual(len(invalid), 1)
            self.assertIn("Test-only capture drop", invalid[0]["failures"])
            report = (output / "report.md").read_text(encoding="utf-8")
            for important in ("not an ASIC", "Both RF modes perform direction extraction", "n_metric",
                              "n<2", "fewer than five", "overstate throughput", "No extension is automated"):
                self.assertIn(important, report)
            after = {path.relative_to(fixture.root).as_posix(): analysis._sha256(path)
                     for path in fixture.root.rglob("*") if path.is_file()}
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
