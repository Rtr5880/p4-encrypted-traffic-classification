"""Synthetic report fixtures only: no privileged run or clock audit."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import analyze_raw_performance as analysis


def row(value=100, valid=True):
    return dict(mode="rf_c", workload="classification-heavy", rate_pps=100,
        repetition=0, block_id="block_0", valid=valid, failures=[] if valid else ["pacing failed"],
        metric_validity=dict(offered_load=valid, delivered_throughput=valid,
            packet_accounting=True, classification_rate=True, resources=True,
            kernel_forwarding_latency=False),
        metrics={metric: value for metric in analysis.METRIC_GATES})


def fixture(root, rows):
    hashes, trials = {}, []
    for index, trial in enumerate(rows):
        name = f"trial_{index}"
        folder = root / name
        folder.mkdir()
        path = folder / "trial_summary.json"
        path.write_text(json.dumps(trial))
        hashes[f"{name}/trial_summary.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
        trials.append(name)
    summary = dict(schema_version=analysis.SCHEMA_VERSION,
        clock_rate_qualification=dict(status="inconclusive"),
        artifact_hashes=hashes, trials=trials)
    (root / "summary.json").write_text(json.dumps(summary))
    return summary


def v3_row(value=100, mode="rf_c", warning=False):
    trial = row(value)
    trial["mode"] = mode
    trial["warnings"] = ["Preserved warm-up upper-bound lateness warning"] if warning else []
    trial["verdicts"] = {
        "measurement_integrity": {"status": "PASS", "failures": []},
        "independent_raw_qualification": {"status": "PASS"},
        "sender_pacing_conformance": {"status": "WARNING" if warning else "PASS",
            "warmup": {"status": "WARNING" if warning else "PASS",
                       "warnings": ["Maximum completion upper bound exceeded unchanged threshold"] if warning else []},
            "measurement": {"status": "PASS", "warnings": []}}}
    return trial


def fixture_v3(root, rows, qualified=True):
    summary = fixture(root, rows)
    summary.update(schema_version=analysis.V3_SCHEMA,
        local_trial_summary_file="trial_summary.json",
        qualified_trial_summary_file="qualified_trial_summary.json",
        raw_rate_qualified=qualified,
        clock_rate_qualification={"status": "PASS" if qualified else "INCONCLUSIVE", "passed": qualified})
    for index, trial in enumerate(rows):
        prefix = f"trial_{index}"
        qualified_path = root / prefix / "qualified_trial_summary.json"
        qualified_path.write_text(json.dumps(trial))
        summary["artifact_hashes"][f"{prefix}/qualified_trial_summary.json"] = hashlib.sha256(qualified_path.read_bytes()).hexdigest()
        for phase in ("warmup", "measurement"):
            phase_name = "warmup_measurement.json" if phase == "warmup" else "measurement.json"
            warned = trial["verdicts"]["sender_pacing_conformance"][phase]["status"] == "WARNING"
            pacing = dict(valid=not warned, reasons=["Upper-bound scheduling disturbance"] if warned else [],
                send_lateness_summary_ns={"median": 50000, "p99": 200000, "maximum": 500000},
                send_completion_lateness_summary_ns={"median": 60000, "p99": 300000,
                                                     "maximum": 5113093 if warned else 600000},
                sender_interpacket_gap_summary_ns={"median": 10000000, "p99": 10200000, "maximum": 15000000},
                sender_short_gap_fraction=.0008, maximum_send_lateness_limit_ns=5000000,
                p99_send_lateness_limit_ns=1000000, send_completion_lateness_ns=[100, 5113093] if warned else [100])
            phase_path = root / prefix / phase_name
            phase_path.write_text(json.dumps({"pacing_quality": pacing,
                "capture_statistics": {"input": {"socket_drops": 0}, "output": {"socket_drops": 0}}}))
            summary["artifact_hashes"][f"{prefix}/{phase_name}"] = hashlib.sha256(phase_path.read_bytes()).hexdigest()
    (root / "summary.json").write_text(json.dumps(summary))
    return summary


def fixture_v4(root, rows, *, qualified=True, partial=False, partial_directory=True):
    """Sealed v4 attempt receipts; partial attempts have no invented row."""
    summary = fixture_v3(root, rows, qualified=qualified)
    summary["schema_version"] = analysis.V4_SCHEMA
    summary.update(attempts=[], partial_trials=[], completed_trials=len(rows))
    (root / "attempts").mkdir()
    identities = [(name, trial, "completed") for name, trial in zip(summary["trials"], rows)]
    if partial:
        name = "partial_trial"
        trial = v3_row(mode="rf_b")
        trial["rate_pps"] = 5000
        identities.append((name, trial, "exception"))
        summary["partial_trials"].append(name)
        if partial_directory:
            (root / name).mkdir()
            path = root / name / "partial_measurement.json"
            path.write_text(json.dumps({"diagnostic_only": True, "raw_observations": [1, 2, 3]}))
            summary["artifact_hashes"][f"{name}/partial_measurement.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    for ordinal, (name, trial, status) in enumerate(identities, 1):
        attempt = dict(ordinal=ordinal, trial_directory=name, mode=trial["mode"],
            workload=trial["workload"], rate_pps=trial["rate_pps"], block_id=trial["block_id"],
            status=status, start_receipt=f"attempts/attempt_{ordinal:03d}_start.json",
            result_receipt=f"attempts/attempt_{ordinal:03d}_result.json")
        for key in ("start_receipt", "result_receipt"):
            payload = dict(attempt)
            if key == "result_receipt":
                payload["trial_directory_exists"] = (root / name).is_dir()
                if status == "exception":
                    payload["error"] = "Synthetic callback failure; partial evidence retained"
            path = root / attempt[key]
            path.write_text(json.dumps(payload))
            summary["artifact_hashes"][attempt[key]] = hashlib.sha256(path.read_bytes()).hexdigest()
        summary["attempts"].append(attempt)
    summary["attempted_trials"] = len(identities)
    (root / "summary.json").write_text(json.dumps(summary))
    return summary


def v5_schedule():
    return [dict(block_id=f"block_{index:02d}", rate_pps=rate, workload=workload,
        repetition=repeat, modes=list(analysis.MODES))
        for index, (rate, workload, repeat) in enumerate(
            (rate, workload, repeat) for rate in (100, 250, 500, 1000)
            for workload in analysis.WORKLOADS for repeat in range(1, 6))]


def v5_rows(count=160, warning_indices=(), invalid_indices=()):
    rows = []
    for index in range(count):
        block = v5_schedule()[index // 4]
        trial = v3_row(block["rate_pps"] + index % 4 * .01, mode=analysis.MODES[index % 4],
                       warning=index in warning_indices)
        trial.update({key: block[key] for key in ("block_id", "rate_pps", "workload", "repetition")})
        trial["metrics"].update(packets_sent=2000, packets_received=2000, packets_lost=0,
            loss_fraction=0, decisions=25 if trial["mode"].startswith("rf_") else None,
            decision_rate_pps=1.25 if trial["mode"].startswith("rf_") else None,
            bmv2_cpu_one_core_percent=10 + index % 4, bmv2_rss_peak_mib=100 + index % 4)
        if index in invalid_indices:
            trial.update(valid=False, failures=["raw_clock_sample_gap_over_25ms"])
            trial["verdicts"]["measurement_integrity"] = {"status": "FAIL"}
            trial["metric_validity"].update(offered_load=False, delivered_throughput=False, cpu=False,
                cpu_accounting=True, memory=True, classification_counts=True)
        rows.append(trial)
    return rows


def fixture_v5(root, rows, *, qualified=True, partial=False):
    summary = fixture_v4(root, rows, qualified=qualified, partial=partial)
    summary.update(schema_version=analysis.V5_SCHEMA, expected_trials=160,
        protocol=dict(rates_pps=[100, 250, 500, 1000], repetitions=5,
                      duration_seconds=20, warmup_seconds=5), schedule_file="schedule.json",
        status="raw_benchmark_passed" if len(rows) == 160 else "raw_benchmark_incomplete",
        passed=len(rows) == 160)
    schedule = v5_schedule()
    path = root / "schedule.json"
    path.write_text(json.dumps({"schema_version": analysis.V5_SCHEMA, "schedule": schedule}))
    summary["artifact_hashes"]["schedule.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    for index, attempt in enumerate(summary["attempts"]):
        block = schedule[index // 4]
        attempt.update({key: block[key] for key in ("block_id", "rate_pps", "workload", "repetition")})
        attempt["mode"] = analysis.MODES[index % 4]
        for key in ("start_receipt", "result_receipt"):
            path = root / attempt[key]
            payload = json.loads(path.read_text())
            payload.update(attempt)
            path.write_text(json.dumps(payload))
            summary["artifact_hashes"][attempt[key]] = hashlib.sha256(path.read_bytes()).hexdigest()
    for index, trial in enumerate(rows):
        for name, payload in (("counter_check.json", {"expected_packets": 25,
            "packets": trial["metrics"]["decisions"]}), ("resources.json", {"runner": {"memory": {
                "rss_max_sampled_mib": 200, "vmhwm_lifetime_mib": 250}}})):
            path = root / f"trial_{index}" / name
            path.write_text(json.dumps(payload))
            summary["artifact_hashes"][f"trial_{index}/{name}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (root / "summary.json").write_text(json.dumps(summary))
    return summary


class AnalysisTests(unittest.TestCase):
    def test_invalid_throughput_not_pooled_valid_resources_retained(self):
        first, second = row(100), row(10000, False)
        values = analysis.aggregate([first, second])[0]["metrics"]
        self.assertEqual(values["delivered_pps"]["median"], 100)
        self.assertEqual(values["delivered_pps"]["valid_trials"], 1)
        self.assertEqual(values["bmv2_cpu_seconds"]["valid_trials"], 2)
        self.assertEqual(values["bmv2_cpu_seconds"]["median"], 5050)
        self.assertIsNone(values["delivered_pps"]["confidence_interval"])
        self.assertIn("Single trial", values["delivered_pps"]["interpretation"])

    def test_missing_nonnumeric_values_not_zero(self):
        trial = row()
        trial["metrics"]["offered_pps"] = None
        trial["metrics"]["delivered_pps"] = float("nan")
        values = analysis.aggregate([trial])[0]["metrics"]
        self.assertEqual(values["offered_pps"]["valid_trials"], 0)
        self.assertIsNone(values["offered_pps"]["median"])
        self.assertIsNone(values["delivered_pps"]["median"])

    def test_unqualified_absolute_rates_and_cpu_percent_not_pooled(self):
        values = analysis.aggregate([row()], raw_rate_qualified=False)[0]["metrics"]
        for metric in analysis.RATE_QUALIFIED_METRICS:
            self.assertIsNone(values[metric]["median"])
            self.assertEqual(values[metric]["valid_trials"], 0)
        self.assertEqual(values["packets_received"]["median"], 100)
        self.assertEqual(values["bmv2_cpu_seconds"]["median"], 100)
        self.assertEqual(values["bmv2_rss_peak_mib"]["median"], 100)

    def test_qualification_requires_run_and_independent_pass(self):
        self.assertFalse(analysis._rate_qualification({"raw_rate_qualified": True}))
        self.assertFalse(analysis._rate_qualification({"raw_rate_qualified": True,
            "clock_rate_qualification": {"passed": False}}))
        self.assertFalse(analysis._rate_qualification({"raw_rate_qualified": False,
            "clock_rate_qualification": {"passed": True}}))
        self.assertTrue(analysis._rate_qualification({"raw_rate_qualified": True,
            "clock_rate_qualification": {"passed": True}}))

    def test_memory_valid_when_cpu_gate_fails(self):
        trial = row()
        trial["metric_validity"].update(cpu=False, memory=True)
        values = analysis.aggregate([trial])[0]["metrics"]
        self.assertIsNone(values["bmv2_cpu_seconds"]["median"])
        self.assertEqual(values["bmv2_rss_peak_mib"]["median"], 100)

    def test_seals_checked_analysis_is_exclusive_and_originals_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root, [row()])
            originals = {path: path.read_bytes() for path in root.rglob("*.json")}
            with patch.object(analysis, "_plot", return_value={"status": "disabled for unit test"}):
                first = analysis.analyze(root)
                second = analysis.analyze(root)
            self.assertNotEqual(first, second)
            for path, payload in originals.items():
                self.assertEqual(path.read_bytes(), payload)
            report = json.loads((first / "report.json").read_text())
            self.assertFalse(report["kernel_forwarding_latency_qualified"])
            self.assertEqual(report["clock_rate_qualification"]["status"], "inconclusive")
            self.assertNotIn("delay_p95_us", report["aggregates"][0]["metrics"])

    def test_tampering_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root, [row()])
            (root / "trial_0" / "trial_summary.json").write_text("{}")
            with self.assertRaisesRegex(analysis.RawAnalysisError, "SHA256 mismatch"):
                analysis.analyze(root)
            self.assertFalse(list(root.glob("analysis_*")))

    def test_protocol_cannot_claim_kernel_latency(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            trial = row()
            trial["metric_validity"]["kernel_forwarding_latency"] = True
            fixture(root, [trial])
            with self.assertRaisesRegex(analysis.RawAnalysisError, "cannot qualify"):
                analysis.verify_run(root)

    def test_v2_reads_qualified_summary_and_seals_immutable_local_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payload = fixture(root, [row()])
            final = row(valid=False)
            final['failures'] = ['Independent qualification inconclusive']
            path = root / 'trial_0' / 'qualified_trial_summary.json'
            path.write_text(json.dumps(final))
            payload.update(schema_version='raw-performance-calibration-v2',
                local_trial_summary_file='trial_summary.json',
                qualified_trial_summary_file='qualified_trial_summary.json')
            payload['artifact_hashes']['trial_0/qualified_trial_summary.json'] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / 'summary.json').write_text(json.dumps(payload))
            _, _, rows, _ = analysis.verify_run(root)
            self.assertFalse(rows[0]['valid'])
            self.assertEqual(rows[0]['failures'], final['failures'])
            payload['artifact_hashes'].pop('trial_0/trial_summary.json')
            (root / 'summary.json').write_text(json.dumps(payload))
            with self.assertRaisesRegex(analysis.RawAnalysisError, 'Unsealed immutable local summary'):
                analysis.verify_run(root)

    def test_v2_cannot_select_local_summary_as_qualified_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payload = fixture(root, [row()])
            payload.update(schema_version='raw-performance-calibration-v2',
                           local_trial_summary_file='trial_summary.json',
                           qualified_trial_summary_file='trial_summary.json')
            (root / 'summary.json').write_text(json.dumps(payload))
            with self.assertRaisesRegex(analysis.RawAnalysisError, 'distinct immutable'):
                analysis.verify_run(root)

    def test_v3_warning_retains_qualified_average_rates_and_warmup_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture_v3(root, [v3_row(99.99, warning=True)])
            originals = {path: path.read_bytes() for path in root.rglob("*.json")}
            with patch.object(analysis, "_plot", return_value={"status": "disabled for unit test"}):
                output = analysis.analyze(root)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["aggregates"][0]["metrics"]["offered_pps"]["median"], 99.99)
            self.assertEqual(report["aggregates"][0]["pacing_warning_trials"], 1)
            self.assertEqual(report["pacing_warning_trials"], ["trial_0"])
            self.assertEqual(report["trials"][0]["pacing_distributions"]["warmup"]
                ["send_completion_lateness_summary_ns"]["maximum"], 5113093)
            self.assertEqual(report["trials"][0]["warnings"], ["Preserved warm-up upper-bound lateness warning"])
            markdown = (output / "report.md").read_text(encoding="utf-8")
            self.assertIn("VALID — PACING WARNING", markdown)
            self.assertIn("not validated scientific boundaries", markdown)
            self.assertIn("5.113", markdown)
            self.assertIn("not validated forwarding-delay percentiles", markdown)
            self.assertFalse(report["kernel_forwarding_latency_qualified"])
            for path, original in originals.items():
                self.assertEqual(path.read_bytes(), original)

    def test_v3_unknown_qualification_withholds_rates_but_keeps_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            trial = v3_row(warning=True)
            trial["verdicts"]["independent_raw_qualification"]["status"] = "INCONCLUSIVE"
            fixture_v3(root, [trial], qualified=False)
            with patch.object(analysis, "_plot", return_value={}):
                output = analysis.analyze(root)
            report = json.loads((output / "report.json").read_text())
            self.assertIsNone(report["aggregates"][0]["metrics"]["offered_pps"]["median"])
            self.assertEqual(report["aggregates"][0]["metrics"]["packets_received"]["median"], 100)
            self.assertEqual(report["comparison_screens"][0]["status"], "NOT QUALIFIED")

    def test_v3_inconclusive_row_cannot_inherit_qualified_rates_from_global_flag(self):
        trial = v3_row()
        trial["verdicts"]["independent_raw_qualification"]["status"] = "INCONCLUSIVE"
        values = analysis.aggregate([trial], raw_rate_qualified=True)[0]["metrics"]
        self.assertIsNone(values["offered_pps"]["median"])
        self.assertEqual(values["packets_received"]["median"], 100)

    def test_v3_all_modes_close_loads_still_disclose_pacing_and_no_equivalence(self):
        rows = [v3_row(value, mode=mode, warning=mode == "rf_b")
                for mode, value in zip(analysis.MODES, (100, 100.1, 99.9, 100))]
        screens = analysis.comparison_screen(rows, True)
        self.assertEqual(screens[0]["status"], "LOAD SCREEN PASS")
        self.assertAlmostEqual(screens[0]["normalized_achieved_load_spread"], .002)
        self.assertEqual(screens[0]["pacing_warning_trials"], ["rf_b"])
        self.assertFalse(screens[0]["uniform_load_claim_qualified"])
        self.assertFalse(screens[0]["saturation_claim_qualified"])

    def test_v3_missing_mode_and_mismatched_achieved_loads_flagged(self):
        rows = [v3_row(value, mode=mode) for mode, value in zip(analysis.MODES, (100, 100, 100, 95))]
        self.assertEqual(analysis.comparison_screen(rows, True)[0]["status"], "LOAD MISMATCH WARNING")
        self.assertEqual(analysis.comparison_screen(rows[:3], True)[0]["status"], "NOT QUALIFIED")
        self.assertEqual(analysis.comparison_screen(rows, False)[0]["status"], "NOT QUALIFIED")
        rows[0]["metric_validity"]["offered_load"] = False
        self.assertEqual(analysis.comparison_screen(rows, True)[0]["status"], "NOT QUALIFIED")

    def test_v3_phase_evidence_must_be_sealed_and_verdicts_explicit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            summary = fixture_v3(root, [v3_row()])
            summary["artifact_hashes"].pop("trial_0/warmup_measurement.json")
            (root / "summary.json").write_text(json.dumps(summary))
            with patch.object(analysis, "_plot", return_value={}):
                with self.assertRaisesRegex(analysis.RawAnalysisError, "Unsealed v3 warmup"):
                    analysis.analyze(root)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            trial = v3_row()
            trial["verdicts"]["measurement_integrity"]["status"] = "UNKNOWN"
            fixture_v3(root, [trial])
            with self.assertRaisesRegex(analysis.RawAnalysisError, "measurement_integrity verdict"):
                analysis.verify_run(root)

    def test_v4_pass_and_warning_use_same_metric_and_pacing_contract(self):
        for warning in (False, True):
            with self.subTest(warning=warning), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                trial = v3_row(4999.99, warning=warning)
                trial["rate_pps"] = 5000
                fixture_v4(root, [trial])
                originals = {path: path.read_bytes() for path in root.rglob("*.json")}
                with patch.object(analysis, "_plot", return_value={}):
                    output = analysis.analyze(root)
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["aggregates"][0]["metrics"]["offered_pps"]["median"], 4999.99)
                self.assertEqual(report["aggregates"][0]["pacing_warning_trials"], int(warning))
                self.assertEqual(report["attempt_accounting"]["attempted_trials"], 1)
                self.assertEqual(report["attempt_accounting"]["completed_trials"], 1)
                self.assertFalse(report["kernel_forwarding_latency_qualified"])
                markdown = (output / "report.md").read_text(encoding="utf-8")
                self.assertIn("Three independent verdicts", markdown)
                self.assertIn("Sender-pacing distributions", markdown)
                self.assertIn("Attempt accounting", markdown)
                if warning:
                    self.assertIn("VALID — PACING WARNING", markdown)
                    self.assertIn("5.113", markdown)
                for path, original in originals.items():
                    self.assertEqual(path.read_bytes(), original)

    def test_v4_unknown_qualification_withholds_rates_and_retains_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            trial = v3_row(5000, warning=True)
            trial["rate_pps"] = 5000
            trial["verdicts"]["independent_raw_qualification"]["status"] = "INCONCLUSIVE"
            fixture_v4(root, [trial], qualified=False)
            with patch.object(analysis, "_plot", return_value={}):
                output = analysis.analyze(root)
            report = json.loads((output / "report.json").read_text())
            self.assertIsNone(report["aggregates"][0]["metrics"]["offered_pps"]["median"])
            self.assertEqual(report["aggregates"][0]["metrics"]["packets_received"]["median"], 5000)
            self.assertEqual(report["pacing_warning_trials"], ["trial_0"])

    def test_v4_partial_attempts_disclosed_without_numerical_rows_or_evidence_changes(self):
        for completed in (False, True):
            for exists in (False, True):
                with self.subTest(completed=completed, exists=exists), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    fixture_v4(root, [v3_row()] if completed else [], qualified=False,
                               partial=True, partial_directory=exists)
                    originals = {path: path.read_bytes() for path in root.rglob("*.json")}
                    with patch.object(analysis, "_plot", return_value={}):
                        output = analysis.analyze(root)
                    report = json.loads((output / "report.json").read_text())
                    accounting = report["attempt_accounting"]
                    self.assertEqual(accounting["attempted_trials"], 1 + int(completed))
                    self.assertEqual(accounting["completed_trials"], int(completed))
                    self.assertEqual(accounting["partial_trials"], ["partial_trial"])
                    self.assertEqual(len(report["trials"]), int(completed))
                    self.assertEqual(len(report["aggregates"]), int(completed))
                    self.assertFalse(accounting["numerical_rows_invented"])
                    partial = accounting["partial_attempts"][0]
                    self.assertEqual(partial["trial_directory_exists"], exists)
                    self.assertIn("callback failure", partial["result_metadata"]["error"])
                    markdown = (output / "report.md").read_text(encoding="utf-8")
                    self.assertIn("callback failure", markdown)
                    self.assertIn("no numerical row is invented", markdown)
                    for path, original in originals.items():
                        self.assertEqual(path.read_bytes(), original)

    def test_v4_attempt_accounting_and_sealed_receipts_required(self):
        for problem in ("count", "receipt", "partial", "identity", "existence"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                summary = fixture_v4(root, [v3_row()], partial=True)
                if problem == "count":
                    summary["attempted_trials"] += 1
                elif problem == "receipt":
                    summary["artifact_hashes"].pop(summary["attempts"][-1]["result_receipt"])
                elif problem == "partial":
                    summary["partial_trials"] = []
                elif problem == "identity":
                    summary["attempts"][0]["mode"] = "forwarding"
                else:
                    name = summary["attempts"][-1]["result_receipt"]
                    path = root / name
                    receipt = json.loads(path.read_text())
                    receipt["trial_directory_exists"] = False
                    path.write_text(json.dumps(receipt))
                    summary["artifact_hashes"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
                (root / "summary.json").write_text(json.dumps(summary))
                with self.assertRaisesRegex(analysis.RawAnalysisError, "accounting|Unsealed|identity|existence"):
                    analysis.verify_run(root)

    def test_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payload = fixture(root, [row()])
            payload["artifact_hashes"]["../outside.json"] = "0" * 64
            (root / "summary.json").write_text(json.dumps(payload))
            with self.assertRaisesRegex(analysis.RawAnalysisError, "Unsafe"):
                analysis.verify_run(root)

    def test_trial_descriptive_statistics_preserve_outliers_and_defined_quartiles(self):
        stats = analysis.descriptive([1, 2, 3, 4, 10])
        self.assertEqual(stats["median"], 3)
        self.assertEqual(stats["range"], 9)
        self.assertEqual(stats["q1"], 2)
        self.assertEqual(stats["q3"], 4)
        self.assertEqual(stats["interquartile_range"], 2)
        self.assertAlmostEqual(stats["standard_deviation"], 3.5355339059)
        self.assertIsNone(stats["confidence_interval"])
        self.assertIsNone(analysis.descriptive([0, 0])["coefficient_of_variation"])
        self.assertIsNone(analysis.descriptive([])["median"])

    def test_v5_all_160_trials_and_six_paired_mode_comparisons_are_descriptive(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture_v5(root, v5_rows(warning_indices=(2,)))
            originals = {path: path.read_bytes() for path in root.rglob("*.json")}
            with patch.object(analysis, "_plot", return_value={"status": "disabled synthetic fixture"}):
                output = analysis.analyze(root)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["schema_version"], "raw-performance-analysis-v3")
            self.assertEqual(report["block_accounting"]["complete_qualified_blocks"], 40)
            self.assertEqual(len(report["aggregates"]), 32)
            self.assertEqual(len(report["paired_comparisons"]), 48)
            self.assertEqual(report["block_accounting"]["not_attempted_trials"], 0)
            pair = next(item for item in report["paired_comparisons"] if item["workload"] == "classification-heavy"
                and item["rate_pps"] == 100 and item["first_mode"] == "forwarding" and item["second_mode"] == "rf_b")
            cpu = pair["metrics"]["bmv2_cpu_one_core_percent"]
            self.assertEqual(cpu["valid_pairs"], 5)
            self.assertEqual(cpu["absolute_difference"]["median"], 2)
            self.assertEqual(cpu["percent_difference"]["median"], 20)
            self.assertEqual(cpu["pacing_warning_pairs"], 1)
            self.assertIsNone(cpu["absolute_difference"]["confidence_interval"])
            self.assertEqual(pair["metrics"]["classification_completion_fraction"]["valid_pairs"], 0)
            rf = next(group for group in report["aggregates"] if group["mode"] == "rf_b"
                and group["workload"] == "classification-heavy" and group["rate_pps"] == 100)
            self.assertEqual(rf["metrics"]["classification_completion_fraction"]["median"], 1)
            self.assertEqual(rf["metrics"]["offered_pps"]["pacing_warning_valid_trials"], 1)
            self.assertEqual(rf["metrics"]["runner_rss_peak_mib"]["median"], 200)
            self.assertFalse(report["kernel_forwarding_latency_qualified"])
            self.assertFalse(report["saturation_claim_qualified"])
            markdown = (output / "report.md").read_text(encoding="utf-8")
            self.assertIn("Final reduced WSL RAW benchmark", markdown)
            self.assertIn("second minus first", markdown)
            self.assertIn("not confidence intervals", markdown)
            self.assertIn("completed_valid", markdown)
            for path, original in originals.items():
                self.assertEqual(path.read_bytes(), original)

    def test_v5_partial_attempt_missing_modes_and_diagnostic_pairs_are_not_imputed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture_v5(root, v5_rows(3), partial=True)
            with patch.object(analysis, "_plot", return_value={}):
                output = analysis.analyze(root)
            report = json.loads((output / "report.json").read_text())
            accounting = report["block_accounting"]
            self.assertEqual(accounting["completed_trials"], 3)
            self.assertEqual(accounting["not_attempted_trials"], 156)
            self.assertEqual(accounting["complete_numerical_blocks"], 0)
            self.assertEqual(accounting["blocks"][0]["mode_states"]["rf_c"], "partial_attempt")
            self.assertEqual(accounting["blocks"][1]["mode_states"]["rf_c"], "not_attempted")
            self.assertEqual(len(report["trials"]), 3)
            missing = next(item for item in report["aggregates"] if item["mode"] == "rf_c")
            self.assertIsNone(missing["metrics"]["offered_pps"]["median"])
            self.assertEqual(missing["uncompleted_trials"], 5)
            pair = next(item for item in report["paired_comparisons"] if item["rate_pps"] == 100
                and item["workload"] == "classification-heavy" and item["first_mode"] == "forwarding"
                and item["second_mode"] == "features")
            self.assertEqual(pair["metrics"]["bmv2_cpu_one_core_percent"]["valid_pairs"], 0)
            self.assertEqual(pair["observations"][0]["metrics"]["bmv2_cpu_one_core_percent"]["difference"], 1)
            self.assertFalse(pair["observations"][0]["metrics"]["bmv2_cpu_one_core_percent"]["included_in_descriptive_comparison"])

    def test_v5_failed_clock_gate_withholds_rates_retains_counts_and_invalid_block(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture_v5(root, v5_rows(4, invalid_indices=(3,)))
            with patch.object(analysis, "_plot", return_value={}):
                output = analysis.analyze(root)
            report = json.loads((output / "report.json").read_text())
            block = report["block_accounting"]["blocks"][0]
            self.assertTrue(block["complete_numerical_block"])
            self.assertFalse(block["complete_qualified_block"])
            self.assertEqual(block["invalid_modes"], ["rf_c"])
            group = next(item for item in report["aggregates"] if item["mode"] == "rf_c"
                and item["rate_pps"] == 100 and item["workload"] == "classification-heavy")
            self.assertIsNone(group["metrics"]["offered_pps"]["median"])
            self.assertEqual(group["metrics"]["packets_received"]["median"], 2000)
            self.assertEqual(group["metrics"]["classification_completion_fraction"]["median"], 1)
            self.assertEqual(group["metrics"]["bmv2_rss_peak_mib"]["valid_trials"], 1)
            self.assertIn("raw_clock_sample_gap_over_25ms", report["trials"][3]["failures"])

    def test_v5_schedule_prefix_identity_and_sealed_derivatives_required(self):
        for problem in ("missing_schedule", "subset", "repetition", "attempt_order", "counter", "resources"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                summary = fixture_v5(root, v5_rows(4))
                if problem == "missing_schedule":
                    summary["artifact_hashes"].pop("schedule.json")
                elif problem == "subset":
                    summary["protocol"]["rates_pps"] = [100, 250]
                elif problem == "repetition":
                    summary["attempts"][0]["repetition"] = 2
                elif problem == "attempt_order":
                    summary["attempts"][0]["mode"] = "rf_c"
                elif problem == "counter":
                    summary["artifact_hashes"].pop("trial_2/counter_check.json")
                else:
                    summary["artifact_hashes"].pop("trial_0/resources.json")
                (root / "summary.json").write_text(json.dumps(summary))
                with patch.object(analysis, "_plot", return_value={}):
                    with self.assertRaises(analysis.RawAnalysisError):
                        analysis.analyze(root)
                self.assertFalse(list(root.glob("analysis_*")))

    def test_v5_zero_baselines_and_load_mismatches_do_not_create_relative_claims(self):
        rows = v5_rows(4)
        for trial in rows:
            trial["source_protocol"] = analysis.V5_SCHEMA
            trial["metrics"]["packets_lost"] = 0
        accounting = {"blocks": v5_schedule()}
        pairs = analysis.paired_comparisons(rows, True, accounting)
        first = pairs[0]
        self.assertIsNone(first["observations"][0]["metrics"]["packets_lost"]["percent_difference"])
        rows[3]["metrics"]["offered_pps"] = 90
        pairs = analysis.paired_comparisons(rows, True, accounting)
        self.assertTrue(all(item["metrics"]["offered_pps"]["valid_pairs"] == 0 for item in pairs))
        self.assertTrue(any(observation["block_load_screen"] == "LOAD MISMATCH WARNING"
            for item in pairs for observation in item["observations"]))

    def test_v5_supported_metric_figures_render_without_latency_or_false_zero_rows(self):
        try:
            import matplotlib
        except ImportError:
            self.skipTest("Plot dependency unavailable; nonprivileged WSL suite verifies real rendering")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture_v5(root, v5_rows(4, warning_indices=(2,)))
            output = analysis.analyze(root)
            report = json.loads((output / "report.json").read_text())
            figures = report["figures"]
            self.assertEqual(figures["status"], "generated")
            self.assertFalse(figures["confidence_intervals"])
            self.assertEqual(len(figures["files"]), 6)
            for name in figures["files"]:
                self.assertGreater((output / name).stat().st_size, 1000)
            self.assertEqual(sum(group["total_trials"] for group in report["aggregates"]), 4)
            self.assertTrue(all("latency" not in name for name in figures["files"]))


if __name__ == "__main__":
    unittest.main()
