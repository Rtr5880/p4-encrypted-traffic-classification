"""Nonprivileged linked-session fixtures; no benchmark traffic or clock changes."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import analyze_raw_performance as original
import analyze_raw_performance_continuation as continuation
from test_analyze_raw_performance import fixture_v5, v5_rows, v5_schedule


def write(root, name, payload, hashes=None):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    if hashes is not None:
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return path


def fixture(parent, count=159, *, qualified=True, invalid_indices=(), partial=False):
    source, prepared, current = (parent / name for name in ("historical_session", "original_prepared", "continuation_session"))
    for root in (source, prepared, current):
        root.mkdir()
    historical = v5_rows(1, warning_indices=(0,), invalid_indices=(0,))
    historical[0]["metrics"].update(packets_sent=20000, packets_received=19950, packets_lost=50)
    historical[0]["verdicts"]["independent_raw_qualification"]["status"] = "INCONCLUSIVE"
    old_summary = fixture_v5(source, historical, qualified=False)
    old_summary.update(cleanup_errors=[], frozen_inputs_unchanged=True)
    manifest = write(prepared, "manifest.json", {"synthetic_test_fixture": True})
    manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
    write(source, "provenance.json", dict(prepared_directory=str(prepared),
        prepared_manifest_sha256=manifest_hash), old_summary["artifact_hashes"])
    write(source, "summary.json", old_summary)
    link = dict(source_root=str(source), summary_sha256=hashlib.sha256((source / "summary.json").read_bytes()).hexdigest(),
        prepared_directory=str(prepared), prepared_manifest_sha256=manifest_hash,
        preserved_artifacts=len(old_summary["artifact_hashes"]), trials=old_summary["trials"],
        attempted_trials=1, completed_trials=1, schema_version=original.V5_SCHEMA,
        original_missing_output_packets=50, timing_requalified=False)
    rows = v5_rows()[1:count + 1]
    for index in invalid_indices:
        trial = rows[index]
        trial.update(valid=False, failures=["raw_clock_sample_gap_over_25ms"])
        trial["verdicts"]["measurement_integrity"] = {"status": "FAIL"}
        trial["metric_validity"].update(offered_load=False, delivered_throughput=False, cpu=False,
            cpu_accounting=True, memory=True, classification_counts=True)
    # Reuse v5 fixture acquisition artifacts but not its first-session ordering.
    summary = fixture_v5(current, rows, qualified=qualified)
    hashes = summary["artifact_hashes"]
    names, attempts = [], []
    for index, trial in enumerate(rows):
        ordinal, session_ordinal = index + 2, index + 1
        old_name, name = f"trial_{index}", f"trial_{ordinal:03d}_fixture"
        shutil.copytree(current / old_name, current / name)
        for artifact in list(hashes):
            if artifact.startswith(old_name + "/"):
                hashes[name + artifact[len(old_name):]] = hashes.pop(artifact)
        names.append(name)
        attempt = dict(ordinal=ordinal, session_ordinal=session_ordinal,
            original_schedule_ordinal=ordinal, execution_session_id=current.name, trial_directory=name, status="completed",
            start_receipt=f"attempts/continuation_{ordinal:03d}_start.json",
            result_receipt=f"attempts/continuation_{ordinal:03d}_result.json",
            **{key: trial[key] for key in ("mode", "workload", "rate_pps", "block_id", "repetition")})
        qualified_copy = deepcopy(trial)
        qualified_copy.update(original_schedule_ordinal=ordinal, execution_session_id=current.name,
                              raw_rate_qualified=qualified)
        qualified_copy["verdicts"]["independent_raw_qualification"]["status"] = "PASS" if qualified else "INCONCLUSIVE"
        if not qualified:
            qualified_copy["valid"] = False
            qualified_copy["failures"].append("Independent RAW elapsed-rate/load qualification did not pass")
            for gate in ("offered_load", "delivered_throughput", "classification_rate", "cpu"):
                qualified_copy["metric_validity"][gate] = False
        write(current, f"{name}/qualified_trial_summary.json", qualified_copy, hashes)
        seal = {artifact[len(name) + 1:]: expected for artifact, expected in hashes.items()
                if artifact.startswith(name + "/") and not artifact.endswith("/qualified_trial_summary.json")}
        write(current, f"{name}/trial_evidence_seal.json", {"artifact_hashes": seal}, hashes)
        write(current, attempt["start_receipt"], dict(attempt, status="started"), hashes)
        write(current, attempt["result_receipt"], dict(attempt=attempt, status="completed",
            trial_directory_exists=True, measurements_fabricated=False,
            local_summary_sha256=hashes[f"{name}/trial_summary.json"],
            trial_evidence_seal_sha256=hashes[f"{name}/trial_evidence_seal.json"]), hashes)
        attempts.append(attempt)
    partial_names = []
    if partial:
        ordinal = count + 2
        trial = v5_rows()[ordinal - 1]
        name = f"trial_{ordinal:03d}_fixture"
        (current / name).mkdir()
        attempt = dict(ordinal=ordinal, session_ordinal=count + 1, original_schedule_ordinal=ordinal,
            trial_directory=name, status="exception",
            start_receipt=f"attempts/continuation_{ordinal:03d}_start.json",
            result_receipt=f"attempts/continuation_{ordinal:03d}_result.json",
            **{key: trial[key] for key in ("mode", "workload", "rate_pps", "block_id", "repetition")})
        write(current, attempt["start_receipt"], dict(attempt, status="started"), hashes)
        write(current, attempt["result_receipt"], dict(attempt=attempt, status="exception",
            trial_directory_exists=True, error="Synthetic unsafe execution; stop immediately"), hashes)
        attempts.append(attempt)
        partial_names.append(name)
    summary.update(schema_version=continuation.SCHEMA, execution_session_id=current.name,
        expected_trials=160, expected_session_trials=159, historical_campaign=link,
        trials=names, attempts=attempts, attempted_trials=len(attempts), completed_trials=len(rows),
        partial_trials=partial_names, status="continuation_completed" if count == 159 else "continuation_incomplete",
        passed=count == 159 and not invalid_indices and qualified, acquisition_complete=count == 159 and not partial,
        continuation_policy={"completed_local_failures": "preserve INVALID and continue"})
    write(current, "historical_campaign.json", link, hashes)
    write(current, "clock_rate_qualification.json", summary["clock_rate_qualification"], hashes)
    write(current, "summary.json", summary)
    return source, prepared, current, old_summary, summary


class ContinuationAnalysisTests(unittest.TestCase):
    def test_full_159_session_preserves_first_failure_and_reports_160_without_promotion(self):
        with tempfile.TemporaryDirectory() as folder:
            source, prepared, current, _, summary = fixture(Path(folder))
            before = {path: path.read_bytes() for root in (source, prepared, current)
                      for path in root.rglob("*.json")}
            with patch.object(original, "_plot", return_value={"status": "disabled synthetic fixture"}):
                output = continuation.analyze(current)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["source_protocol"], continuation.SCHEMA)
            self.assertEqual(report["attempt_accounting"]["attempted_trials"], 160)
            self.assertEqual(report["session_attempt_accounting"]["attempted_trials"], 159)
            self.assertEqual(report["block_accounting"]["completed_trials"], 160)
            self.assertEqual(report["block_accounting"]["complete_numerical_blocks"], 40)
            self.assertEqual(report["block_accounting"]["complete_qualified_blocks"], 39)
            self.assertEqual(report["block_accounting"]["not_attempted_trials"], 0)
            self.assertTrue(report["campaign"]["continuation_session_passed"])
            self.assertTrue(report["campaign"]["acquisition_complete"])
            self.assertFalse(report["campaign"]["passed"])
            historical = report["trials"][0]
            self.assertTrue(historical["is_historical"])
            self.assertFalse(historical["valid"])
            self.assertEqual(historical["metrics"]["packets_lost"], 50)
            self.assertEqual(original._verdict(historical, "independent_raw_qualification"), "INCONCLUSIVE")
            self.assertFalse(historical["absolute_rate_qualified"])
            self.assertEqual(historical["source_run"], str(source))
            forwarding = next(item for item in report["aggregates"] if item["mode"] == "forwarding"
                and item["workload"] == "classification-heavy" and item["rate_pps"] == 100)
            self.assertEqual(forwarding["metrics"]["offered_pps"]["valid_trials"], 4)
            self.assertEqual(forwarding["metrics"]["packets_lost"]["valid_trials"], 5)
            self.assertEqual(forwarding["metrics"]["packets_lost"]["maximum"], 50)
            pair = next(item for item in report["paired_comparisons"] if item["workload"] == "classification-heavy"
                and item["rate_pps"] == 100 and item["first_mode"] == "forwarding" and item["second_mode"] == "features")
            self.assertEqual(pair["metrics"]["offered_pps"]["valid_pairs"], 4)
            self.assertFalse(report["kernel_forwarding_latency_qualified"])
            markdown = (output / "report.md").read_text()
            self.assertIn("not one uninterrupted run", markdown)
            self.assertIn("historical 50 missing outputs", markdown)
            self.assertIn("continuation_session", markdown)
            for path, payload in before.items():
                self.assertEqual(path.read_bytes(), payload)

    def test_completed_invalid_session_trial_retains_metric_masks_and_later_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, current, _, _ = fixture(Path(folder), count=7, invalid_indices=(1,))
            with patch.object(original, "_plot", return_value={}):
                output = continuation.analyze(current)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(len(report["trials"]), 8)
            self.assertEqual(report["block_accounting"]["complete_numerical_blocks"], 2)
            self.assertEqual(report["block_accounting"]["complete_qualified_blocks"], 1)
            bad = report["trials"][2]
            self.assertFalse(bad["valid"])
            self.assertEqual(bad["failures"], ["raw_clock_sample_gap_over_25ms"])
            self.assertFalse(original._metric_valid(bad, "offered_pps", True))
            self.assertTrue(original._metric_valid(bad, "packets_received", True))
            self.assertTrue(report["trials"][3]["valid"])

    def test_session_qualification_failure_masks_rates_without_discarding_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, current, _, _ = fixture(Path(folder), count=3, qualified=False)
            with patch.object(original, "_plot", return_value={}):
                output = continuation.analyze(current)
            report = json.loads((output / "report.json").read_text())
            for group in report["aggregates"]:
                for metric in original.RATE_QUALIFIED_METRICS:
                    self.assertIsNone(group["metrics"][metric]["median"])
            self.assertEqual(sum(item["metrics"]["packets_received"]["valid_trials"]
                                 for item in report["aggregates"]), 4)
            self.assertFalse(report["raw_rate_qualified"])

    def test_partial_exception_is_retained_without_synthesized_row_or_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, current, _, _ = fixture(Path(folder), count=2, partial=True)
            with patch.object(original, "_plot", return_value={}):
                output = continuation.analyze(current)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["attempt_accounting"]["attempted_trials"], 4)
            self.assertEqual(len(report["trials"]), 3)
            self.assertEqual(report["attempt_accounting"]["partial_trials"], ["trial_004_fixture"])
            self.assertEqual(report["block_accounting"]["not_attempted_trials"], 156)
            self.assertEqual(report["block_accounting"]["blocks"][0]["mode_states"]["rf_c"], "partial_attempt")
            self.assertFalse(report["attempt_accounting"]["numerical_rows_invented"])

    def test_changed_historical_artifact_or_receipt_is_rejected_before_analysis(self):
        for problem in ("source_summary", "source_row", "source_count", "prepared_manifest", "receipt_mismatch"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as folder:
                source, prepared, current, old, summary = fixture(Path(folder), count=3)
                if problem == "source_summary":
                    write(source, "summary.json", dict(old, completed_trials=2))
                elif problem == "source_row":
                    write(source, "trial_0/qualified_trial_summary.json", {"valid": True})
                elif problem == "prepared_manifest":
                    write(prepared, "manifest.json", {"changed": True})
                else:
                    if problem == "source_count":
                        summary["historical_campaign"]["preserved_artifacts"] += 1
                        write(current, "historical_campaign.json", summary["historical_campaign"], summary["artifact_hashes"])
                    else:
                        write(current, "historical_campaign.json", dict(summary["historical_campaign"], completed_trials=2), summary["artifact_hashes"])
                    write(current, "summary.json", summary)
                with self.assertRaises(continuation.RawAnalysisError):
                    continuation.analyze(current)
                self.assertFalse(list(current.glob("analysis_*")))

    def test_schedule_ordinal_reordering_or_selective_first_retry_is_rejected(self):
        for problem in ("schedule", "ordinal", "session_ordinal", "first_retry", "repetition", "receipt"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as folder:
                _, _, current, _, summary = fixture(Path(folder), count=3)
                if problem == "schedule":
                    schedule = v5_schedule()
                    schedule[0]["modes"] = list(reversed(schedule[0]["modes"]))
                    write(current, "schedule.json", {"schedule": schedule}, summary["artifact_hashes"])
                elif problem == "ordinal":
                    summary["attempts"][0]["ordinal"] = 3
                elif problem == "session_ordinal":
                    summary["attempts"][0]["session_ordinal"] = 2
                elif problem == "first_retry":
                    summary["attempts"][0]["mode"] = "forwarding"
                elif problem == "repetition":
                    summary["attempts"][0]["repetition"] = 2
                else:
                    name = summary["attempts"][0]["result_receipt"]
                    receipt = json.loads((current / name).read_text())
                    receipt["attempt"]["original_schedule_ordinal"] = 1
                    write(current, name, receipt, summary["artifact_hashes"])
                write(current, "summary.json", summary)
                with self.assertRaises(continuation.RawAnalysisError):
                    continuation.analyze(current)
                self.assertFalse(list(current.glob("analysis_*")))

    def test_qualified_copy_cannot_promote_failure_modify_metrics_or_change_session(self):
        for problem in ("promote", "metrics", "session", "qualification", "local_seal"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as folder:
                _, _, current, _, summary = fixture(Path(folder), count=3, invalid_indices=(1,))
                name = summary["trials"][1]
                artifact = f"{name}/qualified_trial_summary.json"
                value = json.loads((current / artifact).read_text())
                if problem == "promote":
                    value["valid"] = True
                    value["failures"] = []
                    value["verdicts"]["measurement_integrity"]["status"] = "PASS"
                    value["metric_validity"]["offered_load"] = True
                elif problem == "metrics":
                    value["metrics"]["packets_received"] += 1
                elif problem == "session":
                    value["execution_session_id"] = "other_session"
                elif problem == "qualification":
                    value["verdicts"]["independent_raw_qualification"]["status"] = "INCONCLUSIVE"
                else:
                    summary["artifact_hashes"].pop(f"{name}/trial_evidence_seal.json")
                if problem != "local_seal":
                    write(current, artifact, value, summary["artifact_hashes"])
                write(current, "summary.json", summary)
                with self.assertRaises(continuation.RawAnalysisError):
                    continuation.analyze(current)
                self.assertFalse(list(current.glob("analysis_*")))

    def test_current_independent_qualification_file_must_match_sealed_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            _, _, current, _, summary = fixture(Path(folder), count=3)
            write(current, "clock_rate_qualification.json", {"status": "INCONCLUSIVE", "passed": False},
                  summary["artifact_hashes"])
            write(current, "summary.json", summary)
            with self.assertRaisesRegex(continuation.RawAnalysisError, "clock qualification"):
                continuation.analyze(current)
            self.assertFalse(list(current.glob("analysis_*")))


if __name__ == "__main__":
    unittest.main()
