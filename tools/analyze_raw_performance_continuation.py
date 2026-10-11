#!/usr/bin/env python3
"""Read-only linked-session analysis for the bounded 159-trial continuation.

The original v5 analyzer and all historical evidence remain unchanged. Each
session is independently sealed and qualified. No later clock pass can promote
the failed historical first trial or qualify its elapsed-time measurements.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets

import analyze_raw_performance as original


SCHEMA = "raw-performance-benchmark-continuation-v6"
RawAnalysisError = original.RawAnalysisError


def _archive(root):
    root = Path(root).absolute()
    for path in (root, *root.parents):
        original._reject_link(path)
    summary = original._json(original._safe_path(root, "summary.json"))
    hashes = summary.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        raise RawAnalysisError("Nonempty continuation artifact_hashes required")
    for name, expected in hashes.items():
        if (name == "summary.json" or not isinstance(expected, str) or len(expected) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in expected)):
            raise RawAnalysisError(f"Malformed continuation seal: {name}")
        if original._sha256(original._safe_path(root, name)) != expected.lower():
            raise RawAnalysisError(f"Artifact SHA256 mismatch: {name}")
    return root, summary, hashes


def _historical(root, summary, hashes):
    link = summary.get("historical_campaign")
    if (not isinstance(link, dict) or "historical_campaign.json" not in hashes
            or original._json(original._safe_path(root, "historical_campaign.json")) != link):
        raise RawAnalysisError("Sealed historical_campaign receipt is missing or inconsistent")
    source = Path(link.get("source_root", ""))
    prepared = Path(link.get("prepared_directory", ""))
    if not source.is_absolute() or not prepared.is_absolute() or source.resolve() == root.resolve():
        raise RawAnalysisError("Historical source/preparation must be distinct absolute paths")
    for path in (prepared, *prepared.parents):
        original._reject_link(path)
    historical_root, historical_summary, rows, integrity = original.verify_run(source)
    if (historical_summary.get("schema_version") != original.V5_SCHEMA
            or link.get("schema_version") != original.V5_SCHEMA
            or link.get("summary_sha256") != integrity["summary_sha256"]
            or link.get("preserved_artifacts") != integrity["artifact_hashes_verified"]
            or link.get("attempted_trials") != 1 or link.get("completed_trials") != 1
            or historical_summary.get("attempted_trials") != 1
            or historical_summary.get("completed_trials") != 1
            or len(rows) != 1 or rows[0]["valid"] is not False
            or historical_summary.get("partial_trials") != []
            or link.get("trials") != historical_summary.get("trials")):
        raise RawAnalysisError("Historical first-trial identity, seal, or original failed verdict changed")
    if (historical_summary.get("cleanup_errors") != []
            or historical_summary.get("frozen_inputs_unchanged") is not True
            or rows[0]["metrics"].get("packets_sent") != 20000
            or rows[0]["metrics"].get("packets_received") != 19950
            or rows[0]["metrics"].get("packets_lost") != 50
            or link.get("original_missing_output_packets") != 50
            or link.get("timing_requalified") is not False):
        raise RawAnalysisError("Historical cleanup, frozen provenance, or original 50 missing outputs changed")
    historical_attempts = integrity["attempt_accounting"]
    original.schedule_accounting(historical_root, historical_summary, rows, historical_attempts)
    provenance_name = "provenance.json"
    if provenance_name not in historical_summary["artifact_hashes"]:
        raise RawAnalysisError("Historical preparation provenance is not sealed")
    provenance = original._json(original._safe_path(historical_root, provenance_name))
    manifest = original._safe_path(prepared, "manifest.json")
    manifest_hash = original._sha256(manifest)
    if (manifest_hash != link.get("prepared_manifest_sha256")
            or manifest_hash != provenance.get("prepared_manifest_sha256")
            or Path(provenance.get("prepared_directory", "")).resolve() != prepared.resolve()):
        raise RawAnalysisError("Historical prepared-manifest binding changed")
    source_schedule = original._json(original._safe_path(historical_root, "schedule.json"))["schedule"]
    current_schedule = original._json(original._safe_path(root, "schedule.json"))["schedule"]
    if source_schedule != current_schedule or historical_summary.get("protocol") != summary.get("protocol"):
        raise RawAnalysisError("Continuation changed the original sealed schedule or numerical protocol")
    return historical_root, historical_summary, rows, integrity


def _verify_current_rows(root, summary, hashes):
    names = summary.get("trials")
    attempts = summary.get("attempts")
    if (not isinstance(names, list) or any(not isinstance(name, str) for name in names)
            or len(names) != len(set(names)) or not isinstance(attempts, list)
            or any(not isinstance(item, dict) for item in attempts)):
        raise RawAnalysisError("Unique current-session trial names and attempts required")
    normalized = deepcopy(summary)
    normalized["attempts"] = deepcopy(attempts)
    for session_ordinal, (actual, adapted) in enumerate(zip(attempts, normalized["attempts"]), 1):
        ordinal = session_ordinal + 1
        if (actual.get("ordinal") != ordinal or type(actual.get("ordinal")) is not int
                or actual.get("session_ordinal") != session_ordinal
                or actual.get("original_schedule_ordinal") != ordinal):
            raise RawAnalysisError("Continuation original/session attempt ordinal changed")
        adapted["ordinal"] = session_ordinal
        for key in ("start_receipt", "result_receipt"):
            if actual.get(key) not in hashes:
                raise RawAnalysisError(f"Unsealed continuation attempt receipt: {actual.get(key)}")
            receipt = original._json(original._safe_path(root, actual[key]))
            identity = receipt.get("attempt", receipt)
            if any(identity.get(field) != actual.get(field) for field in
                   ("ordinal", "session_ordinal", "original_schedule_ordinal", "mode", "workload",
                    "rate_pps", "block_id", "repetition", "trial_directory")):
                raise RawAnalysisError("Continuation attempt receipt identity changed")
    accounting = original._verify_attempts(root, normalized, names, hashes)
    for retained, actual in zip(accounting["attempts"], attempts):
        retained.update(ordinal=actual["ordinal"], session_ordinal=actual["session_ordinal"],
                        original_schedule_ordinal=actual["original_schedule_ordinal"])
    rows, keys = [], set()
    for name in names:
        original._safe_path(root, name, directory=True)
        for filename in ("trial_summary.json", "qualified_trial_summary.json"):
            if f"{name}/{filename}" not in hashes:
                raise RawAnalysisError(f"Unsealed immutable continuation summary: {name}/{filename}")
        local = original._json(original._safe_path(root, f"{name}/trial_summary.json"))
        row = original._json(original._safe_path(root, f"{name}/qualified_trial_summary.json"))
        attempt = next(item for item in accounting["attempts"] if item["trial_directory"] == name)
        if any(attempt.get(key) != row.get(key) for key in
               ("mode", "workload", "rate_pps", "block_id", "repetition")):
            raise RawAnalysisError("Continuation row identity disagrees with sealed attempt")
        if (row.get("execution_session_id") != summary["execution_session_id"]
                or row.get("original_schedule_ordinal") != attempt["ordinal"]
                or attempt.get("execution_session_id") != summary["execution_session_id"]):
            raise RawAnalysisError("Continuation qualified row/source-session metadata changed")
        session_pass = original._rate_qualification(summary)
        expected_qualification = summary["clock_rate_qualification"].get("status", "INCONCLUSIVE")
        if (row.get("raw_rate_qualified") is not session_pass
                or original._verdict(row, "independent_raw_qualification") != expected_qualification
                or not session_pass and row.get("valid") is not False):
            raise RawAnalysisError("Continuation row qualification does not belong to its execution session")
        seal_name = f"{name}/trial_evidence_seal.json"
        if seal_name not in hashes:
            raise RawAnalysisError("Completed continuation trial lacks its immutable local evidence seal")
        seal = original._json(original._safe_path(root, seal_name)).get("artifact_hashes")
        result = attempt["result_metadata"]
        if (not isinstance(seal, dict) or not seal
                or result.get("trial_evidence_seal_sha256") != hashes[seal_name]
                or result.get("local_summary_sha256") != hashes[f"{name}/trial_summary.json"]
                or "trial_summary.json" not in seal or "qualified_trial_summary.json" in seal
                or "trial_evidence_seal.json" in seal):
            raise RawAnalysisError("Continuation local acquisition seal/receipt binding changed")
        for artifact, expected in seal.items():
            if hashes.get(f"{name}/{artifact}") != expected:
                raise RawAnalysisError("Continuation local evidence seal disagrees with root seal")
            original._safe_path(root / name, artifact)
        if (row.get("metrics") != local.get("metrics")
                or any(row.get(key) != local.get(key) for key in
                       ("mode", "workload", "rate_pps", "block_id", "repetition"))
                or not set(local.get("failures", [])).issubset(row.get("failures", []))
                or row.get("verdicts", {}).get("sender_pacing_conformance") != local.get("verdicts", {}).get("sender_pacing_conformance")
                or local.get("valid") is False and row.get("valid") is not False
                or original._verdict(local, "measurement_integrity") == "FAIL"
                   and original._verdict(row, "measurement_integrity") != "FAIL"
                or any(value is False and row.get("metric_validity", {}).get(gate) is not False
                       for gate, value in local.get("metric_validity", {}).items())):
            raise RawAnalysisError("Continuation qualified copy modified observations or promoted an original integrity failure")
        if (row.get("mode") not in original.MODES or row.get("workload") not in original.WORKLOADS
                or not original._finite(row.get("rate_pps")) or row["rate_pps"] <= 0
                or type(row.get("valid")) is not bool or not isinstance(row.get("metrics"), dict)
                or not isinstance(row.get("failures"), list)
                or any(not isinstance(reason, str) for reason in row["failures"])):
            raise RawAnalysisError(f"Invalid continuation numerical row: {name}")
        validity = row.get("metric_validity")
        if not isinstance(validity, dict):
            raise RawAnalysisError("Continuation per-metric validity missing")
        for gate in set(original.METRIC_GATES.values()):
            fallback = (validity.get("classification_rate") if gate == "classification_counts" else
                        validity.get("cpu", validity.get("resources")) if gate == "cpu_accounting" else
                        validity.get("resources") if gate in ("cpu", "memory") else None)
            if type(validity.get(gate, fallback)) is not bool:
                raise RawAnalysisError(f"Missing boolean continuation metric gate: {gate}")
        if validity.get("kernel_forwarding_latency") is not False:
            raise RawAnalysisError("Reduced continuation cannot qualify kernel forwarding latency")
        for verdict, allowed in (("measurement_integrity", ("PASS", "FAIL")),
                ("independent_raw_qualification", ("PASS", "FAIL", "INCONCLUSIVE")),
                ("sender_pacing_conformance", ("PASS", "WARNING"))):
            if original._verdict(row, verdict) not in allowed:
                raise RawAnalysisError(f"Invalid continuation {verdict} verdict")
        key = row["block_id"], row["mode"]
        if key in keys:
            raise RawAnalysisError("Duplicate continuation scheduled identity")
        keys.add(key)
        # The unchanged descriptive helpers consume v5 row semantics. Actual
        # acquisition protocol and source session remain explicit alongside it.
        row.update(source_protocol=original.V5_SCHEMA, source_session_protocol=SCHEMA,
                   trial_directory=name, original_schedule_ordinal=attempt["ordinal"])
        row["warnings"] = list(row.get("warnings", []))
        row["invalid_metric_observations"] = {metric: repr(row["metrics"][metric])
            for metric in original.METRIC_GATES if row["metrics"].get(metric) is not None
            and not original._finite(row["metrics"][metric])}
        for metric in row["invalid_metric_observations"]:
            row["warnings"].append(f"{metric}: nonnumeric/nonfinite value is unavailable")
            row["metrics"][metric] = None
        rows.append(row)
    return rows, accounting


def verify_run(run):
    root, summary, hashes = _archive(run)
    if (summary.get("schema_version") != SCHEMA or summary.get("expected_trials") != 160
            or summary.get("expected_session_trials") != 159
            or summary.get("schedule_file") != "schedule.json" or "schedule.json" not in hashes
            or summary.get("local_trial_summary_file") != "trial_summary.json"
            or summary.get("qualified_trial_summary_file") != "qualified_trial_summary.json"
            or not isinstance(summary.get("execution_session_id"), str)
            or not summary["execution_session_id"]):
        raise RawAnalysisError("Continuation schema, session identity, or fixed schedule coverage changed")
    if ("clock_rate_qualification.json" not in hashes
            or original._json(original._safe_path(root, "clock_rate_qualification.json")) != summary.get("clock_rate_qualification")):
        raise RawAnalysisError("Continuation independent clock qualification is not bound to its sealed evidence")
    historical_root, historical_summary, historical_rows, historical_integrity = _historical(root, summary, hashes)
    current_rows, session_attempts = _verify_current_rows(root, summary, hashes)
    historical_attempts = deepcopy(historical_integrity["attempt_accounting"])
    sessions = ((historical_root, historical_summary, historical_rows, historical_attempts, True),
                (root, summary, current_rows, session_attempts, False))
    rows, attempted = [], []
    for session_root, session_summary, session_rows, accounting, historical in sessions:
        qualified = original._rate_qualification(session_summary)
        session_id = session_summary.get("execution_session_id", session_root.name)
        for row in session_rows:
            original._attach_pacing(session_root, session_summary, row)
            original._attach_supported_derivatives(session_root, session_summary, row)
            row.update(source_run=str(session_root), execution_session_id=session_id,
                       source_session_protocol=session_summary["schema_version"], is_historical=historical,
                       absolute_rate_qualified=qualified)
            if not qualified:
                row["effective_metric_validity"] = deepcopy(row["metric_validity"])
                for metric in original.RATE_QUALIFIED_METRICS:
                    row["effective_metric_validity"][original.METRIC_GATES[metric]] = False
            row["qualification_warnings"] = [] if qualified else [
                "This source session's independent RAW qualification did not pass; a later session cannot qualify or promote its absolute rates or CPU percentages."]
            rows.append(row)
        for item in accounting["attempts"]:
            item.update(source_run=str(session_root), execution_session_id=session_id, is_historical=historical)
            attempted.append(item)
    combined_attempts = dict(attempted_trials=len(attempted), completed_trials=len(rows),
        partial_trials=historical_attempts["partial_trials"] + session_attempts["partial_trials"],
        attempts=attempted, partial_attempts=[item for item in attempted if not item["has_completed_numerical_row"]],
        numerical_rows_invented=False,
        interpretation="Two independently sealed execution sessions; original failed attempt retained without retry or retroactive qualification.")
    accounting = original.schedule_accounting(root, summary, rows, combined_attempts)
    integrity = dict(artifact_hashes_verified=len(hashes), summary_sha256=original._sha256(root / "summary.json"),
        algorithm="sha256", historical_artifact_hashes_verified=historical_integrity["artifact_hashes_verified"],
        historical_summary_sha256=historical_integrity["summary_sha256"],
        session_attempt_accounting=session_attempts, attempt_accounting=combined_attempts,
        block_accounting=accounting, historical_campaign=deepcopy(summary["historical_campaign"]),
        execution_sessions=[dict(source_run=str(session_root), execution_session_id=session_summary.get("execution_session_id", session_root.name),
            source_protocol=session_summary["schema_version"], is_historical=historical,
            completed_trials=len(session_rows), raw_rate_qualified=original._rate_qualification(session_summary),
            clock_rate_qualification=deepcopy(session_summary.get("clock_rate_qualification", {})))
            for session_root, session_summary, session_rows, _, historical in sessions],
        limitation="Unsigned SHA256 manifests detect accidental changes, not an actor able to replace both artifacts and manifests. Root summaries are outside their own seals.")
    return root, summary, rows, integrity


def _markdown(report):
    adapted = deepcopy(report)
    adapted["source_protocol"] = original.V5_SCHEMA
    text = original.report_markdown(adapted)
    lines = ["## Separate-session provenance and qualification", "",
        "The first trial is immutable historical evidence; the remaining trials were acquired in a separate session. This is not one uninterrupted run. No failed trial was selectively retried or requalified.", "",
        "| Session | Historical | Completed trials | Independent RAW rate qualification | Source |",
        "|---|---|---:|---|---|"]
    for item in report["execution_sessions"]:
        lines.append(f"| {item['execution_session_id']} | {item['is_historical']} | {item['completed_trials']} | "
            f"{'PASS' if item['raw_rate_qualified'] else 'NOT QUALIFIED'} | `{item['source_run']}` |")
    lines.extend(["", "The historical 50 missing outputs and original FAIL/INCONCLUSIVE verdicts remain unchanged. Absolute rates and CPU percentages are gated by the source session's qualification, not by a later session's pass. Valid counts per metric and matched-block exclusions remain explicit.", ""])
    lines.extend([f"Continuation-session pass: **{report['campaign']['continuation_session_passed']}**; continuation acquisition complete: **{report['campaign']['continuation_acquisition_complete']}**. "
        f"Combined 160-trial acquisition complete: **{report['campaign']['acquisition_complete']}**; all 160 trials qualified: **{report['campaign']['passed']}**. A successful continuation cannot erase trial 1's failure.", ""])
    return text.replace("## Timing qualification", "\n".join(lines) + "\n## Continuation-session timing qualification", 1)


def analyze(run):
    root, summary, trials, integrity = verify_run(run)
    # True enables the unchanged helpers to use each row's verified source-
    # session masks/verdicts. It does not assert a pooled timing qualification.
    aggregates = original.aggregate(trials, True)
    existing = {(group["mode"], group["workload"], group["rate_pps"]): group for group in aggregates}
    for mode in original.MODES:
        for workload in original.WORKLOADS:
            for rate in (100, 250, 500, 1000):
                key = mode, workload, rate
                if key not in existing:
                    existing[key] = dict(mode=mode, workload=workload, rate_pps=rate,
                        instrument_valid_trials=0, total_trials=0, pacing_warning_trials=0,
                        metrics={metric: dict(valid_trials=0, total_trials=0, invalid_or_unavailable_trials=0,
                            pacing_warning_valid_trials=0, **original.descriptive([])) for metric in original.METRIC_GATES})
                existing[key]["expected_trials"] = 5
                existing[key]["uncompleted_trials"] = 5 - existing[key]["total_trials"]
    report = dict(schema_version="raw-performance-continuation-analysis-v1", source_run=str(root),
        source_protocol=SCHEMA, integrity=integrity, clock_domain="CLOCK_MONOTONIC_RAW",
        raw_rate_qualified=original._rate_qualification(summary),
        qualification_scope="Current continuation session only; every row independently retains its source-session qualification. No cross-session promotion.",
        clock_rate_qualification=summary.get("clock_rate_qualification", {}),
        execution_sessions=integrity["execution_sessions"], historical_campaign=integrity["historical_campaign"],
        metric_definitions=original.METRIC_NOTES, trials=trials,
        aggregates=[existing[key] for key in sorted(existing)],
        comparison_screens=original.comparison_screen(trials, True),
        attempt_accounting=integrity["attempt_accounting"], session_attempt_accounting=integrity["session_attempt_accounting"],
        block_accounting=integrity["block_accounting"],
        paired_comparisons=original.paired_comparisons(trials, True, integrity["block_accounting"]),
        campaign=dict(status=summary.get("status", "UNAVAILABLE"),
            passed=len(trials) == 160 and all(row["valid"] for row in trials),
            continuation_session_passed=summary.get("passed", False),
            continuation_acquisition_complete=summary.get("acquisition_complete", False),
            acquisition_complete=len(trials) == 160 and integrity["attempt_accounting"]["attempted_trials"] == 160
                and not integrity["attempt_accounting"]["partial_trials"],
            expected_trials=160, expected_session_trials=159, abort_reason=summary.get("abort_reason")),
        pacing_warning_trials=[row["trial_directory"] for row in trials
            if original._verdict(row, "sender_pacing_conformance") == "WARNING"],
        invalid_trials=[row["trial_directory"] for row in trials if not row["valid"]],
        kernel_forwarding_latency_qualified=False, physical_cpu_time_independently_qualified=False,
        traffic_shape_comparability_established=False, uniform_load_claim_qualified=False, saturation_claim_qualified=False,
        conclusion="Bounded linked-session repeated campaign; unchanged original failure, metric-specific valid counts, source-session qualification and matched-block descriptive comparisons. No latency, capacity, saturation, or selective-retry claim.")
    folder = root / ("analysis_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + secrets.token_hex(4))
    folder.mkdir(exist_ok=False)
    adapted = dict(report, source_protocol=original.V5_SCHEMA)
    report["figures"] = original._plot(adapted, folder)
    (folder / "report.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (folder / "report.md").write_text(_markdown(report), encoding="utf-8")
    return folder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    print(f"Linked-session RAW performance analysis saved to: {analyze(args.run)}")


if __name__ == "__main__":
    main()
