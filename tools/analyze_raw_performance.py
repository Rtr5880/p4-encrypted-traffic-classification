#!/usr/bin/env python3
"""Offline, SHA256-checked reduced RAW calibration analysis.

Metric-specific validity is retained. No kernel-delay percentiles, saturation
claims, inference-delay estimates, or standalone direction-extraction costs are
derived. Inputs are never rewritten; every analysis gets a new output directory.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from itertools import combinations
import json
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
import secrets
import statistics


SCHEMA_VERSION = "raw-performance-calibration-v1"
V3_SCHEMA = "raw-performance-calibration-v3"
V4_SCHEMA = "raw-performance-calibration-v4"
V5_SCHEMA = "raw-performance-benchmark-v5"
ATTEMPT_SCHEMAS = (V4_SCHEMA, V5_SCHEMA)
THREE_VERDICT_SCHEMAS = (V3_SCHEMA, *ATTEMPT_SCHEMAS)
QUALIFIED_SUMMARY_SCHEMAS = ("raw-performance-calibration-v2", *THREE_VERDICT_SCHEMAS)
SUPPORTED_SCHEMAS = (SCHEMA_VERSION, *QUALIFIED_SUMMARY_SCHEMAS)
MODES = ("forwarding", "features", "rf_b", "rf_c")
WORKLOADS = ("classification-heavy", "cached-forwarding")
METRIC_GATES = {
    "offered_pps": "offered_load",
    "delivered_pps": "delivered_throughput",
    "delivered_ethernet_mbps": "delivered_throughput",
    "packets_sent": "packet_accounting", "packets_received": "packet_accounting",
    "packets_lost": "packet_accounting", "duplicates": "packet_accounting",
    "reordered": "packet_accounting", "packets_duplicated": "packet_accounting",
    "packets_reordered": "packet_accounting", "decisions": "classification_counts",
    "decision_rate_pps": "classification_rate",
    "bmv2_cpu_one_core_percent": "cpu", "bmv2_cpu_seconds": "cpu_accounting",
    "bmv2_rss_peak_mib": "memory", "bmv2_hwm_mib": "memory",
    "runner_cpu_one_core_percent": "cpu", "runner_cpu_seconds": "cpu_accounting",
    "delivery_fraction": "packet_accounting", "loss_fraction": "packet_accounting",
    "expected_decisions": "classification_counts",
    "classification_completion_fraction": "classification_counts",
    "runner_rss_peak_mib": "memory", "runner_hwm_mib": "memory",
}
RATE_QUALIFIED_METRICS = frozenset(("offered_pps", "delivered_pps", "delivered_ethernet_mbps",
                                  "decision_rate_pps", "bmv2_cpu_one_core_percent",
                                  "runner_cpu_one_core_percent"))
METRIC_NOTES = {
    "offered_load": "Successful socket sends / RAW offered-window duration; not exact BMv2 arrival spacing.",
    "delivered_throughput": "Unique matched delivered packets and Ethernet frame bytes / RAW offered duration, including documented bounded capture drain. Not instantaneous kernel output rate or physical-wire rate.",
    "packet_accounting": "Sequence/byte accounting after bounded drain; non-delivery is not automatically BMv2-attributable loss. Duplicates/reordering refer to capture observations.",
    "classification_rate": "RF decision counter delta / RAW offered duration. Counter observations may include completion during drain; not inference latency or accuracy.",
    "classification_counts": "Verified RF decision counter deltas; numerator remains available even if independent elapsed-rate qualification is inconclusive.",
    "classification_completion_fraction": "Observed RF measurement-window counter delta / planned eligible eight-packet instances from sealed counter_check.json. Dimensionless fraction, not prediction accuracy; forwarding/features are not applicable. Warm-up is excluded by counter subtraction.",
    "delivery_fraction": "Unique matched output packets / successful measured sends after bounded drain. Dimensionless fraction, separately packet-accounting gated; no automatic attribution of missing packets to BMv2.",
    "resources": "Linux OS-accounted process CPU divided by RAW snapshot-window duration; CPU numerator not independently frequency-qualified. RSS maximum is sampled; VmHWM is lifetime high-water RSS and can include warm-up.",
    "cpu": "OS-accounted process ticks/SC_CLK_TCK supply CPU seconds; percent uses RAW snapshot-window elapsed seconds. The numerator has no independent physical-frequency qualification. CPU percentages require current absolute-rate qualification.",
    "cpu_accounting": "OS-accounted CPU tick/second differences, not independently calibrated physical CPU time; retained separately from elapsed-time-normalized percentages.",
    "memory": "Linux VmRSS is sampled in the measurement window. VmHWM is lifetime high-water RSS, possibly including warm-up. Both use Linux kB (KiB); neither needs a frequency-qualified elapsed-time denominator.",
    "kernel_forwarding_latency": "Unqualified under reduced protocol; raw timestamp evidence and warnings retained separately. No kernel p50/p95/p99 or isolated RF latency reported.",
    "sender_pacing_conformance": "Unchanged numerical thresholds are prespecified engineering heuristics, not published or empirically validated validity boundaries. Warning trials retain independently qualified average-rate measurements and reliable counts; warnings alone do not qualify uniform-load or saturation claims.",
}


class RawAnalysisError(ValueError):
    pass


def _json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RawAnalysisError(f"Cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise RawAnalysisError(f"Expected JSON object: {path}")
    return value


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_link(path):
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise RawAnalysisError(f"Symlink/junction artifact is not allowed: {path}")


def _safe_path(root, name, directory=False):
    if not isinstance(name, str) or not name or "\\" in name:
        raise RawAnalysisError("Artifact names must be relative POSIX paths")
    relative, windows = PurePosixPath(name), PureWindowsPath(name)
    if (relative.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in ("", ".", "..") for part in name.split("/"))):
        raise RawAnalysisError(f"Unsafe artifact path: {name}")
    path = root
    for part in relative.parts:
        path /= part
        _reject_link(path)
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError, RuntimeError) as error:
        raise RawAnalysisError(f"Absent or out-of-run artifact: {name}") from error
    if not (path.is_dir() if directory else path.is_file()):
        raise RawAnalysisError(f"Wrong artifact kind: {name}")
    return path


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _metric_valid(row, metric, raw_rate_qualified=True):
    gate = METRIC_GATES[metric]
    gates = row.get("effective_metric_validity", row["metric_validity"])
    fallback = (gates.get('classification_rate') if gate == 'classification_counts' else
                gates.get('cpu', gates.get('resources')) if gate == 'cpu_accounting' else
                gates.get('resources') if gate in ('cpu', 'memory') else None)
    value = gates.get(gate, fallback)
    independent_pass = raw_rate_qualified
    if row.get("source_protocol") in THREE_VERDICT_SCHEMAS or "verdicts" in row:
        independent_pass = independent_pass and _verdict(row, "independent_raw_qualification") == "PASS"
    return value is True and (metric not in RATE_QUALIFIED_METRICS or independent_pass)


def _rate_qualification(summary):
    qualification = summary.get("clock_rate_qualification", summary.get("qualification"))
    if not isinstance(qualification, dict):
        return False
    actual_pass = (qualification["passed"] is True if "passed" in qualification
                   else qualification.get("status") == "PASS")
    # Both the run's authoritative decision and its retained independent
    # qualification must pass. A prior coarse pass or omission never suffices.
    return summary.get("raw_rate_qualified") is True and actual_pass


def _verify_attempts(root, summary, completed_names, hashes):
    """Validate v4 attempt receipts without inventing rows for partial trials."""
    attempts = summary.get("attempts")
    partial = summary.get("partial_trials")
    if not isinstance(attempts, list) or any(not isinstance(item, dict) for item in attempts):
        raise RawAnalysisError("Version 4 requires an attempt metadata ledger")
    names = [item.get("trial_directory") for item in attempts]
    if (any(not isinstance(name, str) for name in names) or len(names) != len(set(names))
            or not isinstance(partial, list) or any(not isinstance(name, str) for name in partial)
            or len(partial) != len(set(partial))):
        raise RawAnalysisError("Version 4 attempt/partial directories must be unique")
    if (type(summary.get("attempted_trials")) is not int
            or summary["attempted_trials"] != len(attempts)
            or type(summary.get("completed_trials")) is not int
            or summary["completed_trials"] != len(completed_names)
            or not set(completed_names).issubset(names)
            or set(partial) != set(names) - set(completed_names)):
        raise RawAnalysisError("Version 4 attempt/completed/partial accounting does not reconcile")
    metadata = []
    for ordinal, item in enumerate(attempts, 1):
        if (item.get("ordinal") != ordinal or type(item.get("ordinal")) is not int
                or item.get("mode") not in MODES or item.get("workload") not in WORKLOADS
                or not _finite(item.get("rate_pps")) or item["rate_pps"] <= 0
                or item.get("status") not in ("started", "completed", "exception")):
            raise RawAnalysisError("Invalid version 4 attempt identity/status")
        completed = item["trial_directory"] in completed_names
        if completed != (item["status"] == "completed"):
            raise RawAnalysisError("Version 4 attempt status disagrees with completed rows")
        retained = dict(item)
        for key, destination in (("start_receipt", "start_metadata"),
                                 ("result_receipt", "result_metadata")):
            name = item.get(key)
            if (not isinstance(name, str) or not name.startswith("attempts/")
                    or name not in hashes):
                raise RawAnalysisError(f"Unsealed version 4 attempt receipt: {name}")
            retained[destination] = _json(_safe_path(root, name))
        directory = root / item["trial_directory"]
        # _safe_path also rejects traversal/symlinks. For an exception before
        # mkdir, validate its path syntax against the same safe relative rules
        # using its parent, then retain the documented absence explicitly.
        relative = PurePosixPath(item["trial_directory"])
        if (relative.is_absolute() or len(relative.parts) != 1
                or "\\" in item["trial_directory"] or ":" in item["trial_directory"]
                or item["trial_directory"] in ("", ".", "..")):
            raise RawAnalysisError("Unsafe version 4 trial directory")
        _reject_link(directory)
        if directory.exists():
            _safe_path(root, item["trial_directory"], directory=True)
        reported_exists = retained["result_metadata"].get("trial_directory_exists")
        if type(reported_exists) is not bool or reported_exists != directory.is_dir():
            raise RawAnalysisError("Version 4 attempt directory existence disagrees with receipt")
        retained["has_completed_numerical_row"] = completed
        retained["trial_directory_exists"] = reported_exists
        metadata.append(retained)
    return dict(attempted_trials=len(attempts), completed_trials=len(completed_names),
                partial_trials=list(partial), attempts=metadata,
                partial_attempts=[item for item in metadata if not item["has_completed_numerical_row"]],
                numerical_rows_invented=False,
                interpretation="Incomplete attempts retain sealed receipts and any partial files; no missing measurement is synthesized or pooled.")


def verify_run(run):
    root = Path(run).absolute()
    for path in (root, *root.parents):
        _reject_link(path)
    summary = _json(_safe_path(root, "summary.json"))
    schema = summary.get("schema_version", summary.get("protocol"))
    if schema not in SUPPORTED_SCHEMAS:
        raise RawAnalysisError(f"Expected schema_version in {SUPPORTED_SCHEMAS}")
    qualified_name = summary.get("qualified_trial_summary_file", "trial_summary.json")
    if schema in QUALIFIED_SUMMARY_SCHEMAS:
        if qualified_name != "qualified_trial_summary.json" or summary.get("local_trial_summary_file") != "trial_summary.json":
            raise RawAnalysisError("Versions 2/3/4/5 require distinct immutable local and qualified summaries")
    elif qualified_name != "trial_summary.json":
        raise RawAnalysisError("Unexpected version 1 summary filename")
    hashes = summary.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        raise RawAnalysisError("Nonempty artifact_hashes manifest required")
    for name, expected in sorted(hashes.items()):
        if name == "summary.json":
            raise RawAnalysisError("Root summary cannot self-hash")
        if (not isinstance(expected, str) or len(expected) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in expected)):
            raise RawAnalysisError(f"Malformed SHA256: {name}")
        if _sha256(_safe_path(root, name)) != expected.lower():
            raise RawAnalysisError(f"Artifact SHA256 mismatch: {name}")
    names = summary.get("trials")
    if (not isinstance(names, list) or (not names and schema not in ATTEMPT_SCHEMAS) or
            any(not isinstance(name, str) for name in names) or len(names) != len(set(names))):
        raise RawAnalysisError("trials must contain unique relative directories")
    attempt_accounting = (_verify_attempts(root, summary, names, hashes)
                          if schema in ATTEMPT_SCHEMAS else None)
    trials, keys = [], set()
    for name in names:
        _safe_path(root, name, directory=True)
        artifact = f"{name}/{qualified_name}"
        if schema in QUALIFIED_SUMMARY_SCHEMAS and f"{name}/trial_summary.json" not in hashes:
            raise RawAnalysisError(f"Unsealed immutable local summary: {name}")
        if artifact not in hashes:
            raise RawAnalysisError(f"Unsealed trial summary: {artifact}")
        row = _json(_safe_path(root, artifact))
        row["source_protocol"] = schema
        if attempt_accounting is not None:
            attempt = next(item for item in attempt_accounting["attempts"]
                           if item["trial_directory"] == name)
            if any(attempt.get(key) != row.get(key)
                   for key in ("mode", "workload", "rate_pps", "block_id",
                               *(("repetition",) if schema == V5_SCHEMA else ()))):
                raise RawAnalysisError(f"Version 4 attempt identity disagrees with completed row: {name}")
        if row.get("mode") not in MODES or row.get("workload") not in WORKLOADS:
            raise RawAnalysisError(f"Unknown mode/workload: {name}")
        if not _finite(row.get("rate_pps")) or row["rate_pps"] <= 0:
            raise RawAnalysisError(f"Invalid target rate: {name}")
        if type(row.get("valid")) is not bool:
            raise RawAnalysisError(f"Missing boolean trial validity: {name}")
        validity = row.get("metric_validity")
        if not isinstance(validity, dict):
            raise RawAnalysisError(f"Missing per-metric validity: {name}")
        if any(type(validity.get(gate,
                validity.get('classification_rate') if gate == 'classification_counts' else
                validity.get('cpu', validity.get('resources')) if gate == 'cpu_accounting' else
                validity.get('resources') if gate in ('cpu', 'memory') else None)) is not bool
               for gate in set(METRIC_GATES.values())):
            raise RawAnalysisError(f"Missing boolean metric gate: {name}")
        if validity.get("kernel_forwarding_latency") is not False:
            raise RawAnalysisError("Reduced protocol cannot qualify kernel forwarding latency")
        if not isinstance(row.get("metrics"), dict):
            raise RawAnalysisError(f"Missing metrics object: {name}")
        if schema in THREE_VERDICT_SCHEMAS:
            expected = {"measurement_integrity": ("PASS", "FAIL"),
                        "independent_raw_qualification": ("PASS", "FAIL", "INCONCLUSIVE"),
                        "sender_pacing_conformance": ("PASS", "WARNING")}
            for verdict, allowed in expected.items():
                if _verdict(row, verdict) not in allowed:
                    raise RawAnalysisError(f"Missing/invalid {schema} {verdict} verdict: {name}")
        if not isinstance(row.get("failures"), list) or any(not isinstance(value, str) for value in row["failures"]):
            raise RawAnalysisError(f"Missing failure reasons: {name}")
        key = (row["mode"], row["workload"], row["rate_pps"], row.get("block_id", name))
        if key in keys:
            raise RawAnalysisError(f"Duplicate mode within block: {key}")
        keys.add(key)
        row["trial_directory"] = name
        row["warnings"] = list(row.get("warnings", [])) + [f"{metric}: nonnumeric/nonfinite value is unavailable"
            for metric in METRIC_GATES if row["metrics"].get(metric) is not None
            and not _finite(row["metrics"][metric])]
        row["invalid_metric_observations"] = {metric: repr(row["metrics"][metric])
            for metric in METRIC_GATES if row["metrics"].get(metric) is not None
            and not _finite(row["metrics"][metric])}
        # Retain the original observation explicitly but never replace invalid
        # numeric values with zero or serialize a nonstandard JSON NaN token.
        for metric in row["invalid_metric_observations"]:
            row["metrics"][metric] = None
        trials.append(row)
    integrity = dict(artifact_hashes_verified=len(hashes), summary_sha256=_sha256(root / "summary.json"),
        algorithm="sha256", limitation="Unsigned manifest detects accidental changes, not a party able to replace both artifacts and manifest. Root summary is outside its own hash manifest.")
    if attempt_accounting is not None:
        integrity["attempt_accounting"] = attempt_accounting
    return root, summary, trials, integrity


def descriptive(values):
    """Trial-level summaries; linearly interpolated quartiles, no invented CI."""
    values = sorted(values)
    def percentile(fraction):
        if not values:
            return None
        position = fraction * (len(values) - 1)
        low = int(position)
        high = min(low + 1, len(values) - 1)
        return values[low] + (values[high] - values[low]) * (position - low)
    q1, q3 = percentile(.25), percentile(.75)
    return dict(mean=statistics.mean(values) if values else None,
        median=statistics.median(values) if values else None,
        minimum=min(values) if values else None, maximum=max(values) if values else None,
        range=max(values) - min(values) if values else None,
        standard_deviation=statistics.stdev(values) if len(values) > 1 else None,
        q1=q1, q3=q3, interquartile_range=q3 - q1 if values else None,
        coefficient_of_variation=(statistics.stdev(values) / abs(statistics.mean(values))
            if len(values) > 1 and statistics.mean(values) != 0 else None),
        quartile_method="linear interpolation at (n-1)*p", confidence_interval=None,
        interpretation="Single trial: no replication or confidence interval" if len(values) <= 1
            else "Repeated-trial descriptive summaries only; no independence, confidence interval or significance claim")


def aggregate(trials, raw_rate_qualified=True):
    groups = defaultdict(list)
    for row in trials:
        groups[(row["mode"], row["workload"], row["rate_pps"])].append(row)
    result = []
    for (mode, workload, rate), rows in sorted(groups.items()):
        metrics = {}
        for metric, gate in METRIC_GATES.items():
            values = [row["metrics"][metric] for row in rows
                if _metric_valid(row, metric, raw_rate_qualified)
                and _finite(row["metrics"].get(metric))]
            metrics[metric] = dict(valid_trials=len(values), total_trials=len(rows),
                invalid_or_unavailable_trials=len(rows) - len(values),
                pacing_warning_valid_trials=sum(_verdict(row, "sender_pacing_conformance") == "WARNING"
                    and _metric_valid(row, metric, raw_rate_qualified)
                    and _finite(row["metrics"].get(metric)) for row in rows), **descriptive(values))
        result.append(dict(mode=mode, workload=workload, rate_pps=rate,
            instrument_valid_trials=sum(row["valid"] for row in rows), total_trials=len(rows), metrics=metrics,
            pacing_warning_trials=sum(_verdict(row, "sender_pacing_conformance") == "WARNING" for row in rows),
            pacing_warning_policy="Warning observations remain included when a metric's integrity and independent-rate requirements pass; no selective removal of warning trials."))
    return result


def _attach_supported_derivatives(root, summary, row):
    """v5 postprocessing only: no new acquisition or historical reinterpretation."""
    if row.get("source_protocol") != V5_SCHEMA:
        return
    metrics = row["metrics"]
    sent, received = metrics.get("packets_sent"), metrics.get("packets_received")
    metrics["delivery_fraction"] = received / sent if _finite(sent) and sent > 0 and _finite(received) else None
    if row["mode"].startswith("rf_"):
        name = f"{row['trial_directory']}/counter_check.json"
        if name not in summary["artifact_hashes"]:
            raise RawAnalysisError(f"Unsealed v5 classification completion evidence: {name}")
        counts = _json(_safe_path(root, name))
        expected, observed = counts.get("expected_packets"), counts.get("packets")
        if (type(expected) is not int or expected <= 0 or type(observed) is not int
                or observed != metrics.get("decisions")):
            raise RawAnalysisError(f"Invalid v5 classification completion accounting: {name}")
        metrics["expected_decisions"] = expected
        metrics["classification_completion_fraction"] = observed / expected
        row["classification_completion_meaning"] = "Observed measurement-window decision delta / planned eligible eight-packet flow count; not accuracy. Warm-up counter baseline is subtracted."
    else:
        metrics["expected_decisions"] = metrics["classification_completion_fraction"] = None
    name = f"{row['trial_directory']}/resources.json"
    if name not in summary["artifact_hashes"]:
        raise RawAnalysisError(f"Unsealed v5 resource evidence: {name}")
    memory = _json(_safe_path(root, name)).get("runner", {}).get("memory", {})
    for metric, field in (("runner_rss_peak_mib", "rss_max_sampled_mib"), ("runner_hwm_mib", "vmhwm_lifetime_mib")):
        value = memory.get(field)
        metrics[metric] = value if _finite(value) else None


def schedule_accounting(root, summary, trials, attempts):
    """Verify the fixed sealed schedule and preserve every absent/failed mode."""
    name = summary.get("schedule_file")
    if name != "schedule.json" or name not in summary["artifact_hashes"]:
        raise RawAnalysisError("v5 requires sealed schedule.json")
    schedule = _json(_safe_path(root, name)).get("schedule")
    protocol = summary.get("protocol", {})
    if (not isinstance(schedule, list) or len(schedule) != 40
            or protocol.get("rates_pps") != [100, 250, 500, 1000]
            or protocol.get("repetitions") != 5 or protocol.get("duration_seconds") != 20
            or protocol.get("warmup_seconds") != 5 or summary.get("expected_trials") != 160):
        raise RawAnalysisError("v5 fixed schedule/protocol coverage changed")
    expected = {(rate, workload, repeat) for rate in (100, 250, 500, 1000)
                for workload in WORKLOADS for repeat in range(1, 6)}
    identities, blocks_by_id = set(), {}
    for block in schedule:
        if (not isinstance(block, dict) or not isinstance(block.get("block_id"), str)
                or not block["block_id"] or block["block_id"] in blocks_by_id
                or not isinstance(block.get("modes"), list)
                or sorted(block["modes"]) != sorted(MODES)):
            raise RawAnalysisError("Invalid v5 four-mode block identity")
        identity = (block.get("rate_pps"), block.get("workload"), block.get("repetition"))
        if (type(block.get("rate_pps")) is not int or type(block.get("repetition")) is not int
                or identity not in expected or identity in identities):
            raise RawAnalysisError("Invalid/duplicate v5 block coverage")
        identities.add(identity)
        blocks_by_id[block["block_id"]] = block
    if identities != expected:
        raise RawAnalysisError("Missing v5 planned block")
    ordered_attempts = [(block["block_id"], mode) for block in schedule for mode in block["modes"]]
    observed_attempts = []
    for item in attempts["attempts"]:
        block = blocks_by_id.get(item["block_id"])
        if not block or any(item.get(key) != block[key] for key in ("rate_pps", "workload", "repetition")):
            raise RawAnalysisError("v5 attempt does not match its planned block")
        observed_attempts.append((item["block_id"], item["mode"]))
    if observed_attempts != ordered_attempts[:len(observed_attempts)]:
        raise RawAnalysisError("v5 attempt order is not an unmodified schedule prefix; no selective retries")
    rows = {(row["block_id"], row["mode"]): row for row in trials}
    attempts_by_key = {(item["block_id"], item["mode"]): item for item in attempts["attempts"]}
    blocks = []
    for block in schedule:
        states = {}
        for mode in block["modes"]:
            key = block["block_id"], mode
            row = rows.get(key)
            if row and any(row.get(field) != block[field] for field in ("rate_pps", "workload", "repetition")):
                raise RawAnalysisError("v5 row does not match its planned block")
            states[mode] = ("completed_valid" if row and row["valid"] else "completed_invalid" if row
                            else "partial_attempt" if key in attempts_by_key else "not_attempted")
        blocks.append(dict(block_id=block["block_id"], workload=block["workload"],
            rate_pps=block["rate_pps"], repetition=block["repetition"],
            ordered_modes=block["modes"], mode_states=states,
            complete_numerical_block=all(state.startswith("completed_") for state in states.values()),
            complete_qualified_block=all(state == "completed_valid" for state in states.values()),
            missing_or_partial_modes=[mode for mode, state in states.items() if not state.startswith("completed_")],
            invalid_modes=[mode for mode, state in states.items() if state == "completed_invalid"]))
    return dict(expected_trials=160, expected_blocks=40, attempted_trials=len(observed_attempts),
        completed_trials=len(trials), not_attempted_trials=160 - len(observed_attempts),
        complete_numerical_blocks=sum(block["complete_numerical_block"] for block in blocks),
        complete_qualified_blocks=sum(block["complete_qualified_block"] for block in blocks),
        incomplete_blocks=[block["block_id"] for block in blocks if not block["complete_numerical_block"]],
        blocks=blocks, selective_retries=False,
        interpretation="Unattempted/partial/invalid modes stay explicit; missing rows are not imputed and incomplete blocks cannot establish four-mode comparisons.")


def paired_comparisons(trials, raw_rate_qualified, block_accounting):
    """All six same-block mode pairs, descriptive only, never packet pseudoreplication."""
    lookup = {(row["block_id"], row["mode"]): row for row in trials}
    screens = {(item["block_id"]): item for item in comparison_screen(trials, raw_rate_qualified)}
    groups = defaultdict(list)
    for block in block_accounting["blocks"]:
        screen = screens.get(block["block_id"], {})
        for first, second in combinations(MODES, 2):
            left, right = lookup.get((block["block_id"], first)), lookup.get((block["block_id"], second))
            observation = dict(block_id=block["block_id"], repetition=block["repetition"],
                first_mode=first, second_mode=second, difference_definition="second minus first",
                block_load_screen=screen.get("status", "NOT QUALIFIED"),
                achieved_offered_pps={mode: row["metrics"].get("offered_pps") if row else None
                    for mode, row in ((first, left), (second, right))},
                pacing_by_mode={mode: dict(verdict=_verdict(row, "sender_pacing_conformance"),
                    distributions=row.get("pacing_distributions", {})) if row else None
                    for mode, row in ((first, left), (second, right))}, metrics={})
            comparison_allowed = screen.get("status") == "LOAD SCREEN PASS"
            for metric in METRIC_GATES:
                available = (left is not None and right is not None
                    and _metric_valid(left, metric, raw_rate_qualified)
                    and _metric_valid(right, metric, raw_rate_qualified)
                    and _finite(left["metrics"].get(metric)) and _finite(right["metrics"].get(metric)))
                difference = right["metrics"][metric] - left["metrics"][metric] if available else None
                baseline = left["metrics"][metric] if available else None
                observation["metrics"][metric] = dict(difference=difference,
                    percent_difference=difference / abs(baseline) * 100 if difference is not None and baseline != 0 else None,
                    included_in_descriptive_comparison=bool(available and comparison_allowed),
                    exclusion_reason=None if available and comparison_allowed else "Incomplete/unqualified/load-mismatched four-mode block or unavailable metric; retained diagnostic differences are not pooled.")
            groups[(block["workload"], block["rate_pps"], first, second)].append(observation)
    result = []
    for (workload, rate, first, second), observations in sorted(groups.items()):
        metrics = {}
        for metric in METRIC_GATES:
            included = [item for item in observations if item["metrics"][metric]["included_in_descriptive_comparison"]]
            values = [item["metrics"][metric]["difference"] for item in included]
            percentages = [item["metrics"][metric]["percent_difference"] for item in included
                           if item["metrics"][metric]["percent_difference"] is not None]
            metrics[metric] = dict(valid_pairs=len(included), expected_pairs=len(observations),
                pacing_warning_pairs=sum(any(item["pacing_by_mode"][mode]["verdict"] == "WARNING"
                    for mode in (first, second)) for item in included),
                absolute_difference=descriptive(values), percent_difference=descriptive(percentages))
        result.append(dict(workload=workload, rate_pps=rate, first_mode=first, second_mode=second,
            difference_definition="second minus first; relative difference uses absolute first-mode baseline; undefined at zero",
            metrics=metrics, observations=observations,
            interpretation="Five prespecified matched blocks; descriptive trial differences, not statistical significance or inherent speed. Pacing warnings are retained. RF-B/C compare deployed forests, not direction extraction alone."))
    return result


def comparison_screen(trials, raw_rate_qualified):
    """Descriptive same-block offered-load screen, not equivalence or acceptance.

    All four configurations must be present and qualified; warnings are never
    excluded to obtain a more convenient comparison. The existing 2% offered-
    rate tolerance is transparently reused as an engineering screening value,
    not a new acquisition gate or proof of statistical comparability.
    """
    groups = defaultdict(list)
    for row in trials:
        groups[(row["workload"], row["rate_pps"], row.get("block_id", row.get("repetition")))].append(row)
    screens = []
    for (workload, target, block), rows in sorted(groups.items(), key=lambda item: str(item[0])):
        modes = [row["mode"] for row in rows]
        reasons = []
        if sorted(modes) != sorted(MODES):
            reasons.append("The block does not contain exactly one trial for each of the four modes")
        if not raw_rate_qualified:
            reasons.append("Current independent RAW qualification did not pass")
        if any(not row["valid"] or not _metric_valid(row, "offered_pps", raw_rate_qualified)
               or not _finite(row["metrics"].get("offered_pps")) for row in rows):
            reasons.append("At least one mode lacks an integrity-valid qualified achieved offered rate")
        offered = {row["mode"]: row["metrics"].get("offered_pps") for row in rows}
        available = [value for value in offered.values() if _finite(value)]
        spread = (max(available) - min(available)) / target if len(available) == 4 and not reasons else None
        status = "NOT QUALIFIED" if reasons else ("LOAD SCREEN PASS" if spread <= .02 else "LOAD MISMATCH WARNING")
        warnings = [row.get("trial_directory", row["mode"]) for row in rows
                    if _verdict(row, "sender_pacing_conformance") == "WARNING"]
        screens.append(dict(workload=workload, target_pps=target, block_id=block,
            status=status, reasons=reasons, achieved_offered_pps=offered,
            normalized_achieved_load_spread=spread,
            engineering_screening_threshold=.02,
            screening_basis="Existing 2% offered-rate engineering tolerance reused for descriptive cross-mode screening only; not a new acquisition acceptance policy or statistical equivalence bound.",
            pacing_warning_trials=warnings,
            pacing_by_mode={row["mode"]: row.get("pacing_distributions", {}) for row in rows},
            uniform_load_claim_qualified=False, saturation_claim_qualified=False,
            interpretation="Descriptive balanced-block load screen only. Compare achieved loads and retained pacing distributions; warnings and non-comparable blocks cannot establish uniform-load, saturation, or an inherent speed ranking."))
    return screens


def _verdict(row, name):
    value = row.get("verdicts", {}).get(name)
    if isinstance(value, dict):
        return value.get("status", "UNAVAILABLE")
    if isinstance(value, str):
        return value
    # Historical strict protocols remain strict; absence is not relabelled.
    return "NOT SEPARATELY RECORDED (historical protocol)"


def _pacing_summary(pacing):
    if not isinstance(pacing, dict):
        return {}
    return {name: pacing.get(name) for name in (
        "valid", "status", "reasons", "warnings", "thresholds", "nominal_interval_ns",
        "p99_send_lateness_limit_ns", "maximum_send_lateness_limit_ns",
        "actual_offered_pps_over_window", "sender_short_gap_fraction",
        "send_lateness_summary_ns", "send_completion_lateness_summary_ns",
        "sender_interpacket_gap_summary_ns")}


def _attach_pacing(root, summary, row):
    if row.get("source_protocol") not in THREE_VERDICT_SCHEMAS:
        return
    evidence = {}
    for phase, filename in (("warmup", "warmup_measurement.json"), ("measurement", "measurement.json")):
        name = f"{row['trial_directory']}/{filename}"
        if name not in summary["artifact_hashes"]:
            version = {V3_SCHEMA: "v3", V4_SCHEMA: "v4", V5_SCHEMA: "v5"}[row["source_protocol"]]
            raise RawAnalysisError(f"Unsealed {version} {phase} pacing evidence: {name}")
        phase_report = _json(_safe_path(root, name))
        evidence[phase] = _pacing_summary(phase_report.get("pacing_quality"))
        evidence[phase]["source_file"] = name
        evidence[phase]["raw_arrays_retained_in_source"] = True
        evidence[phase]["capture_packet_statistics"] = phase_report.get("capture_statistics")
    row["pacing_distributions"] = evidence


def _number(value, digits=3):
    return "unavailable" if value is None else f"{value:,.{digits}f}"


def report_markdown(report):
    final = report.get("source_protocol") == V5_SCHEMA
    lines = ["# Final reduced WSL RAW benchmark — repeated-trial performance" if final else
        "# Reduced WSL RAW calibration — preliminary instrumentation results", "",
        "This is not a capacity benchmark, classification-accuracy test, or isolated RF-latency measurement.", "",
        f"Verified {report['integrity']['artifact_hashes_verified']} sealed artifacts. Source summary SHA256: `{report['integrity']['summary_sha256']}`.", "",
        "## Timing qualification", "",
        "The complete qualification object is retained in report.json. A previous RAW rate pass does not automatically qualify this acquisition under load.", "",
        f"Current acquisition absolute-rate qualification: **{'PASS' if report['raw_rate_qualified'] else 'NOT QUALIFIED — absolute rates and CPU percentages withheld from aggregates'}**.", "",
        "Qualification bounds are campaign-average coarse rate bounds, not individual 20-second-trial frequency certificates. Full queries and warnings remain in report.json.", "",
        "| Reference | Status | RAW estimate ppm | Lower / upper ppm | Valid / failed queries | Highest-load queries |",
        "|---|---|---:|---|---|---:|",
        *[f"| {name} | {item.get('status', 'INCONCLUSIVE')} | {_number(item.get('raw_rate', {}).get('midpoint_estimate_ppm'))} | "
          f"{_number(item.get('raw_rate', {}).get('lower_ppm'))} / {_number(item.get('raw_rate', {}).get('upper_ppm'))} | "
          f"{item.get('valid_queries', 0)} / {item.get('failed_queries', 0)} | {item.get('representative_load_queries', 0)} |"
          for name, item in report['clock_rate_qualification'].get('providers', {}).items()], ""]
    if report.get("source_protocol") in ATTEMPT_SCHEMAS:
        accounting = report["attempt_accounting"]
        lines += ["## Attempt accounting", "",
            f"Campaign status: **{report['campaign']['status']}**; campaign passed: **{report['campaign']['passed']}**. Abort reason: {report['campaign']['abort_reason'] or 'none'}.", "",
            f"Attempted: **{accounting['attempted_trials']}**; completed numerical trial rows: **{accounting['completed_trials']}**; incomplete attempts: **{len(accounting['partial_trials'])}**.", "",
            "Every attempt's sealed start/result receipts are retained in report.json. Incomplete attempts are not discarded or replaced with zeros, and no numerical row is invented from their partial evidence.", ""]
        if accounting["partial_attempts"]:
            lines += ["| Attempt | Mode | Workload | Target pps | Status | Trial directory present | Failure receipt / reason |",
                      "|---|---|---|---:|---|---|---|"]
            for attempt in accounting["partial_attempts"]:
                receipt = attempt["result_metadata"]
                reason = receipt.get("error", receipt.get("exception", receipt.get("reason", "See sealed result receipt")))
                reason = str(reason).replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {attempt['ordinal']} | {attempt['mode']} | {attempt['workload']} | {attempt['rate_pps']} | {attempt['status']} | {attempt['trial_directory_exists']} | `{attempt['result_receipt']}`: {reason} |")
            lines += ["", "Partial attempt files remain diagnostic evidence only; completed-row aggregates do not establish coverage of a failed or uncompleted mode/rate block.", ""]
    if report.get("source_protocol") in THREE_VERDICT_SCHEMAS:
        lines += ["## Three independent verdicts", "",
            "**Sender-pacing warnings do not invalidate reliable counts or independently qualified average-rate measurements.** Numerical limits are unchanged engineering heuristics, not validated scientific boundaries. Warnings remain visible and are never silently removed from aggregates.", "",
            "| Mode | Workload | Target pps | Measurement integrity | Independent RAW qualification | Sender conformance |",
            "|---|---|---:|---|---|---|"]
        for row in report["trials"]:
            lines.append(f"| {row['mode']} | {row['workload']} | {row['rate_pps']} | " + " | ".join(
                _verdict(row, name) for name in ("measurement_integrity", "independent_raw_qualification", "sender_pacing_conformance")) + " |")
        lines += ["", "## Sender-pacing distributions — not forwarding latency", "",
            "Lateness values are application-send deadline observations or conservative send-completion upper bounds. They are **not validated forwarding-delay percentiles**. Every raw array, numerical threshold and outlier remains in the sealed phase measurement file. Warm-up is not discarded.", "",
            "| Mode | Workload | Target pps | Phase | Conformance | Start median / p99 / max ms | Completion median / p99 / max ms | Short-gap fraction |",
            "|---|---|---:|---|---|---|---|---:|"]
        for row in report["trials"]:
            for phase in ("warmup", "measurement"):
                evidence = row.get("pacing_distributions", {}).get(phase, {})
                rendered = []
                for field in ("send_lateness_summary_ns", "send_completion_lateness_summary_ns"):
                    summary = evidence.get(field) or {}
                    rendered.append(" / ".join(_number(summary.get(key) / 1e6 if _finite(summary.get(key)) else None)
                        for key in ("median", "p99", "maximum")))
                verdict = row.get("verdicts", {}).get("sender_pacing_conformance", {}).get(phase, {})
                phase_status = verdict.get("status", "UNAVAILABLE") if isinstance(verdict, dict) else str(verdict)
                lines.append(f"| {row['mode']} | {row['workload']} | {row['rate_pps']} | {phase} | {phase_status} | " +
                    " | ".join(rendered) + f" | {_number(evidence.get('sender_short_gap_fraction'), 6)} |")
        lines += ["", "## Four-mode achieved-load comparability screen", "",
            "Identical target rates are insufficient. For each balanced block, the normalized achieved-load spread is `(maximum achieved pps − minimum achieved pps) / target pps`. The existing 2% tolerance is reused **only as an engineering descriptive screen**, not a new acquisition gate, equivalence proof or statistical significance test.", "",
            "| Workload | Target pps | Block | Screen | Achieved min / max pps | Normalized spread % | Pacing-warning trials |",
            "|---|---:|---|---|---|---:|---|"]
        for item in report["comparison_screens"]:
            values = [value for value in item["achieved_offered_pps"].values() if _finite(value)]
            spread = item["normalized_achieved_load_spread"]
            lines.append(f"| {item['workload']} | {item['target_pps']} | {item['block_id']} | {item['status']} | " +
                f"{_number(min(values) if values else None)} / {_number(max(values) if values else None)} | " +
                f"{_number(spread * 100 if spread is not None else None)} | {', '.join(item['pacing_warning_trials']) or 'none'} |")
            if item["reasons"]:
                lines += ["", "Screen limitations: " + "; ".join(item["reasons"]), ""]
        lines += ["", "A close achieved-load screen alone does not establish matched traffic shape. Compare the phase distributions and warm-up warnings above. Mismatched blocks support no model-overhead conclusion. " +
            ("Five prespecified blocks support descriptive variability and paired differences, not an inherent speed ranking or statistical significance. " if final else "One trial per configuration cannot establish an inherent speed ranking; ") +
            "No uniform-load, saturation or maximum-throughput claim is established.", ""]
    lines += ["## Measured trial values", "",
        "All throughput denominators are RAW offered-window seconds; delivery may complete during documented drain. CPU is Linux OS-accounted, not independently calibrated physical CPU usage.", "",
        "| Mode | Workload | Target pps | Offered pps | Delivered pps | Ethernet Mb/s | Sent/output/missing | Decisions | Decisions/s | BMv2 CPU % | RSS sampled / lifetime HWM MiB | Overall |",
        "|---|---|---:|---:|---:|---:|---|---:|---:|---:|---|---|",
    ]
    for row in report["trials"]:
        def cell(metric, digits=3):
            if metric in ('decisions', 'decision_rate_pps') and row['mode'] in ('forwarding', 'features'):
                return 'N/A (no RF)'
            gate = METRIC_GATES[metric]
            value = row["metrics"].get(metric)
            rendered = _number(value if _finite(value) else None, digits)
            return rendered + (" [INVALID / UNQUALIFIED]" if not _metric_valid(row, metric, report["raw_rate_qualified"]) else "")
        verdict = 'VALID' if row['valid'] else 'INVALID'
        if _verdict(row, 'sender_pacing_conformance') == 'WARNING':
            verdict += ' — PACING WARNING'
        lines.append(f"| {row['mode']} | {row['workload']} | {row['rate_pps']} | {cell('offered_pps')} | {cell('delivered_pps')} | {cell('delivered_ethernet_mbps')} | {cell('packets_sent',0)} / {cell('packets_received',0)} / {cell('packets_lost',0)} | {cell('decisions',0)} | {cell('decision_rate_pps')} | {cell('bmv2_cpu_one_core_percent')} | {cell('bmv2_rss_peak_mib')} / {cell('bmv2_hwm_mib')} | {verdict} |")
    lines += ["", "## Resource and packet-accounting detail", "",
        "Invalid rows remain visible. Blank/unavailable values are not zeros; classification counters are not applicable to forwarding/features modes.", "",
        "The missing-output count is **actual observed path non-delivery only when input capture, byte matching, bounded drain and capture reliability gates pass**. It is never automatically attributed to BMv2. Socket drops, receive-buffer loss or incomplete capture are instrumentation loss and invalidate the affected accounting. Kernel timestamp invalidity is distinct from packet capture validity.", "",
        "| Mode | Workload | Target pps | Duplicate observations | Ordering regressions | BMv2 CPU s | Runner CPU s | Runner CPU % |",
        "|---|---|---:|---:|---:|---:|---:|---:|"]
    for row in report["trials"]:
        values = []
        for metric in ("packets_duplicated", "packets_reordered", "bmv2_cpu_seconds", "runner_cpu_seconds", "runner_cpu_one_core_percent"):
            observed = row["metrics"].get(metric)
            values.append(_number(observed if _finite(observed) else None) +
                (" [INVALID / UNQUALIFIED]" if not _metric_valid(row, metric, report["raw_rate_qualified"]) else ""))
        lines.append(f"| {row['mode']} | {row['workload']} | {row['rate_pps']} | " + " | ".join(values) + " |")
    lines += ["", "## Valid-trial aggregates", "",
        "Each observation is a trial, not a packet. Values are median [minimum, maximum], with the number of valid trials. Single-trial ranges do not represent statistical uncertainty.", "",
        "| Mode | Workload | Target pps | Delivered pps | BMv2 CPU % | Sampled RSS MiB |",
        "|---|---|---:|---|---|---|"]
    for group in report["aggregates"]:
        entries = []
        for metric in ("delivered_pps", "bmv2_cpu_one_core_percent", "bmv2_rss_peak_mib"):
            stats = group["metrics"][metric]
            entries.append(f"{_number(stats['median'])} [{_number(stats['minimum'])}, {_number(stats['maximum'])}]; n={stats['valid_trials']}/{stats['total_trials']}")
        lines.append(f"| {group['mode']} | {group['workload']} | {group['rate_pps']} | " + " | ".join(entries) + " |")
    if final:
        accounting = report["block_accounting"]
        lines += ["", "## Prespecified schedule coverage", "",
            f"Expected **160 trials / 40 matched blocks**. Completed: **{accounting['completed_trials']}**; not attempted: **{accounting['not_attempted_trials']}**. " +
            f"Complete numerical blocks: **{accounting['complete_numerical_blocks']}**; fully qualified blocks: **{accounting['complete_qualified_blocks']}**.", "",
            "No selective retries, missing-value imputation, outlier deletion or promotion of incomplete blocks. Invalid measurements and incomplete attempts remain visible; per-metric valid counts—not the planned five—determine every summary.", "",
            "| Block | Workload | Target pps | Repetition | Mode states |",
            "|---|---|---:|---:|---|"]
        for block in accounting["blocks"]:
            states = "; ".join(f"{mode}: {status}" for mode, status in block["mode_states"].items())
            lines.append(f"| {block['block_id']} | {block['workload']} | {block['rate_pps']} | {block['repetition']} | {states} |")
        lines += ["", "## Repeated-trial variability and metric validity", "",
            "Median, full observed minimum–maximum range, sample SD and linearly interpolated IQR are descriptive trial-level quantities. Range/IQR/SD are not confidence intervals. Five restart-separated repetitions can remain temporally correlated within this laptop session.", "",
            "| Mode | Workload | Target pps | Metric | Median | Min–max | Sample SD | IQR | Valid / planned | Included pacing warnings |",
            "|---|---|---:|---|---:|---|---:|---:|---|---:|"]
        display = ("offered_pps", "delivered_pps", "delivered_ethernet_mbps", "packets_sent", "packets_received",
                   "packets_lost", "delivery_fraction", "decision_rate_pps", "classification_completion_fraction",
                   "bmv2_cpu_one_core_percent", "runner_cpu_one_core_percent", "bmv2_cpu_seconds",
                   "runner_cpu_seconds", "bmv2_rss_peak_mib", "bmv2_hwm_mib", "runner_rss_peak_mib")
        for group in report["aggregates"]:
            for metric in display:
                if not group["mode"].startswith("rf_") and metric in ("decision_rate_pps", "classification_completion_fraction"):
                    continue
                item = group["metrics"][metric]
                lines.append(f"| {group['mode']} | {group['workload']} | {group['rate_pps']} | {metric} | " +
                    f"{_number(item['median'])} | {_number(item['minimum'])}–{_number(item['maximum'])} | " +
                    f"{_number(item['standard_deviation'])} | {_number(item['interquartile_range'])} | " +
                    f"{item['valid_trials']} / 5 | {item['pacing_warning_valid_trials']} |")
        lines += ["", "## Paired four-mode comparisons", "",
            "All six mode pairs are compared within the same prespecified workload/rate/repetition block. Differences below are **second minus first**; relative change is `100 × difference / |first|` and is unavailable when the baseline is zero. CPU differences are percentage points; RSS differences are MiB. Full per-block values and pacing distributions remain in report.json.", "",
            "Pair summaries require a complete integrity-qualified four-mode achieved-load screen; diagnostic differences for excluded blocks are retained but not pooled. Pacing warnings are included and counted. This is not a significance test, causal isolation of RF latency, or a standalone direction-extraction measurement.", "",
            "| Workload | Target pps | First → second | Metric | Median paired difference [min, max] | Median relative % | SD / IQR | Valid pairs / 5 | Warning pairs |",
            "|---|---:|---|---|---|---:|---|---|---:|"]
        for pair in report["paired_comparisons"]:
            for metric in ("delivered_pps", "bmv2_cpu_one_core_percent", "bmv2_rss_peak_mib"):
                item = pair["metrics"][metric]
                stats = item["absolute_difference"]
                lines.append(f"| {pair['workload']} | {pair['rate_pps']} | {pair['first_mode']} → {pair['second_mode']} | {metric} | " +
                    f"{_number(stats['median'])} [{_number(stats['minimum'])}, {_number(stats['maximum'])}] | " +
                    f"{_number(item['percent_difference']['median'])} | {_number(stats['standard_deviation'])} / {_number(stats['interquartile_range'])} | " +
                    f"{item['valid_pairs']} / {item['expected_pairs']} | {item['pacing_warning_pairs']} |")
    lines += ["", "## Metric-specific validity and failures", ""]
    for row in report["trials"]:
        lines += [f"### {row['trial_directory']}", "",
            ", ".join(f"{gate}: {'PASS' if value else 'INVALID / UNQUALIFIED'}" for gate, value in row["metric_validity"].items()), "",
            "Failures: " + ("; ".join(row["failures"]) or "none"), "",
            "Warnings: " + ("; ".join(row["warnings"]) or "none"), ""]
        if report.get("source_protocol") in THREE_VERDICT_SCHEMAS:
            pacing = row.get("verdicts", {}).get("sender_pacing_conformance", {})
            for phase in ("warmup", "measurement"):
                phase_data = pacing.get(phase, {})
                warnings = phase_data.get("warnings", phase_data.get("reasons", [])) if isinstance(phase_data, dict) else []
                lines += [f"{phase} pacing conformance: {phase_data.get('status', 'UNAVAILABLE') if isinstance(phase_data, dict) else phase_data}; warnings: " + ("; ".join(warnings) or "none"), "",
                    f"{phase} capture socket statistics: `{json.dumps(row.get('pacing_distributions', {}).get(phase, {}).get('capture_packet_statistics'), sort_keys=True)}`", ""]
    lines += ["## Definitions and scope", ""]
    lines.extend(f"- {gate}: {meaning}" for gate, meaning in METRIC_NOTES.items())
    lines += ["", "RF-B and RF-C both already extract direction features. Their comparison isolates deployed forest differences, not standalone direction-extraction cost.", "",
        "Aggregates use each metric's integrity/qualification-valid trials only; pacing-warning trials remain included when the metric is valid. Unavailable/invalid values are never replaced by zero. Individual invalid observations and original strict historical verdicts remain preserved. Descriptive replication alone establishes no statistically meaningful speed ranking. No uniform-load, saturation or maximum-capacity claim is made.", ""]
    return "\n".join(lines)


def _plot(report, folder):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return dict(status="unavailable", reason="matplotlib not installed; no figure invented")
    if report.get("source_protocol") == V5_SCHEMA:
        return _plot_final(report, folder, plt)
    figure, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for axis, (metric, label) in zip(axes, (("delivered_pps", "Delivered packets / RAW offered second"),
                                        ("bmv2_cpu_one_core_percent", "BMv2 OS-accounted CPU (% of one core)"))):
        rows = report["aggregates"]
        positions, values, names, warnings = [], [], [], []
        for row in rows:
            stats = row["metrics"][metric]
            if stats["median"] is not None:
                positions.append(len(positions))
                values.append(stats["median"])
                names.append(f"{row['mode']}\n{row['workload']}\n{row['rate_pps']} pps; n={stats['valid_trials']}")
                warnings.append(row.get("pacing_warning_trials", 0) > 0)
        bars = axis.bar(positions, values, color="#3267ac")
        for bar, warned in zip(bars, warnings):
            if warned:
                bar.set_hatch("///")
                bar.set_edgecolor("#a34800")
        axis.set_xticks(positions, names, rotation=35, ha="right", fontsize=7)
        axis.set_ylabel(label)
        axis.grid(axis="y", alpha=.25)
        if not values:
            axis.text(.5, .5, "No valid observations", transform=axis.transAxes, ha="center")
    figure.suptitle("Preliminary RAW calibration — no capacity/latency claim; hatched bars include pacing warnings")
    figure.tight_layout()
    figure.savefig(folder / "raw_calibration.png", dpi=180)
    plt.close(figure)
    return dict(status="generated", files=["raw_calibration.png"], confidence_intervals=False)


def _plot_final(report, folder, plt):
    """Publication-ready descriptive figures from valid trials, never latency."""
    files = []
    colors = dict(zip(MODES, ("#555555", "#0072B2", "#009E73", "#D55E00")))
    panels = (
        ("offered_pps", "Achieved offered load (pps)"),
        ("delivered_pps", "Delivered packets / RAW offered second"),
        ("delivered_ethernet_mbps", "Delivered Ethernet throughput (Mb/s)"),
        ("delivery_fraction", "Matched output / sent packet fraction"),
        ("decision_rate_pps", "RF decisions / RAW offered second"),
        ("classification_completion_fraction", "RF decisions / planned eligible instances"),
        ("bmv2_cpu_one_core_percent", "BMv2 OS-accounted CPU (% of one core)"),
        ("runner_cpu_one_core_percent", "Runner OS-accounted CPU (% of one core)"),
        ("bmv2_rss_peak_mib", "BMv2 sampled peak RSS (MiB)"),
        ("bmv2_hwm_mib", "BMv2 lifetime VmHWM (MiB; includes warm-up)"),
        ("runner_rss_peak_mib", "Runner sampled peak RSS (MiB)"),
        ("runner_hwm_mib", "Runner lifetime VmHWM (MiB; includes warm-up)"))
    for workload in WORKLOADS:
        fig, axes = plt.subplots(3, 4, figsize=(17, 11), squeeze=False)
        for axis, (metric, label) in zip(axes.flat, panels):
            available = False
            for mode_index, mode in enumerate(MODES):
                groups = sorted((group for group in report["aggregates"]
                    if group["workload"] == workload and group["mode"] == mode
                    and group["metrics"][metric]["median"] is not None), key=lambda group: group["rate_pps"])
                if not groups:
                    continue
                available = True
                x = [group["rate_pps"] for group in groups]
                stats = [group["metrics"][metric] for group in groups]
                median = [item["median"] for item in stats]
                error = [[item["median"] - item["minimum"] for item in stats],
                         [item["maximum"] - item["median"] for item in stats]]
                axis.errorbar(x, median, yerr=error, label=mode, color=colors[mode],
                    marker="o", markersize=4, capsize=3, linewidth=1.2)
                axis.fill_between(x, [item["q1"] for item in stats], [item["q3"] for item in stats],
                                  color=colors[mode], alpha=.1)
                for rate, value, item in zip(x, median, stats):
                    if item["valid_trials"] != 5 or item["pacing_warning_valid_trials"]:
                        axis.annotate(f"n={item['valid_trials']}" + (" W" if item["pacing_warning_valid_trials"] else ""),
                            (rate, value), xytext=(2, 6 + mode_index * 8), textcoords="offset points",
                            fontsize=6, color=colors[mode])
            axis.set_title(label, fontsize=9)
            axis.set_xlabel("Target offered load (pps)", fontsize=8)
            axis.set_xticks((100, 250, 500, 1000))
            axis.tick_params(labelsize=7)
            axis.grid(alpha=.2)
            if not available:
                axis.text(.5, .5, "No qualified observations", transform=axis.transAxes, ha="center")
        handles, labels = axes[0, 0].get_legend_handles_labels()
        fig.legend(handles, labels, loc="upper center", ncol=4, bbox_to_anchor=(.5, .955))
        fig.suptitle(f"Reduced WSL RAW benchmark: {workload}\nMedians; whiskers = observed range; shaded = IQR; W = retained pacing warning", fontsize=12)
        fig.text(.5, .012, "Five prespecified restart-separated trials per cell; n=5 unless labelled otherwise. Missing values omitted; W=retained warning. No latency, significance or capacity claim.", ha="center", fontsize=8)
        fig.tight_layout(rect=(0, .025, 1, .925))
        stem = "raw_benchmark_" + workload
        for extension in ("png", "pdf", "svg"):
            name = stem + "." + extension
            fig.savefig(folder / name, dpi=200)
            files.append(name)
        plt.close(fig)
    return dict(status="generated", files=files, confidence_intervals=False,
        error_bars="Observed trial minimum/maximum; shaded linear-interpolation IQR; not uncertainty bounds",
        missing_values="No zeros substituted; qualified n and retained warning markers disclosed")


def analyze(run):
    root, summary, trials, integrity = verify_run(run)
    rate_qualified = _rate_qualification(summary)
    for row in trials:
        _attach_pacing(root, summary, row)
        _attach_supported_derivatives(root, summary, row)
        row["absolute_rate_qualified"] = rate_qualified
        row["qualification_warnings"] = [] if rate_qualified else [
            "Current acquisition independent RAW rate qualification did not pass or was not provided; absolute offered/delivered/decision rates and CPU percentages excluded from aggregation. Packet counts, CPU-accounted seconds and memory are separately gated."]
    report = dict(schema_version="raw-performance-analysis-v2", source_run=str(root),
        source_protocol=summary.get("schema_version", summary.get("protocol")),
        integrity=integrity, clock_domain="CLOCK_MONOTONIC_RAW",
        raw_rate_qualified=rate_qualified,
        clock_rate_qualification=summary.get("clock_rate_qualification", summary.get("qualification", {"status": "not provided; inconclusive"})),
        metric_definitions=METRIC_NOTES, trials=trials, aggregates=aggregate(trials, rate_qualified),
        comparison_screens=comparison_screen(trials, rate_qualified),
        pacing_warning_trials=[row["trial_directory"] for row in trials
                              if _verdict(row, "sender_pacing_conformance") == "WARNING"],
        invalid_trials=[row["trial_directory"] for row in trials if not row["valid"]],
        kernel_forwarding_latency_qualified=False,
        physical_cpu_time_independently_qualified=False,
        traffic_shape_comparability_established=False,
        uniform_load_claim_qualified=False, saturation_claim_qualified=False,
        conclusion="Calibration only: inspect metric gates and clock qualification before approving any sweep. No automatic sweep, latency, saturation or speed-ranking claim.")
    if report["source_protocol"] in ATTEMPT_SCHEMAS:
        report["attempt_accounting"] = integrity["attempt_accounting"]
        report["campaign"] = dict(status=summary.get("status", "UNAVAILABLE"),
                                  passed=summary.get("passed", False),
                                  expected_trials=summary.get("expected_trials"),
                                  abort_reason=summary.get("abort_reason"))
    if report["source_protocol"] == V5_SCHEMA:
        report["schema_version"] = "raw-performance-analysis-v3"
        report["block_accounting"] = schedule_accounting(root, summary, trials, report["attempt_accounting"])
        report["paired_comparisons"] = paired_comparisons(trials, rate_qualified, report["block_accounting"])
        existing = {(group["mode"], group["workload"], group["rate_pps"]): group for group in report["aggregates"]}
        for mode in MODES:
            for workload in WORKLOADS:
                for rate in (100, 250, 500, 1000):
                    key = mode, workload, rate
                    if key not in existing:
                        existing[key] = dict(mode=mode, workload=workload, rate_pps=rate,
                            instrument_valid_trials=0, total_trials=0, pacing_warning_trials=0,
                            metrics={metric: dict(valid_trials=0, total_trials=0, invalid_or_unavailable_trials=0,
                                pacing_warning_valid_trials=0, **descriptive([])) for metric in METRIC_GATES})
                    existing[key]["expected_trials"] = 5
                    existing[key]["uncompleted_trials"] = 5 - existing[key]["total_trials"]
        report["aggregates"] = [existing[key] for key in sorted(existing)]
        report["conclusion"] = "Final prespecified repeated RAW performance campaign: per-metric valid trial summaries and matched-block descriptive comparisons only. Maximum tested load is not capacity or saturation. RF-B/C both extract direction; latency remains unqualified. No new experiment is launched."
    folder = root / ("analysis_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + secrets.token_hex(4))
    folder.mkdir(exist_ok=False)
    report["figures"] = _plot(report, folder)
    (folder / "report.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (folder / "report.md").write_text(report_markdown(report), encoding="utf-8")
    return folder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    print(f"RAW calibration analysis saved to: {analyze(args.run)}")


if __name__ == "__main__":
    main()
