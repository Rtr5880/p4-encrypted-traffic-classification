#!/usr/bin/env python3
"""Offline, integrity-checked analysis of performance-benchmark-v1 runs.

This module never opens a network interface or changes a raw run. Statistical
observations are complete trials, not individual packet delays. Plotting is lazy
so the integrity and statistics functions also work without matplotlib.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path, PurePosixPath, PureWindowsPath
import random
import secrets
import statistics
from typing import Any


SCHEMA_VERSION = "performance-benchmark-v1"
MODES = ("forwarding", "features", "rf_b", "rf_c")
WORKLOADS = ("classification-heavy", "cached-forwarding")
NUMERIC_METRICS = (
    "offered_pps", "received_pps", "ethernet_mbps", "loss_fraction",
    "packets_sent", "packets_received", "packets_lost", "packets_duplicated",
    "packets_reordered", "delay_min_us", "delay_mean_us", "delay_median_us",
    "delay_p95_us", "delay_p99_us", "delay_max_us", "bmv2_cpu_one_core_percent",
    "bmv2_cpu_seconds", "bmv2_rss_peak_mib", "bmv2_hwm_mib",
    "runner_cpu_one_core_percent", "runner_cpu_seconds", "decisions",
    "decision_rate_pps", "output_kernel_interarrival_pps",
)
QUALITY_METRICS = ("pacing_valid", "clock_valid")
LATENCY_METRICS = tuple(name for name in NUMERIC_METRICS if name.startswith("delay_"))
SUMMARY_FIELDS = (
    "n_metric", "mean", "median", "std", "minimum", "maximum",
    "mean_ci95_low", "mean_ci95_high", "median_ci95_low", "median_ci95_high",
    "exploratory",
)
COLORS = dict(zip(MODES, ("#36454f", "#14838c", "#3267ac", "#b85724")))


class BenchmarkAnalysisError(ValueError):
    """Malformed or untrustworthy input; analysis stops before writing output."""


def _finite(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkAnalysisError(f"Cannot read JSON {path}: {error}") from error
    if not isinstance(data, dict):
        raise BenchmarkAnalysisError(f"Expected JSON object in {path}")
    return data


def _reject_link(path: Path) -> None:
    # is_junction exists on Windows Python 3.12; resolve alone is insufficient.
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise BenchmarkAnalysisError(f"Symlink/junction is not permitted: {path}")


def _safe_path(root: Path, name: Any, *, directory: bool = False) -> Path:
    if not isinstance(name, str) or not name or "\\" in name:
        raise BenchmarkAnalysisError(f"Artifact path must be a relative POSIX path: {name!r}")
    relative = PurePosixPath(name)
    windows = PureWindowsPath(name)
    if (relative.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in ("..", ".") for part in name.split("/"))
            or any(not part for part in name.split("/"))):
        raise BenchmarkAnalysisError(f"Unsafe artifact path: {name!r}")
    path = root
    for part in relative.parts:
        path = path / part
        _reject_link(path)
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError, RuntimeError) as error:
        raise BenchmarkAnalysisError(f"Artifact is absent or outside the run: {name}") from error
    if not (path.is_dir() if directory else path.is_file()):
        raise BenchmarkAnalysisError(f"Expected {'directory' if directory else 'file'}: {name}")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_run(run_dir: str | Path) -> tuple[Path, dict, list[dict], dict]:
    """Verify declared SHA256 artifacts and tracked trial summaries, then load.

    Root summary.json (or run_summary.json) is intentionally outside its own
    manifest. This detects accidental artifact changes; it is not a signature
    or proof against a party able to replace both artifacts and the manifest.
    """
    root = Path(run_dir).absolute()
    for parent in (root, *root.parents):
        _reject_link(parent)
    if not root.is_dir():
        raise BenchmarkAnalysisError(f"Run directory does not exist: {root}")
    summary_paths = [root / name for name in ("summary.json", "run_summary.json")
                     if (root / name).exists()]
    if len(summary_paths) != 1:
        raise BenchmarkAnalysisError("Expected exactly one root summary.json or run_summary.json")
    _reject_link(summary_paths[0])
    summary = _json(summary_paths[0])
    if summary.get("schema_version") != SCHEMA_VERSION:
        raise BenchmarkAnalysisError(f"Expected schema_version={SCHEMA_VERSION!r}")
    if not isinstance(summary.get("status"), str):
        raise BenchmarkAnalysisError("Root status must be a string")
    protocol = summary.get("protocol")
    if not isinstance(protocol, dict):
        raise BenchmarkAnalysisError("Root protocol must be an object")
    rates = protocol.get("rates_pps")
    if (not isinstance(rates, list) or not rates
            or any(not _finite(rate) or rate <= 0 for rate in rates)
            or len(set(rates)) != len(rates)):
        raise BenchmarkAnalysisError("protocol.rates_pps must contain unique finite positive rates")
    if type(protocol.get("seed")) is not int:
        raise BenchmarkAnalysisError("protocol.seed must be an integer")
    for name in ("duration_seconds", "warmup_seconds"):
        if not _finite(protocol.get(name)) or protocol[name] < 0:
            raise BenchmarkAnalysisError(f"protocol.{name} must be finite and nonnegative")
    if protocol["duration_seconds"] <= 0:
        raise BenchmarkAnalysisError("protocol.duration_seconds must be positive")
    if type(protocol.get("repetitions")) is not int or protocol["repetitions"] < 1:
        raise BenchmarkAnalysisError("protocol.repetitions must be a positive integer")
    hashes = summary.get("artifact_hashes")
    if not isinstance(hashes, dict):
        raise BenchmarkAnalysisError("artifact_hashes must be an object")
    for name, expected in sorted(hashes.items()):
        if name in ("summary.json", "run_summary.json"):
            raise BenchmarkAnalysisError("Root summary cannot hash itself")
        if (not isinstance(expected, str) or len(expected) != 64
                or any(character not in "0123456789abcdefABCDEF" for character in expected)):
            raise BenchmarkAnalysisError(f"Malformed SHA256 for {name!r}")
        path = _safe_path(root, name)
        actual = _sha256(path)
        if actual != expected.lower():
            raise BenchmarkAnalysisError(f"Artifact SHA256 mismatch: {name}")
    trial_names = summary.get("trials")
    if (not isinstance(trial_names, list) or any(not isinstance(name, str) for name in trial_names)
            or len(set(trial_names)) != len(trial_names)):
        raise BenchmarkAnalysisError("trials must be a list of unique relative directories")
    trials = []
    seen = set()
    for name in trial_names:
        directory = _safe_path(root, name, directory=True)
        artifact_name = f"{name}/trial_summary.json"
        if artifact_name not in hashes:
            raise BenchmarkAnalysisError(f"Trial summary is not hash-declared: {artifact_name}")
        trial = _json(_safe_path(root, artifact_name))
        mode, workload = trial.get("mode"), trial.get("workload")
        rate, repetition = trial.get("rate_pps"), trial.get("repetition")
        block_id = trial.get("block_id")
        if mode not in MODES or workload not in WORKLOADS:
            raise BenchmarkAnalysisError(f"Unrecognized mode/workload in {directory}")
        if not _finite(rate) or rate <= 0 or rate not in rates:
            raise BenchmarkAnalysisError(f"Trial rate is absent from the protocol in {directory}")
        if type(repetition) is not int or repetition < 0:
            raise BenchmarkAnalysisError(f"Trial repetition must be a nonnegative integer in {directory}")
        if not isinstance(block_id, str) or not block_id:
            raise BenchmarkAnalysisError(f"Trial block_id must be a nonempty string in {directory}")
        key = (mode, workload, rate, block_id)
        if key in seen:
            raise BenchmarkAnalysisError(f"Duplicate mode within paired block: {key}")
        seen.add(key)
        if type(trial.get("valid")) is not bool:
            raise BenchmarkAnalysisError(f"Trial valid must be boolean in {directory}")
        failures = trial.get("failures")
        if not isinstance(failures, list) or any(not isinstance(item, str) for item in failures):
            raise BenchmarkAnalysisError(f"Trial failures must be a string list in {directory}")
        raw_metrics = trial.get("metrics")
        if not isinstance(raw_metrics, dict):
            raise BenchmarkAnalysisError(f"Trial metrics must be an object in {directory}")
        metrics, warnings = {}, []
        for metric in NUMERIC_METRICS:
            value = raw_metrics.get(metric)
            metrics[metric] = value if _finite(value) else None
            if value is not None and not _finite(value):
                warnings.append(f"{metric}: nonfinite or nonnumeric value excluded")
        for metric in QUALITY_METRICS:
            value = raw_metrics.get(metric)
            if value is not None and type(value) is not bool:
                raise BenchmarkAnalysisError(f"{metric} must be boolean or null in {directory}")
            metrics[metric] = value
        if metrics["clock_valid"] is not True:
            for metric in LATENCY_METRICS:
                if metrics[metric] is not None:
                    warnings.append(f"{metric}: excluded because clock validity is not true")
                metrics[metric] = None
            metrics["output_kernel_interarrival_pps"] = None
        trials.append({"trial_directory": name, "mode": mode, "workload": workload,
                       "rate_pps": rate, "repetition": repetition, "block_id": block_id,
                       "valid": trial["valid"], "failures": failures, "metrics": metrics,
                       "data_warnings": warnings})
    integrity = {"declared_artifacts_verified": len(hashes),
                 "algorithm": "sha256", "summary_file": summary_paths[0].name,
                 "summary_sha256": _sha256(summary_paths[0]),
                 "trial_summaries_hash_declared": True,
                 "limitation": "Hashes detect artifact changes relative to an unsigned manifest; the root summary is not self-hashed."}
    return root, summary, trials, integrity


def load_run(run_dir: str | Path) -> tuple[dict, list[dict]]:
    """Runner compatibility API: integrity-checked root summary and trial rows."""
    _, summary, trials, _ = verify_run(run_dir)
    return summary, trials


def _percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    left = math.floor(position)
    right = math.ceil(position)
    return ordered[left] + (ordered[right] - ordered[left]) * (position - left)


def _seed(seed: int, label: Any) -> int:
    payload = json.dumps([seed, label], sort_keys=True, separators=(",", ":"))
    return int.from_bytes(hashlib.sha256(payload.encode("utf-8")).digest()[:16], "big")


def summarize_trials(values: list, *, seed: int, bootstrap_samples: int = 5000) -> dict:
    """Finite trial values; sample SD and seeded percentile bootstrap CIs.

    n=1 has a degenerate descriptive bootstrap interval, not evidence of zero
    population variability. Every result with n<5 is explicitly exploratory.
    """
    if type(bootstrap_samples) is not int or bootstrap_samples < 1:
        raise ValueError("bootstrap_samples must be a positive integer")
    sample = [float(value) for value in values if _finite(value)]
    n = len(sample)
    result = {field: None for field in SUMMARY_FIELDS}
    result.update(n_metric=n, exploratory=n < 5)
    if not sample:
        return result
    result.update(mean=statistics.fmean(sample), median=statistics.median(sample),
                  std=statistics.stdev(sample) if n > 1 else None,
                  minimum=min(sample), maximum=max(sample))
    generator = random.Random(seed)
    means, medians = [], []
    if n == 1:
        means = medians = [sample[0]]
    else:
        for _ in range(bootstrap_samples):
            resampled = generator.choices(sample, k=n)
            means.append(statistics.fmean(resampled))
            medians.append(statistics.median(resampled))
    result.update(mean_ci95_low=_percentile(means, .025),
                  mean_ci95_high=_percentile(means, .975),
                  median_ci95_low=_percentile(medians, .025),
                  median_ci95_high=_percentile(medians, .975))
    return result


def aggregate_groups(trials: list[dict], protocol: dict, *, bootstrap_samples: int = 5000) -> list[dict]:
    """Include unattempted protocol groups with n=0; use only valid trials."""
    buckets = defaultdict(list)
    for trial in trials:
        buckets[(trial["mode"], trial["workload"], trial["rate_pps"])].append(trial)
    groups = []
    for workload in WORKLOADS:
        for rate in sorted(protocol["rates_pps"]):
            for mode in MODES:
                attempted = buckets[(mode, workload, rate)]
                valid = [trial for trial in attempted if trial["valid"]]
                metrics = {}
                for metric in NUMERIC_METRICS:
                    values = [trial["metrics"].get(metric) for trial in valid]
                    metrics[metric] = summarize_trials(values,
                        seed=_seed(protocol["seed"], [mode, workload, rate, metric]),
                        bootstrap_samples=bootstrap_samples)
                groups.append({"mode": mode, "workload": workload, "rate_pps": rate,
                               "n_attempted": len(attempted), "n_valid": len(valid),
                               "exploratory": len(valid) < 5, "metrics": metrics})
    return groups


def paired_comparisons(trials: list[dict], protocol: dict, *, bootstrap_samples: int = 5000) -> list[dict]:
    """Match B/C by block_id within workload/rate; resample paired differences."""
    buckets = defaultdict(lambda: defaultdict(dict))
    for trial in trials:
        if trial["mode"] in ("rf_b", "rf_c"):
            group = buckets[(trial["workload"], trial["rate_pps"])]
            group[trial["block_id"]][trial["mode"]] = trial
    comparisons = []
    for workload in WORKLOADS:
        for rate in sorted(protocol["rates_pps"]):
            blocks = buckets[(workload, rate)]
            valid = {block: pair for block, pair in blocks.items()
                     if "rf_b" in pair and "rf_c" in pair
                     and pair["rf_b"]["valid"] and pair["rf_c"]["valid"]}
            pair_values = []
            for block, pair in sorted(valid.items()):
                absolute, percent = {}, {}
                for metric in NUMERIC_METRICS:
                    b, c = (pair[mode]["metrics"].get(metric) for mode in ("rf_b", "rf_c"))
                    usable = _finite(b) and _finite(c)
                    absolute[metric] = float(c) - float(b) if usable else None
                    percent[metric] = 100 * (float(c) - float(b)) / float(b) if usable and b != 0 else None
                pair_values.append({"block_id": block, "absolute_c_minus_b": absolute,
                                    "percent_c_minus_b_over_b": percent})
            metrics = {}
            for metric in NUMERIC_METRICS:
                metrics[metric] = {}
                for name in ("absolute_c_minus_b", "percent_c_minus_b_over_b"):
                    values = [pair[name][metric] for pair in pair_values]
                    metrics[metric][name] = summarize_trials(values,
                        seed=_seed(protocol["seed"], ["paired", workload, rate, metric, name]),
                        bootstrap_samples=bootstrap_samples)
            comparisons.append({"workload": workload, "rate_pps": rate,
                "n_attempted_blocks": len(blocks), "n_valid_pairs": len(valid),
                "n_excluded_blocks": len(blocks) - len(valid),
                "exploratory": len(valid) < 5, "metrics": metrics, "pairs": pair_values})
    return comparisons


def controlled_extension_eligibility(trials: list[dict], protocol: dict) -> dict:
    """Report a human-reviewed extension gate; never schedule or send traffic."""
    initial_rate = 5000
    gates = []
    for workload in WORKLOADS:
        for mode in MODES:
            attempted = [trial for trial in trials if trial["mode"] == mode
                         and trial["workload"] == workload and trial["rate_pps"] == initial_rate]
            valid = [trial for trial in attempted if trial["valid"]]
            reasons = []
            if len(valid) < 5:
                reasons.append("Fewer than five valid trials at the initial 5000 pps rate")
            # Any observed loss/anomaly at the initial rate makes extension
            # ineligible; selecting only the successful repetitions is unsafe.
            for trial in attempted:
                metrics = trial["metrics"]
                failed = []
                for metric in ("loss_fraction", "packets_lost", "packets_duplicated", "packets_reordered"):
                    if not _finite(metrics.get(metric)) or metrics[metric] != 0:
                        failed.append(f"{metric} is not verified zero")
                if not _finite(metrics.get("received_pps")) or metrics["received_pps"] < .98 * initial_rate:
                    failed.append("received_pps is below 98% of the target or unavailable")
                for metric in QUALITY_METRICS:
                    if metrics.get(metric) is not True:
                        failed.append(f"{metric} is not true")
                if failed:
                    reasons.append(f"{trial['trial_directory']}: " + "; ".join(failed))
            gates.append({"mode": mode, "workload": workload, "rate_pps": initial_rate,
                          "n_attempted": len(attempted), "n_valid": len(valid),
                          "eligible": not reasons, "reasons": reasons})
    return {"eligible": initial_rate in protocol["rates_pps"] and all(gate["eligible"] for gate in gates),
            "initial_rate_pps": initial_rate, "groups": gates, "automated_extension": False,
            "meaning": "Eligibility is a prerequisite for a separately reviewed controlled extension, not proof of saturation or available capacity. CPU utilization is not a saturation test."}


def extension_eligibility(rows: list[dict]) -> dict:
    """Runner compatibility API; inspect recorded rows, never extend a run."""
    return controlled_extension_eligibility(rows, {"rates_pps": sorted({row["rate_pps"] for row in rows})})


def _csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_tables(output: Path, trials: list[dict], groups: list[dict], pairs: list[dict]) -> None:
    trial_fields = ["trial_directory", "mode", "workload", "rate_pps", "repetition", "block_id",
                    "valid", "failures", "data_warnings", *NUMERIC_METRICS, *QUALITY_METRICS]
    rows = []
    for trial in trials:
        row = {key: trial[key] for key in trial_fields if key in trial}
        row.update(trial["metrics"])
        for key in ("failures", "data_warnings"):
            row[key] = json.dumps(trial[key], ensure_ascii=False)
        rows.append(row)
    _csv(output / "per_trial.csv", rows, trial_fields)
    fields = ["mode", "workload", "rate_pps", "n_attempted", "n_valid", "metric", *SUMMARY_FIELDS]
    rows = []
    for group in groups:
        for metric, summary in group["metrics"].items():
            rows.append({key: group[key] for key in fields if key in group} | {"metric": metric} | summary)
    _csv(output / "group_statistics.csv", rows, fields)
    fields = ["workload", "rate_pps", "n_attempted_blocks", "n_valid_pairs", "n_excluded_blocks",
              "metric", "comparison", *SUMMARY_FIELDS]
    rows = []
    for pair in pairs:
        for metric, comparisons in pair["metrics"].items():
            for comparison, summary in comparisons.items():
                rows.append({key: pair[key] for key in fields if key in pair}
                            | {"metric": metric, "comparison": comparison} | summary)
    _csv(output / "paired_statistics.csv", rows, fields)
    invalid = [{"trial_directory": trial["trial_directory"], "mode": trial["mode"],
                "workload": trial["workload"], "rate_pps": trial["rate_pps"],
                "block_id": trial["block_id"],
                "failures": json.dumps(trial["failures"], ensure_ascii=False)}
               for trial in trials if not trial["valid"]]
    _csv(output / "invalid_trials.csv", invalid,
         ["trial_directory", "mode", "workload", "rate_pps", "block_id", "failures"])


def _figures(output: Path, groups: list[dict], pairs: list[dict], trials: list[dict]) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator

    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                         "savefig.dpi": 300, "figure.dpi": 120})
    folder = output / "figures"
    folder.mkdir()
    artifacts = []

    def save(figure, name):
        figure.tight_layout()
        for suffix in ("png", "pdf"):
            path = folder / f"{name}.{suffix}"
            figure.savefig(path, dpi=300, bbox_inches="tight")
            artifacts.append(path.relative_to(output).as_posix())
        plt.close(figure)

    def line_panels(specifications, name, title):
        fig, axes = plt.subplots(len(WORKLOADS), len(specifications), squeeze=False,
                                 figsize=(5 * len(specifications), 3.6 * len(WORKLOADS)))
        for row, workload in enumerate(WORKLOADS):
            for col, (metric, label) in enumerate(specifications):
                ax = axes[row][col]
                available = False
                for mode in MODES:
                    points = sorted([group for group in groups if group["mode"] == mode
                                     and group["workload"] == workload
                                     and group["metrics"][metric]["n_metric"] > 0],
                                    key=lambda group: group["rate_pps"])
                    if not points:
                        continue
                    available = True
                    rates = [point["rate_pps"] for point in points]
                    means = [point["metrics"][metric]["mean"] for point in points]
                    lower = [max(0, mean - point["metrics"][metric]["mean_ci95_low"])
                             for mean, point in zip(means, points)]
                    upper = [max(0, point["metrics"][metric]["mean_ci95_high"] - mean)
                             for mean, point in zip(means, points)]
                    ax.errorbar(rates, means, yerr=[lower, upper], label=mode,
                                color=COLORS[mode], marker="o", capsize=3, linewidth=1.4)
                if not available:
                    ax.text(.5, .5, "No valid measured values", ha="center", va="center", transform=ax.transAxes)
                ax.set_title(workload)
                ax.set_xlabel("Configured offered rate (packets/s)")
                ax.set_ylabel(label)
                ax.grid(alpha=.22)
                if available:
                    ax.legend(fontsize=8)
        fig.suptitle(title + "\nMeans and trial-bootstrap 95% intervals; n<5 is exploratory", fontsize=11)
        save(fig, name)

    line_panels([("received_pps", "Drain-inclusive received packets/s"),
                 ("ethernet_mbps", "Received Ethernet frame Mbit/s"),
                 ("output_kernel_interarrival_pps", "Output kernel interarrival packets/s")],
                "throughput_vs_rate", "Observed throughput")
    line_panels([("delay_median_us", "Trial median delay (us)"), ("delay_p95_us", "Trial p95 delay (us)"),
                 ("delay_p99_us", "Trial p99 delay (us)")], "latency_vs_rate", "Kernel software timestamp path delays")
    line_panels([("bmv2_cpu_one_core_percent", "BMv2 CPU (% of one core)"),
                 ("runner_cpu_one_core_percent", "Runner CPU (% of one core)")], "cpu_vs_rate", "Measured process CPU")
    line_panels([("bmv2_rss_peak_mib", "BMv2 sampled peak RSS (MiB)"),
                 ("bmv2_hwm_mib", "BMv2 lifetime high-water RSS (MiB)")], "rss_vs_rate", "Observed BMv2 resident memory")
    metrics = [("received_pps", "Received packets/s"), ("delay_median_us", "Median delay (us)"),
               ("delay_p95_us", "p95 delay (us)"), ("delay_p99_us", "p99 delay (us)"),
               ("bmv2_cpu_one_core_percent", "BMv2 CPU (percentage points)"),
               ("bmv2_rss_peak_mib", "Peak RSS (MiB)")]
    fig, axes = plt.subplots(2, 3, figsize=(14, 8), squeeze=False)
    for ax, (metric, label) in zip(axes.flat, metrics):
        found = False
        for index, workload in enumerate(WORKLOADS):
            points = [pair for pair in pairs if pair["workload"] == workload
                      and pair["metrics"][metric]["absolute_c_minus_b"]["n_metric"] > 0]
            if not points:
                continue
            found = True
            means = [pair["metrics"][metric]["absolute_c_minus_b"]["mean"] for pair in points]
            errors = [[max(0, mean - pair["metrics"][metric]["absolute_c_minus_b"]["mean_ci95_low"])
                       for mean, pair in zip(means, points)],
                      [max(0, pair["metrics"][metric]["absolute_c_minus_b"]["mean_ci95_high"] - mean)
                       for mean, pair in zip(means, points)]]
            ax.errorbar([pair["rate_pps"] for pair in points], means, yerr=errors,
                        marker=("o", "s")[index], capsize=3, label=workload)
        ax.axhline(0, color="#666666", linewidth=.7)
        ax.set_xlabel("Configured offered rate (packets/s)")
        ax.set_ylabel("C - B: " + label)
        ax.grid(alpha=.22)
        if found:
            ax.legend(fontsize=8)
        else:
            ax.text(.5, .5, "No valid matched pairs", ha="center", va="center", transform=ax.transAxes)
    fig.suptitle("Within-block RF-C minus RF-B differences\nMean paired differences and paired-trial bootstrap 95% intervals; n<5 is exploratory", fontsize=11)
    save(fig, "paired_c_minus_b")
    reasons = Counter()
    for trial in trials:
        if not trial["valid"]:
            for reason in set(trial["failures"] or ["Invalid trial without a recorded reason"]):
                reasons[reason] += 1
    ordered = sorted(reasons.items(), key=lambda item: (-item[1], item[0]))
    fig, ax = plt.subplots(figsize=(12, max(3, .4 * len(ordered) + 1.5)))
    if ordered:
        ax.barh(range(len(ordered)), [count for _, count in ordered], color="#9a4d44")
        ax.set_yticks(range(len(ordered)), labels=[reason for reason, _ in ordered], fontsize=8)
        ax.invert_yaxis()
    else:
        ax.text(.5, .5, "No invalid trials recorded", ha="center", va="center", transform=ax.transAxes)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlabel("Invalid trials recording each reason (a trial can have several reasons)")
    ax.set_title("Instrument quality exclusions")
    save(fig, "invalid_quality_counts")
    return artifacts


def _display(value: Any) -> str:
    return "unavailable" if value is None else f"{value:.6g}" if _finite(value) else str(value)


def _metric_cell(summary: dict) -> str:
    if summary["n_metric"] == 0:
        return "unavailable (n=0)"
    return (f"{_display(summary['mean'])} [{_display(summary['mean_ci95_low'])}, "
            f"{_display(summary['mean_ci95_high'])}] (n={summary['n_metric']})")


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _report(analysis: dict) -> str:
    protocol, trials = analysis["protocol"], analysis["trials"]
    valid = sum(trial["valid"] for trial in trials)
    text = ["# Performance benchmark analysis", "",
            f"Run: `{analysis['run_directory']}`. Recorded run status: `{analysis['run_status']}`.", "",
            f"{len(trials)} attempted trials; {valid} instrument-valid; {len(trials) - valid} excluded. "
            f"Verified {analysis['integrity']['declared_artifacts_verified']} SHA256 artifacts before analysis. "
            "The unsigned root manifest is not a provenance signature.", "",
            f"Protocol: rates {protocol['rates_pps']} packets/s; measured duration "
            f"{protocol['duration_seconds']} s; warmup {protocol['warmup_seconds']} s; "
            f"{protocol['repetitions']} requested repetitions; seed {protocol['seed']}.", "",
            "## Statistical interpretation", "",
            "Each observation is one trial. Group statistics include only instrument-valid trials, "
            "including trustworthy observed output loss. Loss alone does not invalidate a trial. "
            "No packet observation is treated as an independent replicate. `n_attempted`, `n_valid`, "
            "and each metric's `n_metric` disclose the denominators. Missing/nonfinite metrics and "
            "delays without a valid clock are excluded only from the affected statistic.", "",
            f"CIs are seeded percentile bootstrap 95% intervals with {analysis['bootstrap']['resamples']} "
            "resamples over trials, for both means and medians. Sample standard deviation uses n-1 "
            "and is unavailable for n<2. Results with fewer than five usable trials/pairs are exploratory. "
            "A one-trial bootstrap interval collapses to the observed value and cannot estimate population variability. "
            "These intervals do not establish equivalence, causality, saturation, or absence of a difference.", "",
            "RF-B/C comparisons match exact block_id within each workload/rate and require both trials "
            "to be valid. Absolute changes are C-B; percentage changes are 100*(C-B)/B within each "
            "pair, then summarized across pairs. A zero B value has an absolute change but no percentage "
            "change. Each metric's paired n is disclosed. Bootstrap resamples paired differences together.", "",
            "## Metric denominators and limits", "",
            "Offered packets/s is packets sent divided by the actual measured sender-window duration. "
            "Received packets/s uses unique output packets, including the bounded capture drain, divided "
            "by that same measured window; it is not a drain-window or interarrival-rate measurement. "
            "A large backlog delivered during the drain can overstate throughput delivered within the "
            "sender window. Successful drain-inclusive delivery alone cannot prove sustainable capacity. "
            "The supplementary output_kernel_interarrival_pps is (N-1)/(last-first) over usable output "
            "kernel timestamps when the clock is valid; it uses a different denominator and is not "
            "substituted for the primary window metric. Queue drain and this supplementary rate must "
            "be considered when interpreting degradation or capacity. "
            "Ethernet Mbit/s uses observed received Ethernet frame bytes and 8/1,000,000 over that window; "
            "it excludes Ethernet FCS, preamble, and interpacket gap. Loss fraction is unique missing "
            "output packets / sent packets when the input capture and capture-drop audits are trustworthy.", "",
            "Delay is the paired input/output Linux kernel software timestamp difference for exact frame "
            "observations. The delay percentiles are calculated within each trial before trial aggregation; "
            "no percentile is calculated by pooling packet observations from different trials. Missing paired "
            "timestamps or a failed clock audit prevent usable delay metrics. Userspace receive scheduling "
            "is not a latency observation. The virtual/native clocks and scheduler are part of this path.", "",
            "BMv2 and runner CPU each use process CPU-seconds / measured wall-seconds * 100, where "
            "100% means one CPU core; more than 100% can occur for multiple threads. Runner CPU is "
            "reported separately from BMv2 CPU. Sampled peak RSS is a measured-window sample maximum; "
            "VmHWM is the process lifetime high-water mark and can include warmup. Neither is an "
            "isolated model memory measurement. RF decision rate uses observed decision-count delta "
            "/ measured wall-seconds; forwarding/features modes have no RF decision rate.", "",
            "This run concerns BMv2 software forwarding in the recorded host/WSL environment. It is "
            "not an ASIC measurement, a NIC hardware timestamp measurement, or isolated inference timing. "
            "Host load, virtualization, packet capture, and scheduling can affect both offered traffic and "
            "the observed path. Low CPU utilization is not proof of unsaturated forwarding capacity.", "",
            "The classification-heavy and cached-forwarding labels describe workload construction; "
            "they do not claim classification accuracy or real-world dataset representativeness. Both "
            "RF modes perform direction extraction. Their comparison includes the forests and their "
            "execution paths; it does not isolate standalone direction-extraction cost.", "",
            "## Group counts", "",
            "| Workload | Rate (pps) | Mode | Attempted | Valid | Interpretation |",
            "|---|---:|---|---:|---:|---|"]
    for group in analysis["groups"]:
        text.append(f"| {group['workload']} | {group['rate_pps']} | {group['mode']} | "
                    f"{group['n_attempted']} | {group['n_valid']} | "
                    f"{'exploratory' if group['exploratory'] else 'at least five valid trials'} |")
    text += ["", "Full metric summaries and mean/median intervals are in `group_statistics.csv`. "
             "The figures show only recorded run observations with usable metrics.", "",
             "## Observed trial results", "",
             "Each cell is the mean of usable trial values [bootstrap 95% CI] (metric n). "
             "Latency columns average each trial's stated percentile; they do not pool packets.", "",
             "| Workload | Rate (pps) | Mode | Received packets/s | Loss fraction | Mean trial median delay (us) | Mean trial p95 (us) | Mean trial p99 (us) |",
             "|---|---:|---|---|---|---|---|---|"]
    for group in analysis["groups"]:
        cells = [_metric_cell(group["metrics"][metric]) for metric in
                 ("received_pps", "loss_fraction", "delay_median_us", "delay_p95_us", "delay_p99_us")]
        text.append(f"| {group['workload']} | {group['rate_pps']} | {group['mode']} | " + " | ".join(cells) + " |")
    text += ["", "| Workload | Rate (pps) | Mode | BMv2 CPU (% of one core) | Runner CPU (% of one core) | BMv2 sampled peak RSS (MiB) |",
             "|---|---:|---|---|---|---|"]
    for group in analysis["groups"]:
        cells = [_metric_cell(group["metrics"][metric]) for metric in
                 ("bmv2_cpu_one_core_percent", "runner_cpu_one_core_percent", "bmv2_rss_peak_mib")]
        text.append(f"| {group['workload']} | {group['rate_pps']} | {group['mode']} | " + " | ".join(cells) + " |")
    text += ["",
             "## Paired RF-C/RF-B counts", "",
             "| Workload | Rate (pps) | Attempted blocks | Valid pairs | Excluded blocks |",
             "|---|---:|---:|---:|---:|"]
    for pair in analysis["paired_comparisons"]:
        text.append(f"| {pair['workload']} | {pair['rate_pps']} | {pair['n_attempted_blocks']} | "
                    f"{pair['n_valid_pairs']} | {pair['n_excluded_blocks']} |")
    text += ["", "Metric-specific absolute and percentage denominators are in `paired_statistics.csv`. "
             "The following cells are means of within-pair changes [bootstrap 95% CI] (paired metric n).", "",
             "| Workload | Rate (pps) | Received C-B (pps) | Trial p99 C-B (%) | BMv2 CPU C-B (%) | Peak RSS C-B (MiB) |",
             "|---|---:|---|---|---|---|"]
    for pair in analysis["paired_comparisons"]:
        specifications = [("received_pps", "absolute_c_minus_b"), ("delay_p99_us", "percent_c_minus_b_over_b"),
                          ("bmv2_cpu_one_core_percent", "percent_c_minus_b_over_b"),
                          ("bmv2_rss_peak_mib", "absolute_c_minus_b")]
        cells = [_metric_cell(pair["metrics"][metric][comparison]) for metric, comparison in specifications]
        text.append(f"| {pair['workload']} | {pair['rate_pps']} | " + " | ".join(cells) + " |")
    text += ["",
             "## Invalid trials and recorded reasons", "",
             "| Trial | Mode | Workload | Rate (pps) | Reasons |", "|---|---|---|---:|---|"]
    invalid = [trial for trial in trials if not trial["valid"]]
    for trial in invalid:
        text.append(f"| {_md(trial['trial_directory'])} | {trial['mode']} | {trial['workload']} | "
                    f"{trial['rate_pps']} | {_md('; '.join(trial['failures']) or 'No recorded reason')} |")
    if not invalid:
        text.append("| None | | | | No invalid trials recorded |")
    warnings = [(trial["trial_directory"], warning) for trial in trials for warning in trial["data_warnings"]]
    if warnings:
        text += ["", "## Metric availability warnings", "", "| Trial | Warning |", "|---|---|"]
        for trial, warning in warnings:
            text.append(f"| {_md(trial)} | {_md(warning)} |")
    extension = analysis["controlled_extension"]
    text += ["", "## Controlled extension eligibility", "",
             f"Initial 5000 pps gate: **{'eligible for separate review' if extension['eligible'] else 'not eligible'}**. "
             "No extension is automated. Every mode/workload requires at least five valid trials, "
             "verified zero loss/duplication/reordering, received throughput at least 98% of target, "
             "and valid pacing/clock observations at the initial rate. Any recorded initial-rate "
             "trial that fails these checks prevents eligibility. Eligibility does not prove saturation.", "",
             "| Workload | Mode | Valid at 5000 pps | Eligible | Reasons |", "|---|---|---:|---|---|"]
    for gate in extension["groups"]:
        text.append(f"| {gate['workload']} | {gate['mode']} | {gate['n_valid']} | {gate['eligible']} | "
                    f"{_md('; '.join(gate['reasons']) or 'All initial-rate checks passed')} |")
    text += ["", "## Artifacts", "",
             "`per_trial.csv` retains every trial, including invalid trials and its reasons. "
             "`invalid_trials.csv` is the exclusion table. `analysis.json` retains all statistics, "
             "paired values, integrity results, and gate reasons. PNG figures are rendered at 300 dpi; "
             "each figure also has a PDF.", ""]
    for name in analysis["figure_artifacts"]:
        if name.endswith(".png"):
            text += [f"![{Path(name).stem.replace('_', ' ')}]({name})", ""]
    return "\n".join(text)


def analyze_run(run_dir: str | Path, output_root: str | Path | None = None, *, bootstrap_samples: int = 5000) -> Path:
    """Create a new unique offline analysis folder; raw input is never written."""
    if type(bootstrap_samples) is not int or bootstrap_samples < 1:
        raise BenchmarkAnalysisError("bootstrap_samples must be a positive integer")
    root, summary, trials, integrity = verify_run(run_dir)
    destination = Path(output_root or "results/performance_benchmark_analysis").absolute()
    for parent in (destination, *destination.parents):
        _reject_link(parent)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise BenchmarkAnalysisError("Analysis output must be outside the raw run directory")
    groups = aggregate_groups(trials, summary["protocol"], bootstrap_samples=bootstrap_samples)
    pairs = paired_comparisons(trials, summary["protocol"], bootstrap_samples=bootstrap_samples)
    extension = controlled_extension_eligibility(trials, summary["protocol"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = destination / f"analysis-{stamp}-{secrets.token_hex(4)}"
    output.mkdir(parents=True, exist_ok=False)
    analysis = {"schema_version": "performance-benchmark-analysis-v1", "run_directory": str(root),
                "run_status": summary["status"], "prepared_directory": summary.get("prepared_directory"),
                "created_utc": datetime.now(timezone.utc).isoformat(), "protocol": summary["protocol"],
                "integrity": integrity,
                "bootstrap": {"resamples": bootstrap_samples, "seed": summary["protocol"]["seed"],
                              "unit": "trial or within-block paired trial difference", "method": "percentile",
                              "confidence": .95, "statistics": ["mean", "median"]},
                "trials": trials, "groups": groups, "paired_comparisons": pairs,
                "controlled_extension": extension}
    _write_tables(output, trials, groups, pairs)
    analysis["figure_artifacts"] = _figures(output, groups, pairs, trials)
    (output / "analysis.json").write_text(json.dumps(analysis, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (output / "report.md").write_text(_report(analysis), encoding="utf-8")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path, help="Existing raw benchmark run directory")
    parser.add_argument("--output-root", default=Path("results/performance_benchmark_analysis"), type=Path)
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    arguments = parser.parse_args(argv)
    try:
        output = analyze_run(arguments.run, arguments.output_root, bootstrap_samples=arguments.bootstrap_samples)
    except (BenchmarkAnalysisError, OSError, ImportError) as error:
        parser.exit(2, f"Analysis failed: {error}\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
