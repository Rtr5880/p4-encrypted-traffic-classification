#!/usr/bin/env python3
"""Read-only recovery of an interrupted RAW calibration into a fresh directory.

Never finalizes, overwrites or adds files to the historical acquisition. Hashes
establish the evidence read for this recovery and detect concurrent changes;
they cannot retroactively authenticate an acquisition lacking a final seal.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from pathlib import Path
import secrets
import stat

SCHEMA = "raw-calibration-recovery-v1"
MODES = ("forwarding", "features", "rf_b", "rf_c")
WORKLOADS = ("classification-heavy", "cached-forwarding")
RATE_GATES = ("offered_load", "delivered_throughput", "classification_rate", "cpu")
RATE_METRICS = ("offered_pps", "delivered_pps", "delivered_ethernet_mbps",
                "decision_rate_pps", "bmv2_cpu_one_core_percent", "runner_cpu_one_core_percent")


class RecoveryError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise RecoveryError(message)


def read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"),
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (OSError, UnicodeError, ValueError) as error:
        raise RecoveryError(f"Cannot read valid JSON: {path}: {error}") from error
    require(isinstance(value, dict), f"JSON object required: {path}")
    return value


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot(root):
    require(root.is_dir() and not root.is_symlink(), "Source must be a real evidence directory")
    for parent in root.parents:
        require(not parent.is_symlink(), "Symlink evidence parent is not allowed")
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"Symlink evidence artifact is not allowed: {path}")
        if stat.S_ISSOCK(path.lstat().st_mode):
            require(path.name == 'notifications.ipc' and path.parent.parent == root
                    and path.parent.name.startswith('trial_'),
                    f"Unexpected nonregular evidence artifact: {path}")
            # BMv2 leaves an inert UNIX notification endpoint. Never open/read,
            # connect to, remove or pretend to SHA256-hash it; retain metadata.
            continue
        require(path.is_dir() or path.is_file(), f"Nonregular evidence artifact: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sha256(path)
    require(result, "No evidence artifacts found")
    return result


def notification_metadata(root):
    result = {}
    for path in sorted(root.glob('trial_*/notifications.ipc')):
        details = path.lstat()
        if stat.S_ISSOCK(details.st_mode):
            result[path.relative_to(root).as_posix()] = dict(
                kind='unix_notification_socket', inode=details.st_ino,
                device=details.st_dev, mode=details.st_mode, mtime_ns=details.st_mtime_ns,
                content_hashed=False, endpoint_accessed=False)
    return result


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def equal(actual, expected, name):
    if number(actual) and number(expected):
        require(math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9),
                f"Inconsistent {name}: {actual!r} versus {expected!r}")
    else:
        require(actual == expected, f"Inconsistent {name}: {actual!r} versus {expected!r}")


def _phase(observation, plan, label):
    count = plan["packet_count"]
    require(type(count) is int and count > 0, f"Invalid plan count: {label}")
    equal(observation["planned_packets"], count, label + " planned count")
    sent = observation["sent_packets"]
    require(type(sent) is int and 0 <= sent <= count, f"Invalid sent count: {label}")
    packets = observation["per_packet"]
    for name in ("input_occurrences", "output_occurrences", "send_start_raw_ns", "send_finish_raw_ns"):
        require(isinstance(packets.get(name), list) and len(packets[name]) == count,
                f"Invalid per-packet array: {label}/{name}")
    for endpoint in ("input", "output"):
        occurrences = packets[endpoint + "_occurrences"]
        require(all(type(n) is int and n >= 0 for n in occurrences), f"Invalid occurrences: {label}")
        unique = sum(n > 0 for n in occurrences)
        equal(observation[f"captured_{endpoint}_unique"], unique, label + " unique " + endpoint)
        equal(observation[f"missing_{endpoint}_sequences"],
              [index for index, n in enumerate(occurrences) if n == 0], label + " missing " + endpoint)
        equal(observation["capture_counters"][endpoint]["duplicates"],
              sum(max(0, n - 1) for n in occurrences), label + " duplicate " + endpoint)
    equal(sum(value is not None for value in packets["send_start_raw_ns"]), sent,
          label + " observed sends")
    require(type(observation["reduced_quality_valid"]) is bool and
            isinstance(observation["reduced_quality_reasons"], list), "Invalid local quality verdict")
    equal(observation["reduced_quality_valid"], not observation["reduced_quality_reasons"],
          label + " quality reasons")
    require(observation["kernel_timestamp_diagnostics"]["qualified_for_performance_claims"] is False,
            "Recovery cannot qualify kernel forwarding latency")
    pacing = observation["pacing_quality"]
    equal(pacing["maximum_send_lateness_limit_ns"],
          max(5_000_000, 3 * pacing["nominal_interval_ns"]), label + " unchanged pacing maximum")


def _counter(counts, plan, mode, label):
    if not mode.startswith("rf_"):
        require(counts["packets"] is None and counts["bytes"] is None and
                counts["rf_inference_present"] is False, f"Invented RF counters: {label}")
        return
    require(counts["rf_inference_present"] is True, f"Missing RF counters: {label}")
    deltas = counts["class_counter_deltas"]
    require(isinstance(deltas, list) and len(deltas) == 6, f"Six RF class counters required: {label}")
    for before, after, delta in zip(counts["before"], counts["after"], deltas):
        for key in ("packets", "bytes"):
            require(type(delta[key]) is int and delta[key] >= 0, f"Invalid RF delta: {label}")
            equal(delta[key], after[key] - before[key], label + " counter delta")
    equal(counts["packets"], sum(row["packets"] for row in deltas), label + " decisions")
    equal(counts["bytes"], sum(row["bytes"] for row in deltas), label + " decision bytes")
    equal(counts["bytes"], counts["packets"] * plan["frame_bytes"], label + " byte multiplier")
    equal(counts["expected_packets"], plan["expected_classifications"], label + " expected decisions")
    require(0 <= counts["packets"] <= counts["expected_packets"], f"Excess decisions: {label}")


def _resource_summary(resources):
    result = {}
    for who in ("bmv2", "runner"):
        item = resources[who]
        require(item["clock_domain"] == "CLOCK_MONOTONIC_RAW", "Wrong resource clock")
        duration = item["raw_duration_seconds"]
        require(number(duration) and duration > 0, "Invalid resource window")
        cpu, memory = item["cpu"], item["memory"]
        if cpu["valid"]:
            equal(cpu["seconds"], (cpu["user_ticks_delta"] + cpu["system_ticks_delta"]) /
                  cpu["clock_ticks_per_second"], who + " OS CPU seconds")
            equal(cpu["percent_one_core"], cpu["seconds"] / duration * 100, who + " CPU percent")
        if memory["valid"]:
            equal(memory["rss_max_sampled_mib"], memory["rss_max_sampled_kib"] / 1024, who + " RSS")
            equal(memory["vmhwm_lifetime_mib"], memory["vmhwm_lifetime_kib"] / 1024, who + " HWM")
        result[who] = {key: deepcopy(value) for key, value in item.items() if key != "samples"}
    return result


def _trial(path):
    row = read_json(path / "trial_summary.json")
    require(row["mode"] in MODES and row["workload"] in WORKLOADS and row["rate_pps"] in (100, 1000),
            "Unknown RAW calibration configuration")
    require(row["kernel_forwarding_latency_qualified"] is False and row["accuracy_scored"] is False,
            "Historical trial is not the reduced performance protocol")
    observation = read_json(path / "measurement.json")
    warmup = read_json(path / "warmup_measurement.json")
    provenance = read_json(path / "provenance.json")
    resources = read_json(path / "resources.json")
    counts = read_json(path / "counter_check.json")
    warm_counts = read_json(path / "warmup_counter_check.json")
    equal(provenance["mode"], row["mode"], "mode provenance")
    for field in ("rate_pps", "block_id", "workload"):
        equal(provenance["block"][field], row[field], "block provenance " + field)
    measured, warm = provenance["measurement"], provenance["warmup"]
    for phase, plan, label, counter in ((observation, measured, "measurement", counts),
                                        (warmup, warm, "warmup", warm_counts)):
        _phase(phase, plan, label)
        _counter(counter, plan, row["mode"], label)
    if row["mode"].startswith("rf_"):
        equal(counts["before"], warm_counts["after"], "warm-up / measurement counter boundary")
        equal(counts["before"], read_json_counter(path / "counter_before.json"), "saved counter before")
        equal(counts["after"], read_json_counter(path / "counter_after.json"), "saved counter after")
    warm_slots = {flow["slot"] for flow in warm["flow_tuples"]}
    measured_slots = {flow["slot"] for flow in measured["flow_tuples"]}
    require(not warm_slots & measured_slots, "Warm-up slots contaminate measurement")
    resource_summary = _resource_summary(resources)
    duration = observation["throughput"]["raw_sender_window_seconds"]
    require(number(duration) and duration > 0, "Invalid RAW offered window")
    metrics = row["metrics"]
    expected = {"packets_sent": observation["sent_packets"],
                "packets_received": observation["captured_output_unique"],
                "packets_lost": len(observation["missing_output_sequences"]),
                "packets_duplicated": observation["capture_counters"]["output"]["duplicates"],
                "packets_reordered": observation["capture_counters"]["output"]["sequence_regressions"],
                "raw_window_seconds": duration, "decisions": counts["packets"],
                "target_pps": row["rate_pps"],
                "offered_pps": observation["sent_packets"] / duration,
                "delivered_pps": observation["captured_output_unique"] / duration,
                "delivered_ethernet_mbps": observation["captured_output_unique"] * measured["frame_bytes"] * 8 / duration / 1e6,
                "decision_rate_pps": counts["packets"] / duration if counts["packets"] is not None else None}
    for who in ("bmv2", "runner"):
        cpu = resources[who]["cpu"]
        expected[who + "_cpu_seconds"] = cpu["seconds"] if cpu["valid"] else None
        expected[who + "_cpu_one_core_percent"] = cpu["percent_one_core"] if cpu["valid"] else None
    for name, value in expected.items():
        equal(metrics[name], value, "trial metric " + name)
    warm_ok = warmup["reduced_quality_valid"] and warm_counts["capacity_accounting_passed"]
    require(type(row["valid"]) is bool and row["valid"] == row["instrument_valid_before_rate_qualification"],
            "Expected original pre-qualification local verdict")
    require(not row["valid"] or (observation["reduced_quality_valid"] and warm_ok),
            "Passing trial contradicts failed phase evidence")
    require(row["valid"] == (not row["failures"]), "Local validity contradicts failure reasons")
    return {"trial_directory": path.name, "original_trial_summary": row,
            "measurement_resource_summary": resource_summary,
            "phase_quality": {"warmup": _phase_quality(warmup), "measurement": _phase_quality(observation)},
            "counter_checks": {"warmup": warm_counts, "measurement": counts}}


def read_json_counter(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RecoveryError(f"Invalid counter report: {path}") from error
    if isinstance(value, dict):
        require(value.get('returncode') == 0 and isinstance(value.get('stdout'), str),
                "Failed or malformed historical CLI counter query")
        matches = re.findall(r'FeatureIngress\.rf_decisions\[(\d+)\]=\s*\((\d+) bytes, (\d+) packets\)',
                             value['stdout'])
        require(len(matches) == 6 and {int(index) for index, _, _ in matches} == set(range(6)),
                "Six complete unique saved CLI counters required")
        return [dict(bytes=int(byte_count), packets=int(packet_count))
                for _, byte_count, packet_count in sorted(matches, key=lambda row: int(row[0]))]
    require(isinstance(value, list) and len(value) == 6, "Six saved counters required")
    return value


def _phase_quality(observation):
    return {"local_quality_valid": observation["reduced_quality_valid"],
            "local_quality_reasons": deepcopy(observation["reduced_quality_reasons"]),
            "pacing": {key: deepcopy(value) for key, value in observation["pacing_quality"].items()
                       if not isinstance(value, list)},
            "raw_clock_audit": {key: deepcopy(value) for key, value in observation["raw_clock_audit"].items()
                                if not isinstance(value, list)},
            "capture_counters": deepcopy(observation["capture_counters"]),
            "capture_statistics": deepcopy(observation["capture_statistics"]),
            "sent_packets": observation["sent_packets"],
            "received_packets": observation["captured_output_unique"],
            "kernel_latency": {"qualified": False,
                               "original_diagnostic_file": "measurement.json / warmup_measurement.json",
                               "reasons": deepcopy(observation["kernel_timestamp_diagnostics"].get("reasons", []))}}


def markdown(report):
    lines = ["# Interrupted RAW calibration — separate recovery report", "",
             "The original acquisition is unchanged. This recovery is not a successful calibration, capacity benchmark, classification-accuracy result or latency measurement.", "",
             f"Source: `{report['source_run']}`", "",
             f"Recovered {report['attempted_trials']} original trial reports: {report['local_valid_trials']} local PASS, {report['local_failed_trials']} local FAIL. Final historical campaign summary was absent.", "",
             f"Independent RAW qualification: **{report['clock_rate_qualification']['status']}**. " +
             ("Absolute throughput, offered/decision rates and CPU percentages below are **unqualified diagnostic estimates**, excluded from qualified claims." if not report['raw_rate_qualified']
              else "Qualified individual metric gates are retained, but this unfinished historical campaign remains incomplete."), "",
             f"Highest attempted load: **{report['highest_attempted_pps']} pps**. Highest locally accepted measurement-window target: **{report['highest_locally_accepted_pps']} pps**. The saved qualification object's representative-load target is **{report['qualification_representative_target_pps']} pps**; these are not interchangeable.", "",
             "| Trial | Mode / workload | Target pps | Sent / received / missing | Decisions | Offered / delivered pps (unqualified) | BMv2 OS CPU seconds | RSS / lifetime HWM MiB | Local result |",
             "|---|---|---:|---|---:|---|---:|---|---|"]
    for item in report["trials"]:
        row, metrics = item["original_trial_summary"], item["original_trial_summary"]["metrics"]
        decision = "N/A" if metrics["decisions"] is None else str(metrics["decisions"])
        lines.append(f"| {item['trial_directory']} | {row['mode']} / {row['workload']} | {row['rate_pps']} | {metrics['packets_sent']} / {metrics['packets_received']} / {metrics['packets_lost']} | {decision} | {metrics['offered_pps']:.6f} / {metrics['delivered_pps']:.6f} | {metrics['bmv2_cpu_seconds']} | {metrics.get('bmv2_rss_peak_mib')} / {metrics.get('bmv2_hwm_mib')} | {'PASS' if row['valid'] else 'FAIL'} |")
    lines += ["", "## Preserved phase-quality findings", ""]
    for item in report["trials"]:
        for phase, quality in item["phase_quality"].items():
            pacing = quality["pacing"]
            maximum = pacing["send_completion_lateness_summary_ns"]["maximum"]
            limit = pacing["maximum_send_lateness_limit_ns"]
            if not quality["local_quality_valid"]:
                lines += [f"### {item['trial_directory']} — {phase}", "",
                          f"Maximum send-completion upper-bound lateness: **{maximum / 1e6:.6f} ms**, allowed **{limit / 1e6:.6f} ms**; excess **{max(0, maximum-limit) / 1e6:.6f} ms**.", "",
                          "Reasons: " + "; ".join(quality["local_quality_reasons"]), ""]
    lines += ["## Independent timing references", "",
              "| Provider | Status | Estimate ppm | Lower / upper ppm | Representative-load queries | Reasons |",
              "|---|---|---:|---|---:|---|"]
    for name, provider in report["clock_rate_qualification"].get("providers", {}).items():
        rate = provider.get("raw_rate", {})
        lines.append(f"| {name} | {provider.get('status')} | {rate.get('midpoint_estimate_ppm')} | {rate.get('lower_ppm')} / {rate.get('upper_ppm')} | {provider.get('representative_load_queries')} | {'; '.join(provider.get('reasons', []))} |")
    no_loaded_query = any(provider.get("representative_load_queries", 0) == 0
                          for provider in report["clock_rate_qualification"].get("providers", {}).values())
    lines += ["", "## Interpretation and preservation", "",
              "The warm-up failure remains a failure even when the separate measurement phase passes. Complete packet delivery does not override pacing qualification. " +
              ("At least one required independent reference has no complete query inside accepted measurement windows; numerical campaign-average rate bounds alone do not meet the under-load requirement." if no_loaded_query else
               "Required reference-window overlap counts remain in the original qualification object; no new timing acquisition is performed by recovery."), "",
              "Packet counts and separately valid RF counter deltas remain observations. Linux OS-accounted CPU seconds are not independently calibrated physical CPU time. RSS maximum is sampled; lifetime VmHWM may include warm-up. Delivered-rate estimates use the offered RAW window and include bounded capture drain.", "",
              "RF-B and RF-C both extract direction features; this comparison does not isolate direction-extraction cost. Kernel timestamp evidence and its warnings remain in the original files. No p50/p95/p99 forwarding delay, isolated inference latency, saturation or maximum-capacity claim is derived.", "",
              f"SHA256 verified before and after recovery for **{report['preservation']['original_artifacts']} original artifacts**. The new hash snapshot detects changes during recovery but cannot retroactively authenticate an unfinished historical acquisition. All original summaries, values, failure reasons and qualification records remain available at their unchanged paths.", "",
              f"Retained metadata for **{len(report['preservation']['original_notification_endpoint_metadata'])} existing UNIX notification endpoints**. Socket endpoints are not byte files and cannot be SHA256-hashed; they were not opened, connected to or removed. Their metadata was verified unchanged before/after recovery.", "",
              "Recommendation: fix finalization and under-load query scheduling, investigate the original pacing samples, then use a separately prepared manual calibration. Do not relax the five-millisecond gate or reuse this acquisition as qualified benchmark evidence.", ""]
    return "\n".join(lines)


def recover(run, output=None):
    root = Path(run).absolute()
    before = snapshot(root)
    before_notifications = notification_metadata(root)
    require("summary.json" not in before, "Use the standard analyzer for a finalized acquisition")
    qualification = read_json(root / "clock_rate_qualification.json")
    require(qualification.get("status") in ("PASS", "FAIL", "INCONCLUSIVE"), "Invalid qualification status")
    require(type(qualification.get("passed")) is bool and
            qualification["passed"] == (qualification["status"] == "PASS"), "Inconsistent qualification verdict")
    require(qualification.get("criterion_ppm") == 1000, "Changed independent-reference tolerance")
    read_json(root / "provenance.json")
    paths = sorted(path for path in root.iterdir() if path.name.startswith("trial_") and path.is_dir())
    require(paths and all((path / "trial_summary.json").is_file() for path in paths),
            "Incomplete or missing original trial reports")
    try:
        trials = [_trial(path) for path in paths]
    except (KeyError, TypeError, IndexError, ZeroDivisionError) as error:
        raise RecoveryError(f"Malformed or incomplete trial evidence: {error}") from error
    require(len({(item["original_trial_summary"]["mode"], item["original_trial_summary"]["block_id"])
                 for item in trials}) == len(trials), "Duplicate mode/block observations")
    qualified = qualification["passed"]
    for item in trials:
        original = item["original_trial_summary"]
        item["effective_metric_validity"] = deepcopy(original["metric_validity"])
        if not qualified or not original["valid"]:
            for gate in RATE_GATES:
                item["effective_metric_validity"][gate] = False
        metric_gates = {"offered_pps": "offered_load", "delivered_pps": "delivered_throughput",
                        "delivered_ethernet_mbps": "delivered_throughput", "decision_rate_pps": "classification_rate",
                        "bmv2_cpu_one_core_percent": "cpu", "runner_cpu_one_core_percent": "cpu"}
        item["qualified_rate_claims"] = {key: (original["metrics"].get(key)
                                              if item["effective_metric_validity"].get(metric_gates[key]) else None)
                                         for key in RATE_METRICS}
    report = {"schema_version": SCHEMA, "source_run": str(root),
              "historical_final_summary_absent": True, "historical_campaign_finalization_success": False,
              "passed": False, "raw_rate_qualified": qualified,
              "attempted_trials": len(trials), "local_valid_trials": sum(item["original_trial_summary"]["valid"] for item in trials),
              "local_failed_trials": sum(not item["original_trial_summary"]["valid"] for item in trials),
              "highest_attempted_pps": max(item["original_trial_summary"]["rate_pps"] for item in trials),
              "highest_locally_accepted_pps": max((item["original_trial_summary"]["rate_pps"] for item in trials
                                                  if item["original_trial_summary"]["valid"]), default=None),
              "qualification_representative_target_pps": qualification.get("representative_load_target_pps"),
              "clock_rate_qualification": qualification, "trials": trials,
              "kernel_forwarding_latency_qualified": False, "isolated_inference_latency_measured": False,
              "new_fits": 0, "accuracy_scored": False,
              "preservation": {"original_artifacts": len(before), "hashes_before_after_equal": True,
                               "original_notification_endpoint_metadata": before_notifications,
                               "notification_metadata_before_after_equal": True,
                               "retroactive_authentication_claimed": False},
              "decision": "Incomplete historical attempt; preserve failures. No full sweep approved or launched."}
    require(snapshot(root) == before and notification_metadata(root) == before_notifications,
            "Original evidence changed while being read; recovery refused")
    folder = (Path(output).absolute() if output is not None else root.parent /
              ("recovery_" + root.name + "_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + secrets.token_hex(4)))
    require(folder.resolve() != root.resolve() and root.resolve() not in folder.resolve().parents,
            "Recovery output must be separate, not inside or equal to original evidence")
    for parent in (folder, *folder.parents):
        require(not parent.is_symlink(), "Symlink recovery output path is not allowed")
    require(folder.parent.is_dir(), "Recovery output parent must already exist")
    require(not folder.exists(), "Recovery output already exists; never overwrite it")
    folder.mkdir(exist_ok=False)
    for name, data in (("report.json", report), ("original_artifact_hashes.json", before)):
        with (folder / name).open("x", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, allow_nan=False)
            stream.write("\n")
    with (folder / "report.md").open("x", encoding="utf-8") as stream:
        stream.write(markdown(report))
    require(snapshot(root) == before and notification_metadata(root) == before_notifications,
            "Original evidence changed during output generation; recovery untrusted")
    return folder


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = recover(args.run, args.output)
    except (OSError, RecoveryError) as error:
        print(f"RECOVERY REFUSED: {error}")
        return 2
    print(f"SEPARATE RECOVERY SAVED: {result}\nOriginal acquisition unchanged; failures and unqualified rates preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
