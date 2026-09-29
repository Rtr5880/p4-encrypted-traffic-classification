#!/usr/bin/env python3
"""Read-only sensitivity audit of idle timeouts; no features, training or splits.

Import the COMMITTED pilot's decoder so eligibility does not silently change.
An idle boundary is tested before adding the arriving packet. It starts a new
candidate instance, whose first-N window starts with that packet. Every eligible
packet refreshes last-seen, including packets after the classification prefix.
"""

import argparse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

import extract_feature_pilot as pilot


WINDOWS = pilot.WINDOWS
DELAY_LIMITS_US = (1_000, 10_000, 100_000, 1_000_000, 10_000_000,
                   60_000_000, 120_000_000)


def policy_name(seconds):
    return "no_timeout" if seconds is None else f"idle_{seconds}s"


@dataclass
class Instance:
    """Constant-size state, not a list of all packets or all past instances."""

    index: int
    first_frame: int
    first_us: int
    count: int = 0
    last_frame: int = 0
    last_us: int = 0
    prefixes: dict = field(default_factory=dict)

    def add(self, packet, effective_us):
        self.count += 1
        self.last_frame, self.last_us = packet.frame, effective_us
        if self.count in WINDOWS:
            self.prefixes[self.count] = (packet.frame, effective_us - self.first_us)


@dataclass
class Parent:
    """One capture-scoped bidirectional tuple, shared across timeout policies."""

    identity: str
    last_raw_ns: int
    effective_ns: int
    count: int = 0
    instances: dict = field(default_factory=dict)
    max_gap_us: int = 0


def empty_stats():
    return {
        "instances": 0, "idle_boundaries": 0, "packets_accounted_for": 0,
        "windows": {str(n): {
            "records": 0, "short_instances": 0,
            "short_instances_closed_by_idle": 0,
            "short_instances_at_capture_end": 0,
            "packets_in_eligible_instances": 0,
            "original_prefixes_retained": 0, "original_prefixes_split": 0,
            "observation_delay_us_sum": 0, "observation_delay_us_max": 0,
            "observation_delay_histogram": {
                "upper_bounds_us_inclusive": list(DELAY_LIMITS_US),
                "counts": [0] * (len(DELAY_LIMITS_US) + 1),
            },
        } for n in WINDOWS},
    }


class Audit:
    """Stream each eligible packet through all candidate policies exactly once."""

    def __init__(self, capture, seconds, instance_stream, max_conversations=50000):
        if not seconds or len(seconds) > 8 or any(type(s) is not int or s < 1 for s in seconds):
            raise ValueError("Provide between 1 and 8 positive integer idle thresholds")
        if len(set(seconds)) != len(seconds):
            raise ValueError("Duplicate idle thresholds are not allowed")
        if max_conversations < 1:
            raise ValueError("max_conversations must be positive")
        self.capture = capture
        self.thresholds = {"no_timeout": None}
        self.thresholds.update({policy_name(s): s * 1_000_000 for s in sorted(seconds)})
        self.stats = {name: empty_stats() for name in self.thresholds}
        self.parents = {}
        self.stream = instance_stream
        self.max_conversations = max_conversations
        self.finished = False
        self.raw_backward_steps = 0
        self.timestamp_adjustments = 0
        self.max_timestamp_adjustment_ns = 0
        self.eligible_packets = 0

    def close_instance(self, parent, name, instance, reason):
        stats = self.stats[name]
        stats["instances"] += 1
        stats["packets_accounted_for"] += instance.count
        stats["idle_boundaries"] += reason == "idle_boundary"
        windows = {}
        for n in WINDOWS:
            window = stats["windows"][str(n)]
            if n in instance.prefixes:
                frame, delay = instance.prefixes[n]
                window["records"] += 1
                window["packets_in_eligible_instances"] += instance.count
                window["observation_delay_us_sum"] += delay
                window["observation_delay_us_max"] = max(window["observation_delay_us_max"], delay)
                bucket = next((i for i, limit in enumerate(DELAY_LIMITS_US) if delay <= limit),
                              len(DELAY_LIMITS_US))
                window["observation_delay_histogram"]["counts"][bucket] += 1
                windows[str(n)] = {"eligible": True, "decision_frame": frame,
                                   "observation_delay_us": delay}
            else:
                window["short_instances"] += 1
                field_name = ("short_instances_closed_by_idle" if reason == "idle_boundary"
                              else "short_instances_at_capture_end")
                window[field_name] += 1
                windows[str(n)] = {"eligible": False}
        record = {
            "evaluation_only": True, "training_ready": False,
            "capture_id": self.capture["capture_id"], "capture_sha256": self.capture["sha256"],
            "provisional_class": self.capture["initial_class"], "policy": name,
            "parent_candidate_conversation_id": parent.identity,
            "instance_id": f"{parent.identity}:{name}:{instance.index}",
            "instance_index": instance.index, "eligible_packets": instance.count,
            "first_frame": instance.first_frame, "last_frame": instance.last_frame,
            "first_effective_us": instance.first_us, "last_effective_us": instance.last_us,
            "close_reason": reason, "windows": windows,
        }
        self.stream.write(json.dumps(record, separators=(",", ":")) + "\n")

    def add(self, packet):
        if self.finished:
            raise ValueError("Cannot add packets to a finished audit")
        key = pilot.make_key(packet)
        parent = self.parents.get(key)
        gap_us = None
        if parent is None:
            if len(self.parents) >= self.max_conversations:
                raise ValueError("Conversation memory guard reached; no silent data loss")
            identity = json.dumps([self.capture["capture_id"], self.capture["sha256"], key],
                                  separators=(",", ":"))
            parent = Parent(hashlib.sha256(identity.encode()).hexdigest(),
                            packet.timestamp_ns, packet.timestamp_ns)
            self.parents[key] = parent
        else:
            # Repair derived time only. Keep the same parent clock across policies
            # and boundaries; do not sort packets or modify the original capture.
            self.raw_backward_steps += packet.timestamp_ns < parent.last_raw_ns
            effective_ns = max(parent.effective_ns, packet.timestamp_ns)
            adjustment = effective_ns - packet.timestamp_ns
            self.timestamp_adjustments += adjustment > 0
            self.max_timestamp_adjustment_ns = max(self.max_timestamp_adjustment_ns, adjustment)
            gap_us = effective_ns // 1000 - parent.effective_ns // 1000
            parent.max_gap_us = max(parent.max_gap_us, gap_us)
            parent.last_raw_ns, parent.effective_ns = packet.timestamp_ns, effective_ns
        effective_us = parent.effective_ns // 1000
        parent.count += 1
        self.eligible_packets += 1
        for name, limit_us in self.thresholds.items():
            instance = parent.instances.get(name)
            if instance is None:
                instance = Instance(1, packet.frame, effective_us)
                parent.instances[name] = instance
            elif limit_us is not None and gap_us >= limit_us:
                # The packet that reveals expiry belongs to the NEW instance.
                self.close_instance(parent, name, instance, "idle_boundary")
                instance = Instance(instance.index + 1, packet.frame, effective_us)
                parent.instances[name] = instance
            instance.add(packet, effective_us)
            if parent.count in WINDOWS:
                metric = "original_prefixes_retained" if instance.index == 1 else "original_prefixes_split"
                self.stats[name]["windows"][str(parent.count)][metric] += 1

    def finish(self):
        if self.finished:
            raise ValueError("Audit already finished")
        self.finished = True
        for parent in self.parents.values():
            for name, instance in parent.instances.items():
                # End-of-file is right-censoring, NOT proof of connection closure.
                self.close_instance(parent, name, instance, "capture_end")
        for stats in self.stats.values():
            if stats["packets_accounted_for"] != self.eligible_packets:
                raise ValueError("Packet conservation check failed")
            if stats["instances"] != len(self.parents) + stats["idle_boundaries"]:
                raise ValueError("Instance conservation check failed")
            for n in WINDOWS:
                window = stats["windows"][str(n)]
                original = self.stats["no_timeout"]["windows"][str(n)]["records"]
                if window["records"] + window["short_instances"] != stats["instances"]:
                    raise ValueError("Window accounting check failed")
                if window["original_prefixes_retained"] + window["original_prefixes_split"] != original:
                    raise ValueError("Original prefix accounting check failed")
        return {
            "filename": self.capture["filename"], "capture_id": self.capture["capture_id"],
            "capture_sha256": self.capture["sha256"],
            "provisional_class": self.capture["initial_class"],
            "candidate_conversations": len(self.parents), "eligible_packets": self.eligible_packets,
            "timing": {
                "raw_backward_steps": self.raw_backward_steps,
                "timestamp_adjustments": self.timestamp_adjustments,
                "max_timestamp_adjustment_ns": self.max_timestamp_adjustment_ns,
                "largest_gap_us": max((p.max_gap_us for p in self.parents.values()), default=0),
            },
            "policies": self.stats,
        }


def read_capture(command, directory, capture, seconds, max_conversations):
    rejected, total = Counter(), 0
    with (directory / "instances.jsonl").open("x", encoding="utf-8") as instances, \
            (directory / "tshark.stderr.log").open("x", encoding="utf-8") as stderr, \
            (directory / "field_parse_errors.jsonl").open("x", encoding="utf-8") as errors:
        audit = Audit(capture, seconds, instances, max_conversations)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
                                   text=True, encoding="utf-8", errors="strict")
        try:
            for line in process.stdout:
                total += 1
                values = line.rstrip("\r\n").split("\t")
                packet, reason = pilot.decode_fields(values)
                if packet is not None:
                    audit.add(packet)
                else:
                    rejected[reason] += 1
                    if reason.startswith("missing_or_invalid_header_field:") and rejected[reason] <= 3:
                        name = reason.split(":", 1)[1]
                        errors.write(json.dumps({"frame": values[0][:160], "field": name,
                            "raw_value": values[pilot.FIELDS.index(name)][:160]}) + "\n")
                if total % 100000 == 0:
                    print(f"  Read {total:,} frames; {len(audit.parents):,} candidate conversations", flush=True)
            code = process.wait()
            if code:
                raise ValueError(f"TShark exited with code {code}; inspect {directory / 'tshark.stderr.log'}")
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
        if not audit.parents:
            raise ValueError(f"No eligible conversations among {total} frames; rejections: {dict(rejected)}")
        result = audit.finish()
    result.update(frames_read=total, rejected_frames_by_first_reason=dict(sorted(rejected.items())))
    if total != result["eligible_packets"] + sum(rejected.values()):
        raise ValueError("Capture accounting check failed")
    return result


def select_names(manifest, names, all_included):
    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported capture inventory schema")
    rows = manifest["captures"]
    filenames = [row["filename"] for row in rows]
    if len(filenames) != len(set(filenames)):
        raise ValueError("Inventory contains ambiguous duplicate filenames")
    if all_included:
        selected = [row["filename"] for row in rows if row.get("include_in_baseline") is True]
    else:
        selected = names
    if not selected or len(selected) != len(set(selected)):
        raise ValueError("Select one or more distinct included captures")
    for name in selected:
        if name not in filenames:
            raise ValueError(f"Capture not inventoried: {name}")
        row = rows[filenames.index(name)]
        if row.get("include_in_baseline") is not True or not row.get("initial_class"):
            raise ValueError(f"Capture excluded or missing provisional class: {name}")
    return selected


def print_comparison(result):
    print(f"\n{result['filename']} (provisional {result['provisional_class']})")
    print(f"{'Policy':<14} {'Instances':>10} {'N4 records':>11} {'N4 short':>9} {'N8 records':>11} {'N8 short':>9} {'Original N8 split':>18}")
    for name, stats in result["policies"].items():
        w4, w8 = stats["windows"]["4"], stats["windows"]["8"]
        print(f"{name:<14} {stats['instances']:>10} {w4['records']:>11} {w4['short_instances']:>9} "
              f"{w8['records']:>11} {w8['short_instances']:>9} {w8['original_prefixes_split']:>18}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path.home() / "p4/etc-training/metadata/capture_inventory.json")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--capture", action="append", help="Repeat for several inventoried filenames")
    selection.add_argument("--all-included", action="store_true", help="Audit every included capture, one at a time")
    parser.add_argument("--idle-seconds", type=int, nargs="+", default=[30, 60, 120])
    parser.add_argument("--output-root", type=Path, default=Path.home() / "p4/etc-training/results/idle_timeout")
    parser.add_argument("--max-conversations", type=int, default=50000)
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args(argv)
    directory = None
    try:
        # Validate resource parameters before reading a real capture or making output.
        import io
        Audit({}, args.idle_seconds, io.StringIO(), args.max_conversations)
        manifest_path = args.manifest.expanduser()
        _, manifest_hash = pilot.fingerprint(manifest_path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        names = select_names(manifest, args.capture, args.all_included)
        version = subprocess.run([args.tshark, "--version"], capture_output=True, text=True,
                                 encoding="utf-8", check=True).stdout
        root = args.output_root.expanduser()
        root.mkdir(parents=True, exist_ok=True)
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:10]
        directory = root / run_id
        directory.mkdir(exist_ok=False)
        pilot.write_json(directory / "policy.json", {
            "schema_version": 1, "evaluation_only": True, "training_ready": False,
            "manifest_sha256": manifest_hash, "captures": names,
            "idle_seconds": sorted(args.idle_seconds), "no_timeout_baseline_included": True,
            "boundary_rule": "Before arrival: floor(effective_now_ns/1000) - floor(previous_effective_ns/1000) >= idle_seconds * 1000000",
            "clock": "Per capture-scoped bidirectional tuple running maximum in integer ns; shared by all policies; originals never modified",
            "last_seen": "Every eligible packet, including ACKs, retransmissions and all packets after N",
            "window": "One opening first-N prefix per candidate instance per N=4 or N=8 experiment; no rolling windows",
            "first_packet": "The packet revealing an idle boundary starts the new instance; no gap inherited from the old instance",
            "label_policy": "capture-only; provisional activity hints, not verified ground truth",
            "hard_timeout": None, "tcp_syn_fin_rst_handling": False,
            "observation_delay": "Effective time of Nth eligible packet minus first; not model inference latency",
            "original_prefixes_split": "No-timeout first-N prefixes containing at least one tested idle boundary; denominators differ from all new-instance records",
            "capture_end": "Right-censored; not proof of TCP or application-session termination",
            "p4_implementation_verified": False, "automatic_timeout_selection": False,
            "split_warning": "Related candidate instances may be dependent; timeout segmentation does not establish session independence",
            "max_conversations": args.max_conversations, "tshark_version": version,
            "evaluator_sha256": pilot.fingerprint(Path(__file__))[1],
            "pilot_sha256": pilot.fingerprint(Path(pilot.__file__))[1],
        })
        print("IDLE-TIMEOUT EVALUATION ONLY: originals unchanged; no model fitting or feature exports.", flush=True)
        results = []
        for index, name in enumerate(names, 1):
            print(f"\n[{index}/{len(names)}] {name}", flush=True)
            if pilot.fingerprint(manifest_path)[1] != manifest_hash:
                raise ValueError("Inventory changed during evaluation")
            capture, path, before = pilot.select_capture(manifest_path, name)
            capture_dir = directory / f"capture_{index:03d}"
            capture_dir.mkdir(exist_ok=False)
            command = [args.tshark, "-n", "-r", str(path), "-T", "fields",
                       "-E", "occurrence=a", "-E", "aggregator=,"]
            for name_field in pilot.FIELDS:
                command.extend(["-e", name_field])
            pilot.write_json(capture_dir / "source.json", {"capture": capture, "tshark_command": command})
            result = read_capture(command, capture_dir, capture, args.idle_seconds, args.max_conversations)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("Capture changed during evaluation; results rejected")
            result["evidence_directory"] = capture_dir.name
            results.append(result)
            print_comparison(result)
        if pilot.fingerprint(manifest_path)[1] != manifest_hash:
            raise ValueError("Inventory changed during evaluation")
        pilot.write_json(directory / "summary.json", {
            "status": "evaluation_complete", "evaluation_only": True, "training_ready": False,
            "captures_evaluated": len(results), "captures": results,
            "warning": "Idle-only sensitivity audit, not validated sessions. More records do not imply greater accuracy. No timeout selected.",
        })
        print(f"\nEvidence saved to: {directory}")
        print("EVALUATION COMPLETE — NOT TRAINING-READY; no timeout chosen.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        if directory is not None:
            pilot.write_json(directory / "failure.json", {"status": "failed", "training_ready": False, "error": str(error)})
        print(f"ERROR: {error}", file=sys.stderr)
        if directory is not None:
            print(f"Incomplete diagnostic output only: {directory}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
