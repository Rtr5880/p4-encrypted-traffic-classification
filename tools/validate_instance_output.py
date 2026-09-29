#!/usr/bin/env python3
"""Read-only independent arithmetic/schema checks on an instance-extractor run.

This does not validate activity labels, capture truth, session independence,
TCP protocol correctness, split design or live P4/BMv2 equivalence.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys


B = ("size_min", "size_max", "size_sum", "iat_min", "iat_max", "iat_sum")
C = B + ("reverse_packet_count", "direction_change_count")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rows(path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def verify_features(record, n):
    """Compute from arrays independently of the extractor's incremental updates."""
    require(record["n"] == n, "Wrong N")
    require(record["training_ready"] is False, "Unverified records marked training-ready")
    require(set(record["features_B"]) == set(B), "B feature allowlist mismatch")
    require(set(record["features_C"]) == set(C), "C feature allowlist mismatch")
    for value in list(record["features_B"].values()) + list(record["features_C"].values()):
        require(type(value) is int and value >= 0, "Features must be nonnegative integers")
    debug = record["debug_metadata_not_model_inputs"]
    trace = debug["trace"]
    require(len(trace) == n, "Wrong trace length")
    sizes, times, directions, frames = [], [], [], []
    for item in trace:
        require(type(item["size_bytes"]) is int and 0 < item["size_bytes"] <= 65535, "Invalid trace size")
        require(type(item["raw_timestamp_ns"]) is int and item["raw_timestamp_ns"] >= 0, "Invalid timestamp")
        require(type(item["timestamp_adjustment_ns"]) is int and item["timestamp_adjustment_ns"] >= 0, "Invalid correction")
        effective = (item["raw_timestamp_ns"] + item["timestamp_adjustment_ns"]) // 1000
        require(item["effective_timestamp_us"] == effective, "Timestamp quantisation mismatch")
        require(item["direction"] in ("F", "R"), "Invalid direction")
        require(type(item["frame"]) is int and item["frame"] > 0, "Invalid frame")
        sizes.append(item["size_bytes"])
        times.append(effective)
        directions.append(item["direction"])
        frames.append(item["frame"])
    require(directions[0] == "F", "Orientation was not reset at instance start")
    require(all(a < b for a, b in zip(frames, frames[1:])), "Trace frame order is invalid")
    gaps = [b - a for a, b in zip(times, times[1:])]
    require(all(g >= 0 for g in gaps), "Negative effective IAT")
    require(trace[0]["iat_us"] is None, "Artificial initial IAT")
    require([item["iat_us"] for item in trace[1:]] == gaps, "Trace IAT mismatch")
    expected = dict(zip(C, (min(sizes), max(sizes), sum(sizes), min(gaps), max(gaps), sum(gaps),
        directions.count("R"), sum(a != b for a, b in zip(directions, directions[1:])))))
    require(record["features_C"] == expected, "Feature arithmetic mismatch")
    require(record["features_B"] == {k: expected[k] for k in B}, "B/C shared features differ")
    require(expected["size_sum"] < 2**19 and all(expected[k] < 2**48 for k in B if k.startswith("iat_")), "Feature width exceeded")
    require(debug["first_frame"] == frames[0] and debug["decision_frame"] == frames[-1], "Decision/frame provenance mismatch")
    require(frames[-1] <= debug["last_frame"] and times[-1] <= debug["last_effective_us"], "Prefix extends beyond instance")
    require(debug["first_effective_us"] == times[0], "First timestamp mismatch")
    require(debug["observation_delay_us"] == sum(gaps), "Observation-delay mismatch")
    require(debug["prefix_timestamp_adjustments"] == sum(t["timestamp_adjustment_ns"] > 0 for t in trace), "Prefix correction count mismatch")
    return trace


def validate_run(directory):
    directory = Path(directory).resolve()
    require(not (directory / "failure.json").exists(), "Run is marked failed")
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    policy = json.loads((directory / "policy.json").read_text(encoding="utf-8"))
    require(summary["status"] == "instance_extraction_complete", "Incomplete or wrong run type")
    require(summary["training_ready"] is False and policy["training_ready"] is False, "Unexpected training-ready claim")
    require(policy["features_B"] == list(B) and policy["features_C"] == list(C), "Policy allowlist mismatch")
    require(summary["captures_evaluated"] == len(summary["captures"]), "Capture count mismatch")
    require(sorted(policy["captures"]) == sorted(c["filename"] for c in summary["captures"]), "Capture selection mismatch")
    total_records = Counter()
    total_instances = 0
    all_parent_ids = set()
    capture_ids = set()
    for capture in summary["captures"]:
        require(capture["capture_id"] not in capture_ids, "Duplicate capture identity")
        capture_ids.add(capture["capture_id"])
        child_name = capture["evidence_directory"]
        require(re.fullmatch(r"capture_\d{3,}", child_name) is not None, "Invalid evidence directory")
        child = directory / child_name
        require(child.resolve().parent == directory, "Evidence directory escapes run")
        source = json.loads((child / "source.json").read_text(encoding="utf-8"))["capture"]
        require(source["capture_id"] == capture["capture_id"] and source["sha256"] == capture["capture_sha256"], "Source provenance mismatch")
        instances = {}
        parents = set()
        starts, ends = Counter(), Counter()
        for item in rows(child / "instances.jsonl"):
            iid = item["instance_id"]
            require(iid not in instances, "Duplicate instance ID")
            require(item["training_ready"] is False, "Unexpected training-ready instance")
            require(item["capture_id"] == capture["capture_id"] and item["capture_sha256"] == capture["capture_sha256"], "Cross-capture provenance mismatch")
            require(item["label"] == capture["provisional_class"] and item["label_basis"] == "capture_activity_hint", "Label provenance mismatch")
            require(item["policy_id"] == f"{policy['policy_version']}:{policy['boundary_policy']}:{policy['idle_seconds']}s", "Boundary policy mismatch")
            require(iid == f"{item['parent_candidate_conversation_id']}:{item['policy_id']}:{item['instance_index']}", "Instance identity mismatch")
            debug = item["debug_metadata_not_model_inputs"]
            require(type(debug["eligible_packets"]) is int and debug["eligible_packets"] > 0, "Empty instance")
            require(debug["first_frame"] <= debug["last_frame"], "Instance frame bounds invalid")
            starts[debug["start_reason"]] += 1
            ends[debug["end_reason"]] += 1
            instances[iid] = item
            parents.add(item["parent_candidate_conversation_id"])
        require(not (parents & all_parent_ids), "Parent identity reused across captures")
        all_parent_ids.update(parents)
        require(len(instances) == capture["instances"] and len(parents) == capture["candidate_conversations"], "Instance/parent totals mismatch")
        require(sum(x["debug_metadata_not_model_inputs"]["eligible_packets"] for x in instances.values()) == capture["eligible_packets"], "Packet conservation failed")
        require(capture["frames_read"] == capture["eligible_packets"] + sum(capture["rejected_frames_by_first_reason"].values()), "Rejected-frame accounting failed")
        require(dict(starts) == capture["start_reasons"] and dict(ends) == capture["end_reasons"], "Boundary count mismatch")
        n4_traces = {}
        for n in (4, 8):
            seen, delay_sum, delay_max, corrected = set(), 0, 0, 0
            for record in rows(child / f"features_n{n}.jsonl"):
                iid = record["instance_id"]
                require(iid in instances and iid not in seen, "Unknown or duplicate feature instance")
                seen.add(iid)
                require(record["record_id"] == f"{iid}:n{n}", "Record identity mismatch")
                for key, value in instances[iid].items():
                    if key != "debug_metadata_not_model_inputs":
                        require(record[key] == value, f"Record metadata mismatch: {key}")
                for key, value in instances[iid]["debug_metadata_not_model_inputs"].items():
                    require(record["debug_metadata_not_model_inputs"][key] == value, f"Record debug mismatch: {key}")
                trace = verify_features(record, n)
                require(instances[iid]["debug_metadata_not_model_inputs"]["eligible_packets"] >= n, "Short instance exported")
                if n == 4:
                    n4_traces[iid] = trace
                else:
                    require(n4_traces.get(iid) == trace[:4], "N4/N8 opening packets differ")
                debug = record["debug_metadata_not_model_inputs"]
                delay_sum += debug["observation_delay_us"]
                delay_max = max(delay_max, debug["observation_delay_us"])
                corrected += debug["prefix_timestamp_adjustments"] > 0
            expected = {iid for iid, item in instances.items() if item["debug_metadata_not_model_inputs"]["eligible_packets"] >= n}
            require(seen == expected, "Missing eligible feature records")
            stats = capture["windows"][str(n)]
            require(len(seen) == stats["records"] and len(instances) - len(seen) == stats["short_instances"], "Window totals mismatch")
            require(delay_sum == stats["observation_delay_us_sum"] and delay_max == stats["observation_delay_us_max"], "Delay totals mismatch")
            require(corrected == stats["prefixes_with_timestamp_adjustments"], "Correction totals mismatch")
            total_records[n] += len(seen)
        total_instances += len(instances)
    return {"captures": len(capture_ids), "instances": total_instances,
            "n4_records": total_records[4], "n8_records": total_records[8]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path, help="Exact completed extraction run directory")
    args = parser.parse_args(argv)
    try:
        result = validate_run(args.run.expanduser())
        print(json.dumps(result, indent=2))
        print("VALIDATION PASS — arithmetic, B/C pairing and output accounting; labels/session independence NOT verified.")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"VALIDATION FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
