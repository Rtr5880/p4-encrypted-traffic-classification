#!/usr/bin/env python3
"""Six deterministic real-PCAP examples from the frozen held-out N8 population.

Listing reads only the pinned 6 MiB preparation, never all original captures.
Preparing verifies ONE original capture and its exact eight frozen source frames.
Labels are capture activity hints; neither activity nor encryption is proven for
each individual packet/flow. Selection never consults model predictions.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import native_prefix as prefix
from pcap_replay_io import PacketRecord, iter_capture

SCHEMA = "pcap-demo-example-v1"
CLASSES = ("CHAT", "FT", "MAIL", "P2P", "STREAMING", "VOIP")
DEFAULT_EXAMPLE = "voip"
MAX_DURATION_US = 2_000_000
SOURCE_PREPARATION = "results/native_evaluation_preparation/20261007T182217Z_a93176dc1f"
SOURCE_MANIFEST_SHA256 = "a7a6646b4703d5353a5a7d56ca7a527a3c763ed5746c429c28886783597e8db1"
SOURCE_POPULATION_SHA256 = "871f11ae35b4a66222d2335146bfae6a0d1546c907760f08cd695161b5d40f67"
SELECTION_POLICY = (
    "One per capture-derived class; frozen held-out N8 first-observed instance 1; "
    "bidirectional, zero adjusted timestamps, 0 < original span <= 2 seconds; "
    "prefer UDP, then span nearest one second, then stable original record ID. "
    "No selection on predictions or correctness. Original gaps are not scaled."
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _verify(path, expected, hashes):
    path = Path(path).resolve()
    _require(path.is_file(), f"Missing pinned example source: {path}")
    actual = prefix.sha256_file(path)
    _require(actual == expected, f"Pinned example source SHA-256 mismatch: {path}")
    hashes[str(path)] = actual
    return actual


def _load_source(repo):
    repo = Path(repo or Path(__file__).resolve().parent.parent).resolve()
    source = repo / SOURCE_PREPARATION
    hashes = {}
    _verify(source / "manifest.json", SOURCE_MANIFEST_SHA256, hashes)
    manifest = prefix.read_json(source / "manifest.json")
    _require(manifest.get("status") == "prepared" and manifest.get("schema") == "native-evaluation-v2"
             and manifest.get("new_fits") == 0 and manifest.get("gap_scaling") is False
             and manifest.get("cases") == 398 and manifest.get("compile_definitions") ==
             {"TEST_TIMESTAMPS": 0, "DEBUG_REPORT": 1, "FLOW_SLOTS": 65536},
             "Unsupported frozen native preparation")
    _require(manifest.get("population_sha256") == SOURCE_POPULATION_SHA256,
             "Frozen population pin disagrees with native manifest")
    _verify(source / "population.json", SOURCE_POPULATION_SHA256, hashes)
    population = prefix.read_json(source / "population.json")
    _require(tuple(population.get("classes", ())) == CLASSES and len(population.get("cases", [])) == 398,
             "Frozen held-out population/classes changed")
    identities = [case["case_id"] for case in population["cases"]]
    _require(len(set(identities)) == 398, "Duplicate frozen case identity")
    return repo, source, manifest, population, hashes


def select_cases(cases):
    """Pure deterministic selection, deliberately independent of predictions."""
    cases = list(cases)
    selected = {}
    for label in CLASSES:
        candidates = []
        for case in cases:
            record, extracted = case["record"], case["extraction_record"]
            debug = extracted["debug_metadata_not_model_inputs"]
            if record["label"] != label or record["partition"] != "test" or record["n"] != 8:
                continue
            if extracted["instance_index"] != 1 or debug["start_reason"] != "first_observed":
                continue
            if not 0 < case["duration_us"] <= MAX_DURATION_US or debug["prefix_timestamp_adjustments"] != 0:
                continue
            if case["features_C"]["reverse_packet_count"] == 0:
                continue
            candidates.append(case)
        _require(candidates, f"No bounded frozen example for capture activity hint {label}")
        candidates.sort(key=lambda case: (case["wire_key"][0] != 17,
                                           abs(case["duration_us"] - 1_000_000), case["case_id"]))
        selected[label.lower()] = candidates[0]
    return selected


def _validate_saved_case(case):
    record, extracted, capture = case["record"], case["extraction_record"], case["capture"]
    _require(record["record_id"] == case["case_id"] == case["fresh_instance_record_id"],
             "Selected original/fresh instance identity changed")
    _require(record["partition"] == "test" and record["n"] == 8
             and record["label_basis"] == "capture_activity_hint"
             and record["label"] in CLASSES, "Example is not a frozen capture-labelled held-out N8 record")
    for key in ("record_id", "instance_id", "parent_candidate_conversation_id", "capture_id",
                "capture_sha256", "features_B", "features_C", "label", "label_basis", "n"):
        _require(record[key] == extracted[key], f"Frozen record/trace mismatch: {key}")
    _require(record["capture_id"] == capture["capture_id"] and record["capture_sha256"] == capture["sha256"]
             and capture["include_in_baseline"] is True and capture["initial_class"] == record["label"],
             "Capture metadata does not match selected instance")
    _require(extracted["policy_id"] == "instances-v1:idle-tcp:60s"
             and extracted["instance_index"] == 1
             and extracted["debug_metadata_not_model_inputs"]["start_reason"] == "first_observed",
             "Selected instance cannot use existing isolated native pilot semantics")
    _require(len(case["packets"]) == 8, "Example must contain exactly eight original packets")
    records = []
    for packet in case["packets"]:
        raw = bytes.fromhex(packet["raw_ip_hex"])
        _require(hashlib.sha256(raw).hexdigest() == packet["sha256"], "Saved original packet SHA-256 mismatch")
        _require(len(raw) + 137 <= 9000, "Selected debug output exceeds the existing link MTU")
        records.append(PacketRecord(packet["original_frame"], packet["timestamp_ns"],
                                    len(raw), len(raw), 228, raw))
    bodies, b, c, relative = prefix.validate_original_packets(extracted, records)
    _require(b == case["features_B"] == record["features_B"] and c == case["features_C"] == record["features_C"],
             "Saved feature definitions disagree with independent packet arithmetic")
    _require(relative == case["relative_us"] and relative[0] == 0
             and relative[-1] == case["duration_us"] <= MAX_DURATION_US,
             "Saved original packet schedule changed")
    _require(extracted["debug_metadata_not_model_inputs"]["key"] == case["wire_key"],
             "Frozen flow key changed")
    return bodies


def _metadata(slug, case):
    _validate_saved_case(case)
    record, capture = case["record"], case["capture"]
    trace = case["extraction_record"]["debug_metadata_not_model_inputs"]["trace"]
    packet_summary = []
    for position, (saved, entry, offset) in enumerate(zip(case["packets"], trace, case["relative_us"], strict=True), 1):
        packet, _ = prefix.decode_raw_packet(bytes.fromhex(saved["raw_ip_hex"]),
                                            saved["original_frame"], saved["timestamp_ns"])
        packet_summary.append({"position": position, "original_frame": saved["original_frame"],
                               "ip_size_bytes": packet.size, "direction": entry["direction"],
                               "capture_offset_us": offset, "protocol": packet.protocol,
                               "src": packet.src, "dst": packet.dst,
                               "src_port": packet.sport, "dst_port": packet.dport})
    return {"slug": slug, "label": record["label"], "capture_activity_hint": record["label"],
            "label_basis": record["label_basis"], "capture_id": capture["capture_id"],
            "capture_name": capture["filename"], "record_id": case["case_id"],
            "partition": "test", "eligible_packets": 8, "protocol": case["wire_key"][0],
            "wire_key": deepcopy(case["wire_key"]), "duration_us": case["duration_us"],
            "duration_seconds": case["duration_us"] / 1_000_000,
            "original_frames": [packet["original_frame"] for packet in case["packets"]],
            "capture_sha256": capture["sha256"], "packet_summary": packet_summary,
            "selected_packet_sha256": [packet["sha256"] for packet in case["packets"]],
            "features_B": deepcopy(case["features_B"]), "features_C": deepcopy(case["features_C"]),
            "capture_time_predictions": deepcopy(case["original_predictions"]),
            "encryption_verified": False, "activity_ground_truth_verified": False,
            "original_capture_verified_on_prepare": False, "selection_policy": SELECTION_POLICY}


def list_examples(repo=None):
    """List six saved previews; source capture files are NOT read or hashed."""
    _, _, _, population, _ = _load_source(repo)
    selected = select_cases(population["cases"])
    return [_metadata(slug, case) for slug, case in selected.items()]


def prepare_example(repo=None, example=DEFAULT_EXAMPLE):
    """Verify selected real source bytes; return an existing native-pilot bundle.

    This is read-only. The runner persists the resulting bundle in NEW demo
    evidence, uses a fresh switch for each model, and supplies actual ingress
    timestamps to the existing parity oracle. No capture timestamps are injected.
    """
    _require(isinstance(example, str) and example in tuple(label.lower() for label in CLASSES),
             "Example must be chat, ft, mail, p2p, streaming or voip")
    repo, source, manifest, population, hashes = _load_source(repo)
    case = select_cases(population["cases"])[example]
    _validate_saved_case(case)
    capture = case["capture"]
    capture_path = Path(capture["path"]).resolve()
    _require(capture_path.stat().st_size == capture["size_bytes"], "Selected original capture size changed")
    _require(population["input_sha256"].get(str(capture_path)) == capture["sha256"],
             "Selected capture pin disagrees with frozen population")
    _verify(capture_path, capture["sha256"], hashes)
    numbers = {packet["original_frame"] for packet in case["packets"]}
    raw_records = []
    for packet in iter_capture(capture_path):
        if packet.number in numbers:
            raw_records.append(packet)
        if packet.number >= max(numbers):
            break
    bodies, b, c, relative = prefix.validate_original_packets(case["extraction_record"], raw_records)
    _require(bodies == case["packets"] and b == case["features_B"]
             and c == case["features_C"] and relative == case["relative_us"],
             "Selected actual capture prefix differs from frozen native preparation")
    import integrate_rf as integration
    import run_native_clock_pilot as native
    deployment = Path(population["deployment"])
    _verify(deployment / "summary.json",
            population["input_sha256"][str((deployment / "summary.json").resolve())], hashes)
    exports, _, _ = integration.load_deployment(deployment)
    for model in "BC":
        _require(tuple(exports[model]["classes"]) == CLASSES, "Frozen RF class order changed")
        _require(native.predict(exports[model], c) == case["original_predictions"][model],
                 "Frozen capture-time reference prediction changed")
    for name in ("flow_features.p4", "rf-models.json", "rf_b.p4", "rf_c.p4"):
        path = (repo / "p4" / name).resolve()
        _verify(path, population["input_sha256"][str(path)], hashes)
    _verify(manifest["clock_source_receipt"], manifest["clock_source_receipt_sha256"], hashes)
    for artifact in manifest["programs"].values():
        path = Path(artifact["path"]).resolve()
        _require(path.is_relative_to(source), "Native debug program is outside its pinned preparation")
        _verify(path, artifact["sha256"], hashes)
    hashes[str(Path(__file__).resolve())] = prefix.sha256_file(Path(__file__))
    _verify(Path(prefix.__file__), population["input_sha256"][str(Path(prefix.__file__).resolve())], hashes)
    dep_summary = prefix.read_json(deployment / "summary.json")
    hashes[str((deployment / "summary.json").resolve())] = prefix.sha256_file(deployment / "summary.json")
    for relative_name, sha in dep_summary["output_sha256"].items():
        path = (deployment / relative_name).resolve()
        _require(path.is_relative_to(deployment.resolve()), "Frozen deployment artifact escaped its root")
        _verify(path, sha, hashes)
    preview = _metadata(example, case)
    preview["original_capture_verified_on_prepare"] = True
    return {"schema_version": SCHEMA, "pilot_only": True, "demo_only": True, "accuracy_scored": False,
            "whole_capture_replay": False, "native_clock_required": True,
            "record": deepcopy(case["record"]), "extraction_record": deepcopy(case["extraction_record"]),
            "packets": bodies, "capture": deepcopy(capture), "relative_us": relative,
            "features_B": b, "features_C": c, "original_predictions": deepcopy(case["original_predictions"]),
            "deployment": str(deployment), "input_sha256": hashes, "selected_example": preview,
            "native_programs": deepcopy(manifest["programs"]),
            "clock_receipt": manifest["clock_source_receipt"],
            "clock_receipt_sha256": manifest["clock_source_receipt_sha256"],
            "source_clock_receipt": manifest["clock_source_receipt"],
            "source_clock_receipt_sha256": manifest["clock_source_receipt_sha256"],
            "source_clock_receipt_is_current_binary_attestation": False,
            "source_preparation": str(source), "source_population_sha256": SOURCE_POPULATION_SHA256,
            "selection": {"policy": SELECTION_POLICY, "uses_predictions": False,
                          "uses_capture_activity_hints": True, "max_duration_seconds": 2,
                          "bounded_examples": 6, "gap_scaling": False},
            "limitations": ["A selected isolated first-eight prefix, not new live network capture or whole-session replay.",
                            "Capture activity hint is not verified flow-level activity or encryption ground truth.",
                            "Demonstration selection is not representative accuracy sampling.",
                            "RF-B and RF-C see identical original bytes/schedules, but separate native replays may have different ingress jitter."]}


select_example = prepare_example


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("list",))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        examples = list_examples()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"PCAP example catalog unavailable: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(examples, indent=2, allow_nan=False))
    else:
        print("Frozen real-PCAP examples — activity hints, not guaranteed predictions or independent ground truth.")
        print("Listing verifies saved metadata only; selected original capture bytes are verified during preparation.")
        for item in examples:
            predicted = "/".join(item["capture_time_predictions"][m]["class"] for m in "BC")
            print(f"{item['slug']:10} {item['capture_name']:28} {item['duration_seconds']:.6f}s  "
                  f"N=8  hint={item['label']:9} saved capture-time B/C={predicted}")
            print(f"  make dashboard-live DEMO=pcap EXAMPLE={item['slug']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
