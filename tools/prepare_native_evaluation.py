"""Read-only preparation of the complete frozen N8 held-out population.

Unlike the short native pilot, this module NEVER selects on duration, direction,
instance index, activity, or predictions. Every one of the 398 frozen test rows
must validate or preparation fails. Real raw IP bodies are preserved unchanged.
Fresh-switch prefixes have local instance numbering, mapped to original IDs.
"""
from collections import Counter, defaultdict
import hashlib
import io
import json
from pathlib import Path

import generate_rf_p4 as generator
import integrate_rf as integration
import native_prefix as prefix
import prepare_rf_deployment as reference
import replay_real_pcaps as replay


DEPLOYMENT_RUN = "20260929T221518Z_a61fc37702"
EXPECTED_TEST_COUNT = 398
CLASSES = ("CHAT", "FT", "MAIL", "P2P", "STREAMING", "VOIP")
EXPECTED_CLASS_SUPPORT = {"CHAT": 35, "FT": 104, "MAIL": 29,
                          "P2P": 48, "STREAMING": 77, "VOIP": 105}


def _verify(path, expected, hashes):
    path = Path(path).resolve()
    actual = prefix.sha256_file(path)
    if expected is not None and actual != expected:
        raise ValueError(f"Frozen evaluation input changed: {path}")
    previous = hashes.get(str(path))
    if previous is not None and previous != actual:
        raise ValueError(f"Input changed during preparation: {path}")
    hashes[str(path)] = actual
    return actual


def _sealed_path(root, relative):
    path = (Path(root) / relative).resolve()
    if not path.is_relative_to(Path(root).resolve()) or not path.is_file():
        raise ValueError(f"Unsafe or absent sealed input: {relative}")
    return path


def predict(export, features):
    vector = [features[name] for name in export["feature_order"]]
    leaves, _, scores = reference.predict_export(export, [vector])
    index = int(scores[0].argmax())
    return {"leaves": leaves[0].tolist(), "scores": scores[0].tolist(),
            "prediction": index, "class": export["classes"][index]}


def validate_population(table_rows):
    """Keep all test rows; enforce identity, six-class counts and parent disjointness."""
    rows = list(table_rows)
    ids = [row["record_id"] for row in rows]
    if len(ids) != len(set(ids)) or any(row["n"] != 8 for row in rows):
        raise ValueError("Frozen N8 table has duplicate IDs or mixed packet windows")
    if any(row["partition"] not in ("development", "test") for row in rows):
        raise ValueError("Unknown frozen split partition")
    test = sorted((row for row in rows if row["partition"] == "test"), key=lambda row: row["record_id"])
    if len(test) != EXPECTED_TEST_COUNT:
        raise ValueError(f"Expected exactly {EXPECTED_TEST_COUNT} held-out rows, got {len(test)}")
    support = dict(Counter(row["label"] for row in test))
    if support != EXPECTED_CLASS_SUPPORT:
        raise ValueError(f"Frozen held-out six-class population changed: {support}")
    test_parents = {row["parent_candidate_conversation_id"] for row in test}
    development_parents = {row["parent_candidate_conversation_id"] for row in rows if row["partition"] == "development"}
    if test_parents & development_parents:
        raise ValueError("Development/test parent groups overlap")
    if any(row["label_basis"] != "capture_activity_hint" for row in test):
        raise ValueError("Unexpected target-label basis in the frozen experiment")
    return test


def pair_extraction_rows(test_rows, extraction_rows):
    """Reconnect every immutable table row to its original validated N8 trace."""
    targets = {row["record_id"]: row for row in test_rows}
    matched = {}
    for row in extraction_rows:
        identity = row["record_id"]
        if identity not in targets:
            continue
        if identity in matched:
            raise ValueError(f"Duplicate frozen extraction record: {identity}")
        target = targets[identity]
        for name in ("record_id", "instance_id", "parent_candidate_conversation_id", "capture_id",
                     "capture_sha256", "features_B", "features_C", "label", "label_basis", "n"):
            if row[name] != target[name]:
                raise ValueError(f"Prepared/extraction mismatch for {identity}: {name}")
        if row["policy_id"] != "instances-v1:idle-tcp:60s" or row["instance_index"] < 1:
            raise ValueError("Unexpected frozen instance policy/index")
        debug = row["debug_metadata_not_model_inputs"]
        trace = debug["trace"]
        if len(trace) != 8 or trace[0]["frame"] != debug["first_frame"] or trace[-1]["frame"] != debug["decision_frame"]:
            raise ValueError("Expected complete original first-eight trace")
        if any(right["frame"] <= left["frame"] for left, right in zip(trace, trace[1:])):
            raise ValueError("Frozen trace frame order is invalid")
        # These 398 fixed prefixes are unadjusted. An unexpected adjustment is a
        # preparation failure, never permission to silently drop the test row.
        if debug["prefix_timestamp_adjustments"] != 0 or any(item["timestamp_adjustment_ns"] != 0 for item in trace):
            raise ValueError("Frozen test prefix has unexpected timestamp correction")
        if trace[0]["direction"] != "F" or debug["eligible_packets"] < 8:
            raise ValueError("Invalid frozen prefix orientation/count")
        matched[identity] = row
    if set(matched) != set(targets):
        missing = sorted(set(targets) - set(matched))
        raise ValueError(f"Missing original extraction traces: {missing[:3]}")
    return matched


def validate_case(record, extracted, capture, raw_records, exports):
    """Independently verify bytes/features and fresh-prefix instance semantics."""
    bodies, b, c, relative_us = prefix.validate_original_packets(extracted, raw_records)
    original_key = extracted["debug_metadata_not_model_inputs"]["key"]
    if len(relative_us) != 8 or relative_us[0] != 0 or any(gap >= 60_000_000 for gap in
                    (right - left for left, right in zip(relative_us, relative_us[1:]))):
        raise ValueError("Frozen N8 prefix cannot remain one idle-60s instance")
    outputs = {4: io.StringIO(), 8: io.StringIO()}
    oracle = replay.ReplayOracle(capture, outputs, io.StringIO(), idle_seconds=60, boundary_policy="idle-tcp")
    owners, decision = {}, None
    for body, offset in zip(bodies, relative_us, strict=True):
        raw = bytes.fromhex(body["raw_ip_hex"])
        packet, tcp = prefix.decode_raw_packet(raw, body["original_frame"], (1_000_000 + offset) * 1000)
        _, current, _, _, collision = replay.expectation(oracle, packet, tcp, owners, origin_us=0)
        if collision:
            raise ValueError("One-prefix fresh oracle unexpectedly collides")
        if current is not None:
            if decision is not None:
                raise ValueError("Fresh prefix classified more than once")
            decision = current
    audit = oracle.finish()
    if decision is None or audit["instances"] != 1 or audit["windows"]["8"]["records"] != 1:
        raise ValueError("Original prefix does not form one fresh eight-packet instance")
    if decision["features_B"] != b or decision["features_C"] != c:
        raise ValueError("Fresh-prefix reference disagrees with original features")
    if decision["parent_candidate_conversation_id"] != record["parent_candidate_conversation_id"]:
        raise ValueError("Original parent identity changed in fresh-prefix reference")
    first_raw = bytes.fromhex(bodies[0]["raw_ip_hex"])
    first_packet, _ = prefix.decode_raw_packet(first_raw, bodies[0]["original_frame"], bodies[0]["timestamp_ns"])
    return {"case_id": record["record_id"], "record": record, "capture": capture,
            "extraction_record": extracted, "packets": bodies, "relative_us": relative_us,
            "features_B": b, "features_C": c, "duration_us": relative_us[-1],
            "slot": replay.slot_for(first_packet), "wire_key": original_key,
            "fresh_instance_record_id": decision["record_id"],
            "original_predictions": {s: predict(exports[s], c) for s in "BC"}}


def plan_batches(cases, max_cases=32, start_spacing_us=2000):
    """Deterministic first-fit decreasing duration; no shared state slot or tuple."""
    cases = list(cases)
    if type(max_cases) is not int or not 1 <= max_cases <= 32:
        raise ValueError("Batch size must be an integer from one to 32")
    if type(start_spacing_us) is not int or not 0 <= start_spacing_us <= 1_000_000:
        raise ValueError("Start spacing must be integer microseconds from zero to one second")
    if not cases or len({case["case_id"] for case in cases}) != len(cases):
        raise ValueError("Empty or duplicate evaluation case population")
    states = []
    for case in sorted(cases, key=lambda item: (-item["duration_us"], item["case_id"])):
        if type(case["duration_us"]) is not int or case["duration_us"] < 0:
            raise ValueError("Case duration is invalid")
        if type(case["slot"]) is not int or not 0 <= case["slot"] < 65536:
            raise ValueError("Case slot is outside the frozen P4 table")
        parent = case["record"]["parent_candidate_conversation_id"]
        key = json.dumps(case["wire_key"], separators=(",", ":"))
        for state in states:
            if (len(state["cases"]) < max_cases and case["slot"] not in state["slots"]
                    and key not in state["keys"] and parent not in state["parents"]):
                break
        else:
            state = {"cases": [], "slots": set(), "keys": set(), "parents": set(), "span": 0}
            states.append(state)
        offset = len(state["cases"]) * start_spacing_us
        state["cases"].append({"case_id": case["case_id"], "start_offset_us": offset})
        state["slots"].add(case["slot"])
        state["keys"].add(key)
        state["parents"].add(parent)
        state["span"] = max(state["span"], offset + case["duration_us"])
    batches = [{"batch_id": f"batch_{index:03d}", "cases": state["cases"],
                "scheduled_span_us": state["span"], "fresh_switch_required": True}
               for index, state in enumerate(states, 1)]
    return {"schema_version": 1, "policy": "first-fit decreasing original prefix duration, then stable record ID",
            "max_cases": max_cases, "start_spacing_us": start_spacing_us, "gap_scaling": False,
            "unique_parent_tuple_and_slot_per_batch": True, "fresh_switch_per_batch_and_model": True,
            "case_count": len(cases), "evaluations_per_repetition": 2 * len(cases),
            "batch_count": len(batches), "batches": batches,
            "estimated_scheduled_span_us_per_model": sum(batch["scheduled_span_us"] for batch in batches),
            "estimated_scheduled_span_us_per_repetition": 2 * sum(batch["scheduled_span_us"] for batch in batches),
            "estimate_excludes": ["Compilation", "switch startup", "capture draining", "CLI queries", "cleanup"]}


def prepare_population(repo):
    """Read all 398 rows and their exact packets; return data, never write output."""
    repo = Path(repo).resolve()
    prepared = repo / "results/baseline_preparation" / prefix.PREPARED_RUN
    manifest_path = prepared / "manifest.json"
    manifest = prefix.read_json(manifest_path)
    if manifest["status"] != "prepared" or tuple(manifest["classes"]) != CLASSES:
        raise ValueError("Unexpected frozen baseline preparation/classes")
    hashes = {}
    _verify(manifest_path, None, hashes)
    for relative, expected in manifest["payload_sha256"].items():
        _verify(_sealed_path(prepared, relative), expected, hashes)
    table_path = prepared / "table_n8.jsonl"
    test_rows = validate_population(prefix.read_jsonl(table_path))
    extraction = Path(manifest["extraction_run"]).resolve()
    for name in ("policy.json", "summary.json"):
        _verify(extraction / name, manifest["extraction_sha256"][name], hashes)
    policy = prefix.read_json(extraction / "policy.json")
    if policy["idle_seconds"] != 60 or policy["boundary_policy"] != "idle-tcp" or \
       tuple(policy["features_B"]) != prefix.B_FEATURES or tuple(policy["features_C"]) != prefix.C_FEATURES:
        raise ValueError("Frozen extraction policy or feature order changed")
    for name, expected in policy["source_sha256"].items():
        _verify(_sealed_path(Path(replay.instances.__file__).parent, name), expected, hashes)
    inventory_path = repo / "metadata/capture_inventory.json"
    _verify(inventory_path, policy["manifest_sha256"], hashes)
    inventory = prefix.read_json(inventory_path)
    by_capture = {row["capture_id"]: row for row in inventory["captures"]}
    if len(by_capture) != len(inventory["captures"]):
        raise ValueError("Duplicate inventory capture IDs")
    summary = prefix.read_json(extraction / "summary.json")
    if summary["status"] != "instance_extraction_complete":
        raise ValueError("Frozen instance extraction incomplete")
    audits = {row["capture_id"]: row for row in summary["captures"]}
    capture_rows = defaultdict(list)
    for row in test_rows:
        capture_rows[row["capture_id"]].append(row)
    traces = []
    for capture_id in sorted(capture_rows):
        capture = by_capture[capture_id]
        audit = audits[capture_id]
        if not capture["include_in_baseline"] or audit["capture_sha256"] != capture["sha256"]:
            raise ValueError("Frozen selected capture missing, excluded or changed")
        relative = (Path(audit["evidence_directory"]) / "features_n8.jsonl").as_posix()
        path = _sealed_path(extraction, relative)
        _verify(path, manifest["extraction_sha256"][relative], hashes)
        traces.extend(prefix.read_jsonl(path))
    paired = pair_extraction_rows(test_rows, traces)
    deployment = repo / "results/rf_deployment" / DEPLOYMENT_RUN
    exports, _, _ = integration.load_deployment(deployment)
    config = prefix.read_json(deployment / "run_config.json")
    if Path(config["prepared_directory"]).resolve() != prepared or config["excluded_test_records"] != EXPECTED_TEST_COUNT:
        raise ValueError("RF deployment does not belong to this frozen held-out experiment")
    for name in ("manifest.json", "table_n8.jsonl"):
        path = prepared / name
        expected = config["input_and_source_sha256"][str(path)]
        if hashes[str(path)] != expected:
            raise ValueError("Prepared data differs from the original selected RF deployment")
    sealed = prefix.read_json(deployment / "summary.json")["output_sha256"]
    for relative, expected in sealed.items():
        _verify(_sealed_path(deployment, relative), expected, hashes)
    _verify(deployment / "summary.json", None, hashes)
    for s in "BC":
        if tuple(exports[s]["classes"]) != CLASSES or tuple(exports[s]["feature_order"]) != getattr(prefix, f"{s}_FEATURES"):
            raise ValueError("Frozen forest class/feature order changed")
    for path in (Path(prefix.__file__), Path(replay.__file__), Path(replay.capture_io.__file__),
                 Path(replay.instances.__file__), Path(replay.pilot.__file__), Path(reference.__file__),
                 Path(integration.__file__), Path(generator.__file__), Path(replay.feature_helpers.__file__),
                 repo / "p4/flow_features.p4", repo / "p4/rf_b.p4", repo / "p4/rf_c.p4", repo / "p4/rf-models.json"):
        if str(path.resolve()) not in hashes:
            _verify(path, None, hashes)
    cases = []
    for capture_id in sorted(capture_rows):
        capture = by_capture[capture_id]
        path = Path(capture["path"]).resolve()
        before = path.stat()
        if before.st_size != capture["size_bytes"]:
            raise ValueError("Original capture size changed")
        _verify(path, capture["sha256"], hashes)  # exactly once per selected capture
        needed = {item["frame"] for row in capture_rows[capture_id]
                  for item in paired[row["record_id"]]["debug_metadata_not_model_inputs"]["trace"]}
        raw_by_frame = {}
        last_needed = max(needed)
        for raw in replay.capture_io.iter_capture(path):
            if raw.number in needed:
                raw_by_frame[raw.number] = raw
            if raw.number >= last_needed:
                break
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Capture changed during preparation")
        if set(raw_by_frame) != needed:
            raise ValueError("Original capture is missing selected prefix frames")
        for record in capture_rows[capture_id]:
            extracted = paired[record["record_id"]]
            originals = [raw_by_frame[item["frame"]] for item in extracted["debug_metadata_not_model_inputs"]["trace"]]
            if record["capture_sha256"] != capture["sha256"]:
                raise ValueError("Held-out row capture fingerprint differs from original")
            cases.append(validate_case(record, extracted, capture, originals, exports))
    cases.sort(key=lambda case: case["case_id"])
    ids = [case["case_id"] for case in cases]
    if ids != [row["record_id"] for row in test_rows]:
        raise ValueError("Prepared population lost, duplicated or reordered test cases")
    durations = [case["duration_us"] for case in cases]
    return {"schema_version": 1, "population": "all frozen held-out N8 records", "cases": cases,
            "classes": list(CLASSES), "deployment": str(deployment), "input_sha256": hashes,
            "ordered_case_ids_sha256": hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode()).hexdigest(),
            "summary": {"cases": len(cases), "packet_prefixes": len(cases), "packets_per_model": 8 * len(cases),
                        "class_support": dict(Counter(case["record"]["label"] for case in cases)),
                        "captures": len(capture_rows), "parents": len({case["record"]["parent_candidate_conversation_id"] for case in cases}),
                        "prefixes_over_two_seconds": sum(value > 2_000_000 for value in durations),
                        "later_original_instances": sum(case["extraction_record"]["instance_index"] > 1 for case in cases),
                        "unidirectional_prefixes": sum(case["features_C"]["reverse_packet_count"] == 0 for case in cases),
                        "duration_us_min": min(durations), "duration_us_max": max(durations)},
            "accuracy_scored": False, "models_fitted": False, "native_traffic_sent": False,
            "limitations": ["Isolated held-out prefixes with fresh switch state; not chronological whole-capture replay.",
                            "Original capture-relative gaps remain unchanged; background/later traffic is omitted.",
                            "Fresh local instance IDs are mapped explicitly to original immutable record IDs.",
                            "Labels remain provisional capture-derived hints, not verified per-flow activity.",
                            "Raw headers are checked against frozen TShark-derived traces; no new label inference."]}
