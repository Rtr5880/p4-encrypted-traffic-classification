"""Nonprivileged deterministic catalog tests; synthetic TEMP fixtures only.

These fixtures are never used by the real demonstration or historical evidence.
No network interfaces, source PCAPs, model fitting or privileged tools are used.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pcap_demo_examples as examples
import integrate_rf as integration
import run_native_clock_pilot as native


def sha(content):
    return hashlib.sha256(content).hexdigest()


def fixture_case(label, capture_path):
    packets, objects, trace = [], [], []
    for index in range(8):
        reverse = bool(index % 2)
        src, dst = (b"\x0a\xfe\x00\x02", b"\x0a\xfe\x00\x01") if reverse else (b"\x0a\xfe\x00\x01", b"\x0a\xfe\x00\x02")
        sport, dport = (443, 40123) if reverse else (40123, 443)
        payload = bytes([index]) * (12 + index)
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        raw = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), index, 0, 64, 17, 0, src, dst) + udp
        timestamp = 1_000_000_000 + index * 100_000_000
        packet, tcp = examples.prefix.decode_raw_packet(raw, index + 1, timestamp)
        objects.append(packet)
        packets.append({"original_frame": index + 1, "timestamp_ns": timestamp,
                        "raw_ip_hex": raw.hex(), "sha256": sha(raw)})
        trace.append({"frame": index + 1, "raw_timestamp_ns": timestamp,
                      "effective_timestamp_us": timestamp // 1000, "timestamp_adjustment_ns": 0,
                      "size_bytes": len(raw), "direction": "R" if reverse else "F",
                      "tcp": None, "iat_us": 100000 if index else None})
    b, c = examples.prefix.feature_statistics(objects)
    parent = "fixture-" + label.lower()
    instance = parent + ":instances-v1:idle-tcp:60s:1"
    record_id = instance + ":n8"
    capture_id = "fixtures/" + capture_path.name
    raw_capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    for packet in packets:
        raw = bytes.fromhex(packet["raw_ip_hex"])
        seconds, nanos = divmod(packet["timestamp_ns"], 1_000_000_000)
        raw_capture += struct.pack("<IIII", seconds, nanos // 1000, len(raw), len(raw)) + raw
    capture_path.write_bytes(raw_capture)
    capture = {"capture_id": capture_id, "filename": capture_path.name,
               "path": str(capture_path), "sha256": sha(raw_capture), "size_bytes": len(raw_capture),
               "include_in_baseline": True, "initial_class": label, "label_scope": "capture_activity_hint"}
    record = {"record_id": record_id, "instance_id": instance,
              "parent_candidate_conversation_id": parent, "capture_id": capture_id,
              "capture_sha256": capture["sha256"], "features_B": b, "features_C": c,
              "label": label, "label_basis": "capture_activity_hint", "n": 8,
              "partition": "test", "validation_fold": None}
    key = json.loads(json.dumps(examples.prefix.pilot.make_key(objects[0])))
    extracted = dict(record, policy_id="instances-v1:idle-tcp:60s", instance_index=1,
                     debug_metadata_not_model_inputs={"trace": trace, "start_reason": "first_observed",
                         "first_frame": 1, "decision_frame": 8, "prefix_timestamp_adjustments": 0,
                         "forward_endpoint": [objects[0].src, objects[0].sport], "key": key,
                         "observation_delay_us": 700000, "eligible_packets": 8})
    prediction = {"class": label, "prediction": examples.CLASSES.index(label),
                  "leaves": [0] * 10, "scores": [1] * 6}
    return {"case_id": record_id, "fresh_instance_record_id": record_id,
            "record": record, "extraction_record": extracted, "capture": capture,
            "packets": packets, "features_B": b, "features_C": c,
            "relative_us": [index * 100000 for index in range(8)], "duration_us": 700000,
            "wire_key": key, "slot": 1, "original_predictions": {"B": prediction, "C": prediction}}


class PcapExampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pcap-example-test-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.source = self.repo / "prepared"
        self.source.mkdir()
        self.cases = [fixture_case(label, self.repo / (label.lower() + ".pcap")) for label in examples.CLASSES]
        self.population = {"cases": self.cases, "classes": list(examples.CLASSES),
                           "deployment": str(self.repo / "deployment"), "input_sha256": {}}
        for case in self.cases:
            self.population["input_sha256"][case["capture"]["path"]] = case["capture"]["sha256"]
        self.manifest = {"programs": {}}
        for model in "BC":
            path = self.source / (model + ".json")
            path.write_text('{}')
            self.manifest["programs"][model] = {"path": str(path), "sha256": sha(path.read_bytes())}
        receipt = self.repo / "clock_receipt.json"
        receipt.write_text('{}')
        self.manifest.update(clock_source_receipt=str(receipt), clock_source_receipt_sha256=sha(receipt.read_bytes()))
        p4 = self.repo / "p4"
        p4.mkdir()
        for name in ("flow_features.p4", "rf-models.json", "rf_b.p4", "rf_c.p4"):
            path = p4 / name
            path.write_text("fixture frozen source")
            self.population["input_sha256"][str(path)] = sha(path.read_bytes())
        deployment = Path(self.population["deployment"])
        deployment.mkdir()
        (deployment / "summary.json").write_text(json.dumps({"output_sha256": {}}))
        self.population["input_sha256"][str(deployment / "summary.json")] = sha((deployment / "summary.json").read_bytes())
        self.population["input_sha256"][str(Path(examples.prefix.__file__).resolve())] = examples.prefix.sha256_file(examples.prefix.__file__)

    def source_tuple(self):
        return self.repo, self.source, self.manifest, self.population, {}

    def prepare(self, slug="voip"):
        case = self.cases[examples.CLASSES.index(slug.upper())]
        with patch.object(examples, "_load_source", return_value=self.source_tuple()), \
             patch.object(integration, "load_deployment", return_value=({m: {"classes": list(examples.CLASSES)} for m in "BC"}, None, None)), \
             patch.object(native, "predict", side_effect=lambda export, features: case["original_predictions"]["B"]):
            return examples.prepare_example(self.repo, slug)

    def test_deterministic_selection_has_exactly_one_per_hint(self):
        a = examples.select_cases(self.cases)
        b = examples.select_cases(reversed(self.cases))
        self.assertEqual(list(a), [label.lower() for label in examples.CLASSES])
        self.assertEqual({k:v["case_id"] for k,v in a.items()}, {k:v["case_id"] for k,v in b.items()})

    def test_selection_does_not_consult_predictions(self):
        cases = deepcopy(self.cases)
        for case in cases:
            case["original_predictions"] = {"B": "intentionally unusable", "C": None}
        self.assertEqual(examples.select_cases(cases)["voip"]["case_id"], self.cases[-1]["case_id"])

    def test_selection_rejects_missing_class_and_invalid_structural_candidates(self):
        with self.assertRaises(ValueError):
            examples.select_cases(self.cases[:-1])
        for change in ("long", "later_instance", "development", "adjusted", "one_direction"):
            cases = deepcopy(self.cases)
            case = cases[-1]
            if change == "long": case["duration_us"] = 2_000_001
            if change == "later_instance": case["extraction_record"]["instance_index"] = 2
            if change == "development": case["record"]["partition"] = "development"
            if change == "adjusted": case["extraction_record"]["debug_metadata_not_model_inputs"]["prefix_timestamp_adjustments"] = 1
            if change == "one_direction": case["features_C"]["reverse_packet_count"] = 0
            with self.subTest(change=change), self.assertRaises(ValueError):
                examples.select_cases(cases)

    def test_udp_duration_and_stable_id_are_structural_tiebreakers(self):
        tcp = deepcopy(self.cases[-1])
        tcp["wire_key"][0] = 6
        tcp["duration_us"] = 1_000_000
        tcp["case_id"] = "aaa"
        chosen = examples.select_cases(self.cases + [tcp])["voip"]
        self.assertEqual(chosen["wire_key"][0], 17)

    def test_preview_has_eight_exact_source_summaries_no_packet_payloads(self):
        with patch.object(examples, "_load_source", return_value=self.source_tuple()), \
             patch.object(examples, "iter_capture", side_effect=AssertionError("Listing must not read original captures")):
            rows = examples.list_examples(self.repo)
        self.assertEqual(len(rows), 6)
        row = rows[-1]
        self.assertEqual([x["position"] for x in row["packet_summary"]], list(range(1,9)))
        self.assertEqual([x["direction"] for x in row["packet_summary"]], ["F","R"] * 4)
        self.assertFalse(row["encryption_verified"])
        self.assertFalse(row["activity_ground_truth_verified"])
        self.assertFalse(row["original_capture_verified_on_prepare"])
        self.assertNotIn("raw_ip_hex", json.dumps(row))

    def test_selected_original_capture_and_same_eight_packet_bundle_verify(self):
        bundle = self.prepare()
        original = self.cases[-1]
        self.assertEqual(bundle["packets"], original["packets"])
        self.assertEqual(bundle["relative_us"], original["relative_us"])
        self.assertEqual(bundle["features_B"], original["features_B"])
        self.assertEqual(bundle["features_C"], original["features_C"])
        self.assertTrue(bundle["selected_example"]["original_capture_verified_on_prepare"])
        capture_pins = [path for path in bundle["input_sha256"] if path.endswith(".pcap")]
        self.assertEqual(capture_pins, [original["capture"]["path"]])
        self.assertFalse(bundle["accuracy_scored"])
        self.assertFalse(bundle["whole_capture_replay"])
        self.assertFalse(bundle["source_clock_receipt_is_current_binary_attestation"])

    def test_selected_capture_modified_bytes_fail_without_overwrite(self):
        path = Path(self.cases[-1]["capture"]["path"])
        content = bytearray(path.read_bytes())
        content[-1] ^= 1
        path.write_bytes(content)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.prepare()
        self.assertEqual(path.read_bytes(), bytes(content))

    def test_saved_packet_hash_feature_frame_and_schedule_errors_fail(self):
        for kind in ("packet_hash", "feature", "frame", "schedule", "identity"):
            case = deepcopy(self.cases[-1])
            if kind == "packet_hash": case["packets"][0]["sha256"] = "0" * 64
            if kind == "feature": case["features_B"]["size_sum"] += 1
            if kind == "frame": case["packets"][0]["original_frame"] = 999
            if kind == "schedule": case["relative_us"][-1] += 1
            if kind == "identity": case["fresh_instance_record_id"] = "other"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                examples._validate_saved_case(case)

    def test_frozen_p4_change_is_not_accepted(self):
        (self.repo / "p4/rf_c.p4").write_text("changed frozen source")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.prepare()

    def test_model_deployment_summary_pin_is_not_recomputed_as_truth(self):
        (self.repo / "deployment/summary.json").write_text('{"output_sha256":{},"changed":true}')
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.prepare()

    def test_native_program_outside_preparation_is_rejected(self):
        self.manifest["programs"]["B"]["path"] = str(self.repo / "clock_receipt.json")
        with self.assertRaisesRegex(ValueError, "outside"):
            self.prepare()

    def test_invalid_slug_fails_before_reading_any_sources(self):
        with patch.object(examples, "_load_source") as load:
            for slug in ("all", "../../secret", "VOICE", None):
                with self.assertRaises(ValueError):
                    examples.prepare_example(self.repo, slug)
            load.assert_not_called()

    def test_pinned_manifest_changed_bytes_are_rejected(self):
        root = self.repo / examples.SOURCE_PREPARATION
        root.mkdir(parents=True)
        manifest = root / "manifest.json"
        manifest.write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            examples._load_source(self.repo)

    def test_pinned_population_changed_bytes_are_rejected(self):
        root = self.repo / examples.SOURCE_PREPARATION
        root.mkdir(parents=True)
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"status": "prepared", "schema": "native-evaluation-v2",
            "new_fits": 0, "gap_scaling": False, "cases": 398,
            "compile_definitions": {"TEST_TIMESTAMPS": 0, "DEBUG_REPORT": 1, "FLOW_SLOTS": 65536},
            "population_sha256": "0" * 64}))
        (root / "population.json").write_text('{}')
        with patch.object(examples, "SOURCE_MANIFEST_SHA256", sha(manifest.read_bytes())), \
             patch.object(examples, "SOURCE_POPULATION_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                examples._load_source(self.repo)


if __name__ == "__main__":
    unittest.main()
