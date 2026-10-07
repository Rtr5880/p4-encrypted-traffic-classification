"""Full-population preparation fixtures; no packet sending or model fitting."""
import copy
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import prepare_native_evaluation as preparation
import native_prefix as prefix
from pcap_replay_io import ClassicPcapWriter, PacketRecord, iter_capture
import rf_parity_probes as probes
import test_native_prefix as fixtures


def exports():
    b = probes.synthetic_export()
    c = copy.deepcopy(b)
    c["feature_set"] = "C"
    c["feature_order"] = list(preparation.reference.FEATURES["C"])
    c["domains"] = {name: preparation.reference.DOMAINS[name] for name in c["feature_order"]}
    return {"B": b, "C": c}


def original_case(instance_index=1, unidirectional=False, long=False):
    _, _, raw = fixtures.make_fixture()
    if unidirectional:
        raw = [PacketRecord(row.number, row.timestamp_ns, row.captured_len, row.wire_len,
                            row.linktype, fixtures.udp(row.wire_len)) for row in raw]
    if long:
        raw = [PacketRecord(row.number, (1_000_000 + index * 30_000_000) * 1000,
                            row.captured_len, row.wire_len, row.linktype, row.data)
               for index, row in enumerate(raw)]
    capture = {"capture_id": "folder/cap.pcap", "filename": "cap.pcap",
               "sha256": "capturehash", "initial_class": "VOIP"}
    outputs = {4: io.StringIO(), 8: io.StringIO()}
    extractor = prefix.instances.Extractor(capture, outputs, io.StringIO())
    for row in raw:
        packet, tcp = prefix.decode_raw_packet(row.data, row.number, row.timestamp_ns)
        extractor.add(packet, tcp)
    extractor.finish()
    extracted = json.loads(outputs[8].getvalue())
    if instance_index > 1:
        extracted["instance_index"] = instance_index
        extracted["instance_id"] = extracted["instance_id"].rsplit(":", 1)[0] + f":{instance_index}"
        extracted["record_id"] = extracted["instance_id"] + ":n8"
        extracted["debug_metadata_not_model_inputs"]["start_reason"] = "after_tcp_rst"
    record = {name: extracted[name] for name in ("record_id", "instance_id", "parent_candidate_conversation_id",
        "capture_id", "capture_sha256", "features_B", "features_C", "label", "label_basis", "n")}
    record["partition"] = "test"
    return record, extracted, capture, raw


def table_population():
    rows = []
    for label, count in preparation.EXPECTED_CLASS_SUPPORT.items():
        for index in range(count):
            rows.append({"record_id": f"{label}_{index}:n8", "n": 8, "partition": "test",
                         "label": label, "label_basis": "capture_activity_hint",
                         "parent_candidate_conversation_id": f"parent_{label}_{index}"})
    rows.append({"record_id": "development:n8", "n": 8, "partition": "development",
                 "parent_candidate_conversation_id": "development_parent"})
    return rows


class PopulationTests(unittest.TestCase):
    def test_exact_398_population_with_all_class_supports(self):
        selected = preparation.validate_population(table_population())
        self.assertEqual(len(selected), 398)
        self.assertEqual([row["record_id"] for row in selected], sorted(row["record_id"] for row in selected))

    def test_missing_changed_class_duplicate_and_parent_overlap_fail(self):
        base = table_population()
        variants = [base[1:], base + [copy.deepcopy(base[0])]]
        altered = copy.deepcopy(base)
        altered[0]["label"] = "BROWSING"
        variants.append(altered)
        overlap = copy.deepcopy(base)
        overlap[-1]["parent_candidate_conversation_id"] = overlap[0]["parent_candidate_conversation_id"]
        variants.append(overlap)
        for rows in variants:
            with self.assertRaises(ValueError):
                preparation.validate_population(rows)

    def test_extraction_pairing_has_no_pilot_constraints(self):
        record, extracted, _, _ = original_case(instance_index=4, unidirectional=True, long=True)
        matched = preparation.pair_extraction_rows([record], [extracted])
        self.assertEqual(matched[record["record_id"]]["instance_index"], 4)
        self.assertEqual(extracted["features_C"]["reverse_packet_count"], 0)
        self.assertGreater(extracted["features_C"]["iat_sum"], 2_000_000)

    def test_pairing_missing_duplicate_mismatched_feature_or_target_fails(self):
        record, extracted, _, _ = original_case()
        with self.assertRaisesRegex(ValueError, "Missing"):
            preparation.pair_extraction_rows([record], [])
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            preparation.pair_extraction_rows([record], [extracted, extracted])
        for field, value in (("label", "wrong"), ("features_C", {}), ("capture_id", "wrong")):
            bad = copy.deepcopy(extracted)
            bad[field] = value
            with self.assertRaisesRegex(ValueError, field):
                preparation.pair_extraction_rows([record], [bad])


class OriginalPacketTests(unittest.TestCase):
    def test_later_original_ids_are_preserved_but_local_id_is_fresh(self):
        record, extracted, capture, raw = original_case(instance_index=7)
        case = preparation.validate_case(record, extracted, capture, raw, exports())
        self.assertEqual(case["case_id"], record["record_id"])
        self.assertTrue(case["fresh_instance_record_id"].endswith(":1:n8"))
        self.assertTrue(case["case_id"].endswith(":7:n8"))
        self.assertEqual(set(case["original_predictions"]), {"B", "C"})
        self.assertEqual([bytes.fromhex(item["raw_ip_hex"]) for item in case["packets"]], [item.data for item in raw])

    def test_long_and_unidirectional_prefixes_validate_not_drop(self):
        record, extracted, capture, raw = original_case(unidirectional=True, long=True)
        case = preparation.validate_case(record, extracted, capture, raw, exports())
        self.assertEqual(case["duration_us"], 210_000_000)
        self.assertEqual(case["features_C"]["reverse_packet_count"], 0)
        self.assertEqual(case["relative_us"], [index * 30_000_000 for index in range(8)])

    def test_changed_original_bytes_features_or_frame_fail(self):
        record, extracted, capture, raw = original_case()
        bad = copy.deepcopy(extracted)
        bad["features_C"]["direction_change_count"] += 1
        with self.assertRaises(ValueError):
            preparation.validate_case(record, bad, capture, raw, exports())
        corrupted = raw.copy()
        first = corrupted[0]
        body = bytearray(first.data)
        struct.pack_into("!H", body, 20, 9999)
        corrupted[0] = PacketRecord(first.number, first.timestamp_ns, first.captured_len,
                                    first.wire_len, first.linktype, bytes(body))
        with self.assertRaises(ValueError):
            preparation.validate_case(record, extracted, capture, corrupted, exports())


def planned_case(identity, duration, slot, parent=None, wire=None):
    return {"case_id": identity, "duration_us": duration, "slot": slot,
            "record": {"parent_candidate_conversation_id": parent or identity},
            "wire_key": wire or [17, ["10.0.0.1", slot], ["10.0.0.2", 443]]}


class BatchTests(unittest.TestCase):
    def test_first_fit_decreasing_duration_and_exact_offset_spans(self):
        cases = [planned_case("c", 20, 3), planned_case("a", 100, 1), planned_case("b", 50, 2)]
        plan = preparation.plan_batches(cases, max_cases=2, start_spacing_us=10)
        self.assertEqual(plan["batch_count"], 2)
        self.assertEqual(plan["batches"][0]["cases"], [{"case_id": "a", "start_offset_us": 0},
                                                    {"case_id": "b", "start_offset_us": 10}])
        self.assertEqual(plan["estimated_scheduled_span_us_per_model"], 120)
        self.assertEqual(plan["evaluations_per_repetition"], 6)
        self.assertEqual(plan, preparation.plan_batches(list(reversed(cases)), 2, 10))

    def test_slot_parent_and_wire_tuple_conflicts_get_fresh_batches(self):
        base = planned_case("a", 100, 1)
        for conflict in (planned_case("b", 50, 1), planned_case("b", 50, 2, parent="a"),
                         planned_case("b", 50, 2, wire=base["wire_key"])):
            plan = preparation.plan_batches([base, conflict])
            self.assertEqual(plan["batch_count"], 2)
            self.assertTrue(all(batch["fresh_switch_required"] for batch in plan["batches"]))

    def test_every_case_once_for_full_population(self):
        cases = [planned_case(f"c{index:04}", 1000 - index, index % 330,
                              parent=f"p{index % 368}") for index in range(398)]
        plan = preparation.plan_batches(cases)
        by_id = {case["case_id"]: case for case in cases}
        visited = []
        for batch in plan["batches"]:
            selected = [by_id[item["case_id"]] for item in batch["cases"]]
            self.assertLessEqual(len(selected), 32)
            self.assertEqual(len({case["slot"] for case in selected}), len(selected))
            self.assertEqual(len({case["record"]["parent_candidate_conversation_id"] for case in selected}), len(selected))
            visited.extend(case["case_id"] for case in selected)
        self.assertEqual(sorted(visited), sorted(by_id))
        self.assertEqual(plan["evaluations_per_repetition"], 796)

    def test_invalid_plans_fail(self):
        base = planned_case("a", 100, 1)
        variants = [([], 32, 2000), ([base, base], 32, 2000), ([base], 33, 2000),
                    ([base], True, 2000), ([base], 32, -1), ([base], 32, 0.5),
                    ([planned_case("a", -1, 1)], 32, 2000),
                    ([planned_case("a", 1, 65536)], 32, 2000)]
        for cases, count, spacing in variants:
            with self.assertRaises(ValueError):
                preparation.plan_batches(cases, count, spacing)


class CompleteFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.prepared = self.repo / "results/baseline_preparation" / prefix.PREPARED_RUN
        self.extraction = self.repo / "extraction"
        self.deployment = self.repo / "results/rf_deployment" / preparation.DEPLOYMENT_RUN
        for path in (self.prepared, self.extraction / "capture_001", self.deployment,
                     self.repo / "metadata", self.repo / "p4"):
            path.mkdir(parents=True, exist_ok=True)
        self.capture_path = self.repo / "capture.pcap"
        frames = []
        for conversation in range(6):
            for pos in range(8):
                raw = fixtures.udp(50 + pos, reverse=pos % 2 == 1, sport=10000 + conversation)
                frame = conversation * 8 + pos + 1
                timestamp = (1_000_000 + conversation * 1_000_000 + pos * 1000) * 1000
                frames.append(PacketRecord(frame, timestamp, len(raw), len(raw), 101, raw))
        with ClassicPcapWriter(self.capture_path, linktype=101) as writer:
            for row in frames:
                writer.write(row.timestamp_ns, row.data)
        capture = {"capture_id": "folder/cap.pcap", "filename": "cap.pcap", "path": str(self.capture_path),
                   "sha256": prefix.sha256_file(self.capture_path), "size_bytes": self.capture_path.stat().st_size,
                   "include_in_baseline": True, "initial_class": "VOIP"}
        output = {4: io.StringIO(), 8: io.StringIO()}
        extractor = prefix.instances.Extractor(capture, output, io.StringIO())
        for row in frames:
            extractor.add(*prefix.decode_raw_packet(row.data, row.number, row.timestamp_ns))
        audit = extractor.finish()
        rows = [json.loads(line) for line in output[8].getvalue().splitlines()]
        for row, label in zip(rows, preparation.CLASSES):
            row["label"] = label
        table = [{**{key: value for key, value in row.items() if key not in ("debug_metadata_not_model_inputs", "instance_index", "policy_id")},
                  "partition": "test"} for row in rows]
        self._json(self.repo / "metadata/capture_inventory.json", {"captures": [capture]})
        policy = {"idle_seconds": 60, "boundary_policy": "idle-tcp",
                  "features_B": list(prefix.B_FEATURES), "features_C": list(prefix.C_FEATURES), "source_sha256": {},
                  "manifest_sha256": prefix.sha256_file(self.repo / "metadata/capture_inventory.json")}
        self._json(self.extraction / "policy.json", policy)
        self._json(self.extraction / "summary.json", {"status": "instance_extraction_complete", "captures": [
            dict(audit, evidence_directory="capture_001")]})
        self._jsonl(self.extraction / "capture_001/features_n8.jsonl", rows)
        self._jsonl(self.prepared / "table_n8.jsonl", table)
        manifest = {"status": "prepared", "classes": list(preparation.CLASSES), "extraction_run": str(self.extraction),
                    "payload_sha256": {"table_n8.jsonl": prefix.sha256_file(self.prepared / "table_n8.jsonl")},
                    "extraction_sha256": {relative: prefix.sha256_file(self.extraction / relative)
                        for relative in ("policy.json", "summary.json", "capture_001/features_n8.jsonl")}}
        self._json(self.prepared / "manifest.json", manifest)
        config = {"prepared_directory": str(self.prepared), "excluded_test_records": 6,
                  "input_and_source_sha256": {str(self.prepared / name): prefix.sha256_file(self.prepared / name)
                                               for name in ("manifest.json", "table_n8.jsonl")}}
        self._json(self.deployment / "run_config.json", config)
        self._json(self.deployment / "summary.json", {"output_sha256": {
            "run_config.json": prefix.sha256_file(self.deployment / "run_config.json")}})
        for name in ("flow_features.p4", "rf_b.p4", "rf_c.p4", "rf-models.json"):
            (self.repo / "p4" / name).write_text("fixture", encoding="utf-8")
        self.patches = [patch.object(preparation, "EXPECTED_TEST_COUNT", 6),
                        patch.object(preparation, "EXPECTED_CLASS_SUPPORT", {name: 1 for name in preparation.CLASSES}),
                        patch.object(preparation.integration, "load_deployment", return_value=(exports(), {}, {}))]
        for context in self.patches:
            context.start()
            self.addCleanup(context.stop)

    @staticmethod
    def _json(path, obj):
        path.write_text(json.dumps(obj), encoding="utf-8")

    @staticmethod
    def _jsonl(path, rows):
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def test_prepares_every_fixture_case_without_writes_and_capture_scanned_once(self):
        before = {str(path): prefix.sha256_file(path) for path in self.repo.rglob("*") if path.is_file()}
        with patch.object(preparation.replay.capture_io, "iter_capture", wraps=iter_capture) as reader:
            population = preparation.prepare_population(self.repo)
        after = {str(path): prefix.sha256_file(path) for path in self.repo.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(len(population["cases"]), 6)
        self.assertEqual(population["summary"]["class_support"], {name: 1 for name in preparation.CLASSES})
        self.assertEqual(reader.call_count, 1)
        self.assertFalse(population["models_fitted"])
        self.assertFalse(population["native_traffic_sent"])

    def test_modified_original_capture_fails_preparation(self):
        body = bytearray(self.capture_path.read_bytes())
        body[-1] ^= 1
        self.capture_path.write_bytes(body)
        with self.assertRaisesRegex(ValueError, "changed"):
            preparation.prepare_population(self.repo)

    def test_modified_frozen_table_fails_preparation(self):
        with (self.prepared / "table_n8.jsonl").open("a", encoding="utf-8") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            preparation.prepare_population(self.repo)


if __name__ == "__main__":
    unittest.main()
