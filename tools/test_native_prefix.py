"""Small read-only prefix fixtures; no PCAP downloads, training or root access."""

import copy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import native_prefix as prefix
from pcap_replay_io import ClassicPcapWriter, PacketRecord


def udp(size=50, reverse=False, sport=41294):
    src, dst = (bytes((10, 8, 0, 10)), bytes((173, 194, 76, 127)))
    ports = sport, 19305
    if reverse:
        src, dst, ports = dst, src, ports[::-1]
    body = bytearray(size)
    body[0] = 0x45
    struct.pack_into("!H", body, 2, size)
    body[8:10] = bytes((64, 17))
    body[12:16], body[16:20] = src, dst
    struct.pack_into("!HHHH", body, 20, *ports, size - 20, 0)
    body[28:] = bytes((index % 256 for index in range(size - 28)))
    return bytes(body)


def make_fixture(record_id="parent:instances-v1:idle-tcp:60s:1:n8", protocol=17):
    sizes = [148, 132, 50, 189, 98, 169, 74, 74]
    gaps = [0, 41451, 27928, 37759, 38207, 26100, 9886, 59]
    reverse = [False, True, False, False, False, False, True, True]
    time_us, raw_records, packets, trace = 1_429_042_478_422_666, [], [], []
    for index, (size, gap, rev) in enumerate(zip(sizes, gaps, reverse), 1):
        time_us += gap
        raw = udp(size, rev)
        packet, tcp = prefix.decode_raw_packet(raw, index, time_us * 1000)
        packets.append(packet)
        raw_records.append(PacketRecord(index, time_us * 1000, len(raw), len(raw), 101, raw))
        trace.append({"frame": index, "raw_timestamp_ns": time_us * 1000,
                      "effective_timestamp_us": time_us, "timestamp_adjustment_ns": 0,
                      "size_bytes": size, "direction": "R" if rev else "F",
                      "iat_us": None if index == 1 else gap, "tcp": None})
    b, c = prefix.feature_statistics(packets)
    record = {"record_id": record_id, "instance_id": record_id[:-3], "instance_index": 1,
              "parent_candidate_conversation_id": "parent", "capture_id": "folder/cap.pcap",
              "capture_sha256": "capturehash", "partition": "test", "n": 8,
              "label": "UNUSED", "features_B": b, "features_C": c}
    extracted = copy.deepcopy(record)
    extracted.pop("partition")
    extracted["debug_metadata_not_model_inputs"] = {
        "key": [protocol, ["10.8.0.10", 41294], ["173.194.76.127", 19305]],
        "forward_endpoint": ["10.8.0.10", 41294], "first_frame": 1, "decision_frame": 8,
        "start_reason": "first_observed", "prefix_timestamp_adjustments": 0,
        "observation_delay_us": b["iat_sum"], "trace": trace}
    return record, extracted, raw_records


class DecodeAndArithmeticTests(unittest.TestCase):
    def test_independent_features_and_packet_bytes(self):
        _, extracted, raw = make_fixture()
        bodies, b, c, relative = prefix.validate_original_packets(extracted, raw)
        self.assertEqual(b, {"size_min": 50, "size_max": 189, "size_sum": 934,
                             "iat_min": 59, "iat_max": 41451, "iat_sum": 181390})
        self.assertEqual(c["reverse_packet_count"], 3)
        self.assertEqual(c["direction_change_count"], 3)
        self.assertEqual(relative, [0, 41451, 69379, 107138, 145345, 171445, 181331, 181390])
        for body, original in zip(bodies, raw):
            self.assertEqual(bytes.fromhex(body["raw_ip_hex"]), original.data)
            self.assertEqual(body["sha256"], hashlib.sha256(original.data).hexdigest())

    def test_tcp_flags_sequence_and_payload(self):
        body = bytearray(45)
        body[0], body[8], body[9] = 0x45, 64, 6
        struct.pack_into("!H", body, 2, len(body))
        body[12:16], body[16:20] = bytes((1, 2, 3, 4)), bytes((5, 6, 7, 8))
        struct.pack_into("!HHII", body, 20, 5000, 443, 1234, 5678)
        body[32], body[33] = 0x50, 0x13
        packet, tcp = prefix.decode_raw_packet(bytes(body), 2, 1234567)
        self.assertEqual(packet.size, 45)
        self.assertEqual(asdict(tcp), {"syn": True, "ack": True, "fin": True,
                                      "rst": False, "seq": 1234, "ack_number": 5678, "payload_len": 5})

    def test_rejected_raw_headers(self):
        valid = udp()
        cases = []
        for position, value in ((0, 0x65), (9, 1), (6, 0x20)):
            body = bytearray(valid)
            body[position] = value
            cases.append(bytes(body))
        cases.extend((valid[:19], valid[:-1], udp(sport=53)))
        malformed_udp = bytearray(valid)
        struct.pack_into("!H", malformed_udp, 24, 7)
        cases.append(bytes(malformed_udp))
        for body in cases:
            with self.subTest(body=body.hex()), self.assertRaises(ValueError):
                prefix.decode_raw_packet(body, 1, 0)

    def test_trace_mismatches_fail_loudly(self):
        _, extracted, raw = make_fixture()
        mutations = (
            lambda item: item["features_C"].update(reverse_packet_count=7),
            lambda item: item["debug_metadata_not_model_inputs"]["trace"][2].update(size_bytes=999),
            lambda item: item["debug_metadata_not_model_inputs"]["trace"][2].update(iat_us=999),
            lambda item: item["debug_metadata_not_model_inputs"]["trace"][2].update(direction="R"),
        )
        for mutation in mutations:
            bad = copy.deepcopy(extracted)
            mutation(bad)
            with self.assertRaises(ValueError):
                prefix.validate_original_packets(bad, raw)
        with self.assertRaises(ValueError):
            prefix.validate_original_packets(extracted, raw[:-1])
        with self.assertRaises(ValueError):
            prefix.validate_original_packets(extracted, [replace(raw[0], wire_len=999)] + raw[1:])

    def test_timestamp_flooring_before_subtraction(self):
        packets = [prefix.decode_raw_packet(udp(), index + 1, 999 + index * 1001)[0]
                   for index in range(8)]
        b, _ = prefix.feature_statistics(packets)
        self.assertEqual(b["iat_sum"], 8)
        self.assertEqual(b["iat_max"], 2)
        with self.assertRaises(ValueError):
            prefix.feature_statistics(packets, [0, 1, 2, 3, 2, 5, 6, 7])
        with self.assertRaises(ValueError):
            prefix.feature_statistics(packets[:7])


class SelectionTests(unittest.TestCase):
    def test_prefer_udp_then_record_id_not_label(self):
        tcp_table, tcp_row, _ = make_fixture("aaa:n8", protocol=6)
        udp_table, udp_row, _ = make_fixture("zzz:n8")
        udp_table["label"], udp_row["label"] = "not-used", "different-not-used"
        selected, _, count = prefix.select_record([tcp_table, udp_table], [tcp_row, udp_row], "folder/cap.pcap")
        self.assertEqual(selected["record_id"], "zzz:n8")
        self.assertEqual(count, 2)

    def test_no_development_continuation_long_or_adjusted_prefix(self):
        table, row, _ = make_fixture()
        cases = []
        dev = copy.deepcopy(table)
        dev["partition"] = "development"
        cases.append((dev, row))
        for key, value in (("start_reason", "idle_timeout"), ("prefix_timestamp_adjustments", 1)):
            bad = copy.deepcopy(row)
            bad["debug_metadata_not_model_inputs"][key] = value
            cases.append((table, bad))
        continuation = copy.deepcopy(row)
        continuation["instance_index"] = 2
        cases.append((table, continuation))
        adjusted = copy.deepcopy(row)
        adjusted["debug_metadata_not_model_inputs"]["trace"][1]["timestamp_adjustment_ns"] = 1
        cases.append((table, adjusted))
        for table_case, row_case in cases:
            with self.assertRaises(ValueError):
                prefix.select_record([table_case], [row_case], "folder/cap.pcap")
        with self.assertRaises(ValueError):
            prefix.select_record([table], [row], "folder/cap.pcap", max_duration_seconds=0.01)

    def test_prepared_feature_mismatch_is_not_silently_skipped(self):
        table, row, _ = make_fixture()
        table["features_B"]["size_sum"] += 1
        with self.assertRaisesRegex(ValueError, "features_B"):
            prefix.select_record([table], [row], "folder/cap.pcap")

    def test_duration_guard(self):
        table, row, _ = make_fixture()
        for limit in (0, -1, 60, float("nan"), float("inf")):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                prefix.select_record([table], [row], "folder/cap.pcap", limit)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.prepared = self.repo / "results" / "baseline_preparation" / prefix.PREPARED_RUN
        self.extraction = self.repo / "extraction"
        (self.extraction / "capture_001").mkdir(parents=True)
        self.prepared.mkdir(parents=True)
        (self.repo / "metadata").mkdir()
        table, extracted, raw = make_fixture()
        self.capture_path = self.repo / "cap.pcap"
        with ClassicPcapWriter(self.capture_path, linktype=101) as writer:
            for item in raw:
                writer.write(item.timestamp_ns, item.data)
        capture_digest = prefix.sha256_file(self.capture_path)
        table["capture_sha256"] = extracted["capture_sha256"] = capture_digest
        capture = {"capture_id": "folder/cap.pcap", "filename": "cap.pcap",
                   "path": str(self.capture_path), "sha256": capture_digest,
                   "size_bytes": self.capture_path.stat().st_size, "include_in_baseline": True}
        self._write(self.repo / "metadata" / "capture_inventory.json", {"captures": [capture]})
        inventory_hash = prefix.sha256_file(self.repo / "metadata" / "capture_inventory.json")
        policy = {"idle_seconds": 60, "boundary_policy": "idle-tcp",
                  "features_B": list(prefix.B_FEATURES), "features_C": list(prefix.C_FEATURES),
                  "manifest_sha256": inventory_hash}
        self._write(self.extraction / "policy.json", policy)
        self._write(self.extraction / "summary.json", {"captures": [
            {"capture_id": capture["capture_id"], "evidence_directory": "capture_001"}]})
        self._write(self.extraction / "capture_001" / "features_n8.jsonl", extracted, jsonl=True)
        self._write(self.prepared / "table_n8.jsonl", table, jsonl=True)
        manifest = {"status": "prepared", "extraction_run": str(self.extraction),
                    "payload_sha256": {"table_n8.jsonl": prefix.sha256_file(self.prepared / "table_n8.jsonl")},
                    "extraction_sha256": {name: prefix.sha256_file(self.extraction / name)
                        for name in ("policy.json", "summary.json", "capture_001/features_n8.jsonl")}}
        self._write(self.prepared / "manifest.json", manifest)

    @staticmethod
    def _write(path, obj, jsonl=False):
        path.write_text(json.dumps(obj) + ("\n" if jsonl else ""), encoding="utf-8")

    def test_complete_fixture_reads_only_and_preserves_originals(self):
        before = {str(path): prefix.sha256_file(path) for path in self.repo.rglob("*") if path.is_file()}
        bundle = prefix.prepare_prefix(self.repo, "cap.pcap")
        after = {str(path): prefix.sha256_file(path) for path in self.repo.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(len(bundle["packets"]), 8)
        self.assertEqual(bundle["record"]["partition"], "test")
        self.assertFalse(bundle["selection"]["uses_labels_or_predictions"])
        self.assertFalse(bundle["accuracy_scored"])
        self.assertTrue(bundle["native_clock_required"])
        self.assertEqual(len(bundle["input_sha256"]), 7)

    def test_capture_checksum_mismatch(self):
        raw = bytearray(self.capture_path.read_bytes())
        raw[-1] ^= 1
        self.capture_path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "checksum"):
            prefix.prepare_prefix(self.repo, "cap.pcap")

    def test_prepared_table_checksum_mismatch(self):
        with (self.prepared / "table_n8.jsonl").open("a") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(ValueError, "checksum"):
            prefix.prepare_prefix(self.repo, "cap.pcap")

    def test_unknown_capture_fails(self):
        with self.assertRaisesRegex(ValueError, "absent"):
            prefix.prepare_prefix(self.repo, "missing.pcap")


if __name__ == "__main__":
    unittest.main()
