"""Byte-level and state-key checks for synthetic performance workload plans."""

import ipaddress
import struct
import unittest
import zlib

import performance_workload as workload


class PerformanceWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.heavy = workload.build_workload("classification-heavy", 32, 8, "unit-pilot")

    def test_pilot_count_direction_and_eighth_positions(self):
        self.assertEqual(self.heavy.packet_count, 256)
        self.assertEqual(self.heavy.decision_positions(), tuple(range(224, 256)))
        self.assertEqual(self.heavy.expected_classifications, 32)
        for flow_index, flow in enumerate(self.heavy.flows):
            for packet_index in range(8):
                sequence = packet_index * 32 + flow_index
                actual = self.heavy.flow_for(sequence)
                self.assertEqual(actual, flow if packet_index % 2 == 0 else flow.reversed())
                self.assertEqual(actual.slot, flow.slot)
                self.assertEqual(self.heavy.packet_in_flow(sequence), packet_index + 1)

    def test_independent_wire_layout_and_ipv4_checksum(self):
        for frame_bytes in (128, 512, 1500):
            plan = workload.build_workload("classification-heavy", 2, 8, "checksum", frame_bytes)
            for sequence in (0, 2, 15):
                frame = plan.frame_for(sequence)
                self.assertEqual(len(frame), frame_bytes)
                self.assertEqual(frame[12:14], b"\x08\x00")
                self.assertEqual(frame[14], 0x45)
                self.assertEqual(struct.unpack_from("!H", frame, 16)[0], frame_bytes - 14)
                self.assertEqual(struct.unpack_from("!H", frame, 18)[0], sequence)
                words = struct.unpack("!10H", frame[14:34])
                folded = sum(words)
                while folded >> 16:
                    folded = (folded & 65535) + (folded >> 16)
                self.assertEqual(folded, 65535)
                self.assertEqual(struct.unpack_from("!HH", frame, 38), (frame_bytes - 34, 0))
                self.assertEqual(frame[42:46], b"ETCP")
                self.assertEqual(struct.unpack_from("!Q", frame, 66)[0], sequence)
                decoded = workload.parse_frame(frame)
                self.assertEqual(decoded.sequence, sequence)
                self.assertEqual(decoded.flow, plan.flow_for(sequence))
                self.assertEqual(plan.sequence_from_frame(frame), sequence)

    def test_exact_crc_network_order_and_numeric_endpoint_sort(self):
        flow = workload.FlowTuple("198.19.0.1", "198.18.0.10", 30000, 25000)
        numeric_low = int(ipaddress.IPv4Address("198.18.0.10"))
        numeric_high = int(ipaddress.IPv4Address("198.19.0.1"))
        independent = zlib.crc32(struct.pack("!BIHIH", 17, numeric_low, 25000,
                                           numeric_high, 30000)) % 65536
        self.assertEqual(flow.slot, independent)
        self.assertEqual(flow.reversed().slot, independent)

    def test_reserved_warmup_slots_cannot_alias_measured_slots(self):
        warm = workload.build_workload("warm-up", 32, 8, "warm")
        measured = workload.build_workload("cached-forwarding", 4096, 16, "measure",
                                            namespace=1, reserved_slots=warm.slots)
        self.assertEqual(len(set(measured.slots)), 4096)
        self.assertFalse(set(measured.slots) & set(warm.slots))
        self.assertEqual(measured.packet_count, 65536)

    def test_same_recipe_is_identical_for_both_models(self):
        second = workload.build_workload("classification-heavy", 32, 8, "unit-pilot")
        self.assertEqual(self.heavy.manifest(), second.manifest())
        self.assertEqual([self.heavy.frame_for(sequence) for sequence in range(256)],
                         [second.frame_for(sequence) for sequence in range(256)])
        foreign = workload.build_workload("classification-heavy", 32, 8, "different-run")
        self.assertIsNone(self.heavy.sequence_from_frame(foreign.frame_for(0)))
        self.assertNotEqual(self.heavy.source_mac, foreign.source_mac)
        self.assertNotEqual(self.heavy.destination_mac, foreign.destination_mac)
        self.assertEqual(self.heavy.source_mac[0] & 3, 2)
        self.assertEqual(self.heavy.destination_mac[0] & 3, 2)

    def test_unrelated_malformed_and_inconsistent_tags_are_rejected(self):
        self.assertIsNone(self.heavy.sequence_from_frame(b"unrelated"))
        frame = bytearray(self.heavy.frame_for(0))
        frame[24] ^= 1  # IPv4 checksum byte.
        self.assertIsNone(self.heavy.sequence_from_frame(bytes(frame)))
        frame = bytearray(self.heavy.frame_for(0))
        frame[46] = 2  # Unsupported payload-tag version.
        self.assertIsNone(self.heavy.sequence_from_frame(bytes(frame)))
        frame = bytearray(self.heavy.frame_for(0))
        struct.pack_into("!I", frame, 74, 31)  # Inconsistent flow ID.
        self.assertIsNone(self.heavy.sequence_from_frame(bytes(frame)))
        frame = bytearray(self.heavy.frame_for(0))
        struct.pack_into("!I", frame, 78, 8)  # Inconsistent ordinal.
        self.assertIsNone(self.heavy.sequence_from_frame(bytes(frame)))
        frame = bytearray(self.heavy.frame_for(0))
        struct.pack_into("!Q", frame, 66, 256)  # Out-of-range sequence.
        self.assertIsNone(self.heavy.sequence_from_frame(bytes(frame)))

    def test_corrupt_payload_padding_associates_but_full_byte_check_fails(self):
        frame = bytearray(self.heavy.frame_for(0))
        frame[-1] ^= 1
        self.assertEqual(self.heavy.sequence_from_frame(bytes(frame)), 0)
        self.assertNotEqual(bytes(frame), self.heavy.frame_for(0))

    def test_uniform_schedule_keeps_idle_semantics_and_no_injected_clock(self):
        self.assertEqual(self.heavy.nominal_offset_ns(255, 100), 2550000000)
        self.assertEqual(self.heavy.nominal_offset_ns(1, 3), 333333333)
        for bad in (0, -1, float("inf"), float("nan"), True):
            with self.assertRaises(ValueError):
                self.heavy.nominal_offset_ns(0, bad)
        with self.assertRaises(ValueError):
            self.heavy.nominal_offset_ns(0, 32 / 60)

    def test_bounded_inputs_and_invalid_flows_are_rejected(self):
        for sequence in (-1, 256, True, 1.0):
            with self.assertRaises(ValueError):
                self.heavy.frame_for(sequence)
        for parameters in ((0, 8, 128), (4097, 8, 128), (32, 7, 128),
                           (32, 9, 128), (32, 8, 81), (32, 8, 1515), (4096, 32, 128)):
            with self.assertRaises(ValueError):
                workload.build_workload("classification-heavy", *parameters[:2],
                                        "bounds", frame_bytes=parameters[2])
        with self.assertRaises(ValueError):
            workload.build_workload("cached-forwarding", 8, 8, "bounds")
        with self.assertRaises(ValueError):
            workload.build_workload("warm-up", 8, 8, "bounds", reserved_slots=(-1,))
        with self.assertRaises(ValueError):
            workload.build_workload("warm-up", 8, 8, "bounds", reserved_slots=range(65536))
        with self.assertRaises(ValueError):
            workload.WorkloadPlan("warm-up", (self.heavy.flows[0],) * 2, 8, "collision")
        with self.assertRaises(ValueError):
            workload.FlowTuple("198.18.0.1", "198.19.0.1", 53, 20000)
        with self.assertRaises(ValueError):
            workload.WorkloadPlan("warm-up", (workload.FlowTuple("1.2.3.4", "5.6.7.8", 20, 21),),
                                  8, "outside")

    def test_cached_workload_exposes_startup_classification_and_steady_packets(self):
        plan = workload.build_workload("cached-forwarding", 8, 32, "cached")
        self.assertEqual(plan.packet_count, 256)
        self.assertEqual(plan.decision_positions(), tuple(range(56, 64)))
        self.assertEqual(plan.packet_count - 8 * plan.flow_count, 192)
        manifest = plan.manifest()
        self.assertEqual(manifest["expected_classifications_if_fresh_state_and_no_loss"], 8)
        self.assertIsNone(manifest["accuracy_oracle"])
        self.assertFalse(manifest["ports_and_addresses_are_model_inputs"])
        self.assertTrue(manifest["engineered_collision_free"])
        self.assertEqual(len(manifest["workload_recipe_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
