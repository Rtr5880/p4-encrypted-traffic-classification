"""Deterministic high-rate recipes, scheduling, phase isolation and wire checks."""

from collections import Counter
from dataclasses import FrozenInstanceError
import ipaddress
import struct
import unittest
from unittest import mock
import zlib

import benchmark_workload as workload


class BenchmarkWorkloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pool = workload.select_flows(32)
        cls.heavy = cls.plan(128)
        cls.cached = cls.plan(512, "cached-forwarding")
        cls.high_warm, cls.high_measure = workload.build_phase_pair(
            5000, 5, 20, "classification-heavy", "high-rate")

    @classmethod
    def plan(cls, count, name="classification-heavy", phase="measurement", frame_bytes=128):
        ppf = 8 if name == "classification-heavy" else 32
        allocated = ((count + 8 * ppf - 1) // (8 * ppf)) * 8
        return workload.BenchmarkPlan(name, phase, cls.pool[:allocated], count, ppf,
                                      "unit-block", frame_bytes)

    def test_default_high_rate_counts_and_actual_classifications(self):
        warm, measured = self.high_warm, self.high_measure
        self.assertEqual((warm.packet_count, measured.packet_count), (25000, 100000))
        self.assertEqual((warm.flow_count, measured.flow_count), (3128, 12504))
        self.assertEqual((warm.expected_classifications, measured.expected_classifications),
                         (3120, 12496))
        self.assertEqual(sum(warm.actual_packets_per_flow), warm.packet_count)
        self.assertEqual(sum(measured.actual_packets_per_flow), measured.packet_count)
        self.assertEqual(warm.actual_packets_per_flow[-8:], (5,) * 8)
        self.assertEqual(measured.actual_packets_per_flow[-8:], (4,) * 8)
        self.assertEqual(len(measured.decision_positions()), measured.expected_classifications)

    def test_ten_thousand_pps_combined_recipe_and_sixty_second_recipe(self):
        warm, measured = workload.build_phase_pair(10000, 5, 20, "classification-heavy", "10k")
        self.assertEqual(warm.packet_count + measured.packet_count, 250000)
        self.assertEqual(warm.flow_count + measured.flow_count, 31256)
        self.assertEqual(len(set(warm.slots + measured.slots)), 31256)
        warm, measured = workload.build_phase_pair(5000, 5, 60, "classification-heavy", "60s")
        self.assertEqual(warm.flow_count + measured.flow_count, 40632)
        self.assertEqual(warm.packet_count + measured.packet_count, 325000)

    def test_warmup_measurement_have_no_shared_keys_or_state_slots(self):
        warm, measured = self.high_warm, self.high_measure
        self.assertFalse(set(warm.slots) & set(measured.slots))
        self.assertFalse(set(warm.flows) & set(measured.flows))
        self.assertFalse(set(warm.flows) & {flow.reversed() for flow in measured.flows})
        self.assertEqual(len(set(warm.slots + measured.slots)), warm.flow_count + measured.flow_count)
        self.assertNotEqual(warm.run_token, measured.run_token)
        self.assertNotEqual(warm.source_mac, measured.source_mac)
        self.assertIsNone(measured.sequence_from_frame(warm.frame_for(0)))
        self.assertIsNone(warm.sequence_from_frame(measured.frame_for(0)))

    def test_block_schedule_directions_and_transition(self):
        for plan in (self.heavy, self.cached):
            block_packets = 8 * plan.packets_per_flow
            for sequence in range(plan.packet_count):
                group, in_block = divmod(sequence, block_packets)
                index = group * 8 + in_block % 8
                ordinal = in_block // 8 + 1
                self.assertEqual(plan.flow_id_for(sequence), index)
                self.assertEqual(plan.packet_in_flow(sequence), ordinal)
                original = plan.flows[index]
                self.assertEqual(plan.flow_for(sequence), original if ordinal % 2 else original.reversed())
                self.assertEqual(plan.flow_for(sequence).slot, original.slot)
            self.assertEqual(plan.packet_in_flow(block_packets - 1), plan.packets_per_flow)
            self.assertEqual(plan.packet_in_flow(block_packets), 1)
            self.assertEqual(plan.flow_id_for(block_packets), 8)

    def test_partial_block_counts_match_all_actual_packet_ordinals(self):
        for name in ("classification-heavy", "cached-forwarding"):
            for count in (1, 7, 8, 55, 56, 57, 63, 64, 65, 71, 72, 119, 120, 121, 127, 128, 129, 255, 256):
                with self.subTest(name=name, count=count):
                    plan = self.plan(count, name)
                    actual = Counter(plan.flow_id_for(seq) for seq in range(count))
                    decisions = tuple(seq for seq in range(count) if plan.packet_in_flow(seq) == 8)
                    cached = sum(plan.packet_in_flow(seq) > 8 for seq in range(count))
                    self.assertEqual(plan.actual_packets_per_flow,
                                     tuple(actual[index] for index in range(plan.flow_count)))
                    self.assertEqual(plan.used_flow_count, len(actual))
                    self.assertEqual(plan.decision_positions(), decisions)
                    self.assertEqual(plan.expected_classifications, len(decisions))
                    self.assertEqual(plan.expected_cached_packets, cached)

    def test_decision_times_are_distributed_through_window(self):
        for plan in (self.heavy, self.cached):
            expected = tuple(base + index for base in range(56, plan.packet_count, 8 * plan.packets_per_flow)
                             for index in range(8) if base + index < plan.packet_count)
            self.assertEqual(plan.decision_positions(), expected)
        positions = self.high_measure.decision_positions()
        self.assertLess(positions[0], 64)
        self.assertGreater(positions[-1], self.high_measure.packet_count - 128)
        for lower in (0, 25000, 50000, 75000):
            self.assertTrue(any(lower <= sequence < lower + 25000 for sequence in positions))
        self.assertEqual(self.heavy.nominal_offset_ns(127, 100), 1270000000)
        self.assertEqual(self.heavy.nominal_offset_ns(1, 3), 333333333)

    def test_normal_wire_encoding_checksum_and_big_sequence(self):
        for frame_bytes in (workload.MIN_FRAME_BYTES, 128, workload.MAX_FRAME_BYTES):
            plan = self.plan(128, frame_bytes=frame_bytes)
            for sequence in (0, 7, 8, 56, 63, 64, 127):
                frame = plan.frame_for(sequence)
                self.assertEqual(len(frame), frame_bytes)
                self.assertEqual(frame[12:14], b"\x08\x00")
                self.assertEqual(frame[14], 0x45)
                self.assertEqual(struct.unpack_from("!H", frame, 16)[0], frame_bytes - 14)
                self.assertEqual(struct.unpack_from("!HH", frame, 38), (frame_bytes - 34, 0))
                folded = sum(struct.unpack("!10H", frame[14:34]))
                while folded >> 16:
                    folded = (folded & 65535) + (folded >> 16)
                self.assertEqual(folded, 65535)
                decoded = workload.parse_frame(frame)
                self.assertEqual(decoded.sequence, sequence)
                self.assertEqual(decoded.flow_id, plan.flow_id_for(sequence))
                self.assertEqual(decoded.packet_ordinal, plan.packet_in_flow(sequence))
                self.assertEqual(decoded.flow, plan.flow_for(sequence))
                self.assertEqual(plan.sequence_from_frame(frame), sequence)
        frame = self.high_measure.frame_for(65536)
        self.assertEqual(struct.unpack_from("!H", frame, 18)[0], 0)
        self.assertEqual(workload.parse_frame(frame).sequence, 65536)
        self.assertEqual(self.high_measure.sequence_from_frame(frame), 65536)

    def test_fast_decoder_uses_fixed_tag_and_rejects_inconsistent_tags(self):
        original = self.heavy.frame_for(64)
        with mock.patch.object(workload, "parse_frame", side_effect=AssertionError("slow parser")), \
                mock.patch.object(workload.ipaddress, "IPv4Address", side_effect=AssertionError("IP parsing")):
            self.assertEqual(self.heavy.sequence_from_frame(original), 64)
        for offset in (42, 46, 47, 50):
            bad = bytearray(original)
            bad[offset] ^= 1
            self.assertIsNone(self.heavy.sequence_from_frame(bytes(bad)))
        for offset, fmt, value in ((66, "!Q", 128), (74, "!I", 0), (78, "!I", 2)):
            bad = bytearray(original)
            struct.pack_into(fmt, bad, offset, value)
            self.assertIsNone(self.heavy.sequence_from_frame(bytes(bad)))
        for bad in (b"", b"unrelated", original[:-1], original + b"\x00", bytearray(original), None):
            self.assertIsNone(self.heavy.sequence_from_frame(bad))

    def test_association_and_full_frame_corruption_check_are_distinct(self):
        original = self.heavy.frame_for(8)
        for offset in (24, 34, len(original) - 1):
            bad = bytearray(original)
            bad[offset] ^= 1
            self.assertEqual(self.heavy.sequence_from_frame(bytes(bad)), 8)
            self.assertNotEqual(bytes(bad), original)

    def test_same_recipe_is_identical_across_four_modes(self):
        modes = [workload.build_phase_pair(100, 5, 20, "cached-forwarding", "repeated-block")
                 for _ in range(4)]
        for phase_index in (0, 1):
            first = modes[0][phase_index]
            for pair in modes[1:]:
                plan = pair[phase_index]
                self.assertEqual(plan.manifest(), first.manifest())
                self.assertEqual([plan.frame_for(seq) for seq in range(plan.packet_count)],
                                 [first.frame_for(seq) for seq in range(first.packet_count)])
        foreign = workload.build_phase_pair(100, 5, 20, "cached-forwarding", "another-block")[1]
        self.assertIsNone(modes[0][1].sequence_from_frame(foreign.frame_for(0)))

    def test_manifest_exposes_actual_partial_counts_and_cached_packets(self):
        plan = self.plan(65, "cached-forwarding")
        manifest = plan.manifest()
        self.assertEqual(manifest["phase"], "measurement")
        self.assertEqual(manifest["classification_packet_count"], 8)
        self.assertEqual(manifest["cached_forwarding_packet_count"], 1)
        self.assertEqual(manifest["preclassification_packet_count"], 56)
        self.assertEqual(manifest["actual_packets_per_flow"], [9] + [8] * 7)
        self.assertEqual(sum(manifest[field] for field in ("classification_packet_count",
                         "cached_forwarding_packet_count", "preclassification_packet_count")), 65)
        self.assertEqual(manifest["partial_final_block_packets"], 65)
        self.assertEqual(manifest["completed_flow_count"], 0)
        self.assertIsNone(manifest["accuracy_oracle"])
        self.assertIsNone(manifest["ground_truth_activity_labels"])
        self.assertEqual(len(manifest["workload_recipe_sha256"]), 64)
        short = self.plan(1).manifest()
        self.assertEqual(short["allocated_flow_count"], 8)
        self.assertEqual(short["used_flow_count"], 1)
        self.assertEqual(short["unused_allocated_flow_count"], 7)

    def test_zero_warmup_is_empty_and_measurement_isolated(self):
        warm, measured = workload.build_phase_pair(10, 0, 1, "classification-heavy", "smoke")
        self.assertEqual((warm.packet_count, warm.flow_count, warm.expected_classifications), (0, 0, 0))
        self.assertEqual(warm.slots, ())
        self.assertEqual(warm.decision_positions(), ())
        self.assertEqual(warm.actual_packets_per_flow, ())
        self.assertEqual(warm.manifest()["actual_packets_per_flow"], [])
        with self.assertRaises(ValueError):
            warm.frame_for(0)
        self.assertEqual(measured.packet_count, 10)

    def test_decimal_duration_counts_are_exact_without_rounding(self):
        warm, measured = workload.build_phase_pair(10, 0.1, 0.3, "classification-heavy", "decimal")
        self.assertEqual((warm.packet_count, measured.packet_count), (1, 3))
        for arguments in ((3, 0, 0.5), (10, 0.15, 1), (1, 0, 0.00001)):
            with self.assertRaisesRegex(ValueError, "integer packet count"):
                workload.build_phase_pair(*arguments, "classification-heavy", "fractional")

    def test_limits_are_checked_before_allocation(self):
        invalid = (
            (0, 5, 20), (10001, 5, 20), (True, 5, 20), (float("nan"), 5, 20),
            (float("inf"), 5, 20), (10**1000, 5, 20), (100, -1, 20), (100, 10.01, 20),
            (100, True, 20), (100, 5, 0), (100, 5, 60.01),
            (100, 5, float("nan")), (10000, 5, 60),
        )
        with mock.patch.object(workload, "select_flows", side_effect=AssertionError("allocation")):
            for args in invalid:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    workload.build_phase_pair(*args, "classification-heavy", "unsafe")
            with self.assertRaisesRegex(ValueError, "slot safety limit"):
                workload.build_phase_pair(10000, 0, 50, "classification-heavy", "slot-bound")
            for kwargs in ({"namespace": -1}, {"namespace": 65534}, {"namespace": True},
                           {"concurrency": 7}, {"concurrency": True},
                           {"frame_bytes": 81}, {"frame_bytes": 1515}):
                with self.assertRaises(ValueError):
                    workload.build_phase_pair(100, 5, 20, "classification-heavy", "unsafe", **kwargs)
            for name, run_id in (("unknown", "run"), ("classification-heavy", ""),
                                 ("cached-forwarding", "x" * 1025)):
                with self.assertRaises(ValueError):
                    workload.build_phase_pair(100, 5, 20, name, run_id)

    def test_maximum_slot_and_packet_boundaries_are_representable(self):
        warm, measured = workload.build_phase_pair(10000, 0, 48, "classification-heavy", "slot-limit",
                                                   namespace=65533)
        self.assertEqual(warm.flow_count + measured.flow_count, workload.MAX_OCCUPIED_SLOTS)
        self.assertEqual(len(set(measured.slots)), workload.MAX_OCCUPIED_SLOTS)
        warm, measured = workload.build_phase_pair(10000, 0, 50, "cached-forwarding", "packet-limit")
        self.assertEqual(warm.packet_count + measured.packet_count, workload.MAX_TOTAL_PACKETS)
        with self.assertRaisesRegex(ValueError, "packet safety limit"):
            workload.build_phase_pair(10000, 0, 50.0001, "cached-forwarding", "over-limit")

    def test_direct_plan_guards_and_immutability(self):
        with self.assertRaises(FrozenInstanceError):
            self.heavy.packet_count = 64
        variants = (
            {"name": "unknown"}, {"phase": "other"}, {"phase": "measurement", "packet_count": 0},
            {"packets_per_flow": 9}, {"packet_count": True}, {"flows": list(self.heavy.flows)},
            {"flows": self.heavy.flows[:-1]}, {"flows": (self.pool[0],) * 16},
            {"flows": tuple(workload.FlowTuple("1.2.3.4", "5.6.7.8", 20000 + i, 20000)
                             for i in range(16))},
        )
        base = dict(name=self.heavy.name, phase=self.heavy.phase, flows=self.heavy.flows,
                    packet_count=self.heavy.packet_count, packets_per_flow=8, run_id="invalid")
        for values in variants:
            with self.subTest(values=values), self.assertRaises(ValueError):
                workload.BenchmarkPlan(**(base | values))
        for sequence in (-1, 128, True, 1.0):
            with self.assertRaises(ValueError):
                self.heavy.frame_for(sequence)
        for rate in (0, 10001, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                self.heavy.nominal_offset_ns(0, rate)

    def test_allocator_crc_matches_frozen_network_key(self):
        for flow in workload.select_flows(32, namespace=65533):
            low, high = sorted(((int(ipaddress.IPv4Address(flow.src)), flow.sport),
                                (int(ipaddress.IPv4Address(flow.dst)), flow.dport)))
            slot = zlib.crc32(struct.pack("!BIHIH", 17, *low, *high)) % 65536
            self.assertEqual(flow.slot, slot)
            self.assertEqual(flow.reversed().slot, slot)
        self.assertEqual(workload.select_flows(0), ())
        for count in (-1, 60001, True):
            with self.assertRaises(ValueError):
                workload.select_flows(count)


if __name__ == "__main__":
    unittest.main()
