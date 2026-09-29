"""Controlled candidate-instance tests; synthetic packets, not measured PCAPs."""

from dataclasses import replace
import io
import json
import unittest

import extract_flow_instances as extractor
import evaluate_idle_timeouts as audit
import test_extract_feature_pilot as fixtures
import validate_instance_output as validator


CAPTURE = {"filename": "synthetic.pcap", "capture_id": "synthetic/synthetic.pcap",
           "sha256": "a" * 64, "initial_class": "MAIL"}
packet = fixtures.packet
ACK = extractor.Tcp(False, True, False, False, 100, 200, 0)


def tcp(**changes):
    return replace(ACK, **changes)


def run(packets, controls=None, **options):
    outputs = {n: io.StringIO() for n in (4, 8)}
    instances = io.StringIO()
    worker = extractor.Extractor(CAPTURE, outputs, instances, **options)
    if controls is None:
        controls = [ACK if p.protocol == 6 else None for p in packets]
    for p, control in zip(packets, controls, strict=True):
        worker.add(p, control)
    summary = worker.finish()
    records = {n: [json.loads(line) for line in stream.getvalue().splitlines()]
               for n, stream in outputs.items()}
    return summary, records, [json.loads(line) for line in instances.getvalue().splitlines()]


class FeatureTests(unittest.TestCase):
    def test_features_and_parent_identity_match_pilot(self):
        packets = fixtures.oracle_packets()
        summary, records, instances = run(packets)
        original = fixtures.accumulate(packets, capture_id=CAPTURE["capture_id"],
                                      capture_sha256=CAPTURE["sha256"])
        for n in (4, 8):
            record = records[n][0]
            self.assertEqual(record["features_C"], original.snapshots[n]["features"])
            self.assertEqual(record["features_B"], {k: record["features_C"][k] for k in extractor.B_FEATURES})
            self.assertEqual(record["parent_candidate_conversation_id"], original.conversation_id)
            validator.verify_features(record, n)
        self.assertEqual(summary["timing"]["timestamp_adjustments"], 1)
        self.assertEqual(len(instances), 1)

    def test_snapshots_freeze_and_no_rolling_windows(self):
        packets = fixtures.oracle_packets() + [packet(i, 1000 + i, size=65535) for i in range(9, 20)]
        summary, records, instances = run(packets)
        expected = fixtures.accumulate(fixtures.oracle_packets())
        for n in (4, 8):
            self.assertEqual(len(records[n]), 1)
            self.assertEqual(records[n][0]["features_C"], expected.snapshots[n]["features"])
        self.assertEqual(instances[0]["debug_metadata_not_model_inputs"]["eligible_packets"], 19)
        self.assertEqual(summary["eligible_packets"], 19)

    def test_short_instances_are_counted_per_window(self):
        for count, expected4, expected8 in ((1, 0, 0), (3, 0, 0), (4, 1, 0), (7, 1, 0), (8, 1, 1)):
            with self.subTest(count=count):
                summary, records, _ = run(fixtures.oracle_packets()[:count])
                for n, expected in ((4, expected4), (8, expected8)):
                    self.assertEqual(len(records[n]), expected)
                    self.assertEqual(summary["windows"][str(n)]["short_instances"], 1 - expected)

    def test_true_zero_retained_but_no_artificial_initial_zero(self):
        for times, expected in (([0, 10, 30, 60], (10, 30, 60)), ([0, 0, 1, 2], (0, 1, 2))):
            _, records, _ = run([packet(i + 1, t) for i, t in enumerate(times)])
            f = records[4][0]["features_B"]
            self.assertEqual((f["iat_min"], f["iat_max"], f["iat_sum"]), expected)

    def test_floor_absolute_time_then_subtract(self):
        times = [999, 1000, 1999, 2000]
        _, records, _ = run([packet(i + 1, 0, timestamp_ns=t) for i, t in enumerate(times)])
        self.assertEqual(records[4][0]["features_B"]["iat_sum"], 2)

    def test_parent_clocks_independent(self):
        packets = [packet(1, 100_000_000), packet(2, 0, sport=1000), packet(3, 100_000_001)]
        summary, _, _ = run(packets)
        self.assertEqual(summary["candidate_conversations"], 2)
        self.assertEqual(summary["timing"]["raw_backward_steps"], 0)

    def test_running_max_not_previous_raw_time(self):
        summary, records, _ = run([packet(i + 1, t) for i, t in enumerate([100, 110, 105, 107, 115])])
        self.assertEqual(summary["timing"]["raw_backward_steps"], 1)
        self.assertEqual(summary["timing"]["timestamp_adjustments"], 2)
        self.assertEqual(records[4][0]["features_B"]["iat_sum"], 10)

    def test_width_limits_fail_instead_of_wrapping(self):
        prefix = extractor.Prefix(packet(1, 0))
        for i in range(8):
            prefix.add(packet(i + 1, i, size=65535), i * 1000, ACK)
        self.assertEqual(prefix.snapshots[8]["features_C"]["size_sum"], 524280)
        prefix = extractor.Prefix(packet(1, 0))
        with self.assertRaisesRegex(ValueError, "width"):
            for i, t in enumerate([0, 2**48, 2**48, 2**48]):
                prefix.add(packet(i + 1, t), t * 1000, ACK)

    def test_model_inputs_exclude_labels_ports_flags_and_ids(self):
        _, records, _ = run(fixtures.oracle_packets())
        for n in (4, 8):
            self.assertEqual(len(records[n][0]["features_B"]), 6)
            self.assertEqual(len(records[n][0]["features_C"]), 8)
            self.assertFalse(records[n][0]["training_ready"])
            self.assertEqual(records[n][0]["label_basis"], "capture_activity_hint")


class BoundaryTests(unittest.TestCase):
    def test_exact_idle_threshold_expires_before_arrival(self):
        for gap, expected in ((59_999_999, 1), (60_000_000, 2), (60_000_001, 2)):
            with self.subTest(gap=gap):
                summary, _, _ = run([packet(1, 0), packet(2, gap)])
                self.assertEqual(summary["instances"], expected)

    def test_idle_resets_direction_and_initial_iat(self):
        packets = [packet(i + 1, i) for i in range(4)]
        packets += [packet(i + 5, 70_000_000 + i * 10, reverse=True) for i in range(4)]
        summary, records, instances = run(packets)
        self.assertEqual(summary["instances"], 2)
        second = records[4][1]
        self.assertEqual(second["features_C"]["reverse_packet_count"], 0)
        self.assertEqual(second["features_C"]["iat_sum"], 30)
        self.assertIsNone(second["debug_metadata_not_model_inputs"]["trace"][0]["iat_us"])
        self.assertEqual(instances[0]["parent_candidate_conversation_id"], instances[1]["parent_candidate_conversation_id"])
        self.assertNotEqual(instances[0]["instance_id"], instances[1]["instance_id"])

    def test_all_packets_refresh_idle_no_hard_timeout(self):
        summary, records, _ = run([packet(i + 1, i * 20_000_000) for i in range(30)])
        self.assertEqual(summary["instances"], 1)
        self.assertEqual(len(records[8]), 1)
        self.assertEqual(records[8][0]["features_B"]["iat_sum"], 140_000_000)

    def test_udp_uses_only_idle_boundaries(self):
        summary, _, _ = run([packet(1, 0, protocol=17), packet(2, 60_000_000, protocol=17)])
        self.assertEqual(summary["instances"], 2)
        self.assertEqual(summary["end_reasons"], {"idle_timeout": 1, "capture_end": 1})

    def test_retransmitted_opening_syn_not_split(self):
        controls = [tcp(syn=True, ack=False, seq=10), tcp(syn=True, ack=False, seq=10), ACK,
                    tcp(syn=True, ack=False, seq=10)]
        summary, _, _ = run([packet(i + 1, i) for i in range(4)], controls)
        self.assertEqual(summary["instances"], 1)

    def test_changed_syn_signature_starts_new_instance(self):
        summary, _, instances = run([packet(1, 0), packet(2, 1)],
                                    [tcp(syn=True, ack=False, seq=10), tcp(syn=True, ack=False, seq=20)])
        self.assertEqual(summary["instances"], 2)
        self.assertEqual(instances[1]["debug_metadata_not_model_inputs"]["start_reason"], "fresh_tcp_syn")

    def test_midstream_to_syn_starts_new_instance(self):
        summary, _, _ = run([packet(1, 0), packet(2, 1)], [ACK, tcp(syn=True, ack=False)])
        self.assertEqual(summary["end_reasons"]["fresh_tcp_syn"], 1)

    def test_syn_boundary_resets_reverse_direction(self):
        packets = [packet(1, 0)] + [packet(i + 2, i + 1, reverse=True) for i in range(4)]
        _, records, _ = run(packets, [ACK, tcp(syn=True, ack=False), ACK, ACK, ACK])
        self.assertEqual(records[4][0]["features_C"]["reverse_packet_count"], 0)
        self.assertEqual(records[4][0]["debug_metadata_not_model_inputs"]["first_frame"], 2)

    def test_possible_simultaneous_open_kept_together(self):
        summary, _, _ = run([packet(1, 0), packet(2, 1, reverse=True)],
                            [tcp(syn=True, ack=False, seq=10), tcp(syn=True, ack=False, seq=20)])
        self.assertEqual(summary["instances"], 1)

    def test_synack_first_recognizes_late_matching_syn(self):
        summary, _, _ = run([packet(1, 0, reverse=True), packet(2, 1)],
                            [tcp(syn=True, seq=20, ack_number=11), tcp(syn=True, ack=False, seq=10)])
        self.assertEqual(summary["instances"], 1)

    def test_synack_alone_does_not_split(self):
        summary, _, _ = run([packet(1, 0), packet(2, 1, reverse=True)], [ACK, tcp(syn=True)])
        self.assertEqual(summary["instances"], 1)

    def test_one_fin_does_not_end_half_closed_connection(self):
        summary, _, _ = run([packet(i + 1, i, reverse=bool(i % 2)) for i in range(4)],
                            [ACK, tcp(fin=True), ACK, ACK])
        self.assertEqual(summary["instances"], 1)

    def test_both_fins_keep_final_ack_but_new_syn_starts_instance(self):
        packets = [packet(1, 0), packet(2, 1), packet(3, 2, reverse=True), packet(4, 3), packet(5, 4)]
        controls = [tcp(syn=True, ack=False, seq=10), tcp(fin=True), tcp(fin=True), ACK,
                    tcp(syn=True, ack=False, seq=10)]
        summary, records, _ = run(packets, controls)
        self.assertEqual(summary["instances"], 2)
        self.assertEqual(records[4][0]["debug_metadata_not_model_inputs"]["last_frame"], 4)

    def test_rst_included_then_closes_and_marks_continuation(self):
        packets = [packet(i + 1, i, reverse=i >= 4) for i in range(8)]
        summary, records, instances = run(packets, [ACK] * 3 + [tcp(rst=True)] + [ACK] * 4)
        self.assertEqual(summary["instances"], 2)
        self.assertEqual([r["features_C"]["reverse_packet_count"] for r in records[4]], [0, 0])
        self.assertEqual(instances[0]["debug_metadata_not_model_inputs"]["last_frame"], 4)
        self.assertEqual(instances[1]["debug_metadata_not_model_inputs"]["start_reason"], "after_tcp_rst")

    def test_idle_priority_and_idle_after_rst(self):
        syn = tcp(syn=True, ack=False)
        summary, _, instances = run([packet(1, 0), packet(2, 60_000_000)], [ACK, syn])
        self.assertNotIn("fresh_tcp_syn", summary["end_reasons"])
        self.assertEqual(instances[1]["debug_metadata_not_model_inputs"]["start_reason"], "idle_timeout")
        _, _, instances = run([packet(1, 0), packet(2, 60_000_000)], [tcp(rst=True), syn])
        self.assertEqual(instances[1]["debug_metadata_not_model_inputs"]["start_reason"], "idle_after_tcp_rst")

    def test_idle_only_ignores_tcp_events_and_matches_previous_audit(self):
        packets = [packet(i + 1, t * 1_000_000) for i, t in enumerate([0, 1, 2, 3, 65, 66, 67, 68])]
        summary, _, _ = run(packets, [tcp(rst=True), tcp(syn=True, ack=False)] + [ACK] * 6,
                            boundary_policy="idle-only")
        worker = audit.Audit(CAPTURE, (60,), io.StringIO())
        for p in packets:
            worker.add(p)
        previous = worker.finish()["policies"]["idle_60s"]
        self.assertEqual(summary["instances"], previous["instances"])
        for n in (4, 8):
            for key in ("records", "short_instances"):
                self.assertEqual(summary["windows"][str(n)][key], previous["windows"][str(n)][key])

    def test_memory_finished_and_metadata_guards(self):
        worker = extractor.Extractor(CAPTURE, {n: io.StringIO() for n in (4, 8)}, io.StringIO(), max_conversations=1)
        worker.add(packet(1, 0), ACK)
        with self.assertRaisesRegex(ValueError, "memory guard"):
            worker.add(packet(2, 1, sport=1000), ACK)
        with self.assertRaisesRegex(ValueError, "metadata"):
            worker.add(packet(2, 1), None)
        worker.finish()
        with self.assertRaisesRegex(ValueError, "finished"):
            worker.add(packet(3, 2), ACK)
        with self.assertRaisesRegex(ValueError, "finished"):
            worker.finish()

    def test_invalid_configuration_rejected(self):
        for options in ({"idle_seconds": 0}, {"idle_seconds": True}, {"idle_seconds": 1.5},
                        {"max_conversations": 0}, {"boundary_policy": "unknown"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                run([], **options)


class DecoderTests(unittest.TestCase):
    @staticmethod
    def fields(**overrides):
        base = dict(zip(extractor.pilot.FIELDS, fixtures.DecoderTests().fields()))
        base.update(dict(zip(extractor.TCP_FIELDS, ("False", "True", "False", "False", "100", "200", "0"))))
        base.update(overrides)
        return [base[name] for name in extractor.FIELDS]

    def test_raw_tcp_fields_decode_textual_and_numeric_flags(self):
        for false, true in (("False", "True"), ("0", "1")):
            p, control, reason = extractor.decode_fields(self.fields(**{"tcp.flags.syn": false, "tcp.flags.ack": true}))
            self.assertIsNone(reason)
            self.assertEqual(control, ACK)
            self.assertEqual(p.size, 100)

    def test_unknown_missing_and_multiple_control_fields_reject(self):
        for key, value in (("tcp.flags.syn", "unknown"), ("tcp.seq_raw", ""),
                           ("tcp.seq_raw", "100,200"), ("tcp.seq_raw", str(2**32)), ("tcp.len", "1000")):
            with self.subTest(key=key, value=value):
                p, _, reason = extractor.decode_fields(self.fields(**{key: value}))
                self.assertIsNone(p)
                self.assertTrue(reason)

    def test_udp_requires_blank_tcp_fields(self):
        values = {name: "" for name in extractor.TCP_FIELDS}
        values.update({"frame.protocols": "raw:ip:udp", "ip.proto": "17", "tcp.srcport": "",
                       "tcp.dstport": "", "udp.srcport": "40000", "udp.dstport": "12345"})
        p, control, reason = extractor.decode_fields(self.fields(**values))
        self.assertEqual(p.protocol, 17)
        self.assertIsNone(control)
        self.assertIsNone(reason)
        values["tcp.seq_raw"] = "0"
        self.assertEqual(extractor.decode_fields(self.fields(**values))[2], "unexpected_tcp_control_fields_in_udp")

    def test_original_filter_priority_and_bad_schema(self):
        self.assertEqual(extractor.decode_fields(self.fields(**{"tcp.dstport": "53"}))[2], "port_53_baseline_exclusion")
        with self.assertRaises(ValueError):
            extractor.decode_fields(["1", "2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
