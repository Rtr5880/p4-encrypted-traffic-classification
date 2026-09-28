"""Synthetic pilot-extractor tests: no real captures, training or WSL access.

These test the feature arithmetic and decoder contract, not live BMv2 timing
parity, application-session identification, or the correctness of class labels.
"""

from copy import deepcopy
import csv
from dataclasses import replace
import unittest

import extract_feature_pilot as pilot


FEATURE_NAMES = {
    "size_min", "size_max", "size_sum", "iat_min", "iat_max", "iat_sum",
    "reverse_packet_count", "direction_change_count",
}


def packet(frame, timestamp_us, size=100, reverse=False, **overrides):
    values = {
        "frame": frame,
        "timestamp_ns": timestamp_us * 1000,
        "src": "10.8.8.234",
        "dst": "74.125.133.16",
        "sport": 51040,
        "dport": 993,
        "protocol": 6,
        "size": size,
    }
    if reverse:
        values["src"], values["dst"] = values["dst"], values["src"]
        values["sport"], values["dport"] = values["dport"], values["sport"]
    values.update(overrides)
    return pilot.Packet(**values)


def accumulate(packets, **overrides):
    options = {
        "capture_id": "VPN-PCAPS-01/synthetic.pcap",
        "capture_sha256": "a" * 64,
        "initial_class": "MAIL",
        "label_policy": "capture-only",
    }
    options.update(overrides)
    result = pilot.FlowAccumulator(packets[0], **options)
    for value in packets[1:]:
        result.add(value)
    return result


def oracle_packets():
    sizes = [100, 200, 120, 80, 60, 300, 70, 90]
    timestamps = [1000, 1010, 1009, 1025, 1030, 1030, 1040, 1060]
    reverse = [False, True, True, False, False, True, False, True]
    return [
        packet(index + 1, timestamp, size, backward)
        for index, (timestamp, size, backward)
        in enumerate(zip(timestamps, sizes, reverse))
    ]


class TimestampTests(unittest.TestCase):
    def test_epoch_precision_does_not_pass_through_float(self):
        first = pilot.timestamp_ns("1433773942.445821001")
        second = pilot.timestamp_ns("1433773942.445821002")
        self.assertEqual(first, 1433773942445821001)
        self.assertEqual(second - first, 1)

    def test_fractional_seconds_have_exact_units(self):
        self.assertEqual(pilot.timestamp_ns("1.1"), 1100000000)
        self.assertEqual(pilot.timestamp_ns("0.000001000"), 1000)
        self.assertEqual(pilot.timestamp_ns("0.000000001"), 1)

    def test_malformed_timestamps_are_not_silently_zero(self):
        for value in ("", "not-a-time", "NaN", "1.2.3"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    pilot.timestamp_ns(value)


class ConversationIdentityTests(unittest.TestCase):
    def test_key_matches_both_directions(self):
        forward = packet(1, 0)
        reverse = packet(2, 1, reverse=True)
        self.assertEqual(pilot.make_key(forward), pilot.make_key(reverse))
        hash(pilot.make_key(forward))

    def test_ports_and_protocol_are_part_of_key(self):
        value = packet(1, 0)
        for changed in (
            replace(value, sport=value.sport + 1),
            replace(value, dport=value.dport + 1),
            replace(value, protocol=17),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(pilot.make_key(value), pilot.make_key(changed))

    def test_capture_scopes_conversation_identity(self):
        first = accumulate([packet(1, 0)])
        repeated = accumulate([packet(1, 0)])
        other_capture = accumulate(
            [packet(1, 0)], capture_id="VPN-PCAPs-02/other.pcap",
        )
        self.assertEqual(first.conversation_id, repeated.conversation_id)
        self.assertNotEqual(first.conversation_id, other_capture.conversation_id)

    def test_first_observed_endpoint_not_sorted_key_defines_forward(self):
        packets = oracle_packets()
        swapped = [
            replace(value, src=value.dst, dst=value.src,
                    sport=value.dport, dport=value.sport)
            for value in packets
        ]
        original = accumulate(packets)
        mirrored = accumulate(swapped)
        for window in (4, 8):
            self.assertEqual(
                original.snapshots[window]["features"],
                mirrored.snapshots[window]["features"],
            )


class FeatureArithmeticTests(unittest.TestCase):
    def test_known_four_and_eight_packet_feature_oracles(self):
        flow = accumulate(oracle_packets())
        expected_four = {
            "size_min": 80, "size_max": 200, "size_sum": 500,
            "iat_min": 0, "iat_max": 15, "iat_sum": 25,
            "reverse_packet_count": 2, "direction_change_count": 2,
        }
        expected_eight = {
            "size_min": 60, "size_max": 300, "size_sum": 1020,
            "iat_min": 0, "iat_max": 20, "iat_sum": 60,
            "reverse_packet_count": 4, "direction_change_count": 5,
        }
        self.assertEqual(flow.snapshots[4]["features"], expected_four)
        self.assertEqual(flow.snapshots[8]["features"], expected_eight)
        self.assertEqual(flow.count, 8)
        self.assertEqual(flow.max_gap_us, 20)
        for window in (4, 8):
            snapshot = flow.snapshots[window]
            self.assertEqual(set(snapshot["features"]), FEATURE_NAMES)
            self.assertEqual(len(snapshot["trace"]), window)
            self.assertEqual(snapshot["raw_backward_steps"], 1)
            self.assertEqual(snapshot["timestamp_adjustments"], 1)
            self.assertEqual(snapshot["max_timestamp_adjustment_ns"], 1000)
            for value in snapshot["features"].values():
                self.assertIsInstance(value, int)

    def test_no_artificial_zero_gap_is_included(self):
        flow = accumulate([packet(index + 1, value)
                           for index, value in enumerate([100, 110, 130, 160])])
        features = flow.snapshots[4]["features"]
        self.assertEqual(features["iat_min"], 10)
        self.assertEqual(features["iat_max"], 30)
        self.assertEqual(features["iat_sum"], 60)

    def test_genuine_zero_gaps_are_retained(self):
        flow = accumulate([packet(index + 1, 100) for index in range(4)])
        features = flow.snapshots[4]["features"]
        self.assertEqual((features["iat_min"], features["iat_max"],
                          features["iat_sum"]), (0, 0, 0))
        self.assertEqual(flow.raw_backward_steps, 0)
        self.assertEqual(flow.timestamp_adjustments, 0)

    def test_running_max_corrections_differ_from_raw_reversals(self):
        times = [100, 110, 105, 107, 115, 120, 125, 130]
        flow = accumulate([packet(index + 1, value)
                           for index, value in enumerate(times)])
        self.assertEqual(flow.raw_backward_steps, 1)
        self.assertEqual(flow.timestamp_adjustments, 2)
        self.assertEqual(flow.snapshots[4]["max_timestamp_adjustment_ns"], 5000)
        self.assertEqual(flow.snapshots[4]["timestamp_adjustments"], 2)
        self.assertEqual(flow.snapshots[8]["features"]["iat_sum"], 30)
        self.assertEqual(flow.snapshots[8]["features"]["iat_max"], 10)

    def test_absolute_timestamp_quantisation_precedes_gap_calculation(self):
        times_ns = [1000999, 1001000, 1001999, 1002000]
        flow = accumulate([
            packet(index + 1, 0, timestamp_ns=value)
            for index, value in enumerate(times_ns)
        ])
        features = flow.snapshots[4]["features"]
        self.assertEqual(features["iat_min"], 0)
        self.assertEqual(features["iat_max"], 1)
        self.assertEqual(features["iat_sum"], 2)

    def test_raw_nanosecond_reversal_is_reported_even_with_zero_us_gap(self):
        times_ns = [1000999, 1000900, 1001000, 1002000]
        flow = accumulate([
            packet(index + 1, 0, timestamp_ns=value)
            for index, value in enumerate(times_ns)
        ])
        snapshot = flow.snapshots[4]
        self.assertEqual(snapshot["raw_backward_steps"], 1)
        self.assertEqual(snapshot["timestamp_adjustments"], 1)
        self.assertEqual(snapshot["max_timestamp_adjustment_ns"], 99)
        self.assertEqual(snapshot["features"]["iat_sum"], 2)

    def test_snapshot_eligibility_requires_at_least_n_packets(self):
        expected = {1: set(), 3: set(), 4: {4}, 7: {4}, 8: {4, 8}}
        values = oracle_packets()
        for count, windows in expected.items():
            with self.subTest(count=count):
                flow = accumulate(values[:count])
                self.assertEqual(set(flow.snapshots), windows)
                self.assertEqual(flow.count, count)

    def test_prefix_features_and_diagnostics_freeze_while_full_audit_continues(self):
        values = oracle_packets()
        flow = accumulate(values[:4])
        saved_four = deepcopy(flow.snapshots[4])
        for value in values[4:]:
            flow.add(value)
        self.assertEqual(flow.snapshots[4], saved_four)
        saved_both = deepcopy(flow.snapshots)
        flow.add(packet(9, 2000, size=65535, reverse=True))
        flow.add(packet(10, 1990, size=40))
        self.assertEqual(flow.snapshots, saved_both)
        self.assertEqual(flow.count, 10)
        self.assertEqual(flow.max_gap_us, 940)
        self.assertEqual(flow.raw_backward_steps, 2)
        self.assertEqual(flow.timestamp_adjustments, 2)

    def test_same_direction_has_no_reverse_packets_or_changes(self):
        flow = accumulate([packet(index + 1, index * 10) for index in range(8)])
        features = flow.snapshots[8]["features"]
        self.assertEqual(features["reverse_packet_count"], 0)
        self.assertEqual(features["direction_change_count"], 0)

    def test_interleaved_conversations_have_independent_state(self):
        values = oracle_packets()
        flows = {}
        for value in values:
            other = replace(value, sport=1111, dport=2222, src="192.0.2.1",
                            dst="192.0.2.2", timestamp_ns=value.timestamp_ns + 1000000)
            for current in (value, other):
                key = pilot.make_key(current)
                if key not in flows:
                    flows[key] = accumulate([current])
                else:
                    flows[key].add(current)
        main = flows[pilot.make_key(values[0])]
        separate = accumulate(values)
        self.assertEqual(main.snapshots, separate.snapshots)
        self.assertEqual(len(flows), 2)

    def test_maximum_valid_eight_packet_size_sum_fits_without_wrap(self):
        flow = accumulate([packet(index + 1, index, size=65535)
                           for index in range(8)])
        self.assertEqual(flow.snapshots[8]["features"]["size_sum"], 524280)

    def test_iat_48_bit_limit_is_explicit(self):
        maximum = (1 << 48) - 1
        flow = accumulate([packet(index + 1, value)
                           for index, value in enumerate([0, maximum, maximum, maximum])])
        self.assertEqual(flow.snapshots[4]["features"]["iat_sum"], maximum)
        with self.assertRaises(ValueError):
            accumulate([packet(index + 1, value)
                        for index, value in enumerate([0, maximum + 1,
                                                       maximum + 1, maximum + 1])])


class LabellingTests(unittest.TestCase):
    def test_default_keeps_capture_hint_even_for_port_443(self):
        flow = accumulate([packet(1, 0, dport=443)], initial_class="VOIP")
        self.assertEqual(flow.label, "VOIP")
        self.assertTrue(flow.label_basis)

    def test_reference_port_policy_is_explicit_and_checks_both_endpoints(self):
        for overrides in ({"sport": 443}, {"dport": 80},
                          {"protocol": 17, "dport": 443}):
            with self.subTest(overrides=overrides):
                flow = accumulate([packet(1, 0, **overrides)],
                                  label_policy="reference-port", initial_class="VOIP")
                self.assertEqual(flow.label, "BROWSING")
                self.assertTrue(flow.label_basis)

    def test_reference_port_policy_preserves_streaming(self):
        flow = accumulate([packet(1, 0, dport=443)],
                          label_policy="reference-port", initial_class="STREAMING")
        self.assertEqual(flow.label, "STREAMING")

    def test_reference_policy_preserves_non_web_capture_hint(self):
        flow = accumulate([packet(1, 0)], label_policy="reference-port")
        self.assertEqual(flow.label, "MAIL")


class DecoderTests(unittest.TestCase):
    def test_actual_tshark_rows_with_false_mf_decode(self):
        # Verbatim field values reported by the user's TShark installation.
        lines = [
            '"1","1429042349.477136000","52","52","raw:ip:tcp","4","10.8.0.10","74.125.226.22","6","52","20","0","False","41939","80",,',
            '"2","1429042349.502572000","52","52","raw:ip:tcp","4","74.125.226.22","10.8.0.10","6","52","20","0","False","80","41939",,',
            '"3","1429042353.349135000","52","52","raw:ip:tcp","4","10.8.0.10","173.194.123.70","6","52","20","0","False","42610","80",,',
        ]
        packets = []
        for fields in csv.reader(lines):
            value, reason = pilot.decode_fields(fields)
            self.assertIsNone(reason)
            self.assertIsNotNone(value)
            self.assertEqual(value.size, 52)
            packets.append(value)
        self.assertEqual(packets[0].timestamp_ns, 1429042349477136000)
        self.assertEqual(pilot.make_key(packets[0]), pilot.make_key(packets[1]))
        self.assertNotEqual(pilot.make_key(packets[0]), pilot.make_key(packets[2]))

    def test_false_mf_accepts_textual_and_numeric_forms(self):
        for flag in ("False", "false", "FALSE", "0", " false "):
            with self.subTest(flag=flag):
                value, reason = pilot.decode_fields(self.fields(**{"ip.flags.mf": flag}))
                self.assertIsNotNone(value)
                self.assertIsNone(reason)

    def test_true_mf_still_rejects_fragments(self):
        for flag in ("True", "true", "TRUE", "1", " true "):
            with self.subTest(flag=flag):
                value, reason = pilot.decode_fields(self.fields(**{"ip.flags.mf": flag}))
                self.assertIsNone(value)
                self.assertEqual(reason, "ipv4_fragment")

    def test_unknown_mf_is_not_silently_treated_as_false(self):
        for flag in ("", "unknown", "2", "yes"):
            with self.subTest(flag=flag):
                value, reason = pilot.decode_fields(self.fields(**{"ip.flags.mf": flag}))
                self.assertIsNone(value)
                self.assertEqual(reason, "missing_or_invalid_header_field:ip.flags.mf")

    def test_conversion_failures_identify_specific_fields(self):
        for name, bad in (("ip.proto", "six"), ("ip.src", "bad-address"),
                          ("tcp.srcport", ""), ("frame.time_epoch", "bad-time")):
            with self.subTest(name=name):
                value, reason = pilot.decode_fields(self.fields(**{name: bad}))
                self.assertIsNone(value)
                self.assertEqual(reason, f"missing_or_invalid_header_field:{name}")

    def fields(self, **overrides):
        values = {
            "frame.number": "1",
            "frame.time_epoch": "1433773942.445821001",
            "frame.len": "100",
            "frame.cap_len": "100",
            "frame.protocols": "raw:ip:tcp",
            "ip.version": "4",
            "ip.src": "10.8.8.234",
            "ip.dst": "74.125.133.16",
            "ip.proto": "6",
            "ip.len": "100",
            "ip.hdr_len": "20",
            "ip.flags.mf": "0",
            "ip.frag_offset": "0",
            "tcp.srcport": "51040",
            "tcp.dstport": "993",
            "udp.srcport": "",
            "udp.dstport": "",
        }
        values.update(overrides)
        return [values.get(name, "") for name in pilot.FIELDS]

    def reject(self, **overrides):
        value, reason = pilot.decode_fields(self.fields(**overrides))
        self.assertIsNone(value)
        self.assertTrue(reason)

    def test_raw_ipv4_tcp_fields_decode_with_ip_length(self):
        value, reason = pilot.decode_fields(self.fields())
        self.assertIsNone(reason)
        self.assertEqual(value.frame, 1)
        self.assertEqual(value.timestamp_ns, 1433773942445821001)
        self.assertEqual(value.size, 100)
        self.assertEqual((value.src, value.dst, value.sport, value.dport, value.protocol),
                         ("10.8.8.234", "74.125.133.16", 51040, 993, 6))

    def test_raw_ipv4_udp_fields_decode(self):
        value, reason = pilot.decode_fields(self.fields(**{
            "frame.protocols": "raw:ip:udp", "ip.proto": "17",
            "tcp.srcport": "", "tcp.dstport": "",
            "udp.srcport": "40000", "udp.dstport": "19305",
        }))
        self.assertIsNone(reason)
        self.assertEqual((value.protocol, value.sport, value.dport), (17, 40000, 19305))

    def test_dns_is_excluded_for_either_endpoint(self):
        for port in ("tcp.srcport", "tcp.dstport"):
            with self.subTest(port=port):
                self.reject(**{port: "53"})
        for port in ("udp.srcport", "udp.dstport"):
            with self.subTest(port=port):
                changes = {
                    "frame.protocols": "raw:ip:udp", "ip.proto": "17",
                    "tcp.srcport": "", "tcp.dstport": "",
                    "udp.srcport": "40000", "udp.dstport": "19305",
                    port: "53",
                }
                self.reject(**changes)

    def test_first_and_noninitial_fragments_are_excluded(self):
        self.reject(**{"ip.flags.mf": "1"})
        self.reject(**{"ip.frag_offset": "8"})

    def test_truncated_capture_records_are_excluded(self):
        self.reject(**{"frame.cap_len": "99"})

    def test_multiple_ip_layers_are_not_silently_mixed(self):
        self.reject(**{
            "frame.protocols": "raw:ip:gre:ip:tcp",
            "ip.src": "192.0.2.1,10.8.8.234",
            "ip.dst": "192.0.2.2,74.125.133.16",
            "ip.proto": "47,6",
            "ip.len": "140,100",
        })

    def test_ipv6_and_icmp_quoted_tcp_are_not_accepted(self):
        self.reject(**{"frame.protocols": "raw:ipv6:tcp", "ip.version": "6"})
        self.reject(**{"frame.protocols": "raw:ip:icmp:ip:tcp", "ip.proto": "1"})

    def test_missing_invalid_or_ambiguous_fields_are_rejected(self):
        for overrides in (
            {"tcp.srcport": ""},
            {"tcp.srcport": "51040,12345"},
            {"tcp.dstport": "65536"},
            {"ip.src": "not-an-address"},
            {"ip.len": "65536"},
            {"ip.len": "19"},
            {"ip.version": ""},
        ):
            with self.subTest(overrides=overrides):
                self.reject(**overrides)

    def test_identical_endpoints_have_no_usable_direction(self):
        self.reject(**{"ip.dst": "10.8.8.234", "tcp.dstport": "51040"})

    def test_pilot_explicitly_rejects_non_raw_encapsulation(self):
        self.reject(**{"frame.protocols": "eth:ethertype:ip:tcp", "frame.len": "114", "frame.cap_len": "114"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
