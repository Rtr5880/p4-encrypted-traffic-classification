"""Regression checks for the controlled real-capture parity boundary.

No real dataset, model fitting, live interfaces or BMv2 process is required.
The runner tests replace only process/pipe I/O; normal decoding and comparison
still reject deliberately missing, extra and corrupted switch reports.
"""
import copy
import gzip
import hashlib
import io
import itertools
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import extract_feature_pilot as pilot
import extract_flow_instances as instances
import pcap_replay_io as capture_io
import replay_real_pcaps as replay
import test_p4_features as helpers


CAPTURE = {'capture_id': 'fixture', 'sha256': '0' * 64,
           'filename': 'fixture.pcap', 'initial_class': 'VOIP'}


def oracle():
    return replay.ReplayOracle(CAPTURE, {4: io.StringIO(), 8: io.StringIO()}, io.StringIO())


def packet(number, stamp_us, reverse=False, flow=0, proto=17, size=100):
    endpoints = [(f'10.0.0.{10 + flow}', 1000 + flow), ('10.0.0.2', 2000)]
    if reverse:
        endpoints.reverse()
    return pilot.Packet(number, stamp_us * 1000, endpoints[0][0], endpoints[1][0],
                        endpoints[0][1], endpoints[1][1], proto, size)


def tcp(rst=False):
    return instances.Tcp(False, True, False, rst, 100, 200, 60)


def response(feature, rf, raw):
    fields = {name: 0 for name, _ in helpers.FIELDS}
    fields.update(magic=0x45544352, version=1)
    fields.update(feature)
    body = b''.join(fields[name].to_bytes(width, 'big') for name, width in helpers.FIELDS)
    rf_values = {'valid': 0, 'model': 1, 'prediction': 255, 'leaves': [0] * 10, 'scores': [0] * 6}
    rf_values.update(rf)
    rf_header = struct.pack('!IBBBB10H6I', 0x52464952, 1, rf_values['valid'],
                            rf_values['model'], rf_values['prediction'],
                            *rf_values['leaves'], *rf_values['scores'])
    return bytes.fromhex('02000000000202000000000188b6') + body + rf_header + raw


def checked_example(number=8, decision=True):
    raw = bytes.fromhex('4500002800010000401100000a00000a0a000002') + b'x' * 20
    features = {'packet_id': number, 'observed_us': 7000, 'status': 2 if decision else 1,
                'slot': 27743, 'instance': 1, 'count': 8 if decision else 7,
                'effective_us': 7000, 'size_min': 40, 'size_max': 40,
                'size_sum': 320 if decision else 280, 'iat_min': 1000,
                'iat_max': 1000, 'iat_sum': 7000 if decision else 6000,
                'reverse_count': 4 if decision else 3, 'direction_changes': 7 if decision else 6}
    expected_rf = {'leaves': list(range(10)), 'scores': [3, 11, 40, 15, 0, 7], 'prediction': 2}
    rf = dict(expected_rf, valid=1) if decision else {}
    row = {'fields': features, 'raw_length': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
    return features, rf, raw, row, expected_rf if decision else None


class AdapterTests(unittest.TestCase):
    def test_wrapper_keeps_every_ip_byte_and_floors_before_offset(self):
        # Fractional origin subtraction before flooring would incorrectly give 0.
        raw = bytes.fromhex('4500001400010000400100000a0000010a000002')
        record = capture_io.PacketRecord(7, 1_000_001_050, len(raw), len(raw), 101, raw)
        wrapped = replay.wrap_packet(record, 1_000_000)
        self.assertEqual(wrapped[:14], replay.ETHERNET)
        self.assertEqual(struct.unpack('!II', wrapped[14:22]), (0x45544354, 7))
        self.assertEqual(int.from_bytes(wrapped[22:28], 'big'), 1)
        self.assertEqual(wrapped[28:], raw)

    def test_scan_and_adapter_preserve_backward_capture_order(self):
        raw = bytes.fromhex('4500001400010000400100000a0000010a000002')
        stamps = [1_000_002_900, 1_000_001_050, 1_000_003_010]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'raw.pcap'
            with capture_io.ClassicPcapWriter(path, linktype=101, nanosecond=True) as writer:
                for stamp in stamps:
                    writer.write(stamp, raw)
            scan = replay.scan_capture(path)
            wrapped = [replay.wrap_packet(r, scan['origin_us']) for r in capture_io.iter_capture(path)]
        self.assertEqual(scan['capture_order_backward_steps'], 1)
        self.assertEqual(scan['origin_us'], 1_000_001)
        self.assertEqual([int.from_bytes(frame[22:28], 'big') for frame in wrapped], [1, 0, 2])
        self.assertEqual([int.from_bytes(frame[18:22], 'big') for frame in wrapped], [1, 2, 3])

    def test_wrapper_rejects_unsupported_inputs_and_timestamp_wrap(self):
        raw = b'\x45' + b'\0' * 19
        base = capture_io.PacketRecord(1, 1_000_000, 20, 20, 101, raw)
        for record, origin in [
            (capture_io.PacketRecord(1, 1_000_000, 20, 20, 1, raw), 0),
            (capture_io.PacketRecord(1, 1_000_000, 20, 20, 101, b'\x60' + raw[1:]), 0),
            (capture_io.PacketRecord(2**32, 1_000_000, 20, 20, 101, raw), 0),
            (base, 1001),
            (capture_io.PacketRecord(1, 2**48 * 1000, 20, 20, 101, raw), 0),
        ]:
            with self.subTest(record=record, origin=origin), self.assertRaises(ValueError):
                replay.wrap_packet(record, origin)

    def test_numeric_endpoint_order_crc_golden_and_reverse_invariance(self):
        # Numeric .2 precedes .10; lexical dotted-address order is the opposite.
        # CRC32 golden input hex: 110a00000207d00a00000a03e8.
        forward = packet(1, 0)
        reverse = packet(2, 1, reverse=True)
        self.assertEqual(replay.slot_for(forward, 2**32), 718433375)
        self.assertEqual(replay.slot_for(forward), 27743)
        self.assertEqual(replay.slot_for(reverse), 27743)
        self.assertEqual(pilot.make_key(forward), pilot.make_key(reverse))


class OracleTests(unittest.TestCase):
    def test_packet_eight_rst_is_a_decision_before_instance_close(self):
        ref, owners = oracle(), {}
        for number in range(1, 9):
            fields, decision, *_ = replay.expectation(ref, packet(number, number * 1000, proto=6),
                                                       tcp(rst=number == 8), owners, 0)
            self.assertEqual(decision is not None, number == 8)
        self.assertEqual((fields['status'], fields['active'], fields['count']), (2, 0, 8))
        fields, decision, *_ = replay.expectation(ref, packet(9, 9000, proto=6), tcp(), owners, 0)
        self.assertEqual((fields['instance'], fields['flags'], fields['count']), (2, 4, 1))
        self.assertIsNone(decision)
        fields, *_ = replay.expectation(ref, packet(10, 60_009_000, proto=6), tcp(), owners, 0)
        self.assertEqual((fields['instance'], fields['flags'], fields['count']), (3, 2, 1))

    def test_post_eight_freezes_features_but_refreshes_idle_clock(self):
        ref, owners = oracle(), {}
        frozen = None
        for number in range(1, 10):
            fields, decision, *_ = replay.expectation(ref, packet(number, number * 1000,
                reverse=number % 2 == 0, size=100 + number), None, owners, 0)
            if number == 8:
                frozen = {name: fields[helpers.FEATURE_NAMES.get(name, name)] for name in instances.C_FEATURES}
                self.assertIsNotNone(decision)
            if number == 9:
                self.assertIsNone(decision)
                self.assertEqual(fields['status'], 1)
                self.assertEqual(frozen, {name: fields[helpers.FEATURE_NAMES.get(name, name)] for name in instances.C_FEATURES})
        self.assertEqual(frozen, {'size_min': 101, 'size_max': 108, 'size_sum': 836,
            'iat_min': 1000, 'iat_max': 1000, 'iat_sum': 7000,
            'reverse_packet_count': 4, 'direction_change_count': 7})
        # Idle interval from packet 8 exceeds 60 s, but from packet 9 is just below.
        stamp = 9000 + 59_999_999
        fields, decision, *_ = replay.expectation(ref, packet(10, stamp), None, owners, 0)
        self.assertEqual((fields['instance'], fields['flags'], fields['count']), (1, 0, 8))
        self.assertIsNone(decision)
        fields, *_ = replay.expectation(ref, packet(11, stamp + 60_000_000), None, owners, 0)
        self.assertEqual((fields['instance'], fields['flags'], fields['count']), (2, 2, 1))

    def test_backward_time_clamp_keeps_original_nanosecond_policy(self):
        ref, owners = oracle(), {}
        stamps = [1_000_001_999, 1_000_001_001, 1_000_002_000]
        gaps = []
        for number, stamp in enumerate(stamps, 1):
            pkt = packet(number, 0)
            pkt = pilot.Packet(pkt.frame, stamp, pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.protocol, pkt.size)
            fields, *_ = replay.expectation(ref, pkt, None, owners, 1_000_001)
            gaps.append((fields['effective_us'], fields['iat_sum']))
        self.assertEqual(gaps, [(0, 0), (0, 0), (1, 1)])
        audit = ref.finish()
        self.assertEqual(audit['timing']['timestamp_adjustments'], 1)
        self.assertEqual(audit['timing']['max_timestamp_adjustment_ns'], 998)

    def test_collision_excludes_whole_parent_instances_and_preserves_owner(self):
        ref, owners, decisions, collision_instances = oracle(), {}, [], set()
        number = collision_packets = 0
        for flow, base in [(0, 0), (1, 10_000), (0, 20_000), (1, 60_020_000)]:
            for index in range(1, 9):
                number += 1
                pkt = packet(number, base + index * 1000, flow=flow, proto=6 if flow == 0 else 17)
                fields, decision, key, instance_id, collision = replay.expectation(
                    ref, pkt, tcp(rst=index == 8) if flow == 0 else None, owners, 0, slots=1)
                if collision:
                    collision_packets += 1
                    collision_instances.add(instance_id)
                    self.assertEqual((fields['status'], fields['count'], fields['instance'], fields['size_sum']), (3, 0, 0, 0))
                else:
                    self.assertEqual(fields['count'], index)
                    self.assertEqual(fields['size_sum'], 100 * index)
                if decision:
                    decisions.append(decision)
        audit = ref.finish()
        excluded = [d for d in decisions if d['collision_excluded']]
        admitted = [d for d in decisions if not d['collision_excluded']]
        self.assertEqual((collision_packets, len(collision_instances)), (16, 2))
        self.assertEqual((audit['windows']['8']['records'], len(excluded), len(admitted)), (4, 2, 2))
        self.assertEqual({d['packet_id'] for d in admitted}, {8, 24})
        self.assertEqual(len(decisions) - len(excluded), len(admitted))
        self.assertEqual(len(owners), 1)


class ReportTests(unittest.TestCase):
    def test_malformed_report_keeps_original_failure_diagnostics(self):
        features, rf, raw, row, expected = checked_example()
        complete = response(features, rf, raw)
        for frame in (complete[:10], complete[:replay.RF_OFFSET + 3]):
            with self.subTest(length=len(frame)):
                with self.assertRaises(ValueError) as failure:
                    replay.verify_frame(frame, row, 'C', expected)
                detail = replay.mismatch_details(frame, row, failure.exception)
                self.assertEqual(detail['error'], str(failure.exception))
                self.assertEqual(detail['frame'], 8)
                self.assertEqual(detail['observed_packet_length'], len(frame))
                self.assertIn('observed_rf_decode_error', detail)
                self.assertEqual(detail['expected'], row)
                json.dumps(detail, allow_nan=False)

    def test_valid_report_checks_all_four_parity_levels(self):
        features, rf, raw, row, expected = checked_example()
        feature_report, rf_report = replay.verify_frame(response(features, rf, raw), row, 'C', expected)
        self.assertEqual(feature_report['packet_id'], 8)
        self.assertEqual(rf_report['leaves'], list(range(10)))
        self.assertEqual(rf_report['scores'], expected['scores'])
        self.assertEqual(rf_report['prediction'], 2)

    def test_corruption_of_each_layer_fails_instead_of_matching_only_class(self):
        base_features, base_rf, base_raw, row, expected = checked_example()
        mutations = ['size_sum', 'status', 'slot', 'packet_id', 'instance', 'flags',
                     'observed_us', 'leaves', 'scores', 'prediction', 'model', 'raw', 'length']
        for name in mutations:
            with self.subTest(mutation=name):
                features, rf, raw = dict(base_features), copy.deepcopy(base_rf), base_raw
                local_row = copy.deepcopy(row)
                if name in ('flags',):
                    local_row['fields'][name] = 0
                    features[name] = 1
                elif name in features:
                    features[name] += 1
                elif name in ('leaves', 'scores'):
                    rf[name][0] += 1
                elif name == 'prediction':
                    rf[name] = 0
                elif name == 'model':
                    rf[name] = 0
                elif name == 'raw':
                    raw = raw[:-1] + b'z'
                elif name == 'length':
                    raw += b'z'
                with self.assertRaises(ValueError):
                    replay.verify_frame(response(features, rf, raw), local_row, 'C', expected)

    def test_non_decision_rejects_stale_or_extra_rf_output(self):
        features, rf, raw, row, _ = checked_example(7, decision=False)
        replay.verify_frame(response(features, rf, raw), row, 'C', None)
        for mutation in ({'valid': 1}, {'prediction': 0}, {'leaves': [1] + [0] * 9}, {'scores': [1] + [0] * 5}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                replay.verify_frame(response(features, mutation, raw), row, 'C', None)


class RunnerTests(unittest.TestCase):
    def exercise_runner(self, mode):
        """Fake private child reports at the transport boundary; compare is real."""
        features, rf, raw, row, _ = checked_example(1, decision=False)
        framed = response(features, rf, raw)
        record = capture_io.PacketRecord(1, 0, len(framed), len(framed), 0, framed)
        batches = {'ok': [[record]], 'missing': [], 'duplicate': [[record, record]]}[mode]

        class Tail:
            def __init__(self, path):
                self.batches = iter(batches)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def poll(self):
                return next(self.batches, [])
            def finish(self):
                return []

        class Process:
            def poll(self):
                return None
            def terminate(self):
                pass
            def wait(self, timeout=None):
                return 0

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with capture_io.ClassicPcapWriter(root / 'adapted.pcap', nanosecond=False) as writer:
                writer.write(0, replay.ETHERNET + raw)
            with gzip.open(root / 'expected_packets.jsonl.gz', 'wt', encoding='utf-8') as out:
                out.write(json.dumps(row) + '\n')
            args = SimpleNamespace(switch=Path('/unused/private-switch'), stall_seconds=0.5)
            prepared = {'packets': 1, 'expected_n8_instances': 0, 'collision_excluded_n8_instances': 0,
                        'rejected_packets': 0}
            clock = itertools.count(step=0.02)
            with patch.object(replay.os, 'open', return_value=9876), \
                 patch.object(replay.os, 'close'), \
                 patch.object(replay, 'write_nonblocking'), \
                 patch.object(replay, 'archive_created'), \
                 patch.object(replay.subprocess, 'Popen', return_value=Process()), \
                 patch.object(replay.capture_io, 'PcapTailReader', Tail), \
                 patch.object(replay.time, 'monotonic', side_effect=lambda: next(clock)), \
                 patch.object(replay.time, 'sleep'):
                return replay.run_replay(args, root / 'program.json', root, 'C', prepared, {}, {})

    @unittest.skipUnless(hasattr(replay.os, 'mkfifo'), 'Private FIFO runner is Linux-only')
    def test_runner_accepts_exact_packet_accounting(self):
        result = self.exercise_runner('ok')
        self.assertEqual(result['packets_checked'], 1)
        self.assertEqual(result['classifications'], 0)

    @unittest.skipUnless(hasattr(replay.os, 'mkfifo'), 'Private FIFO runner is Linux-only')
    def test_runner_rejects_missing_output_instead_of_counting_it_as_collision(self):
        with self.assertRaisesRegex(ValueError, 'stalled'):
            self.exercise_runner('missing')

    @unittest.skipUnless(hasattr(replay.os, 'mkfifo'), 'Private FIFO runner is Linux-only')
    def test_runner_rejects_duplicate_or_extra_output(self):
        with self.assertRaisesRegex(ValueError, 'additional BMv2 output'):
            self.exercise_runner('duplicate')


if __name__ == '__main__':
    unittest.main()
