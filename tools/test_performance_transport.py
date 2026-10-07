"""Pure tests: no raw sockets, interfaces, traffic or privileged operations."""

import socket
import struct
import unittest

import performance_transport as transport


TAG = bytes.fromhex('020000000001020000000002')


def make_frame(sequence):
    return TAG + b'\x08\x00\x45' + b'\x00' * 19 + struct.pack('!I', sequence) + b'\x00' * 22


def decode(frame):
    if frame[:12] != TAG:
        return None
    if len(frame) < 38:
        raise ValueError('Short sequence payload')
    return struct.unpack('!I', frame[34:38])[0]


def cmsg(timestamp_ns):
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    return [(socket.SOL_SOCKET, transport.SO_TIMESTAMPING_OLD,
             transport.SCM_TIMESTAMPING64.pack(seconds, nanoseconds, 0, 0, 0, 0))]


class PerformanceTransportTests(unittest.TestCase):
    def setUp(self):
        self.frames = [make_frame(seq) for seq in range(4)]

    def ledger_with_all_packets(self):
        ledger = transport.CaptureLedger(self.frames, decode)
        for seq, frame in enumerate(self.frames):
            now = 1_000_000_000_000 + seq * 10_000_000
            ledger.observe('input', frame, transport.PACKET_OUTGOING, cmsg(now), 0, now)
            ledger.observe('output', frame, transport.PACKET_OTHERHOST, cmsg(now + 100_000), 0, now)
        return ledger

    def audit(self):
        audit = transport.ClockAudit()
        audit.observe(100, 1_000_000_000_100, 110)
        audit.observe(10_000_100, 1_000_010_000_100, 10_000_110)
        return audit.report()

    def report(self, ledger=None, stats=None, clock=None):
        return transport.build_report(
            ledger or self.ledger_with_all_packets(),
            [100, 10_000_100, 20_000_100, 30_000_100],
            [200, 10_000_200, 20_000_200, 30_000_200],
            100, 40_000_100, 100, .3,
            stats if stats is not None else {'input': {'socket_packets': 4, 'socket_drops': 0},
                                             'output': {'socket_packets': 4, 'socket_drops': 0}},
            clock or self.audit(), [], [], {'input': 1000, 'output': 1000})

    def test_plan_rejects_non_dense_sequences_and_bad_bounds(self):
        self.assertAlmostEqual(transport.validate_plan(self.frames, 100, decode, .3), .04)
        for frames, rate, drain in ((self.frames[::-1], 100, .3), (self.frames, float('nan'), .3),
                                    (self.frames, 5001, .3), (self.frames, 100, 0),
                                    ([], 100, .3), ([b'bad'], 100, .3)):
            with self.assertRaises(ValueError):
                transport.validate_plan(frames, rate, decode, drain)

    def test_timestamp_and_packet_statistics_abis(self):
        self.assertEqual(transport.parse_timestamp_ns(cmsg(1_234_567_890)), 1_234_567_890)
        for ancillary in ([], cmsg(1_234_567_890) * 2,
                          [(socket.SOL_SOCKET, 37, b'bad')],
                          [(socket.SOL_SOCKET, 37, transport.SCM_TIMESTAMPING64.pack(1, 1_000_000_000, 0, 0, 0, 0))],
                          [(socket.SOL_SOCKET, 37, transport.SCM_TIMESTAMPING64.pack(0, 0, 0, 0, 1, 2))]):
            with self.assertRaises(ValueError):
                transport.parse_timestamp_ns(ancillary)
        self.assertEqual(transport.parse_packet_statistics(struct.pack('=II', 11, 2))['socket_drops'], 2)
        with self.assertRaises(ValueError):
            transport.parse_packet_statistics(b'bad')

    def test_clock_step_is_invalid_even_without_wall_regression(self):
        audit = transport.ClockAudit()
        audit.observe(100, 1_000_000_100, 110)
        audit.observe(10_000_100, 1_007_000_100, 10_000_110)
        report = audit.report()
        self.assertFalse(report['valid'])
        self.assertEqual(report['realtime_regressions'], 0)
        self.assertEqual(report['detected_offset_changes'], 1)

    def test_wide_bracket_invalidates_clock_quality(self):
        audit = transport.ClockAudit()
        audit.observe(100, 1_000_000_100, 2_000_100)
        audit.observe(10_000_100, 1_010_000_100, 10_000_110)
        self.assertFalse(audit.report()['valid'])

    def test_exact_frames_and_kernel_delays_pass(self):
        report = self.report()
        self.assertTrue(report['pilot_passed'])
        self.assertEqual(report['observed_loss_fraction_after_drain'], 0)
        self.assertEqual(report['latency']['summary_us']['median'], 100)
        self.assertEqual(report['throughput']['actual_offered_pps_over_window'], 100)
        self.assertEqual(report['throughput']['actual_sender_interpacket_pps'], 100)
        self.assertAlmostEqual(report['throughput']['observed_output_kernel_interarrival_pps'], 100)

    def test_capture_drops_withhold_loss_and_latency_claims(self):
        stats = {'input': {'socket_packets': 4, 'socket_drops': 0},
                 'output': {'socket_packets': 5, 'socket_drops': 1}}
        report = self.report(stats=stats)
        self.assertFalse(report['packet_delivery_valid'])
        self.assertIsNone(report['observed_loss_fraction_after_drain'])
        self.assertFalse(report['latency']['valid'])
        self.assertIsNone(report['latency']['summary_us'])

    def test_missing_stats_withhold_loss_claim(self):
        report = self.report(stats={'input': None, 'output': None})
        self.assertFalse(report['pilot_passed'])
        self.assertIsNone(report['observed_loss_fraction_after_drain'])

    def test_clock_problem_preserves_packet_counts(self):
        clock = self.audit()
        clock['valid'] = False
        clock['reasons'] = ['Detected CLOCK_REALTIME step']
        report = self.report(clock=clock)
        self.assertTrue(report['packet_delivery_valid'])
        self.assertEqual(report['captured_output_unique'], 4)
        self.assertFalse(report['pilot_passed'])
        self.assertIsNone(report['latency']['summary_us'])
        self.assertIsNone(report['throughput']['observed_output_kernel_interarrival_pps'])

    def test_missing_output_counts_observed_loss_after_drain(self):
        ledger = self.ledger_with_all_packets()
        ledger.counts['output'][3] = 0
        ledger.timestamps['output'][3] = None
        report = self.report(ledger)
        self.assertTrue(report['packet_delivery_valid'])
        self.assertEqual(report['observed_loss_fraction_after_drain'], .25)
        self.assertFalse(report['pilot_passed'])
        self.assertIsNone(report['latency']['summary_us'])

    def test_duplicate_corruption_and_unrelated_counts_are_visible(self):
        ledger = self.ledger_with_all_packets()
        ledger.observe('output', self.frames[0], 3, cmsg(2_000_000_000), 0, 99)
        changed = self.frames[1][:-1] + b'\x01'
        ledger.observe('output', changed, 3, cmsg(2_000_000_000), 0, 100)
        ledger.observe('output', b'noise', 0, [], 0, 101)
        report = self.report(ledger)
        counters = report['capture_counters']['output']
        self.assertEqual(counters['duplicates'], 1)
        self.assertEqual(counters['corrupted_frames'], 1)
        self.assertEqual(counters['untagged'], 1)
        self.assertFalse(report['pilot_passed'])

    def test_missing_timestamp_preserves_exact_frame_count(self):
        ledger = transport.CaptureLedger(self.frames, decode)
        ledger.observe('input', self.frames[0], 4, [], 0, 99)
        self.assertEqual(ledger.counts['input'][0], 1)
        self.assertIsNone(ledger.timestamps['input'][0])
        self.assertEqual(ledger.counters['input']['missing_timestamps'], 1)

    def test_packet_direction_filter_accepts_otherhost(self):
        ledger = transport.CaptureLedger(self.frames, decode)
        ledger.observe('input', self.frames[0], 0, cmsg(1_000_000_000), 0, 99)
        ledger.observe('output', self.frames[0], 4, cmsg(1_000_000_000), 0, 99)
        ledger.observe('output', self.frames[0], 3, cmsg(1_000_000_000), 0, 99)
        self.assertEqual(ledger.counts['input'][0], 0)
        self.assertEqual(ledger.counts['output'][0], 1)
        self.assertEqual(ledger.counters['output']['wrong_packet_type'], 1)

    def test_truncated_ancillary_does_not_discard_packet_evidence(self):
        ledger = transport.CaptureLedger(self.frames, decode)
        ledger.observe('input', self.frames[0], 4, cmsg(1_000_000_000),
                       getattr(socket, 'MSG_CTRUNC', 0x08), 99)
        self.assertEqual(ledger.counts['input'][0], 1)
        self.assertIsNone(ledger.timestamps['input'][0])
        self.assertEqual(ledger.counters['input']['truncated_ancillary'], 1)

    def test_negative_kernel_difference_withholds_latency(self):
        ledger = self.ledger_with_all_packets()
        ledger.timestamps['output'][2] = ledger.timestamps['input'][2] - 1
        report = self.report(ledger)
        self.assertFalse(report['latency']['valid'])
        self.assertEqual(report['latency']['negative_timestamp_differences'], 1)
        self.assertTrue(report['packet_delivery_valid'])


if __name__ == '__main__':
    unittest.main()
