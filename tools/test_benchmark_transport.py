"""Pure/offline tests; no raw sockets, traffic or privileged operations."""

import importlib
from pathlib import Path
import socket
import struct
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

# Windows staging uses the existing read-only pilot helper. Installed tools are
# siblings and do not need this local test-only search path.
PILOT = Path(__file__).resolve().parents[1] / 'performance_benchmark' / 'transport'
if PILOT.is_dir():
    sys.path.insert(0, str(PILOT))
import benchmark_transport as transport


TAG = bytes.fromhex('020000000001020000000002')


def make_frame(sequence):
    return TAG + b'\x08\x00\x45' + b'\x00' * 19 + struct.pack('!I', sequence) + b'\x00' * 22


def decode(frame):
    return struct.unpack_from('!I', frame, 34)[0]


def cmsg(timestamp_ns):
    seconds, nanoseconds = divmod(timestamp_ns, 1_000_000_000)
    return [(socket.SOL_SOCKET, 37,
             transport.SCM_TIMESTAMPING64.pack(seconds, nanoseconds, 0, 0, 0, 0))]


def clock_report(start=100, end=40_000_100):
    audit = transport.ClockAudit()
    for mono in range(start - 100, end + 101, 5_000_000):
        audit.observe(mono, 1_000_000_000_000 + mono, mono + 10)
    audit.observe(end + 100, 1_000_000_000_000 + end + 100, end + 110)
    return audit.report(start, end)


class PureTransportTests(unittest.TestCase):
    def test_native_reader_keeps_every_sample_and_unchanged_width_gate(self):
        samples = iter([(0, 1000000000000, 5),
                        (5000000, 1000005000000, 5200000),
                        (10000000, 1000010000000, 10000005)])
        audit = transport.ClockAudit(bracket_reader=lambda: next(samples))
        for _ in range(3):
            audit.sample()
        self.assertEqual(len(audit.samples), 3)
        report = audit.report(10, 9000000)
        self.assertFalse(report['valid'])
        self.assertEqual(report['maximum_bracket_width_ns'], 200000)
        self.assertEqual(report['maximum_allowed_bracket_width_ns'], 100000)
        self.assertEqual(report['clock_bracket_backend'], 'linux-native-three-read-v1')

    def setUp(self):
        self.frames = [make_frame(seq) for seq in range(4)]
        self.start = 100
        self.end = 40_000_100
        self.starts = [self.start + seq * 10_000_000 for seq in range(4)]

    def ledger(self, input_times=None, output_order=None):
        ledger = transport.CaptureLedger(self.frames, decode)
        input_times = input_times or [1_000_000_000_000 + seq * 10_000_000 for seq in range(4)]
        for seq in range(4):
            ledger.observe('input', self.frames[seq], 4, cmsg(input_times[seq]), 0, 987654321)
        for seq in output_order or range(4):
            ledger.observe('output', self.frames[seq], 3, cmsg(input_times[seq] + 100_000), 0, 987654322)
        return ledger

    def report(self, ledger=None, starts=None, end=None, clock=None, stats=None):
        return transport.build_report(
            ledger or self.ledger(), starts or self.starts,
            [value + 100 for value in starts or self.starts], self.start,
            self.end if end is None else end, 100, 2,
            stats or {'input': {'socket_packets': 4, 'socket_drops': 0},
                      'output': {'socket_packets': 4, 'socket_drops': 0}},
            clock or clock_report(), [], [], {'input': 1024, 'output': 1024})

    def test_large_plan_bounds_and_duration(self):
        large = [make_frame(seq) for seq in range(500_000)]
        self.assertEqual(transport.validate_plan(large, 10000, decode, 2), 50)
        self.assertEqual(transport.MAX_PACKETS, 500000)
        class Oversize(list):
            def __len__(self):
                return 500001
        with self.assertRaises(ValueError):
            transport.validate_plan(Oversize(self.frames), 10000, decode, 2)
        for frames, rate, drain in ((large, 1000, 2), (self.frames, 10001, 2),
                                    (self.frames, 100, .049), (self.frames, 100, 2.001),
                                    (self.frames, float('nan'), 2),
                                    (self.frames[::-1], 100, 2)):
            with self.assertRaises(ValueError):
                transport.validate_plan(frames, rate, decode, drain)

    def test_good_pacing_exact_bytes_and_path_delay(self):
        report = self.report()
        self.assertTrue(report['gate_valid'])
        self.assertTrue(report['delivery_valid'])
        self.assertTrue(report['latency_valid'])
        self.assertTrue(report['pacing_quality']['valid'])
        self.assertEqual(report['latency']['summary_us']['median'], 100)
        self.assertEqual(report['throughput']['actual_offered_pps_over_window'], 100)
        self.assertEqual(report['throughput']['actual_input_kernel_interarrival_pps'], 100)
        self.assertEqual(report['throughput']['observed_output_unique_pps_over_measured_window'], 100)
        self.assertTrue(report['throughput']['output_count_includes_bounded_drain'])
        self.assertEqual(report['pacing_quality']['input_kernel_short_gap_fraction'], 0)
        self.assertEqual(report['per_packet']['send_start_monotonic_ns'], self.starts)

    def test_sender_and_kernel_burst_are_reported_independently(self):
        # Last kernel gap is less than a quarter nominal interval, although
        # userspace send deadlines were met perfectly.
        kernel = [1_000_000_000_000, 1_000_010_000_000,
                  1_000_029_000_000, 1_000_030_000_000]
        report = self.report(ledger=self.ledger(kernel))
        self.assertFalse(report['pacing_quality']['valid'])
        self.assertEqual(report['pacing_quality']['input_kernel_short_gap_fraction'], 1 / 3)
        self.assertEqual(report['pacing_quality']['sender_short_gap_fraction'], 0)
        self.assertTrue(report['delivery_valid'])
        self.assertTrue(report['latency_valid'])
        starts = [100, 10_000_100, 41_000_100, 42_000_100]
        report = self.report(starts=starts, end=43_000_100)
        self.assertGreater(report['pacing_quality']['sender_short_gap_fraction'], .01)
        self.assertFalse(report['pacing_quality']['valid'])
        self.assertEqual(report['pacing_quality']['send_lateness_ns'][2], 21_000_000)

    def test_offered_rate_gate_uses_actual_window(self):
        report = self.report(end=self.end + 2_000_000)
        self.assertFalse(report['pacing_quality']['valid'])
        self.assertAlmostEqual(report['pacing_quality']['actual_offered_pps_over_window'], 4 / .042)

    def test_clock_gap_and_bracket_limits(self):
        for gap, bracket in ((25_000_001, 10), (5_000_000, 100_001)):
            audit = transport.ClockAudit()
            audit.observe(0, 1_000_000_000_000, bracket)
            audit.observe(gap, 1_000_000_000_000 + gap, gap + 10)
            self.assertFalse(audit.report()['valid'])
        audit = transport.ClockAudit()
        audit.observe(0, 1_000_000_000_000, 10)
        audit.observe(25_000_000, 1_000_025_000_000, 25_100_000)
        self.assertTrue(audit.report()['valid'])

    def test_clock_sample_scope_excludes_drain_gap(self):
        audit = transport.ClockAudit()
        for mono in (0, 5_000_000, 10_000_000, 15_000_000, 2_000_000_000):
            audit.observe(mono, 1_000_000_000_000 + mono, mono + 10)
        report = audit.report(100, 10_000_100)
        self.assertTrue(report['valid'])
        self.assertEqual(report['maximum_sample_gap_ns'], 5_000_000)
        self.assertEqual(len(report['samples']), 5)
        self.assertEqual(len(report['measured_window_samples']), 4)

    def test_unbracketed_window_and_clock_step_invalidate_latency(self):
        audit = transport.ClockAudit()
        audit.observe(100, 1_000_000_100, 110)
        audit.observe(5_000_100, 1_007_000_100, 5_000_110)
        report = audit.report(99, 5_000_101)
        self.assertFalse(report['valid'])
        self.assertEqual(report['detected_offset_changes'], 1)
        phase = self.report(clock=report)
        self.assertTrue(phase['delivery_valid'])
        self.assertFalse(phase['latency_valid'])

    def test_exact_one_millisecond_offset_displacement_is_rejected(self):
        audit = transport.ClockAudit()
        audit.observe(0, 1_000_000_000_000, 10)
        audit.observe(5_000_000, 1_000_006_000_000, 5_000_010)
        report = audit.report()
        self.assertEqual(report['maximum_observed_offset_displacement_ns'], 1_000_000)
        self.assertFalse(report['valid'])

    def test_false_recvmsg_fallback_and_missing_timestamps_rejected(self):
        fallback = [(socket.SOL_SOCKET, 35, struct.pack('=qq', 1234, 5678))]
        with self.assertRaises(ValueError):
            transport.parse_timestamp_ns(fallback)
        ledger = self.ledger()
        ledger.timestamps['input'][2] = None
        ledger.counters['input']['missing_timestamps'] = 1
        report = self.report(ledger)
        self.assertTrue(report['delivery_valid'])
        self.assertFalse(report['latency_valid'])
        self.assertFalse(report['pacing_quality']['valid'])
        self.assertEqual(report['latency']['timestamp_socket_option'], 37)
        self.assertEqual(report['latency']['timestamp_flags'], 24)

    def test_loss_drop_duplicate_corruption_and_reordering_counters(self):
        ledger = self.ledger()
        ledger.counts['output'][3] = 0
        ledger.timestamps['output'][3] = None
        report = self.report(ledger)
        self.assertTrue(report['delivery_valid'])
        self.assertEqual(report['observed_loss_fraction_after_drain'], .25)
        self.assertFalse(report['latency_valid'])
        self.assertTrue(report['capacity_quality_valid'])
        self.assertEqual(report['throughput']['reliable_output_unique_pps_over_measured_window'], 75)
        self.assertEqual(report['throughput']['observed_output_kernel_interarrival_pps'], 100)
        report = self.report(stats={'input': {'socket_drops': 1}, 'output': {'socket_drops': 0}})
        self.assertFalse(report['delivery_valid'])
        self.assertIsNone(report['observed_loss_fraction_after_drain'])
        ledger = self.ledger()
        ledger.observe('output', self.frames[0], 3, cmsg(1_000_000_000_000), 0, 1)
        ledger.observe('output', self.frames[1][:-1] + b'\x01', 3, [], 0, 1)
        report = self.report(ledger)
        self.assertEqual(report['capture_counters']['output']['duplicates'], 1)
        self.assertEqual(report['capture_counters']['output']['corrupted_frames'], 1)
        self.assertFalse(report['delivery_valid'])
        report = self.report(self.ledger(output_order=[1, 0, 2, 3]))
        self.assertEqual(report['capture_counters']['output']['sequence_regressions'], 1)
        self.assertFalse(report['latency_valid'])

    def test_unread_capture_backlog_invalidates_loss_inference(self):
        report = self.report(stats={'input': {'socket_packets': 5, 'socket_drops': 0},
                                    'output': {'socket_packets': 4, 'socket_drops': 0}})
        self.assertFalse(report['delivery_valid'])
        self.assertFalse(report['capacity_quality_valid'])
        self.assertIsNone(report['observed_loss_fraction_after_drain'])

    def test_negative_delays_and_input_ordering(self):
        ledger = self.ledger()
        ledger.timestamps['output'][2] = ledger.timestamps['input'][2] - 1
        report = self.report(ledger)
        self.assertEqual(report['latency']['negative_timestamp_differences'], 1)
        self.assertFalse(report['latency_valid'])
        ledger = self.ledger()
        ledger.counters['input']['sequence_regressions'] = 1
        report = self.report(ledger)
        self.assertFalse(report['latency_valid'])
        self.assertFalse(report['pacing_quality']['valid'])

    def test_import_never_opens_sockets(self):
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('Network on import')):
            importlib.reload(transport)


class FakeSocket:
    def __init__(self, trace, number, fail_send=False):
        self.trace, self.number, self.fail_send = trace, number, fail_send
        self.closed = False

    def setsockopt(self, level, option, value):
        self.trace.append(('option', self.number, option, value))

    def getsockopt(self, level, option, size=None):
        if option == transport.PACKET_STATISTICS:
            return struct.pack('=II', 0, 0)
        return 1024

    def bind(self, address):
        self.trace.append(('bind', self.number, address))

    def setblocking(self, value):
        self.trace.append(('blocking', self.number, value))

    def send(self, frame):
        self.trace.append(('send', self.number))
        if self.fail_send:
            raise BlockingIOError('full send queue')
        return len(frame)

    def recvmsg(self, *args):
        raise BlockingIOError

    def close(self):
        self.closed = True
        self.trace.append(('close', self.number))

    def fileno(self):
        return 100 + self.number


class FakeSelector:
    def __init__(self, trace):
        self.trace = trace

    def register(self, receiver, events, role):
        self.trace.append(('register', role))

    def select(self, timeout):
        time.sleep(min(timeout, .001))
        return []

    def close(self):
        self.trace.append(('selector_close',))


class CallbackLifecycleTests(unittest.TestCase):
    def run_fake(self, start=None, end=None, fail_send=False, paced_sender=None):
        trace, handles = [], []
        def factory(*args):
            handle = FakeSocket(trace, len(handles), fail_send)
            handles.append(handle)
            return handle
        with mock.patch.object(transport, '_require_linux_abi'), \
             mock.patch.object(transport.socket, 'AF_PACKET', 17, create=True), \
             mock.patch.object(transport.socket, 'socket', side_effect=factory), \
             mock.patch.object(transport.selectors, 'DefaultSelector', return_value=FakeSelector(trace)):
            try:
                report = transport.run_phase([make_frame(0)], 'host-in', 'host-out', 1000,
                                             sequence_from_frame=decode, drain_seconds=.05,
                                             on_window_start=lambda: start(trace) if start else trace.append(('start',)),
                                             on_window_end=lambda: end(trace) if end else trace.append(('end',)),
                                             paced_sender=paced_sender)
            except transport.PhaseCallbackError as error:
                report = error
        return trace, handles, report

    def test_callbacks_follow_socket_setup_and_precede_cleanup(self):
        trace, handles, report = self.run_fake()
        start = trace.index(('start',))
        end = trace.index(('end',))
        send = trace.index(('send', 2))
        self.assertLess(trace.index(('blocking', 2, False)), start)
        self.assertLess(start, send)
        self.assertLess(send, end)
        self.assertLess(end, trace.index(('close', 0)))
        self.assertTrue(all(handle.closed for handle in handles))
        self.assertEqual(report['sent_packets'], 1)
        timestamp_options = [row for row in trace if row[0] == 'option' and row[2] == 37]
        self.assertEqual(len(timestamp_options), 2)
        self.assertTrue(all(row[3] == 24 for row in timestamp_options))
        self.assertFalse(any(row[0] == 'option' and row[2] == 35 for row in trace))

    def test_callback_failures_abort_and_propagate_partial_evidence(self):
        def fail(trace):
            trace.append(('callback_failure',))
            raise OSError('resource counter unreadable')
        for which in ('start', 'end'):
            trace, handles, result = self.run_fake(**{which: fail})
            self.assertIsInstance(result, transport.PhaseCallbackError)
            self.assertEqual(result.callback_name, 'on_window_' + which)
            self.assertFalse(result.partial_report['gate_valid'])
            self.assertTrue(all(handle.closed for handle in handles))
            self.assertEqual(result.partial_report['sent_packets'], 0 if which == 'start' else 1)

    def test_nonblocking_send_failure_returns_invalid_report(self):
        trace, handles, report = self.run_fake(fail_send=True)
        self.assertEqual(report['sent_packets'], 0)
        self.assertEqual(report['unsent_sequences'], [0])
        self.assertFalse(report['gate_valid'])
        self.assertTrue(any('Nonblocking send failed' in value for value in report['errors']))
        self.assertIn(('end',), trace)
        self.assertTrue(all(handle.closed for handle in handles))

    def test_native_plan_preallocation_and_decode_outside_resource_window(self):
        events = []
        class Plan:
            def run_raw(self, fd):
                events.append(('native_run', fd))
                start = time.monotonic_ns()
                return SimpleNamespace(scheduled_start_ns=start,
                                       send_window_end_ns=start + 1_000_000,
                                       sent_count=1)
            def report(self, result):
                events.append('decode')
                return {'sent_starts': [result.scheduled_start_ns],
                        'sent_finishes': [result.scheduled_start_ns + 10],
                        'errors': []}
            def cancel(self):
                events.append('cancel')
            def close(self):
                events.append('closed')
        class Sender:
            provenance = {'backend': 'test-only'}
            def prepare(self, frames, offsets, duration):
                events.append(('prepared', len(frames), offsets, duration))
                return Plan()
        trace, handles, report = self.run_fake(
            start=lambda trace: events.append('start'),
            end=lambda trace: events.append('end'), paced_sender=Sender())
        self.assertEqual(events, [('prepared', 1, [0], 1_000_000), 'start',
                                  ('native_run', 102), 'end', 'decode', 'closed'])
        self.assertTrue(all(handle.closed for handle in handles))
        self.assertEqual(report['sent_packets'], 1)
        self.assertEqual(report['scheduling']['backend'], 'linux-native-paced-send-v1')
        self.assertEqual(report['pacing_quality']['maximum_send_lateness_limit_ns'], 5_000_000)

    def test_native_partial_results_retained_when_resource_end_fails(self):
        events = []
        class Plan:
            def run_raw(self, fd):
                start = time.monotonic_ns()
                return SimpleNamespace(scheduled_start_ns=start,
                                       send_window_end_ns=start + 1_000_000,
                                       sent_count=0)
            def report(self, result):
                events.append('decode')
                return {'sent_starts': [], 'sent_finishes': [],
                        'errors': ['Native nonblocking send failed at sequence 0'],
                        'attempted_starts': [result.scheduled_start_ns]}
            def cancel(self):
                events.append('cancel')
            def close(self):
                events.append('closed')
        class Sender:
            provenance = {'backend': 'test-only'}
            def prepare(self, *args):
                return Plan()
        def fail(trace):
            raise OSError('resource end failed')
        _, handles, error = self.run_fake(end=fail, paced_sender=Sender())
        self.assertIsInstance(error, transport.PhaseCallbackError)
        self.assertEqual(events, ['decode', 'closed'])
        self.assertIn('Native nonblocking send failed at sequence 0', error.partial_report['errors'])
        self.assertEqual(len(error.partial_report['scheduling']['native_attempts']['attempted_starts']), 1)
        self.assertTrue(all(handle.closed for handle in handles))

    def test_invalid_interfaces_are_rejected_before_socket_setup(self):
        with mock.patch.object(transport.socket, 'socket', side_effect=AssertionError('Socket opened')):
            with self.assertRaises(ValueError):
                transport.run_phase([make_frame(0)], 'same', 'same', 1000,
                                    sequence_from_frame=decode)


if __name__ == '__main__':
    unittest.main()
