"""Offline RAW timing, gate separation and exact capture accounting tests."""
import importlib
import socket
from pathlib import Path
import platform
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import raw_benchmark_transport as raw
import test_benchmark_transport as fixtures


class RawTransportTests(fixtures.PureTransportTests):
    # This subclass adds RAW-specific checks. Inherited tests continue checking
    # the untouched legacy transport through fixtures.transport.
    def raw_report(self, ledger=None, starts=None, end=None, stats=None, clock=None):
        starts = self.starts if starts is None else starts
        return raw.build_report(ledger or self.ledger(), starts, [value + 100 for value in starts],
            self.start, self.end if end is None else end, 100, 2,
            stats or {'input': {'socket_packets': 4, 'socket_drops': 0},
                      'output': {'socket_packets': 4, 'socket_drops': 0}},
            clock or fixtures.clock_report(), {'valid': True, 'reasons': [], 'samples': []},
            [], [], {'input': 1024, 'output': 1024})

    def test_wall_clock_failure_does_not_become_latency_pass(self):
        failed = fixtures.clock_report()
        failed.update(valid=False, reasons=['Wall correction detected'])
        report = self.raw_report(clock=failed)
        self.assertTrue(report['reduced_quality_valid'])
        self.assertFalse(report['metric_validity']['kernel_forwarding_latency'])
        self.assertFalse(report['kernel_timestamp_diagnostics']['valid'])
        self.assertIsNone(report['kernel_timestamp_diagnostics']['summary_us'])
        self.assertIn('Wall correction detected', report['kernel_timestamp_diagnostics']['reasons'])
        self.assertNotIn('send_start_monotonic_ns', report['per_packet'])
        self.assertEqual(report['per_packet']['send_start_raw_ns'], self.starts)
        self.assertEqual(report['clock_domains']['kernel_packet_timestamps'], 'CLOCK_REALTIME')

    def test_raw_clock_failure_withholds_rates_not_counts(self):
        report = raw.build_report(self.ledger(), self.starts, [v + 100 for v in self.starts],
            self.start, self.end, 100, 2,
            {'input': {'socket_packets': 4, 'socket_drops': 0}, 'output': {'socket_packets': 4, 'socket_drops': 0}},
            fixtures.clock_report(), {'valid': False, 'reasons': ['raw_clock_sample_gap_over_25ms']},
            [], [], {}, None)
        self.assertFalse(report['reduced_quality_valid'])
        self.assertTrue(report['metric_validity']['packet_accounting'])
        self.assertFalse(report['metric_validity']['offered_load'])

    def test_raw_offered_duration_not_legacy_rate(self):
        report = self.raw_report(end=self.end + 2_000_000)
        self.assertFalse(report['pacing_quality']['valid'])
        self.assertEqual(report['raw_pacing_conformance_status'], 'WARNING')
        self.assertTrue(report['measurement_integrity_valid'])
        self.assertTrue(report['metric_validity']['offered_load'])
        self.assertAlmostEqual(report['throughput']['actual_offered_pps_over_window'], 4 / .042)

    def test_5113us_completion_warning_keeps_counts_and_local_rates_eligible(self):
        frames = [fixtures.make_frame(i) for i in range(10)]
        ledger = raw.CaptureLedger(frames, fixtures.decode)
        for role, packet_type in (('input', 4), ('output', 3)):
            for i, frame in enumerate(frames):
                ledger.observe(role, frame, packet_type, fixtures.cmsg(1_000_000_000_000 + i * 1_000_000), 0, 100)
        starts = [self.start + i * 1_000_000 for i in range(10)]
        finishes = [value + 100 for value in starts]
        starts[4] += 160_204
        finishes[4] = self.start + 4_000_000 + 5_113_093
        for i in range(5, 10):
            starts[i] = finishes[i - 1] + 100
            finishes[i] = starts[i] + 100
        report = raw.build_report(ledger, starts, finishes, self.start, self.start + 10_000_000,
            1000, 2, {role: {'socket_packets': 10, 'socket_drops': 0} for role in ('input', 'output')},
            fixtures.clock_report(), {'valid': True, 'reasons': [], 'samples': []}, [], [], {})
        self.assertEqual(report['protocol'], 'raw-performance-calibration-v3')
        self.assertEqual(report['pacing_quality']['maximum_send_lateness_limit_ns'], 5_000_000)
        self.assertEqual(report['pacing_quality']['p99_send_lateness_limit_ns'], 1_000_000)
        self.assertEqual(report['pacing_quality']['send_completion_lateness_summary_ns']['maximum'], 5_113_093)
        self.assertEqual(report['raw_pacing_conformance_status'], 'WARNING')
        self.assertTrue(report['pacing_warnings'])
        self.assertTrue(report['measurement_integrity_valid'])
        self.assertTrue(report['reduced_quality_valid'])
        self.assertTrue(report['metric_validity']['packet_accounting'])
        self.assertTrue(report['metric_validity']['offered_load'])
        self.assertTrue(report['metric_validity']['delivered_throughput'])
        self.assertFalse(report['metric_validity']['kernel_forwarding_latency'])
        self.assertFalse(report['pacing_conformance']['uniform_load_or_saturation_claims_supported'])

    def test_path_non_delivery_is_not_capture_loss_or_switch_drop_attribution(self):
        ledger = self.ledger()
        ledger.counts['output'][3] = 0
        ledger.timestamps['output'][3] = None
        ledger.counters['output']['read_packets'] = 3
        report = self.raw_report(ledger=ledger, stats={
            'input': {'socket_packets': 4, 'socket_drops': 0},
            'output': {'socket_packets': 3, 'socket_drops': 0}})
        self.assertTrue(report['measurement_integrity_valid'])
        self.assertTrue(report['metric_validity']['packet_accounting'])
        self.assertTrue(report['metric_validity']['delivered_throughput'])
        self.assertEqual(report['path_non_delivery']['missing_output_after_bounded_drain'], 1)
        self.assertEqual(report['observed_loss_fraction_after_drain'], .25)
        self.assertEqual(report['throughput']['delivered_pps'], 75)
        dropped = self.raw_report(ledger=ledger, stats={
            'input': {'socket_packets': 4, 'socket_drops': 0},
            'output': {'socket_packets': 3, 'socket_drops': 1}})
        self.assertFalse(dropped['measurement_integrity_valid'])
        self.assertFalse(dropped['metric_validity']['packet_accounting'])
        self.assertFalse(dropped['metric_validity']['delivered_throughput'])
        self.assertIsNone(dropped['path_non_delivery']['missing_output_after_bounded_drain'])
        self.assertIsNone(dropped['observed_loss_fraction_after_drain'])
        self.assertTrue(dropped['metric_validity']['offered_load'])

    def test_reordered_exact_frames_are_observations_not_corrupted_accounting(self):
        report = self.raw_report(ledger=self.ledger(output_order=[1, 0, 2, 3]))
        self.assertEqual(report['capture_counters']['output']['sequence_regressions'], 1)
        self.assertEqual(report['raw_pacing_conformance_status'], 'WARNING')
        self.assertTrue(report['measurement_integrity_valid'])
        self.assertTrue(report['metric_validity']['packet_accounting'])

    def test_raw_sender_regression_is_hard_failure_even_if_pacing_is_warning(self):
        starts = [100, 10_000_100, 9_000_100, 30_000_100]
        report = self.raw_report(starts=starts)
        self.assertEqual(report['raw_pacing_conformance_status'], 'WARNING')
        self.assertFalse(report['measurement_integrity_valid'])
        self.assertFalse(report['metric_validity']['offered_load'])
        self.assertFalse(report['metric_validity']['delivered_throughput'])
        self.assertTrue(report['metric_validity']['packet_accounting'])

    def test_incomplete_sender_plan_is_hard_failure_not_warning_only(self):
        report = self.raw_report(starts=self.starts[:-1])
        self.assertEqual(report['raw_pacing_conformance_status'], 'WARNING')
        self.assertFalse(report['measurement_integrity_valid'])
        self.assertFalse(report['metric_validity']['packet_accounting'])
        self.assertFalse(report['metric_validity']['offered_load'])

    def test_native_final_wait_error_is_hard_even_after_all_frames_sent(self):
        report = raw.build_report(self.ledger(), self.starts, [value + 100 for value in self.starts],
            self.start, self.end, 100, 2,
            {role: {'socket_packets': 4, 'socket_drops': 0} for role in ('input', 'output')},
            fixtures.clock_report(), {'valid': True, 'reasons': [], 'samples': []},
            ['Native sender final-window sleep failed at sequence 4'], [], {})
        self.assertFalse(report['measurement_integrity_valid'])
        self.assertFalse(report['metric_validity']['offered_load'])
        self.assertFalse(report['metric_validity']['packet_accounting'])

    def test_send_completion_bracket_cannot_hide_late_syscall(self):
        pacing = raw.assess_raw_pacing(self.ledger(), self.starts,
            [value + 31_000_000 for value in self.starts], self.start, self.end, 100)
        self.assertFalse(pacing['valid'])
        self.assertIn('RAW send-completion upper-bound maximum lateness exceeded its pacing limit', pacing['reasons'])

    def test_realtime_kernel_burst_is_retained_not_qualified(self):
        times = [1_000_000_000_000, 1_000_010_000_000, 1_000_029_000_000, 1_000_030_000_000]
        report = self.raw_report(ledger=self.ledger(times))
        self.assertTrue(report['reduced_quality_valid'])
        self.assertFalse(report['legacy_kernel_arrival_pacing']['valid'])
        self.assertFalse(report['legacy_kernel_arrival_pacing']['qualified_kernel_arrival_pacing'])

    def test_raw_burst_early_send_and_regression_fail(self):
        for starts in ([100, 10_000_100, 29_000_100, 30_000_100],
                       [100, 9_999_100, 20_000_100, 30_000_100],
                       [100, 10_000_100, 9_000_100, 30_000_100]):
            with self.subTest(starts=starts):
                self.assertFalse(self.raw_report(starts=starts)['pacing_quality']['valid'])

    def test_drain_inclusive_delivery_is_not_egress_rate(self):
        report = self.raw_report()
        self.assertEqual(report['throughput']['delivered_pps'], 100)
        self.assertTrue(report['throughput']['output_count_includes_bounded_drain'])
        self.assertFalse(report['throughput']['output_rate_valid'])
        self.assertNotIn('observed_output_kernel_interarrival_pps', report['throughput'])

    def test_capture_drop_backlog_and_corruption_are_not_ignored(self):
        for stats in ({'input': {'socket_packets': 4, 'socket_drops': 1}, 'output': {'socket_packets': 4, 'socket_drops': 0}},
                      {'input': {'socket_packets': 5, 'socket_drops': 0}, 'output': {'socket_packets': 4, 'socket_drops': 0}}):
            self.assertFalse(self.raw_report(stats=stats)['reduced_quality_valid'])
        ledger = self.ledger()
        ledger.counters['output']['corrupted_frames'] = 1
        self.assertFalse(self.raw_report(ledger=ledger)['reduced_quality_valid'])

    def test_missing_kernel_timestamp_remains_warning_not_fake_latency(self):
        ledger = self.ledger()
        ledger.timestamps['input'][2] = None
        ledger.counters['input']['missing_timestamps'] = 1
        report = self.raw_report(ledger=ledger)
        self.assertTrue(report['metric_validity']['packet_accounting'])
        self.assertFalse(report['kernel_timestamp_diagnostics']['valid'])
        self.assertTrue(report['kernel_timestamp_diagnostics']['reasons'])

    def test_import_never_opens_sockets_raw(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('Import network access')):
            importlib.reload(raw)


@unittest.skipUnless(platform.system() == 'Linux' and shutil.which('cc'), 'Unprivileged Linux socketpair worker check')
class RawPhaseWorkerTests(unittest.TestCase):
    def test_native_sender_capture_audit_callbacks_and_cleanup_without_packet_sockets(self):
        import native_raw_paced_sender as sender
        frames = [fixtures.make_frame(i) for i in range(8)]
        input_tx, input_rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        output_tx, output_rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        send_tx, pump_rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        pump_rx.settimeout(.02)
        stop = threading.Event()
        callbacks = []

        class Shim:
            # The metadata/statistics are SYNTHETIC contract fixtures, not real
            # kernel packet observations or performance evidence.
            def __init__(self, handle, role):
                self.handle, self.role, self.read_count = handle, role, 0
            def fileno(self): return self.handle.fileno()
            def bind(self, address): pass
            def setblocking(self, value): self.handle.setblocking(value)
            def setsockopt(self, level, name, value): pass
            def getsockopt(self, level, name, size=None):
                if name == raw.PACKET_STATISTICS:
                    return raw.PACKET_STATS.pack(self.read_count, 0)
                return 1024 * 1024
            def recvmsg(self, *args):
                frame, ancillary, flags, address = self.handle.recvmsg(*args)
                self.read_count += 1
                return frame, fixtures.cmsg(time.time_ns()), flags, ('fixture', 0, 4 if self.role == 'input' else 3)
            def close(self): self.handle.close()

        def pump():
            while not stop.is_set():
                try:
                    frame = pump_rx.recv(65535)
                    input_tx.send(frame)
                    output_tx.send(frame)
                except socket.timeout:
                    continue
                except OSError:
                    return

        def bracket():
            return (raw.raw_now_ns(), time.monotonic_ns(), time.time_ns(), time.monotonic_ns(), raw.raw_now_ns())

        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='raw_phase_workers_') as name:
                native = sender.NativeRawPacedSender(sender.build_native_raw_paced_sender(
                    repo=Path(name), source=Path(sender.__file__).with_name('raw_paced_sender.c')))
                shims = iter((Shim(input_rx, 'input'), Shim(output_rx, 'output'), Shim(send_tx, 'sender')))
                with patch.object(raw.socket, 'socket', side_effect=lambda *a, **k: next(shims)):
                    report = raw.run_phase(frames, 'fixture-input', 'fixture-output', 100,
                        sequence_from_frame=fixtures.decode, drain_seconds=.05, clock_reader=bracket,
                        paced_sender=native, on_window_start=lambda: callbacks.append('start'),
                        on_window_end=lambda: callbacks.append('end'))
                self.assertEqual(report['sent_packets'], 8)
                self.assertEqual(report['captured_input_unique'], 8)
                self.assertEqual(report['captured_output_unique'], 8)
                self.assertEqual(callbacks, ['start', 'end'])
                self.assertFalse(report['metric_validity']['kernel_forwarding_latency'])
                self.assertGreaterEqual(report['actual_drain_raw_seconds'], .05)
                self.assertEqual(report['scheduling']['clock_domain'], 'CLOCK_MONOTONIC_RAW')
        finally:
            stop.set()
            thread.join(.2)
            for handle in (input_tx, input_rx, output_tx, output_rx, send_tx, pump_rx):
                handle.close()
        self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
