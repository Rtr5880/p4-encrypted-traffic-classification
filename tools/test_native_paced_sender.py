#!/usr/bin/env python3
"""Pure plan tests plus Linux-only unprivileged AF_UNIX datagram ABI tests.

No interfaces, BMv2 process, privileged traffic, RF model, or prior evidence are
accessed. Native tests build into a new tempfile directory and do not impose
benchmark pacing thresholds on a shared machine's unit-test scheduler.
"""
import ctypes
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import native_paced_sender as n


class _FakeLibrary:
    def __init__(self):
        self.etc_paced_sender_cancel_new = Mock(return_value=123)
        self.etc_paced_sender_cancel_request = Mock()
        self.etc_paced_sender_cancel_free = Mock()
        self.etc_paced_sender_run = Mock(side_effect=self._run)

    @staticmethod
    def _run(fd, blob, blob_size, offsets, lengths, deadlines, count, duration,
             starts, finishes, flag, pointer):
        result = pointer._obj
        result.scheduled_start_ns, result.send_window_end_ns = 1_000_000, 1_100_000
        for index in range(count):
            starts[index] = 1_000_000 + deadlines[index]
            finishes[index] = starts[index] + 10
        result.sent_count = result.attempted_count = count
        result.error_index = result.returned_bytes = -1
        return 0


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.sender = n.NativePacedSender.__new__(n.NativePacedSender)
        self.sender._library = _FakeLibrary()

    def plan(self):
        return self.sender.prepare([b'a' * 60, b'b' * 64], [0, 100_000], 200_000)

    def test_prepare_packs_original_bytes_and_exact_offsets_without_sending(self):
        with self.plan() as plan:
            self.assertEqual(bytes(plan._blob), b'a' * 60 + b'b' * 64)
            self.assertEqual(list(plan._offsets), [0, 60])
            self.assertEqual(list(plan._lengths), [60, 64])
            self.assertEqual(list(plan._deadlines), [0, 100_000])
            self.sender._library.etc_paced_sender_run.assert_not_called()

    def test_raw_result_defers_list_conversion(self):
        with self.plan() as plan:
            raw = plan.run_raw(12)
            self.assertIsInstance(raw, n._Result)
            self.assertEqual(raw.sent_count, 2)
            report = plan.report(raw)
            self.assertEqual(report['sent_starts'], [1_000_000, 1_100_000])
            self.assertEqual(report['sent_finishes'], [1_000_010, 1_100_010])
            self.assertEqual(report['errors'], [])
            with self.assertRaises(n.NativeSenderError):
                plan.run_raw(12)

    def test_error_attempt_is_not_hidden_or_retried(self):
        def failed(*args):
            starts, finishes, pointer = args[8], args[9], args[11]
            starts[0], finishes[0] = 20, 22
            starts[1], finishes[1] = 30, 33
            result = pointer._obj
            result.scheduled_start_ns, result.send_window_end_ns = 10, 34
            result.sent_count, result.attempted_count = 1, 2
            result.error_code, result.error_errno, result.error_index = 7, 11, 1
            result.returned_bytes = -1
            return 0
        self.sender._library.etc_paced_sender_run.side_effect = failed
        with self.plan() as plan:
            result = plan.run(12)
            self.assertEqual(result['sent_starts'], [20])
            self.assertEqual(result['attempted_starts'], [20, 30])
            self.assertEqual(result['attempted_finishes'], [22, 33])
            self.assertIn('errno=11', result['errors'][0])
            self.sender._library.etc_paced_sender_run.assert_called_once()

    def test_cancel_and_close_are_idempotent(self):
        plan = self.plan()
        plan.cancel()
        self.sender._library.etc_paced_sender_cancel_request.assert_called_once_with(123)
        plan.close()
        plan.close()
        plan.cancel()
        self.sender._library.etc_paced_sender_cancel_free.assert_called_once_with(123)
        self.sender._library.etc_paced_sender_cancel_request.assert_called_once()
        with self.assertRaises(n.NativeSenderError):
            plan.run(12)

    def test_close_rejects_active_run(self):
        plan = self.plan()
        plan._running = True
        with self.assertRaises(n.NativeSenderError):
            plan.close()
        self.sender._library.etc_paced_sender_cancel_free.assert_not_called()
        plan._running = False
        plan.close()

    def test_invalid_plans_fail_before_cancel_allocation(self):
        cases = [([], [], 100_000), ([b'a' * 59], [0], 100_000),
                 ([bytearray(60)], [0], 100_000), ([b'a' * 60], [False], 100_000),
                 ([b'a' * 60], [1], 100_000), ([b'a' * 60], [0], True),
                 ([b'a' * 60], [0], 99_999), ([b'a' * 60], [0], 1_000_000_001),
                 ([b'a' * 60] * 2, [0, 1], 200_000),
                 ([b'a' * 60] * 2, [0, 100_000], 100_000)]
        for frames, offsets, duration in cases:
            with self.subTest(offsets=offsets, duration=duration):
                with self.assertRaises(n.NativeSenderError):
                    self.sender.prepare(frames, offsets, duration)
        self.sender._library.etc_paced_sender_cancel_new.assert_not_called()

    def test_negative_boolean_or_noninteger_fd_rejected(self):
        for descriptor in [-1, True, 1.5, '12']:
            with self.plan() as plan:
                with self.assertRaises(n.NativeSenderError):
                    plan.run(descriptor)

    def test_invalid_report_counts_rejected(self):
        with self.plan() as plan:
            raw = plan.run_raw(12)
            raw.sent_count = 3
            with self.assertRaises(n.NativeSenderError):
                plan.report(raw)

    def test_import_has_no_build_load_or_thread_side_effects(self):
        spec = importlib.util.spec_from_file_location('sender_import_probe', n.__file__)
        module = importlib.util.module_from_spec(spec)
        with (patch('ctypes.CDLL') as loader, patch('subprocess.run') as process,
              patch('threading.Thread.start') as thread):
            spec.loader.exec_module(module)
        loader.assert_not_called()
        process.assert_not_called()
        thread.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('cc'), 'Linux C compiler required')
class NativeAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='etc-native-sender-test-')
        cls.directory = Path(cls.temporary.name)
        cls.path = n.build_native_paced_sender(repo=cls.directory,
            source=Path(n.__file__).with_name('paced_sender.c'),
            output_root=cls.directory / 'builds')
        cls.sender = n.NativePacedSender(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def sockets(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.setblocking(False)
        right.setblocking(False)
        return left, right

    def test_datagrams_preserve_bytes_deadlines_and_raw_times(self):
        left, right = self.sockets()
        frames = [bytes([index]) * 60 for index in range(8)]
        with self.sender.prepare(frames, [index * 1_000_000 for index in range(8)], 8_000_000) as plan:
            report = plan.run(left.fileno())
            self.assertEqual(report['errors'], [])
            self.assertEqual(report['sent_count'], 8)
            self.assertEqual([right.recv(2000) for _ in frames], frames)
            start = report['scheduled_start_ns']
            self.assertTrue(all(actual >= start + index * 1_000_000
                                for index, actual in enumerate(report['sent_starts'])))
            self.assertTrue(all(before <= after for before, after
                                in zip(report['sent_starts'], report['sent_finishes'])))
            self.assertGreaterEqual(report['send_window_end_ns'], start + 8_000_000)

    def test_blocking_fd_rejected_without_changing_flags(self):
        left, right = self.sockets()
        left.setblocking(True)
        with self.sender.prepare([b'a' * 60], [0], 1_000_000) as plan:
            report = plan.run(left.fileno())
        self.assertEqual(report['native_result']['error_code'], 2)
        self.assertEqual(report['sent_count'], 0)
        self.assertTrue(left.getblocking())
        with self.assertRaises(BlockingIOError):
            right.recv(2000)

    def test_atomic_cancel_before_run_sends_nothing(self):
        left, right = self.sockets()
        with self.sender.prepare([b'a' * 60], [0], 1_000_000) as plan:
            plan.cancel()
            report = plan.run(left.fileno())
        self.assertEqual(report['native_result']['error_code'], 5)
        self.assertEqual(report['sent_count'], 0)
        with self.assertRaises(BlockingIOError):
            right.recv(2000)

    def test_closed_peer_send_error_retained_and_not_retried(self):
        left, right = self.sockets()
        right.close()
        with self.sender.prepare([b'a' * 60, b'b' * 60], [0, 1_000_000], 2_000_000) as plan:
            report = plan.run(left.fileno())
        self.assertEqual(report['sent_count'], 0)
        self.assertEqual(report['attempted_count'], 1)
        self.assertEqual(report['native_result']['error_code'], 7)
        self.assertGreater(report['native_result']['error_errno'], 0)
        self.assertEqual(len(report['attempted_starts']), 1)
        self.assertEqual(len(report['attempted_finishes']), 1)

    def test_cancel_during_native_loop(self):
        left, right = self.sockets()
        with self.sender.prepare([b'a' * 60] * 32,
            [index * 3_000_000 for index in range(32)], 96_000_000) as plan:
            timer = threading.Timer(.012, plan.cancel)
            timer.start()
            try:
                report = plan.run(left.fileno())
            finally:
                timer.join()
        self.assertEqual(report['native_result']['error_code'], 5)
        self.assertLess(report['sent_count'], 32)

    def test_c_loop_progresses_while_another_thread_holds_python_gil(self):
        left, right = self.sockets()
        frames = [bytes([index]) * 60 for index in range(32)]
        reports, failures = [], []
        with self.sender.prepare(frames, [index * 3_125_000 for index in range(32)], 100_000_000) as plan:
            entered = threading.Event()
            def worker():
                try:
                    entered.set()
                    reports.append(plan.run(left.fileno()))
                except Exception as error:
                    failures.append(error)
            thread = threading.Thread(target=worker)
            old = sys.getswitchinterval()
            thread.start()
            self.assertTrue(entered.wait(1))
            # Let the worker enter CDLL, then hold the GIL through a portion of
            # its native loop. Test progress, not deadline quality under CPU load.
            time.sleep(.010)
            try:
                sys.setswitchinterval(.2)
                busy_start = time.monotonic_ns()
                while time.monotonic_ns() - busy_start < 40_000_000:
                    pass
                busy_end = time.monotonic_ns()
            finally:
                sys.setswitchinterval(old)
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(reports[0]['errors'], [])
        self.assertEqual(reports[0]['sent_count'], 32)
        self.assertGreaterEqual(sum(busy_start <= value <= busy_end
                                    for value in reports[0]['sent_starts']), 2)

    def test_receipt_and_provenance_seal(self):
        provenance = self.sender.provenance
        for path, digest in provenance['input_sha256'].items():
            self.assertEqual(n.sha256_file(path), digest)
        provenance['policy']['spinning'] = True
        self.assertFalse(self.sender.provenance['policy']['spinning'])
        receipt = json.loads((self.path.parent / 'receipt.json').read_text())
        receipt['policy']['send_retries'] = 1
        with patch.object(n, '_read_json', return_value=receipt):
            with self.assertRaises(n.NativeSenderError):
                n.NativePacedSender(self.path)


if __name__ == '__main__':
    unittest.main()
