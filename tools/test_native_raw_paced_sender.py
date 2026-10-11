#!/usr/bin/env python3
"""Unprivileged RAW sender contracts, deterministic clock seams, socketpair smoke.

No packet socket, veth, BMv2, clock adjustment or service control is used.
Socketpair smoke establishes API execution, NOT external clock qualification or
benchmark pacing quality. Linux native tests skip explicitly elsewhere.
"""
import ctypes
import errno
import json
from pathlib import Path
import platform
import shutil
import socket
import tempfile
import time
import unittest

import native_raw_paced_sender as sender

SOURCE = Path(sender.__file__).with_name('raw_paced_sender.c')
IS_LINUX_NATIVE = platform.system() == 'Linux' and shutil.which('cc') is not None


class RawPolicyTests(unittest.TestCase):
    def test_clock_policy_is_explicit_and_not_old_backend(self):
        self.assertEqual(sender.POLICY['clock'], 'CLOCK_MONOTONIC_RAW')
        self.assertTrue(sender.POLICY['raw_deadline_recheck'])
        self.assertEqual(sender.POLICY['max_wake_sleep_ns'], 1_000_000)
        for key in ('frequency_correction', 'spinning', 'deadline_rebasing', 'filters'):
            self.assertIs(sender.POLICY[key], False)
        self.assertEqual(sender.POLICY['sleep_retries'], 0)
        self.assertEqual(sender.POLICY['send_retries'], 0)
        self.assertEqual(sender.ABI_VERSION, 2)
        self.assertNotEqual(sender.BACKEND_NAME, 'linux-native-paced-send-v1')


@unittest.skipUnless(IS_LINUX_NATIVE, 'Requires unprivileged Linux C compiler')
class RawNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='etc_raw_sender_test_')
        cls.root = Path(cls.temp.name)
        cls.library = sender.build_native_raw_paced_sender(
            repo=cls.root, output_root=cls.root / 'build', source=SOURCE)
        cls.native = sender.NativeRawPacedSender(cls.library)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_socketpair_raw_times_and_frames(self):
        frames = [bytes([index]) * 128 for index in range(4)]
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            tx.setblocking(False)
            rx.settimeout(1)
            before = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            with self.native.prepare(frames, [0, 50_000_000, 100_000_000, 150_000_000],
                                     200_000_000) as plan:
                report = plan.run(tx.fileno())
            after = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            self.assertEqual(report['errors'], [])
            self.assertEqual(report['clock_domain'], 'CLOCK_MONOTONIC_RAW')
            self.assertEqual(report['sent_count'], 4)
            start = report['scheduled_start_ns']
            self.assertLessEqual(before, start)
            self.assertLessEqual(report['send_window_end_ns'], after)
            self.assertGreaterEqual(report['send_window_end_ns'], start + 200_000_000)
            for observed, offset, finish in zip(report['sent_starts'],
                    [0, 50_000_000, 100_000_000, 150_000_000], report['sent_finishes']):
                self.assertGreaterEqual(observed, start + offset)
                self.assertGreaterEqual(finish, observed)
            self.assertEqual([rx.recv(1514) for _ in frames], frames)
        finally:
            tx.close()
            rx.close()

    def test_blocking_socket_rejected_without_send(self):
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            with self.native.prepare([b'x' * 128], [0], 1_000_000) as plan:
                report = plan.run(tx.fileno())
            self.assertEqual(report['native_result']['error_code'], 2)
            self.assertEqual(report['attempted_count'], 0)
        finally:
            tx.close()
            rx.close()

    def test_cancel_before_start_and_single_use(self):
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            tx.setblocking(False)
            with self.native.prepare([b'x' * 128], [0], 1_000_000) as plan:
                plan.cancel()
                report = plan.run(tx.fileno())
                self.assertEqual(report['native_result']['error_code'], 5)
                self.assertEqual(report['sent_count'], 0)
                with self.assertRaises(sender.NativeSenderError):
                    plan.run(tx.fileno())
        finally:
            tx.close()
            rx.close()

    def test_receipt_rejects_monotonic_policy_and_tampering(self):
        receipt_path = self.library.parent / 'receipt.json'
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual(receipt['policy']['clock'], 'CLOCK_MONOTONIC_RAW')
        bad_dir = self.root / 'bad_receipt'
        bad_dir.mkdir()
        bad_library = bad_dir / self.library.name
        shutil.copyfile(self.library, bad_library)
        receipt['policy']['clock'] = 'CLOCK_MONOTONIC'
        (bad_dir / 'receipt.json').write_text(json.dumps(receipt))
        with self.assertRaisesRegex(sender.NativeSenderError, 'policy/layout'):
            sender.NativeRawPacedSender(bad_library)


@unittest.skipUnless(IS_LINUX_NATIVE, 'Requires unprivileged Linux C compiler')
class DeterministicRawClockTests(unittest.TestCase):
    """Replace syscalls in a test-only library; production source stays unchanged."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='etc_raw_clock_seam_')
        cls.root = Path(cls.temp.name)
        source = cls.root / 'clock_seam.c'
        source.write_text('''#define clock_gettime test_clock_gettime
#define clock_nanosleep test_clock_nanosleep
#define send test_send
#include "''' + SOURCE.as_posix() + '''"
#undef clock_gettime
#undef clock_nanosleep
#undef send
static int mode = 0, sleeps = 0, sends = 0, bad_sleep = 0;
static int64_t fake_raw = 0;
static void *test_cancel = NULL;
void test_setup(int value) {
    mode = value; sleeps = sends = bad_sleep = 0;
    fake_raw = INT64_C(123000000000); test_cancel = NULL;
}
void test_set_cancel(void *flag) { test_cancel = flag; }
int test_sleep_count(void) { return sleeps; }
int test_send_count(void) { return sends; }
int test_bad_sleep(void) { return bad_sleep; }
int test_clock_gettime(clockid_t clock, struct timespec *out) {
    if (clock != CLOCK_MONOTONIC_RAW) { errno = EINVAL; return -1; }
    out->tv_sec = fake_raw / INT64_C(1000000000);
    out->tv_nsec = fake_raw % INT64_C(1000000000);
    return 0;
}
int test_clock_nanosleep(clockid_t clock, int flags,
        const struct timespec *req, struct timespec *remaining) {
    int64_t duration = req->tv_sec * INT64_C(1000000000) + req->tv_nsec;
    (void) remaining;
    ++sleeps;
    if (clock != CLOCK_MONOTONIC || flags != 0 || duration < 1 ||
            duration > ETC_MAX_WAKE_SLEEP_NS) { ++bad_sleep; return EINVAL; }
    if (mode == 2) return EINTR;
    if (mode == 3) etc_paced_sender_cancel_request(test_cancel);
    if (mode == 4) fake_raw -= INT64_C(100000);
    else if (mode == 5) fake_raw += INT64_C(50000000);
    else if (mode != 6) {
        int64_t advance = mode == 1 ? duration * 97 / 100 : duration;
        fake_raw += advance > 0 ? advance : 1;
        if (mode == 8) fake_raw += INT64_C(600000);
    }
    return 0;
}
ssize_t test_send(int fd, const void *bytes, size_t size, int flags) {
    (void) fd; (void) bytes;
    if (flags != (MSG_DONTWAIT | MSG_NOSIGNAL)) { errno = EINVAL; return -1; }
    ++sends;
    if (mode == 7 && sends == 2) { errno = EAGAIN; return -1; }
    return (ssize_t) size;
}
''')
        library = sender.build_native_raw_paced_sender(repo=cls.root, source=source,
                                                       output_root=cls.root / 'build')
        cls.native = sender.NativeRawPacedSender(library)
        cls.lib = cls.native._library
        cls.lib.test_setup.argtypes = [ctypes.c_int]
        cls.lib.test_setup.restype = None
        cls.lib.test_set_cancel.argtypes = [ctypes.c_void_p]
        cls.lib.test_set_cancel.restype = None
        for name in ('test_sleep_count', 'test_send_count', 'test_bad_sleep'):
            getattr(cls.lib, name).restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def execute(self, mode):
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            tx.setblocking(False)
            self.lib.test_setup(mode)
            with self.native.prepare([b'x' * 128] * 3,
                                     [0, 2_000_000, 4_000_000], 6_000_000) as plan:
                self.lib.test_set_cancel(plan._flag)
                report = plan.run(tx.fileno())
            self.assertEqual(self.lib.test_bad_sleep(), 0)
            return report
        finally:
            tx.close()
            rx.close()

    def test_immutable_exact_raw_deadlines(self):
        report = self.execute(0)
        self.assertEqual(report['errors'], [])
        start = report['scheduled_start_ns']
        self.assertEqual(report['sent_starts'], [start, start + 2_000_000, start + 4_000_000])
        self.assertEqual(report['send_window_end_ns'], start + 6_000_000)

    def test_early_wake_rechecks_raw_and_blocks_again(self):
        report = self.execute(1)
        self.assertEqual(report['errors'], [])
        start = report['scheduled_start_ns']
        self.assertEqual(report['sent_starts'], [start, start + 2_000_000, start + 4_000_000])
        self.assertGreater(self.lib.test_sleep_count(), 6)

    def test_interrupted_sleep_not_retried(self):
        report = self.execute(2)
        self.assertEqual(report['native_result']['error_code'], 4)
        self.assertEqual(report['native_result']['error_errno'], errno.EINTR)
        self.assertEqual(report['sent_count'], 1)
        self.assertEqual(self.lib.test_sleep_count(), 1)

    def test_late_wakes_are_retained_without_rebasing(self):
        report = self.execute(8)
        self.assertEqual(report['errors'], [])
        start = report['scheduled_start_ns']
        self.assertEqual(report['sent_starts'], [start, start + 2_600_000,
                                                 start + 4_200_000])
        self.assertEqual(report['sent_count'], 3)
        # The second lateness does not shift the third immutable deadline.
        self.assertLess(report['sent_starts'][2] - (start + 4_000_000),
                        report['sent_starts'][1] - (start + 2_000_000))

    def test_cancel_during_wake_sleep(self):
        report = self.execute(3)
        self.assertEqual(report['native_result']['error_code'], 5)
        self.assertEqual(report['sent_count'], 1)
        self.assertEqual(self.lib.test_sleep_count(), 1)

    def test_raw_regression_fails_closed(self):
        report = self.execute(4)
        self.assertEqual(report['native_result']['error_code'], 3)
        self.assertEqual(report['sent_count'], 1)

    def test_late_window_never_rebased_or_filtered(self):
        report = self.execute(5)
        self.assertEqual(report['native_result']['error_code'], 6)
        self.assertEqual(report['sent_count'], 1)
        self.assertEqual(report['scheduled_start_ns'], 123_000_000_000)

    def test_frozen_clock_wake_loop_is_bounded(self):
        report = self.execute(6)
        self.assertEqual(report['native_result']['error_code'], 9)
        self.assertEqual(self.lib.test_sleep_count(), 4096)
        self.assertEqual(report['sent_count'], 1)

    def test_failed_nonblocking_send_not_retried(self):
        report = self.execute(7)
        self.assertEqual(report['native_result']['error_code'], 7)
        self.assertEqual(report['native_result']['error_errno'], errno.EAGAIN)
        self.assertEqual(report['sent_count'], 1)
        self.assertEqual(report['attempted_count'], 2)
        self.assertEqual(self.lib.test_send_count(), 2)


if __name__ == '__main__':
    unittest.main()
