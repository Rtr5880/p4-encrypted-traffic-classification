"""Unprivileged tests: scheduler, exact-byte ledger and mocked AF_PACKET I/O."""
from collections import deque
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_pilot_transport as transport


def frame(value=0, tag=bytes.fromhex('020000000002020000000001')):
    # Test packet ID deliberately stays zero; matching must use all IP bytes.
    return tag + b'\x08\x00' + b'\x45' + bytes([value]) + bytes(18)


class LedgerTests(unittest.TestCase):
    def test_duplicate_ip_ids_and_repeated_identical_frames_use_occurrences(self):
        first, second = frame(1), frame(2)
        ledger = transport.OccurrenceLedger([first, second, first])
        self.assertEqual([ledger.match(key) for key in (first, second, first)], [0, 1, 2])
        self.assertFalse(ledger.missing())
        self.assertFalse(ledger.errors)
        self.assertIsNone(ledger.match(first))
        self.assertIn('Duplicate', ledger.errors[0])

    def test_modified_packet_and_reorder_fail(self):
        ledger = transport.OccurrenceLedger([b'a', b'b'])
        self.assertEqual(ledger.match(b'b'), 1)
        self.assertIsNone(ledger.match(b'c'))
        self.assertEqual(ledger.missing(), [0])
        self.assertEqual(len(ledger.errors), 2)

    def test_scheduler_never_skips_delayed_packet(self):
        self.assertIsNone(transport.due_index(1, [0, 100], 1000, 100999))
        self.assertEqual(transport.due_index(1, [0, 100], 1000, 101000), 1)
        self.assertEqual(transport.due_index(0, [0, 0], 1000, 999999), 0)
        self.assertIsNone(transport.due_index(2, [0, 100], 1000, 999999))


class MatcherTests(unittest.TestCase):
    def test_directions_tags_and_callback_isolation(self):
        expected = frame(1)
        calls = []
        def decode(raw):
            calls.append(raw)
            return raw[14:]
        matcher = transport.CaptureMatcher([expected], decode)
        matcher.observe('output', frame(1, b'X' * 12), 0, 0, 0)
        matcher.observe('input', expected, 0, 0, 0)
        matcher.observe('output', expected, 4, 0, 0)
        self.assertFalse(calls)
        matcher.observe('input', expected, 4, 1, 2)
        matcher.observe('output', expected, 0, 3, 4)
        report = matcher.report([])
        self.assertTrue(report['transport_passed'])
        self.assertEqual(report['expected_packets'], 1)
        self.assertEqual(report['input_observations'][0]['monotonic_ns'], 1)
        self.assertEqual(report['output_observations'][0]['wall_ns'], 4)
        self.assertEqual(len(calls), 1)

    def test_malformed_and_duplicate_tagged_reports_fail(self):
        expected = frame(1)
        def malformed(raw):
            raise ValueError('bad magic')
        matcher = transport.CaptureMatcher([expected], malformed)
        matcher.observe('output', expected, 0, 1, 2)
        self.assertIn('bad magic', matcher.report([])['errors'][0])
        matcher = transport.CaptureMatcher([expected], lambda raw: raw[14:])
        matcher.observe('input', expected, 4, 1, 2)
        matcher.observe('output', expected, 0, 1, 2)
        matcher.observe('output', expected, 0, 1, 2)
        self.assertFalse(matcher.report([])['transport_passed'])

    def test_nonreport_none_is_ignored_but_cannot_satisfy_missing(self):
        matcher = transport.CaptureMatcher([frame()], lambda raw: None)
        matcher.observe('output', frame(), 0, 1, 2)
        self.assertEqual(matcher.report([])['missing_output_indices'], [0])
        self.assertEqual(matcher.ignored['tagged_nonreport'], 1)


class PlanTests(unittest.TestCase):
    def test_good_plan_and_invalid_plans(self):
        transport.validate_plan([frame()] * 8, list(range(8)), 1, .2)
        invalid = [([], [], 1, .2), ([frame()] * 9, [0] * 9, 1, .2),
                   ([frame()], [1], 1, .2), ([frame(), frame()], [0, -1], 1, .2),
                   ([frame(), frame()], [0, 1000000], 1, .2),
                   ([frame()], [0], float('nan'), .2),
                   ([frame()], [0], 1, 3), ([b'bad'], [0], 1, .2),
                   ([frame(), frame(tag=b'X' * 12)], [0, 1], 1, .2)]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                transport.validate_plan(*args)


class LiveMockTests(unittest.TestCase):
    def test_timeout_reports_missing_and_closes_all_sockets(self):
        opened = []
        ticks = iter(range(0, 10000000, 100000))
        class FakeSocket:
            def __init__(self):
                self.closed = False
                opened.append(self)
            def bind(self, address):
                pass
            def setblocking(self, value):
                pass
            def settimeout(self, value):
                pass
            def send(self, raw):
                return len(raw)
            def close(self):
                self.closed = True
        class FakeSelector:
            def register(self, *args):
                pass
            def select(self, timeout):
                return []
            def close(self):
                pass
        with patch.object(transport.sys, 'platform', 'linux'), \
             patch.object(transport.socket, 'AF_PACKET', 17, create=True), \
             patch.object(transport.socket, 'socket', side_effect=lambda *args: FakeSocket()), \
             patch.object(transport.selectors, 'DefaultSelector', return_value=FakeSelector()), \
             patch.object(transport.time, 'monotonic_ns', side_effect=lambda: next(ticks)):
            result = transport.replay_frames([frame(1)], [0], 'in', 'out', .001,
                                             key_from_output=lambda raw: raw[14:], drain_seconds=0)
        self.assertFalse(result['transport_passed'])
        self.assertEqual(result['missing_input_indices'], [0])
        self.assertEqual(result['missing_output_indices'], [0])
        self.assertTrue(all(sock.closed for sock in opened))
        self.assertIn('deadline', result['errors'][0])

    def test_socket_binding_failure_still_closes_created_socket(self):
        class BadSocket:
            closed = False
            def bind(self, address):
                raise OSError('interface absent')
            def close(self):
                self.closed = True
        bad = BadSocket()
        with patch.object(transport.sys, 'platform', 'linux'), \
             patch.object(transport.socket, 'AF_PACKET', 17, create=True), \
             patch.object(transport.socket, 'socket', return_value=bad), \
             self.assertRaisesRegex(OSError, 'interface absent'):
            transport.replay_frames([frame()], [0], 'in', 'out', 1,
                                     key_from_output=lambda raw: raw[14:])
        self.assertTrue(bad.closed)

    def test_capture_sockets_bound_before_send_and_cleanup(self):
        opened, registered, sends = [], [], []
        ticks = iter(range(0, 1000000000, 100000))
        class FakeSocket:
            def __init__(self):
                self.queue = deque()
                self.closed = False
                self.bound = None
                opened.append(self)
            def bind(self, address):
                self.bound = address
            def setblocking(self, value):
                pass
            def settimeout(self, value):
                pass
            def send(self, raw):
                self_test.assertEqual(len(registered), 2)
                self_test.assertTrue(all(sock.bound for sock in opened))
                opened[0].queue.append((raw, ('in', 0, 4)))
                opened[1].queue.append((raw, ('out', 0, 0)))
                sends.append(raw)
                return len(raw)
            def recvfrom(self, size):
                if not self.queue:
                    raise BlockingIOError
                return self.queue.popleft()
            def close(self):
                self.closed = True
        class FakeSelector:
            closed = False
            def register(self, sock, events, role):
                registered.append(SimpleNamespace(fileobj=sock, data=role))
            def select(self, timeout):
                return [(key, 1) for key in registered if key.fileobj.queue]
            def close(self):
                self.closed = True
        self_test = self
        selector = FakeSelector()
        with patch.object(transport.sys, 'platform', 'linux'), \
             patch.object(transport.socket, 'AF_PACKET', 17, create=True), \
             patch.object(transport.socket, 'socket', side_effect=lambda *args: FakeSocket()), \
             patch.object(transport.selectors, 'DefaultSelector', return_value=selector), \
             patch.object(transport.time, 'monotonic_ns', side_effect=lambda: next(ticks)), \
             patch.object(transport.time, 'time_ns', return_value=123):
            result = transport.replay_frames([frame(1), frame(2)], [0, 10], 'in', 'out', 1,
                                             key_from_output=lambda raw: raw[14:], drain_seconds=0)
        self.assertTrue(result['transport_passed'], result)
        self.assertEqual(sends, [frame(1), frame(2)])
        self.assertEqual([row['packet_index'] for row in result['sent_logs']], [0, 1])
        self.assertEqual(result['input_observations'][0]['wall_ns'], 123)
        self.assertEqual(len(result['socket_read_delay_diagnostics']), 2)
        self.assertTrue(all(sock.closed for sock in opened))
        self.assertTrue(selector.closed)


if __name__ == '__main__':
    unittest.main()
