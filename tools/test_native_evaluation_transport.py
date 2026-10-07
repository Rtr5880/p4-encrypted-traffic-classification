"""Batch transport tests use fake clocks/sockets; no privileges or interfaces."""
from collections import deque
import copy
import heapq
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_evaluation_transport as transport


def make_plan(case_id='first', number=1, start=0, offsets=None):
    tag = bytes([2, 0, 0, 0, 0, number, 2, 0, 0, 0, 0, number])
    # Same IPv4 identification in every packet; full bytes, not IDs, identify occurrences.
    frames = [tag + b'\x08\x00' + b'\x45' + bytes([position]) + bytes(18)
              for position in range(8)]
    return {'case_id': case_id, 'frames': frames,
            'relative_us': list(range(0, 8000, 1000)) if offsets is None else offsets,
            'start_offset_us': start}


def decode_output(frame):
    return frame[14:] if frame[12:14] == b'\x88\xb6' else None


class FakeWorld:
    def __init__(self, total, *, omit_input=None, omit_output=None, duplicate=False,
                 reverse_cases=False, reverse_packets=False, mutate=False,
                 bad_ethertype=False, noise=False, fail_send=None, interrupt=False,
                 bind_failure=False, read_failure=False):
        self.total = total
        self.now_ns = 1000000000
        self.opened, self.keys, self.sent, self.pending = [], [], [], []
        self.closed = False
        self.omit_input, self.omit_output = omit_input, omit_output
        self.duplicate, self.reverse_cases, self.reverse_packets = duplicate, reverse_cases, reverse_packets
        self.mutate, self.bad_ethertype, self.noise = mutate, bad_ethertype, noise
        self.fail_send, self.interrupt = fail_send, interrupt
        self.bind_failure, self.read_failure = bind_failure, read_failure

    def monotonic_ns(self):
        self.now_ns += 1000
        return self.now_ns

    def socket(self, *args):
        world = self
        class FakeSocket:
            def __init__(self):
                self.queue, self.closed, self.bound = deque(), False, None
                world.opened.append(self)
            def bind(self, address):
                if world.bind_failure:
                    raise OSError('fake interface absent')
                self.bound = address
            def setblocking(self, value):
                pass
            def settimeout(self, value):
                pass
            def send(self, frame):
                if world.interrupt:
                    raise KeyboardInterrupt
                if world.fail_send == len(world.sent):
                    raise OSError('fake send failure')
                if len(world.keys) != 2 or not all(item.bound for item in world.opened):
                    raise AssertionError('Both capture endpoints must be ready before sending')
                position = len(world.sent)
                world.sent.append(frame)
                if position != world.omit_input:
                    world.opened[0].queue.append((frame, ('input', 0, 4)))
                output = frame[:12] + (b'\x08\x00' if world.bad_ethertype else b'\x88\xb6') + frame[14:]
                if world.mutate:
                    output = output[:-1] + bytes([output[-1] ^ 1])
                if position != world.omit_output:
                    world.pending.append((output, ('output', 0, 0)))
                if world.noise:
                    world.opened[0].queue.append((b'N' * 34, ('input', 0, 4)))
                    world.opened[1].queue.append((b'N' * 34, ('output', 0, 0)))
                if len(world.sent) == world.total:
                    outputs = world.pending
                    if world.reverse_cases:
                        groups = {}
                        for item in outputs:
                            groups.setdefault(item[0][:12], []).append(item)
                        outputs = [item for tag in reversed(groups) for item in groups[tag]]
                    if world.reverse_packets:
                        outputs = list(reversed(outputs))
                    if world.duplicate:
                        outputs = outputs + [outputs[0]]
                    world.opened[1].queue.extend(outputs)
                return len(frame)
            def recvfrom(self, length):
                if world.read_failure:
                    raise OSError('fake capture failure')
                if not self.queue:
                    raise BlockingIOError
                return self.queue.popleft()
            def close(self):
                self.closed = True
        return FakeSocket()

    def register(self, sock, events, role):
        self.keys.append(SimpleNamespace(fileobj=sock, data=role))

    def select(self, timeout):
        self.now_ns += max(0, int(timeout * 1e9))
        return [(key, 1) for key in self.keys if key.fileobj.queue]

    def close(self):
        self.closed = True

    def run(self, plans, timeout=1, drain=0):
        with patch.object(transport.sys, 'platform', 'linux'), \
             patch.object(transport.socket, 'AF_PACKET', 17, create=True), \
             patch.object(transport.socket, 'socket', side_effect=self.socket), \
             patch.object(transport.selectors, 'DefaultSelector', return_value=self), \
             patch.object(transport.time, 'monotonic_ns', side_effect=self.monotonic_ns), \
             patch.object(transport.time, 'time_ns', return_value=123456):
            return transport.replay_batch(plans, 'input', 'output', timeout,
                                          key_from_output=decode_output, drain_seconds=drain)


class ValidationTests(unittest.TestCase):
    def test_heap_interleaves_without_changing_within_case_offsets(self):
        plans = [make_plan(), make_plan('second', 2, start=500)]
        schedule = transport.build_schedule(plans)
        popped = [heapq.heappop(schedule) for _ in range(16)]
        self.assertEqual(popped[:4], [(0, 0, 0), (500, 1, 0), (1000, 0, 1), (1500, 1, 1)])
        self.assertEqual([entry[2] for entry in popped if entry[1] == 0], list(range(8)))
        self.assertEqual(transport.validate_batch(plans, 1, .3), 7500)

    def test_validate_before_socket_creation(self):
        bad = make_plan()
        bad['relative_us'][-1] = -1
        with patch.object(transport.socket, 'socket') as factory, self.assertRaises(ValueError):
            transport.replay_batch([bad], 'input', 'output', 1, key_from_output=decode_output)
        factory.assert_not_called()

    def test_duplicate_ids_tags_invalid_counts_and_timeout(self):
        base = make_plan()
        invalid = [([], 1, .3), ([base] * 33, 1, .3), ([base, copy.deepcopy(base)], 1, .3),
                   ([base, dict(copy.deepcopy(base), case_id='different')], 1, .3),
                   ([base], 601, .3), ([base], float('nan'), .3), ([base], .007, .3)]
        for plans, timeout, drain in invalid:
            with self.subTest(timeout=timeout, count=len(plans)), self.assertRaises(ValueError):
                transport.validate_batch(plans, timeout, drain)
        for field, value in [('case_id', ''), ('frames', base['frames'][:7]),
                             ('start_offset_us', -1), ('relative_us', [1] * 8)]:
            bad = dict(base, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                transport.validate_batch([bad], 1, .3)


class BatchTests(unittest.TestCase):
    def test_interleaved_sends_and_reverse_intercase_output_order_pass(self):
        plans = [make_plan(), make_plan('second', 2, start=500)]
        world = FakeWorld(16, reverse_cases=True, noise=True)
        report = world.run(plans)
        self.assertTrue(report['transport_passed'], report)
        self.assertEqual([raw[:12] for raw in world.sent[:4]],
                         [plans[0]['frames'][0][:12], plans[1]['frames'][0][:12]] * 2)
        for case in report['cases'].values():
            self.assertTrue(case['transport_passed'])
            self.assertEqual([row['packet_index'] for row in case['output_observations']], list(range(8)))
            self.assertEqual(len(case['socket_read_delay_diagnostics']), 8)
        self.assertEqual(report['cases']['second']['sent_logs'][0]['batch_scheduled_offset_us'], 500)
        self.assertEqual(report['cases']['second']['sent_logs'][0]['scheduled_offset_us'], 0)
        self.assertEqual(report['ignored'], {'input_untagged': 16, 'output_untagged': 16})
        self.assertTrue(world.closed and all(handle.closed for handle in world.opened))

    def test_identical_repeated_ip_packets_use_occurrences(self):
        plan = make_plan()
        plan['frames'] = [plan['frames'][0]] * 8
        report = FakeWorld(8).run([plan])
        self.assertTrue(report['transport_passed'])
        self.assertEqual(len(report['cases']['first']['output_observations']), 8)

    def test_long_prefix_gaps_are_not_scaled_or_shortened(self):
        plan = make_plan(offsets=[0, 1, 2, 3, 4, 5, 6, 135000000])
        world = FakeWorld(8)
        report = world.run([plan], timeout=140)
        self.assertTrue(report['transport_passed'])
        logs = report['cases']['first']['sent_logs']
        self.assertEqual(logs[-1]['batch_scheduled_offset_us'], 135000000)
        self.assertGreaterEqual(logs[-1]['actual_batch_offset_us'], 135000000)
        self.assertLess(logs[-1]['actual_batch_offset_us'], 135001000)

    def test_duplicates_reorder_corruption_and_known_tag_wrong_ethertype_fail(self):
        for option in ('duplicate', 'reverse_packets', 'mutate', 'bad_ethertype'):
            with self.subTest(option=option):
                report = FakeWorld(8, **{option: True}).run([make_plan()])
                self.assertFalse(report['transport_passed'])
                self.assertTrue(report['cases']['first']['errors'])
        bad = FakeWorld(8, bad_ethertype=True).run([make_plan()])
        self.assertEqual(bad['cases']['first']['ignored']['tagged_nonreport'], 0)

    def test_missing_input_and_output_are_reported_separately_for_every_case(self):
        plans = [make_plan(), make_plan('second', 2, start=500)]
        for role in ('input', 'output'):
            with self.subTest(role=role):
                report = FakeWorld(16, **{'omit_' + role: 0}).run(plans)
                self.assertFalse(report['transport_passed'])
                self.assertEqual(set(report['cases']), {'first', 'second'})
                self.assertEqual(report['cases']['first']['missing_' + role + '_indices'], [0])
                self.assertEqual(report['cases']['first']['missing_' + ('output' if role == 'input' else 'input') + '_indices'], [])
                self.assertTrue(report['cases']['second']['transport_passed'])
                self.assertIn('deadline', report['global_errors'][0])

    def test_fatal_send_returns_all_cases_promptly_with_long_future_deadline(self):
        plans = [make_plan(offsets=[0, 1, 2, 3, 4, 5, 6, 135000000]),
                 make_plan('second', 2, start=1000)]
        world = FakeWorld(16, fail_send=0)
        report = world.run(plans, timeout=140, drain=.3)
        self.assertFalse(report['transport_passed'])
        self.assertEqual(set(report['cases']), {'first', 'second'})
        self.assertEqual(report['scheduling']['sent_packets'], 0)
        self.assertLess(report['scheduling']['finished_monotonic_ns'] - report['scheduling']['started_monotonic_ns'], 400000000)
        self.assertIn('Send failed', report['global_errors'][0])
        self.assertTrue(all(handle.closed for handle in world.opened))

    def test_capture_failure_returns_partial_diagnostics_and_closes(self):
        world = FakeWorld(8, read_failure=True)
        report = world.run([make_plan()])
        self.assertFalse(report['transport_passed'])
        self.assertIn('Capture socket failed', report['global_errors'][0])
        self.assertEqual(report['scheduling']['sent_packets'], 1)
        self.assertTrue(all(handle.closed for handle in world.opened))

    def test_setup_failure_and_ctrl_c_raise_but_always_close(self):
        for option, error in [('bind_failure', OSError), ('interrupt', KeyboardInterrupt)]:
            with self.subTest(option=option):
                world = FakeWorld(8, **{option: True})
                with self.assertRaises(error):
                    world.run([make_plan()])
                self.assertTrue(world.closed and all(handle.closed for handle in world.opened))


if __name__ == '__main__':
    unittest.main()
