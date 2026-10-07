#!/usr/bin/env python3
"""Bounded native-clock pilot sender/capture using Linux AF_PACKET sockets.

No Scapy, subprocesses, files, switch management or interface configuration.
Only frames carrying this invocation's Ethernet address pair are retained.
Capture timestamps are userspace observations, NOT performance measurements.
"""
from collections import defaultdict, deque
import math
import selectors
import socket
import sys
import time


ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
MAX_PILOT_PACKETS = 8


def validate_plan(frames, relative_us, timeout_seconds, drain_seconds):
    """Reject bad plans before opening sockets or sending anything."""
    if not 1 <= len(frames) <= MAX_PILOT_PACKETS or len(frames) != len(relative_us):
        raise ValueError('Pilot needs 1..8 frames and one scheduled offset per frame')
    if any(type(frame) is not bytes or len(frame) < 34 or frame[12:14] != b'\x08\x00'
           or frame[14] >> 4 != 4 for frame in frames):
        raise ValueError('Expected complete ordinary Ethernet/IPv4 frame bytes')
    if len({frame[:12] for frame in frames}) != 1:
        raise ValueError('All pilot frames must share one invocation-specific Ethernet address pair')
    if any(type(offset) is not int or offset < 0 for offset in relative_us):
        raise ValueError('Scheduled offsets must be nonnegative integer microseconds')
    if relative_us[0] != 0 or relative_us != sorted(relative_us):
        raise ValueError('Scheduled offsets must start at zero and be nondecreasing')
    if not math.isfinite(timeout_seconds) or timeout_seconds <= relative_us[-1] / 1e6:
        raise ValueError('Total timeout must exceed the final scheduled packet time')
    if not math.isfinite(drain_seconds) or not 0 <= drain_seconds <= 2:
        raise ValueError('Drain interval must be finite and between zero and two seconds')


def due_index(next_index, relative_us, started_ns, now_ns):
    """Return the next due index; never skip or reorder a delayed packet."""
    if next_index < len(relative_us) and now_ns >= started_ns + relative_us[next_index] * 1000:
        return next_index
    return None


class OccurrenceLedger:
    """Assign exact-byte matches in occurrence order, not by IPv4 packet ID.

    Identical repeated packets are necessarily indistinguishable. Their count
    and position among nonidentical packets are checked, not their mutual order.
    """
    def __init__(self, keys):
        self.pending = defaultdict(deque)
        for index, key in enumerate(keys):
            self.pending[key].append(index)
        self.known = set(keys)
        self.observed = []
        self.errors = []

    def match(self, key):
        if key not in self.known:
            self.errors.append('Tagged frame has unexpected or modified packet bytes')
            return None
        if not self.pending[key]:
            self.errors.append('Duplicate tagged frame beyond the expected occurrence count')
            return None
        index = self.pending[key].popleft()
        if index != len(self.observed):
            self.errors.append(f'Packet reordering: observed index {index}, expected {len(self.observed)}')
        self.observed.append(index)
        return index

    def missing(self):
        return sorted(index for queue in self.pending.values() for index in queue)


class CaptureMatcher:
    """Keep only tagged observations and fail on corruption/duplicates/order."""
    def __init__(self, frames, key_from_output):
        self.tag = frames[0][:12]
        self.expected_packets = len(frames)
        self.key_from_output = key_from_output
        self.input = OccurrenceLedger(frames)
        self.output = OccurrenceLedger([frame[14:] for frame in frames])
        self.input_observations = []
        self.output_observations = []
        self.errors = []
        self.ignored = {'input_untagged': 0, 'output_untagged': 0,
                        'input_not_outgoing': 0, 'output_outgoing': 0,
                        'tagged_nonreport': 0}

    def observe(self, role, frame, packet_type, monotonic_ns, wall_ns):
        if frame[:12] != self.tag:
            self.ignored[role + '_untagged'] += 1
            return
        if role == 'input' and packet_type != PACKET_OUTGOING:
            self.ignored['input_not_outgoing'] += 1
            return
        if role == 'output' and packet_type == PACKET_OUTGOING:
            self.ignored['output_outgoing'] += 1
            return
        if role == 'input':
            ledger, observations, key = self.input, self.input_observations, frame
        elif role == 'output':
            ledger, observations = self.output, self.output_observations
            try:
                key = self.key_from_output(frame)
            except (ValueError, TypeError, KeyError, IndexError) as error:
                self.errors.append(f'Malformed tagged output report: {error}')
                return
            if key is None:
                self.ignored['tagged_nonreport'] += 1
                return
            if type(key) is not bytes:
                self.errors.append('Output packet-key decoder did not return bytes or None')
                return
        else:
            raise ValueError('Unknown capture role')
        index = ledger.match(key)
        if index is not None:
            observations.append({'packet_index': index, 'monotonic_ns': monotonic_ns,
                                 'wall_ns': wall_ns, 'frame_hex': frame.hex()})

    def report(self, sent_logs):
        errors = self.errors + self.input.errors + self.output.errors
        sends = {row['packet_index']: row['actual_send_monotonic_ns'] for row in sent_logs}
        socket_read_delays = [{'packet_index': row['packet_index'],
                              'output_socket_read_after_send_us':
                              (row['monotonic_ns'] - sends[row['packet_index']]) / 1000}
                             for row in self.output_observations if row['packet_index'] in sends]
        return {'transport_passed': not errors and not self.input.missing() and not self.output.missing(),
                'expected_packets': self.expected_packets,
                'sent_logs': sent_logs, 'input_observations': self.input_observations,
                'output_observations': self.output_observations, 'errors': errors,
                'missing_input_indices': self.input.missing(), 'missing_output_indices': self.output.missing(),
                'ignored': self.ignored,
                'socket_read_delay_diagnostics': socket_read_delays,
                'capture_time_meaning': 'Userspace socket-read timestamps; diagnostic only, not latency benchmark'}


def replay_frames(frames, relative_us, input_iface, output_iface, timeout_seconds, *,
                  key_from_output, drain_seconds=0.2):
    """Send an isolated first-eight prefix with original relative packet gaps.

    ``key_from_output`` validates native debug headers and returns unchanged raw
    IP bytes; None means unrelated/nonreport traffic. Both capture sockets are
    bound before sending. The timeout covers the WHOLE scheduled replay, not
    merely post-send waiting. This function requires raw-socket permission.
    """
    validate_plan(frames, relative_us, timeout_seconds, drain_seconds)
    if sys.platform != 'linux' or not hasattr(socket, 'AF_PACKET'):
        raise ValueError('Live native-clock pilot requires Linux AF_PACKET support')
    if not input_iface or not output_iface or input_iface == output_iface:
        raise ValueError('Use two distinct isolated host endpoint interfaces')
    matcher = CaptureMatcher(frames, key_from_output)
    sent_logs = []
    sockets = []
    poller = selectors.DefaultSelector()
    try:
        for role, interface in (('input', input_iface), ('output', output_iface)):
            receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sockets.append(receiver)
            receiver.bind((interface, 0))
            receiver.setblocking(False)
            poller.register(receiver, selectors.EVENT_READ, role)
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sockets.append(sender)
        sender.bind((input_iface, 0))
        sender.settimeout(2.0)
        # All capture endpoints are now bound and ready. No startup sleep.
        started_ns = time.monotonic_ns()
        deadline_ns = started_ns + int(timeout_seconds * 1e9)
        next_index = 0
        complete_ns = None
        while time.monotonic_ns() < deadline_ns:
            now_ns = time.monotonic_ns()
            index = due_index(next_index, relative_us, started_ns, now_ns)
            if index is not None:
                send_started_ns = time.monotonic_ns()
                length = sender.send(frames[index])
                send_finished_ns = time.monotonic_ns()
                if length != len(frames[index]):
                    raise OSError(f'Partial raw frame send: {length}/{len(frames[index])}')
                sent_logs.append({'packet_index': index, 'scheduled_offset_us': relative_us[index],
                                  'actual_send_monotonic_ns': send_started_ns,
                                  'send_finished_monotonic_ns': send_finished_ns,
                                  'scheduled_monotonic_ns': started_ns + relative_us[index] * 1000,
                                  'send_lateness_ns': send_started_ns - started_ns - relative_us[index] * 1000})
                next_index += 1
            if next_index == len(frames) and not matcher.input.missing() and not matcher.output.missing():
                complete_ns = complete_ns or time.monotonic_ns()
                if time.monotonic_ns() - complete_ns >= drain_seconds * 1e9:
                    break
            next_due_ns = (started_ns + relative_us[next_index] * 1000
                           if next_index < len(frames) else deadline_ns)
            wait_seconds = max(0.0, min(0.02, (next_due_ns - time.monotonic_ns()) / 1e9,
                                       (deadline_ns - time.monotonic_ns()) / 1e9))
            for key, _ in poller.select(wait_seconds):
                # Cap one drain so unrelated traffic cannot starve scheduling.
                for _ in range(64):
                    try:
                        frame, address = key.fileobj.recvfrom(65535)
                    except BlockingIOError:
                        break
                    observed_ns, observed_wall_ns = time.monotonic_ns(), time.time_ns()
                    matcher.observe(key.data, frame, address[2], observed_ns, observed_wall_ns)
        else:
            matcher.errors.append('Replay/capture deadline expired; inspect missing packet indices')
        report = matcher.report(sent_logs)
        report.update({'expected_packets': len(frames), 'input_iface': input_iface,
                       'output_iface': output_iface, 'started_monotonic_ns': started_ns,
                       'finished_monotonic_ns': time.monotonic_ns(), 'timeout_seconds': timeout_seconds,
                       'scheduling_policy': 'Original within-prefix offsets, monotonic clock, no gap scaling'})
        return report
    finally:
        poller.close()
        for opened in sockets:
            opened.close()
