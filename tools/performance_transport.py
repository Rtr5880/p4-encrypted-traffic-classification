#!/usr/bin/env python3
"""Bounded paced Linux AF_PACKET trials for normal, unmodified output frames.

The two kernel SO_TIMESTAMPING observations measure the host/veth forwarding
path, including queues and BMv2 scheduling. They do not isolate RF inference
time. Software timestamps use CLOCK_REALTIME, so a separate monotonic/realtime
audit can reject detected clock steps. No userspace read time is called latency.

This module never creates interfaces/processes/files or changes a switch.
Frames are prepared before the measured interval. Capture runs concurrently
with the paced sender, and PACKET_STATISTICS checks both capture sockets.

Timestamp semantics: https://docs.kernel.org/networking/timestamping.html
Linux 5.15 outgoing taps stamp skb clones in dev_queue_xmit_nit:
https://github.com/torvalds/linux/blob/v5.15/net/core/dev.c#L2124
The SO_TIMESTAMPNS recvmsg fallback intentionally avoided here is documented in:
https://github.com/torvalds/linux/blob/v5.15/net/socket.c#L775
"""

import math
import selectors
import socket
import struct
import sys
import threading
import time


ETH_P_ALL = 0x0003
PACKET_HOST = 0
PACKET_OTHERHOST = 3
PACKET_OUTGOING = 4
SOL_PACKET = 263
PACKET_STATISTICS = 6
SO_TIMESTAMPING_OLD = 37
SOF_TIMESTAMPING_RX_SOFTWARE = 1 << 3
SOF_TIMESTAMPING_SOFTWARE = 1 << 4
MAX_PACKETS = 100_000
MAX_RATE_PPS = 5_000
MAX_DURATION_SECONDS = 60
CLOCK_SAMPLE_SECONDS = 0.01
CLOCK_STEP_TOLERANCE_NS = 1_000_000
TIMESPEC64 = struct.Struct('=qq')
SCM_TIMESTAMPING64 = struct.Struct('=qqqqqq')
PACKET_STATS = struct.Struct('=II')


def validate_plan(frames, rate_pps, sequence_from_frame, drain_seconds):
    """Validate all bytes and IDs before opening sockets or sending traffic."""
    if not isinstance(frames, (list, tuple)) or not 1 <= len(frames) <= MAX_PACKETS:
        raise ValueError('Trial requires 1..100000 prebuilt frames')
    if (type(rate_pps) not in (int, float) or not math.isfinite(rate_pps)
            or not 1 <= rate_pps <= MAX_RATE_PPS):
        raise ValueError('Rate must be finite and in [1, 5000] packets/second')
    duration = len(frames) / rate_pps
    if not 0 < duration <= MAX_DURATION_SECONDS:
        raise ValueError('Scheduled trial duration must be in (0, 60] seconds')
    if (type(drain_seconds) not in (int, float) or not math.isfinite(drain_seconds)
            or not 0.05 <= drain_seconds <= 2):
        raise ValueError('Post-window capture drain must be in [0.05, 2] seconds')
    if not callable(sequence_from_frame):
        raise ValueError('A trial-specific sequence decoder is required')
    tag = None
    for index, frame in enumerate(frames):
        if (type(frame) is not bytes or not 60 <= len(frame) <= 1514
                or frame[12:14] != b'\x08\x00' or frame[14] >> 4 != 4):
            raise ValueError('Expected complete 60..1514 byte Ethernet/IPv4 frames')
        tag = frame[:12] if tag is None else tag
        if frame[:12] != tag:
            raise ValueError('All trial frames must share one invocation-specific MAC address pair')
        sequence = sequence_from_frame(frame)
        if type(sequence) is not int or sequence != index:
            raise ValueError('Frame decoder must return dense unique sequence IDs 0..N-1')
    return duration


def parse_timestamp_ns(ancillary, timestamp_option=SO_TIMESTAMPING_OLD):
    """Require an actual software timestamp, without recvmsg-time fallback.

    SO_TIMESTAMPNS is deliberately not enabled: Linux can fill a missing skb
    timestamp at recvmsg time for that option. SO_TIMESTAMPING alone reports
    only the software timestamp already carried by the captured skb.
    """
    found = [data for level, kind, data in ancillary
             if level == socket.SOL_SOCKET and kind == timestamp_option]
    if len(found) != 1 or len(found[0]) != SCM_TIMESTAMPING64.size:
        raise ValueError('Missing, duplicate or incorrectly sized SO_TIMESTAMPING cmsg')
    seconds, nanoseconds, _, _, _, _ = SCM_TIMESTAMPING64.unpack(found[0])
    if seconds <= 0 or not 0 <= nanoseconds < 1_000_000_000:
        raise ValueError('Invalid kernel timespec')
    return seconds * 1_000_000_000 + nanoseconds


def parse_packet_statistics(data):
    if len(data) != PACKET_STATS.size:
        raise ValueError('Unexpected PACKET_STATISTICS ABI')
    packets, drops = PACKET_STATS.unpack(data)
    return {'socket_packets': packets, 'socket_drops': drops,
            'meaning': 'All packets delivered to this capture socket; includes unrelated traffic'}


def summarize(values):
    """Linear-interpolated quantiles, with no dependency in the packet path."""
    ordered = sorted(values)
    if not ordered:
        return {'count': 0, 'minimum': None, 'median': None, 'p95': None,
                'p99': None, 'maximum': None, 'mean': None}

    def quantile(probability):
        position = (len(ordered) - 1) * probability
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)

    return {'count': len(ordered), 'minimum': ordered[0], 'median': quantile(.5),
            'p95': quantile(.95), 'p99': quantile(.99), 'maximum': ordered[-1],
            'mean': sum(ordered) / len(ordered)}


class ClockAudit:
    """Bracket CLOCK_REALTIME with MONOTONIC reads and reject detected changes.

    Sampling does not prove that no step-and-reversal happened between samples.
    Keep the maximum sample gap and bracket width to expose that limitation.
    """
    def __init__(self, tolerance_ns=CLOCK_STEP_TOLERANCE_NS):
        self.tolerance_ns = tolerance_ns
        self.samples = []
        self.detected_offset_changes = 0
        self.realtime_regressions = 0
        self.previous_wall_ns = None
        self.reference_interval = None

    def observe(self, monotonic_before_ns, realtime_ns, monotonic_after_ns):
        if monotonic_after_ns < monotonic_before_ns:
            raise ValueError('Monotonic clock regressed inside audit sample')
        interval = (realtime_ns - monotonic_after_ns,
                    realtime_ns - monotonic_before_ns)
        if self.reference_interval is None:
            self.reference_interval = interval
        else:
            low, high = self.reference_interval
            distance = max(0, interval[0] - high, low - interval[1])
            if distance >= self.tolerance_ns:
                self.detected_offset_changes += 1
        if self.previous_wall_ns is not None and realtime_ns < self.previous_wall_ns:
            self.realtime_regressions += 1
        self.previous_wall_ns = realtime_ns
        self.samples.append({'monotonic_before_ns': monotonic_before_ns,
                             'realtime_ns': realtime_ns,
                             'monotonic_after_ns': monotonic_after_ns,
                             'offset_low_ns': interval[0], 'offset_high_ns': interval[1]})

    def sample(self):
        before = time.monotonic_ns()
        wall = time.time_ns()
        self.observe(before, wall, time.monotonic_ns())

    def report(self):
        maximum_bracket = max((row['monotonic_after_ns'] - row['monotonic_before_ns']
                               for row in self.samples), default=None)
        maximum_gap = max((b['monotonic_before_ns'] - a['monotonic_before_ns']
                           for a, b in zip(self.samples, self.samples[1:])), default=None)
        reasons = []
        if len(self.samples) < 2:
            reasons.append('Too few realtime/monotonic clock audit samples')
        if self.detected_offset_changes:
            reasons.append('Detected CLOCK_REALTIME/MONOTONIC offset change at or above tolerance')
        if self.realtime_regressions:
            reasons.append('CLOCK_REALTIME regressed between audit samples')
        if maximum_bracket is not None and maximum_bracket >= self.tolerance_ns:
            reasons.append('A clock audit bracket was too wide to establish clock stability')
        return {'valid': not reasons, 'reasons': reasons, 'samples': self.samples,
                'detected_offset_changes': self.detected_offset_changes,
                'realtime_regressions': self.realtime_regressions,
                'offset_change_tolerance_ns': self.tolerance_ns,
                'requested_sample_interval_seconds': CLOCK_SAMPLE_SECONDS,
                'maximum_sample_gap_ns': maximum_gap,
                'maximum_bracket_width_ns': maximum_bracket,
                'limitation': 'Periodic sampling detects observed changes; it cannot exclude a clock step and reversal between samples'}


class CaptureLedger:
    """Bounded exact-frame matching by payload sequence; counts every category."""
    def __init__(self, frames, sequence_from_frame):
        self.frames = frames
        self.tag = frames[0][:12]
        self.sequence_from_frame = sequence_from_frame
        self.counts = {role: [0] * len(frames) for role in ('input', 'output')}
        self.timestamps = {role: [None] * len(frames) for role in ('input', 'output')}
        self.last_kernel_ns = {'input': None, 'output': None}
        self.last_sequence = {'input': None, 'output': None}
        self.last_output_read_monotonic_ns = None
        self.counters = {role: dict.fromkeys(
            ('read_packets', 'untagged', 'wrong_packet_type', 'tagged_decode_failures',
             'unexpected_sequences', 'corrupted_frames', 'duplicates',
             'missing_timestamps', 'kernel_timestamp_regressions', 'sequence_regressions',
             'truncated_frames', 'truncated_ancillary'), 0)
            for role in ('input', 'output')}
        self.examples = []

    def _example(self, role, reason, sequence=None):
        if len(self.examples) < 8:
            self.examples.append({'role': role, 'reason': reason, 'sequence': sequence})

    def observe(self, role, frame, packet_type, ancillary, flags,
                read_monotonic_ns, timestamp_option=SO_TIMESTAMPING_OLD):
        counts = self.counters[role]
        counts['read_packets'] += 1
        if frame[:12] != self.tag:
            counts['untagged'] += 1
            return
        expected_type = (packet_type == PACKET_OUTGOING if role == 'input'
                         else packet_type in (PACKET_HOST, PACKET_OTHERHOST))
        if not expected_type:
            counts['wrong_packet_type'] += 1
            return
        if flags & getattr(socket, 'MSG_TRUNC', 0x20):
            counts['truncated_frames'] += 1
            self._example(role, 'Truncated trial frame')
            return
        try:
            sequence = self.sequence_from_frame(frame)
        except (ValueError, TypeError, KeyError, IndexError, struct.error) as error:
            counts['tagged_decode_failures'] += 1
            self._example(role, f'Malformed tagged sequence: {error}')
            return
        if type(sequence) is not int:
            counts['tagged_decode_failures'] += 1
            self._example(role, 'Tagged frame has no valid sequence')
            return
        if not 0 <= sequence < len(self.frames):
            counts['unexpected_sequences'] += 1
            self._example(role, 'Unexpected trial sequence', sequence)
            return
        if frame != self.frames[sequence]:
            counts['corrupted_frames'] += 1
            self._example(role, 'Trial frame bytes changed', sequence)
            return
        self.counts[role][sequence] += 1
        if self.counts[role][sequence] > 1:
            counts['duplicates'] += 1
            self._example(role, 'Duplicate exact trial frame', sequence)
            return
        if self.last_sequence[role] is not None and sequence < self.last_sequence[role]:
            counts['sequence_regressions'] += 1
        self.last_sequence[role] = sequence
        if role == 'output':
            self.last_output_read_monotonic_ns = read_monotonic_ns
        if flags & getattr(socket, 'MSG_CTRUNC', 0x08):
            counts['truncated_ancillary'] += 1
            counts['missing_timestamps'] += 1
            self._example(role, 'Truncated timestamp ancillary data', sequence)
            return
        try:
            timestamp = parse_timestamp_ns(ancillary, timestamp_option)
        except ValueError as error:
            counts['missing_timestamps'] += 1
            self._example(role, str(error), sequence)
            return
        previous = self.last_kernel_ns[role]
        if previous is not None and timestamp < previous:
            counts['kernel_timestamp_regressions'] += 1
        self.last_kernel_ns[role] = timestamp
        self.timestamps[role][sequence] = timestamp


def build_report(ledger, sent_starts, sent_finishes, scheduled_start_ns,
                 send_window_end_ns, rate_pps, drain_seconds, capture_statistics,
                 clock_report, errors, timestamp_setup_errors, capture_buffers):
    """Pure report builder: keep packet evidence even when delay is invalid."""
    sent_count = len(sent_starts)
    sent_sequences = list(range(sent_count))
    unsent_sequences = list(range(sent_count, len(ledger.frames)))
    missing = {role: [seq for seq in sent_sequences if not ledger.counts[role][seq]]
               for role in ('input', 'output')}
    unexpected_unsent = {role: [seq for seq in unsent_sequences if ledger.counts[role][seq]]
                         for role in ('input', 'output')}
    delivery_reasons = list(errors)
    if sent_count != len(ledger.frames):
        delivery_reasons.append('Not all scheduled frames were sent successfully')
    for role in ('input', 'output'):
        stats = capture_statistics.get(role)
        if stats is None:
            delivery_reasons.append(f'{role} PACKET_STATISTICS unavailable; cannot establish capture completeness')
        elif stats['socket_drops']:
            delivery_reasons.append(f'{role} capture socket dropped packets; switch loss cannot be inferred')
        counters = ledger.counters[role]
        if any(counters[key] for key in ('tagged_decode_failures', 'unexpected_sequences',
                                         'corrupted_frames', 'duplicates', 'truncated_frames')):
            delivery_reasons.append(f'{role} captured malformed, changed, duplicated or unexpected trial frames')
        if unexpected_unsent[role]:
            delivery_reasons.append(f'{role} observed trial sequences that were not sent')
    if missing['input']:
        delivery_reasons.append('Input capture does not contain every successful raw-socket send')
    delivery_valid = not delivery_reasons
    latency_reasons = list(timestamp_setup_errors) + list(clock_report['reasons'])
    if not delivery_valid:
        latency_reasons.append('Capture/delivery validation failed')
    if missing['output']:
        latency_reasons.append('Output capture is incomplete; full-trial latency summary withheld')
    for role in ('input', 'output'):
        if ledger.counters[role]['missing_timestamps']:
            latency_reasons.append(f'{role} kernel timestamps missing or malformed')
        if ledger.counters[role]['kernel_timestamp_regressions']:
            latency_reasons.append(f'{role} kernel CLOCK_REALTIME timestamps regressed')
    paired = [None] * len(ledger.frames)
    negative_count = 0
    for sequence in sent_sequences:
        input_ns = ledger.timestamps['input'][sequence]
        output_ns = ledger.timestamps['output'][sequence]
        if input_ns is None or output_ns is None:
            continue
        value = output_ns - input_ns
        paired[sequence] = value
        negative_count += value < 0
    if negative_count:
        latency_reasons.append('Negative input-to-output kernel timestamp differences')
    if any(paired[seq] is None for seq in sent_sequences):
        latency_reasons.append('Not every sent frame has two usable kernel timestamps')
    latency_valid = not latency_reasons
    duration_seconds = len(ledger.frames) / rate_pps
    actual_window_seconds = ((send_window_end_ns - scheduled_start_ns) / 1e9
                             if scheduled_start_ns is not None else None)
    send_span_seconds = ((sent_starts[-1] - sent_starts[0]) / 1e9
                         if len(sent_starts) > 1 else None)
    kernel_output_pps = None
    output_span_seconds = None
    if latency_valid and sent_count > 1:
        output_timestamps = [ledger.timestamps['output'][seq] for seq in sent_sequences]
        output_span_seconds = (max(output_timestamps) - min(output_timestamps)) / 1e9
        if output_span_seconds > 0:
            kernel_output_pps = (sent_count - 1) / output_span_seconds
    capture_completion_seconds = (
        (ledger.last_output_read_monotonic_ns - scheduled_start_ns) / 1e9
        if scheduled_start_ns is not None and ledger.last_output_read_monotonic_ns is not None else None)
    lateness = [actual - (scheduled_start_ns + round(seq * 1e9 / rate_pps))
                for seq, actual in enumerate(sent_starts)]
    bytes_sent = sum(len(ledger.frames[seq]) for seq in sent_sequences)
    return {
        'pilot_passed': delivery_valid and not missing['output'] and latency_valid,
        'packet_delivery_valid': delivery_valid,
        'packet_delivery_reasons': delivery_reasons,
        'planned_packets': len(ledger.frames), 'sent_packets': sent_count,
        'captured_input_unique': sum(bool(value) for value in ledger.counts['input']),
        'captured_output_unique': sum(bool(value) for value in ledger.counts['output']),
        'missing_input_sequences': missing['input'], 'missing_output_sequences': missing['output'],
        'unsent_sequences': unsent_sequences, 'unexpected_unsent_sequences': unexpected_unsent,
        'observed_loss_fraction_after_drain': (len(missing['output']) / sent_count
                                              if delivery_valid and sent_count else None),
        'loss_meaning': 'Missing output sequences after the bounded drain; inferable only with complete input capture and zero capture socket drops',
        'capture_counters': ledger.counters, 'capture_error_examples': ledger.examples,
        'capture_statistics': capture_statistics, 'capture_receive_buffers_bytes': capture_buffers,
        'throughput': {
            'target_offered_pps': rate_pps, 'planned_window_seconds': duration_seconds,
            'actual_sender_window_seconds': actual_window_seconds,
            'actual_offered_pps_over_window': (sent_count / actual_window_seconds
                                               if actual_window_seconds and actual_window_seconds > 0 else None),
            'actual_offered_frame_bits_per_second_over_window': (bytes_sent * 8 / actual_window_seconds
                                                                 if actual_window_seconds and actual_window_seconds > 0 else None),
            'send_interpacket_span_seconds': send_span_seconds,
            'actual_sender_interpacket_pps': ((sent_count - 1) / send_span_seconds
                                              if send_span_seconds and send_span_seconds > 0 else None),
            'observed_output_kernel_interarrival_pps': kernel_output_pps,
            'observed_output_kernel_interarrival_span_seconds': output_span_seconds,
            'output_capture_completion_monotonic_seconds': capture_completion_seconds,
            'output_capture_completion_meaning': 'Userspace capture completion diagnostic; not a kernel arrival interval or inference latency',
            'rate_meaning': 'Sender window includes one full nominal packet interval after the last scheduled send. Interpacket rates use (N-1)/(last-first). Ethernet frame bits exclude preamble, FCS and interframe gap; these virtual links do not establish physical wire rate',
            'send_lateness_us': summarize([value / 1000 for value in lateness]),
        },
        'latency': {
            'valid': latency_valid, 'reasons': latency_reasons,
            'kernel_timestamp_source': 'Linux SO_TIMESTAMPING RX_SOFTWARE|SOFTWARE, skb software timestamps in CLOCK_REALTIME; SO_TIMESTAMPNS recvmsg fallback disabled',
            'timestamp_socket_option': SO_TIMESTAMPING_OLD,
            'timestamp_flags': SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE,
            'ancillary_payload_bytes': SCM_TIMESTAMPING64.size,
            'timestamp_semantics_reference': 'https://docs.kernel.org/networking/timestamping.html',
            'meaning': 'Input host endpoint PACKET_OUTGOING to output host endpoint PACKET_HOST/OTHERHOST; includes host/veth path, BMv2 queueing, processing and scheduling. Does not isolate inference time',
            'summary_us': summarize([value / 1000 for value in paired if value is not None]) if latency_valid else None,
            'negative_timestamp_differences': negative_count,
            'paired_kernel_timestamp_differences_ns': paired,
            'clock_audit': clock_report,
        },
        'per_packet': {'input_kernel_timestamp_ns': ledger.timestamps['input'],
                       'output_kernel_timestamp_ns': ledger.timestamps['output'],
                       'input_occurrences': ledger.counts['input'],
                       'output_occurrences': ledger.counts['output'],
                       'send_start_monotonic_ns': sent_starts,
                       'send_finish_monotonic_ns': sent_finishes},
        'scheduling': {'policy': 'One prebuilt frame per evenly spaced monotonic deadline; no capture-gated sends or busy spin',
                       'started_monotonic_ns': scheduled_start_ns,
                       'send_window_end_monotonic_ns': send_window_end_ns,
                       'drain_seconds': drain_seconds},
    }


def run_trial(frames, input_iface, output_iface, rate_pps, *, sequence_from_frame,
              drain_seconds=0.3):
    """Pace one bounded plan while capturing both isolated host endpoints.

    Requires a 64-bit Linux process with raw-socket permission. Fresh capture
    sockets start before the sender. Packet bytes/counters remain available
    when wall clock quality makes the delay measurement unusable.
    """
    duration_seconds = validate_plan(frames, rate_pps, sequence_from_frame, drain_seconds)
    if (sys.platform != 'linux' or not hasattr(socket, 'AF_PACKET')
            or struct.calcsize('@l') != 8 or struct.calcsize('@ll') != TIMESPEC64.size):
        raise ValueError('Live performance trials require the verified Linux 64-bit AF_PACKET/timespec ABI')
    if not input_iface or not output_iface or input_iface == output_iface:
        raise ValueError('Use two distinct isolated host endpoint interfaces')
    ledger = CaptureLedger(frames, sequence_from_frame)
    audit = ClockAudit()
    errors, timestamp_setup_errors, capture_buffers = [], [], {}
    capture_statistics, sent_starts, sent_finishes = {}, [], []
    opened, captures = [], {}
    selector = selectors.DefaultSelector()
    stop_capture = threading.Event()
    capture_failed = threading.Event()
    capture_ready = threading.Event()
    worker = None
    scheduled_start_ns = None
    send_window_end_ns = None
    timestamp_option = getattr(socket, 'SO_TIMESTAMPING', SO_TIMESTAMPING_OLD)

    def capture_worker():
        try:
            audit.sample()
            capture_ready.set()
            next_audit_ns = time.monotonic_ns() + round(CLOCK_SAMPLE_SECONDS * 1e9)
            while not stop_capture.is_set():
                for key, _ in selector.select(CLOCK_SAMPLE_SECONDS):
                    # Bounded drain per endpoint prevents noisy input starving
                    # output capture and the independent clock audit.
                    for _ in range(128):
                        if stop_capture.is_set():
                            break
                        try:
                            frame, ancillary, flags, address = key.fileobj.recvmsg(
                                65535, socket.CMSG_SPACE(SCM_TIMESTAMPING64.size))
                        except BlockingIOError:
                            break
                        ledger.observe(key.data, frame, address[2], ancillary, flags,
                                       time.monotonic_ns(), timestamp_option)
                        if time.monotonic_ns() >= next_audit_ns:
                            audit.sample()
                            next_audit_ns = time.monotonic_ns() + round(CLOCK_SAMPLE_SECONDS * 1e9)
                if time.monotonic_ns() >= next_audit_ns:
                    audit.sample()
                    next_audit_ns = time.monotonic_ns() + round(CLOCK_SAMPLE_SECONDS * 1e9)
            audit.sample()
        except Exception as error:
            errors.append(f'Capture worker failed: {type(error).__name__}: {error}')
            capture_failed.set()
            capture_ready.set()

    try:
        for role, interface in (('input', input_iface), ('output', output_iface)):
            receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            opened.append(receiver)
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            capture_buffers[role] = receiver.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            try:
                receiver.setsockopt(socket.SOL_SOCKET, timestamp_option,
                                    SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE)
            except OSError as error:
                timestamp_setup_errors.append(f'{role} SO_TIMESTAMPING setup failed: {error}')
            receiver.bind((interface, 0))
            receiver.setblocking(False)
            selector.register(receiver, selectors.EVENT_READ, role)
            captures[role] = receiver
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        opened.append(sender)
        sender.bind((input_iface, 0))
        sender.settimeout(1.0)
        worker = threading.Thread(target=capture_worker, name='performance-capture', daemon=True)
        worker.start()
        if not capture_ready.wait(1.0):
            errors.append('Capture worker did not become ready within one second')
        if not errors:
            scheduled_start_ns = time.monotonic_ns()
            scheduled_end_ns = scheduled_start_ns + round(duration_seconds * 1e9)
            for sequence, frame in enumerate(frames):
                if capture_failed.is_set():
                    break
                due_ns = scheduled_start_ns + round(sequence * 1e9 / rate_pps)
                remaining_seconds = (due_ns - time.monotonic_ns()) / 1e9
                if remaining_seconds > 0:
                    time.sleep(remaining_seconds)
                if time.monotonic_ns() >= scheduled_end_ns:
                    errors.append('Sender fell behind the bounded trial window; remaining frames were not sent')
                    break
                before_ns = time.monotonic_ns()
                try:
                    sent_length = sender.send(frame)
                    after_ns = time.monotonic_ns()
                    if sent_length != len(frame):
                        raise OSError(f'Partial raw frame send: {sent_length}/{len(frame)}')
                except OSError as error:
                    errors.append(f'Send failed at sequence {sequence}: {error}')
                    break
                sent_starts.append(before_ns)
                sent_finishes.append(after_ns)
            if len(sent_starts) == len(frames):
                remaining_seconds = (scheduled_end_ns - time.monotonic_ns()) / 1e9
                if remaining_seconds > 0:
                    time.sleep(remaining_seconds)
            send_window_end_ns = time.monotonic_ns()
            if not capture_failed.is_set():
                stop_capture.wait(drain_seconds)
        else:
            send_window_end_ns = time.monotonic_ns()
        stop_capture.set()
        worker.join(1.0)
        if worker.is_alive():
            errors.append('Capture worker failed to stop within one second')
            # Closing the capture sockets forces any failed selector out of IO.
            for receiver in captures.values():
                receiver.close()
            worker.join(1.0)
            if worker.is_alive():
                raise RuntimeError('Capture worker still active after forced socket closure')
        for role, receiver in captures.items():
            try:
                # Fresh sockets, read once: this kernel option resets counters.
                capture_statistics[role] = parse_packet_statistics(receiver.getsockopt(
                    SOL_PACKET, PACKET_STATISTICS, PACKET_STATS.size))
            except (OSError, ValueError) as error:
                capture_statistics[role] = None
                errors.append(f'{role} capture statistics failed: {error}')
        report = build_report(ledger, sent_starts, sent_finishes, scheduled_start_ns,
                              send_window_end_ns, rate_pps, drain_seconds, capture_statistics,
                              audit.report(), errors, timestamp_setup_errors, capture_buffers)
        report.update({'input_iface': input_iface, 'output_iface': output_iface,
                       'finished_monotonic_ns': time.monotonic_ns()})
        return report
    finally:
        stop_capture.set()
        if worker is not None and worker.is_alive():
            worker.join(0.5)
        for handle in opened:
            handle.close()
        selector.close()
        if worker is not None and worker.is_alive():
            worker.join(0.5)
