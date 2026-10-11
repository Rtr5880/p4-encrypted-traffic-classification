#!/usr/bin/env python3
"""Bounded, paced AF_PACKET benchmark phases; importing never sends traffic.

Frames, capture storage and monotonic deadline offsets are prepared before the
resource sampling callbacks. The capture sockets remain open for the phase and
its drain. A separate 5 ms clock sampler is independent of receiver scheduling.
Only existing skb SO_TIMESTAMPING software observations establish path delays;
userspace recvmsg times are capture-completion diagnostics, never latency.

This module opens only the two explicitly named interfaces. It does not create
interfaces, start switches, write artifacts or alter the pilot transport module.
"""

from dataclasses import asdict, dataclass
import math
import selectors
import socket
import struct
import sys
import threading
import time

import performance_transport as pilot


ETH_P_ALL = pilot.ETH_P_ALL
PACKET_HOST = pilot.PACKET_HOST
PACKET_OTHERHOST = pilot.PACKET_OTHERHOST
PACKET_OUTGOING = pilot.PACKET_OUTGOING
SOL_PACKET = pilot.SOL_PACKET
PACKET_STATISTICS = pilot.PACKET_STATISTICS
SO_TIMESTAMPING_OLD = 37
TIMESTAMP_FLAGS = 24
SCM_TIMESTAMPING64 = pilot.SCM_TIMESTAMPING64
PACKET_STATS = pilot.PACKET_STATS
MAX_PACKETS = 500_000
MAX_RATE_PPS = 10_000
MAX_DURATION_SECONDS = 60
CLOCK_SAMPLE_SECONDS = .005
MAX_CLOCK_GAP_NS = 25_000_000
MAX_CLOCK_BRACKET_NS = 100_000
CLOCK_STEP_TOLERANCE_NS = 1_000_000
parse_timestamp_ns = pilot.parse_timestamp_ns
parse_packet_statistics = pilot.parse_packet_statistics
summarize = pilot.summarize
CaptureLedger = pilot.CaptureLedger


@dataclass(frozen=True)
class PacingQuality:
    offered_rate_relative_tolerance: float = .02
    p99_send_lateness_floor_ns: int = 1_000_000
    maximum_send_lateness_floor_ns: int = 5_000_000
    short_gap_interval_fraction: float = .25
    maximum_short_input_gap_fraction: float = .01


class PhaseCallbackError(RuntimeError):
    """Resource callback failure with evidence retained after socket cleanup."""
    def __init__(self, callback_name, cause, partial_report):
        super().__init__(f'{callback_name} failed: {type(cause).__name__}: {cause}')
        self.callback_name = callback_name
        self.cause = cause
        self.partial_report = partial_report


def validate_plan(frames, rate_pps, sequence_from_frame, drain_seconds):
    """Validate prebuilt bytes and dense IDs before any socket is opened."""
    if not isinstance(frames, (list, tuple)) or not 1 <= len(frames) <= MAX_PACKETS:
        raise ValueError('Phase requires 1..500000 prebuilt frames')
    if (type(rate_pps) not in (int, float) or not math.isfinite(rate_pps)
            or not 1 <= rate_pps <= MAX_RATE_PPS):
        raise ValueError('Rate must be finite and in [1, 10000] packets/second')
    duration = len(frames) / rate_pps
    if not 0 < duration <= MAX_DURATION_SECONDS:
        raise ValueError('Scheduled phase duration must be in (0, 60] seconds')
    if (type(drain_seconds) not in (int, float) or not math.isfinite(drain_seconds)
            or not .05 <= drain_seconds <= 2):
        raise ValueError('Post-window capture drain must be in [0.05, 2] seconds')
    if not callable(sequence_from_frame):
        raise ValueError('A phase-specific sequence decoder is required')
    tag = frames[0][:12] if type(frames[0]) is bytes else None
    for sequence, frame in enumerate(frames):
        if (type(frame) is not bytes or not 60 <= len(frame) <= 1514
                or frame[12:14] != b'\x08\x00' or frame[14] >> 4 != 4):
            raise ValueError('Expected complete 60..1514 byte Ethernet/IPv4 frames')
        if frame[:12] != tag:
            raise ValueError('Every phase frame must share its invocation-specific MAC pair')
        decoded = sequence_from_frame(frame)
        if type(decoded) is not int or decoded != sequence:
            raise ValueError('Frame decoder must return dense unique sequence IDs 0..N-1')
    return duration


def _quality(gates):
    quality = PacingQuality() if gates is None else (
        PacingQuality(**gates) if isinstance(gates, dict) else gates)
    if not isinstance(quality, PacingQuality):
        raise ValueError('gates must be PacingQuality or its field dictionary')
    for name, value in asdict(quality).items():
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError(f'Invalid pacing threshold: {name}')
    if (quality.offered_rate_relative_tolerance > 1
            or quality.maximum_short_input_gap_fraction > 1
            or not 0 < quality.short_gap_interval_fraction < 1):
        raise ValueError('Pacing fractions must be in their bounded probability range')
    return quality


class ClockAudit(pilot.ClockAudit):
    """Audit the measured window with strict gap and bracket bounds."""
    def __init__(self, *args, bracket_reader=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bracket_reader = bracket_reader

    def sample(self):
        if self.bracket_reader is None:
            return super().sample()
        before, realtime, after = self.bracket_reader()
        self.observe(before, realtime, after)

    def report(self, measured_start_ns=None, measured_end_ns=None):
        all_samples = list(self.samples)
        selected = all_samples
        coverage_reasons = []
        if measured_start_ns is not None and measured_end_ns is not None:
            before = [i for i, row in enumerate(all_samples)
                      if row['monotonic_after_ns'] <= measured_start_ns]
            after = [i for i, row in enumerate(all_samples)
                     if row['monotonic_before_ns'] >= measured_end_ns]
            if not before or not after:
                coverage_reasons.append('Clock audit does not bracket the complete measured window')
            else:
                selected = all_samples[before[-1]:after[0] + 1]
        # Base clock checks also apply to the complete pre-window audit history.
        result = super().report()
        maximum_gap = max((b['monotonic_before_ns'] - a['monotonic_before_ns']
                           for a, b in zip(selected, selected[1:])), default=None)
        maximum_bracket = max((row['monotonic_after_ns'] - row['monotonic_before_ns']
                               for row in all_samples), default=None)
        measured_maximum_bracket = max((row['monotonic_after_ns'] - row['monotonic_before_ns']
                                        for row in selected), default=None)
        # Twice the midpoint preserves nanosecond comparisons without losing
        # integer precision at epoch-sized realtime/monotonic offsets.
        offset_midpoints = [row['offset_low_ns'] + row['offset_high_ns']
                            for row in all_samples]
        offset_displacement = ((max(offset_midpoints) - min(offset_midpoints)) / 2
                               if offset_midpoints else None)
        reasons = list(result['reasons']) + coverage_reasons
        if offset_displacement is not None and offset_displacement >= CLOCK_STEP_TOLERANCE_NS:
            reasons.append('Observed CLOCK_REALTIME/MONOTONIC offset displacement reached 1 ms')
        if maximum_gap is not None and maximum_gap > MAX_CLOCK_GAP_NS:
            reasons.append('Measured-window clock audit sample gap exceeded 25 ms')
        if maximum_bracket is not None and maximum_bracket > MAX_CLOCK_BRACKET_NS:
            reasons.append('Clock audit bracket exceeded 100 us')
        if any(b['monotonic_before_ns'] < a['monotonic_before_ns']
               for a, b in zip(all_samples, all_samples[1:])):
            reasons.append('MONOTONIC regressed between clock audit samples')
        result.update({
            'valid': not reasons, 'reasons': reasons,
            'requested_sample_interval_seconds': CLOCK_SAMPLE_SECONDS,
            'maximum_sample_gap_ns': maximum_gap,
            'maximum_bracket_width_ns': maximum_bracket,
            'measured_window_maximum_bracket_width_ns': measured_maximum_bracket,
            'all_samples_maximum_gap_ns': result['maximum_sample_gap_ns'],
            'maximum_allowed_sample_gap_ns': MAX_CLOCK_GAP_NS,
            'maximum_allowed_bracket_width_ns': MAX_CLOCK_BRACKET_NS,
            'maximum_observed_offset_displacement_ns': offset_displacement,
            'measured_start_monotonic_ns': measured_start_ns,
            'measured_end_monotonic_ns': measured_end_ns,
            'measured_window_samples': selected,
            'sample_gap_scope': 'Samples immediately bracketing the measured sender window; drain is excluded',
            'clock_bracket_backend': 'linux-native-three-read-v1' if self.bracket_reader is not None else 'python-three-read-v1',
        })
        return result


def _gaps(values):
    return [b - a for a, b in zip(values, values[1:])]


def _interpacket_rate(values):
    if len(values) < 2:
        return None, None
    span = (max(values) - min(values)) / 1e9
    return ((len(values) - 1) / span if span > 0 else None), span


def assess_pacing(ledger, sent_starts, scheduled_start_ns, send_window_end_ns,
                  rate_pps, quality=None):
    """Separate generator validity from delivery and clock-delay validity."""
    quality = _quality(quality)
    interval_ns = 1e9 / rate_pps
    window_seconds = ((send_window_end_ns - scheduled_start_ns) / 1e9
                      if scheduled_start_ns is not None and send_window_end_ns is not None else None)
    offered_pps = (len(sent_starts) / window_seconds
                   if window_seconds is not None and window_seconds > 0 else None)
    lateness = ([actual - (scheduled_start_ns + round(seq * interval_ns))
                 for seq, actual in enumerate(sent_starts)]
                if scheduled_start_ns is not None else [])
    sender_gaps = _gaps(sent_starts)
    input_values = [value for value in ledger.timestamps['input'][:len(sent_starts)]
                    if value is not None]
    input_gaps = _gaps(input_values)
    short_limit_ns = interval_ns * quality.short_gap_interval_fraction
    input_short_fraction = (sum(gap < short_limit_ns for gap in input_gaps) / len(input_gaps)
                            if input_gaps else 0.0)
    sender_short_fraction = (sum(gap < short_limit_ns for gap in sender_gaps) / len(sender_gaps)
                             if sender_gaps else 0.0)
    lateness_summary = summarize(lateness)
    p99_limit = max(quality.p99_send_lateness_floor_ns, interval_ns)
    maximum_limit = max(quality.maximum_send_lateness_floor_ns, 3 * interval_ns)
    reasons = []
    if len(sent_starts) != len(ledger.frames):
        reasons.append('Not every planned frame was sent')
    if (offered_pps is None or abs(offered_pps / rate_pps - 1)
            > quality.offered_rate_relative_tolerance):
        reasons.append('Actual offered rate is outside the permitted target tolerance')
    if lateness_summary['p99'] is None or lateness_summary['p99'] > p99_limit:
        reasons.append('p99 send deadline lateness exceeded its pacing limit')
    if lateness_summary['maximum'] is None or lateness_summary['maximum'] > maximum_limit:
        reasons.append('Maximum send deadline lateness exceeded its pacing limit')
    counters = ledger.counters['input']
    if (len(input_values) != len(sent_starts) or counters['missing_timestamps']
            or counters['truncated_ancillary']):
        reasons.append('Every sent frame requires a usable input kernel timestamp')
    if counters['kernel_timestamp_regressions'] or counters['sequence_regressions']:
        reasons.append('Input kernel timestamp or sequence ordering regressed')
    if input_short_fraction > quality.maximum_short_input_gap_fraction:
        reasons.append('Input kernel interarrival burst fraction exceeded its pacing limit')
    input_rate, input_span = _interpacket_rate(input_values)
    return {
        'valid': not reasons, 'reasons': reasons, 'thresholds': asdict(quality),
        'nominal_interval_ns': interval_ns,
        'p99_send_lateness_limit_ns': p99_limit,
        'maximum_send_lateness_limit_ns': maximum_limit,
        'actual_offered_pps_over_window': offered_pps,
        'actual_input_kernel_interarrival_pps': input_rate,
        'actual_input_kernel_interarrival_span_seconds': input_span,
        'short_gap_threshold_ns': short_limit_ns,
        'input_kernel_short_gap_fraction': input_short_fraction,
        'sender_short_gap_fraction': sender_short_fraction,
        'send_lateness_ns': lateness, 'send_lateness_summary_ns': lateness_summary,
        'sender_interpacket_gaps_ns': sender_gaps,
        'sender_interpacket_gap_summary_ns': summarize(sender_gaps),
        'input_kernel_interarrival_gaps_ns': input_gaps,
        'input_kernel_interarrival_gap_summary_ns': summarize(input_gaps),
        'meaning': 'Input interarrival gaps come from kernel timestamps; receiver read scheduling is not pacing or latency evidence',
    }


def build_report(ledger, sent_starts, sent_finishes, scheduled_start_ns,
                 send_window_end_ns, rate_pps, drain_seconds, capture_statistics,
                 clock_report, errors, timestamp_setup_errors, capture_buffers,
                 gates=None):
    """Keep all raw evidence while reporting independent validity gates."""
    report = pilot.build_report(
        ledger, sent_starts, sent_finishes, scheduled_start_ns, send_window_end_ns,
        rate_pps, drain_seconds, capture_statistics, clock_report, errors,
        timestamp_setup_errors, capture_buffers)
    for role in ('input', 'output'):
        stats = capture_statistics.get(role)
        if (stats is not None and 'socket_packets' in stats
                and stats['socket_packets'] != ledger.counters[role]['read_packets']):
            report['packet_delivery_reasons'].append(
                f'{role} kernel socket packet count differs from recvmsg accounting; capture completeness is unestablished')
    report['packet_delivery_valid'] = not report['packet_delivery_reasons']
    if not report['packet_delivery_valid'] and 'Capture/delivery validation failed' not in report['latency']['reasons']:
        report['latency']['reasons'].append('Capture/delivery validation failed')
    if not report['packet_delivery_valid']:
        report['observed_loss_fraction_after_drain'] = None
    latency = report['latency']
    for role in ('input', 'output'):
        if ledger.counters[role]['sequence_regressions']:
            latency['reasons'].append(f'{role} exact-frame sequence ordering regressed')
    latency['valid'] = not latency['reasons']
    if not latency['valid']:
        latency['summary_us'] = None
    pacing = assess_pacing(ledger, sent_starts, scheduled_start_ns,
                           send_window_end_ns, rate_pps, gates)
    delivery_valid = report['packet_delivery_valid']
    gate_valid = delivery_valid and latency['valid'] and pacing['valid']
    capacity_reasons = list(report['packet_delivery_reasons']) + list(pacing['reasons'])
    capacity_reasons += list(timestamp_setup_errors) + list(clock_report['reasons'])
    for role in ('input', 'output'):
        counts = ledger.counters[role]
        if counts['missing_timestamps'] or counts['truncated_ancillary']:
            capacity_reasons.append(f'{role} captured kernel timestamps are missing or malformed')
        if counts['kernel_timestamp_regressions'] or counts['sequence_regressions']:
            capacity_reasons.append(f'{role} captured timestamp or sequence ordering regressed')
    if latency['negative_timestamp_differences']:
        capacity_reasons.append('Negative paired kernel path delays')
    capacity_valid = not capacity_reasons
    report.update({'delivery_valid': delivery_valid, 'latency_valid': latency['valid'],
                   'gate_valid': gate_valid, 'phase_valid': gate_valid,
                   'capacity_quality_valid': capacity_valid,
                   'capacity_quality_reasons': capacity_reasons,
                   'pilot_passed': gate_valid, 'pacing_quality': pacing,
                   'errors': list(errors),
                   'timestamp_setup_errors': list(timestamp_setup_errors)})
    throughput = report['throughput']
    window = throughput['actual_sender_window_seconds']
    output_count = report['captured_output_unique']
    output_values = [value for value in ledger.timestamps['output'] if value is not None]
    output_rate, output_span = _interpacket_rate(output_values)
    throughput.update({
        'observed_output_unique_pps_over_measured_window': output_count / window if window and window > 0 else None,
        'output_count_includes_bounded_drain': True,
        'output_rate_denominator': 'Measured sender window duration; unique output count includes bounded post-window drain',
        'actual_input_kernel_interarrival_pps': pacing['actual_input_kernel_interarrival_pps'],
        'actual_input_kernel_interarrival_span_seconds': pacing['actual_input_kernel_interarrival_span_seconds'],
        'raw_output_kernel_interarrival_pps': output_rate,
        'raw_output_kernel_interarrival_span_seconds': output_span,
        'observed_output_kernel_interarrival_pps': output_rate if capacity_valid else None,
        'observed_output_kernel_interarrival_span_seconds': output_span if capacity_valid else None,
        'output_rate_valid': capacity_valid,
        'reliable_output_unique_pps_over_measured_window': output_count / window if capacity_valid and window and window > 0 else None,
        'sender_short_gap_fraction': pacing['sender_short_gap_fraction'],
        'input_kernel_short_gap_fraction': pacing['input_kernel_short_gap_fraction'],
    })
    report['scheduling']['policy'] = 'Precomputed evenly spaced monotonic deadlines; persistent nonblocking sender and independent capture/audit threads'
    report['scheduling']['send_socket_mode'] = 'Nonblocking; errors abort the phase without retry bursts'
    return report


def _require_linux_abi():
    if (sys.platform != 'linux' or not hasattr(socket, 'AF_PACKET')
            or struct.calcsize('@l') != 8 or struct.calcsize('@ll') != pilot.TIMESPEC64.size):
        raise ValueError('Live phases require verified Linux 64-bit AF_PACKET/timespec ABI')


def run_phase(frames, input_iface, output_iface, rate_pps, *, sequence_from_frame,
              drain_seconds=2.0, gates=None, on_window_start=None,
              on_window_end=None, clock_reader=None, paced_sender=None):
    """Run one phase using only its two distinct, already isolated interfaces.

    Callbacks have no arguments. Start runs after all socket/worker setup; end
    runs after the measured sending interval and before the capture drain.
    Callback failures raise PhaseCallbackError containing the invalid partial
    report after cleanup. Plan/ABI errors raise ValueError before traffic.
    Other runtime failures return an invalid report with their error evidence.
    """
    duration = validate_plan(frames, rate_pps, sequence_from_frame, drain_seconds)
    quality = _quality(gates)
    if not isinstance(input_iface, str) or not input_iface or not isinstance(output_iface, str) or not output_iface or input_iface == output_iface:
        raise ValueError('Use two distinct isolated host endpoint interfaces')
    if any(callback is not None and not callable(callback)
           for callback in (on_window_start, on_window_end)):
        raise ValueError('Window callbacks must be callable or None')
    _require_linux_abi()
    ledger = CaptureLedger(frames, sequence_from_frame)
    audit = ClockAudit(bracket_reader=clock_reader)
    deadline_offsets = [round(sequence * 1e9 / rate_pps) for sequence in range(len(frames))]
    # Pack frames and allocate native arrays BEFORE the measured resource window.
    # A single CDLL call removes per-packet Python/GIL reacquisition. It does not
    # promise scheduler immunity or change any deadline/quality threshold.
    native_plan = (paced_sender.prepare(frames, deadline_offsets, round(duration * 1e9))
                   if paced_sender is not None else None)
    native_result = native_report = None
    starts_storage, finishes_storage = [None] * len(frames), [None] * len(frames)
    sent_count = 0
    scheduled_start_ns = send_window_end_ns = None
    opened, captures = [], {}
    capture_buffers, capture_statistics = {}, {}
    errors, timestamp_setup_errors = [], []
    stop_capture, capture_ready, capture_failed = (threading.Event() for _ in range(3))
    stop_audit, audit_ready = threading.Event(), threading.Event()
    audit_lock = threading.Lock()
    capture_worker_thread = audit_worker_thread = None
    selector = None
    callback_failure = None
    window_started = False

    def sample_clock():
        # Both the independent periodic sampler and the explicit end sample
        # use the same lock; raw sample ordering remains unambiguous.
        with audit_lock:
            audit.sample()

    def capture_worker():
        try:
            capture_ready.set()
            while not stop_capture.is_set():
                for key, _ in selector.select(.005):
                    # A time budget and socket rotation serve large workloads
                    # without imposing a tiny fixed per-read packet limit.
                    budget_end_ns = time.monotonic_ns() + 2_000_000
                    while not stop_capture.is_set():
                        try:
                            frame, ancillary, flags, address = key.fileobj.recvmsg(
                                65535, socket.CMSG_SPACE(SCM_TIMESTAMPING64.size))
                        except BlockingIOError:
                            break
                        ledger.observe(key.data, frame, address[2], ancillary, flags,
                                       time.monotonic_ns(), SO_TIMESTAMPING_OLD)
                        if time.monotonic_ns() >= budget_end_ns:
                            break
            # Finish already queued datagrams within a small cleanup bound.
            # Accounting below rejects any kernel/read mismatch instead of
            # calling an unread receive queue switch loss.
            cleanup_end_ns = time.monotonic_ns() + 50_000_000
            for role, receiver in captures.items():
                while time.monotonic_ns() < cleanup_end_ns:
                    try:
                        frame, ancillary, flags, address = receiver.recvmsg(
                            65535, socket.CMSG_SPACE(SCM_TIMESTAMPING64.size))
                    except BlockingIOError:
                        break
                    ledger.observe(role, frame, address[2], ancillary, flags,
                                   time.monotonic_ns(), SO_TIMESTAMPING_OLD)
        except Exception as error:
            errors.append(f'Capture worker failed: {type(error).__name__}: {error}')
            capture_failed.set()
            if native_plan is not None:
                native_plan.cancel()
            capture_ready.set()

    def audit_worker():
        try:
            sample_clock()
            audit_ready.set()
            while not stop_audit.wait(CLOCK_SAMPLE_SECONDS):
                sample_clock()
        except Exception as error:
            errors.append(f'Clock sampler failed: {type(error).__name__}: {error}')
            capture_failed.set()
            if native_plan is not None:
                native_plan.cancel()
            audit_ready.set()

    def finish_clock_window():
        # Bracket the sender end before draining. Sampling continues through
        # drain so a wall step affecting a late output timestamp is detected;
        # the 25 ms gap gate still applies only to the measured sender window.
        sample_clock()

    try:
        selector = selectors.DefaultSelector()
        for role, interface in (('input', input_iface), ('output', output_iface)):
            receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            opened.append(receiver)
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
            capture_buffers[role] = receiver.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            try:
                receiver.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPING_OLD, TIMESTAMP_FLAGS)
            except OSError as error:
                timestamp_setup_errors.append(f'{role} SO_TIMESTAMPING setup failed: {error}')
            receiver.bind((interface, 0))
            receiver.setblocking(False)
            selector.register(receiver, selectors.EVENT_READ, role)
            captures[role] = receiver
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        opened.append(sender)
        sender.bind((input_iface, 0))
        sender.setblocking(False)
        capture_worker_thread = threading.Thread(target=capture_worker, name='benchmark-capture', daemon=True)
        audit_worker_thread = threading.Thread(target=audit_worker, name='benchmark-clock', daemon=True)
        capture_worker_thread.start()
        audit_worker_thread.start()
        if not capture_ready.wait(1) or not audit_ready.wait(1):
            errors.append('Capture and clock workers did not become ready within one second')
        if not errors:
            if on_window_start is not None:
                try:
                    on_window_start()
                except Exception as error:
                    callback_failure = ('on_window_start', error)
                    raise RuntimeError('Resource start callback failed') from error
            window_started = True
            if native_plan is not None:
                native_result = native_plan.run_raw(sender.fileno())
                scheduled_start_ns = native_result.scheduled_start_ns
                send_window_end_ns = native_result.send_window_end_ns
                sent_count = native_result.sent_count
            else:
                scheduled_start_ns = time.monotonic_ns()
                scheduled_end_ns = scheduled_start_ns + round(duration * 1e9)
                for sequence, frame in enumerate(frames):
                    if capture_failed.is_set():
                        break
                    due_ns = scheduled_start_ns + deadline_offsets[sequence]
                    remaining = (due_ns - time.monotonic_ns()) / 1e9
                    if remaining > 0:
                        time.sleep(remaining)
                    before_ns = time.monotonic_ns()
                    if before_ns >= scheduled_end_ns:
                        errors.append('Sender exceeded the bounded phase window; remaining frames were not sent')
                        break
                    try:
                        sent_length = sender.send(frame)
                        after_ns = time.monotonic_ns()
                        if sent_length != len(frame):
                            raise OSError(f'Partial raw frame send: {sent_length}/{len(frame)}')
                    except OSError as error:
                        errors.append(f'Nonblocking send failed at sequence {sequence}: {error}')
                        break
                    starts_storage[sequence], finishes_storage[sequence] = before_ns, after_ns
                    sent_count += 1
                if sent_count == len(frames):
                    remaining = (scheduled_end_ns - time.monotonic_ns()) / 1e9
                    if remaining > 0:
                        time.sleep(remaining)
                send_window_end_ns = time.monotonic_ns()
            if on_window_end is not None:
                try:
                    on_window_end()
                except Exception as error:
                    callback_failure = ('on_window_end', error)
                    raise RuntimeError('Resource end callback failed') from error
            finish_clock_window()
            if not capture_failed.is_set():
                stop_capture.wait(drain_seconds)
    except Exception as error:
        errors.append(f'Phase failed: {type(error).__name__}: {error}')
        if window_started and send_window_end_ns is None:
            send_window_end_ns = time.monotonic_ns()
        if audit_worker_thread is not None:
            try:
                finish_clock_window()
            except Exception as clock_error:
                errors.append(f'Final clock sample failed: {clock_error}')
    finally:
        stop_capture.set()
        stop_audit.set()
        if capture_worker_thread is not None:
            capture_worker_thread.join(1)
            if capture_worker_thread.is_alive():
                errors.append('Capture worker did not stop within one second')
                for receiver in captures.values():
                    try:
                        receiver.close()
                    except OSError as error:
                        errors.append(f'Forced capture close failed: {error}')
                capture_worker_thread.join(.5)
                if capture_worker_thread.is_alive():
                    errors.append('Capture worker remained active after forced socket closure')
        if audit_worker_thread is not None:
            audit_worker_thread.join(.5)
            if audit_worker_thread.is_alive():
                errors.append('Clock sampler remained active after cleanup')
            else:
                try:
                    sample_clock()
                except Exception as error:
                    errors.append(f'Final post-drain clock sample failed: {error}')
        for role, receiver in captures.items():
            try:
                capture_statistics[role] = parse_packet_statistics(receiver.getsockopt(
                    SOL_PACKET, PACKET_STATISTICS, PACKET_STATS.size))
            except (OSError, ValueError) as error:
                capture_statistics[role] = None
                errors.append(f'{role} capture statistics failed: {error}')
        for handle in opened:
            try:
                handle.close()
            except OSError as error:
                errors.append(f'Socket cleanup failed: {error}')
        if selector is not None:
            try:
                selector.close()
            except Exception as error:
                errors.append(f'Selector cleanup failed: {error}')
        if native_plan is not None:
            try:
                if native_result is not None:
                    # Decode raw arrays only AFTER resource callbacks/drain.
                    # Worker threads have stopped before the cancellation flag
                    # is freed, so they cannot write into a closed native plan.
                    native_report = native_plan.report(native_result)
                    starts_storage = native_report['sent_starts']
                    finishes_storage = native_report['sent_finishes']
                    errors.extend(native_report['errors'])
            finally:
                native_plan.close()
    report = build_report(
        ledger, starts_storage[:sent_count], finishes_storage[:sent_count],
        scheduled_start_ns, send_window_end_ns, rate_pps, drain_seconds,
        capture_statistics, audit.report(scheduled_start_ns, send_window_end_ns),
        errors, timestamp_setup_errors, capture_buffers, quality)
    report.update({'input_iface': input_iface, 'output_iface': output_iface,
                   'finished_monotonic_ns': time.monotonic_ns()})
    report['scheduling']['backend'] = ('linux-native-paced-send-v1' if paced_sender is not None
                                        else 'python-paced-send-v1')
    if paced_sender is not None:
        report['scheduling']['policy'] = 'Precomputed evenly spaced absolute CLOCK_MONOTONIC deadlines; one GIL-releasing native call; independent Python capture/audit threads'
        report['scheduling']['native_sender_provenance'] = paced_sender.provenance
        report['scheduling']['native_attempts'] = ({key: value for key, value in native_report.items()
                                                  if key not in ('sent_starts', 'sent_finishes')}
                                                 if native_report is not None else None)
    if callback_failure is not None:
        name, cause = callback_failure
        raise PhaseCallbackError(name, cause, report) from cause
    return report
