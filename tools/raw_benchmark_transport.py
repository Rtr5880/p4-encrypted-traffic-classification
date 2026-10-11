#!/usr/bin/env python3
"""Reduced RAW-clock AF_PACKET phases; importing never sends traffic.

Frames, capture storage and RAW deadline offsets are prepared before the
resource sampling callbacks. The capture sockets remain open for the phase and
its drain. A separate 5 ms clock sampler is independent of receiver scheduling.
Existing skb software observations are retained UNQUALIFIED in diagnostics;
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
import benchmark_transport as legacy
from raw_clock import RawClockAudit


def raw_now_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def wait_raw(event, seconds):
    """Supported-clock waits are wake aids; only RAW establishes expiry."""
    end = raw_now_ns() + round(seconds * 1e9)
    while not event.is_set():
        remaining = end - raw_now_ns()
        if remaining <= 0:
            break
        event.wait(min(remaining / 1e9, .005))



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


ClockAudit = legacy.ClockAudit
PacingQuality = legacy.PacingQuality
_quality = legacy._quality


def _gaps(values):
    return [b - a for a, b in zip(values, values[1:])]


def _interpacket_rate(values):
    if len(values) < 2:
        return None, None
    span = (max(values) - min(values)) / 1e9
    return ((len(values) - 1) / span if span > 0 else None), span



def assess_raw_pacing(ledger, starts, finishes, begin, end, rate, quality=None):
    quality = _quality(quality)
    interval = 1e9 / rate
    window = (end - begin) / 1e9 if begin is not None and end is not None else None
    offered = len(starts) / window if window and window > 0 else None
    lateness = [value - begin - round(i * interval) for i, value in enumerate(starts)] if begin is not None else []
    gaps = _gaps(starts)
    short_fraction = sum(gap < interval * quality.short_gap_interval_fraction for gap in gaps) / len(gaps) if gaps else 0
    summary = summarize(lateness)
    finish_lateness = [value - begin - round(i * interval) for i, value in enumerate(finishes)] if begin is not None else []
    finish_summary = summarize(finish_lateness)
    p99_limit = max(quality.p99_send_lateness_floor_ns, interval)
    maximum_limit = max(quality.maximum_send_lateness_floor_ns, 3 * interval)
    reasons = []
    if len(starts) != len(ledger.frames) or len(finishes) != len(starts):
        reasons.append('Not every planned frame has a successful RAW-timed send')
    if offered is None or abs(offered / rate - 1) > quality.offered_rate_relative_tolerance:
        reasons.append('Actual RAW offered rate exceeds the unchanged 2% tolerance')
    if any(value < 0 for value in lateness):
        reasons.append('A send occurred before its immutable RAW deadline')
    if summary['p99'] is None or summary['p99'] > p99_limit:
        reasons.append('RAW p99 send lateness exceeded its pacing limit')
    if summary['maximum'] is None or summary['maximum'] > maximum_limit:
        reasons.append('RAW maximum send lateness exceeded its pacing limit')
    if finish_summary['p99'] is None or finish_summary['p99'] > p99_limit:
        reasons.append('RAW send-completion upper-bound p99 lateness exceeded its pacing limit')
    if finish_summary['maximum'] is None or finish_summary['maximum'] > maximum_limit:
        reasons.append('RAW send-completion upper-bound maximum lateness exceeded its pacing limit')
    if any(b < a for a, b in zip(starts, finishes)) or any(gap < 0 for gap in gaps):
        reasons.append('RAW send timestamps regressed')
    if short_fraction > quality.maximum_short_input_gap_fraction:
        reasons.append('RAW sender short-gap fraction exceeded the 1% threshold')
    for role in ('input', 'output'):
        if ledger.counters[role]['sequence_regressions']:
            reasons.append(f'{role} exact-frame observation order regressed')
    return {'valid': not reasons, 'reasons': reasons, 'clock_domain': 'CLOCK_MONOTONIC_RAW',
        'thresholds': asdict(quality), 'nominal_interval_ns': interval,
        'p99_send_lateness_limit_ns': p99_limit, 'maximum_send_lateness_limit_ns': maximum_limit,
        'actual_offered_pps_over_window': offered, 'sender_short_gap_fraction': short_fraction,
        'send_lateness_ns': lateness, 'send_lateness_summary_ns': summary,
        'send_completion_lateness_ns': finish_lateness,
        'send_completion_lateness_summary_ns': finish_summary,
        'send_call_brackets_ns': [b - a for a, b in zip(starts, finishes)],
        'sender_interpacket_gaps_ns': gaps, 'sender_interpacket_gap_summary_ns': summarize(gaps),
        'legacy_kernel_input_gap_gate_applicable': False,
        'meaning': 'RAW application send deadlines/gaps; NOT kernel-arrival pacing. The old kernel gap check is retained separately, not passed or silently removed.'}


def assess_raw_send_integrity(ledger, starts, finishes, begin, end, errors=()):
    """Hard sender-evidence requirements, independent of pacing heuristics.

    Exact successful sends and well-ordered RAW boundaries establish the
    numerator/window evidence. Being late relative to the intended traffic
    schedule does not, by itself, invalidate these observations.
    """
    # The native sender can fail during its final window wait even after every
    # frame was submitted. Such an error remains hard for offered-rate evidence.
    reasons = [error for error in errors if error.startswith('Native sender ')]
    if len(starts) != len(ledger.frames) or len(finishes) != len(starts):
        reasons.append('Not every planned frame has a successful RAW-timed send')
    if begin is None or end is None or end <= begin:
        reasons.append('RAW sender window boundaries are missing or non-positive')
    if (any(finish < start for start, finish in zip(starts, finishes))
            or any(b < a for a, b in zip(starts, starts[1:]))
            or any(b < a for a, b in zip(finishes, finishes[1:]))):
        reasons.append('RAW send timestamps regressed or send brackets are inverted')
    if begin is not None and any(value < begin for value in starts):
        reasons.append('RAW send evidence begins before its measured window')
    if end is not None and any(value > end for value in finishes):
        reasons.append('RAW send evidence extends beyond its measured window')
    return {'valid': not reasons, 'reasons': reasons}


def build_report(ledger, starts, finishes, begin, end, rate, drain, statistics,
                 legacy_clock, raw_clock, errors, timestamp_errors, buffers, gates=None):
    # Exact packet matching/socket accounting and all old timestamp evidence are
    # reused unchanged. Legacy clock verdicts are never turned into passes.
    report = legacy.build_report(ledger, starts, finishes, begin, end, rate, drain,
        statistics, legacy_clock, errors, timestamp_errors, buffers, gates)
    old_verdict = {key: report.pop(key) for key in ('latency_valid', 'gate_valid',
        'capacity_quality_valid', 'capacity_quality_reasons', 'pilot_passed', 'phase_valid')}
    kernel = report.pop('latency')
    kernel.update({'legacy_continuity_valid': kernel['valid'], 'valid': False,
        'qualified_for_performance_claims': False, 'summary_us': None})
    kernel['reasons'].append('CLOCK_REALTIME elapsed rate is not qualified; kernel forwarding latency is outside the reduced RAW protocol')
    old_pacing = report.pop('pacing_quality')
    old_pacing.update({'applicable_to_reduced_protocol': False,
                      'qualified_kernel_arrival_pacing': False})
    pacing = assess_raw_pacing(ledger, starts, finishes, begin, end, rate, gates)
    counts_valid = report['packet_delivery_valid']
    send_integrity = assess_raw_send_integrity(ledger, starts, finishes, begin, end, errors)
    integrity_reasons = (report['packet_delivery_reasons'] + send_integrity['reasons']
                         + raw_clock['reasons'])
    integrity_valid = counts_valid and send_integrity['valid'] and raw_clock['valid']
    raw_sender_rate_valid = send_integrity['valid'] and raw_clock['valid']
    pacing_status = 'PASS' if pacing['valid'] else 'WARNING'
    report.update({'protocol': 'raw-performance-calibration-v3',
        'clock_domains': {'sender_and_elapsed': 'CLOCK_MONOTONIC_RAW',
                         'kernel_packet_timestamps': 'CLOCK_REALTIME',
                         'legacy_clock_audit': 'CLOCK_REALTIME vs CLOCK_MONOTONIC'},
        'raw_clock_audit': raw_clock, 'pacing_quality': pacing,
        'measurement_integrity': {'valid': integrity_valid,
            'status': 'PASS' if integrity_valid else 'FAIL', 'reasons': integrity_reasons,
            'sender_evidence': send_integrity},
        'measurement_integrity_valid': integrity_valid,
        'measurement_integrity_reasons': integrity_reasons,
        'raw_pacing_conformance_status': pacing_status,
        'pacing_warnings': [] if pacing['valid'] else list(pacing['reasons']),
        'pacing_conformance': {'status': pacing_status,
            'warnings': [] if pacing['valid'] else list(pacing['reasons']),
            'engineering_heuristics': True, 'numerical_thresholds_unchanged': True,
            'uniform_load_or_saturation_claims_supported': False,
            'meaning': 'Prespecified engineering pacing conformance, not a scientific boundary of packet-count or average-rate validity; even PASS is not a capacity or saturation qualification.'},
        'kernel_timestamp_diagnostics': kernel, 'legacy_kernel_arrival_pacing': old_pacing,
        'legacy_protocol_verdict': old_verdict,
        'metric_validity': {'offered_load': raw_sender_rate_valid,
            'packet_accounting': counts_valid,
            'delivered_throughput': integrity_valid,
            'kernel_forwarding_latency': False},
        'metric_validity_scope': 'Local evidence eligibility only; absolute RAW-normalized rates additionally require independent campaign RAW qualification. Pacing WARNING does not replace or waive either hard requirement.',
        'reduced_quality_valid': integrity_valid,
        'reduced_quality_reasons': integrity_reasons,
        'path_non_delivery': {'valid': counts_valid,
            'missing_output_after_bounded_drain': len(report['missing_output_sequences']) if counts_valid else None,
            'meaning': 'Exact successful input frames not observed at the output after bounded drain, only when capture completeness is established. This does not attribute non-delivery to BMv2; capture/instrumentation loss instead invalidates this inference.'},
        'errors': list(errors), 'timestamp_setup_errors': list(timestamp_errors)})
    # Explicitly rename inherited fields whose numerical domain is now RAW.
    packet = report['per_packet']
    packet['send_start_raw_ns'] = packet.pop('send_start_monotonic_ns')
    packet['send_finish_raw_ns'] = packet.pop('send_finish_monotonic_ns')
    scheduling = report['scheduling']
    scheduling['started_raw_ns'] = scheduling.pop('started_monotonic_ns')
    scheduling['send_window_end_raw_ns'] = scheduling.pop('send_window_end_monotonic_ns')
    scheduling['clock_domain'] = 'CLOCK_MONOTONIC_RAW'
    through = report['throughput']
    through['output_capture_completion_raw_seconds'] = through.pop('output_capture_completion_monotonic_seconds')
    through['raw_sender_window_seconds'] = through.pop('actual_sender_window_seconds')
    through['clock_domain'] = 'CLOCK_MONOTONIC_RAW'
    kernel['unqualified_kernel_rate_diagnostics'] = {'clock_domain': 'CLOCK_REALTIME',
        'values': {name: through.pop(name) for name in list(through) if 'kernel_interarrival' in name}}
    through.pop('reliable_output_unique_pps_over_measured_window', None)
    through.pop('input_kernel_short_gap_fraction', None)
    through['kernel_rate_qualified'] = False
    through['sender_short_gap_fraction'] = pacing['sender_short_gap_fraction']
    through['output_rate_valid'] = False
    through['delivered_pps'] = (report['captured_output_unique'] / through['raw_sender_window_seconds']
        if through['raw_sender_window_seconds'] and through['raw_sender_window_seconds'] > 0 else None)
    through['output_rate_denominator'] = 'RAW offered window; unique output includes bounded drain; not kernel egress service rate or maximum capacity'
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
    if clock_reader is None or paced_sender is None or paced_sender.provenance['policy']['clock'] != 'CLOCK_MONOTONIC_RAW':
        raise ValueError('A sealed native RAW sender and native five-read bracket are required')
    ledger = CaptureLedger(frames, sequence_from_frame)
    audit = RawClockAudit(bracket_reader=clock_reader)
    legacy_audit = ClockAudit()
    deadline_offsets = [round(sequence * 1e9 / rate_pps) for sequence in range(len(frames))]
    # Pack frames and allocate native arrays BEFORE the measured resource window.
    # A single CDLL call removes per-packet Python/GIL reacquisition. It does not
    # promise scheduler immunity or change any deadline/quality threshold.
    native_plan = paced_sender.prepare(frames, deadline_offsets, round(duration * 1e9))
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
            row = clock_reader()
            audit.observe(*row)
            legacy_audit.observe(row[1], row[2], row[3])

    def capture_worker():
        try:
            capture_ready.set()
            while not stop_capture.is_set():
                for key, _ in selector.select(.005):
                    # A time budget and socket rotation serve large workloads
                    # without imposing a tiny fixed per-read packet limit.
                    budget_end_ns = raw_now_ns() + 2_000_000
                    while not stop_capture.is_set():
                        try:
                            frame, ancillary, flags, address = key.fileobj.recvmsg(
                                65535, socket.CMSG_SPACE(SCM_TIMESTAMPING64.size))
                        except BlockingIOError:
                            break
                        ledger.observe(key.data, frame, address[2], ancillary, flags,
                                       raw_now_ns(), SO_TIMESTAMPING_OLD)
                        if raw_now_ns() >= budget_end_ns:
                            break
            # Finish already queued datagrams within a small cleanup bound.
            # Accounting below rejects any kernel/read mismatch instead of
            # calling an unread receive queue switch loss.
            cleanup_end_ns = raw_now_ns() + 50_000_000
            for role, receiver in captures.items():
                while raw_now_ns() < cleanup_end_ns:
                    try:
                        frame, ancillary, flags, address = receiver.recvmsg(
                            65535, socket.CMSG_SPACE(SCM_TIMESTAMPING64.size))
                    except BlockingIOError:
                        break
                    ledger.observe(role, frame, address[2], ancillary, flags,
                                   raw_now_ns(), SO_TIMESTAMPING_OLD)
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
            if on_window_end is not None:
                try:
                    on_window_end()
                except Exception as error:
                    callback_failure = ('on_window_end', error)
                    raise RuntimeError('Resource end callback failed') from error
            finish_clock_window()
            if not capture_failed.is_set():
                drain_start_raw_ns = raw_now_ns()
                wait_raw(stop_capture, drain_seconds)
                drain_end_raw_ns = raw_now_ns()
    except Exception as error:
        errors.append(f'Phase failed: {type(error).__name__}: {error}')
        if window_started and send_window_end_ns is None:
            send_window_end_ns = raw_now_ns()
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
    legacy_clock_report = legacy_audit.report()
    legacy_clock_report['clock_bracket_backend'] = 'linux-native-raw-five-read-v1; embedded MONOTONIC/REALTIME/MONOTONIC reads'
    report = build_report(
        ledger, starts_storage[:sent_count], finishes_storage[:sent_count],
        scheduled_start_ns, send_window_end_ns, rate_pps, drain_seconds,
        capture_statistics, legacy_clock_report, audit.report(scheduled_start_ns, send_window_end_ns),
        errors, timestamp_setup_errors, capture_buffers, quality)
    report.update({'input_iface': input_iface, 'output_iface': output_iface,
                   'finished_raw_ns': raw_now_ns(),
                   'actual_drain_raw_seconds': (drain_end_raw_ns - drain_start_raw_ns) / 1e9
                       if 'drain_end_raw_ns' in locals() else None})
    report['scheduling']['backend'] = paced_sender.provenance['backend']
    if paced_sender is not None:
        report['scheduling']['policy'] = 'Immutable RAW deadlines; supported relative sleeps and RAW rechecks; no frequency correction, spin, send retry or deadline rebasing'
        report['scheduling']['native_sender_provenance'] = paced_sender.provenance
        report['scheduling']['native_attempts'] = ({key: value for key, value in native_report.items()
                                                  if key not in ('sent_starts', 'sent_finishes')}
                                                 if native_report is not None else None)
    if callback_failure is not None:
        name, cause = callback_failure
        raise PhaseCallbackError(name, cause, report) from cause
    return report
