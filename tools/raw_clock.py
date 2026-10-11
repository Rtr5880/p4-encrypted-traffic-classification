#!/usr/bin/env python3
"""RAW sampling and bounded measurement-only SNTP rate qualification.

No import-time work, clock-setting calls, service changes, benchmark execution,
or NTP discipline. Source clock observations are retained without retries or
best-sample selection. Network bounds include the entire request/response
interval and advertised upstream uncertainty; they are not confidence intervals
or traceable SI certificates. REALTIME/MONOTONIC behaviour remains diagnostic.
"""

import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

BACKEND_NAME = 'linux-native-raw-five-read-v1'
FIELD_ORDER = ['raw_before_ns', 'monotonic_before_ns', 'realtime_ns',
               'monotonic_after_ns', 'raw_after_ns']
CLOCK_SEQUENCE = ['CLOCK_MONOTONIC_RAW', 'CLOCK_MONOTONIC', 'CLOCK_REALTIME',
                  'CLOCK_MONOTONIC', 'CLOCK_MONOTONIC_RAW']
MAX_BRACKET_NS = 100_000
MAX_GAP_NS = 25_000_000
STEP_NS = 1_000_000
SAMPLE_SECONDS = 0.005
RATE_BUDGET_PPM = 1000
MIN_REFERENCE_SPAN_SECONDS = 180
MIN_QUERIES_PER_PROVIDER = 3
PROVIDERS = ('time.cloudflare.com', 'time.google.com', 'ntp.ubuntu.com')
NTP_EPOCH = 2208988800
LOAD_QUERY_OFFSET_NS = 2_000_000_000
NETWORK_QUERY_TIMEOUT_SECONDS = 2
LOAD_QUERY_END_MARGIN_NS = 2_000_000_000


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _save_exclusive(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def build_raw_clock_reader(repo=None, cc=None, output_root=None):
    """Compile the reader into a new directory; never overwrite past evidence."""
    if platform.system() != 'Linux' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError('RAW reader requires 64-bit Linux')
    repo = Path(repo or Path(__file__).resolve().parent.parent).resolve(strict=True)
    source = repo / 'tools' / 'raw_clock_bracket.c'
    bundled = repo / 'p4' / 'compiler' / 'cc'
    compiler = shutil.which(str(cc or (bundled if bundled.is_file() else 'cc')))
    if not compiler:
        raise RuntimeError('C compiler unavailable')
    compiler = Path(compiler).resolve(strict=True)
    root = Path(output_root or repo / 'results' / 'raw_clock_reader').resolve()
    directory = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex)
    directory.mkdir(parents=True, exist_ok=False)
    library = directory / 'raw_clock_bracket.so'
    flags = ['-std=c11', '-O2', '-fPIC', '-shared', '-Wall', '-Wextra', '-Werror']
    command = [str(compiler), *flags, str(source), '-o', str(library)]
    source_hash, compiler_hash = sha256_file(source), sha256_file(compiler)
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    _save_exclusive(directory / 'compile.json', {
        'command': command, 'returncode': result.returncode, 'stdout': result.stdout,
        'stderr': result.stderr, 'source_sha256': source_hash,
        'compiler_sha256': compiler_hash,
    })
    if result.returncode:
        raise RuntimeError(f'RAW reader compilation failed; see {directory}')
    if sha256_file(source) != source_hash or sha256_file(compiler) != compiler_hash:
        raise RuntimeError('RAW reader source/compiler changed during build')
    _save_exclusive(directory / 'receipt.json', {
        'backend': BACKEND_NAME, 'abi_version': 1, 'units': 'nanoseconds',
        'field_order': FIELD_ORDER, 'clock_sequence': CLOCK_SEQUENCE,
        'atomic': False, 'retries': 0, 'filters': False,
        'source': str(source), 'source_sha256': source_hash,
        'library': str(library), 'library_sha256': sha256_file(library),
        'compiler': str(compiler), 'compiler_sha256': compiler_hash,
        'compile_sha256': sha256_file(directory / 'compile.json'),
    })
    return library


class RawClockReader:
    def __init__(self, library):
        library = Path(library).resolve(strict=True)
        with (library.parent / 'receipt.json').open(encoding='utf-8') as stream:
            receipt = json.load(stream)
        if (receipt.get('backend') != BACKEND_NAME or receipt.get('abi_version') != 1 or
                receipt.get('field_order') != FIELD_ORDER or
                receipt.get('clock_sequence') != CLOCK_SEQUENCE or
                receipt.get('units') != 'nanoseconds' or receipt.get('atomic') is not False or
                receipt.get('retries') != 0 or receipt.get('filters') is not False):
            raise RuntimeError('RAW reader receipt contract mismatch')
        for path_key, hash_key in [('source', 'source_sha256'), ('library', 'library_sha256'),
                                   ('compiler', 'compiler_sha256')]:
            if sha256_file(receipt[path_key]) != receipt[hash_key]:
                raise RuntimeError(f'RAW reader {path_key} hash mismatch')
        if Path(receipt['library']).resolve() != library:
            raise RuntimeError('RAW reader receipt library path mismatch')
        if sha256_file(library.parent / 'compile.json') != receipt['compile_sha256']:
            raise RuntimeError('RAW reader compile receipt hash mismatch')
        self.provenance = dict(receipt, receipt_sha256=sha256_file(library.parent / 'receipt.json'),
            input_sha256={str(Path(__file__).resolve()): sha256_file(__file__),
                str(Path(receipt['source']).resolve()): receipt['source_sha256'],
                str(library): receipt['library_sha256'],
                str(Path(receipt['compiler']).resolve()): receipt['compiler_sha256'],
                str(library.parent / 'receipt.json'): sha256_file(library.parent / 'receipt.json'),
                str(library.parent / 'compile.json'): receipt['compile_sha256']})
        self._library = ctypes.CDLL(str(library), use_errno=True)
        self._library.raw_clock_abi_version.argtypes = []
        self._library.raw_clock_abi_version.restype = ctypes.c_int
        if self._library.raw_clock_abi_version() != 1:
            raise RuntimeError('RAW reader native ABI mismatch')
        self._library.read_raw_clock_bracket.argtypes = [ctypes.POINTER(ctypes.c_int64)]
        self._library.read_raw_clock_bracket.restype = ctypes.c_int

    def read(self):
        values = (ctypes.c_int64 * 5)()
        error = self._library.read_raw_clock_bracket(values)
        if error:
            raise OSError(error, 'Native RAW clock read failed')
        return tuple(values)


def _row(value):
    if len(value) != 5 or any(type(item) is not int for item in value):
        raise ValueError('Clock observation requires five integer nanosecond fields')
    return tuple(value)


class RawClockAudit:
    """Measurement-window continuity/instrumentation gates, not absolute rate."""
    def __init__(self, bracket_reader=None):
        self.bracket_reader = bracket_reader
        self.samples = []

    def sample(self):
        if self.bracket_reader is None:
            raise RuntimeError('Native RAW bracket reader required')
        self.observe(*self.bracket_reader())

    def observe(self, *values):
        self.samples.append(_row(values))

    def report(self, start_raw_ns=None, end_raw_ns=None):
        if (start_raw_ns is None) != (end_raw_ns is None):
            raise ValueError('Both RAW window endpoints are required')
        if start_raw_ns is not None and end_raw_ns <= start_raw_ns:
            raise ValueError('RAW window must have positive duration')
        rows = list(self.samples)
        if start_raw_ns is not None and rows:
            # Retain the immediately surrounding observations to assess edge gaps.
            before = [i for i, row in enumerate(rows) if row[4] <= start_raw_ns]
            after = [i for i, row in enumerate(rows) if row[0] >= end_raw_ns]
            first = before[-1] if before else 0
            last = after[0] if after else len(rows) - 1
            selected = rows[first:last + 1]
            covered = bool(before and after)
        else:
            selected, covered = rows, start_raw_ns is None
        reasons = []
        brackets = [row[4] - row[0] for row in rows]
        measured_brackets = [row[4] - row[0] for row in selected]
        mono_brackets = [row[3] - row[1] for row in selected]
        gaps = [b[4] - a[4] for a, b in zip(selected, selected[1:])]
        raw_regressions = sum(b[0] < a[4] for a, b in zip(rows, rows[1:]))
        within = sum(row[4] < row[0] for row in rows)
        if len(selected) < 2:
            reasons.append('insufficient_raw_audit_samples')
        if not covered:
            reasons.append('raw_audit_missing_window_brackets')
        if any(value < 0 or value > MAX_BRACKET_NS for value in brackets):
            reasons.append('raw_clock_read_bracket_over_100us_or_regressed')
        if any(value > MAX_GAP_NS for value in gaps):
            reasons.append('raw_clock_sample_gap_over_25ms')
        if raw_regressions or within:
            reasons.append('raw_clock_regression')
        real_steps, mono_steps = [], []
        for index, (a, b) in enumerate(zip(selected, selected[1:]), 1):
            raw_elapsed = ((b[0] + b[4]) - (a[0] + a[4])) / 2
            real_step = b[2] - a[2] - raw_elapsed
            mono_step = ((b[1] + b[3]) - (a[1] + a[3])) / 2 - raw_elapsed
            if abs(real_step) >= STEP_NS:
                real_steps.append({'selected_sample_index': index, 'realtime_minus_raw_step_ns': real_step})
            if abs(mono_step) >= STEP_NS:
                mono_steps.append({'selected_sample_index': index, 'monotonic_minus_raw_step_ns': mono_step})
        return {
            'valid': not reasons, 'reasons': reasons, 'clock': 'CLOCK_MONOTONIC_RAW',
            'clock_bracket_backend': BACKEND_NAME, 'field_order': FIELD_ORDER,
            'sample_count': len(rows), 'measured_window_samples': len(selected),
            'samples': [list(row) for row in rows], 'measured_window_covered': covered,
            'measurement_start_raw_ns': start_raw_ns, 'measurement_end_raw_ns': end_raw_ns,
            'maximum_read_bracket_ns': max(brackets, default=0),
            'measured_window_maximum_read_bracket_ns': max(measured_brackets, default=0),
            'maximum_monotonic_read_bracket_ns_diagnostic': max(mono_brackets, default=0),
            'maximum_sample_gap_ns': max(gaps, default=0),
            'raw_regressions': raw_regressions, 'raw_within_sample_regressions': within,
            'realtime_minus_raw_steps_diagnostic': real_steps,
            'monotonic_minus_raw_steps_diagnostic': mono_steps,
            'realtime_regressions_diagnostic': sum(b[2] < a[2] for a, b in zip(selected, selected[1:])),
            'monotonic_regressions_diagnostic': sum(b[3] < a[3] for a, b in zip(selected, selected[1:])),
            'absolute_rate_qualified': False,
            'limits': {'maximum_read_bracket_ns': MAX_BRACKET_NS,
                       'maximum_sample_gap_ns': MAX_GAP_NS, 'sample_period_seconds': SAMPLE_SECONDS},
            'diagnostic_clock_events_are_not_discarded': True,
        }


def rate_bounds(local0, local1, reference0, reference1):
    """Conservative interval arithmetic, with no symmetric-network assumption."""
    local_delta = (local1[0] - local0[1], local1[1] - local0[0])
    ref_delta = (reference1[0] - reference0[1], reference1[1] - reference0[0])
    if min(local_delta[0], ref_delta[0]) <= 0:
        raise ValueError('Non-positive elapsed-time lower bound')
    lower = 1e6 * (local_delta[0] / ref_delta[1] - 1)
    upper = 1e6 * (local_delta[1] / ref_delta[0] - 1)
    estimate = 1e6 * (((sum(local1) - sum(local0)) /
                       (sum(reference1) - sum(reference0))) - 1)
    return {'midpoint_estimate_ppm': estimate, 'lower_ppm': lower, 'upper_ppm': upper,
            'reference_elapsed_lower_seconds': ref_delta[0] / 1e9,
            'reference_elapsed_upper_seconds': ref_delta[1] / 1e9,
            'within_1000ppm': lower >= -RATE_BUDGET_PPM and upper <= RATE_BUDGET_PPM,
            'outside_1000ppm': upper < -RATE_BUDGET_PPM or lower > RATE_BUDGET_PPM,
            'uncertainty_interval_is_not_a_confidence_interval': True}


def _ntp_stamp(value):
    seconds, fraction = struct.unpack('!II', value)
    return (seconds - NTP_EPOCH) * 10**9 + fraction * 10**9 // 2**32


def parse_ntp(data, request_stamp):
    if len(data) < 48:
        raise ValueError('Short NTP reply')
    leap, version, mode = data[0] >> 6, (data[0] >> 3) & 7, data[0] & 7
    if leap == 3 or version not in (3, 4) or mode != 4:
        raise ValueError('Unsynchronized or invalid NTP reply')
    if not 1 <= data[1] <= 15:
        raise ValueError('Invalid stratum or Kiss-of-Death reply')
    if data[24:32] != request_stamp:
        raise ValueError('NTP originate nonce mismatch')
    root_delay = struct.unpack('!i', data[4:8])[0] / 65536
    dispersion = struct.unpack('!I', data[8:12])[0] / 65536
    precision = 2.0 ** struct.unpack('!b', data[3:4])[0]
    error = math.ceil((abs(root_delay) / 2 + dispersion + precision) * 1e9) + 1
    t2, t3 = _ntp_stamp(data[32:40]), _ntp_stamp(data[40:48])
    if t3 < t2 or not 1577836800 * 10**9 <= t2 <= t3 < 2082758400 * 10**9:
        raise ValueError('Invalid server timestamps or unsupported NTP era')
    return {'server_receive_ns': t2, 'server_transmit_ns': t3,
            'advertised_error_bound_ns': error, 'root_delay_seconds': root_delay,
            'root_dispersion_seconds': dispersion, 'precision_seconds': precision,
            'leap': leap, 'version': version, 'stratum': data[1],
            'reference_id_hex': data[12:16].hex()}


def resolve_ipv4(provider):
    """Bound DNS as well as UDP: a hung resolver cannot extend the calibration."""
    code = ('import json,socket,sys; print(json.dumps(sorted({x[4][0] for x in '
            'socket.getaddrinfo(sys.argv[1],123,socket.AF_INET,socket.SOCK_DGRAM)})))')
    result = subprocess.run([sys.executable, '-c', code, provider],
                            capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise RuntimeError(f'DNS failed: {result.stderr.strip()}')
    addresses = json.loads(result.stdout)
    if not addresses:
        raise RuntimeError('No IPv4 NTP address')
    for address in addresses:
        socket.inet_pton(socket.AF_INET, address)
    return addresses[0], addresses


def network_query(provider, address, reader, query_index):
    record = {'provider': provider, 'address': address, 'query_index': query_index}
    try:
        request = bytearray(48)
        request[0] = 0x23
        # Echo nonce only: no server/client timestamp arithmetic depends on this.
        stamp = os.urandom(8)
        request[40:48] = stamp
        record['request_hex'] = request.hex()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(NETWORK_QUERY_TIMEOUT_SECONDS)
            sock.connect((address, 123))
            record['before'] = list(_row(reader()))
            if sock.send(request) != 48:
                raise RuntimeError('Short SNTP request send')
            data = sock.recv(2048)
            record['response_hex'] = data.hex()
            record['after'] = list(_row(reader()))
        record.update(parse_ntp(data, stamp))
        record.update(valid=True,
                      raw_request_response_interval_ns=record['after'][4] - record['before'][0])
        record['query_brackets_valid'] = all(
            0 <= record[key][4] - record[key][0] <= MAX_BRACKET_NS for key in ('before', 'after'))
    except Exception as error:
        record.update(valid=False, error=f'{type(error).__name__}: {error}')
    return record


def qualification_report(records, providers=PROVIDERS, start_raw_ns=None,
                         end_raw_ns=None, load_windows=None):
    """No pooling across providers and no optimal query pair selection."""
    windows = list(load_windows or [])
    maximum_load = max((window.get('target_pps', 0) for window in windows), default=0)
    representative = [window for window in windows if window.get('target_pps', 0) == maximum_load]
    reports, states = {}, []
    for provider in providers:
        items = [record for record in records if record['provider'] == provider]
        usable = [record for record in items if record.get('valid') and record.get('query_brackets_valid')]
        reasons = []
        report = {'queries': len(items), 'valid_queries': len(usable),
                  'failed_queries': sum(not record.get('valid', False) for record in items),
                  'invalid_bracket_queries': sum(record.get('valid', False) and
                                                not record.get('query_brackets_valid', False) for record in items),
                  'query_exclusions': [{'query_index': record.get('query_index'),
                                       'reason': record.get('error', 'query_bracket_over_100us_or_regressed')}
                                      for record in items if record not in usable]}
        if len(usable) < MIN_QUERIES_PER_PROVIDER:
            reasons.append('fewer_than_three_valid_queries')
        if report['failed_queries']:
            reasons.append('one_or_more_reference_acquisitions_failed')
        loaded = [record for record in usable if any(
            record['before'][0] >= window['start_raw_ns'] and
            record['after'][4] <= window['end_raw_ns'] for window in representative)]
        report['representative_load_queries'] = len(loaded)
        if not loaded:
            reasons.append('no_valid_query_bracketed_inside_a_measured_load_window')
        if report['invalid_bracket_queries']:
            reasons.append('one_or_more_native_query_brackets_failed_100us_gate')
        if len(usable) >= 2:
            # Chronological first/last, not minimum RTT or best accuracy samples.
            first, last = usable[0], usable[-1]
            local0, local1 = [first['before'][0], first['after'][4]], [last['before'][0], last['after'][4]]
            ref0 = [first['server_transmit_ns'] - first['advertised_error_bound_ns'],
                    first['server_transmit_ns'] + first['advertised_error_bound_ns']]
            ref1 = [last['server_transmit_ns'] - last['advertised_error_bound_ns'],
                    last['server_transmit_ns'] + last['advertised_error_bound_ns']]
            report['first_query_index'], report['last_query_index'] = first['query_index'], last['query_index']
            report['campaign_covered'] = (
                start_raw_ns is not None and end_raw_ns is not None and
                first['after'][4] <= start_raw_ns and last['before'][0] >= end_raw_ns)
            if not report['campaign_covered']:
                reasons.append('reference_endpoints_do_not_bracket_measured_campaign')
            try:
                bounds = rate_bounds(local0, local1, ref0, ref1)
                report['raw_rate'] = bounds
                if bounds['reference_elapsed_lower_seconds'] < MIN_REFERENCE_SPAN_SECONDS:
                    reasons.append('reference_span_under_180_seconds')
                if not reasons and bounds['outside_1000ppm']:
                    report['status'] = 'FAIL'
                elif not reasons and bounds['within_1000ppm']:
                    report['status'] = 'PASS'
                else:
                    report['status'] = 'INCONCLUSIVE'
                    if not bounds['within_1000ppm']:
                        reasons.append('uncertainty_interval_not_contained_within_1000ppm')
            except ValueError as error:
                reasons.append(str(error))
        report.setdefault('status', 'INCONCLUSIVE')
        report['reasons'] = reasons
        reports[provider] = report
        states.append(report['status'])
    status = 'PASS' if states and all(state == 'PASS' for state in states) else (
        'FAIL' if 'FAIL' in states else 'INCONCLUSIVE')
    return {'status': status, 'valid': status == 'PASS', 'passed': status == 'PASS', 'providers': reports,
            'queries': list(records), 'criterion_ppm': RATE_BUDGET_PPM,
            'minimum_reference_span_seconds': MIN_REFERENCE_SPAN_SECONDS,
            'minimum_valid_queries_per_provider': MIN_QUERIES_PER_PROVIDER,
            'network_query_timeout_seconds': 2, 'provider_addresses_pinned': True,
            'representative_load_target_pps': maximum_load,
            'measured_window_query_counts': [dict(window,
                complete_query_count=sum(record.get('valid', False) and
                    record['before'][0] >= window['start_raw_ns'] and
                    record['after'][4] <= window['end_raw_ns'] for record in records))
                for window in windows],
            'reference_queries_can_consume_runner_cpu_and_network_during_trials': True,
            'reference_assumptions': 'Unauthenticated server UTC; advertised root-distance uncertainty plus entire local request/response interval. No network symmetry assumed.',
            'uncertainty_intervals_are_not_statistical_confidence_intervals': True,
            'traceable_si_calibration': False, 'previous_qualification_not_reused': True,
            'clock_or_synchronization_configuration_modified': False}


class RateQualification:
    """Bounded, query-only worker with explicit measured-load scheduling hints.

    Notifications do not acquire references or block the sender. They queue a
    RAW-deadline request for this worker. The declared interval is only a hint:
    qualification_report still checks complete query brackets against actual,
    instrument-valid measurement windows supplied by the campaign runner.
    """
    def __init__(self, reader, interval_seconds=30, providers=PROVIDERS):
        if not 30 <= interval_seconds <= 65:
            raise ValueError('Reference interval must be between 30 and 65 seconds')
        self.reader = reader
        self.interval_seconds = interval_seconds
        self.providers = tuple(providers)
        self.records, self.pins = [], {}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._ready = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._error = None
        self._window_requests = []

    def notify_measurement_window(self, start_raw_ns, end_raw_ns, target_pps,
                                  *, mode=None, workload=None):
        """Queue one bounded provider round; never run DNS/network in caller.

        The worker aims two RAW seconds into the declared measurement window.
        Two seconds remain at its end in addition to the full timeout budget
        for each provider. Supported relative event waits only wake the worker;
        every scheduling decision rechecks the uncorrected RAW clock.
        """
        if (type(start_raw_ns) is not int or type(end_raw_ns) is not int or
                type(target_pps) is not int or start_raw_ns < 0 or target_pps <= 0):
            raise ValueError('Measured-load notification requires positive integer RAW endpoints/rate')
        budget = len(self.providers) * NETWORK_QUERY_TIMEOUT_SECONDS * 10**9
        due = start_raw_ns + LOAD_QUERY_OFFSET_NS
        latest = end_raw_ns - budget - LOAD_QUERY_END_MARGIN_NS
        if latest < due:
            raise ValueError('Measured-load window too short for bounded reference acquisition')
        if self._thread is None or not self._ready.is_set() or self._stop.is_set():
            raise RuntimeError('Measured-load notification requires an active, ready rate qualifier')
        with self._lock:
            if any(item['start_raw_ns'] == start_raw_ns and item['end_raw_ns'] == end_raw_ns
                   for item in self._window_requests):
                raise ValueError('Measured-load window already notified')
            identifier = len(self._window_requests) + 1
            self._window_requests.append({
                'schedule_id': identifier, 'start_raw_ns': start_raw_ns,
                'end_raw_ns': end_raw_ns, 'target_pps': target_pps,
                'mode': mode, 'workload': workload, 'due_raw_ns': due,
                'latest_round_start_raw_ns': latest, 'status': 'pending',
                'notification_is_only_a_scheduling_hint': True})
        self._wake.set()
        return identifier

    def _next_work(self, now_raw_ns, next_query_raw_ns):
        """Deterministic dispatch; no catch-up storms or stale load rounds."""
        with self._lock:
            pending = [item for item in self._window_requests if item['status'] == 'pending']
            for item in pending:
                if now_raw_ns > item['latest_round_start_raw_ns']:
                    item.update(status='not_acquired',
                        reason='worker_missed_bounded_in_window_query_start',
                        observed_raw_ns=now_raw_ns)
            pending = sorted((item for item in pending if item['status'] == 'pending'),
                             key=lambda item: item['due_raw_ns'])
            if pending and now_raw_ns >= pending[0]['due_raw_ns']:
                request = pending[0]
                request.update(status='acquiring', actual_round_start_raw_ns=now_raw_ns)
                return 'measurement_window', request
            # Reserve the single worker when an imminent load query could be
            # delayed by a full autonomous provider round. Do not run both.
            reserve_ns = (len(self.providers) * NETWORK_QUERY_TIMEOUT_SECONDS * 10**9 +
                          LOAD_QUERY_END_MARGIN_NS)
            if (now_raw_ns >= next_query_raw_ns and not
                    (pending and pending[0]['due_raw_ns'] <= now_raw_ns + reserve_ns)):
                return 'periodic', None
        return 'wait', None

    def _round(self, index, final=False, kind='periodic', window_request=None):
        for provider, pin in self.pins.items():
            if self._stop.is_set() and not final:
                break
            record = network_query(provider, pin['address'], self.reader, index)
            record['acquisition_kind'] = kind
            if window_request is not None:
                record['requested_measurement_schedule_id'] = window_request['schedule_id']
                record['requested_target_pps'] = window_request['target_pps']
            with self._lock:
                self.records.append(record)

    def _worker(self):
        try:
            for provider in self.providers:
                try:
                    address, candidates = resolve_ipv4(provider)
                    self.pins[provider] = {'address': address, 'dns_candidates': candidates}
                except Exception as error:
                    with self._lock:
                        self.records.append({'provider': provider, 'query_index': -1,
                                             'valid': False, 'error': f'DNS: {error}'})
            self._round(0, kind='initial')
            self._ready.set()
            index = 1
            next_query = self.reader()[4] + int(self.interval_seconds * 1e9)
            while not self._stop.is_set():
                self._wake.clear()
                work, request = self._next_work(self.reader()[4], next_query)
                if work != 'wait':
                    self._round(index, kind=work, window_request=request)
                    round_end = self.reader()[4]
                    if request is not None:
                        with self._lock:
                            request.update(status='acquired', query_index=index,
                                           actual_round_end_raw_ns=round_end)
                    index += 1
                    # Do not produce catch-up query storms after a delayed round.
                    next_query = round_end + int(self.interval_seconds * 1e9)
                self._wake.wait(0.1)
            self._round(index, final=True, kind='final')
        except Exception as error:
            self._error = f'{type(error).__name__}: {error}'
            self._ready.set()

    def start(self):
        if self._thread is not None:
            raise RuntimeError('Rate qualifier is single-use')
        self._thread = threading.Thread(target=self._worker, name='raw-reference-qualification', daemon=True)
        self._thread.start()
        if not self._ready.wait(25):
            self._stop.set()
            raise RuntimeError('Bounded initial reference acquisition did not complete')
        if self._error:
            raise RuntimeError(self._error)
        return self

    def stop(self):
        if self._thread is None:
            raise RuntimeError('Rate qualifier was not started')
        self._stop.set()
        self._wake.set()
        # At most one in-flight 2 s query plus the three final 2 s queries.
        self._thread.join(9)
        if self._thread.is_alive():
            self._error = 'Bounded final reference acquisition did not complete'

    def report(self, start_raw_ns=None, end_raw_ns=None, load_windows=None):
        with self._lock:
            records = list(self.records)
            schedules = [dict(item) for item in self._window_requests]
        report = qualification_report(records, self.providers, start_raw_ns, end_raw_ns, load_windows)
        report['pinned_references'] = dict(self.pins)
        report['interval_seconds'] = self.interval_seconds
        report['worker_error'] = self._error
        report['worker_finished'] = self._thread is not None and not self._thread.is_alive()
        report['measurement_query_schedule'] = schedules
        report['reference_scheduling'] = {
            'method': 'explicit measurement notifications plus autonomous initial/periodic/final rounds',
            'deadline_clock': 'CLOCK_MONOTONIC_RAW',
            'relative_wait_clock_is_only_a_wake_hint': True,
            'load_round_offset_ns': LOAD_QUERY_OFFSET_NS,
            'load_round_end_margin_ns': LOAD_QUERY_END_MARGIN_NS,
            'per_provider_timeout_seconds': NETWORK_QUERY_TIMEOUT_SECONDS,
            'worker_scheduling_recheck_wait_seconds': 0.1,
            'periodic_round_deferred_for_imminent_load_round': True,
            'periodic_deadline_reset_after_each_completed_round': True,
            'all_acquisition_results_retained': True,
            'notified_windows_do_not_replace_actual_valid_measurement_windows': True}
        if self._error or not report['worker_finished']:
            report.update(status='INCONCLUSIVE', valid=False, passed=False)
        return report
