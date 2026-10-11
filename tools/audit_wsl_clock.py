#!/usr/bin/env python3
"""Read-only Linux/WSL clock evidence; no traffic or performance measurement.

Use the existing benchmark_transport.ClockAudit without changing its gates.
The only timed sampling work is bracketing CLOCK_REALTIME with MONOTONIC and
sleeping to independent 5 ms monotonic deadlines. Context snapshots, commands,
hashing and artifact writes occur outside the measured sampling window.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import uuid


DEFAULT_SECONDS = 180
MIN_SECONDS = 32
MAX_SECONDS = 600
SAMPLE_INTERVAL_NS = 5_000_000
PROGRESS_INTERVAL_NS = 30_000_000_000
OFFSET_STEP_NS = 1_000_000
EXPECTED_GATES = {
    'CLOCK_SAMPLE_SECONDS': .005,
    'MAX_CLOCK_GAP_NS': 25_000_000,
    'MAX_CLOCK_BRACKET_NS': 100_000,
    'CLOCK_STEP_TOLERANCE_NS': OFFSET_STEP_NS,
}
SNAPSHOT_FILES = {
    'boot_id': '/proc/sys/kernel/random/boot_id',
    'current_clocksource': '/sys/devices/system/clocksource/clocksource0/current_clocksource',
    'available_clocksources': '/sys/devices/system/clocksource/clocksource0/available_clocksource',
    'timesync_implicit': '/sys/module/hv_utils/parameters/timesync_implicit',
    'cmdline': '/proc/cmdline',
    'os_release': '/etc/os-release',
}
SERVICE_PROPERTIES = ('ActiveState', 'SubState', 'UnitFileState', 'MainPID')
LIMITATIONS = [
    'Periodic userspace sampling cannot exclude a step and reversal between samples.',
    'This is temporal clock evidence, not a performance or packet-delivery result.',
    'No raw sockets, BMv2, interfaces, service changes or clock changes are used.',
    'No kernel packet timestamp behavior is validated by this audit.',
    'Before/after context snapshots cannot exclude transient context changes between snapshots.',
    'Artifact hashes detect changes relative to the seal; the seal is not externally signed.',
]


def validate_config(seconds, label):
    if (type(seconds) not in (int, float) or not math.isfinite(seconds)
            or not MIN_SECONDS <= seconds <= MAX_SECONDS):
        raise ValueError('seconds must be finite and in [32, 600]')
    if (not isinstance(label, str) or not label.strip() or len(label) > 128
            or not label.isprintable()):
        raise ValueError('label must contain readable text, with no control characters, at most 128 characters')


def write_json(path, value):
    """Exclusive creation protects every previous artifact from overwrite."""
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def new_directory(output_root, label):
    root = Path(output_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r'[^A-Za-z0-9._-]+', '-', label.strip()).strip('.-')[:48] or 'audit'
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    directory = root / f'{stamp}_{slug}_{uuid.uuid4().hex}'
    directory.mkdir()  # No exist_ok: even an unexpected collision is refused.
    return directory


def read_snapshot_file(path):
    try:
        return {'path': path, 'value': Path(path).read_text(encoding='utf-8'), 'error': None}
    except (OSError, UnicodeError) as error:
        return {'path': path, 'value': None, 'error': f'{type(error).__name__}: {error}'}


def readonly_command(argv):
    """These fixed callers use no shell, mutations or privileged operations."""
    environment = dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='cat')
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=10, env=environment, check=False)
        return {'argv': argv, 'returncode': result.returncode,
                'stdout': result.stdout, 'stderr': result.stderr,
                'error': None, 'skipped': False}
    except (OSError, subprocess.SubprocessError) as error:
        def decoded(value):
            return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else (value or '')
        return {'argv': argv, 'returncode': None,
                'stdout': decoded(getattr(error, 'stdout', '')),
                'stderr': decoded(getattr(error, 'stderr', '')),
                'error': f'{type(error).__name__}: {error}', 'skipped': False}


def skipped_command(argv, reason):
    return {'argv': argv, 'returncode': None, 'stdout': '', 'stderr': '',
            'error': None, 'skipped': True, 'skip_reason': reason}


def parse_service_properties(command):
    if command.get('returncode') != 0:
        return {}
    parsed = {}
    for line in command.get('stdout', '').splitlines():
        key, separator, value = line.partition('=')
        if separator and key in SERVICE_PROPERTIES:
            parsed[key] = value
    return parsed


def collect_snapshot():
    """Observe context outside brackets, never activate an inactive timesyncd.

    timesyncd is D-Bus activatable. timedatectl show-timesync can start a stopped
    daemon, so both timedatectl observations are skipped unless systemctl's
    preceding read establishes exactly ActiveState=active. Missing/failed
    observations remain explicit unknowns, not inferred inactive states.
    """
    snapshot = {
        'captured_utc': datetime.now(timezone.utc).isoformat(),
        'kernel': platform.uname()._asdict(),
        'files': {name: read_snapshot_file(path) for name, path in SNAPSHOT_FILES.items()},
    }
    service_argv = ['systemctl', 'show', 'systemd-timesyncd.service', '--no-pager']
    service_argv.extend('--property=' + name for name in SERVICE_PROPERTIES)
    service = readonly_command(service_argv)
    properties = parse_service_properties(service)
    show_argv = ['timedatectl', 'show-timesync', '--all']
    status_argv = ['timedatectl', 'status']
    if properties.get('ActiveState') == 'active':
        show = readonly_command(show_argv)
        status = readonly_command(status_argv)
    else:
        reason = 'Skipped to avoid D-Bus activation: systemd-timesyncd was not established active'
        show = skipped_command(show_argv, reason)
        status = skipped_command(status_argv, reason)
    snapshot['commands'] = {'systemctl_show_timesyncd': service,
                            'timedatectl_show_timesync': show,
                            'timedatectl_status': status}
    snapshot['timesyncd_properties'] = properties
    return snapshot


def compare_context(before, after):
    """Compare stable identity/state fields; retain unavailable observations."""
    before, after = before or {}, after or {}
    changes, unavailable = [], []
    fields = {}
    for name in ('boot_id', 'current_clocksource', 'timesync_implicit', 'cmdline'):
        fields[name] = tuple(snap.get('files', {}).get(name, {}).get('value')
                             for snap in (before, after))
    for name in ('release', 'version'):
        fields['kernel.' + name] = tuple(snap.get('kernel', {}).get(name)
                                         for snap in (before, after))
    for name in SERVICE_PROPERTIES:
        fields['timesyncd.' + name] = tuple(snap.get('timesyncd_properties', {}).get(name)
                                           for snap in (before, after))
    for name, (old, new) in fields.items():
        if old is None or new is None:
            unavailable.append(name)
        elif old.strip() != new.strip():
            changes.append({'field': name, 'before': old.strip(), 'after': new.strip()})
    return {'changed': bool(changes), 'changes': changes,
            'comparison_complete': not unavailable, 'unavailable_fields': unavailable,
            'context_matches': False if changes else (None if unavailable else True),
            'scope': 'Boot, kernel, current clocksource, Hyper-V parameter, cmdline and timesyncd service properties'}


def summarize_steps(samples):
    """Adjacent discontinuities differ from samples changed from the reference.

    Twice each offset midpoint keeps all comparisons exact at epoch-sized
    offsets; division by two only affects the small final reported deltas.
    Adjacent jumps are observations, not proof of an exact number of clock
    correction operations. Slewing can also change the offset.
    """
    jumps = []
    maximum_step_twice = None
    maximum_backward = 0
    monotonic_regressions = 0
    realtime_regressions = 0
    for index, (previous, current) in enumerate(zip(samples, samples[1:]), 1):
        prior_offset = previous['offset_low_ns'] + previous['offset_high_ns']
        current_offset = current['offset_low_ns'] + current['offset_high_ns']
        step_twice = current_offset - prior_offset
        maximum_step_twice = max(maximum_step_twice or 0, abs(step_twice))
        wall_delta = current['realtime_ns'] - previous['realtime_ns']
        if wall_delta < 0:
            realtime_regressions += 1
            maximum_backward = max(maximum_backward, -wall_delta)
        if current['monotonic_before_ns'] < previous['monotonic_before_ns']:
            monotonic_regressions += 1
        if abs(step_twice) >= 2 * OFFSET_STEP_NS:
            jumps.append({'previous_sample_index': index - 1, 'sample_index': index,
                          'offset_step_ns': step_twice / 2,
                          'realtime_delta_ns': wall_delta,
                          'monotonic_delta_ns': current['monotonic_before_ns'] - previous['monotonic_before_ns']})
    return {
        'maximum_absolute_adjacent_offset_step_ns': maximum_step_twice / 2 if maximum_step_twice is not None else None,
        'largest_backward_adjacent_realtime_ns': maximum_backward,
        'adjacent_realtime_regression_count': realtime_regressions,
        'monotonic_regression_count': monotonic_regressions,
        'within_sample_monotonic_regression_count': sum(row['monotonic_after_ns'] < row['monotonic_before_ns'] for row in samples),
        'adjacent_offset_jump_threshold_ns': OFFSET_STEP_NS,
        'adjacent_offset_jump_count': len(jumps),
        'adjacent_offset_jumps': jumps,
        'count_meaning': 'Adjacent jumps at or above 1 ms; distinct from samples differing from the initial reference interval',
    }


def load_clock_audit():
    benchmark = importlib.import_module('benchmark_transport')
    for name, expected in EXPECTED_GATES.items():
        if getattr(benchmark, name, None) != expected:
            raise RuntimeError(f'Existing benchmark clock gate differs: {name}; refusing to relax it')
    return benchmark.ClockAudit


def source_provenance(audit_factory):
    paths = {str(Path(__file__).resolve())}
    for cls in audit_factory.__mro__:
        module = sys.modules.get(cls.__module__)
        path = getattr(module, '__file__', None)
        if path:
            paths.add(str(Path(path).resolve()))
    return [{'path': path, 'sha256': sha256_file(path)} for path in sorted(paths)]


def sample_clock(audit, clock, raw_samples, bracket_reader=None):
    if bracket_reader is None:
        before = clock.monotonic_ns()
        wall = clock.time_ns()
        after = clock.monotonic_ns()
    else:
        before, wall, after = bracket_reader()
    row = {'monotonic_before_ns': before, 'realtime_ns': wall,
           'monotonic_after_ns': after,
           'offset_low_ns': wall - after, 'offset_high_ns': wall - before}
    # Preserve even an invalid bracket that the existing observe() rejects.
    raw_samples.append(row)
    audit.observe(before, wall, after)


def seal_artifacts(directory):
    artifacts = {}
    for path in sorted(Path(directory).iterdir()):
        if path.is_file() and not path.is_symlink():
            artifacts[path.name] = {'sha256': sha256_file(path), 'size_bytes': path.stat().st_size}
    write_json(Path(directory) / 'seal.json', {
        'algorithm': 'SHA-256', 'artifacts': artifacts,
        'scope': 'All preceding artifacts in this unique directory; seal.json excludes itself',
    })


def verify_artifact_seal(directory):
    """Pure/local verification, useful before comparing separate audit runs."""
    directory = Path(directory)
    seal = json.loads((directory / 'seal.json').read_text(encoding='utf-8'))
    expected = seal['artifacts']
    actual = {path.name for path in directory.iterdir() if path.name != 'seal.json'}
    if actual != set(expected):
        return False
    for name, entry in expected.items():
        if Path(name).name != name or name in ('.', '..'):
            return False
        path = directory / name
        if (path.is_symlink() or not path.is_file() or path.stat().st_size != entry['size_bytes']
                or sha256_file(path) != entry['sha256']):
            return False
    return True


def run_audit(seconds, label, output_root, *, clock=time, snapshot_fn=collect_snapshot,
              audit_factory=None, emit=print, bracket_reader=None):
    """Return (new evidence directory, exit code); preserve invalid/partial runs.

    Exit 0 means completed clock quality valid; 2 means completed but invalid;
    130 means interrupted and incomplete; 1 means another incomplete failure.
    Test hooks replace observations, never the production duration bounds.
    """
    validate_config(seconds, label)
    if sys.platform != 'linux':
        raise ValueError('Run this read-only clock audit in Linux/Ubuntu WSL; root is not required')
    factory = load_clock_audit() if audit_factory is None else audit_factory
    audit = factory(bracket_reader=bracket_reader) if bracket_reader is not None else factory()
    sources = source_provenance(factory)
    directory = new_directory(output_root, label)
    raw_samples = []
    before = after = None
    start_ns = target_end_ns = observed_end_ns = None
    complete = False
    failure = None
    exit_code = 1
    try:
        before = snapshot_fn()
        write_json(directory / 'snapshot_before.json', before)
        write_json(directory / 'provenance.json', {
            'schema_version': 1, 'label': label, 'requested_seconds': seconds,
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'sources': sources, 'python': sys.version, 'executable': sys.executable,
            'requested_sample_interval_ns': SAMPLE_INTERVAL_NS,
            'unchanged_benchmark_gates': EXPECTED_GATES,
            'root_required': False, 'performance_measured': False,
            'kernel_packet_timestamps_validated': False,
            'read_only_context_observation': True,
            'native_clock_reader': bracket_reader.provenance if bracket_reader is not None else None,
            'sampling_schedule': 'Sleep to 5 ms monotonic deadlines; skip missed deadlines without catch-up sampling',
            'limitations': LIMITATIONS,
        })
        emit(f'Clock audit {label!r}: {seconds:g}s, read-only; evidence {directory}')
        sample_clock(audit, clock, raw_samples, bracket_reader)  # Immediately BEFORE window start.
        start_ns = clock.monotonic_ns()
        target_end_ns = start_ns + round(seconds * 1_000_000_000)
        next_sample_ns = start_ns + SAMPLE_INTERVAL_NS
        next_progress_ns = start_ns + PROGRESS_INTERVAL_NS
        while True:
            now = clock.monotonic_ns()
            if now >= target_end_ns:
                observed_end_ns = now
                break
            deadline = min(next_sample_ns, target_end_ns)
            if now < deadline:
                clock.sleep((deadline - now) / 1_000_000_000)
                continue
            sample_clock(audit, clock, raw_samples, bracket_reader)
            now = clock.monotonic_ns()
            if now >= next_progress_ns:
                elapsed = (now - start_ns) // 1_000_000_000
                emit(f'{elapsed}s elapsed; {len(raw_samples)} clock samples retained')
                next_progress_ns = start_ns + ((now - start_ns) // PROGRESS_INTERVAL_NS + 1) * PROGRESS_INTERVAL_NS
            next_sample_ns = start_ns + ((now - start_ns) // SAMPLE_INTERVAL_NS + 1) * SAMPLE_INTERVAL_NS
        sample_clock(audit, clock, raw_samples, bracket_reader)  # Final bracket AFTER target end.
        complete = True
    except KeyboardInterrupt:
        failure = {'type': 'KeyboardInterrupt', 'message': 'Interrupted; requested interval is incomplete'}
        exit_code = 130
    except Exception as error:
        failure = {'type': type(error).__name__, 'message': str(error)}
    if observed_end_ns is None and start_ns is not None:
        try:
            observed_end_ns = clock.monotonic_ns()
        except Exception:
            observed_end_ns = raw_samples[-1]['monotonic_after_ns'] if raw_samples else None
    # Snapshot collection is after the last audit bracket, including failures.
    try:
        after = snapshot_fn()
    except KeyboardInterrupt:
        complete = False
        failure = failure or {'type': 'KeyboardInterrupt', 'message': 'Interrupted during after snapshot'}
        exit_code = 130
    except Exception as error:
        complete = False
        failure = failure or {'type': type(error).__name__, 'message': 'After snapshot failed: ' + str(error)}
    if not (directory / 'snapshot_before.json').exists():
        write_json(directory / 'snapshot_before.json', before or {'collection_failed': failure})
    if not (directory / 'provenance.json').exists():
        write_json(directory / 'provenance.json', {
            'schema_version': 1, 'label': label, 'requested_seconds': seconds,
            'sources': sources, 'initialization_failed': failure,
            'unchanged_benchmark_gates': EXPECTED_GATES, 'limitations': LIMITATIONS,
        })
    write_json(directory / 'snapshot_after.json', after or {'collection_failed': failure})
    report = audit.report(start_ns, target_end_ns)
    accepted_sample_count = len(audit.samples)
    report['samples'] = raw_samples
    report['clock_audit_accepted_sample_count'] = accepted_sample_count
    report['sample_gap_scope'] = 'Samples immediately bracketing the requested standalone clock audit interval'
    if not complete:
        report['valid'] = False
        report['reasons'].append('Requested clock audit interval or context collection incomplete')
    write_json(directory / 'audit.json', report)
    context = compare_context(before, after)
    reasons = list(report['reasons'])
    if context['changed']:
        reasons.append('Clock/boot/service context changed between before and after snapshots')
    if not context['comparison_complete']:
        reasons.append('Clock/boot/service identity could not be fully verified')
    quality_valid = complete and report['valid'] and context['context_matches'] is True
    if complete:
        exit_code = 0 if quality_valid else 2
    steps = summarize_steps(raw_samples)
    steps['samples_changed_from_initial_reference_interval_count'] = report['detected_offset_changes']
    bounds = {
        'first_sample_monotonic_before_ns': raw_samples[0]['monotonic_before_ns'] if raw_samples else None,
        'last_sample_monotonic_after_ns': raw_samples[-1]['monotonic_after_ns'] if raw_samples else None,
        'first_sample_realtime_ns': raw_samples[0]['realtime_ns'] if raw_samples else None,
        'last_sample_realtime_ns': raw_samples[-1]['realtime_ns'] if raw_samples else None,
        'window_start_monotonic_ns': start_ns,
        'requested_window_end_monotonic_ns': target_end_ns,
        'observed_window_end_monotonic_ns': observed_end_ns,
    }
    summary = {
        'schema_version': 1, 'label': label, 'requested_seconds': seconds,
        'clock_bracket_backend': 'linux-native-three-read-v1' if bracket_reader is not None else 'python-three-read-v1',
        'status': ('clock_quality_valid' if quality_valid else 'clock_quality_invalid') if complete else 'incomplete',
        'audit_complete': complete, 'clock_quality_valid': bool(quality_valid),
        'clock_quality_reasons': reasons, 'exit_code': exit_code, 'failure': failure,
        'performance_measured': False, 'kernel_packet_timestamps_validated': False,
        'sample_count': len(raw_samples), 'clock_bounds': bounds,
        'elapsed_monotonic_seconds': (observed_end_ns - start_ns) / 1e9 if start_ns is not None and observed_end_ns is not None else None,
        'raw_sample_monotonic_span_seconds': (raw_samples[-1]['monotonic_after_ns'] - raw_samples[0]['monotonic_before_ns']) / 1e9 if raw_samples else None,
        'raw_sample_realtime_span_seconds': (raw_samples[-1]['realtime_ns'] - raw_samples[0]['realtime_ns']) / 1e9 if raw_samples else None,
        'maximum_sample_gap_ns': report['maximum_sample_gap_ns'],
        'maximum_bracket_width_ns': report['maximum_bracket_width_ns'],
        'maximum_observed_offset_displacement_ns': report['maximum_observed_offset_displacement_ns'],
        'steps': steps, 'context_comparison': context, 'limitations': LIMITATIONS,
    }
    write_json(directory / 'summary.json', summary)
    seal_artifacts(directory)
    emit(f"Clock audit {summary['status']}; {len(raw_samples)} samples; adjacent jumps >=1 ms: {steps['adjacent_offset_jump_count']}; reference-changed samples: {report['detected_offset_changes']}; evidence {directory}")
    return directory, exit_code


def build_parser(repo=None):
    repo = Path(__file__).resolve().parent.parent if repo is None else Path(repo)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=float, default=DEFAULT_SECONDS,
                        help='Monotonic audit duration, 32..600 seconds (default 180)')
    parser.add_argument('--label', required=True, help='Readable label, e.g. baseline or after-runtime-change')
    parser.add_argument('--output-root', type=Path, default=repo / 'results' / 'wsl_clock_audit')
    parser.add_argument('--native-library', type=Path, help='Use a sealed native three-read clock collector without changing gates')
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_config(args.seconds, args.label)
    except ValueError as error:
        parser.error(str(error))
    try:
        if args.native_library:
            from native_clock_bracket import NativeClockBracket
            reader = NativeClockBracket(args.native_library)
        else:
            reader = None
        _, exit_code = run_audit(args.seconds, args.label, args.output_root, bracket_reader=reader)
        return exit_code
    except (ValueError, OSError, RuntimeError, ImportError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
