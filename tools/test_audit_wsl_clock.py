"""Pure/offline and fake-clock integration checks; no real waits or packets."""

import copy
import importlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


# Staging-only paths. Installed helpers are siblings of this new audit tool.
STAGING = Path(__file__).resolve().parents[1]
for directory in (STAGING / 'full_performance_benchmark',
                  STAGING / 'performance_benchmark' / 'transport'):
    if directory.is_dir():
        sys.path.insert(0, str(directory))
import audit_wsl_clock as tool


class NativeBracketTests(unittest.TestCase):
    def test_wide_native_bracket_is_retained_not_retried_or_filtered(self):
        class Audit:
            def observe(self, *values): self.values = values
        audit = Audit()
        rows = []
        reader = mock.Mock(return_value=(100, 1000000, 200100))
        tool.sample_clock(audit, mock.Mock(), rows, bracket_reader=reader)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(audit.values, (100,1000000,200100))
        self.assertEqual(rows[0]['monotonic_after_ns']-rows[0]['monotonic_before_ns'],200000)
import benchmark_transport


OFFSET = 1_700_000_000_000_000_000


def sample(mono, offset=OFFSET, width=100):
    wall = mono + offset
    return {'monotonic_before_ns': mono, 'realtime_ns': wall,
            'monotonic_after_ns': mono + width,
            'offset_low_ns': wall - mono - width, 'offset_high_ns': wall - mono}


def context(state='active'):
    return {'kernel': {'release': 'test-kernel', 'version': 'test-build'},
            'files': {name: {'value': value, 'error': None} for name, value in {
                'boot_id': 'boot-one\n', 'current_clocksource': 'hyperv_clocksource_tsc_page\n',
                'timesync_implicit': 'Y\n', 'cmdline': 'test commandline\n'}.items()},
            'timesyncd_properties': {'ActiveState': state, 'SubState': 'running' if state == 'active' else 'dead',
                                    'UnitFileState': 'enabled', 'MainPID': '123' if state == 'active' else '0'}}


class FakeClock:
    """Advance monotonic time only through reads/sleep; zero actual waiting."""
    def __init__(self, *, offset_change_ns=0, change_at_seconds=None,
                 interrupt_after_sleeps=None, first_sleep_delay_ns=0):
        self.now = 1_000_000_000
        self.base = self.now
        self.sleeps = []
        self.offset_change_ns = offset_change_ns
        self.change_at_seconds = change_at_seconds
        self.interrupt_after_sleeps = interrupt_after_sleeps
        self.first_sleep_delay_ns = first_sleep_delay_ns

    def monotonic_ns(self):
        value = self.now
        self.now += 100
        return value

    def time_ns(self):
        shifted = (self.change_at_seconds is not None
                   and self.now - self.base >= self.change_at_seconds * 1e9)
        return self.now + OFFSET + (self.offset_change_ns if shifted else 0)

    def sleep(self, seconds):
        if self.interrupt_after_sleeps is not None and len(self.sleeps) >= self.interrupt_after_sleeps:
            raise KeyboardInterrupt
        if seconds <= 0:
            raise AssertionError('Every sleep must be positive; no busy spin')
        self.sleeps.append(seconds)
        self.now += round(seconds * 1e9)
        if len(self.sleeps) == 1:
            self.now += self.first_sleep_delay_ns


class PureClockTests(unittest.TestCase):
    def test_one_step_is_distinct_from_many_reference_changed_samples(self):
        rows = [sample(i * 5_000_000, OFFSET - (800_000_000 if i >= 3 else 0)) for i in range(8)]
        audit = benchmark_transport.ClockAudit()
        for row in rows:
            audit.observe(row['monotonic_before_ns'], row['realtime_ns'], row['monotonic_after_ns'])
        report = audit.report()
        steps = tool.summarize_steps(rows)
        self.assertEqual(report['detected_offset_changes'], 5)
        self.assertEqual(steps['adjacent_offset_jump_count'], 1)
        self.assertEqual(steps['maximum_absolute_adjacent_offset_step_ns'], 800_000_000)
        self.assertEqual(steps['largest_backward_adjacent_realtime_ns'], 795_000_000)
        self.assertEqual(steps['adjacent_realtime_regression_count'], 1)
        self.assertEqual(steps['adjacent_offset_jumps'][0]['sample_index'], 3)
        self.assertEqual(steps['adjacent_offset_jumps'][0]['offset_step_ns'], -800_000_000)

    def test_exact_one_ms_and_integer_midpoints(self):
        rows = [sample(0), sample(5_000_000, OFFSET + 999_999),
                sample(10_000_000, OFFSET + 1_999_999)]
        steps = tool.summarize_steps(rows)
        self.assertEqual(steps['adjacent_offset_jump_count'], 1)
        self.assertEqual(steps['maximum_absolute_adjacent_offset_step_ns'], 1_000_000)
        self.assertEqual(steps['largest_backward_adjacent_realtime_ns'], 0)
        half = tool.summarize_steps([sample(0, width=100), sample(5_000_000, width=101)])
        self.assertEqual(half['maximum_absolute_adjacent_offset_step_ns'], .5)

    def test_empty_single_and_monotonic_regression(self):
        empty = tool.summarize_steps([])
        self.assertIsNone(empty['maximum_absolute_adjacent_offset_step_ns'])
        self.assertEqual(empty['adjacent_offset_jump_count'], 0)
        self.assertEqual(tool.summarize_steps([sample(0)])['adjacent_offset_jump_count'], 0)
        rows = [sample(100), sample(99, width=-1)]
        steps = tool.summarize_steps(rows)
        self.assertEqual(steps['monotonic_regression_count'], 1)
        self.assertEqual(steps['within_sample_monotonic_regression_count'], 1)

    def test_context_comparison_boot_and_service_changes(self):
        before = context()
        self.assertTrue(tool.compare_context(before, copy.deepcopy(before))['context_matches'])
        after = copy.deepcopy(before)
        after['files']['boot_id']['value'] = 'boot-two\n'
        after['timesyncd_properties']['ActiveState'] = 'inactive'
        comparison = tool.compare_context(before, after)
        self.assertTrue(comparison['changed'])
        self.assertFalse(comparison['context_matches'])
        self.assertEqual({row['field'] for row in comparison['changes']}, {'boot_id', 'timesyncd.ActiveState'})
        missing = tool.compare_context({}, before)
        self.assertFalse(missing['changed'])
        self.assertFalse(missing['comparison_complete'])
        self.assertIsNone(missing['context_matches'])

    def test_duration_and_labels_are_validated_before_artifact_creation(self):
        for seconds in (0, 31.999, 600.001, float('nan'), float('inf'), True, '32'):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                tool.validate_config(seconds, 'baseline')
        for label in ('', ' ', '\n', 'baseline\npost', '\x00', 'x' * 129, None):
            with self.subTest(label=label), self.assertRaises(ValueError):
                tool.validate_config(32, label)
        for seconds in (32, 180, 600):
            tool.validate_config(seconds, 'after runtime change')
        with mock.patch.object(tool, 'new_directory') as create:
            with self.assertRaises(ValueError):
                tool.run_audit(0, 'baseline', Path('unused'))
            create.assert_not_called()
        parser = tool.build_parser(Path('/repo'))
        args = parser.parse_args(['--label', 'baseline'])
        self.assertEqual(args.seconds, 180)
        self.assertEqual(args.output_root, Path('/repo/results/wsl_clock_audit'))

    def test_cli_zero_and_bad_label_exit_two_without_running(self):
        with mock.patch.object(tool, 'run_audit') as run, mock.patch('sys.stderr'):
            for args in (['--seconds', '0', '--label', 'baseline'], ['--label', ' ']):
                with self.assertRaises(SystemExit) as raised:
                    tool.main(args)
                self.assertEqual(raised.exception.code, 2)
            run.assert_not_called()

    def test_existing_gate_mismatch_is_refused(self):
        self.assertIs(tool.load_clock_audit(), benchmark_transport.ClockAudit)
        with mock.patch.object(benchmark_transport, 'MAX_CLOCK_GAP_NS', 26_000_000):
            with self.assertRaises(RuntimeError):
                tool.load_clock_audit()

    def test_import_never_creates_socket_or_process(self):
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('socket forbidden')) as sockets, \
                mock.patch.object(subprocess, 'run', side_effect=AssertionError('process forbidden')) as processes:
            importlib.reload(tool)
            sockets.assert_not_called()
            processes.assert_not_called()


class SnapshotTests(unittest.TestCase):
    def capture(self, active_state, returncode=0):
        stdout = f'ActiveState={active_state}\nSubState=dead\nUnitFileState=enabled\nMainPID=0\n'
        commands = []
        def command(argv):
            commands.append(argv)
            return {'argv': argv, 'returncode': returncode if argv[0] == 'systemctl' else 0,
                    'stdout': stdout if argv[0] == 'systemctl' else 'raw clock status\n',
                    'stderr': '', 'error': None, 'skipped': False}
        with mock.patch.object(tool, 'readonly_command', side_effect=command), \
                mock.patch.object(tool, 'read_snapshot_file', return_value={'value': 'read-only\n', 'error': None}):
            return tool.collect_snapshot(), commands

    def test_inactive_or_unknown_never_calls_timedatectl(self):
        for state, code in (('inactive', 0), ('failed', 0), ('active', 1), ('activating', 0)):
            with self.subTest(state=state, code=code):
                snapshot, commands = self.capture(state, code)
                self.assertEqual(len(commands), 1)
                self.assertEqual(commands[0][0:3], ['systemctl', 'show', 'systemd-timesyncd.service'])
                for name in ('timedatectl_show_timesync', 'timedatectl_status'):
                    self.assertTrue(snapshot['commands'][name]['skipped'])
                    self.assertIn('avoid D-Bus activation', snapshot['commands'][name]['skip_reason'])

    def test_active_records_raw_command_results(self):
        snapshot, commands = self.capture('active')
        self.assertEqual(commands[1:], [['timedatectl', 'show-timesync', '--all'], ['timedatectl', 'status']])
        self.assertEqual(snapshot['commands']['timedatectl_status']['stdout'], 'raw clock status\n')
        self.assertEqual(snapshot['commands']['timedatectl_status']['returncode'], 0)

    def test_command_timeout_retains_partial_output(self):
        error = subprocess.TimeoutExpired(['systemctl'], 10, output=b'partial\n', stderr=b'error\n')
        with mock.patch.object(subprocess, 'run', side_effect=error):
            result = tool.readonly_command(['systemctl', 'show'])
        self.assertIsNone(result['returncode'])
        self.assertEqual(result['stdout'], 'partial\n')
        self.assertEqual(result['stderr'], 'error\n')
        self.assertIn('TimeoutExpired', result['error'])


class FakeRunTests(unittest.TestCase):
    def run_fake(self, root, clock, snapshots=None):
        messages = []
        snapshots = mock.Mock(side_effect=snapshots or [context(), context()])
        with mock.patch.object(tool.sys, 'platform', 'linux'), \
                mock.patch.object(socket, 'socket', side_effect=AssertionError('socket forbidden')), \
                mock.patch.object(subprocess, 'run', side_effect=AssertionError('process forbidden')), \
                mock.patch.object(tool.os, 'geteuid', side_effect=AssertionError('root check forbidden'), create=True):
            directory, code = tool.run_audit(32, 'baseline', root, clock=clock,
                                             snapshot_fn=snapshots, emit=messages.append)
        self.assertEqual(snapshots.call_count, 2)
        audit = json.loads((directory / 'audit.json').read_text(encoding='utf-8'))
        summary = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
        self.assertTrue(tool.verify_artifact_seal(directory))
        return directory, code, audit, summary, messages

    def test_fake_32_seconds_full_bracketing_nonroot_no_packets(self):
        with tempfile.TemporaryDirectory() as root:
            clock = FakeClock()
            directory, code, audit, summary, messages = self.run_fake(root, clock)
            self.assertEqual(code, 0)
            self.assertTrue(summary['audit_complete'])
            self.assertTrue(summary['clock_quality_valid'])
            self.assertFalse(summary['performance_measured'])
            self.assertFalse(summary['kernel_packet_timestamps_validated'])
            self.assertGreater(len(audit['samples']), 6000)
            bounds = summary['clock_bounds']
            self.assertLessEqual(audit['samples'][0]['monotonic_after_ns'], bounds['window_start_monotonic_ns'])
            self.assertGreaterEqual(audit['samples'][-1]['monotonic_before_ns'], bounds['requested_window_end_monotonic_ns'])
            self.assertGreaterEqual(summary['elapsed_monotonic_seconds'], 32)
            self.assertLess(summary['elapsed_monotonic_seconds'], 32.001)
            self.assertTrue(any(message.startswith('30s elapsed') for message in messages))
            self.assertTrue(all(0 < wait <= .005 for wait in clock.sleeps))
            self.assertEqual({path.name for path in directory.iterdir()}, {
                'provenance.json', 'snapshot_before.json', 'snapshot_after.json', 'audit.json', 'summary.json', 'seal.json'})
            self.assertTrue(audit['valid'])
            self.assertEqual(audit['maximum_allowed_sample_gap_ns'], 25_000_000)
            self.assertEqual(audit['maximum_allowed_bracket_width_ns'], 100_000)
            self.assertEqual(audit['offset_change_tolerance_ns'], 1_000_000)

    def test_long_gap_keeps_invalid_evidence_and_skips_missed_deadlines(self):
        with tempfile.TemporaryDirectory() as root:
            clock = FakeClock(first_sleep_delay_ns=40_000_000)
            _, code, audit, summary, _ = self.run_fake(root, clock)
            self.assertEqual(code, 2)
            self.assertFalse(audit['valid'])
            self.assertGreater(summary['maximum_sample_gap_ns'], 25_000_000)
            self.assertEqual(summary['status'], 'clock_quality_invalid')
            self.assertTrue(summary['audit_complete'])
            self.assertLess(len(audit['samples']), 6402)

    def test_one_wall_step_is_invalid_and_counts_are_separate(self):
        with tempfile.TemporaryDirectory() as root:
            _, code, _, summary, _ = self.run_fake(root, FakeClock(offset_change_ns=-800_000_000, change_at_seconds=16))
            self.assertEqual(code, 2)
            self.assertEqual(summary['steps']['adjacent_offset_jump_count'], 1)
            self.assertGreater(summary['steps']['samples_changed_from_initial_reference_interval_count'], 3000)
            self.assertGreater(summary['steps']['largest_backward_adjacent_realtime_ns'], 790_000_000)

    def test_changed_context_invalidates_quality_after_full_audit(self):
        with tempfile.TemporaryDirectory() as root:
            _, code, audit, summary, _ = self.run_fake(root, FakeClock(), [context(), context('inactive')])
            self.assertTrue(audit['valid'])
            self.assertEqual(code, 2)
            self.assertFalse(summary['clock_quality_valid'])
            self.assertTrue(summary['context_comparison']['changed'])

    def test_interrupt_keeps_partial_raw_and_incomplete_summary(self):
        with tempfile.TemporaryDirectory() as root:
            _, code, audit, summary, _ = self.run_fake(root, FakeClock(interrupt_after_sleeps=12))
            self.assertEqual(code, 130)
            self.assertEqual(summary['status'], 'incomplete')
            self.assertFalse(summary['audit_complete'])
            self.assertFalse(summary['clock_quality_valid'])
            self.assertFalse(audit['valid'])
            self.assertGreater(len(audit['samples']), 1)
            self.assertIn('bracket the complete measured window', ' '.join(audit['reasons']))
            self.assertEqual(summary['failure']['type'], 'KeyboardInterrupt')

    def test_exclusive_writes_unique_runs_and_integrity_changes(self):
        with tempfile.TemporaryDirectory() as root:
            first = tool.new_directory(root, 'baseline')
            second = tool.new_directory(root, 'baseline')
            self.assertNotEqual(first, second)
            tool.write_json(first / 'summary.json', {'test': 'initial'})
            with self.assertRaises(FileExistsError):
                tool.write_json(first / 'summary.json', {'test': 'overwrite'})
            tool.seal_artifacts(first)
            self.assertTrue(tool.verify_artifact_seal(first))
            tool.write_json(first / 'extra.json', {'test': 'new'})
            self.assertFalse(tool.verify_artifact_seal(first))
            tool.write_json(second / 'data.json', {'value': 1})
            tool.seal_artifacts(second)
            # This isolated temporary artifact tests corruption detection only.
            with (second / 'data.json').open('a', encoding='utf-8') as stream:
                stream.write(' ')
            self.assertFalse(tool.verify_artifact_seal(second))


if __name__ == '__main__':
    unittest.main()
