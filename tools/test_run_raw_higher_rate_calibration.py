"""Offline v4 bounds, high-rate recipes and immutable campaign finalization.

No sudo, raw sockets, network queries or live benchmark traffic. External
acquisition is mocked; actual exclusive JSON writes and seals are exercised.
"""
from contextlib import nullcontext
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_raw_higher_rate_calibration as runner
import run_raw_performance_calibration as previous


RATES = [250, 500, 2000, 5000]


class FakePlan:
    """Small immutable-looking recipe for orchestration-only regressions."""
    def __init__(self, block, phase):
        self.phase = phase
        self.packet_count = block['rate_pps'] * (5 if phase == 'warmup' else 20)
        self.expected_classifications = 1 if phase == 'warmup' else 2
        self.slots = (1,) if phase == 'warmup' else (2,)
        self.flow_count = 1
        self.frame_bytes = 128

    def manifest(self):
        return dict(phase=self.phase, packet_count=self.packet_count,
                    expected_classifications=self.expected_classifications,
                    slots=list(self.slots))


def fake_plans(block, unused_protocol):
    return FakePlan(block, 'warmup'), FakePlan(block, 'measurement')


class ProtocolTests(unittest.TestCase):
    def test_exact_bounded_matrix_and_frozen_measurement_fields(self):
        current = runner.calibration_protocol(RATES[:])
        old = previous.calibration_protocol([100, 1000])
        self.assertEqual(runner.SCHEMA, 'raw-performance-calibration-v4')
        self.assertEqual(current['rates_pps'], RATES)
        self.assertEqual(current['maximum_trials'], 32)
        self.assertEqual(current['repetitions'], 1)
        for name in ('modes', 'workloads', 'duration_seconds', 'warmup_seconds',
                     'drain_seconds', 'frame_bytes', 'concurrency', 'normal_definitions',
                     'pacing_gates', 'clock_domain', 'sender_backend',
                     'clock_sample_seconds', 'maximum_clock_sampling_gap_ns',
                     'maximum_clock_bracket_ns', 'raw_rate_tolerance_ppm',
                     'qualification_minimum_span_seconds',
                     'kernel_forwarding_latency_qualified',
                     'isolated_inference_latency_measured',
                     'kernel_arrival_pacing_qualified', 'direction_comparison',
                     'warmup_state_isolation'):
            self.assertEqual(current[name], old[name], name)
        self.assertFalse(current['kernel_forwarding_latency_qualified'])
        self.assertFalse(current['accuracy_scored'])
        self.assertEqual(current['new_fits'], 0)

    def test_subsets_extra_rates_duplicates_and_full_sweep_are_rejected(self):
        for rates in ([], [250], [250, 500, 2000], [100, 1000],
                      RATES + [1000], [100, 250, 500, 1000, 2000, 5000],
                      [250, 500, 2000, 2000], [250, 500, 2000, True],
                      [250, 500, 2000, 5000.0], tuple(RATES)):
            with self.subTest(rates=rates), self.assertRaises(ValueError):
                runner.calibration_protocol(rates)
        # Ordering is canonicalized, not used to enable a different matrix.
        self.assertEqual(runner.calibration_protocol(RATES[::-1])['rates_pps'], RATES)

    def test_schedule_contains_exactly_32_unique_trials(self):
        protocol = runner.calibration_protocol(RATES[:])
        blocks = runner.build_schedule(protocol, 'offline-higher-rate')
        self.assertEqual(len(blocks), 8)
        self.assertEqual(sum(len(block['modes']) for block in blocks), 32)
        self.assertEqual({(block['rate_pps'], block['workload']) for block in blocks},
                         {(rate, workload) for rate in RATES
                          for workload in runner.legacy.WORKLOADS})
        trials = [(block['block_id'], mode) for block in blocks for mode in block['modes']]
        self.assertEqual(len(set(trials)), 32)
        self.assertEqual([block['rate_pps'] for block in blocks],
                         [250, 250, 500, 500, 2000, 2000, 5000, 5000])
        for block in blocks:
            self.assertEqual(block['repetition'], 1)
            self.assertEqual(set(block['modes']), set(runner.legacy.MODES))

    def test_schedule_guard_rejects_altered_shape_rates_modes_or_repetitions(self):
        protocol = runner.calibration_protocol(RATES[:])
        original = runner.build_schedule(protocol, 'guarded-higher-rate')
        runner.validate_schedule(protocol, original)
        cases = [original[:-1]]
        for field, value in (('rate_pps', 1000), ('repetition', 2),
                             ('modes', ['rf_b', 'rf_c']), ('workload', 'unknown')):
            altered = deepcopy(original)
            altered[0][field] = value
            cases.append(altered)
        duplicate = deepcopy(original)
        duplicate[-1] = deepcopy(duplicate[-2])
        cases.append(duplicate)
        reordered = deepcopy(original)
        reordered[0], reordered[-1] = reordered[-1], reordered[0]
        cases.append(reordered)
        for blocks in cases:
            with self.subTest(blocks=blocks), self.assertRaises(ValueError):
                runner.validate_schedule(protocol, blocks)

    def test_preparation_seals_ascending_rates_without_live_acquisition(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            base_dir = repo / 'base'
            base_dir.mkdir()
            (base_dir / 'manifest.json').write_text('{}')
            args = SimpleNamespace(rates=RATES[:], base_prepared=base_dir, switch=Path('/switch'))
            base = dict(input_sha256={}, programs={name: {'path': '/' + name + '.json'}
                        for name in runner.legacy.MODES}, clock_receipt='/clock_receipt.json')
            backend = SimpleNamespace(provenance={'input_sha256': {}})
            with patch.object(runner.legacy, 'load_prepared', return_value=(base, {'receipt_sha256': 'clock'})), \
                    patch.object(runner.raw_clock, 'build_raw_clock_reader', return_value=repo / 'clock.so'), \
                    patch.object(runner.raw_clock, 'RawClockReader', return_value=backend), \
                    patch.object(runner.sender_module, 'build_native_raw_paced_sender', return_value=repo / 'sender.so'), \
                    patch.object(runner.sender_module, 'NativeRawPacedSender', return_value=backend), \
                    patch.object(runner, 'source_inputs', return_value={}), \
                    patch.object(runner, 'hash_file', return_value='hash'), \
                    patch.object(runner.legacy, 'plans_for', side_effect=fake_plans), \
                    patch.object(runner.legacy, 'frame_hash', return_value='frames'):
                directory = runner.prepare(args, repo)
            manifest = json.loads((directory / 'manifest.json').read_text())
            self.assertEqual(manifest['schema_version'], runner.SCHEMA)
            self.assertEqual(manifest['expected_live_trials'], 32)
            self.assertEqual(manifest['scheduled_phase_seconds'], 32 * 29)
            self.assertEqual([block['rate_pps'] for block in manifest['schedule']],
                             [250, 250, 500, 500, 2000, 2000, 5000, 5000])
            self.assertEqual(len(manifest['schedule']), 8)
            for block in manifest['schedule']:
                plan = json.loads((directory / block['plan_file']).read_text())
                self.assertEqual(plan['warmup_measurement_slot_overlap'], 0)
                self.assertIn(block['plan_file'], manifest['artifact_hashes'])

    def test_five_thousand_pps_both_workloads_fit_and_isolate_state(self):
        protocol = runner.calibration_protocol(RATES[:])
        expected = {
            'classification-heavy': (3128, 12504, 3120, 12496),
            'cached-forwarding': (784, 3128, 784, 3128),
        }
        for block in runner.legacy.build_schedule(protocol, 'offline-5k'):
            if block['rate_pps'] != 5000:
                continue
            with self.subTest(workload=block['workload']):
                warm, measured = runner.legacy.plans_for(block, protocol)
                self.assertEqual((warm.packet_count, measured.packet_count), (25000, 100000))
                self.assertEqual((warm.flow_count, measured.flow_count,
                                  warm.expected_classifications, measured.expected_classifications),
                                 expected[block['workload']])
                self.assertFalse(set(warm.slots) & set(measured.slots))
                self.assertFalse(set(warm.flows) & set(measured.flows))
                self.assertEqual(len(set(warm.slots + measured.slots)),
                                 warm.flow_count + measured.flow_count)
                self.assertLess(warm.flow_count + measured.flow_count, 60000)
                self.assertEqual(warm.sequence_from_frame(measured.frame_for(0)), None)
                self.assertEqual(measured.sequence_from_frame(warm.frame_for(0)), None)


class ActualHigherLoadWindowTests(unittest.TestCase):
    def records(self):
        records = []
        for index, seconds in enumerate((0, 100, 860, 1000)):
            raw = seconds * 10**9 + 10**9
            for provider in runner.raw_clock.PROVIDERS:
                before = [raw, raw, 1_767_225_600_000_000_000 + raw, raw + 10, raw + 40]
                after = [value + 1_000_000 for value in before]
                records.append(dict(provider=provider, query_index=index, valid=True,
                    query_brackets_valid=True, before=before, after=after,
                    server_transmit_ns=1_767_225_600_000_000_000 + raw,
                    advertised_error_bound_ns=100_000,
                    requested_target_pps=5000 if seconds == 860 else 250))
        return records

    def report(self, highest_window):
        return runner.raw_clock.qualification_report(self.records(), start_raw_ns=3 * 10**9,
            end_raw_ns=990 * 10**9, load_windows=[dict(start_raw_ns=90 * 10**9,
                end_raw_ns=110 * 10**9, target_pps=250), highest_window])

    def test_five_thousand_queries_must_be_inside_actual_valid_measurement_window(self):
        report = self.report(dict(start_raw_ns=850 * 10**9, end_raw_ns=870 * 10**9, target_pps=5000))
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['representative_load_target_pps'], 5000)
        for provider in report['providers'].values():
            self.assertEqual(provider['representative_load_queries'], 1)
            self.assertGreaterEqual(provider['raw_rate']['lower_ppm'], -1000)
            self.assertLessEqual(provider['raw_rate']['upper_ppm'], 1000)
        self.assertEqual(len(report['queries']), 12)

    def test_five_thousand_notification_hint_cannot_promote_warmup_or_outside_query(self):
        report = self.report(dict(start_raw_ns=865 * 10**9, end_raw_ns=885 * 10**9, target_pps=5000))
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(report['representative_load_target_pps'], 5000)
        self.assertTrue(all(provider['representative_load_queries'] == 0
                            for provider in report['providers'].values()))
        self.assertEqual(len(report['queries']), 12)


class HigherCampaignFinalizationTests(unittest.TestCase):
    def exercise(self, *, fail_first=False, warn_first=False, partial_first=False, qualified=True):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            args = SimpleNamespace(prepared=repo / 'prepared', smoke_run=repo / 'smoke')
            protocol = runner.calibration_protocol(RATES[:])
            blocks = runner.build_schedule(protocol, 'finalization-higher-rate')
            plans = {}
            for block in blocks:
                block['plan_file'] = 'plans/' + block['block_id'] + '.json'
                warm, measured = fake_plans(block, protocol)
                plans[args.prepared / block['plan_file']] = dict(warmup=warm.manifest(),
                    measurement=measured.manifest(), warmup_frames_sha256='frames',
                    measurement_frames_sha256='frames')
            manifest = dict(protocol=protocol, schedule=blocks, expected_live_trials=32,
                programs={name: {'path': '/synthetic.json'} for name in runner.legacy.MODES}, input_sha256={})
            receipt = dict(receipt_sha256='hash')
            smoke = dict(passed=True, status='raw_packet_file_smoke_passed',
                prepared_manifest_sha256='hash', clock_receipt_sha256='hash',
                legacy_check=str(repo / 'old_smoke'), legacy_check_sha256='hash')
            payloads, calls, links_created, qualifiers_created = {}, [], [], []
            start_payloads = {}

            class Links:
                def __init__(self, unused_name):
                    self.cleanup_errors = []
                    self.cleaned = False
                    links_created.append(self)
                def __enter__(self):
                    return self
                def __exit__(self, *unused):
                    self.cleaned = True

            class Qualifier:
                def __init__(self, **unused):
                    self.records = [dict(valid=True, query_brackets_valid=True)]
                    self.pins = {name: {} for name in runner.raw_clock.PROVIDERS}
                    self.stopped = False
                    qualifiers_created.append(self)
                def start(self):
                    pass
                def stop(self):
                    self.stopped = True
                def report(self, start, end, *, load_windows):
                    self.windows = load_windows
                    return dict(passed=qualified, status='PASS' if qualified else 'INCONCLUSIVE')

            def read_json(path):
                if path == args.smoke_run / 'summary.json':
                    return smoke
                if path == repo / 'old_smoke' / 'summary.json':
                    return dict(artifact_hashes={})
                if path in plans:
                    return plans[path]
                raise AssertionError(f'Unexpected external read: {path}')

            def trial(*positional, qualifier=None):
                mode, block, directory = positional[2], positional[3], positional[-1]
                self.assertIs(qualifier, qualifiers_created[0])
                start_receipt = directory.parent / 'attempts' / f'attempt_{len(calls) + 1:03d}_start.json'
                self.assertTrue(start_receipt.is_file(), 'Attempt must be registered before acquisition')
                start_payloads[start_receipt.name] = start_receipt.read_bytes()
                self.assertFalse(directory.exists(), 'Runner must not precreate run_trial directory')
                directory.mkdir(exist_ok=True)
                calls.append(mode)
                if partial_first and len(calls) == 1:
                    runner.write_json(directory / 'partial_measurement.json',
                                      dict(status='diagnostic_only', captured_input=17, captured_output=16))
                    payloads[directory.name] = (directory / 'partial_measurement.json').read_bytes()
                    raise RuntimeError('Synthetic acquisition exception after partial evidence')
                valid = not (fail_first and len(calls) == 1)
                warning = warn_first and len(calls) == 1
                start = len(calls) * 30 * 10**9
                row = dict(mode=mode, workload=block['workload'], rate_pps=block['rate_pps'],
                    block_id=block['block_id'], repetition=1, valid=valid,
                    instrument_valid_before_rate_qualification=valid,
                    failures=[] if valid else ['RAW warm-up capture integrity failed'],
                    metric_validity=dict(offered_load=True, delivered_throughput=True,
                        packet_accounting=True, classification_rate=True, classification_counts=True,
                        cpu=True, cpu_accounting=True, resources=True, memory=True,
                        kernel_forwarding_latency=False),
                    metrics=dict(packets_received=block['rate_pps'] * 20, decisions=2),
                    rate_window=dict(start_raw_ns=start, end_raw_ns=start + 20 * 10**9,
                                     target_pps=block['rate_pps'], mode=mode, workload=block['workload']),
                    verdicts=dict(measurement_integrity=dict(status='PASS' if valid else 'FAIL'),
                        independent_raw_qualification=dict(status='NOT_EVALUATED'),
                        sender_pacing_conformance=dict(status='WARNING' if warning else 'PASS',
                            warmup=dict(status='WARNING' if warning else 'PASS',
                                warnings=['unchanged engineering maximum exceeded'] if warning else []),
                            measurement=dict(status='PASS', warnings=[]))))
                runner.write_json(directory / 'trial_summary.json', row)
                payloads[directory.name] = (directory / 'trial_summary.json').read_bytes()
                return row

            with patch.object(runner.os, 'geteuid', return_value=0), \
                    patch.object(runner, 'load_prepared', return_value=(manifest, receipt,
                        SimpleNamespace(read=lambda: None, provenance={}), SimpleNamespace(provenance={}))), \
                    patch.object(runner.integration, 'read_json', side_effect=read_json), \
                    patch.object(runner, 'hash_file', return_value='hash'), \
                    patch.object(runner.legacy, 'verify_seal'), \
                    patch.object(runner.legacy, 'plans_for', side_effect=fake_plans), \
                    patch.object(runner.legacy, 'frame_hash', return_value='frames'), \
                    patch.object(runner.legacy, 'exclusive_run', side_effect=lambda unused: nullcontext()), \
                    patch.object(runner.legacy, 'resource_preflight', return_value={}), \
                    patch.object(runner.legacy, 'host_snapshot', return_value={}), \
                    patch.object(runner.ownership, 'OwnedLinks', Links), \
                    patch.object(runner.ownership, 'verify_hashes'), \
                    patch.object(runner.raw_clock, 'RateQualification', Qualifier), \
                    patch.object(runner, 'run_trial', side_effect=trial):
                output = runner.run(args, repo)

            summary = json.loads((output / 'summary.json').read_text())
            count = 1 if fail_first or partial_first else 32
            completed = 0 if partial_first else count
            self.assertTrue(links_created[0].cleaned)
            self.assertTrue(qualifiers_created[0].stopped)
            self.assertEqual(summary['expected_trials'], 32)
            self.assertEqual(summary['attempted_trials'], count)
            self.assertEqual(summary['completed_trials'], completed)
            self.assertEqual(len(summary['attempts']), count)
            self.assertEqual(len(summary['trials']), completed)
            self.assertEqual(summary['passed'], not fail_first and not partial_first and qualified)
            self.assertEqual(summary['raw_rate_qualified'], qualified)
            self.assertEqual(summary['pacing_warning_trials'], 1 if warn_first else 0)
            pacing = summary['verdicts']['sender_pacing_conformance']
            self.assertEqual(pacing['observed_completed_trials'], completed)
            self.assertEqual(pacing['uncompleted_attempts'], count - completed)
            if partial_first:
                self.assertEqual(pacing['status'], 'NOT_EVALUATED')
            self.assertFalse(summary['uniform_load_claim_eligible'])
            self.assertFalse(summary['saturation_claim_eligible'])
            self.assertFalse(summary['kernel_forwarding_latency_qualified'])
            for ordinal, attempt in enumerate(summary['attempts'], 1):
                self.assertEqual(attempt['ordinal'], ordinal)
                self.assertEqual(attempt['start_receipt'], f'attempts/attempt_{ordinal:03d}_start.json')
                self.assertEqual(attempt['result_receipt'], f'attempts/attempt_{ordinal:03d}_result.json')
                self.assertEqual(attempt['status'], 'exception' if partial_first else 'completed')
                self.assertEqual((output / attempt['start_receipt']).read_bytes(),
                                 start_payloads[Path(attempt['start_receipt']).name])
                result = json.loads((output / attempt['result_receipt']).read_text())
                self.assertTrue(result['trial_directory_exists'])
                self.assertIn(attempt['start_receipt'], summary['artifact_hashes'])
                self.assertIn(attempt['result_receipt'], summary['artifact_hashes'])
            if partial_first:
                self.assertEqual(len(summary['partial_trials']), 1)
                name = summary['partial_trials'][0]
                self.assertEqual((output / name / 'partial_measurement.json').read_bytes(), payloads[name])
                self.assertIn(name + '/partial_measurement.json', summary['artifact_hashes'])
                self.assertIn('Synthetic acquisition exception', summary['abort_reason'])
                self.assertEqual(len(calls), 1)
            else:
                self.assertEqual(summary['partial_trials'], [])
                for name in summary['trials']:
                    self.assertEqual((output / name / 'trial_summary.json').read_bytes(), payloads[name])
                    original = json.loads(payloads[name])
                    final = json.loads((output / name / 'qualified_trial_summary.json').read_text())
                    self.assertEqual(original['verdicts']['independent_raw_qualification']['status'], 'NOT_EVALUATED')
                    self.assertEqual(final['verdicts']['independent_raw_qualification']['status'],
                                     'PASS' if qualified else 'INCONCLUSIVE')
                    self.assertEqual(final['verdicts']['sender_pacing_conformance'],
                                     original['verdicts']['sender_pacing_conformance'])
                    for filename in ('trial_summary.json', 'qualified_trial_summary.json'):
                        self.assertIn(name + '/' + filename, summary['artifact_hashes'])
                self.assertEqual(len(qualifiers_created[0].windows), 0 if fail_first else 32)
            if fail_first:
                self.assertIn('hard capture', summary['abort_reason'])
                self.assertEqual(len(calls), 1)

    def test_full_32_campaign_success_preserves_every_local_summary(self):
        self.exercise()

    def test_returned_hard_gate_stops_but_preserves_failed_evidence(self):
        self.exercise(fail_first=True)

    def test_pacing_warning_does_not_stop_and_is_not_deleted(self):
        self.exercise(warn_first=True)

    def test_partial_exception_attempt_count_and_evidence_are_preserved(self):
        self.exercise(partial_first=True)

    def test_external_inconclusive_finalizes_all_attempts_without_qualifying_rates(self):
        self.exercise(qualified=False)


if __name__ == '__main__':
    unittest.main()
