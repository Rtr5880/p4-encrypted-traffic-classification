"""Offline final-campaign orchestration regressions, without privileged traffic.

Actual exclusive evidence writes and seals are exercised in temporary folders.
Network/reference acquisition and switches are mocked, never started. Historical
calibration evidence is neither loaded nor edited by these tests.
"""
import ast
from contextlib import nullcontext, redirect_stdout
from copy import deepcopy
import inspect
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_raw_performance_benchmark as runner
import run_raw_higher_rate_calibration as calibrated
from test_run_raw_higher_rate_calibration import fake_plans


RATES = [100, 250, 500, 1000]


def protocol_and_schedule():
    protocol = runner.benchmark_protocol(RATES[:])
    return protocol, runner.build_schedule(protocol, 'offline-final-campaign')


class ProtocolScheduleTests(unittest.TestCase):
    def test_fixed_160_matrix_preserves_calibrated_measurement_requirements(self):
        current, blocks = protocol_and_schedule()
        old = calibrated.calibration_protocol([250, 500, 2000, 5000])
        self.assertEqual(runner.SCHEMA, 'raw-performance-benchmark-v5')
        self.assertEqual(current['rates_pps'], RATES)
        self.assertEqual(current['repetitions'], 5)
        self.assertEqual(current['maximum_trials'], 160)
        self.assertEqual(len(blocks), 40)
        changed = {'name', 'rates_pps', 'repetitions', 'maximum_trials'}
        orchestration = {'ordering', 'retry_policy', 'incomplete_block_policy', 'measurement_profile'}
        self.assertEqual(set(current) - set(old), orchestration)
        for name in set(old) - changed:
            self.assertEqual(current[name], old[name], name)
        self.assertEqual(current['maximum_clock_sampling_gap_ns'], 25_000_000)
        self.assertEqual(current['maximum_clock_bracket_ns'], 100_000)
        self.assertFalse(current['kernel_forwarding_latency_qualified'])
        self.assertFalse(current['isolated_inference_latency_measured'])

    def test_rejects_extra_rates_subsets_duplicates_and_non_integer_rates(self):
        for rates in ([], RATES[:-1], RATES + [2000], [100, 250, 500, 500],
                      [100, 250, 500, True], [100, 250, 500, 1000.0], tuple(RATES),
                      [250, 500, 2000, 5000]):
            with self.subTest(rates=rates), self.assertRaises(ValueError):
                runner.benchmark_protocol(rates)
        self.assertEqual(runner.benchmark_protocol(RATES[::-1])['rates_pps'], RATES)

    def test_complete_matrix_repetition_metadata_and_position_balance(self):
        protocol, blocks = protocol_and_schedule()
        expected = {(rate, workload, repetition) for rate in RATES
                    for workload in runner.legacy.WORKLOADS for repetition in range(1, 6)}
        self.assertEqual({(item['rate_pps'], item['workload'], item['repetition'])
                          for item in blocks}, expected)
        self.assertEqual(len({item['block_id'] for item in blocks}), 40)
        self.assertEqual(sum(len(item['modes']) for item in blocks), 160)
        self.assertNotEqual([item['rate_pps'] for item in blocks],
                            sorted(item['rate_pps'] for item in blocks),
                            'Repeated campaign must not be an ascending-load calibration')
        for mode in runner.legacy.MODES:
            self.assertEqual([sum(item['modes'][position] == mode for item in blocks)
                              for position in range(4)], [10, 10, 10, 10])
            for rate in RATES:
                for workload in runner.legacy.WORKLOADS:
                    cell = [item for item in blocks if item['rate_pps'] == rate
                            and item['workload'] == workload]
                    self.assertEqual(sorted(sum(item['modes'][position] == mode for item in cell)
                                            for position in range(4)), [1, 1, 1, 2])
        runner.validate_schedule(protocol, blocks)

    def test_schedule_reproducible_for_same_seed_and_token(self):
        protocol, blocks = protocol_and_schedule()
        self.assertEqual(runner.build_schedule(protocol, 'offline-final-campaign'), blocks)

    def test_schedule_guard_rejects_missing_duplicate_altered_or_unbalanced_blocks(self):
        protocol, original = protocol_and_schedule()
        cases = [original[:-1]]
        for field, value in (('rate_pps', 2000), ('repetition', 6), ('workload', 'unknown'),
                             ('modes', ['rf_b', 'rf_c']), ('block_id', 'incorrect_identity')):
            blocks = deepcopy(original)
            blocks[0][field] = value
            cases.append(blocks)
        duplicate = deepcopy(original)
        duplicate[-1] = deepcopy(duplicate[-2])
        cases.append(duplicate)
        unbalanced = deepcopy(original)
        for block in unbalanced:
            block['modes'] = list(runner.legacy.MODES)
        cases.append(unbalanced)
        for blocks in cases:
            with self.subTest(first=blocks[0]), self.assertRaises(ValueError):
                runner.validate_schedule(protocol, blocks)

    def test_preparation_exclusively_seals_40_paired_plans(self):
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
                    patch.object(runner, 'calibration_receipts', return_value=[]), \
                    patch.object(runner, 'hash_file', return_value='hash'), \
                    patch.object(runner.legacy, 'plans_for', side_effect=fake_plans), \
                    patch.object(runner.legacy, 'frame_hash', return_value='frames'), redirect_stdout(io.StringIO()):
                directory = runner.prepare(args, repo)
            manifest = json.loads((directory / 'manifest.json').read_text())
            self.assertEqual(manifest['schema_version'], runner.SCHEMA)
            self.assertEqual(manifest['expected_live_trials'], 160)
            self.assertEqual(manifest['scheduled_phase_seconds'], 4640)
            self.assertEqual(len(manifest['schedule']), 40)
            runner.legacy.verify_seal(directory, manifest['artifact_hashes'])
            for block in manifest['schedule']:
                plan = json.loads((directory / block['plan_file']).read_text())
                self.assertEqual(plan['warmup_measurement_slot_overlap'], 0)
                self.assertIn(block['plan_file'], manifest['artifact_hashes'])

    def test_real_workloads_remain_bounded_and_disjoint_at_highest_final_rate(self):
        protocol, blocks = protocol_and_schedule()
        for workload in runner.legacy.WORKLOADS:
            block = next(item for item in blocks if item['rate_pps'] == 1000
                         and item['workload'] == workload and item['repetition'] == 1)
            warm, measured = runner.legacy.plans_for(block, protocol)
            with self.subTest(workload=workload):
                self.assertEqual((warm.packet_count, measured.packet_count), (5000, 20000))
                self.assertFalse(set(warm.slots) & set(measured.slots))
                self.assertFalse(set(warm.flows) & set(measured.flows))
                self.assertEqual(len(set(warm.slots + measured.slots)), warm.flow_count + measured.flow_count)
                self.assertLess(warm.flow_count + measured.flow_count, 60000)
                self.assertIsNone(warm.sequence_from_frame(measured.frame_for(0)))
                self.assertIsNone(measured.sequence_from_frame(warm.frame_for(0)))


class MeasurementReuseTests(unittest.TestCase):
    def test_measurement_function_asts_are_identical_to_calibrated_v4(self):
        for name in ('flatten_metrics', 'start_measurement_window', 'pacing_verdict',
                     'pacing_distribution', 'apply_rate_qualification'):
            with self.subTest(function=name):
                current = ast.dump(ast.parse(inspect.getsource(getattr(runner, name))), include_attributes=False)
                old = ast.dump(ast.parse(inspect.getsource(getattr(calibrated, name))), include_attributes=False)
                self.assertEqual(current, old)

    def test_run_trial_only_changes_repetition_metadata(self):
        current = ast.parse(inspect.getsource(runner.run_trial))
        old = ast.parse(inspect.getsource(calibrated.run_trial))
        replacements = 0
        for node in ast.walk(current):
            if isinstance(node, ast.Dict):
                for index, key in enumerate(node.keys):
                    if isinstance(key, ast.Constant) and key.value == 'repetition':
                        self.assertEqual(ast.dump(node.values[index]),
                                         ast.dump(ast.parse("block['repetition']", mode='eval').body))
                        node.values[index] = ast.Constant(value=1)
                        replacements += 1
        self.assertEqual(replacements, 1)
        self.assertEqual(ast.dump(current, include_attributes=False), ast.dump(old, include_attributes=False))


class PreparedProvenanceTests(unittest.TestCase):
    def test_valid_preparation_verifies_backends_frozen_programs_and_historical_receipts(self):
        self.load_case()

    def test_rejects_changed_calibration_receipts_backend_programs_or_trial_count(self):
        for failure in ('receipts', 'backend', 'programs', 'count', 'gate', 'schema', 'schedule'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.load_case(failure=failure)

    def load_case(self, failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            prepared = repo / 'results' / 'raw_performance_benchmark_preparation' / 'run'
            protocol, blocks = protocol_and_schedule()
            manifest = dict(schema_version=runner.SCHEMA, status='prepared', artifact_hashes={},
                input_sha256={}, protocol=protocol, schedule=blocks, expected_live_trials=160,
                scheduled_phase_seconds=4640, prior_calibration_receipts=[{'historical_failure_preserved': True}],
                base_prepared=str(repo / 'base'), programs={'frozen': True},
                clock_receipt_sha256='receipt', raw_clock_library='/clock.so',
                raw_sender_library='/sender.so', raw_clock_provenance={'frozen': True},
                raw_sender_provenance={'frozen': True})
            histories = deepcopy(manifest['prior_calibration_receipts'])
            programs = deepcopy(manifest['programs'])
            backend = SimpleNamespace(provenance={'frozen': True})
            if failure == 'receipts':
                histories = []
            elif failure == 'backend':
                backend.provenance = {'changed': True}
            elif failure == 'programs':
                programs = {'changed': True}
            elif failure == 'count':
                manifest['expected_live_trials'] = 159
            elif failure == 'gate':
                manifest['protocol']['maximum_clock_sampling_gap_ns'] = 26_000_000
            elif failure == 'schema':
                manifest['schema_version'] = 'raw-performance-calibration-v4'
            elif failure == 'schedule':
                manifest['schedule'].pop()
            args = SimpleNamespace(prepared=prepared, switch=Path('/switch'))
            with patch.object(runner.integration, 'read_json', return_value=manifest), \
                    patch.object(runner.legacy, 'verify_seal') as sealed, \
                    patch.object(runner.ownership, 'verify_hashes') as inputs, \
                    patch.object(runner, 'calibration_receipts', return_value=histories) as historical, \
                    patch.object(runner.legacy, 'load_prepared', return_value=(dict(programs=programs),
                        dict(receipt_sha256='receipt'))), \
                    patch.object(runner.raw_clock, 'RawClockReader', return_value=backend), \
                    patch.object(runner.sender_module, 'NativeRawPacedSender', return_value=backend):
                result = runner.load_prepared(args)
            self.assertIs(result[0], manifest)
            sealed.assert_called_once_with(prepared.resolve(), {})
            inputs.assert_called_once_with({})
            historical.assert_called_once_with(repo.resolve())

    def test_historical_failure_receipt_is_preserved_but_not_pooled(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            rows = {f'trial_{index:03d}': dict(valid=True, rate_pps=rate, workload=workload, mode=mode)
                    for index, (rate, workload, mode) in enumerate(
                        ((rate, workload, mode) for rate in RATES
                         for workload in runner.legacy.WORKLOADS for mode in runner.legacy.MODES), 1)}
            good = dict(raw_rate_qualified=True, artifact_hashes={'existing': 'seal'},
                trials=list(rows), status='raw_calibration_passed', expected_trials=16,
                attempted_trials=16, valid_trials=16, abort_reason=None)
            incomplete = dict(good, status='raw_calibration_incomplete', expected_trials=32,
                attempted_trials=21, valid_trials=20, abort_reason='raw_clock_sample_gap_over_25ms')
            original = deepcopy(incomplete)
            def read_json(path):
                if path.name == 'summary.json':
                    return incomplete if 'raw_higher_rate_calibration' in str(path) else good
                return rows[path.parent.name]
            with patch.object(runner.integration, 'read_json', side_effect=read_json), \
                    patch.object(runner.legacy, 'verify_seal') as seals, \
                    patch.object(runner, 'hash_file', return_value='hash'):
                receipts = runner.calibration_receipts(repo)
            self.assertEqual(seals.call_count, 2)
            self.assertEqual(incomplete, original)
            self.assertEqual(receipts[1]['abort_reason'], 'raw_clock_sample_gap_over_25ms')
            self.assertEqual(receipts[1]['attempted_trials'], 21)
            self.assertTrue(all(item['pooled_in_final_aggregates'] is False for item in receipts))

    def test_smoke_reuses_normal_build_packet_files_without_live_pacing_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            args = SimpleNamespace(prepared=repo / 'prepared')
            manifest = dict(base_prepared=str(repo / 'base'))
            receipt = dict(receipt_sha256='receipt')
            with patch.object(runner, 'load_prepared', return_value=(manifest, receipt, None, None)), \
                    patch.object(runner.legacy, 'smoke', return_value=repo / 'legacy_smoke') as old_smoke, \
                    patch.object(runner.integration, 'read_json', return_value={'results': ['8 file checks']}), \
                    patch.object(runner, 'hash_file', return_value='hash'), redirect_stdout(io.StringIO()):
                directory = runner.smoke(args, repo)
            self.assertEqual(old_smoke.call_args.args[0].prepared, repo / 'base')
            summary = json.loads((directory / 'summary.json').read_text())
            self.assertTrue(summary['passed'])
            self.assertFalse(summary['performance_measured'])
            self.assertFalse(summary['live_interfaces_accessed'])
            self.assertFalse(summary['raw_sender_live_pacing_qualified'])
            self.assertEqual(summary['prepared_manifest_sha256'], 'hash')
            self.assertEqual(summary['clock_receipt_sha256'], 'receipt')


class FinalCampaignTests(unittest.TestCase):
    def exercise(self, *, fail_at=None, partial_at=None, warn_at=None, qualified=True):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            args = SimpleNamespace(prepared=repo / 'prepared', smoke_run=repo / 'smoke')
            protocol, blocks = protocol_and_schedule()
            plans = {}
            for block in blocks:
                block['plan_file'] = 'plans/' + block['block_id'] + '.json'
                warm, measured = fake_plans(block, protocol)
                plans[args.prepared / block['plan_file']] = dict(warmup=warm.manifest(),
                    measurement=measured.manifest(), warmup_frames_sha256='frames',
                    measurement_frames_sha256='frames')
            manifest = dict(protocol=protocol, schedule=blocks, expected_live_trials=160,
                prior_calibration_receipts=[],
                programs={name: {'path': '/synthetic.json'} for name in runner.legacy.MODES}, input_sha256={})
            receipt = dict(receipt_sha256='hash')
            smoke = dict(passed=True, status='raw_packet_file_smoke_passed',
                prepared_manifest_sha256='hash', clock_receipt_sha256='hash',
                legacy_check=str(repo / 'old_smoke'), legacy_check_sha256='hash')
            payloads, calls, links_created, qualifiers_created, start_payloads = {}, [], [], [], {}

            class Links:
                def __init__(self, unused_name):
                    self.cleanup_errors, self.cleaned = [], False
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
                ordinal = len(calls) + 1
                start_receipt = directory.parent / 'attempts' / f'attempt_{ordinal:03d}_start.json'
                self.assertTrue(start_receipt.is_file(), 'Attempt receipt precedes acquisition')
                self.assertTrue((directory.parent / 'schedule.json').is_file(), 'Full schedule precedes acquisition')
                start_payloads[start_receipt.name] = start_receipt.read_bytes()
                self.assertFalse(directory.exists(), 'run_trial owns fresh trial directory creation')
                directory.mkdir()
                calls.append((mode, block['block_id'], block['repetition']))
                if ordinal == partial_at:
                    runner.write_json(directory / 'partial_measurement.json',
                                      dict(status='diagnostic_only', captured_input=17, captured_output=16))
                    payloads[directory.name] = (directory / 'partial_measurement.json').read_bytes()
                    raise RuntimeError('Synthetic acquisition exception after partial evidence')
                valid, warning = ordinal != fail_at, ordinal == warn_at
                start = ordinal * 30 * 10**9
                row = dict(mode=mode, workload=block['workload'], rate_pps=block['rate_pps'],
                    block_id=block['block_id'], repetition=block['repetition'], valid=valid,
                    instrument_valid_before_rate_qualification=valid,
                    failures=[] if valid else ['raw_clock_sample_gap_over_25ms'],
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

            with patch.object(runner.os, 'geteuid', return_value=0, create=True), \
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
                    patch.object(runner, 'run_trial', side_effect=trial), redirect_stdout(io.StringIO()):
                output = runner.run(args, repo)

            summary = json.loads((output / 'summary.json').read_text())
            attempted = fail_at or partial_at or 160
            completed = attempted - int(partial_at is not None)
            self.assertTrue(links_created[0].cleaned)
            self.assertTrue(qualifiers_created[0].stopped)
            self.assertEqual(summary['expected_trials'], 160)
            self.assertEqual(summary['attempted_trials'], attempted)
            self.assertEqual(summary['completed_trials'], completed)
            self.assertEqual(len(summary['attempts']), attempted)
            self.assertEqual(len(summary['trials']), completed)
            self.assertEqual(summary['passed'], not fail_at and not partial_at and qualified)
            self.assertEqual(summary['raw_rate_qualified'], qualified)
            self.assertEqual(summary['pacing_warning_trials'], int(warn_at is not None))
            self.assertFalse(summary['uniform_load_claim_eligible'])
            self.assertFalse(summary['saturation_claim_eligible'])
            self.assertFalse(summary['kernel_forwarding_latency_qualified'])
            pacing = summary['verdicts']['sender_pacing_conformance']
            self.assertEqual(pacing['observed_completed_trials'], completed)
            self.assertEqual(pacing['uncompleted_attempts'], attempted - completed)
            self.assertEqual(len(calls), attempted, 'No selective retries after a failure')
            ledger = summary['block_accounting']
            self.assertEqual(ledger['expected_blocks'], 40)
            self.assertEqual(len(ledger['blocks']), 40)
            self.assertEqual(ledger['retries'], 0)
            self.assertFalse(ledger['resume_supported'])
            if attempted == 160:
                self.assertEqual(ledger['acquired_complete_blocks'], 40)
                self.assertEqual(ledger['qualified_complete_blocks'], 40 if qualified else 0)
                self.assertEqual(ledger['interrupted_blocks'], 0)
                self.assertEqual(ledger['unattempted_blocks'], 0)
                self.assertEqual({repetition for _, _, repetition in calls}, {1, 2, 3, 4, 5})
            else:
                self.assertEqual(ledger['interrupted_blocks'], 1)
                self.assertEqual(ledger['unattempted_blocks'], 39)
                interrupted = next(block for block in ledger['blocks'] if block['status'] == 'interrupted')
                self.assertEqual(len(interrupted['attempted_modes']), attempted)
                self.assertEqual(len(interrupted['completed_modes']), completed)
                self.assertEqual(len(interrupted['unattempted_modes']), 4 - attempted)
                self.assertEqual(len(interrupted['partial_modes']), int(partial_at is not None))
                self.assertEqual(len(interrupted['failed_integrity_modes']), int(fail_at is not None))
            for ordinal, attempt in enumerate(summary['attempts'], 1):
                self.assertEqual(attempt['ordinal'], ordinal)
                self.assertEqual(attempt['repetition'], calls[ordinal - 1][2])
                self.assertEqual((output / attempt['start_receipt']).read_bytes(),
                                 start_payloads[Path(attempt['start_receipt']).name])
                result = json.loads((output / attempt['result_receipt']).read_text())
                self.assertTrue(result['trial_directory_exists'])
                self.assertFalse(result['measurements_fabricated'])
                self.assertIn(attempt['start_receipt'], summary['artifact_hashes'])
                self.assertIn(attempt['result_receipt'], summary['artifact_hashes'])
            for name in summary['trials']:
                self.assertEqual((output / name / 'trial_summary.json').read_bytes(), payloads[name])
                original = json.loads(payloads[name])
                final = json.loads((output / name / 'qualified_trial_summary.json').read_text())
                self.assertEqual(original['verdicts']['independent_raw_qualification']['status'], 'NOT_EVALUATED')
                self.assertEqual(final['verdicts']['independent_raw_qualification']['status'],
                                 'PASS' if qualified else 'INCONCLUSIVE')
                self.assertEqual(final['repetition'], original['repetition'])
                self.assertEqual(final['verdicts']['sender_pacing_conformance'],
                                 original['verdicts']['sender_pacing_conformance'])
                if not qualified:
                    for metric in ('offered_load', 'delivered_throughput', 'classification_rate', 'cpu'):
                        self.assertFalse(final['metric_validity'][metric])
                    self.assertTrue(final['metric_validity']['packet_accounting'])
                    self.assertTrue(final['metric_validity']['memory'])
                for filename in ('trial_summary.json', 'qualified_trial_summary.json'):
                    self.assertIn(name + '/' + filename, summary['artifact_hashes'])
            if partial_at is not None:
                self.assertEqual(len(summary['partial_trials']), 1)
                name = summary['partial_trials'][0]
                self.assertEqual((output / name / 'partial_measurement.json').read_bytes(), payloads[name])
                self.assertIn(name + '/partial_measurement.json', summary['artifact_hashes'])
                self.assertIn('Synthetic acquisition exception', summary['abort_reason'])
            else:
                self.assertEqual(summary['partial_trials'], [])
            self.assertIn('schedule.json', summary['artifact_hashes'])
            # The real seal checker, outside the mocked acquisition context.
            runner.legacy.verify_seal(output, summary['artifact_hashes'])

    def test_full_160_campaign_finalization_preserves_every_summary_and_repetition(self):
        self.exercise()

    def test_hard_gate_at_trial_three_stops_and_lists_incomplete_block(self):
        self.exercise(fail_at=3)

    def test_partial_exception_at_trial_three_preserves_evidence_and_unattempted_modes(self):
        self.exercise(partial_at=3)

    def test_pacing_warning_continues_full_campaign_and_remains_visible(self):
        self.exercise(warn_at=2)

    def test_independent_inconclusive_preserves_counts_but_masks_rates_and_cpu_percent(self):
        self.exercise(qualified=False)


if __name__ == '__main__':
    unittest.main()
