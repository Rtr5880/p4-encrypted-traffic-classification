"""Offline continuation-policy regressions: no privileged traffic or old edits.

Mocks never instantiate a live switch, reference query or packet interface.
Real exclusive evidence writes and seal verification are exercised separately.
"""
from copy import deepcopy
from contextlib import nullcontext, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import continue_raw_performance_benchmark as c
import run_raw_performance_benchmark as runner
from test_run_raw_higher_rate_calibration import fake_plans
from test_analyze_raw_performance import fixture_v5, v5_rows


def original_schedule():
    return runner.build_schedule(runner.benchmark_protocol([100, 250, 500, 1000]),
                                 'offline-continuation-policy')


def integrity_row(*, valid=True, code='raw_clock_sample_gap_over_25ms',
                  warmup=False, pacing_warning=False):
    failures = [] if valid else [code]
    return dict(valid=valid, instrument_valid_before_rate_qualification=valid,
        failures=failures,
        measurement_quality_reasons=[] if warmup else failures[:],
        warmup_quality_reasons=failures[:] if warmup else [],
        metric_validity=dict(resources=True, memory=True),
        verdicts=dict(measurement_integrity=dict(status='PASS' if valid else 'FAIL'),
                      sender_pacing_conformance=dict(status='WARNING' if pacing_warning else 'PASS')))


class ContinuationScheduleTests(unittest.TestCase):
    def test_run_trial_is_the_exact_existing_measurement_function(self):
        self.assertIs(c.run_trial, runner.run_trial)

    def test_schema_is_separately_versioned(self):
        self.assertEqual(c.SCHEMA, 'raw-performance-benchmark-continuation-v6')
        self.assertNotEqual(c.SCHEMA, runner.SCHEMA)

    def test_only_stopping_policy_changes_not_quality_limits(self):
        policy = c.continuation_policy()
        self.assertEqual(policy['maximum_clock_sampling_gap_ns'], 25_000_000)
        self.assertEqual(policy['maximum_clock_bracket_ns'], 100_000)
        self.assertEqual(policy['raw_rate_tolerance_ppm'], 1000)
        self.assertEqual(policy['qualification_minimum_span_seconds'], 180)
        self.assertEqual(policy['pacing_gates'], runner.legacy.GATES)
        self.assertEqual(policy['maximum_consecutive_integrity_failures'], 3)
        self.assertEqual(policy['same_code_failure_count'], 4)
        self.assertEqual(policy['same_code_window_completed_trials'], 8)

    def test_suffix_preserves_all_original_trial_identities_and_order(self):
        schedule = original_schedule()
        snapshot = deepcopy(schedule)
        expected = [(block, mode) for block in schedule for mode in block['modes']]
        suffix = c.remaining_schedule(schedule)
        self.assertEqual(len(suffix), 159)
        self.assertEqual([item['ordinal'] for item in suffix], list(range(2, 161)))
        for ordinal, (item, (block, mode)) in enumerate(zip(suffix, expected[1:]), 2):
            self.assertEqual(item['block'], block)
            self.assertEqual(item['mode'], mode)
            self.assertEqual(item['trial_directory'],
                             f'trial_{ordinal:03d}_{block["block_id"]}_{mode}')
        self.assertEqual(schedule, snapshot, 'Suffix derivation must not mutate the sealed schedule')
        self.assertNotIn(f'trial_001_{expected[0][0]["block_id"]}_{expected[0][1]}',
                         [item['trial_directory'] for item in suffix])

    def test_suffix_rejects_changed_original_schedule(self):
        schedule = original_schedule()
        for changed in (schedule[:-1], schedule + [deepcopy(schedule[0])]):
            with self.subTest(length=len(changed)), self.assertRaises(ValueError):
                c.remaining_schedule(changed)
        altered = deepcopy(schedule)
        altered[0]['rate_pps'] = 2000
        with self.assertRaises(ValueError):
            c.remaining_schedule(altered)


class OperationalStopTests(unittest.TestCase):
    def test_isolated_failure_can_continue_without_mutating_verdict(self):
        rows = [integrity_row(), integrity_row(valid=False), integrity_row()]
        before = deepcopy(rows)
        self.assertIsNone(c.operational_stop(rows))
        self.assertEqual(rows, before)
        self.assertFalse(rows[1]['valid'])

    def test_three_consecutive_integrity_failures_stop(self):
        rows = [integrity_row(), integrity_row(valid=False, code='one'),
                integrity_row(valid=False, code='two'), integrity_row(valid=False, code='three')]
        self.assertIsNotNone(c.operational_stop(rows))
        self.assertIsNone(c.operational_stop(rows[:-1]))

    def test_pass_resets_consecutive_failures(self):
        rows = [integrity_row(valid=False, code='one'), integrity_row(valid=False, code='two'),
                integrity_row(), integrity_row(valid=False, code='three'),
                integrity_row(valid=False, code='four')]
        self.assertIsNone(c.operational_stop(rows))

    def test_four_same_codes_in_last_eight_completed_trials_stop(self):
        rows = [integrity_row(valid=False) if index % 2 == 1 else integrity_row()
                for index in range(8)]
        self.assertIsNotNone(c.operational_stop(rows))
        self.assertIsNone(c.operational_stop(rows[:-1]))

    def test_same_code_outside_rolling_window_does_not_stop(self):
        rows = [integrity_row(valid=False), integrity_row()]
        rows += [integrity_row(valid=False) if index in (1, 3, 5) else integrity_row()
                 for index in range(8)]
        self.assertIsNone(c.operational_stop(rows))

    def test_warmup_quality_codes_count_without_losing_their_phase(self):
        rows = [integrity_row(valid=False, warmup=True) if index % 2 == 0 else integrity_row()
                for index in range(8)]
        original = deepcopy(rows)
        self.assertIsNotNone(c.operational_stop(rows))
        self.assertEqual(rows, original)

    def test_generic_warmup_wrapper_does_not_hide_actual_different_codes(self):
        rows = []
        for index in range(8):
            if index % 2:
                rows.append(integrity_row())
            else:
                row = integrity_row(valid=False, code=f'concrete_{index}', warmup=True)
                row['failures'] = ['Disjoint warm-up measurement integrity/counter accounting failed']
                rows.append(row)
        self.assertIsNone(c.operational_stop(rows))

    def test_pacing_warnings_do_not_count_as_integrity_failures(self):
        rows = [integrity_row(pacing_warning=True) for _ in range(10)]
        self.assertIsNone(c.operational_stop(rows))

    def test_resource_exhaustion_is_immediate_stop_not_three_trial_allowance(self):
        row = integrity_row(valid=False, code='Runner RSS exceeded its declared limit')
        self.assertIsNotNone(c.operational_stop([row]))

    def test_resource_sampling_failure_is_invalid_but_not_automatic_resource_exhaustion(self):
        row = integrity_row(valid=False, code='RAW resource-window sampling failed')
        self.assertIsNone(c.operational_stop([row]))

    def test_global_recurring_failure_is_not_hidden_by_different_clock_failures(self):
        rows = []
        for index in range(8):
            row = integrity_row(valid=index % 2 == 0, code=f'distinct_clock_event_{index}')
            if not row['valid']:
                row['failures'].append('RAW resource-window sampling failed')
            rows.append(row)
        self.assertIsNotNone(c.operational_stop(rows))


class QualificationTests(unittest.TestCase):
    def test_inconclusive_session_masks_rate_metrics_but_not_valid_counts_or_memory(self):
        row = integrity_row()
        row['metric_validity'].update(offered_load=True, delivered_throughput=True,
            classification_rate=True, cpu=True, packet_accounting=True, memory=True)
        runner.apply_rate_qualification([row], False, dict(status='INCONCLUSIVE'))
        self.assertFalse(row['valid'])
        for metric in ('offered_load', 'delivered_throughput', 'classification_rate', 'cpu'):
            self.assertFalse(row['metric_validity'][metric])
        self.assertTrue(row['metric_validity']['packet_accounting'])
        self.assertTrue(row['metric_validity']['memory'])
        self.assertEqual(row['verdicts']['independent_raw_qualification']['status'], 'INCONCLUSIVE')

    def test_passing_new_session_does_not_promote_integrity_invalid_trial(self):
        row = integrity_row(valid=False)
        row['metric_validity'].update(offered_load=True, delivered_throughput=True,
            classification_rate=True, cpu=True)
        runner.apply_rate_qualification([row], True, dict(status='PASS'))
        self.assertFalse(row['valid'])
        self.assertEqual(row['failures'], ['raw_clock_sample_gap_over_25ms'])
        for metric in ('offered_load', 'delivered_throughput', 'classification_rate', 'cpu'):
            self.assertFalse(row['metric_validity'][metric])


class ExclusiveEvidenceTests(unittest.TestCase):
    def test_real_trial_seal_rejects_mutation_and_duplicate_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            trial = Path(temporary)
            runner.write_json(trial / 'trial_summary.json', dict(valid=False, failures=['historical']))
            seal = c.seal_trial_evidence(trial)
            self.assertIn('trial_summary.json', seal['artifact_hashes'])
            runner.legacy.verify_seal(trial, seal['artifact_hashes'])
            with self.assertRaises(FileExistsError):
                c.seal_trial_evidence(trial)
            (trial / 'trial_summary.json').write_text('{"valid":true}')
            with self.assertRaises(ValueError):
                runner.legacy.verify_seal(trial, seal['artifact_hashes'])

    def test_exclusive_session_claim_rejects_second_suffix_acquisition(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / 'results').mkdir()
            history = dict(source_root=str(repo / 'historical'), summary_sha256='a' * 64)
            claim = Path(c.claim_session(repo, history, repo / 'first_session'))
            original = claim.read_bytes()
            with self.assertRaises(FileExistsError):
                c.claim_session(repo, history, repo / 'replacement_session')
            self.assertEqual(claim.read_bytes(), original)
            self.assertFalse(json.loads(original)['retry_permitted'])

    def test_actual_historical_seal_binding_and_failed_trial_are_verified_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            history = repo / 'historical'
            history.mkdir()
            prepared = repo / 'prepared'
            prepared.mkdir()
            (prepared / 'manifest.json').write_text('{}')
            schedule = original_schedule()
            protocol = runner.benchmark_protocol(list(runner.FINAL_RATES))
            block, mode = schedule[0], schedule[0]['modes'][0]
            first_name = f'trial_001_{block["block_id"]}_{mode}'
            row = v5_rows(count=1, invalid_indices=(0,))[0]
            row.update(mode=mode, workload=block['workload'], rate_pps=block['rate_pps'],
                       block_id=block['block_id'], repetition=block['repetition'],
                       instrument_valid_before_rate_qualification=False)
            row['metrics'].update(packets_sent=20000, packets_received=19950, packets_lost=50)
            row['verdicts']['independent_raw_qualification']['status'] = 'INCONCLUSIVE'
            summary = fixture_v5(history, [row], qualified=False)
            (history / 'trial_0').rename(history / first_name)
            summary.update(trials=[first_name], cleanup_errors=[], frozen_inputs_unchanged=True,
                           completed_trials=1, attempted_trials=1, partial_trials=[])
            summary['protocol'] = protocol
            attempt = summary['attempts'][0]
            attempt.update(ordinal=1, mode=mode, workload=block['workload'], rate_pps=block['rate_pps'],
                           block_id=block['block_id'], repetition=block['repetition'],
                           trial_directory=first_name)
            for key in ('start_receipt', 'result_receipt'):
                path = history / attempt[key]
                payload = json.loads(path.read_text())
                payload.update(attempt)
                path.write_text(json.dumps(payload))
            (history / 'schedule.json').write_text(json.dumps(dict(
                schema_version=runner.SCHEMA, schedule=schedule, protocol=protocol)))
            (history / 'provenance.json').write_text(json.dumps(dict(prepared_directory=str(prepared),
                prepared_manifest_sha256=runner.hash_file(prepared / 'manifest.json'))))
            summary['artifact_hashes'] = {name: value for name, value in runner.pilot.seal(history).items()
                                          if name != 'summary.json'}
            (history / 'summary.json').write_text(json.dumps(summary))
            before = {path.relative_to(history).as_posix(): path.read_bytes()
                      for path in history.rglob('*') if path.is_file()}
            manifest = dict(schedule=schedule, protocol=protocol)
            with patch.object(runner, 'load_prepared', return_value=(manifest, {}, None, None)):
                receipt, actual_manifest, _, _, _ = c.verify_history(history, prepared, Path('/switch'))
            self.assertEqual(actual_manifest, manifest)
            self.assertEqual(receipt['original_missing_output_packets'], 50)
            self.assertFalse(receipt['timing_requalified'])
            self.assertTrue(receipt['original_verdicts_unchanged'])
            self.assertEqual({path.relative_to(history).as_posix(): path.read_bytes()
                              for path in history.rglob('*') if path.is_file()}, before)
            (history / first_name / 'measurement.json').write_text('{"changed":true}')
            with patch.object(runner, 'load_prepared', return_value=(manifest, {}, None, None)), \
                    self.assertRaises(ValueError):
                c.verify_history(history, prepared, Path('/switch'))


class PreparedBindingTests(unittest.TestCase):
    def reload_case(self, mutate=None):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            prepared = repo / 'prepared'
            prepared.mkdir()
            protocol, schedule = runner.benchmark_protocol(list(runner.FINAL_RATES)), original_schedule()
            history = dict(source_root=str(repo / 'history'), summary_sha256='a' * 64)
            original = dict(protocol=protocol, schedule=schedule, programs={'frozen': True},
                            raw_clock_library='/original_clock.so', raw_sender_library='/original_sender.so',
                            prior_calibration_receipts=[{'original_failure': 'preserved'}])
            receipt = dict(receipt_sha256='clock_receipt')
            backend = SimpleNamespace(provenance={'unchanged': True})
            manifest = dict(schema_version=c.SCHEMA, status='prepared', artifact_hashes={}, input_sha256={},
                historical_campaign=history, original_prepared=str(repo / 'original_prepared'),
                protocol=deepcopy(protocol), schedule=deepcopy(schedule),
                remaining_schedule=c.remaining_schedule(schedule), continuation_policy=c.continuation_policy(),
                programs=deepcopy(original['programs']), expected_trials=160, expected_session_trials=159,
                expected_live_trials=159, scheduled_phase_seconds=4611,
                raw_clock_provenance=backend.provenance, raw_sender_provenance=backend.provenance,
                raw_clock_library=original['raw_clock_library'], raw_sender_library=original['raw_sender_library'],
                prior_calibration_receipts=deepcopy(original['prior_calibration_receipts']),
                clock_receipt_sha256=receipt['receipt_sha256'])
            runner.write_json(prepared / 'historical_campaign.json', history)
            runner.write_json(prepared / 'schedule.json', dict(schedule=schedule, protocol=protocol))
            runner.write_json(prepared / 'remaining_schedule.json', manifest['remaining_schedule'])
            manifest['artifact_hashes'] = runner.pilot.seal(prepared)
            if mutate == 'gate':
                manifest['continuation_policy']['maximum_clock_sampling_gap_ns'] = 26_000_000
            elif mutate == 'order':
                manifest['remaining_schedule'][0], manifest['remaining_schedule'][1] = \
                    manifest['remaining_schedule'][1], manifest['remaining_schedule'][0]
            elif mutate == 'count':
                manifest['expected_session_trials'] = 160
            elif mutate == 'backend':
                manifest['raw_clock_library'] = '/replacement_clock.so'
            elif mutate == 'historical':
                manifest['historical_campaign'] = dict(history, summary_sha256='b' * 64)
            elif mutate == 'prior_receipts':
                manifest['prior_calibration_receipts'] = []
            runner.write_json(prepared / 'manifest.json', manifest)
            args = SimpleNamespace(prepared=prepared, switch=Path('/switch'))
            with patch.object(c, 'verify_history', return_value=(history, original, receipt, backend, backend)) as verified, \
                    patch.object(runner.ownership, 'verify_hashes') as hashes:
                loaded = c.load_prepared(args)
            self.assertEqual(loaded[0], manifest)
            self.assertEqual(loaded[1], receipt)
            hashes.assert_called_once_with({})
            verified.assert_called_once_with(Path(history['source_root']), Path(manifest['original_prepared']), args.switch)

    def test_bound_reload_rechecks_history_original_schedule_backend_and_receipts(self):
        self.reload_case()

    def test_bound_reload_rejects_changes_to_policy_order_counts_backend_or_history(self):
        for mutate in ('gate', 'order', 'count', 'backend', 'historical', 'prior_receipts'):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.reload_case(mutate)

    def test_smoke_reuses_original_normal_programs_and_binds_new_session_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            args = SimpleNamespace(prepared=repo / 'new_prepared')
            args.prepared.mkdir()
            (args.prepared / 'manifest.json').write_text('{}')
            previous = repo / 'original_smoke'
            previous.mkdir()
            runner.write_json(previous / 'summary.json', dict(results=['8 normal file checks']))
            manifest = dict(original_prepared=str(repo / 'original_prepared'),
                historical_campaign=dict(prepared_manifest_sha256='original_manifest_hash'))
            receipt = dict(receipt_sha256='clock_receipt')
            with patch.object(c, 'load_prepared', return_value=(manifest, receipt, None, None)), \
                    patch.object(runner, 'smoke', return_value=previous) as unchanged_smoke, \
                    redirect_stdout(io.StringIO()):
                result = c.smoke(args, repo)
            self.assertEqual(unchanged_smoke.call_args.args[0].prepared, Path(manifest['original_prepared']))
            summary = json.loads((result / 'summary.json').read_text())
            self.assertEqual(summary['prepared_manifest_sha256'], c.hash_file(args.prepared / 'manifest.json'))
            self.assertEqual(summary['original_prepared_manifest_sha256'], 'original_manifest_hash')
            self.assertEqual(summary['clock_receipt_sha256'], 'clock_receipt')
            self.assertFalse(summary['live_interfaces_accessed'])
            self.assertFalse(summary['performance_measured'])
            self.assertFalse(summary['raw_sender_live_pacing_qualified'])


class ContinuationCampaignTests(unittest.TestCase):
    def exercise(self, *, invalid_ordinals=(), partial_ordinal=None, warning_ordinal=None,
                 qualification_passed=True, boundary_error_after=None, seal_error_ordinal=None):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / 'results').mkdir()
            original_prepared = repo / 'original_prepared'
            original_prepared.mkdir()
            (original_prepared / 'manifest.json').write_text('{}')
            prepared = repo / 'prepared'
            prepared.mkdir()
            (prepared / 'manifest.json').write_text('{}')
            historical = repo / 'historical'
            historical.mkdir()
            runner.write_json(historical / 'summary.json', dict(valid=False, missing_packets=50))
            runner.write_json(historical / 'trial_summary.json',
                              dict(valid=False, metrics=dict(packets_sent=20000, packets_received=19950,
                                                             packets_lost=50)))
            historical_bytes = {path.name: path.read_bytes() for path in historical.iterdir()}
            protocol = runner.benchmark_protocol(list(runner.FINAL_RATES))
            blocks = original_schedule()
            for block in blocks:
                block['plan_file'] = 'plans/' + block['block_id'] + '.json'
                warm, measured = fake_plans(block, protocol)
                (original_prepared / 'plans').mkdir(exist_ok=True)
                runner.write_json(original_prepared / block['plan_file'], dict(warmup=warm.manifest(),
                    measurement=measured.manifest(), warmup_frames_sha256='frames', measurement_frames_sha256='frames'))
            history = dict(source_root=str(historical), summary_sha256=runner.hash_file(historical / 'summary.json'),
                prepared_manifest_sha256=runner.hash_file(original_prepared / 'manifest.json'),
                original_verdicts_unchanged=True, original_missing_output_packets=50, timing_requalified=False)
            manifest = dict(schema_version=c.SCHEMA, protocol=protocol, schedule=blocks,
                remaining_schedule=c.remaining_schedule(blocks), original_prepared=str(original_prepared),
                historical_campaign=history, continuation_policy=c.continuation_policy(),
                expected_session_trials=159, expected_trials=160, expected_live_trials=159,
                programs={mode: dict(path='/mock_normal_build.json') for mode in runner.legacy.MODES}, input_sha256={})
            args = SimpleNamespace(prepared=prepared, smoke_run=repo / 'smoke')
            receipt = dict(receipt_sha256='verified_receipt')
            calls, originals, partial_bytes, created_links, qualifiers = [], {}, {}, [], []
            untrusted_names = set()
            actual_seal = c.seal_trial_evidence

            def sealing(directory):
                ordinal = int(directory.name.split('_')[1])
                if ordinal == seal_error_ordinal:
                    untrusted_names.add(directory.name)
                    raise ValueError('Synthetic corrupted trial evidence seal')
                return actual_seal(directory)

            class Links:
                def __init__(self, *unused):
                    self.cleanup_errors, self.cleaned = [], False
                    created_links.append(self)
                def __enter__(self):
                    return self
                def __exit__(self, *unused):
                    self.cleaned = True

            class Qualifier:
                def __init__(self, **unused):
                    self.records = [dict(valid=True, query_brackets_valid=True)]
                    self.pins = {name: {} for name in runner.raw_clock.PROVIDERS}
                    self.stopped = False
                    qualifiers.append(self)
                def start(self):
                    pass
                def stop(self):
                    self.stopped = True
                def report(self, start, end, *, load_windows):
                    self.windows = deepcopy(load_windows)
                    return dict(passed=qualification_passed,
                                status='PASS' if qualification_passed else 'INCONCLUSIVE')

            def boundary(*unused, **unused_keywords):
                if boundary_error_after is not None and len(calls) >= boundary_error_after:
                    raise RuntimeError('Synthetic cleanup/environment failure')
                return dict(environment_verified=True)

            def trial(*positional, qualifier=None):
                mode, block, directory = positional[2], positional[3], positional[-1]
                ordinal = len(calls) + 2
                self.assertIs(qualifier, qualifiers[0])
                self.assertTrue((directory.parent / 'attempts' / f'attempt_{ordinal:03d}_start.json').is_file())
                self.assertFalse(directory.exists(), 'Fresh original trial identity cannot be reused')
                directory.mkdir()
                calls.append((ordinal, mode, deepcopy(block), directory.name))
                if ordinal == partial_ordinal:
                    runner.write_json(directory / 'partial_measurement.json', dict(input_count=17, output_count=16))
                    partial_bytes[directory.name] = (directory / 'partial_measurement.json').read_bytes()
                    raise RuntimeError('Synthetic acquisition exception after partial evidence')
                row = integrity_row(valid=ordinal not in invalid_ordinals,
                                    pacing_warning=ordinal == warning_ordinal)
                row.update(mode=mode, workload=block['workload'], rate_pps=block['rate_pps'],
                    block_id=block['block_id'], repetition=block['repetition'],
                    metrics=dict(packets_sent=block['rate_pps'] * 20,
                                 packets_received=block['rate_pps'] * 20, decisions=None),
                    rate_window=dict(start_raw_ns=ordinal * 30 * 10**9,
                                     end_raw_ns=(ordinal * 30 + 20) * 10**9,
                                     target_pps=block['rate_pps'], mode=mode, workload=block['workload']))
                row['metric_validity'].update(offered_load=True, delivered_throughput=True,
                    classification_rate=True, cpu=True, packet_accounting=True, cpu_accounting=True)
                row['verdicts']['independent_raw_qualification'] = dict(status='NOT_EVALUATED')
                pacing = row['verdicts']['sender_pacing_conformance']
                pacing.update(warmup=dict(status='PASS', warnings=[]),
                    measurement=dict(status=pacing['status'],
                                     warnings=['Unchanged pacing limit exceeded'] if ordinal == warning_ordinal else []))
                runner.write_json(directory / 'trial_summary.json', row)
                originals[directory.name] = (directory / 'trial_summary.json').read_bytes()
                return row

            with patch.object(c.os, 'geteuid', return_value=0, create=True), \
                    patch.object(c, 'load_prepared', return_value=(manifest, receipt,
                        SimpleNamespace(read=lambda: None, provenance={}), SimpleNamespace(provenance={}))), \
                    patch.object(c, 'verify_smoke'), patch.object(c, 'verify_boundary', side_effect=boundary), \
                    patch.object(runner.legacy, 'exclusive_run', side_effect=lambda unused: nullcontext()), \
                    patch.object(runner.legacy, 'resource_preflight', return_value={}), \
                    patch.object(runner.legacy, 'host_snapshot', return_value={}), \
                    patch.object(runner.legacy, 'plans_for', side_effect=fake_plans), \
                    patch.object(runner.legacy, 'frame_hash', return_value='frames'), \
                    patch.object(runner.ownership, 'OwnedLinks', Links), \
                    patch.object(runner.raw_clock, 'RateQualification', Qualifier), \
                    patch.object(c, 'seal_trial_evidence', side_effect=sealing), \
                    patch.object(c, 'run_trial', side_effect=trial), redirect_stdout(io.StringIO()):
                output = c.run(args, repo)
            summary = json.loads((output / 'summary.json').read_text())
            expected_completed = (partial_ordinal - 2 if partial_ordinal is not None else
                                  seal_error_ordinal - 2 if seal_error_ordinal is not None else
                                  boundary_error_after if boundary_error_after is not None else
                                  3 if invalid_ordinals == (2, 3, 4) else 159)
            self.assertEqual(len(originals), expected_completed + int(seal_error_ordinal is not None))
            self.assertEqual(summary['completed_trials'], expected_completed)
            self.assertEqual(summary['attempted_trials'], len(calls))
            self.assertEqual(summary['campaign_attempted_trials'], 1 + len(calls))
            self.assertEqual(summary['campaign_completed_trials'], 1 + expected_completed)
            self.assertEqual(summary['expected_session_trials'], 159)
            self.assertTrue(summary['separately_executed_session'])
            self.assertFalse(summary['historical_trial_requalified'])
            self.assertFalse(summary['kernel_forwarding_latency_qualified'])
            self.assertFalse(summary['isolated_inference_latency_measured'])
            self.assertTrue(created_links[0].cleaned)
            self.assertTrue(qualifiers[0].stopped)
            self.assertFalse(summary['clock_rate_qualification']['historical_session_included'])
            self.assertEqual(summary['clock_rate_qualification']['execution_session_id'], output.name)
            self.assertEqual([item['ordinal'] for item in summary['attempts']], list(range(2, 2 + len(calls))))
            expected_suffix = manifest['remaining_schedule'][:len(calls)]
            self.assertEqual([(o, mode, block, name) for o, mode, block, name in calls],
                             [(item['ordinal'], item['mode'], item['block'], item['trial_directory'])
                              for item in expected_suffix])
            for path in historical.iterdir():
                self.assertEqual(path.read_bytes(), historical_bytes[path.name])
            self.assertEqual(len(list(historical.iterdir())), len(historical_bytes))
            valid_windows = [ordinal for ordinal, _, _, _ in calls
                             if ordinal not in (partial_ordinal, seal_error_ordinal)
                             and ordinal not in invalid_ordinals]
            self.assertEqual([window['start_raw_ns'] // (30 * 10**9) for window in qualifiers[0].windows],
                             valid_windows, 'Only new-session integrity-valid windows can qualify')
            for name, before in originals.items():
                self.assertEqual((output / name / 'trial_summary.json').read_bytes(), before)
                if name in untrusted_names:
                    self.assertFalse((output / name / 'qualified_trial_summary.json').exists())
                    self.assertIn(name + '/trial_summary.json', summary['artifact_hashes'])
                    continue
                qualified_row = json.loads((output / name / 'qualified_trial_summary.json').read_text())
                local = json.loads(before)
                self.assertEqual(qualified_row['valid'],
                                 local['valid'] and qualification_passed and summary['frozen_inputs_unchanged'])
                self.assertEqual(qualified_row['execution_session_id'], output.name)
                if not local['valid'] or not qualification_passed or not summary['frozen_inputs_unchanged']:
                    for metric in ('offered_load', 'delivered_throughput', 'classification_rate', 'cpu'):
                        self.assertFalse(qualified_row['metric_validity'][metric])
                if not qualification_passed:
                    self.assertTrue(qualified_row['metric_validity']['packet_accounting'])
                    self.assertTrue(qualified_row['metric_validity']['memory'])
                self.assertEqual(local['verdicts']['independent_raw_qualification']['status'], 'NOT_EVALUATED')
                trial_seal = json.loads((output / name / 'trial_evidence_seal.json').read_text())
                runner.legacy.verify_seal(output / name, trial_seal['artifact_hashes'])
            for name, before in partial_bytes.items():
                self.assertEqual((output / name / 'partial_measurement.json').read_bytes(), before)
                self.assertFalse((output / name / 'qualified_trial_summary.json').exists())
                self.assertIn(name + '/partial_measurement.json', summary['artifact_hashes'])
            runner.legacy.verify_seal(output, summary['artifact_hashes'])
            return summary

    def test_all159_complete_once_with_original_ordinals_and_fresh_session_certificate(self):
        result = self.exercise()
        self.assertTrue(result['acquisition_complete'])
        self.assertEqual(result['valid_trials'], 159)

    def test_completed_invalid_trial_continues_but_is_never_promoted(self):
        result = self.exercise(invalid_ordinals=(2,))
        self.assertTrue(result['acquisition_complete'])
        self.assertEqual(result['valid_trials'], 158)
        self.assertFalse(result['passed'])

    def test_three_consecutive_failures_stop_with_remaining_trials_unattempted(self):
        result = self.exercise(invalid_ordinals=(2, 3, 4))
        self.assertFalse(result['acquisition_complete'])
        self.assertIn('three consecutive', result['abort_reason'])

    def test_pacing_warning_continues_and_is_reported(self):
        result = self.exercise(warning_ordinal=2)
        self.assertTrue(result['acquisition_complete'])
        self.assertEqual(result['pacing_warning_trials'], 1)

    def test_inconclusive_new_session_preserves_counts_and_withholds_rates(self):
        result = self.exercise(qualification_passed=False)
        self.assertTrue(result['acquisition_complete'])
        self.assertEqual(result['valid_trials'], 0)

    def test_partial_acquisition_exception_preserves_files_and_stops_without_retries(self):
        result = self.exercise(partial_ordinal=4)
        self.assertFalse(result['acquisition_complete'])
        self.assertEqual(len(result['partial_trials']), 1)
        self.assertIn('Synthetic acquisition exception', result['abort_reason'])

    def test_cleanup_environment_failure_stops_after_recorded_trial(self):
        result = self.exercise(boundary_error_after=1)
        self.assertFalse(result['acquisition_complete'])
        self.assertIn('environment', result['abort_reason'])

    def test_corrupted_evidence_seal_preserves_untrusted_files_and_exception_receipt(self):
        result = self.exercise(seal_error_ordinal=3)
        self.assertFalse(result['acquisition_complete'])
        self.assertEqual(result['attempted_trials'], 2)
        self.assertEqual(result['completed_trials'], 1)
        self.assertEqual(len(result['partial_trials']), 1)
        self.assertEqual(result['attempts'][-1]['status'], 'exception')
        self.assertIn('corrupted trial evidence', result['abort_reason'])


if __name__ == '__main__':
    unittest.main()
