"""Unprivileged runner bookkeeping tests: no real sockets, switches or fitting."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_native_evaluation as runner
from test_analyze_native_evaluation import case_fixture, forest, frames_for, outcome as analysis_outcome


def outcome(case, model, **kwargs):
    """Synthetic successful transport needs explicit clock evidence for stage pass."""
    row = analysis_outcome(case, model, **kwargs)
    row['clock_quality'] = runner.analysis.clock_quality([100000 + index * 1000 for index in range(8)])
    return row


def sample_case(case_id='case_a', original_index=1):
    case = case_fixture(case_id, original_index)
    case['record']['record_id'] = case_id
    return case


def counters(prediction=0, count=0, byte_count=0):
    return {index: {'packets': count if index == prediction else 0,
                    'bytes': byte_count if index == prediction else 0} for index in range(6)}


class FramePlanTests(unittest.TestCase):
    def test_original_bodies_offsets_immutable_and_unique_tags(self):
        cases = {name: sample_case(name, index) for index, name in enumerate(('case_a', 'case_b'), 1)}
        batch = {'cases': [{'case_id': 'case_a', 'start_offset_us': 123},
                           {'case_id': 'case_b', 'start_offset_us': 456}]}
        before = copy.deepcopy((cases, batch))
        plans, analysis_cases = runner.frame_plans(batch, cases)
        self.assertEqual((cases, batch), before)
        self.assertEqual(len({plan['frames'][0][:12] for plan in plans}), 2)
        for plan in plans:
            source = cases[plan['case_id']]
            self.assertEqual(plan['relative_us'], source['relative_us'])
            self.assertEqual(plan['start_offset_us'], next(row['start_offset_us'] for row in batch['cases']
                                                         if row['case_id'] == plan['case_id']))
            self.assertEqual(len(plan['frames']), 8)
            self.assertEqual(len({frame[:12] for frame in plan['frames']}), 1)
            self.assertEqual(plan['frames'][0][0], 2)
            self.assertEqual(plan['frames'][0][6], 2)
            for frame, saved in zip(plan['frames'], source['packets'], strict=True):
                self.assertEqual(frame[12:14], b'\x08\x00')
                self.assertEqual(frame[14:], bytes.fromhex(saved['raw_ip_hex']))
            self.assertEqual(analysis_cases[plan['case_id']]['ethernet_tag_hex'], plan['frames'][0][:12].hex())


class CounterTests(unittest.TestCase):
    def test_exact_counts_and_original_trigger_frame_bytes(self):
        case = sample_case()
        rows = [outcome(case, 'B')]
        expected = 14 + len(bytes.fromhex(case['packets'][7]['raw_ip_hex']))
        good = runner.check_counters(counters(count=1, byte_count=expected), rows, {case['case_id']: case})
        self.assertTrue(good['checked'] and good['passed'])
        self.assertEqual(good['expected_packets'], [1, 0, 0, 0, 0, 0])
        self.assertEqual(good['expected_bytes'], [expected, 0, 0, 0, 0, 0])
        # Native debug overhead must not be counted as ingress bytes.
        bad = runner.check_counters(counters(count=1, byte_count=expected + 123), rows, {case['case_id']: case})
        self.assertFalse(bad['passed'])

    def test_verified_unclassified_expected_zero_counter(self):
        case = sample_case()
        row = outcome(case, 'B', valid=False)
        row.update(transport_passed=True, parity_passed=True, classified=False,
                   status='verified_unclassified', verification_passed=True)
        result = runner.check_counters(counters(), [row], {case['case_id']: case})
        self.assertTrue(result['checked'] and result['passed'])
        self.assertEqual(result['expected_packets'], [0] * 6)
        self.assertEqual(result['expected_bytes'], [0] * 6)

    def test_missing_reports_do_not_fabricate_counter_reconciliation(self):
        first, second = sample_case(), sample_case('case_b', 2)
        rows = [outcome(first, 'B'), outcome(second, 'B', valid=False)]
        result = runner.check_counters(counters(count=2, byte_count=100), rows,
                                       {first['case_id']: first, second['case_id']: second})
        self.assertFalse(result['checked'])
        self.assertIn('Missing/corrupt', result['reason'])
        self.assertTrue(rows[0]['classified'])


class OutcomeTests(unittest.TestCase):
    def test_failure_records_original_identity_and_attempt_status(self):
        case = sample_case()
        row = runner.failure_outcome(case, 'C', 'socket_failure', 'denied')
        self.assertEqual(row['case_id'], case['record']['record_id'])
        self.assertEqual(row['original_record_id'], case['record']['record_id'])
        self.assertEqual(row['label'], case['record']['label'])
        self.assertEqual(row['status'], 'failed')
        self.assertTrue(row['attempted'])
        self.assertFalse(row['classified'])
        row = runner.failure_outcome(case, 'B', 'not_attempted', 'interrupted', attempted=False)
        self.assertEqual(row['status'], 'not_attempted')
        self.assertFalse(row['attempted'])

    def test_partial_batch_global_deadline_retains_good_case(self):
        first, second = sample_case(), sample_case('case_b', 2)
        observations = {'global_errors': ['Whole-batch deadline expired'], 'cases': {}}
        for case, valid in ((first, True), (second, False)):
            output = frames_for(case, forest()) if valid else []
            observations['cases'][case['case_id']] = {
                'transport_passed': valid, 'errors': [] if valid else ['missing'],
                'missing_input_indices': [] if valid else [7],
                'missing_output_indices': [] if valid else [7],
                'input_observations': [{}] * (8 if valid else 7),
                'output_observations': [{'frame_hex': frame.hex()} for frame in output],
                'sent_logs': [{'send_lateness_ns': index * 1000} for index in range(8)]}
        results = runner.analyze_transport({case['case_id']: case for case in (first, second)}, observations, forest())
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0]['verification_passed'])
        self.assertTrue(results[0]['classified'])
        self.assertFalse(results[1]['verification_passed'])
        self.assertFalse(results[1]['classified'])
        self.assertEqual(results[1]['failure_kind'], 'transport_failure')


class BatchClockTests(unittest.TestCase):
    def observations(self, *, global_regression=False):
        cases = [sample_case(), sample_case('case_b', 2)]
        observations = {'cases': {}}
        for rank, case in enumerate(cases):
            base = 100000 if rank == 0 else (99000 if global_regression else 101000)
            times = [base + index * 2000 for index in range(8)]
            frames = frames_for(case, forest(), times)
            observations['cases'][case['case_id']] = {
                'input_observations': [{'packet_index': index, 'monotonic_ns': (2 * index + rank) * 1000}
                                       for index in range(8)],
                # Egress collection order need not match ingress across conversations.
                'output_observations': [{'packet_index': index, 'frame_hex': frames[index].hex()}
                                        for index in reversed(range(8))]}
        return cases, observations

    def test_ingress_order_and_packet_occurrence_allow_output_interleaving(self):
        _, observations = self.observations()
        quality = runner.batch_clock_quality(observations)
        self.assertTrue(quality['clean'])
        self.assertTrue(quality['complete'])
        self.assertEqual(quality['matched_packets'], 16)
        self.assertEqual(quality['expected_packets'], 16)
        self.assertEqual(quality['raw_backward_steps'], 0)

    def test_cross_case_clock_regression_detected_when_each_local_clock_is_clean(self):
        _, observations = self.observations(global_regression=True)
        for item in observations['cases'].values():
            rows = sorted(item['output_observations'], key=lambda row: row['packet_index'])
            times = [runner.helpers.decode_report(bytes.fromhex(row['frame_hex']))['observed_us'] for row in rows]
            self.assertTrue(runner.analysis.clock_quality(times)['clean'])
        quality = runner.batch_clock_quality(observations)
        self.assertFalse(quality['clean'])
        self.assertTrue(quality['complete'])
        self.assertEqual(quality['raw_backward_steps'], 8)
        self.assertEqual(quality['max_backward_step_us'], 1000)
        self.assertEqual(quality['events'][0]['previous_case_id'], 'case_a')
        self.assertEqual(quality['events'][0]['case_id'], 'case_b')
        self.assertEqual(quality['events'][0]['previous_packet_position'], 1)
        self.assertEqual(quality['events'][0]['packet_position'], 1)

    def test_missing_output_occurrence_never_certifies_a_clean_complete_batch(self):
        _, observations = self.observations()
        observations['cases']['case_b']['output_observations'].pop()
        quality = runner.batch_clock_quality(observations)
        self.assertFalse(quality['clean'])
        self.assertFalse(quality['complete'])
        self.assertEqual(quality['matched_packets'], 15)
        self.assertEqual(quality['expected_packets'], 16)


class FinalizeTests(unittest.TestCase):
    def finalize(self, cases, rows, **kwargs):
        temporary = tempfile.TemporaryDirectory(prefix='native-runner-unit-')
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        with patch.object(runner, 'EXPECTED_CASES', len(cases)):
            summary, metrics = runner.finalize(directory, {'cases': cases}, rows,
                {'B': forest(), 'C': forest('C')}, completed=kwargs.get('completed', True),
                cleanup_passed=kwargs.get('cleanup_passed', True), execution_error=kwargs.get('execution_error'),
                model_fidelity=kwargs.get('model_fidelity'))
        saved = json.loads((directory / 'summary.json').read_text())
        self.assertEqual(saved, summary)
        self.assertEqual(json.loads((directory / 'metrics.json').read_text()), metrics)
        outcomes = [json.loads(line) for line in (directory / 'outcomes.jsonl').read_text().splitlines()]
        return directory, summary, metrics, outcomes

    def test_all_failed_no_fake_accuracy_and_full_denominator(self):
        case = sample_case()
        directory, summary, metrics, rows = self.finalize([case], [], completed=False, execution_error='Interrupted')
        self.assertFalse(summary['passed'])
        self.assertTrue((directory / 'failure.json').is_file())
        self.assertEqual(len(rows), 2)
        for model in 'BC':
            metric = metrics['models'][model]
            self.assertEqual(metric['classification_coverage'], 0)
            self.assertEqual(metric['correct_decision_rate_over_expected_population'], 0)
            self.assertIsNone(metric['native_conditional_metrics']['accuracy'])
            self.assertIsNone(metric['native_conditional_metrics']['macro_f1'])
        self.assertTrue(all(row['status'] == 'not_attempted' and not row['attempted'] for row in rows))

    def test_success_is_sealed_and_has_no_performance_claim(self):
        case = sample_case()
        directory, summary, metrics, _ = self.finalize([case], [outcome(case, model) for model in 'BC'])
        self.assertTrue(summary['passed'])
        self.assertTrue(summary['raw_clock_clean'])
        self.assertFalse(summary['performance_measured'])
        self.assertEqual(summary['verified_classified_evaluations'], 2)
        self.assertNotIn('summary.json', summary['output_sha256'])
        for name, expected in summary['output_sha256'].items():
            self.assertEqual(runner.native_prefix.sha256_file(directory / name), expected)

    def test_backward_clock_retains_diagnostic_metrics_but_blocks_stage_pass(self):
        case = sample_case()
        times = [100000, 101000, 99000, 100500, 104000, 105000, 106000, 107000]
        rows = []
        for model in 'BC':
            export = forest(model)
            rows.append(runner.analysis.compare_case(case, export, frames_for(case, export, times)))
        directory, summary, metrics, saved = self.finalize([case], rows)
        self.assertFalse(summary['passed'])
        self.assertFalse(summary['raw_clock_clean'])
        self.assertTrue((directory / 'failure.json').is_file())
        self.assertEqual(summary['verified_classified_evaluations'], 2)
        for model in 'BC':
            self.assertEqual(metrics['models'][model]['native_conditional_metrics']['records'], 1)
            self.assertEqual(metrics['models'][model]['classification_coverage'], 1)
        self.assertTrue(all(row['parity_passed'] for row in saved))
        self.assertTrue(all(row['clock_quality']['raw_backward_steps'] == 1 for row in saved))

    def test_missing_clock_evidence_cannot_certify_stage_pass(self):
        case = sample_case()
        rows = [outcome(case, model) for model in 'BC']
        rows[0].pop('clock_quality')
        _, summary, metrics, _ = self.finalize([case], rows)
        self.assertFalse(summary['passed'])
        self.assertFalse(summary['raw_clock_clean'])
        self.assertEqual(metrics['models']['B']['native_conditional_metrics']['records'], 1)

    def test_null_clock_evidence_cannot_certify_stage_pass(self):
        case = sample_case()
        rows = [outcome(case, model) for model in 'BC']
        rows[0]['clock_quality'] = None
        _, summary, _, _ = self.finalize([case], rows)
        self.assertFalse(summary['passed'])
        self.assertFalse(summary['raw_clock_clean'])

    def test_global_clock_regression_blocks_stage_pass_with_clean_local_cases(self):
        cases, observations = BatchClockTests().observations(global_regression=True)
        batch_quality = runner.batch_clock_quality(observations)
        rows = [outcome(case, model) for case in cases for model in 'BC']
        for row in rows:
            self.assertTrue(row['clock_quality']['clean'])
            row['batch_clock_quality'] = batch_quality
        _, summary, metrics, _ = self.finalize(cases, rows)
        self.assertFalse(summary['passed'])
        self.assertFalse(summary['raw_clock_clean'])
        self.assertEqual(summary['verified_classified_evaluations'], 4)
        self.assertEqual(metrics['models']['B']['native_conditional_metrics']['records'], 2)

    def test_null_batch_clock_evidence_cannot_certify_stage_pass(self):
        case = sample_case()
        rows = [outcome(case, model) for model in 'BC']
        rows[0]['batch_clock_quality'] = None
        _, summary, _, _ = self.finalize([case], rows)
        self.assertFalse(summary['passed'])
        self.assertFalse(summary['raw_clock_clean'])

    def test_source_integrity_error_prevents_success_even_after_completed_good_cases(self):
        case = sample_case()
        directory, summary, _, _ = self.finalize([case], [outcome(case, model) for model in 'BC'],
                                                execution_error='Input source checksum changed')
        self.assertFalse(summary['passed'])
        self.assertTrue((directory / 'failure.json').is_file())
        self.assertEqual(summary['execution_error'], 'Input source checksum changed')

    def test_global_batch_failure_prevents_stage_pass_but_preserves_good_metrics(self):
        case = sample_case()
        rows = [outcome(case, model) for model in 'BC']
        rows[0]['batch_transport_errors'] = ['Capture deadline expired elsewhere']
        _, summary, metrics, _ = self.finalize([case], rows)
        self.assertFalse(summary['passed'])
        self.assertEqual(summary['stage_transport_errors'], ['Capture deadline expired elsewhere'])
        self.assertEqual(metrics['models']['B']['verified_classified_records'], 1)

    def test_interrupt_retains_finished_model_and_marks_remaining_not_attempted(self):
        case = sample_case()
        _, summary, metrics, rows = self.finalize([case], [outcome(case, 'B')], completed=False,
                                                execution_error='User interrupted')
        self.assertFalse(summary['passed'])
        by_model = {row['model']: row for row in rows}
        self.assertEqual(by_model['B']['status'], 'verified_classified')
        self.assertEqual(by_model['C']['status'], 'not_attempted')
        self.assertEqual(metrics['models']['B']['classification_coverage'], 1)
        self.assertEqual(metrics['models']['C']['classification_coverage'], 0)

    def test_cleanup_failure_blocks_stage_success(self):
        case = sample_case()
        _, summary, _, _ = self.finalize([case], [outcome(case, model) for model in 'BC'], cleanup_passed=False)
        self.assertFalse(summary['passed'])
        self.assertFalse(summary['cleanup_passed'])

    def test_failed_original_model_fidelity_prevents_success(self):
        case = sample_case()
        fidelity = {'B': {'tested_vectors': 1, 'passed': True},
                    'C': {'tested_vectors': 1, 'passed': False, 'class_mismatches': 1}}
        directory, summary, metrics, _ = self.finalize([case], [outcome(case, model) for model in 'BC'],
                                                      model_fidelity=fidelity)
        self.assertFalse(summary['passed'])
        self.assertTrue((directory / 'failure.json').is_file())
        self.assertEqual(summary['original_sklearn_to_integer_native_vector_parity'], fidelity)
        self.assertEqual(metrics['original_sklearn_to_integer_native_vector_parity'], fidelity)

    def test_duplicate_unexpected_outcome_rejected_before_metrics(self):
        case = sample_case()
        rows = [outcome(case, 'B'), outcome(case, 'B')]
        with self.assertRaisesRegex(ValueError, 'Duplicate/unexpected'):
            self.finalize([case], rows)


class RunInterruptionTests(unittest.TestCase):
    def test_current_batch_is_attempted_future_batches_not_attempted_on_ctrl_c(self):
        with tempfile.TemporaryDirectory(prefix='native-run-interrupt-unit-') as temporary:
            root = Path(temporary)
            prepared, evidence = root / 'prepared', root / 'evidence'
            prepared.mkdir(); evidence.mkdir()
            (prepared / 'manifest.json').write_text('{}', encoding='utf-8')
            switch, cli = root / 'simple_switch', root / 'cli_python'
            for tool in (switch, cli, switch.with_name('simple_switch_CLI')):
                tool.write_text('', encoding='utf-8')
            first, future = sample_case(), sample_case('case_b', 2)
            population = {'cases': [first, future], 'input_sha256': {}}
            plan = {'batches': [{'batch_id': 'first', 'scheduled_span_us': 7000,
                                'cases': [{'case_id': first['case_id'], 'start_offset_us': 0}]},
                                {'batch_id': 'future', 'scheduled_span_us': 7000,
                                 'cases': [{'case_id': future['case_id'], 'start_offset_us': 0}]}]}
            manifest = {'programs': {model: {'path': str(root / ('rf_' + model + '.json'))} for model in 'BC'},
                        'clock_source_receipt': str(root / 'clock_receipt.json')}
            exports = {'B': forest(), 'C': forest('C')}
            by_id = {case['case_id']: case for case in population['cases']}
            links = SimpleNamespace(names=['owned_s1', 'owned_h1', 'owned_s2', 'owned_h2'], owned={}, cleanup_errors=[])
            class FakeLinks:
                exited = False
                def __enter__(self):
                    return links
                def __exit__(self, *args):
                    self.exited = True
            link_context = FakeLinks()
            # run() reads the same object's names outside its context, like OwnedLinks.
            for name in ('names', 'owned', 'cleanup_errors'):
                setattr(link_context, name, getattr(links, name))
            args = SimpleNamespace(prepared=prepared, switch=switch, cli_python=cli,
                                   grace_seconds=5, output_root=evidence)
            def batch_side_effect(args, program, batch, by_id, export, owned, directory):
                if export['feature_set'] == 'B':
                    return [outcome(first, 'B')]
                raise KeyboardInterrupt
            with patch.object(runner, 'EXPECTED_CASES', 2), \
                 patch.object(runner.sys, 'platform', 'linux'), \
                 patch.object(runner.os, 'geteuid', return_value=0), \
                 patch.object(runner.shutil, 'which', return_value='/fake/tool'), \
                 patch.object(runner, 'load_prepared', return_value=(population, plan, manifest, exports, by_id)), \
                 patch.object(runner.clock_contract, 'verify_receipt', return_value={'receipt_sha256': 'clock-fixture'}), \
                 patch.object(runner, 'versions', return_value={'unit_test': True}), \
                 patch.object(runner.pilot_runner, 'new_directory', return_value=evidence), \
                 patch.object(runner.pilot_runner, 'OwnedLinks', return_value=link_context), \
                 patch.object(runner.pilot_runner, 'verify_hashes'), \
                 patch.object(runner.pilot_runner, 'restore_new_evidence_owner') as restore_owner, \
                 patch.object(runner, 'native_model_fidelity', return_value={
                     'B': {'tested_vectors': 1, 'passed': True}, 'C': {'tested_vectors': 0, 'passed': None}}), \
                 patch.object(runner, 'run_batch', side_effect=batch_side_effect):
                _, passed, interrupted = runner.run(args, root)
            self.assertFalse(passed)
            self.assertTrue(interrupted)
            self.assertTrue(link_context.exited)
            restore_owner.assert_called_once_with(evidence)
            rows = [json.loads(line) for line in (evidence / 'outcomes.jsonl').read_text().splitlines()]
            indexed = {(row['case_id'], row['model']): row for row in rows}
            self.assertEqual(len(indexed), 4)
            self.assertEqual(indexed[(first['case_id'], 'B')]['status'], 'verified_classified')
            current = indexed[(first['case_id'], 'C')]
            self.assertTrue(current['attempted'])
            self.assertEqual(current['status'], 'failed')
            self.assertEqual(current['failure_kind'], 'interrupted_batch')
            for model in 'BC':
                self.assertFalse(indexed[(future['case_id'], model)]['attempted'])
                self.assertEqual(indexed[(future['case_id'], model)]['status'], 'not_attempted')


class FidelityTests(unittest.TestCase):
    def artifacts(self, root):
        paths, hashes = {}, {}
        for model in 'BC':
            folder = root / ('n8_RF_' + model)
            folder.mkdir()
            path = folder / 'model.joblib'
            path.write_bytes(b'Sealed unit fixture; never actually deserialize this file.')
            paths[model] = path.resolve()
            hashes[str(path.resolve())] = runner.native_prefix.sha256_file(path)
        return paths, {'deployment': str(root), 'input_sha256': hashes}

    def test_own_native_vectors_and_feature_order_exactly_preserved(self):
        with tempfile.TemporaryDirectory(prefix='native-fidelity-unit-') as temporary:
            paths, population = self.artifacts(Path(temporary))
            first, second = sample_case(), sample_case('case_b', 2)
            b_first = outcome(first, 'B'); b_first['features_C'] = dict(first['features_C'], iat_sum=11111)
            b_second = outcome(second, 'B'); b_second['features_C'] = dict(second['features_C'], iat_sum=22222)
            c_own = outcome(first, 'C'); c_own['features_C'] = dict(first['features_C'], iat_sum=33333,
                                                                 reverse_packet_count=6)
            invalid = outcome(second, 'C'); invalid.update(verification_passed=False, features_C=second['features_C'])
            exports = {'B': forest(), 'C': forest('C')}
            loaded, calls = [], []
            def load(path):
                loaded.append(path)
                return 'trusted-' + path.parent.name
            def verify(model, export, vectors):
                calls.append((model, export['feature_set'], copy.deepcopy(vectors)))
                return {'tested_vectors': len(vectors), 'passed': True}
            with patch.object(runner.reference.baseline.joblib, 'load', side_effect=load), \
                 patch.object(runner.reference, 'verify_parity', side_effect=verify):
                result = runner.native_model_fidelity(population, [c_own, b_second, invalid, b_first], exports)
            self.assertEqual(loaded, [paths['B'], paths['C']])
            self.assertEqual(calls[0][2], [[row['features_C'][name] for name in exports['B']['feature_order']]
                                         for row in (b_second, b_first)])
            self.assertEqual(calls[1][2], [[c_own['features_C'][name] for name in exports['C']['feature_order']]])
            self.assertEqual(result['B']['case_ids_in_vector_order'], ['case_b', 'case_a'])
            self.assertEqual(result['C']['case_ids_in_vector_order'], ['case_a'])
            self.assertEqual(len(calls[0][2][0]), 6)
            self.assertEqual(len(calls[1][2][0]), 8)
            self.assertEqual(result['B']['model_sha256'], population['input_sha256'][str(paths['B'])])

    def test_missing_unsealed_or_changed_artifact_rejected_before_load(self):
        for problem in ('unsealed', 'changed', 'missing'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory(prefix='native-fidelity-unit-') as temporary:
                paths, population = self.artifacts(Path(temporary))
                case = sample_case()
                row = outcome(case, 'B'); row['features_C'] = case['features_C']
                if problem == 'unsealed':
                    population['input_sha256'].pop(str(paths['B']))
                elif problem == 'changed':
                    paths['B'].write_bytes(b'Changed fixture')
                else:
                    paths['B'].unlink()  # Only the file this test just created inside TemporaryDirectory.
                with patch.object(runner.reference.baseline.joblib, 'load') as load, \
                     self.assertRaises((ValueError, OSError)):
                    runner.native_model_fidelity(population, [row], {'B': forest(), 'C': forest('C')})
                load.assert_not_called()

    def test_zero_verified_vectors_has_null_result_and_no_deserialization(self):
        case = sample_case()
        rows = [outcome(case, model, valid=False) for model in 'BC']
        with patch.object(runner.reference.baseline.joblib, 'load') as load, \
             patch.object(runner.reference, 'verify_parity') as verify:
            report = runner.native_model_fidelity({}, rows, {'B': forest(), 'C': forest('C')})
        for model in 'BC':
            self.assertEqual(report[model]['tested_vectors'], 0)
            self.assertIsNone(report[model]['passed'])
        load.assert_not_called()
        verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()
