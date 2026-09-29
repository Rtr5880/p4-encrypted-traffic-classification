"""Synthetic tests for development-only tuning; never research scores."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import train_capture_baseline as baseline
from test_train_capture_baseline import fixture
import tune_capture_baseline as tuning


def result(depth=5, count=10, score=0.7, leaves=20):
    return {'parameters': {'max_depth': depth, 'n_estimators': count},
            'mean_macro_f1': score, 'std_macro_f1': 0.01,
            'folds': [{'fold': f, 'macro_f1': score, 'fit_seconds': 0.1,
                       'model_size': {'trees': count, 'max_depth': depth,
                                      'leaves': leaves, 'nodes': leaves * 2 - count}}
                      for f in range(3)]}


def all_results():
    return {f'n{n}_{algorithm}_{feature}': [result(score=0.7 if feature == 'B' else 0.72)]
            for n in (4, 8) for algorithm in ('RF', 'XGB') for feature in ('B', 'C')}


class DevelopmentTuningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='etc-tuning-test-')
        self.root = Path(self.temp.name)
        with patch.object(baseline, 'load_extraction', return_value=(fixture(), {'synthetic_test_only': True})), redirect_stdout(io.StringIO()):
            self.prepared = baseline.prepare(self.root / 'source', self.root / 'prepared')

    def tearDown(self):
        self.temp.cleanup()

    def test_load_exposes_development_only(self):
        development, manifest, excluded = tuning.load_development(self.prepared)
        complete, _ = baseline.load_prepared(self.prepared)
        for n, rows in development.items():
            self.assertTrue(all(r['partition'] == 'development' for r in rows))
            self.assertEqual(len(rows) + excluded[str(n)], len(complete[n]))
            test_groups = {r['parent_candidate_conversation_id'] for r in complete[n] if r['partition'] == 'test'}
            self.assertFalse(test_groups & {r['parent_candidate_conversation_id'] for r in rows})
        self.assertEqual(manifest['search'], 'fixed')  # Original manifest stays fixed.

    def test_check_only_creates_no_output_and_fits_nothing(self):
        destination = self.root / 'no_output'
        with patch.object(baseline, 'select_configuration', side_effect=AssertionError('Unexpected fitting')), redirect_stdout(io.StringIO()):
            self.assertIsNone(tuning.tune(self.prepared, destination, check_only=True))
        self.assertFalse(destination.exists())

    def test_output_cannot_be_inside_prepared_evidence(self):
        with self.assertRaisesRegex(ValueError, 'outside the prepared'):
            tuning.tune(self.prepared, self.prepared / 'nested')

    def test_tampered_input_stops_before_search(self):
        with (self.prepared / 'table_n4.jsonl').open('a') as file:
            file.write('\n')
        with patch.object(baseline, 'select_configuration', side_effect=AssertionError('Unexpected fitting')):
            with self.assertRaisesRegex(ValueError, 'Prepared file changed'):
                tuning.tune(self.prepared, self.root / 'output')
        self.assertFalse((self.root / 'output').exists())

    def test_candidate_summary_measures_fold_models(self):
        summary = tuning.candidate_summary(result())
        self.assertEqual(summary['configuration_id'], 'depth5_count10')
        self.assertEqual(summary['trees_per_fold_model'], 10)
        self.assertEqual(summary['mean_fold_leaves'], 20)
        self.assertTrue(summary['is_original_configuration'])

    def test_incomplete_folds_rejected(self):
        candidate = result()
        candidate['folds'].pop()
        with self.assertRaisesRegex(ValueError, 'Incomplete fold results'):
            tuning.candidate_summary(candidate)

    def test_inconsistent_tree_counts_rejected(self):
        candidate = result()
        candidate['folds'][0]['model_size']['trees'] = 11
        with self.assertRaisesRegex(ValueError, 'Inconsistent tree counts'):
            tuning.candidate_summary(candidate)

    def test_dominated_candidate_is_marked_not_selected_by_cost_alone(self):
        candidates = [tuning.candidate_summary(result(depth=3, count=5, score=0.7, leaves=10)),
                      tuning.candidate_summary(result(depth=5, count=10, score=0.69, leaves=20)),
                      tuning.candidate_summary(result(depth=7, count=20, score=0.8, leaves=50))]
        marked = tuning.mark_tradeoffs(candidates)
        self.assertEqual([c['on_score_complexity_frontier'] for c in marked], [True, False, True])

    def test_equal_score_equal_cost_neither_dominates(self):
        original = tuning.candidate_summary(result())
        marked = tuning.mark_tradeoffs([original, copy.deepcopy(original)])
        self.assertTrue(all(c['on_score_complexity_frontier'] for c in marked))

    def test_matched_direction_comparison(self):
        compared = tuning.paired_comparison(all_results())
        self.assertEqual(len(compared), 4)
        for entries in compared.values():
            self.assertAlmostEqual(entries[0]['C_minus_B_mean_macro_f1'], 0.02)
            for delta in entries[0]['C_minus_B_by_fold']:
                self.assertAlmostEqual(delta, 0.02)

    def test_unmatched_configurations_fail(self):
        data = all_results()
        data['n4_RF_C'] = [result(count=20)]
        with self.assertRaisesRegex(ValueError, 'Unpaired B/C search configurations'):
            tuning.paired_comparison(data)

    def test_unmatched_fold_order_fails(self):
        data = all_results()
        data['n4_RF_C'][0]['folds'].reverse()
        with self.assertRaisesRegex(ValueError, 'Unpaired B/C fold results'):
            tuning.paired_comparison(data)

    def test_cli_preflight(self):
        with redirect_stdout(io.StringIO()):
            status = tuning.main(['--prepared', str(self.prepared), '--output-root', str(self.root / 'unused'), '--check-only'])
        self.assertEqual(status, 0)
        self.assertFalse((self.root / 'unused').exists())

    def test_partial_failure_is_not_reported_as_success(self):
        with patch.object(baseline, 'select_configuration', side_effect=ValueError('synthetic failure')), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'synthetic failure'):
                tuning.tune(self.prepared, self.root / 'failed')
        output, = (self.root / 'failed').iterdir()
        self.assertTrue((output / 'failure.json').exists())
        self.assertFalse((output / 'summary.json').exists())

    def test_real_synthetic_search_never_passes_test_rows_to_matrix(self):
        before = {p.name: baseline.digest(p) for p in self.prepared.iterdir()}
        original_matrix = baseline.matrix
        matrix_calls = []
        def guarded_matrix(rows, feature_set):
            self.assertTrue(rows)
            self.assertTrue(all(r['partition'] == 'development' for r in rows))
            matrix_calls.append((len(rows), feature_set))
            return original_matrix(rows, feature_set)
        with patch.object(baseline, 'matrix', side_effect=guarded_matrix), \
             patch.object(baseline, 'train', side_effect=AssertionError('Baseline test path called')), \
             patch.object(baseline, 'save_and_reload', side_effect=AssertionError('Unexpected final model export')), \
             redirect_stdout(io.StringIO()):
            output = tuning.tune(self.prepared, self.root / 'tuned')
        summary = baseline.read_json(output / 'summary.json')
        self.assertEqual(summary['status'], 'tuning_complete')
        self.assertEqual(summary['completed_fits'], 216)
        self.assertEqual(summary['test_records_scored'], 0)
        self.assertEqual(summary['final_models_refitted'], 0)
        self.assertEqual(len(matrix_calls), 432)  # One fitting + validation matrix per fit.
        self.assertEqual(len(baseline.read_rows(output / 'cv_progress.jsonl')), 72)
        self.assertEqual(before, {p.name: baseline.digest(p) for p in self.prepared.iterdir()})
        for name, experiment in summary['experiments'].items():
            self.assertEqual(len(experiment['candidates']), 9)
            self.assertGreaterEqual(experiment['best_validation_candidate']['mean_macro_f1'],
                                    experiment['original_configuration']['mean_macro_f1'])
            for candidate in experiment['candidates']:
                multiplier = 6 if '_XGB_' in name else 1
                self.assertEqual(candidate['trees_per_fold_model'], multiplier * candidate['parameters']['n_estimators'])
        self.assertTrue((output / 'report.md').exists())
        self.assertFalse(list(output.rglob('*.joblib')))
        self.assertFalse(list(output.rglob('*.ubj')))
        self.assertFalse(list(output.rglob('test_predictions.jsonl')))
        report = (output / 'report.md').read_text()
        self.assertIn('NOT scored', report)
        self.assertIn('not an unbiased estimate', report)


if __name__ == '__main__':
    unittest.main()
