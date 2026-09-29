"""Synthetic tests only: these scores are NOT research results."""
import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

import train_capture_baseline as baseline


def fixture():
    """Six labels, 30 parents per label, two instances per parent.

    N8 intentionally has fewer instances than N4. Repeated parent groups make
    it possible to detect accidental instance-level rather than parent splits.
    """
    tables = {4: [], 8: []}
    for label_id, label in enumerate(baseline.CLASSES):
        for parent_number in range(30):
            parent = f'{label}_{parent_number:03d}'
            for instance in range(2):
                for n in (4, 8):
                    if n == 8 and instance == 1:
                        continue
                    lo = 50 + label_id * 100 + parent_number
                    features = {'size_min': lo, 'size_max': lo + 10,
                                'size_sum': n * lo + 10, 'iat_min': 1,
                                'iat_max': 10 + label_id,
                                'iat_sum': (n - 1) * (5 + label_id)}
                    instance_id = f'{parent}:instance{instance}'
                    tables[n].append({
                        'record_id': f'{instance_id}:n{n}', 'instance_id': instance_id,
                        'parent_candidate_conversation_id': parent,
                        'capture_id': f'capture_{label}', 'capture_sha256': 'a' * 64,
                        'n': n, 'label': label, 'label_basis': 'capture_activity_hint',
                        'features_B': features,
                        'features_C': {**features, 'reverse_packet_count': 1,
                                       'direction_change_count': 1}})
    return tables


class TrainingBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='etc-baseline-test-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def prepared(self, search='fixed'):
        with patch.object(baseline, 'load_extraction', return_value=(fixture(), {'synthetic_test_only': True})), redirect_stdout(io.StringIO()):
            return baseline.prepare(self.root / 'synthetic_source', self.root / 'prepared', search)

    def test_feature_schema_and_pairing(self):
        tables = fixture()
        self.assertEqual(len(baseline.validate_tables(tables)), 180)
        self.assertEqual(len(baseline.B), 6)
        self.assertEqual(len(baseline.C), 8)

    def test_metadata_is_not_a_model_feature(self):
        rows = fixture()[4]
        xb, yb = baseline.matrix(rows, 'B')
        xc, yc = baseline.matrix(rows, 'C')
        np.testing.assert_array_equal(xb, xc[:, :6])
        np.testing.assert_array_equal(yb, yc)
        self.assertEqual(xb.shape, (360, 6))
        self.assertEqual(xc.shape, (360, 8))
        rows[0]['capture_id'] = 'THIS MUST NEVER BECOME A FEATURE'
        rows[0]['parent_candidate_conversation_id'] = 'nor this'
        np.testing.assert_array_equal(xb, baseline.matrix(rows, 'B')[0])

    def test_unexpected_feature_rejected(self):
        tables = fixture()
        tables[4][0]['features_C']['source_port'] = 443
        with self.assertRaisesRegex(ValueError, 'Unexpected model feature'):
            baseline.validate_tables(tables)

    def test_bc_feature_disagreement_rejected(self):
        tables = fixture()
        tables[4][0]['features_C']['size_sum'] += 1
        with self.assertRaisesRegex(ValueError, 'B/C feature mismatch'):
            baseline.validate_tables(tables)

    def test_invalid_numeric_features_rejected(self):
        for value in (-1, float('nan'), True, 2**48):
            with self.subTest(value=value):
                tables = fixture()
                tables[4][0]['features_B']['iat_sum'] = value
                tables[4][0]['features_C']['iat_sum'] = value
                with self.assertRaisesRegex(ValueError, 'nonnegative bounded integers'):
                    baseline.validate_tables(tables)

    def test_duplicate_record_rejected(self):
        tables = fixture()
        tables[4].append(copy.deepcopy(tables[4][0]))
        with self.assertRaisesRegex(ValueError, 'Duplicate record ID'):
            baseline.validate_tables(tables)

    def test_n8_must_have_n4_parent_provenance(self):
        tables = fixture()
        tables[8][0]['instance_id'] = 'orphan'
        tables[8][0]['record_id'] = 'orphan:n8'
        with self.assertRaisesRegex(ValueError, 'N8 lacks matching N4'):
            baseline.validate_tables(tables)

    def test_conflicting_parent_label_rejected(self):
        tables = fixture()
        tables[4][1]['label'] = 'VOIP'
        with self.assertRaisesRegex(ValueError, 'conflicting provenance/label'):
            baseline.validate_tables(tables)

    def test_group_splits_are_disjoint_and_shared_across_windows(self):
        tables = fixture()
        assignments = baseline.make_splits(tables)
        for n in (4, 8):
            rows = tables[n]
            dev = {r['parent_candidate_conversation_id'] for r in rows if r['partition'] == 'development'}
            test = {r['parent_candidate_conversation_id'] for r in rows if r['partition'] == 'test'}
            self.assertFalse(dev & test)
            for fold in range(3):
                train = {r['parent_candidate_conversation_id'] for r in rows if r['partition'] == 'development' and r['validation_fold'] != fold}
                valid = {r['parent_candidate_conversation_id'] for r in rows if r['partition'] == 'development' and r['validation_fold'] == fold}
                self.assertFalse(train & valid)
                self.assertFalse((train | valid) & test)
            for row in rows:
                self.assertEqual(assignments[row['parent_candidate_conversation_id']],
                                 {k: row[k] for k in ('partition', 'validation_fold')})
        baseline.check_splits(tables, assignments)

    def test_splits_deterministic(self):
        self.assertEqual(baseline.make_splits(fixture()), baseline.make_splits(fixture()))

    def test_modified_row_assignment_rejected(self):
        tables = fixture()
        assignments = baseline.make_splits(tables)
        tables[4][0]['partition'] = 'unassigned'
        with self.assertRaisesRegex(ValueError, 'Row/group split mismatch'):
            baseline.check_splits(tables, assignments)

    def test_missing_test_class_rejected(self):
        tables = fixture()
        assignments = baseline.make_splits(tables)
        for n in (4, 8):
            for row in tables[n]:
                if row['label'] == 'P2P' and row['partition'] == 'test':
                    row.update(partition='development', validation_fold=0)
                    assignments[row['parent_candidate_conversation_id']] = {'partition': 'development', 'validation_fold': 0}
        with self.assertRaisesRegex(ValueError, 'test: a class is absent'):
            baseline.check_splits(tables, assignments)

    def test_prepare_and_seal_round_trip(self):
        directory = self.prepared()
        tables, manifest = baseline.load_prepared(directory)
        self.assertEqual(len(tables[4]), 360)
        self.assertEqual(len(tables[8]), 180)
        self.assertTrue(manifest['preliminary'])
        self.assertFalse(manifest['labels_verified'])
        self.assertFalse(manifest['capture_disjoint'])
        self.assertFalse((directory / 'summary.json').exists())  # No training happened.
        self.assertNotEqual(directory, self.prepared())  # No overwriting an earlier run.

    def test_payload_edit_detected(self):
        directory = self.prepared()
        with (directory / 'table_n4.jsonl').open('a') as file:
            file.write('\n')
        with self.assertRaisesRegex(ValueError, 'Prepared file changed'):
            baseline.load_prepared(directory)

    def test_changed_environment_and_code_detected(self):
        directory = self.prepared()
        with patch.object(baseline, 'environment', return_value={'changed': True}):
            with self.assertRaisesRegex(ValueError, 'environment changed'):
                baseline.load_prepared(directory)
        old = baseline.read_json(directory / 'manifest.json')
        old['script_sha256'] = 'changed'
        (directory / 'manifest.json').write_text(json.dumps(old))
        with self.assertRaisesRegex(ValueError, 'Code changed'):
            baseline.load_prepared(directory)

    def test_failed_preparation_rejected(self):
        directory = self.prepared()
        baseline.write_json(directory / 'failure.json', {'error': 'synthetic'})
        with self.assertRaisesRegex(ValueError, 'marked failed'):
            baseline.load_prepared(directory)

    def test_test_rows_cannot_reach_configuration_selection(self):
        tables = fixture()
        baseline.make_splits(tables)
        with self.assertRaisesRegex(ValueError, 'Test rows reached model selection'):
            baseline.select_configuration(tables[4], 'B', 'RF', baseline.grid('fixed'), lambda value: None)

    def test_fitting_weights_use_only_passed_training_labels(self):
        class Recorder:
            def fit(self, x, y, **kwargs):
                self.kwargs = kwargs
        y = np.array([0, 0, 0, 1, 2, 3, 4, 5])
        model = Recorder()
        baseline.fit_model(model, 'XGB', np.zeros((8, 6)), y)
        expected = np.array([8 / 18] * 3 + [8 / 6] * 5)
        np.testing.assert_allclose(model.kwargs['sample_weight'], expected)
        baseline.fit_model(model, 'RF', np.zeros((8, 6)), y)
        self.assertEqual(model.kwargs, {})  # RF uses internal class_weight, not double weighting.

    def test_missing_fitting_class_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Fitting rows missing a class'):
            baseline.fit_model(None, 'RF', np.zeros((5, 6)), np.arange(5))

    def test_grid_is_fixed_before_test(self):
        self.assertEqual(baseline.grid('fixed'), [{'max_depth': 5, 'n_estimators': 10}])
        self.assertEqual(len(baseline.grid('compact')), 9)
        with self.assertRaises(ValueError):
            baseline.grid('unbounded')

    def test_real_estimators_serialization_and_size(self):
        x, y = baseline.matrix(fixture()[4], 'C')
        for algorithm, expected_trees in (('RF', 2), ('XGB', 12)):
            with self.subTest(algorithm=algorithm):
                model = baseline.make_model(algorithm, {'max_depth': 2, 'n_estimators': 2})
                baseline.fit_model(model, algorithm, x, y)
                size = baseline.complexity(model, algorithm)
                self.assertEqual(size['trees'], expected_trees)
                self.assertLessEqual(size['max_depth'], 2)
                json.dumps(size)  # Reject numpy scalars that cannot be written as JSON.
                directory = self.root / algorithm
                directory.mkdir()
                path, reloaded = baseline.save_and_reload(model, algorithm, directory)
                self.assertTrue(path.is_file())
                np.testing.assert_array_equal(model.predict(x), reloaded.predict(x))
                np.testing.assert_allclose(model.predict_proba(x), reloaded.predict_proba(x), rtol=0, atol=1e-12)

    def test_synthetic_end_to_end_all_eight_experiments(self):
        prepared = self.prepared()
        # Actual RF/XGB fits and serialization; skip eight redundant plot renders.
        with patch.object(baseline, 'plot_confusion'), redirect_stdout(io.StringIO()):
            output = baseline.train(prepared, self.root / 'trained')
        summary = baseline.read_json(output / 'summary.json')
        self.assertEqual(summary['status'], 'training_complete')
        self.assertEqual(len(summary['experiments']), 8)
        for name, metrics in summary['experiments'].items():
            self.assertTrue(metrics['reload_parity'])
            self.assertEqual(set(metrics['per_class_report']) & set(baseline.CLASSES), set(baseline.CLASSES))
            self.assertEqual(sum(map(sum, metrics['confusion_matrix'])), metrics['test_records'])
            self.assertEqual(metrics['model_size']['trees'], 60 if 'XGB' in name else 10)
        self.assertEqual(len(baseline.read_rows(output / 'cv_progress.jsonl')), 8)
        self.assertTrue((output / 'report.md').is_file())

    def test_plot_is_a_real_png(self):
        destination = self.root / 'confusion.png'
        baseline.plot_confusion(np.eye(6, dtype=int) * 10, destination, 'Synthetic test only')
        self.assertEqual(destination.read_bytes()[:8], b'\x89PNG\r\n\x1a\n')

    def test_failed_training_has_failure_not_success_summary(self):
        prepared = self.prepared()
        with patch.object(baseline, 'select_configuration', side_effect=ValueError('synthetic failure')), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'synthetic failure'):
                baseline.train(prepared, self.root / 'failed_training')
        output, = (self.root / 'failed_training').iterdir()
        self.assertTrue((output / 'failure.json').is_file())
        self.assertFalse((output / 'summary.json').exists())


if __name__ == '__main__':
    unittest.main()
