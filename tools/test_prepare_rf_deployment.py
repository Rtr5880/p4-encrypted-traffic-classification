"""Synthetic RF-export tests; none of these scores are research results.

The native scikit-learn estimator is the independent inference oracle.  These
tests do not read a capture, fit real development data, or score the test set.
"""
import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

import prepare_rf_deployment as deployment
import train_capture_baseline as baseline
from test_train_capture_baseline import fixture


def synthetic_vectors(feature_set, count=600, seed=803):
    """Diagnostic integer vectors, not necessarily realizable packet windows."""
    rng = np.random.default_rng(seed)
    return np.column_stack([
        rng.integers(deployment.DOMAINS[name]['min'],
                     deployment.DOMAINS[name]['max'] + 1,
                     size=count, dtype=np.int64)
        for name in deployment.FEATURES[feature_set]
    ])


def leaf(probabilities):
    return {'kind': 'leaf', 'probabilities': list(probabilities),
            'scores': [int(np.rint(p * deployment.SCALE)) for p in probabilities]}


class IntegerThresholdTests(unittest.TestCase):
    def test_small_domain_matches_exhaustive_native_predicate(self):
        for threshold in (-1.0, -0.1, 0.0, 0.5, 1.0, 2.25, 16.5, 31.0, 32.0):
            with self.subTest(threshold=threshold):
                matching = [x for x in range(32)
                            if float(np.float32(x)) <= threshold]
                self.assertEqual(deployment.integer_cut(threshold, 31),
                                 max(matching, default=-1))

    def test_float32_boundary_is_not_floor_of_native_threshold(self):
        upper = 2**26
        threshold = float(2**24)
        self.assertEqual(deployment.integer_cut(threshold, upper), 2**24 + 1)
        self.assertNotEqual(deployment.integer_cut(threshold, upper),
                            int(np.floor(threshold)))

    def test_large_integer_cuts_preserve_both_sides(self):
        upper = 419_999_993
        for center in (2**24, 2**25, 2**28, upper - 30):
            for delta in (-3.5, -1.0, 0.0, 0.5, 2.0, 3.5):
                threshold = center + delta
                with self.subTest(threshold=threshold):
                    cut = deployment.integer_cut(threshold, upper)
                    self.assertGreaterEqual(cut, -1)
                    self.assertLessEqual(cut, upper)
                    for value in range(max(0, cut - 5), min(upper, cut + 5) + 1):
                        self.assertEqual(value <= cut,
                                         float(np.float32(value)) <= threshold)
                    if cut >= 0:
                        self.assertLessEqual(float(np.float32(cut)), threshold)
                    if cut < upper:
                        self.assertGreater(float(np.float32(cut + 1)), threshold)

    def test_constant_branch_sentinels(self):
        self.assertEqual(deployment.integer_cut(-1.0, 65535), -1)
        self.assertEqual(deployment.integer_cut(100000.0, 65535), 65535)
        self.assertEqual(deployment.integer_cut(0.0, 0), 0)
        self.assertEqual(deployment.integer_cut(-0.1, 0), -1)


class ForestExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models = {}
        cls.exports = {}
        cls.vectors = {}
        for feature_set in ('B', 'C'):
            vectors = synthetic_vectors(feature_set)
            labels = np.arange(len(vectors), dtype=np.int64) % len(baseline.CLASSES)
            np.random.default_rng(17).shuffle(labels)
            model = baseline.make_model('RF', deployment.PARAMETERS)
            model.fit(vectors, labels)
            cls.models[feature_set] = model
            cls.exports[feature_set] = deployment.export_forest(model, feature_set)
            cls.vectors[feature_set] = vectors

    def forest_with_constant_leaves(self, probabilities):
        result = copy.deepcopy(self.exports['B'])
        result['trees'] = [{'nodes': [leaf(p)]} for p in probabilities]
        deployment.validate_export(result)
        return result

    def test_export_preserves_feature_and_class_order(self):
        for feature_set in ('B', 'C'):
            result = self.exports[feature_set]
            self.assertEqual(result['feature_set'], feature_set)
            self.assertEqual(result['feature_order'], list(deployment.FEATURES[feature_set]))
            self.assertEqual(result['classes'], list(baseline.CLASSES))
            self.assertEqual(result['score_scale'], deployment.SCALE)
            self.assertEqual(len(result['trees']), 10)
            self.assertEqual(result['parameters'], deployment.PARAMETERS)
            deployment.validate_export(result)

    def test_export_rejects_unselected_forest_settings(self):
        for setting, value in (('class_weight', None), ('max_features', None),
                               ('bootstrap', False), ('random_state', baseline.SEED + 1),
                               ('max_depth', 5), ('n_estimators', 20)):
            model = copy.copy(self.models['B'])
            model.set_params(**{setting: value})
            with self.subTest(setting=setting):
                with self.assertRaises(ValueError):
                    deployment.export_forest(model, 'B')

    def test_native_leaf_probability_and_prediction_parity(self):
        for feature_set in ('B', 'C'):
            with self.subTest(feature_set=feature_set):
                model = self.models[feature_set]
                result = self.exports[feature_set]
                vectors = np.concatenate((self.vectors[feature_set],
                                          synthetic_vectors(feature_set, 250, 442)))
                leaves, probabilities, scores = deployment.predict_export(result, vectors)
                np.testing.assert_array_equal(leaves, model.apply(vectors))
                np.testing.assert_allclose(probabilities, model.predict_proba(vectors),
                                           rtol=0, atol=1e-12)
                np.testing.assert_array_equal(np.argmax(probabilities, axis=1),
                                              model.predict(vectors))
                self.assertEqual(leaves.dtype, np.dtype('int64'))
                self.assertEqual(probabilities.dtype, np.dtype('float64'))
                self.assertEqual(scores.dtype, np.dtype('int64'))
                self.assertEqual(scores.shape, (len(vectors), 6))
                self.assertTrue(np.all(scores >= 0))
                self.assertTrue(np.all(scores <= 10 * deployment.SCALE))

    def test_nonpure_leaves_are_retained_not_replaced_by_votes(self):
        for feature_set in ('B', 'C'):
            nonpure = 0
            for tree_id, tree in enumerate(self.exports[feature_set]['trees']):
                native = self.models[feature_set].estimators_[tree_id].tree_
                for node_id, node in enumerate(tree['nodes']):
                    if node['kind'] != 'leaf':
                        continue
                    probabilities = np.asarray(node['probabilities'])
                    if np.count_nonzero(probabilities) > 1:
                        nonpure += 1
                    expected = native.value[node_id][0]
                    # Current sklearn already stores weighted class fractions.
                    if not np.isclose(expected.sum(), 1.0, rtol=0, atol=1e-12):
                        expected = expected / expected.sum()
                    np.testing.assert_allclose(probabilities, expected, rtol=0, atol=1e-12)
                    np.testing.assert_array_equal(node['scores'],
                                                  np.rint(probabilities * deployment.SCALE))
            self.assertGreater(nonpure, 0)

    def test_probability_aggregation_can_disagree_with_hard_majority(self):
        probabilities = [[0.51, 0.49, 0, 0, 0, 0]] * 6
        probabilities += [[0, 1, 0, 0, 0, 0]] * 4
        result = self.forest_with_constant_leaves(probabilities)
        vector = np.zeros((1, 6), dtype=np.int64)
        _, probabilities, scores = deployment.predict_export(result, vector)
        self.assertEqual(np.argmax(probabilities[0]), 1)
        self.assertEqual(np.argmax(scores[0]), 1)
        self.assertAlmostEqual(probabilities[0, 1], 0.694)
        # Six individual trees chose class 0, but RF's probability mean chose 1.
        self.assertNotEqual(np.argmax(scores[0]), 0)

    def test_equal_scores_use_lowest_class_index_for_argmax(self):
        result = self.forest_with_constant_leaves([[0, 0.5, 0.5, 0, 0, 0]] * 10)
        _, probabilities, scores = deployment.predict_export(
            result, np.zeros((1, 6), dtype=np.int64))
        self.assertEqual(np.argmax(probabilities[0]), 1)
        self.assertEqual(np.argmax(scores[0]), 1)

    def test_quantization_can_create_a_prediction_disagreement(self):
        # Export must expose this case, not claim fixed-point is universally exact.
        epsilon = 1 / (8 * deployment.SCALE)
        result = self.forest_with_constant_leaves(
            [[0.5 - epsilon, 0.5 + epsilon, 0, 0, 0, 0]] * 10)
        _, probabilities, scores = deployment.predict_export(
            result, np.zeros((1, 6), dtype=np.int64))
        self.assertEqual(np.argmax(probabilities[0]), 1)
        self.assertEqual(np.argmax(scores[0]), 0)
        self.assertEqual(scores[0, 0], scores[0, 1])

    def test_full_probability_one_fits_declared_score_domain(self):
        result = self.forest_with_constant_leaves([[0, 0, 0, 0, 0, 1]] * 10)
        _, _, scores = deployment.predict_export(result, np.zeros((1, 6), dtype=np.int64))
        self.assertEqual(scores[0, 5], 10 * deployment.SCALE)
        self.assertLess(scores[0, 5], 2**32)
        self.assertEqual(result['trees'][0]['nodes'][0]['scores'][5], deployment.SCALE)

    def test_json_roundtrip_preserves_predictions(self):
        result = json.loads(json.dumps(self.exports['C'], allow_nan=False))
        deployment.validate_export(result)
        for actual, expected in zip(deployment.predict_export(result, self.vectors['C'][:25]),
                                    deployment.predict_export(self.exports['C'], self.vectors['C'][:25])):
            np.testing.assert_array_equal(actual, expected)

    def test_report_matches_independently_counted_parity(self):
        result = self.exports['B']
        vectors = self.vectors['B'][:75]
        report = deployment.verify_parity(self.models['B'], result, vectors)
        leaves, probabilities, scores = deployment.predict_export(result, vectors)
        native_labels = self.models['B'].predict(vectors)
        integer_mismatches = int(np.count_nonzero(np.argmax(scores, axis=1) != native_labels))
        self.assertEqual(report['tested_vectors'], 75)
        self.assertEqual(report['leaf_mismatches'], 0)
        self.assertLessEqual(report['max_probability_error'], 1e-12)
        self.assertEqual(report['float_prediction_mismatches'], 0)
        self.assertEqual(report['integer_prediction_mismatches'], integer_mismatches)
        self.assertEqual(report['passed'], integer_mismatches == 0)

    def test_mixed_python_bool_is_not_coerced_to_integer(self):
        vectors = self.vectors['B'][:1].tolist()
        vectors[0][0] = True
        with self.assertRaises(ValueError):
            deployment.validate_vectors(self.exports['B'], vectors)

    def test_float_even_integral_is_rejected(self):
        for vectors in (self.vectors['B'][:1].astype(float),
                        [[0.0] * 6], [[float('nan')] * 6], [[float('inf')] * 6]):
            with self.subTest(vectors=vectors):
                with self.assertRaises(ValueError):
                    deployment.validate_vectors(self.exports['B'], vectors)

    def test_each_feature_domain_is_enforced_before_casting(self):
        for feature_set in ('B', 'C'):
            for index, name in enumerate(deployment.FEATURES[feature_set]):
                for value in (-1, deployment.DOMAINS[name]['max'] + 1, 2**64 - 1):
                    vectors = self.vectors[feature_set][:1].tolist()
                    vectors[0][index] = value
                    with self.subTest(feature_set=feature_set, name=name, value=value):
                        with self.assertRaises(ValueError):
                            deployment.validate_vectors(self.exports[feature_set], vectors)

    def test_wrong_rank_width_and_ragged_inputs_rejected(self):
        invalid = ([1] * 6, [[1] * 5], [[1] * 7], [[1] * 6, [1] * 5],
                   [[[1] * 6]], [['1'] * 6], np.ones((1, 6), dtype=bool))
        for vectors in invalid:
            with self.subTest(vectors=vectors):
                with self.assertRaises(ValueError):
                    deployment.validate_vectors(self.exports['B'], vectors)

    def test_valid_python_and_numpy_integers_are_preserved(self):
        for vectors in (self.vectors['C'][:2], self.vectors['C'][:2].tolist()):
            actual = deployment.validate_vectors(self.exports['C'], vectors)
            self.assertEqual(actual.dtype, np.dtype('int64'))
            np.testing.assert_array_equal(actual, self.vectors['C'][:2])

    def test_inclusive_feature_domain_endpoints_are_accepted(self):
        for feature_set in ('B', 'C'):
            names = deployment.FEATURES[feature_set]
            vectors = [[deployment.DOMAINS[name][edge] for name in names]
                       for edge in ('min', 'max')]
            actual = deployment.validate_vectors(self.exports[feature_set], vectors)
            np.testing.assert_array_equal(actual, np.asarray(vectors, dtype=np.int64))

    def test_modified_feature_order_class_order_and_scale_rejected(self):
        mutations = [('feature_order', list(reversed(self.exports['B']['feature_order']))),
                     ('classes', list(reversed(baseline.CLASSES))),
                     ('score_scale', deployment.SCALE + 1),
                     ('trees', self.exports['B']['trees'][:-1])]
        for key, value in mutations:
            result = copy.deepcopy(self.exports['B'])
            result[key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    deployment.validate_export(result)

    def test_invalid_split_edges_cuts_and_features_rejected(self):
        original = self.exports['B']
        node_id = next(i for i, node in enumerate(original['trees'][0]['nodes'])
                       if node['kind'] == 'split')
        split = original['trees'][0]['nodes'][node_id]
        feature_name = original['feature_order'][split['feature_index']]
        mutations = [('left', node_id),  # A cycle must never reach the interpreter.
                     ('right', len(original['trees'][0]['nodes'])),
                     ('feature_index', 6), ('cut', -2),
                     ('cut', deployment.DOMAINS[feature_name]['max'] + 1),
                     ('cut', True), ('threshold_float64', float('nan'))]
        for key, value in mutations:
            result = copy.deepcopy(original)
            result['trees'][0]['nodes'][node_id][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    deployment.validate_export(result)

    def test_invalid_leaf_probabilities_and_scores_rejected(self):
        original = self.forest_with_constant_leaves([[1, 0, 0, 0, 0, 0]] * 10)
        mutations = [('probabilities', [1, 0, 0, 0, 0]),
                     ('probabilities', [0, 0, 0, 0, 0, 0]),
                     ('probabilities', [2, -1, 0, 0, 0, 0]),
                     ('probabilities', [float('nan'), 0, 0, 0, 0, 0]),
                     ('scores', [deployment.SCALE + 1, 0, 0, 0, 0, 0]),
                     ('scores', [-1, 0, 0, 0, 0, 0]),
                     ('scores', [True, 0, 0, 0, 0, 0]),
                     ('scores', [0] * 6)]
        for key, value in mutations:
            result = copy.deepcopy(original)
            result['trees'][0]['nodes'][0][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    deployment.validate_export(result)


class PreparationRunnerTests(unittest.TestCase):
    """Real preparation/refitting on tiny synthetic data; no real PCAP access.

    Only the capture loader and expensive diagnostic-probe generation are
    substituted. Sealed tables, partition checking, model fitting, model reload,
    native/integer parity and evidence writing use the real implementation.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='rf-deployment-test-')
        self.root = Path(self.temporary.name)
        tools = Path(deployment.__file__).parent
        policy = {
            'idle_seconds': 60, 'boundary_policy': 'idle-tcp', 'hard_timeout': None,
            'features_B': list(baseline.B), 'features_C': list(baseline.C),
            'source_sha256': {name: baseline.digest(tools / name) for name in
                              ('extract_feature_pilot.py', 'extract_flow_instances.py')},
        }
        with patch.object(baseline, 'load_extraction',
                          return_value=(fixture(), {'extraction_policy': policy,
                                                    'synthetic_test_only': True})), \
                redirect_stdout(io.StringIO()):
            self.prepared = baseline.prepare(self.root / 'synthetic_source',
                                             self.root / 'prepared', 'fixed')
        self.tables, self.manifest = baseline.load_prepared(self.prepared)
        self.development = [r for r in self.tables[8] if r['partition'] == 'development']
        self.test = [r for r in self.tables[8] if r['partition'] == 'test']
        self.tuning = self.root / 'synthetic_tuning'
        self.tuning.mkdir()
        sources = {'baseline': baseline.__file__, 'tuning': deployment.tuning.__file__,
                   'validator': baseline.validator.__file__}
        baseline.write_json(self.tuning / 'run_config.json', {
            'prepared_manifest_sha256': baseline.digest(self.prepared / 'manifest.json'),
            'input_payload_sha256': self.manifest['payload_sha256'],
            'environment': baseline.environment(), 'training_config': baseline.CONFIG,
            'source_sha256': {name: baseline.digest(path) for name, path in sources.items()},
            'synthetic_test_only': True,
        })
        # These are fixture metadata, deliberately NOT actual tuning results.
        fold_result = {
            'parameters': deployment.PARAMETERS, 'mean_macro_f1': 0.5, 'std_macro_f1': 0.0,
            'folds': [{'fold': index, 'macro_f1': 0.5, 'fit_seconds': 0.01,
                       'model_size': {'trees': 10, 'max_depth': 4, 'leaves': 60, 'nodes': 110}}
                      for index in range(baseline.FOLDS)],
        }
        chosen = deployment.tuning.candidate_summary(fold_result)
        baseline.write_json(self.tuning / 'summary.json', {
            'development_only': True, 'completed_fits': 216, 'test_records_scored': 0,
            'synthetic_test_only': True,
            'experiments': {
                'n8_RF_' + feature_set: {'candidates': [chosen]}
                for feature_set in ('B', 'C')
            },
        })
        baseline.write_json(self.tuning / 'cv_results.json', {
            'synthetic_test_only': True,
            'n8_RF_B': [fold_result], 'n8_RF_C': [fold_result],
        })
        self.output = self.root / 'new_evidence'

    def tearDown(self):
        self.temporary.cleanup()

    def run_prepare(self, check_only=False):
        # Boundary generation is tested separately; keep runner tests quick.
        with patch.object(deployment, 'diagnostic_vectors',
                          side_effect=lambda export, vectors: (vectors[:12], 0)), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return deployment.prepare(self.prepared, self.tuning, self.output, check_only)

    def test_check_only_creates_nothing_and_never_fits_or_predicts(self):
        before = {str(p): baseline.digest(p) for p in self.root.rglob('*') if p.is_file()}
        with patch.object(baseline, 'fit_model', side_effect=AssertionError('Unexpected fit')), \
                patch.object(baseline, 'matrix', side_effect=AssertionError('Unexpected matrix')), \
                patch.object(deployment, 'predict_export',
                             side_effect=AssertionError('Unexpected prediction')):
            self.assertIsNone(self.run_prepare(check_only=True))
        self.assertFalse(self.output.exists())
        after = {str(p): baseline.digest(p) for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_check_only_rejects_noninteger_vector_before_output_creation(self):
        loaded = list(deployment.load_inputs(self.prepared, self.tuning))
        loaded[0] = copy.deepcopy(loaded[0])
        for feature_set in ('B', 'C'):
            features = loaded[0][0]['features_' + feature_set]
            features['size_min'] = float(features['size_min'])
        with patch.object(deployment, 'load_inputs', return_value=tuple(loaded)), \
                patch.object(baseline, 'fit_model', side_effect=AssertionError('Unexpected fit')):
            with self.assertRaisesRegex(ValueError, 'expected an integer'):
                self.run_prepare(check_only=True)
        self.assertFalse(self.output.exists())

    def test_refit_uses_development_only_and_paired_bc_population(self):
        native_matrix = baseline.matrix
        native_fit = baseline.fit_model
        matrix_ids, fitting_rows = {}, []

        def checked_matrix(rows, feature_set):
            self.assertTrue(all(r['partition'] == 'development' for r in rows))
            self.assertTrue(all(r['n'] == 8 for r in rows))
            matrix_ids[feature_set] = [r['record_id'] for r in rows]
            return native_matrix(rows, feature_set)

        def checked_fit(model, algorithm, vectors, labels):
            self.assertEqual(algorithm, 'RF')
            self.assertEqual(len(vectors), len(self.development))
            fitting_rows.append(len(vectors))
            return native_fit(model, algorithm, vectors, labels)

        with patch.object(baseline, 'matrix', side_effect=checked_matrix), \
                patch.object(baseline, 'fit_model', side_effect=checked_fit), \
                patch.object(baseline, 'select_configuration',
                             side_effect=AssertionError('Must not retune')):
            directory = self.run_prepare()
        self.assertEqual(fitting_rows, [len(self.development)] * 2)
        self.assertEqual(matrix_ids['B'], matrix_ids['C'])
        test_ids = {r['record_id'] for r in self.test}
        self.assertFalse(test_ids.intersection(matrix_ids['B']))
        summary = baseline.read_json(directory / 'summary.json')
        self.assertEqual(summary['development_records'], len(self.development))
        self.assertEqual(summary['test_records_scored'], 0)
        self.assertFalse(summary['p4_verified'])
        self.assertFalse(summary['universal_prediction_equivalence_proved'])
        self.assertEqual(set(summary['experiments']), {'n8_RF_B', 'n8_RF_C'})
        self.assertFalse((directory / 'failure.json').exists())
        for feature_set in ('B', 'C'):
            rows = baseline.read_rows(directory / f'development_vectors_{feature_set}.jsonl')
            self.assertEqual([r['record_id'] for r in rows], matrix_ids[feature_set])
            self.assertTrue((directory / ('n8_RF_' + feature_set) / 'model.joblib').is_file())
        for relative, expected in summary['output_sha256'].items():
            self.assertEqual(baseline.digest(directory / relative), expected)

    def test_failed_parity_leaves_failure_marker_but_no_success_summary(self):
        original_verify = deployment.verify_parity

        def failed_parity(model, export, vectors):
            result = original_verify(model, export, vectors)
            result['integer_prediction_mismatches'] = 1
            result['passed'] = False
            return result

        with patch.object(deployment, 'verify_parity', side_effect=failed_parity):
            with self.assertRaisesRegex(ValueError, 'parity gate failed'):
                self.run_prepare()
        runs = list(self.output.iterdir())
        self.assertEqual(len(runs), 1)
        failure = baseline.read_json(runs[0] / 'failure.json')
        self.assertFalse(failure['usable_for_p4'])
        self.assertFalse((runs[0] / 'summary.json').exists())
        for feature_set in ('B', 'C'):
            parity = baseline.read_json(runs[0] / ('n8_RF_' + feature_set) / 'parity.json')
            self.assertFalse(parity['passed'])
            self.assertEqual(parity['development']['integer_prediction_mismatches'], 1)

    def test_input_mutation_during_fit_prevents_success_marker(self):
        native_fit = baseline.fit_model
        calls = 0

        def mutate_fixture_after_fit(model, algorithm, vectors, labels):
            nonlocal calls
            elapsed = native_fit(model, algorithm, vectors, labels)
            if calls == 0:
                path = self.tuning / 'cv_results.json'
                # Only this TemporaryDirectory fixture is changed, never evidence.
                with path.open('a', encoding='utf-8') as stream:
                    stream.write('\n')
            calls += 1
            return elapsed

        with patch.object(baseline, 'fit_model', side_effect=mutate_fixture_after_fit):
            with self.assertRaisesRegex(ValueError, 'Input/source changed during run'):
                self.run_prepare()
        runs = list(self.output.iterdir())
        self.assertEqual(len(runs), 1)
        self.assertTrue((runs[0] / 'failure.json').is_file())
        self.assertFalse((runs[0] / 'summary.json').exists())

    def test_preexisting_prepared_table_mutation_rejected_before_fit(self):
        with (self.prepared / 'table_n8.jsonl').open('a', encoding='utf-8') as stream:
            stream.write('\n')
        with patch.object(baseline, 'fit_model', side_effect=AssertionError('Unexpected fit')):
            with self.assertRaisesRegex(ValueError, 'Prepared file changed'):
                self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_tuning_manifest_mismatch_rejected_before_fit(self):
        path = self.tuning / 'run_config.json'
        config = baseline.read_json(path)
        config['prepared_manifest_sha256'] = '0' * 64
        with path.open('w', encoding='utf-8') as stream:
            json.dump(config, stream)
        with patch.object(baseline, 'fit_model', side_effect=AssertionError('Unexpected fit')):
            with self.assertRaisesRegex(ValueError, 'provenance mismatch'):
                self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_tuning_fold_and_summary_mismatch_rejected_before_fit(self):
        path = self.tuning / 'summary.json'
        summary = baseline.read_json(path)
        summary['experiments']['n8_RF_B']['candidates'][0]['mean_fold_leaves'] += 1
        with path.open('w', encoding='utf-8') as stream:
            json.dump(summary, stream)
        with patch.object(baseline, 'fit_model', side_effect=AssertionError('Unexpected fit')):
            with self.assertRaisesRegex(ValueError, 'summary/fold evidence mismatch'):
                self.run_prepare()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
