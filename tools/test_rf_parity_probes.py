#!/usr/bin/env python3
"""Unit tests for the RF numeric branch witness generator and diagnostics."""

import copy
import unittest

import numpy as np

import prepare_rf_deployment as reference
import rf_parity_probes as probes


class ParityProbeTests(unittest.TestCase):
    def setUp(self):
        self.export = probes.synthetic_export()

    def assert_full_reachable_coverage(self, export):
        vectors = probes.branch_probes(export)
        report = probes.coverage(export, vectors)
        for name in ('nodes', 'leaves', 'branches'):
            self.assertEqual(report[name]['covered'], report[name]['reachable'])
            self.assertEqual(report['uncovered_' + name], [])
        self.assertEqual(len(vectors), len({tuple(row) for row in vectors}))
        self.assertEqual(vectors, probes.branch_probes(export))
        return vectors, report

    def set_threshold(self, node_id, threshold):
        for tree in self.export['trees']:
            node = tree['nodes'][node_id]
            name = self.export['feature_order'][node['feature_index']]
            node['threshold_float64'] = float(threshold)
            node['cut'] = reference.integer_cut(threshold, self.export['domains'][name]['max'])

    def test_all_reachable_nodes_and_boundary_probes(self):
        vectors, report = self.assert_full_reachable_coverage(self.export)
        first = {row[0] for row in vectors}
        self.assertTrue({100, 101, 200, 201, 300, 301} <= first)
        self.assertEqual(report['nodes'], {'total': 70, 'reachable': 70, 'covered': 70})
        self.assertEqual(report['leaves'], {'total': 40, 'reachable': 40, 'covered': 40})
        self.assertEqual(report['branches'], {'total': 60, 'reachable': 60, 'covered': 60})

    def test_repeated_feature_respects_ancestor_constraints(self):
        # The second split is only visited for size_min >= 101, so its
        # size_min <= 50 branch and node 3 are numerically unreachable.
        self.set_threshold(2, 50)
        vectors, report = self.assert_full_reachable_coverage(self.export)
        self.assertEqual(report['leaves']['reachable'], 30)
        self.assertEqual(report['infeasible_nodes'], [[i, 3] for i in range(10)])
        self.assertEqual(report['infeasible_branches'], [[i, 2, 'left'] for i in range(10)])
        self.assertTrue(all(row[0] != 50 for row in vectors))

    def test_always_right_root_negative_cut(self):
        self.set_threshold(0, -0.5)
        self.assertEqual(self.export['trees'][0]['nodes'][0]['cut'], -1)
        _, report = self.assert_full_reachable_coverage(self.export)
        self.assertEqual(report['infeasible_leaves'], [[i, 1] for i in range(10)])
        self.assertEqual(report['infeasible_branches'], [[i, 0, 'left'] for i in range(10)])

    def test_always_left_root_upper_cut_and_unreachable_subtree(self):
        self.set_threshold(0, 65535.5)
        self.assertEqual(self.export['trees'][0]['nodes'][0]['cut'], 65535)
        _, report = self.assert_full_reachable_coverage(self.export)
        self.assertEqual(report['nodes']['reachable'], 20)
        self.assertEqual(report['leaves']['reachable'], 10)
        self.assertEqual(report['branches']['reachable'], 10)
        self.assertEqual(len(report['infeasible_nodes']), 50)
        self.assertEqual(len(report['infeasible_branches']), 50)

    def test_feature_c_domains_and_multiple_ancestor_coordinates(self):
        self.export['feature_set'] = 'C'
        self.export['feature_order'] = list(reference.FEATURES['C'])
        self.export['domains'] = copy.deepcopy(reference.DOMAINS)
        for tree in self.export['trees']:
            tree['nodes'][0]['feature_index'] = 6
            tree['nodes'][2]['feature_index'] = 7
            tree['nodes'][4]['feature_index'] = 6
        self.set_threshold(0, 2.5)
        self.set_threshold(2, 3.5)
        self.set_threshold(4, 5.5)
        vectors, _ = self.assert_full_reachable_coverage(self.export)
        self.assertTrue(all(len(row) == 8 and row[6] <= 7 and row[7] <= 7 for row in vectors))

    def test_constant_trees_have_leaf_witness(self):
        for tree in self.export['trees']:
            tree['nodes'] = [tree['nodes'][1]]
        vectors, report = self.assert_full_reachable_coverage(self.export)
        self.assertEqual(vectors, [[0] * 6])
        self.assertEqual(report['branches'], {'total': 0, 'reachable': 0, 'covered': 0})

    def test_partial_coverage_reports_native_ids(self):
        report = probes.coverage(self.export, [probes.synthetic_vectors()[0]])
        self.assertEqual(report['nodes']['covered'], 20)
        self.assertEqual(report['leaves']['covered'], 10)
        self.assertIn([0, 3], report['uncovered_leaves'])
        self.assertIn([0, 0, 'right'], report['uncovered_branches'])
        self.assertEqual(report['infeasible_nodes'], [])

    def test_synthetic_predictions_ties_maximum_and_soft_not_hard_vote(self):
        leaves, _, scores = reference.predict_export(self.export, probes.synthetic_vectors())
        self.assertEqual(np.argmax(scores, axis=1).tolist(), [0, 2, 5, 1])
        self.assertEqual(leaves.tolist(), [[node] * 10 for node in (1, 3, 5, 6)])
        self.assertEqual(int(scores.max()), 10 * reference.SCALE)
        self.assertEqual(int(scores[0, 0]), int(scores[0, 1]))
        self.assertEqual(int(scores[1, 2]), int(scores[1, 4]))
        hard_classes = [int(np.argmax(tree['nodes'][6]['scores'])) for tree in self.export['trees']]
        self.assertEqual(np.bincount(hard_classes, minlength=6).argmax(), 0)
        self.assertEqual(np.argmax(scores[3]), 1)

    def test_rejects_empty_vectors_bad_width_coercions_and_bad_export(self):
        for vectors in ([], [[0] * 8], [[False] + [0] * 5], [[0.0] + [0] * 5], [[65536] + [0] * 5]):
            with self.subTest(vectors=vectors), self.assertRaises(ValueError):
                probes.coverage(self.export, vectors)
        self.export['trees'][0]['nodes'][0]['cut'] = 99
        with self.assertRaises(ValueError):
            probes.branch_probes(self.export)
        with self.assertRaises(ValueError):
            probes.coverage(self.export, [[0] * 6])

    def test_inputs_not_mutated(self):
        original = copy.deepcopy(self.export)
        vectors = probes.synthetic_vectors()
        expected = copy.deepcopy(vectors)
        probes.branch_probes(self.export)
        probes.coverage(self.export, vectors)
        self.assertEqual(self.export, original)
        self.assertEqual(vectors, expected)


if __name__ == '__main__':
    unittest.main()
