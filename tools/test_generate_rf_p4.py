"""Generator contract tests; actual compiler/BMv2 tests live in integrate_rf.py."""
import copy
from pathlib import Path
import unittest

import generate_rf_p4 as generator
import prepare_rf_deployment as reference
import rf_parity_probes as probes


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = (Path(__file__).resolve().parent.parent / 'p4/flow_features.p4').read_text()

    def setUp(self):
        self.export = probes.synthetic_export()

    def test_inputs_unchanged_and_same_classifier_in_both_programs(self):
        original = copy.deepcopy(self.export)
        sources = generator.generate_sources(self.export, self.base)
        classifier = generator._classifier(self.export)
        self.assertEqual(set(sources), {'integrated', 'vectors'})
        self.assertTrue(all(s.count(classifier) == 1 for s in sources.values()))
        self.assertEqual(self.export, original)

    def test_changed_checkpoint_rejected(self):
        with self.assertRaisesRegex(ValueError, 'checkpoint'):
            generator.generate_sources(self.export, self.base + '\n')

    def test_crlf_normalization_only(self):
        self.assertEqual(generator.generate_sources(self.export, self.base),
                         generator.generate_sources(self.export, self.base.replace('\n', '\r\n')))

    def test_anchor_cardinality(self):
        for text in ('none', 'xx'):
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                generator._replace_once(text, 'x', 'new')

    def test_score_aggregation_and_native_leaf_ids(self):
        code = generator._classifier(self.export)
        self.assertIn('rf.leaf0 = 16w5;', code)
        self.assertIn('rf.score5 = rf.score5 + 32w16777216;', code)
        self.assertNotIn('vote_count', code)

    def test_strict_ascending_argmax(self):
        code = generator._classifier(self.export)
        positions = [code.index(f'if (rf.score{i} > best_score)') for i in range(1, 6)]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('>= best_score', code)
        self.assertIn('rf.prediction = 8w0;', code)

    def test_packet8_gate_and_observable_counter(self):
        code = generator.generate_sources(self.export, self.base)['integrated']
        gate = code.index('/* The complete prefix snapshot')
        end = code.index('#if DEBUG_REPORT', gate)
        block = code[gate:end]
        self.assertIn('if (meta.status == 2)', block)
        self.assertEqual(block.count('rf_infer.apply(meta.rf)'), 1)
        self.assertIn('rf_decisions.count((bit<32>) meta.rf.prediction);', block)
        self.assertIn('counter(6, CounterType.packets) rf_decisions;', code)
        self.assertIn('#if DEBUG_REPORT\n        packet.emit(hdr.report);\n        packet.emit(hdr.rf_report);', code)

    def test_constant_out_of_domain_predicates(self):
        for threshold, branch in ((-0.5, 'right'), (65535.0, 'left')):
            model = copy.deepcopy(self.export)
            node = model['trees'][0]['nodes'][0]
            node['threshold_float64'] = threshold
            node['cut'] = reference.integer_cut(threshold, 65535)
            reference.validate_export(model)
            code = generator._classifier(model)
            self.assertIn(f'Node 0: always {branch}', code)
            self.assertNotIn('32w-1', code)

    def test_bad_export_rejected_before_generation(self):
        broken = copy.deepcopy(self.export)
        broken['trees'][0]['nodes'][1]['scores'][0] += 1
        with self.assertRaisesRegex(ValueError, 'Quantization'):
            generator.generate_sources(broken, self.base)
        broken = copy.deepcopy(self.export)
        broken['feature_order'].reverse()
        with self.assertRaisesRegex(ValueError, 'Feature order'):
            generator.generate_sources(broken, self.base)

    def test_b_does_not_branch_on_direction(self):
        code = generator._classifier(self.export)
        self.assertNotIn('if (rf.f6', code)
        self.assertNotIn('if (rf.f7', code)


if __name__ == '__main__':
    unittest.main()
