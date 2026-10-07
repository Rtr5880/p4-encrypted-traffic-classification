"""Runner contract tests. No live interfaces, traffic, compiler or model fitting."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_performance_pilot as pilot


def save(path, value):
    path.write_text(json.dumps(value), encoding='utf-8')


class PilotContractTests(unittest.TestCase):
    def test_normal_program_requires_no_reports_and_six_decision_bins(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'normal.json'
            program = {'deparsers': [{'order': ['ethernet', 'ipv4', 'udp']}],
                       'counter_arrays': [{'name': 'FeatureIngress.rf_decisions', 'size': 6}]}
            save(path, program)
            self.assertFalse(pilot.validate_normal_program(path)['debug_report_headers_emitted'])
            for changed in (
                dict(program, deparsers=[{'order': ['ethernet', 'feature_report']}]),
                dict(program, counter_arrays=[]),
                dict(program, counter_arrays=[{'name': 'FeatureIngress.rf_decisions', 'size': 5}]),
            ):
                save(path, changed)
                with self.assertRaises(ValueError):
                    pilot.validate_normal_program(path)

    def prerequisite(self, directory):
        receipt = {'artifacts': {'binary': {'sha256': 'frozen'}}, 'receipt_sha256': 'receipt'}
        save(directory / 'provenance.json', {'clock_source_receipt': receipt})
        summary = {'passed': True, 'raw_clock_clean': True, 'expected_cases_per_model': 398,
                   'verified_classified_evaluations': 796, 'cleanup_passed': True,
                   'output_sha256': {'provenance.json': pilot.native_prefix.sha256_file(directory / 'provenance.json')}}
        save(directory / 'summary.json', summary)
        return receipt, summary

    def test_complete_native_prerequisite_and_hashes(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            receipt, _ = self.prerequisite(directory)
            hashes = pilot.verify_native_prerequisite(directory, receipt)
            self.assertEqual(set(hashes), {str(directory / 'summary.json'), str(directory / 'provenance.json')})
            save(directory / 'provenance.json', {'tampered': True})
            with self.assertRaises(ValueError):
                pilot.verify_native_prerequisite(directory, receipt)

    def test_incomplete_native_or_different_binary_is_rejected(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            receipt, summary = self.prerequisite(directory)
            for field, value in [('passed', False), ('raw_clock_clean', False),
                                 ('verified_classified_evaluations', 795), ('cleanup_passed', False)]:
                save(directory / 'summary.json', dict(summary, **{field: value}))
                with self.assertRaises(ValueError):
                    pilot.verify_native_prerequisite(directory, receipt)
            save(directory / 'summary.json', summary)
            with self.assertRaises(ValueError):
                pilot.verify_native_prerequisite(directory, dict(receipt, receipt_sha256='different'))
            save(directory / 'failure.json', {'error': 'prior failure'})
            with self.assertRaises(ValueError):
                pilot.verify_native_prerequisite(directory, receipt)

    def test_seal_cannot_reference_outside_evidence_directory(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp) / 'run'
            directory.mkdir()
            receipt, summary = self.prerequisite(directory)
            outside = Path(temp) / 'outside.json'
            save(outside, {})
            summary['output_sha256']['../outside.json'] = pilot.native_prefix.sha256_file(outside)
            save(directory / 'summary.json', summary)
            with self.assertRaises(ValueError):
                pilot.verify_native_prerequisite(directory, receipt)

    def test_heavy_cached_counts_and_bytes_are_independent_of_predicted_class(self):
        for plan in pilot.make_plans('same-recipe'):
            counters = {index: {'packets': 0, 'bytes': 0} for index in range(6)}
            counters[3] = {'packets': plan.flow_count, 'bytes': plan.flow_count * 128}
            self.assertTrue(pilot.validate_counters(counters, plan)['passed'])
            counters[3]['packets'] += 1
            self.assertFalse(pilot.validate_counters(counters, plan)['passed'])
            counters[3]['packets'] -= 1
            counters[3]['bytes'] += 1
            self.assertFalse(pilot.validate_counters(counters, plan)['passed'])

    def test_packet_phase_latency_uses_ordinal_not_sequence(self):
        for plan in pilot.make_plans('latency'):
            report = {'latency': {'valid': True,
                                 'paired_kernel_timestamp_differences_ns': [1000] * plan.packet_count}}
            result = pilot.phase_latency(report, plan)['kernel_path_delay_us']
            self.assertEqual(result['decision_packet_8']['count'], plan.flow_count)
            self.assertEqual(result['prefix_packets_1_to_7']['count'], 7 * plan.flow_count)
            self.assertEqual(result['cached_packets_after_8']['count'],
                             plan.packet_count - 8 * plan.flow_count)
            report['latency']['valid'] = False
            self.assertTrue(all(value is None for value in
                                pilot.phase_latency(report, plan)['kernel_path_delay_us'].values()))

    def test_wrong_preparation_fails_before_binary_or_live_operations(self):
        with TemporaryDirectory() as temp:
            directory = Path(temp)
            save(directory / 'manifest.json', {'status': 'prepared', 'schema': 'debug-build'})
            with patch.object(pilot.clock_contract, 'verify_receipt') as verify:
                with self.assertRaises(ValueError):
                    pilot.load_prepared(directory, Path('/unused/switch'))
                verify.assert_not_called()

    def test_passed_trial_accounting_and_partial_failure_cleanup(self):
        class FakeLinks:
            def __init__(self, token):
                self.names, self.owned, self.cleanup_errors = ['s1', 'h1', 's2', 'h2'], {}, []
                self.cleaned = False
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                self.cleaned = True

        for failure in (False, True):
            with TemporaryDirectory() as temp:
                root = Path(temp)
                prepared = root / 'prepared'
                prepared.mkdir()
                save(prepared / 'manifest.json', {})
                args = SimpleNamespace(prepared=prepared, switch=Path('/unused/switch'), output_root=root / 'out')
                links = FakeLinks('token')
                manifest = {'programs': {model: {'path': '/unused/' + model} for model in 'BC'},
                            'input_sha256': {}, 'clock_receipt': '/unused/receipt'}
                side_effect = ([{'passed': True}, ValueError('injected failure')] if failure
                               else [{'passed': True}] * 4)
                with patch.object(pilot, 'load_prepared', return_value=(manifest, pilot.make_plans('test'), {})), \
                     patch.object(pilot.os, 'geteuid', return_value=0), \
                     patch.object(pilot.shutil, 'which', return_value='/unused/tool'), \
                     patch.object(pilot.ownership, 'OwnedLinks', return_value=links), \
                     patch.object(pilot.ownership, 'verify_hashes'), \
                     patch.object(pilot.ownership, 'restore_new_evidence_owner'), \
                     patch.object(pilot.clock_contract, 'verify_receipt'), \
                     patch.object(pilot, 'run_trial', side_effect=side_effect):
                    directory, passed = pilot.run(args, root)
                self.assertTrue(links.cleaned)
                summary = json.loads((directory / 'summary.json').read_text())
                self.assertEqual(passed, not failure)
                self.assertEqual(summary['completed_trials'], 1 if failure else 4)
                self.assertEqual(len(summary['attempted_trials']), 2 if failure else 4)
                self.assertEqual((directory / 'failure.json').exists(), failure)
                self.assertFalse(summary['accuracy_scored'])
                self.assertFalse(summary['capacity_sweep'])


if __name__ == '__main__':
    unittest.main()
