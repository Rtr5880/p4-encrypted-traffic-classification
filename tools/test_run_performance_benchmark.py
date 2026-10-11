"""Offline runner contracts; never sudo, open raw sockets or run live trials."""
import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_performance_benchmark as benchmark


def options(**updates):
    values = dict(rates=[100,250,500,1000,2000,5000], repetitions=5, drain_seconds=2,
                  duration_seconds=20, warmup_seconds=5, seed=4022, extension_from=None)
    values.update(updates)
    return argparse.Namespace(**values)


class ProtocolTests(unittest.TestCase):
    def test_native_sender_is_explicit_and_preserves_quality_gates(self):
        legacy = benchmark.protocol_from_args(options())
        native = benchmark.protocol_from_args(options(sender_library=Path('/test-only/sender.so')))
        self.assertEqual(legacy['sender_backend'], 'python-paced-send-v1')
        self.assertEqual(native['sender_backend'], 'linux-native-paced-send-v1')
        self.assertEqual(native['pacing_gates'], legacy['pacing_gates'])
        for name in ('clock_sample_seconds', 'maximum_clock_sampling_gap_ns',
                     'maximum_clock_bracket_ns', 'clock_offset_change_tolerance_ns',
                     'duration_seconds', 'warmup_seconds', 'frame_bytes', 'normal_definitions'):
            self.assertEqual(native[name], legacy[name])

    def test_default_matrix_and_reproducible_balance(self):
        protocol = benchmark.protocol_from_args(options())
        schedule = benchmark.build_schedule(protocol, 'test-only-token')
        self.assertEqual(len(schedule), 60)
        self.assertEqual(schedule, benchmark.build_schedule(protocol, 'test-only-token'))
        for workload in benchmark.WORKLOADS:
            for rate in protocol['rates_pps']:
                blocks = [b for b in schedule if b['workload'] == workload and b['rate_pps'] == rate]
                self.assertEqual(len(blocks), 5)
                for mode in benchmark.MODES:
                    counts = [sum(b['modes'][position] == mode for b in blocks) for position in range(4)]
                    self.assertLessEqual(max(counts)-min(counts), 1)

    def test_extension_and_invalid_configuration_guards(self):
        for changes in ({'rates':[5001]}, {'rates':[0]}, {'rates':[100,100]},
                        {'repetitions':0}, {'repetitions':21}, {'drain_seconds':float('nan')}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                benchmark.protocol_from_args(options(**changes))
        self.assertEqual(benchmark.protocol_from_args(options(rates=[7500], extension_from=Path('/test-only')))['rates_pps'], [7500])

    def test_high_rate_state_and_packet_bounds(self):
        protocol = benchmark.protocol_from_args(options(rates=[5000]))
        block = benchmark.build_schedule(protocol, 'test-only')[0]
        warm, measured = benchmark.plans_for(block, protocol)
        self.assertEqual(warm.packet_count, 25000)
        self.assertEqual(measured.packet_count, 100000)
        self.assertFalse(set(warm.slots) & set(measured.slots))
        self.assertLess(warm.flow_count+measured.flow_count, 65536)
        self.assertEqual(benchmark.frame_hash(measured), benchmark.frame_hash(measured))

    def test_seal_rejects_tamper_and_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'original.json').write_text('{}')
            seal = {'original.json': benchmark.hash_file(root/'original.json')}
            benchmark.verify_seal(root, seal)
            (root/'original.json').write_text('{"changed":true}')
            with self.assertRaises(ValueError):
                benchmark.verify_seal(root, seal)
            with self.assertRaises(ValueError):
                benchmark.verify_seal(root, {'../escape': '0'*64})


class AccountingTests(unittest.TestCase):
    def test_warmup_counter_delta_only(self):
        warm, measured = benchmark.workload.build_phase_pair(64, 1, 4, 'classification-heavy', 'test-only')
        before = [{'bytes':0,'packets':0} for _ in range(6)]
        before[2] = {'packets': warm.expected_classifications, 'bytes': warm.expected_classifications*128}
        after = [dict(v) for v in before]
        after[1] = {'packets': measured.expected_classifications, 'bytes': measured.expected_classifications*128}
        result = benchmark.counter_check(before, after, measured, 'rf_c')
        self.assertTrue(result['passed'])
        self.assertEqual(result['packets'], measured.expected_classifications)
        self.assertEqual(sum(v['packets'] for v in after), warm.expected_classifications+measured.expected_classifications)

    def test_non_rf_decisions_are_not_fake_zero_counts(self):
        _, plan = benchmark.workload.build_phase_pair(64, 0, 1, 'cached-forwarding', 'test-only')
        for mode in ('features','forwarding'):
            result = benchmark.counter_check(None,None,plan,mode)
            self.assertIsNone(result['packets'])
            self.assertFalse(result['rf_inference_present'])

    def test_counter_reset_or_wrong_bytes_rejected(self):
        _, plan = benchmark.workload.build_phase_pair(64, 0, 1, 'classification-heavy', 'test-only')
        before = [{'bytes':128,'packets':1} for _ in range(6)]
        after = [{'bytes':0,'packets':0} for _ in range(6)]
        self.assertFalse(benchmark.counter_check(before,after,plan,'rf_b')['passed'])
        self.assertFalse(benchmark.counter_check(before,after,plan,'rf_b')['structurally_valid'])

    def test_one_lost_output_cannot_hide_missing_all_decisions(self):
        _, plan = benchmark.workload.build_phase_pair(64,0,2,'classification-heavy','test-only')
        observed = {'per_packet': {'output_occurrences': [1]*128}, 'missing_output_sequences': [0]}
        observed['per_packet']['output_occurrences'][0] = 0
        before = [{'bytes':0,'packets':0} for _ in range(6)]
        wrong = [dict(v) for v in before]
        check = benchmark.phase_counter_check(before,wrong,plan,'rf_c',observed)
        self.assertEqual(check['minimum_proven_decisions'], 15)
        self.assertFalse(check['capacity_accounting_passed'])
        valid = [dict(v) for v in before]
        valid[0] = {'bytes':15*128,'packets':15}
        self.assertTrue(benchmark.phase_counter_check(before,valid,plan,'rf_c',observed)['capacity_accounting_passed'])
        valid[0] = {'bytes':17*128,'packets':17}
        self.assertFalse(benchmark.phase_counter_check(before,valid,plan,'rf_c',observed)['capacity_accounting_passed'])
        after = [dict(v) for v in before]
        after[0]['packets'] += 1
        self.assertFalse(benchmark.counter_check(before,after,plan,'rf_b')['structurally_valid'])

    def test_source_removes_only_ingress_state(self):
        sample = ('prefix parser FeatureParser {}\ncontrol FeatureIngress(old) { register old;\n'
          '    apply {\n        meta.status = 0; eligible();\n'
          '        if (meta.eligible) {\n            meta.source_hi = 0; hash(); }\n'
          '#if DEBUG_REPORT\n        emit_report();\n#else\n        forward();\n#endif\n    }\n}\n'
          'control FeatureEgress(stuff) {}\n')
        baseline = benchmark.plain_forwarding_source(sample)
        self.assertIn('parser FeatureParser', baseline)
        self.assertIn('eligible();', baseline)
        self.assertIn('forward();', baseline)
        self.assertIn('control FeatureEgress(stuff)', baseline)
        self.assertNotIn('register old', baseline)
        self.assertNotIn('hash();', baseline)
        self.assertNotIn('emit_report();', baseline)

    def test_runtime_start_and_logging_consistency(self):
        args = argparse.Namespace(switch=Path('/switch'))
        for mode in benchmark.MODES:
            argv = benchmark.switch_argv(args, f'/{mode}.json', 9099, 'private_s1', 'private_s2')
            self.assertNotIn('--use-files', argv)
            self.assertEqual(argv[argv.index('-L')+1], 'warn')
            self.assertIn('1@private_s1', argv)
            self.assertIn('2@private_s2', argv)

    def test_resource_callbacks_complete_after_cleanup(self):
        class FakeSampler:
            def __init__(self,*args): self.entered = self.exited = False
            def __enter__(self): self.entered=True
            def __exit__(self,*args): self.exited=True
            def summary(self): return {'valid':self.entered and self.exited}
        with patch.object(benchmark.resources,'ResourceSampler',FakeSampler):
            monitor = benchmark.MeasurementResources(10)
            with self.assertRaises(ValueError): monitor.report()
            monitor.start()
            monitor.stop()
            monitor.stop()
            self.assertTrue(monitor.report()['bmv2']['valid'])

    def test_partial_resource_start_stops_entered_sampler(self):
        instances=[]
        class FakeSampler:
            def __init__(self,*args): self.stopped=False; instances.append(self)
            def __enter__(self):
                if self is instances[1]: raise RuntimeError('fixture thread limit')
            def __exit__(self,*args): self.stopped=True
            def summary(self): return {'valid':True}
        with patch.object(benchmark.resources,'ResourceSampler',FakeSampler):
            monitor = benchmark.MeasurementResources(10)
            with self.assertRaises(RuntimeError): monitor.start()
            self.assertTrue(instances[0].stopped)
            self.assertFalse(instances[1].stopped)
            self.assertFalse(monitor.report()['runner']['valid'])

    def test_sampler_stop_error_is_recorded_and_other_sampler_stopped(self):
        instances=[]
        class FakeSampler:
            def __init__(self,*args): self.stopped=False; instances.append(self)
            def __enter__(self): pass
            def __exit__(self,*args):
                self.stopped=True
                if self is instances[0]: raise RuntimeError('fixture join failed')
            def summary(self): return {'valid':True}
        with patch.object(benchmark.resources,'ResourceSampler',FakeSampler):
            monitor = benchmark.MeasurementResources(10)
            monitor.start(); monitor.stop()
            self.assertTrue(all(v.stopped for v in instances))
            self.assertFalse(monitor.report()['bmv2']['valid'])


if __name__ == '__main__':
    unittest.main()
