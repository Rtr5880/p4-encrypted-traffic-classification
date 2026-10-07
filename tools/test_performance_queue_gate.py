"""Queue upgrade must not borrow same-binary claims or skip fresh smoke gates."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import run_performance_pilot as runner


class QueuePerformanceGateTests(unittest.TestCase):
    def test_unknown_receipt_schema_has_no_fallback(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'receipt.json'
            path.write_text(json.dumps({'schema': 'unknown'}))
            with patch.object(runner.clock_contract, 'verify_receipt') as old, \
                 patch.object(runner.queue_contract, 'verify_receipt') as new:
                with self.assertRaises(ValueError):
                    runner.verify_current_receipt(path, Path('/unused/switch'))
                old.assert_not_called()
                new.assert_not_called()

    def test_known_receipts_dispatch_only_to_their_own_verifier(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'receipt.json'
            for schema, expected in [('bmv2-steady-clock-v1', 'old'), (runner.queue_contract.SCHEMA, 'new')]:
                path.write_text(json.dumps({'schema': schema}))
                with patch.object(runner.clock_contract, 'verify_receipt', return_value='old') as old, \
                     patch.object(runner.queue_contract, 'verify_receipt', return_value='new') as new:
                    self.assertEqual(runner.verify_current_receipt(path, Path('/unused/switch')), expected)
                    self.assertEqual(old.call_count, expected == 'old')
                    self.assertEqual(new.call_count, expected == 'new')

    def test_missing_native_parity_and_normal_smoke_are_rejected(self):
        with self.assertRaises(ValueError):
            runner.verify_native_packetfile(None, {})
        with self.assertRaises(ValueError):
            runner.verify_normal_smoke(None, Path('/unused'), {})

    def test_normal_smoke_requires_exact_preparation_and_receipt(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            prepared, smoke = root / 'prepared', root / 'smoke'
            prepared.mkdir()
            smoke.mkdir()
            (prepared / 'manifest.json').write_text('{}')
            receipt = {'receipt_sha256': 'new-binary'}
            results = {f'{name}_RF_{model}': {'packets': count, 'unchanged_forwarded_packets': count, 'decisions': 2}
                       for name, count in [('classification-heavy', 16), ('cached-forwarding', 32)] for model in 'BC'}
            summary = {'passed': True, 'status': 'normal_performance_packet_file_passed',
                       'prepared_manifest_sha256': runner.native_prefix.sha256_file(prepared / 'manifest.json'),
                       'clock_receipt': receipt, 'output_sha256': {}, 'results': results}
            path = smoke / 'summary.json'
            path.write_text(json.dumps(summary))
            self.assertEqual(runner.verify_normal_smoke(smoke, prepared, receipt)['path'], str(smoke))
            for field, value in [('prepared_manifest_sha256', 'other-preparation'),
                                 ('clock_receipt', {'receipt_sha256': 'old-binary'}), ('passed', False)]:
                path.write_text(json.dumps(dict(summary, **{field: value})))
                with self.assertRaises(ValueError):
                    runner.verify_normal_smoke(smoke, prepared, receipt)

    def test_historical_p4_hash_cannot_be_replaced_by_a_new_hash(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            native, prep, p4 = root / 'native', root / 'prep', root / 'p4'
            for directory in (native, prep, p4):
                directory.mkdir()
            hashes = {}
            for name in ('flow_features.p4', 'rf_b.p4', 'rf_c.p4', 'rf-models.json'):
                path = p4 / name
                path.write_text('frozen-' + name)
                hashes[str(path)] = runner.native_prefix.sha256_file(path)
            population = prep / 'population.json'
            population.write_text(json.dumps({'input_sha256': hashes}))
            manifest = prep / 'manifest.json'
            manifest.write_text(json.dumps({'population_sha256': runner.native_prefix.sha256_file(population)}))
            (native / 'provenance.json').write_text(json.dumps({'prepared': str(prep),
                'prepared_manifest_sha256': runner.native_prefix.sha256_file(manifest)}))
            self.assertEqual(len(runner.verify_historical_pipeline(native, root)), 6)
            (p4 / 'rf_c.p4').write_text('changed')
            with self.assertRaises(ValueError):
                runner.verify_historical_pipeline(native, root)


if __name__ == '__main__':
    unittest.main()
