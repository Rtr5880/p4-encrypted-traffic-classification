"""Tests that intentionally corrupt inference reports and sealed inputs."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

import integrate_rf as integration
import prepare_rf_deployment as reference
import rf_parity_probes as probes


def report_bytes(prediction=0, valid=1, model=0, leaves=None, scores=None):
    return struct.pack('!IBBBB10H6I', integration.RF_MAGIC, 1, valid, model, prediction,
                       *(leaves or [0] * 10), *(scores or [0] * 6))


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.export = probes.synthetic_export()
        self.rows = probes.synthetic_vectors()
        leaves, _, scores = reference.predict_export(self.export, self.rows)
        self.frames = []
        for i, row in enumerate(self.rows):
            request = integration.vector_frame(i + 1, row)
            self.frames.append(request[:12] + b'\x88\xb8' + request[14:] + report_bytes(
                int(scores[i].argmax()), leaves=leaves[i].tolist(), scores=scores[i].tolist()))

    def test_correct_vector_reports(self):
        result, reports = integration.compare_vectors(self.export, self.rows, self.frames)
        self.assertEqual([r['prediction'] for r in reports], [0, 2, 5, 1])
        integration.require_full_coverage(result['coverage'])

    def test_truncated_or_wrong_magic_header_rejected(self):
        for data in (b'', b'\x00' * 52):
            with self.assertRaises(ValueError):
                integration.decode_rf(data, 0)

    def test_missing_duplicate_or_reordered_reports_rejected(self):
        for frames in (self.frames[:-1], self.frames[::-1], [self.frames[0]] * 4):
            with self.assertRaises(ValueError):
                integration.compare_vectors(self.export, self.rows, frames)

    def test_feature_echo_change_rejected(self):
        frames = self.frames.copy()
        changed = bytearray(frames[0])
        changed[25] ^= 1
        frames[0] = bytes(changed)
        with self.assertRaisesRegex(ValueError, 'Vector/order'):
            integration.compare_vectors(self.export, self.rows, frames)

    def test_leaf_score_and_prediction_mismatches_located(self):
        # RF header starts at 54; prediction offset7, leaf0 offset8, score0 offset28.
        for offset, message in ((54 + 8 + 1, 'leaf ID'), (54 + 28 + 3, 'score sum'), (54 + 7, 'argmax')):
            frames = self.frames.copy()
            changed = bytearray(frames[0])
            changed[offset] ^= 1
            frames[0] = bytes(changed)
            with self.assertRaisesRegex(ValueError, message):
                integration.compare_vectors(self.export, self.rows, frames)

    def test_wrong_model_rejected(self):
        report = integration.decode_rf(report_bytes(model=1), 0)
        with self.assertRaisesRegex(ValueError, 'model identifier'):
            integration.check_rf(report, 'B')

    def test_no_event_must_be_invalid_and_zeroed(self):
        report = integration.decode_rf(report_bytes(prediction=255, valid=0), 0)
        integration.check_rf(report, 'B')
        for key, value in (('prediction', 0), ('valid', 1), ('leaves', [1] * 10), ('scores', [1] * 6)):
            changed = copy.deepcopy(report)
            changed[key] = value
            with self.assertRaisesRegex(ValueError, 'stale inference'):
                integration.check_rf(changed, 'B')

    def test_partial_coverage_cannot_pass_full_coverage_gate(self):
        coverage = probes.coverage(self.export, [self.rows[0]])
        with self.assertRaisesRegex(ValueError, 'coverage'):
            integration.require_full_coverage(coverage)

    def test_sealed_artifact_path_cannot_escape_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            required = {'feature_contract.json', 'run_config.json'}
            for s in ('B', 'C'):
                required.update({f'development_vectors_{s}.jsonl', f'n8_RF_{s}/forest_integer.json',
                    f'n8_RF_{s}/diagnostic_vectors.jsonl', f'n8_RF_{s}/parity.json', f'n8_RF_{s}/model.joblib'})
            hashes = {'../outside': 'x', **{name: 'x' for name in required}}
            (root / 'summary.json').write_text(json.dumps({'output_sha256': hashes}))
            (root / 'run_config.json').write_text(json.dumps({'new_test_predictions': 0, 'new_hyperparameter_search': False}))
            with self.assertRaisesRegex(ValueError, 'Unsafe/missing'):
                integration.load_deployment(root)

    def test_failed_deployment_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'failure.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'failure marker'):
                integration.load_deployment(root)


if __name__ == '__main__':
    unittest.main()
