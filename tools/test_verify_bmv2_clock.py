"""Clock proof checks use isolated files; no BMv2 source or executable is touched."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


TOOL = Path(__file__).with_name('verify_bmv2_clock.py')
SPEC = importlib.util.spec_from_file_location('verify_bmv2_clock', TOOL)
clock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(clock)


def disassembly(elapsed='steady_clock', epoch='system_clock'):
    return (
        '00000100 <SimpleSwitch::get_ts() const>:\n'
        f'  100: call 20 <std::chrono::_V2::{elapsed}::now()@plt>\n\n'
        '00000200 <SimpleSwitch::get_time_since_epoch_us() const>:\n'
        f'  200: call 30 <std::chrono::_V2::{epoch}::now()@plt>\n\n'
        '00000300 <unrelated_clock_user()>:\n'
        '  300: call 40 <std::chrono::_V2::steady_clock::now()@plt>\n\n'
    )


class ClockBuildProofTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / 'targets' / 'simple_switch'
        self.target.mkdir(parents=True)
        (self.target / '.libs').mkdir()
        self.switch = self.target / 'simple_switch'
        self.switch.write_text('#!/bin/sh\nexec .libs/simple_switch\n', encoding='utf-8')
        (self.target / '.libs' / 'simple_switch').write_bytes(b'\x7fELFfixture')
        (self.target / 'simple_switch.h').write_text(
            'using clock = std::chrono::steady_clock;\n'
            'static_assert(clock::is_steady, "monotonic elapsed clock required");\n',
            encoding='utf-8')
        (self.target / 'simple_switch.cpp').write_text(
            'SimpleSwitch::get_time_since_epoch_us() const {\n'
            '  auto tp = std::chrono::system_clock::now();\n'
            '  return tp.time_since_epoch().count();\n}\n', encoding='utf-8')

    def inspect(self, output=None, returncode=0):
        result = subprocess.CompletedProcess(
            ['objdump'], returncode, stdout=output or disassembly(), stderr='failure' if returncode else '')
        with patch.object(clock.subprocess, 'run', return_value=result) as invoked:
            receipt = clock.inspect_build(self.switch)
        self.assertEqual(invoked.call_args.args[0][-1], str(self.target / '.libs' / 'simple_switch'))
        return receipt

    def save_receipt(self, receipt):
        path = self.root / 'clock_receipt.json'
        path.write_text(json.dumps(receipt), encoding='utf-8')
        return path

    def test_accepts_elapsed_steady_and_epoch_system(self):
        before = {path: path.read_bytes() for path in self.target.rglob('*') if path.is_file()}
        receipt = self.inspect()
        self.assertTrue(receipt['compiled_clock_verified'])
        self.assertEqual(receipt['elapsed_clock'], 'std::chrono::steady_clock')
        self.assertEqual(set(receipt['artifacts']), {'wrapper', 'elf', 'header', 'source'})
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_global_steady_symbol_does_not_prove_elapsed_clock(self):
        with self.assertRaisesRegex(ValueError, 'Compiled get_ts'):
            self.inspect(disassembly(elapsed='system_clock'))

    def test_rejects_epoch_changed_to_steady(self):
        with self.assertRaisesRegex(ValueError, 'Compiled epoch'):
            self.inspect(disassembly(epoch='steady_clock'))

    def test_rejects_missing_compiled_elapsed_function(self):
        with self.assertRaisesRegex(ValueError, 'Compiled clock function unavailable'):
            self.inspect('00000300 <unrelated_clock_user()>:\n 300: ret\n')

    def test_rejects_failed_objdump(self):
        with self.assertRaisesRegex(ValueError, 'Cannot inspect compiled clock calls'):
            self.inspect(returncode=1)

    def test_rejects_non_elf_executable(self):
        (self.target / '.libs' / 'simple_switch').write_bytes(b'#!/bin/sh\n')
        with self.assertRaisesRegex(ValueError, 'not ELF'):
            self.inspect()

    def test_rejects_unfixed_source_clock(self):
        (self.target / 'simple_switch.h').write_text(
            'using clock = std::chrono::high_resolution_clock;\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'not steady_clock'):
            self.inspect()

    def test_accepts_unchanged_receipt_without_input_writes(self):
        receipt = self.inspect()
        path = self.save_receipt(receipt)
        before = {item: item.read_bytes() for item in self.root.rglob('*') if item.is_file()}
        actual = clock.verify_receipt(path, self.switch)
        self.assertEqual(actual['receipt_sha256'], clock.sha256_file(path))
        self.assertEqual(set(before), {item for item in self.root.rglob('*') if item.is_file()})
        for item, content in before.items():
            self.assertEqual(item.read_bytes(), content)

    def test_rejects_changed_binary_and_source(self):
        receipt = self.inspect()
        path = self.save_receipt(receipt)
        for name in ('elf', 'header', 'source', 'wrapper'):
            with self.subTest(artifact=name):
                artifact = Path(receipt['artifacts'][name]['path'])
                original = artifact.read_bytes()
                artifact.write_bytes(original + b'changed')
                with self.assertRaisesRegex(ValueError, 'changed'):
                    clock.verify_receipt(path, self.switch)
                artifact.write_bytes(original)

    def test_rejects_forged_binary_and_source_hashes(self):
        for name in ('elf', 'header', 'source'):
            with self.subTest(artifact=name):
                receipt = self.inspect()
                receipt['artifacts'][name]['sha256'] = '0' * 64
                path = self.save_receipt(receipt)
                with self.assertRaisesRegex(ValueError, 'changed'):
                    clock.verify_receipt(path, self.switch)

    def test_receipt_cannot_substitute_unchanged_copy_for_execution_artifact(self):
        for name in ('elf', 'header', 'source', 'wrapper'):
            with self.subTest(artifact=name):
                receipt = self.inspect()
                actual = Path(receipt['artifacts'][name]['path'])
                copy = self.root / ('saved_' + name)
                copy.write_bytes(actual.read_bytes())
                receipt['artifacts'][name]['path'] = str(copy)
                path = self.save_receipt(receipt)
                with self.assertRaises(ValueError):
                    clock.verify_receipt(path, self.switch)

    def test_receipt_rejects_different_selected_switch(self):
        receipt = self.inspect()
        path = self.save_receipt(receipt)
        with self.assertRaisesRegex(ValueError, 'Wrong clock-build receipt'):
            clock.verify_receipt(path, self.root / 'other_simple_switch')


class CleanPilotGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pilot = self.root / 'native_pilot'
        self.pilot.mkdir()
        self.receipt = {
            'receipt_sha256': 'a' * 64,
            'artifacts': {'elf': {'path': '/fixture/.libs/simple_switch', 'sha256': 'b' * 64}},
        }
        self.summary = {
            'status': 'native_pilot_passed', 'passed': True, 'raw_clock_clean': True,
            'native_clock': True, 'cleanup_passed': True,
            'models': {model: {
                'parity_passed': True, 'clock_quality': {'clean': True, 'raw_backward_steps': 0},
                'packets': 8, 'decisions': 1,
            } for model in 'BC'},
            'output_sha256': {},
        }
        for model in 'BC':
            (self.pilot / ('RF_' + model)).mkdir()
            for name in ('comparison', 'counter_query', 'transport'):
                relative = 'RF_' + model + '/' + name + '.json'
                path = self.pilot / relative
                path.write_text('{"passed":true}\n', encoding='utf-8')
                self.summary['output_sha256'][relative] = clock.sha256_file(path)
        interfaces = self.pilot / 'interfaces.json'
        interfaces.write_text('{"cleanup_passed":true}\n', encoding='utf-8')
        self.summary['output_sha256']['interfaces.json'] = clock.sha256_file(interfaces)
        provenance = self.pilot / 'provenance.json'
        provenance.write_text(json.dumps({'clock_source_receipt': self.receipt}), encoding='utf-8')
        self.summary['output_sha256']['provenance.json'] = clock.sha256_file(provenance)
        self.write_summary()

    def write_summary(self):
        (self.pilot / 'summary.json').write_text(json.dumps(self.summary), encoding='utf-8')

    def verify(self, receipt=None):
        return clock.verify_clean_pilot(self.pilot, self.receipt if receipt is None else receipt)

    def test_complete_clean_pilot_passes_without_mutating_evidence(self):
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        result = self.verify()
        self.assertTrue(result['raw_clock_clean'])
        self.assertEqual(result['summary_sha256'], clock.sha256_file(self.pilot / 'summary.json'))
        self.assertEqual(set(before), {path for path in self.root.rglob('*') if path.is_file()})
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_rejects_failure_marker_even_when_summary_passed(self):
        (self.pilot / 'failure.json').write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'failure marker'):
            self.verify()

    def test_old_passed_summary_without_clock_quality_cannot_unlock_full_run(self):
        del self.summary['raw_clock_clean']
        self.write_summary()
        with self.assertRaisesRegex(ValueError, 'raw-clock quality'):
            self.verify()

    def test_rejects_raw_clock_regression_in_either_model(self):
        for model in 'BC':
            with self.subTest(model=model):
                self.summary['models'][model]['clock_quality']['raw_backward_steps'] = 1
                self.write_summary()
                with self.assertRaisesRegex(ValueError, 'clean eight-packet'):
                    self.verify()
                self.summary['models'][model]['clock_quality']['raw_backward_steps'] = 0

    def test_rejects_null_clean_flag_in_either_model(self):
        for model in 'BC':
            with self.subTest(model=model):
                self.summary['models'][model]['clock_quality']['clean'] = None
                self.write_summary()
                with self.assertRaisesRegex(ValueError, 'clean eight-packet'):
                    self.verify()
                self.summary['models'][model]['clock_quality']['clean'] = True

    def test_rejects_null_clock_quality_without_type_error(self):
        self.summary['models']['B']['clock_quality'] = None
        self.write_summary()
        with self.assertRaisesRegex(ValueError, 'clean eight-packet'):
            self.verify()

    def test_rejects_different_clock_receipt_or_actual_binary(self):
        for field in ('receipt_sha256', 'artifacts'):
            with self.subTest(field=field):
                receipt = json.loads(json.dumps(self.receipt))
                if field == 'receipt_sha256':
                    receipt[field] = 'c' * 64
                else:
                    receipt[field]['elf']['sha256'] = 'c' * 64
                with self.assertRaisesRegex(ValueError, 'different clock build'):
                    self.verify(receipt)

    def test_rejects_tampered_output_evidence(self):
        (self.pilot / 'RF_B' / 'comparison.json').write_text('{"passed":false}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            self.verify()

    def test_rejects_output_path_outside_pilot_directory(self):
        outside = self.root / 'outside.json'
        outside.write_text('{}', encoding='utf-8')
        self.summary['output_sha256']['../outside.json'] = clock.sha256_file(outside)
        self.write_summary()
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            self.verify()

    def test_rejects_unsealed_pilot_evidence(self):
        self.summary['output_sha256'] = {}
        self.write_summary()
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == '__main__':
    unittest.main()
