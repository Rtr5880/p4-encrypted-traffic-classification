#!/usr/bin/env python3
"""ABI/integrity/build checks; Linux integration is correctness only."""

from concurrent.futures import ThreadPoolExecutor
import ctypes
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import threading
import types
import unittest
from unittest import mock

import native_clock_bracket as native


class FakeFunction:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class FakeLibrary:
    def __init__(self, values=(100, 1000, 101), error=0, abi=1, size=24, callback=None):
        self.values = values
        self.error = error
        self.calls = 0
        self.etc_clock_bracket_abi = FakeFunction(lambda: abi)
        self.etc_clock_bracket_size = FakeFunction(lambda: size)
        self.etc_read_clock_bracket = FakeFunction(callback or self.read)

    def read(self, pointer):
        self.calls += 1
        output = ctypes.cast(pointer, ctypes.POINTER(native._ClockBracket)).contents
        for name, value in zip(native.FIELD_ORDER, self.values, strict=True):
            setattr(output, name, value)
        return self.error


class NativeClockBracketTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name).resolve()
        (self.repo / 'tools').mkdir()
        self.source = self.repo / 'tools' / 'clock_bracket.c'
        self.source.write_text('/* fixture source */\n', encoding='utf-8')
        self.compiler = self.repo / 'fixture-cc'
        self.compiler.write_bytes(b'fixture compiler')
        self.output_root = self.repo / 'results' / 'native_clock_bracket'
        patcher = mock.patch.object(native, '_require_linux64')
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_compile(self, command, **kwargs):
        if command[-1] == '--version':
            return subprocess.CompletedProcess(command, 0, 'fixture cc 1.0\n', '')
        library_path = Path(command[command.index('-o') + 1])
        library_path.write_bytes(b'fixture shared library')
        return subprocess.CompletedProcess(command, 0, '', '')

    def build(self, side_effect=None):
        with mock.patch.object(native.shutil, 'which', return_value=str(self.compiler)), \
             mock.patch.object(native.subprocess, 'run', side_effect=side_effect or self.fake_compile):
            return native.build_native_clock_bracket(self.repo)

    def load(self, library_path, library=None):
        library = library or FakeLibrary()
        with mock.patch.object(native.ctypes, 'CDLL', return_value=library) as cdll:
            reader = native.NativeClockBracket(library_path)
        cdll.assert_called_once_with(str(library_path), use_errno=True)
        return reader, library

    def rewrite_json(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')

    def test_import_does_not_compile_spawn_or_load_library(self):
        spec = importlib.util.spec_from_file_location('native_clock_import_check', native.__file__)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(subprocess, 'run') as run, mock.patch.object(ctypes, 'CDLL') as cdll:
            spec.loader.exec_module(module)
        run.assert_not_called()
        cdll.assert_not_called()

    def test_build_manifest_and_raw_read_and_provenance(self):
        path = self.build()
        self.assertEqual(path.name, 'libetc_clock_bracket.so')
        self.assertTrue(path.is_relative_to(self.output_root))
        manifest = json.loads((path.parent / 'compile.json').read_text(encoding='utf-8'))
        receipt = json.loads((path.parent / 'receipt.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['command'], [str(self.compiler), *native.COMPILE_FLAGS,
                                              str(self.source), '-o', str(path)])
        self.assertEqual(receipt['clock_sequence'], native.CLOCK_SEQUENCE)
        self.assertIs(receipt['atomic'], False)
        self.assertEqual(receipt['sample_policy'], native.SAMPLE_POLICY)
        reader, library = self.load(path)
        self.assertEqual(reader(), (100, 1000, 101))
        self.assertEqual(library.calls, 1)
        self.assertEqual(library.etc_read_clock_bracket.argtypes,
                         [ctypes.POINTER(native._ClockBracket)])
        self.assertIs(library.etc_read_clock_bracket.restype, ctypes.c_int)
        self.assertEqual(reader.provenance['backend'], 'linux-native-three-read-v1')
        expected_inputs = [self.source, path, path.parent / 'receipt.json',
                           path.parent / 'compile.json', self.compiler, Path(native.__file__).resolve()]
        self.assertEqual(reader.provenance['input_sha256'],
                         {str(item): native.sha256_file(item) for item in expected_inputs})
        json.dumps(reader.provenance, allow_nan=False)
        changed = reader.provenance
        changed['input_sha256'].clear()
        self.assertEqual(len(reader.provenance['input_sha256']), 6)

    def test_int64_boundaries_zero_and_regressions_are_returned_raw(self):
        path = self.build()
        for values in [(-(2 ** 63), 2 ** 63 - 1, -(2 ** 63)), (0, 0, 0), (300, -10, 100),
                       (1, 2, 999999999999)]:
            with self.subTest(values=values):
                reader, library = self.load(path, FakeLibrary(values=values))
                self.assertEqual(reader(), values)
                self.assertTrue(all(type(value) is int for value in reader()))
                self.assertEqual(library.calls, 2)

    def test_native_error_is_not_retried_or_returned_as_sample(self):
        path = self.build()
        reader, library = self.load(path, FakeLibrary(error=22))
        with self.assertRaises(OSError) as raised:
            reader()
        self.assertEqual(raised.exception.errno, 22)
        self.assertEqual(library.calls, 1)
        reader, library = self.load(path, FakeLibrary(error=-1))
        with self.assertRaisesRegex(native.NativeClockError, 'invalid error code'):
            reader()
        self.assertEqual(library.calls, 1)

    def test_abi_and_structure_size_are_checked(self):
        path = self.build()
        for library, expected in [(FakeLibrary(abi=2), 'ABI version mismatch'),
                                  (FakeLibrary(size=32), 'structure size mismatch')]:
            with self.subTest(expected=expected), \
                 mock.patch.object(native.ctypes, 'CDLL', return_value=library):
                with self.assertRaisesRegex(native.NativeClockError, expected):
                    native.NativeClockBracket(path)

    def test_python_structure_layout_is_checked_before_library_load(self):
        class WrongLayout(ctypes.Structure):
            _fields_ = [('monotonic_before_ns', ctypes.c_int64),
                        ('monotonic_after_ns', ctypes.c_int64), ('realtime_ns', ctypes.c_int64)]

        path = self.build()
        with mock.patch.object(native, '_ClockBracket', WrongLayout), \
             mock.patch.object(native.ctypes, 'CDLL') as cdll:
            with self.assertRaisesRegex(native.NativeClockError, 'structure layout'):
                native.NativeClockBracket(path)
            cdll.assert_not_called()

    def test_missing_native_symbol_is_reported(self):
        path = self.build()
        with mock.patch.object(native.ctypes, 'CDLL', return_value=object()):
            with self.assertRaisesRegex(native.NativeClockError, 'Cannot load native clock ABI'):
                native.NativeClockBracket(path)

    def test_concurrent_calls_have_private_output_storage(self):
        path = self.build()
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        addresses = []

        def read(pointer):
            output = ctypes.cast(pointer, ctypes.POINTER(native._ClockBracket)).contents
            with lock:
                index = len(addresses)
                addresses.append(ctypes.addressof(output))
            barrier.wait(timeout=5)
            for name, value in zip(native.FIELD_ORDER, (index, index + 10, index + 20), strict=True):
                setattr(output, name, value)
            return 0

        reader, _ = self.load(path, FakeLibrary(callback=read))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: reader(), range(2)))
        self.assertEqual(set(results), {(0, 10, 20), (1, 11, 21)})
        self.assertEqual(len(set(addresses)), 2)

    def test_hash_tampering_is_rejected_before_loading(self):
        path = self.build()
        for item in [self.source, path, self.compiler, path.parent / 'compile.json']:
            original = item.read_bytes()
            with self.subTest(item=item):
                item.write_bytes(original + b'changed')
                with mock.patch.object(native.ctypes, 'CDLL') as cdll:
                    with self.assertRaisesRegex(native.NativeClockError, 'hash mismatch'):
                        native.NativeClockBracket(path)
                    cdll.assert_not_called()
                item.write_bytes(original)

    def test_receipt_schema_policy_and_path_tampering_are_rejected(self):
        path = self.build()
        receipt_path = path.parent / 'receipt.json'
        original = receipt_path.read_text(encoding='utf-8')
        changes = [lambda value: value.update(extra='unexpected'),
                   lambda value: value.update(schema_version=True),
                   lambda value: value.update(abi_version=True),
                   lambda value: value.update(atomic=True),
                   lambda value: value.update(clock_sequence=list(reversed(native.FIELD_ORDER))),
                   lambda value: value['sample_policy'].update(retries=True),
                   lambda value: value['sample_policy'].update(filters=True),
                   lambda value: value['sample_policy'].update(gate_changes=True),
                   lambda value: value['library'].update(path=str(self.source)),
                   lambda value: value['compiler'].update(sha256='G' * 64),
                   lambda value: value['source'].update(path='relative.c'),
                   lambda value: value['compiler_version'].update(returncode=True)]
        for index, change in enumerate(changes):
            value = json.loads(original)
            change(value)
            self.rewrite_json(receipt_path, value)
            with self.subTest(change=index), mock.patch.object(native.ctypes, 'CDLL') as cdll:
                with self.assertRaises(native.NativeClockError):
                    native.NativeClockBracket(path)
                cdll.assert_not_called()
        receipt_path.write_text(original, encoding='utf-8')
        self.load(path)

    def test_duplicate_receipt_fields_are_rejected(self):
        path = self.build()
        receipt_path = path.parent / 'receipt.json'
        value = receipt_path.read_text(encoding='utf-8')
        receipt_path.write_text(value.replace('"schema_version": 1',
                                              '"schema_version": 1, "schema_version": 1'),
                                encoding='utf-8')
        with self.assertRaisesRegex(native.NativeClockError, 'Duplicate JSON field'):
            native.NativeClockBracket(path)

    def test_resealed_wrong_compile_command_is_rejected(self):
        path = self.build()
        compile_path = path.parent / 'compile.json'
        manifest = json.loads(compile_path.read_text(encoding='utf-8'))
        manifest['command'].insert(1, '-DUNAPPROVED_CLOCK_POLICY=1')
        self.rewrite_json(compile_path, manifest)
        receipt_path = path.parent / 'receipt.json'
        receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
        receipt['compile']['sha256'] = native.sha256_file(compile_path)
        self.rewrite_json(receipt_path, receipt)
        with self.assertRaisesRegex(native.NativeClockError, 'command does not match'):
            native.NativeClockBracket(path)

    def test_compiler_failure_keeps_diagnostics_without_receipt(self):
        def compiler_failure(command, **kwargs):
            if command[-1] == '--version':
                return self.fake_compile(command, **kwargs)
            return subprocess.CompletedProcess(command, 7, 'compiler output', 'compiler failure')

        with self.assertRaises(native.NativeClockBuildError) as raised:
            self.build(compiler_failure)
        directory = raised.exception.directory
        self.assertFalse((directory / 'receipt.json').exists())
        manifest = json.loads((directory / 'compile.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['status'], 'failed')
        self.assertEqual(manifest['returncode'], 7)
        self.assertEqual(manifest['stderr'], 'compiler failure')

    def test_compiler_version_failure_stops_before_compilation(self):
        with mock.patch.object(native.shutil, 'which', return_value=str(self.compiler)), \
             mock.patch.object(native.subprocess, 'run',
                               return_value=subprocess.CompletedProcess([], 9, '', 'version failed')) as run:
            with self.assertRaises(native.NativeClockBuildError) as raised:
                native.build_native_clock_bracket(self.repo)
        self.assertEqual(run.call_count, 1)
        manifest = json.loads((raised.exception.directory / 'compile.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['compiler_version']['returncode'], 9)
        self.assertIsNone(manifest['returncode'])
        self.assertFalse((raised.exception.directory / 'receipt.json').exists())

    def test_compiler_launch_failure_is_recorded(self):
        with self.assertRaises(native.NativeClockBuildError) as raised:
            self.build(mock.Mock(side_effect=OSError('cannot execute compiler')))
        manifest = json.loads((raised.exception.directory / 'compile.json').read_text(encoding='utf-8'))
        self.assertIn('cannot execute compiler', manifest['error'])
        self.assertFalse((raised.exception.directory / 'receipt.json').exists())

    def test_source_change_during_compile_does_not_create_receipt(self):
        def mutate_source(command, **kwargs):
            result = self.fake_compile(command, **kwargs)
            if '-o' in command:
                self.source.write_text('changed while compiling', encoding='utf-8')
            return result

        with self.assertRaisesRegex(native.NativeClockBuildError, 'source changed') as raised:
            self.build(mutate_source)
        self.assertFalse((raised.exception.directory / 'receipt.json').exists())

    def test_each_build_has_a_new_exclusive_directory(self):
        first, second = self.build(), self.build()
        self.assertNotEqual(first.parent, second.parent)
        self.assertTrue(first.exists())
        with mock.patch.object(native.uuid, 'uuid4', return_value=types.SimpleNamespace(hex='fixed')):
            first = self.build()
            original = first.read_bytes()
            with self.assertRaises(FileExistsError):
                self.build()
            self.assertEqual(first.read_bytes(), original)

    def test_c_source_has_three_ordered_reads_before_conversions(self):
        source = Path(native.__file__).with_name('clock_bracket.c').read_text(encoding='utf-8')
        read_positions = [source.index('clock_gettime(CLOCK_MONOTONIC, &before)'),
                          source.index('clock_gettime(CLOCK_REALTIME, &realtime)'),
                          source.index('clock_gettime(CLOCK_MONOTONIC, &after)')]
        self.assertEqual(read_positions, sorted(read_positions))
        self.assertGreater(source.index('timespec_ns(&before'), read_positions[-1])
        self.assertGreater(source.index('struct etc_clock_bracket converted;'), read_positions[-1])
        self.assertEqual(source.count('clock_gettime('), 3)


@unittest.skipUnless(platform.system() == 'Linux' and ctypes.sizeof(ctypes.c_void_p) == 8 and
                     shutil.which('cc'), 'Requires existing cc and 64-bit Linux')
class LinuxNativeIntegrationTests(unittest.TestCase):
    def test_actual_compile_and_100_raw_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            source = Path(native.__file__).with_name('clock_bracket.c').resolve()
            path = native.build_native_clock_bracket(repo, source=source)
            reader = native.NativeClockBracket(path)
            values = [reader() for _ in range(100)]
            self.assertEqual(len(values), 100)
            self.assertTrue(all(len(value) == 3 and all(type(item) is int for item in value)
                                for value in values))
            self.assertEqual(reader.provenance['library_sha256'], native.sha256_file(path))


if __name__ == '__main__':
    unittest.main()
