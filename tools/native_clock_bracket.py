#!/usr/bin/env python3
"""Build and load the Linux native sequential three-clock reader.

The native call reduces Python work between the three reads; it remains
preemptible. Every successful call returns the raw signed nanosecond values.
The caller owns its existing audit gates, retention, and sampling policy.
Imports perform no compilation, process creation, or library loading.
"""

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import uuid


BACKEND_NAME = 'linux-native-three-read-v1'
SCHEMA_VERSION = 1
ABI_VERSION = 1
STRUCT_SIZE = 24
CLOCK_SEQUENCE = ['CLOCK_MONOTONIC', 'CLOCK_REALTIME', 'CLOCK_MONOTONIC']
FIELD_ORDER = ['monotonic_before_ns', 'realtime_ns', 'monotonic_after_ns']
SAMPLE_POLICY = {'retries': 0, 'filters': False, 'gate_changes': False}
COMPILE_FLAGS = ['-std=c11', '-O2', '-fPIC', '-shared', '-Wall', '-Wextra', '-Werror']


class NativeClockError(RuntimeError):
    """A build, receipt, or ABI cannot be used as a native clock reader."""


class NativeClockBuildError(NativeClockError):
    def __init__(self, message, directory):
        super().__init__(message)
        self.directory = Path(directory)


class _ClockBracket(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int64) for name in FIELD_ORDER]


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _require(condition, message):
    if not condition:
        raise NativeClockError(message)


def _require_linux64():
    _require(platform.system() == 'Linux' and ctypes.sizeof(ctypes.c_void_p) == 8,
             'The native clock reader requires a 64-bit Linux process')


def _file_record(path):
    path = Path(path).resolve(strict=True)
    _require(path.is_file(), f'Not a regular input file: {path}')
    return {'path': str(path), 'sha256': sha256_file(path)}


def _json_write_exclusive(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, f'Duplicate JSON field: {key}')
        result[key] = value
    return result


def _read_json(path):
    try:
        with Path(path).open('r', encoding='utf-8') as stream:
            return json.load(stream, object_pairs_hook=_reject_duplicates,
                             parse_constant=lambda value: (_ for _ in ()).throw(
                                 NativeClockError(f'Invalid JSON constant: {value}')))
    except (OSError, UnicodeError, ValueError) as error:
        raise NativeClockError(f'Cannot read native clock metadata: {path}: {error}') from error


def _keys(value, names, description):
    _require(type(value) is dict and set(value) == set(names),
             f'Invalid {description} schema')


def _validate_file_record(value, description, expected_path=None):
    _keys(value, ['path', 'sha256'], description)
    _require(type(value['path']) is str and Path(value['path']).is_absolute(),
             f'{description} must use an absolute path')
    _require(type(value['sha256']) is str and
             re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is not None,
             f'Invalid {description} SHA-256')
    try:
        path = Path(value['path']).resolve(strict=True)
    except OSError as error:
        raise NativeClockError(f'{description} missing: {value["path"]}') from error
    _require(str(path) == value['path'] and path.is_file(),
             f'{description} path is not a resolved regular file')
    if expected_path is not None:
        _require(path == Path(expected_path).resolve(), f'{description} path does not match')
    _require(sha256_file(path) == value['sha256'], f'{description} hash mismatch: {path}')
    return path


def _resolve_compiler(repo, cc):
    if cc is not None:
        candidate = str(cc)
    else:
        bundled = repo / 'p4' / 'compiler' / 'cc'
        candidate = str(bundled) if bundled.is_file() else 'cc'
    located = shutil.which(candidate)
    _require(located is not None, f'C compiler not found: {candidate}')
    return Path(located).resolve(strict=True)


def build_native_clock_bracket(repo=None, cc=None, source=None, output_root=None):
    """Compile into a fresh, exclusive evidence directory; return its .so path.

    Failed compiler runs keep compile.json, create no receipt, and raise a
    NativeClockBuildError whose directory identifies the diagnostic artifact.
    """
    _require_linux64()
    repo = Path(repo or Path(__file__).resolve().parent.parent).resolve(strict=True)
    _require(repo.is_dir(), f'Repository directory missing: {repo}')
    source_record = _file_record(source or repo / 'tools' / 'clock_bracket.c')
    compiler_record = _file_record(_resolve_compiler(repo, cc))
    root = Path(output_root or repo / 'results' / 'native_clock_bracket').resolve()
    root.mkdir(parents=True, exist_ok=True)
    directory = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex)
    directory.mkdir(exist_ok=False)
    library_path = directory / 'libetc_clock_bracket.so'
    command = [compiler_record['path'], *COMPILE_FLAGS, source_record['path'], '-o', str(library_path)]
    manifest = {
        'schema_version': SCHEMA_VERSION, 'backend': BACKEND_NAME, 'status': 'failed',
        'command': command, 'cwd': str(repo), 'source': source_record,
        'compiler': compiler_record, 'compiler_version': None,
        'returncode': None, 'stdout': '', 'stderr': '', 'error': None,
    }
    try:
        version = subprocess.run([compiler_record['path'], '--version'], cwd=repo,
                                 check=False, capture_output=True, text=True)
        manifest['compiler_version'] = {'command': [compiler_record['path'], '--version'],
                                        'returncode': version.returncode,
                                        'stdout': version.stdout, 'stderr': version.stderr}
        _require(version.returncode == 0 and bool(version.stdout.strip()),
                 'Cannot obtain the C compiler version')
        compiled = subprocess.run(command, cwd=repo, check=False, capture_output=True, text=True)
        manifest.update(returncode=compiled.returncode, stdout=compiled.stdout, stderr=compiled.stderr)
        _require(compiled.returncode == 0, f'C compiler failed with exit code {compiled.returncode}')
        library_record = _file_record(library_path)
        _require(sha256_file(source_record['path']) == source_record['sha256'],
                 'C source changed during compilation')
        _require(sha256_file(compiler_record['path']) == compiler_record['sha256'],
                 'C compiler changed during compilation')
        manifest['status'] = 'compiled'
    except (OSError, NativeClockError) as error:
        manifest['error'] = str(error)
        _json_write_exclusive(directory / 'compile.json', manifest)
        raise NativeClockBuildError(str(error), directory) from error
    _json_write_exclusive(directory / 'compile.json', manifest)
    receipt = {
        'schema_version': SCHEMA_VERSION, 'status': 'ready', 'backend': BACKEND_NAME,
        'abi_version': ABI_VERSION, 'struct_size': STRUCT_SIZE, 'units': 'nanoseconds',
        'field_order': FIELD_ORDER, 'clock_sequence': CLOCK_SEQUENCE, 'atomic': False,
        'sample_policy': SAMPLE_POLICY, 'source': source_record, 'library': library_record,
        'compiler': compiler_record, 'compiler_version': manifest['compiler_version'],
        'compile': _file_record(directory / 'compile.json'),
    }
    _json_write_exclusive(directory / 'receipt.json', receipt)
    return library_path


def _validate_receipt(library_path):
    receipt_path = library_path.parent / 'receipt.json'
    receipt = _read_json(receipt_path)
    _keys(receipt, ['schema_version', 'status', 'backend', 'abi_version', 'struct_size',
                    'units', 'field_order', 'clock_sequence', 'atomic', 'sample_policy',
                    'source', 'library', 'compiler', 'compiler_version', 'compile'], 'receipt')
    for key, expected in [('schema_version', SCHEMA_VERSION), ('abi_version', ABI_VERSION),
                          ('struct_size', STRUCT_SIZE)]:
        _require(type(receipt[key]) is int and receipt[key] == expected,
                 f'Unsupported receipt {key}')
    _require(receipt['status'] == 'ready' and receipt['backend'] == BACKEND_NAME and
             receipt['units'] == 'nanoseconds' and receipt['field_order'] == FIELD_ORDER and
             receipt['clock_sequence'] == CLOCK_SEQUENCE and receipt['atomic'] is False,
             'Receipt does not describe the required sequential three-clock reader')
    _keys(receipt['sample_policy'], SAMPLE_POLICY, 'sample policy')
    _require(type(receipt['sample_policy']['retries']) is int and
             receipt['sample_policy']['retries'] == 0 and
             receipt['sample_policy']['filters'] is False and
             receipt['sample_policy']['gate_changes'] is False,
             'Receipt sample policy changed')
    paths = {name: _validate_file_record(receipt[name], name,
             library_path if name == 'library' else
             library_path.parent / 'compile.json' if name == 'compile' else None)
             for name in ['source', 'library', 'compiler', 'compile']}
    version = receipt['compiler_version']
    _keys(version, ['command', 'returncode', 'stdout', 'stderr'], 'compiler version')
    _require(version['command'] == [str(paths['compiler']), '--version'] and
             type(version['returncode']) is int and version['returncode'] == 0 and
             type(version['stdout']) is str and bool(version['stdout'].strip()) and
             type(version['stderr']) is str, 'Invalid compiler version metadata')
    manifest = _read_json(paths['compile'])
    _keys(manifest, ['schema_version', 'backend', 'status', 'command', 'cwd', 'source',
                     'compiler', 'compiler_version', 'returncode', 'stdout', 'stderr',
                     'error'], 'compilation')
    _require(type(manifest['schema_version']) is int and manifest['schema_version'] == SCHEMA_VERSION and
             manifest['backend'] == BACKEND_NAME and manifest['status'] == 'compiled' and
             manifest['source'] == receipt['source'] and manifest['compiler'] == receipt['compiler'] and
             manifest['compiler_version'] == version and
             type(manifest['returncode']) is int and manifest['returncode'] == 0 and
             type(manifest['stdout']) is str and type(manifest['stderr']) is str and
             manifest['error'] is None, 'Compilation metadata does not match receipt')
    _require(type(manifest['cwd']) is str and Path(manifest['cwd']).is_absolute() and
             str(Path(manifest['cwd']).resolve()) == manifest['cwd'],
             'Compilation working directory is not resolved and absolute')
    _require(manifest['command'] == [str(paths['compiler']), *COMPILE_FLAGS,
                                    str(paths['source']), '-o', str(paths['library'])],
             'Compilation command does not match receipt')
    return receipt_path, receipt, paths


class NativeClockBracket:
    """One preemptible C bracket per call, with one private output structure.

    The ABI/library bindings are retained for the reader lifetime. A successful
    read is never retried, filtered, or rejected for clock order or bracket width.
    """
    def __init__(self, library_path):
        _require_linux64()
        library_path = Path(library_path).resolve(strict=True)
        receipt_path, receipt, paths = _validate_receipt(library_path)
        _require(ctypes.sizeof(_ClockBracket) == STRUCT_SIZE and
                 [getattr(_ClockBracket, name).offset for name in FIELD_ORDER] == [0, 8, 16],
                 'Python clock structure layout does not match the ABI')
        try:
            library = ctypes.CDLL(str(library_path), use_errno=True)
            abi = library.etc_clock_bracket_abi
            abi.argtypes, abi.restype = [], ctypes.c_int
            size = library.etc_clock_bracket_size
            size.argtypes, size.restype = [], ctypes.c_size_t
            _require(abi() == ABI_VERSION, 'Native library ABI version mismatch')
            _require(size() == STRUCT_SIZE, 'Native library structure size mismatch')
            read = library.etc_read_clock_bracket
            read.argtypes, read.restype = [ctypes.POINTER(_ClockBracket)], ctypes.c_int
        except (OSError, AttributeError) as error:
            raise NativeClockError(f'Cannot load native clock ABI: {error}') from error
        self._library = library
        self._read = read
        inputs = {str(paths[name]): receipt[name]['sha256'] for name in paths}
        inputs[str(receipt_path)] = sha256_file(receipt_path)
        inputs[str(Path(__file__).resolve())] = sha256_file(__file__)
        self._provenance = {
            'backend': BACKEND_NAME, 'library_path': str(library_path),
            'library_sha256': receipt['library']['sha256'],
            'receipt_path': str(receipt_path), 'receipt_sha256': inputs[str(receipt_path)],
            'source_path': str(paths['source']), 'source_sha256': receipt['source']['sha256'],
            'compiler_path': str(paths['compiler']), 'compiler_sha256': receipt['compiler']['sha256'],
            'abi_version': ABI_VERSION, 'struct_size': STRUCT_SIZE,
            'clock_sequence': list(CLOCK_SEQUENCE), 'atomic': False,
            'input_sha256': inputs,
        }

    @property
    def provenance(self):
        # Return independent serializable state; callers cannot alter our record.
        return json.loads(json.dumps(self._provenance))

    def __call__(self):
        output = _ClockBracket()
        result = self._read(ctypes.byref(output))
        if result != 0:
            if result > 0:
                raise OSError(result, os.strerror(result))
            raise NativeClockError(f'Native read returned invalid error code: {result}')
        return tuple(getattr(output, name) for name in FIELD_ORDER)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='command', required=True)
    compile_parser = subparsers.add_parser('compile', help='Compile a fresh native reader receipt')
    compile_parser.add_argument('--repo', type=Path,
                                default=Path(__file__).resolve().parent.parent)
    compile_parser.add_argument('--cc', help='C compiler executable or PATH name (default: cc)')
    compile_parser.add_argument('--source', type=Path)
    compile_parser.add_argument('--output-root', type=Path)
    args = parser.parse_args(argv)
    try:
        path = build_native_clock_bracket(args.repo, args.cc, args.source, args.output_root)
    except NativeClockError as error:
        parser.exit(1, f'{error}\n')
    print(path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
