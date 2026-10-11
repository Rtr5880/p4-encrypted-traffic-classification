#!/usr/bin/env python3
"""Evidence-sealed Linux sender; import never builds, loads, or sends.

The complete sleep/send loop runs in one ctypes.CDLL call (which releases the
Python GIL). CLOCK_MONOTONIC absolute deadlines are unchanged after a late wake.
Late sends and catch-up gaps remain observable; no retry or filtering occurs.
This does not remove Linux/WSL scheduling jitter or guarantee any quality gate.
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
import threading
import uuid

BACKEND_NAME = 'linux-native-paced-send-v1'
ABI_VERSION = SCHEMA_VERSION = 1
RESULT_FIELDS = ['scheduled_start_ns', 'send_window_end_ns', 'sent_count',
                 'attempted_count', 'error_code', 'error_errno', 'error_index', 'returned_bytes']
RESULT_SIZE = 64
MAX_PACKETS = 500_000
MAX_DURATION_NS = 60_000_000_000
MIN_INTERVAL_NS = 100_000
MAX_INTERVAL_NS = 1_000_000_000
COMPILE_FLAGS = ['-std=c11', '-O2', '-fPIC', '-shared', '-Wall', '-Wextra', '-Werror']
POLICY = {'clock': 'CLOCK_MONOTONIC', 'sleep': 'clock_nanosleep TIMER_ABSTIME',
          'send_retries': 0, 'sleep_retries': 0, 'filters': False,
          'deadline_rebasing': False, 'spinning': False, 'priority_changes': False,
          'send_flags': ['MSG_DONTWAIT', 'MSG_NOSIGNAL'], 'requires_nonblocking_fd': True}
ERROR_NAMES = {1: 'invalid native arguments', 2: 'invalid or blocking sender descriptor',
               3: 'monotonic clock read failed', 4: 'absolute sleep failed',
               5: 'sender cancelled', 6: 'bounded phase window exceeded',
               7: 'nonblocking send failed', 8: 'partial datagram/frame send'}


class NativeSenderError(RuntimeError):
    pass


class NativeSenderBuildError(NativeSenderError):
    def __init__(self, message, directory):
        super().__init__(message)
        self.directory = Path(directory)


class _Result(ctypes.Structure):
    _fields_ = [(field, ctypes.c_int64) for field in RESULT_FIELDS]


def _require(condition, message):
    if not condition:
        raise NativeSenderError(message)


def _linux64():
    _require(platform.system() == 'Linux' and ctypes.sizeof(ctypes.c_void_p) == 8,
             'Native paced sender requires a 64-bit Linux process')


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _record(path):
    path = Path(path).resolve(strict=True)
    _require(path.is_file(), f'Not a regular file: {path}')
    return {'path': str(path), 'sha256': sha256_file(path)}


def _write_json_exclusive(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, f'Duplicate metadata key: {key}')
        result[key] = value
    return result


def _read_json(path):
    try:
        with Path(path).open(encoding='utf-8') as stream:
            return json.load(stream, object_pairs_hook=_pairs,
                             parse_constant=lambda value: (_ for _ in ()).throw(
                                 NativeSenderError(f'Invalid JSON constant: {value}')))
    except (OSError, ValueError) as error:
        raise NativeSenderError(f'Cannot read sender metadata {path}: {error}') from error


def _checked_record(value, name, expected=None):
    _require(type(value) is dict and set(value) == {'path', 'sha256'}, f'Invalid {name} record')
    _require(type(value['path']) is str and Path(value['path']).is_absolute() and
             type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']),
             f'Invalid {name} path/hash')
    try:
        path = Path(value['path']).resolve(strict=True)
    except OSError as error:
        raise NativeSenderError(f'Missing {name}: {value["path"]}') from error
    _require(str(path) == value['path'] and path.is_file(), f'Unresolved {name} path')
    if expected is not None:
        _require(path == Path(expected).resolve(), f'{name} path does not match')
    _require(sha256_file(path) == value['sha256'], f'{name} hash mismatch: {path}')
    return path


def build_native_paced_sender(repo=None, cc=None, source=None, output_root=None):
    """Build an exclusive library/receipt; failed builds keep compile diagnostics."""
    _linux64()
    repo = Path(repo or Path(__file__).resolve().parent.parent).resolve(strict=True)
    _require(repo.is_dir(), 'Repository directory missing')
    source_record = _record(source or Path(__file__).with_name('paced_sender.c'))
    compiler = shutil.which(str(cc or 'cc'))
    _require(compiler is not None, f'C compiler not found: {cc or "cc"}')
    compiler_record = _record(compiler)
    root = Path(output_root or repo / 'results' / 'native_paced_sender').resolve()
    root.mkdir(parents=True, exist_ok=True)
    directory = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex)
    directory.mkdir(exist_ok=False)
    library_path = directory / 'libetc_paced_sender.so'
    command = [compiler_record['path'], *COMPILE_FLAGS, source_record['path'], '-o', str(library_path)]
    manifest = {'schema_version': SCHEMA_VERSION, 'backend': BACKEND_NAME, 'status': 'failed',
                'command': command, 'cwd': str(repo), 'source': source_record,
                'compiler': compiler_record, 'compiler_version': None,
                'returncode': None, 'stdout': '', 'stderr': '', 'error': None}
    try:
        version = subprocess.run([compiler_record['path'], '--version'], cwd=repo,
                                 check=False, capture_output=True, text=True)
        manifest['compiler_version'] = {'command': [compiler_record['path'], '--version'],
                                        'returncode': version.returncode,
                                        'stdout': version.stdout, 'stderr': version.stderr}
        _require(version.returncode == 0 and bool(version.stdout.strip()), 'Cannot obtain compiler version')
        compiled = subprocess.run(command, cwd=repo, check=False, capture_output=True, text=True)
        manifest.update(returncode=compiled.returncode, stdout=compiled.stdout, stderr=compiled.stderr)
        _require(compiled.returncode == 0, f'Compiler exited {compiled.returncode}')
        library_record = _record(library_path)
        _require(_record(source_record['path']) == source_record, 'C source changed during build')
        _require(_record(compiler_record['path']) == compiler_record, 'Compiler changed during build')
        manifest['status'] = 'compiled'
    except (OSError, NativeSenderError) as error:
        manifest['error'] = str(error)
        _write_json_exclusive(directory / 'compile.json', manifest)
        raise NativeSenderBuildError(str(error), directory) from error
    _write_json_exclusive(directory / 'compile.json', manifest)
    receipt = {'schema_version': SCHEMA_VERSION, 'backend': BACKEND_NAME, 'status': 'ready',
               'abi_version': ABI_VERSION, 'result_size': RESULT_SIZE,
               'result_fields': RESULT_FIELDS, 'units': 'nanoseconds', 'policy': POLICY,
               'source': source_record, 'compiler': compiler_record, 'library': library_record,
               'compiler_version': manifest['compiler_version'],
               'compile': _record(directory / 'compile.json')}
    _write_json_exclusive(directory / 'receipt.json', receipt)
    return library_path


def _validate_receipt(library_path):
    receipt_path = library_path.parent / 'receipt.json'
    receipt = _read_json(receipt_path)
    _require(type(receipt) is dict and set(receipt) == {
        'schema_version', 'backend', 'status', 'abi_version', 'result_size', 'result_fields',
        'units', 'policy', 'source', 'compiler', 'library', 'compiler_version', 'compile'},
        'Invalid sender receipt schema')
    for key, expected in [('schema_version', SCHEMA_VERSION), ('abi_version', ABI_VERSION),
                          ('result_size', RESULT_SIZE)]:
        _require(type(receipt[key]) is int and receipt[key] == expected, f'Unsupported {key}')
    _require(receipt['backend'] == BACKEND_NAME and receipt['status'] == 'ready' and
             receipt['result_fields'] == RESULT_FIELDS and receipt['units'] == 'nanoseconds' and
             receipt['policy'] == POLICY, 'Unsupported sender policy/layout')
    paths = {name: _checked_record(receipt[name], name,
             library_path if name == 'library' else
             library_path.parent / 'compile.json' if name == 'compile' else None)
             for name in ['source', 'compiler', 'library', 'compile']}
    manifest = _read_json(paths['compile'])
    _require(type(manifest) is dict and set(manifest) == {
        'schema_version', 'backend', 'status', 'command', 'cwd', 'source', 'compiler',
        'compiler_version', 'returncode', 'stdout', 'stderr', 'error'}, 'Invalid compile schema')
    _require(type(manifest['schema_version']) is int and manifest['schema_version'] == SCHEMA_VERSION and
             manifest['backend'] == BACKEND_NAME and manifest['status'] == 'compiled' and
             type(manifest['returncode']) is int and manifest['returncode'] == 0 and
             manifest['error'] is None and type(manifest['stdout']) is str and
             type(manifest['stderr']) is str and manifest['source'] == receipt['source'] and
             manifest['compiler'] == receipt['compiler'] and
             manifest['compiler_version'] == receipt['compiler_version'] and
             manifest['command'] == [str(paths['compiler']), *COMPILE_FLAGS, str(paths['source']),
                                     '-o', str(paths['library'])], 'Compile record does not match receipt')
    _require(type(manifest['cwd']) is str and Path(manifest['cwd']).is_absolute() and
             str(Path(manifest['cwd']).resolve()) == manifest['cwd'], 'Compile cwd is not absolute/resolved')
    version = receipt['compiler_version']
    _require(type(version) is dict and set(version) == {'command', 'returncode', 'stdout', 'stderr'} and
             version['command'] == [str(paths['compiler']), '--version'] and
             type(version['returncode']) is int and version['returncode'] == 0 and
             type(version['stdout']) is str and bool(version['stdout'].strip()) and
             type(version['stderr']) is str, 'Invalid compiler version evidence')
    return receipt_path, receipt, paths


class NativePacedSender:
    def __init__(self, library_path):
        _linux64()
        library_path = Path(library_path).resolve(strict=True)
        receipt_path, receipt, paths = _validate_receipt(library_path)
        _require(ctypes.sizeof(_Result) == RESULT_SIZE and
                 [getattr(_Result, name).offset for name in RESULT_FIELDS] == list(range(0, 64, 8)),
                 'Python result layout disagrees with native ABI')
        try:
            library = ctypes.CDLL(str(library_path), use_errno=True)
            library.etc_paced_sender_abi.argtypes = []
            library.etc_paced_sender_abi.restype = ctypes.c_int
            library.etc_paced_sender_result_size.argtypes = []
            library.etc_paced_sender_result_size.restype = ctypes.c_size_t
            _require(library.etc_paced_sender_abi() == ABI_VERSION and
                     library.etc_paced_sender_result_size() == RESULT_SIZE, 'Native sender ABI mismatch')
            library.etc_paced_sender_cancel_new.argtypes = []
            library.etc_paced_sender_cancel_new.restype = ctypes.c_void_p
            library.etc_paced_sender_cancel_request.argtypes = [ctypes.c_void_p]
            library.etc_paced_sender_cancel_request.restype = None
            library.etc_paced_sender_cancel_free.argtypes = [ctypes.c_void_p]
            library.etc_paced_sender_cancel_free.restype = None
            library.etc_paced_sender_run.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte),
                ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t, ctypes.c_int64,
                ctypes.POINTER(ctypes.c_int64), ctypes.POINTER(ctypes.c_int64), ctypes.c_void_p,
                ctypes.POINTER(_Result)]
            library.etc_paced_sender_run.restype = ctypes.c_int
        except (OSError, AttributeError) as error:
            raise NativeSenderError(f'Cannot load sender ABI: {error}') from error
        self._library = library
        inputs = {str(paths[name]): receipt[name]['sha256'] for name in paths}
        inputs[str(receipt_path)] = sha256_file(receipt_path)
        inputs[str(Path(__file__).resolve())] = sha256_file(__file__)
        self._provenance = {'backend': BACKEND_NAME, 'library_path': str(library_path),
            'library_sha256': receipt['library']['sha256'], 'receipt_path': str(receipt_path),
            'receipt_sha256': inputs[str(receipt_path)], 'abi_version': ABI_VERSION,
            'result_size': RESULT_SIZE, 'policy': POLICY, 'input_sha256': inputs}

    @property
    def provenance(self):
        return json.loads(json.dumps(self._provenance))

    def prepare(self, frames, deadline_offsets, duration_ns):
        """Allocate and validate all buffers before the measurement callback."""
        return NativeSendPlan(self, frames, deadline_offsets, duration_ns)


class NativeSendPlan:
    """Single-use plan. close() rejects an active run; cancel() is atomic in C.

    Cancellation is checked between sleeps/sends. An in-progress absolute sleep
    is not interrupted; bounded plans guarantee it spans no more than one second.
    Keep the plan alive until all external cancellation workers have joined.
    """
    def __init__(self, sender, frames, deadlines, duration_ns):
        _require(type(frames) in (list, tuple) and 1 <= len(frames) <= MAX_PACKETS,
                 'Plan requires 1..500000 prebuilt frames')
        _require(type(deadlines) in (list, tuple) and len(deadlines) == len(frames),
                 'A deadline offset is required for every frame')
        _require(type(duration_ns) is int and 0 < duration_ns <= MAX_DURATION_NS and
                 MIN_INTERVAL_NS <= duration_ns // len(frames) <= MAX_INTERVAL_NS,
                 'Plan duration/rate is outside supported bounds')
        _require(all(type(frame) is bytes and 60 <= len(frame) <= 1514 for frame in frames),
                 'Expected prebuilt 60..1514-byte frames')
        _require(all(type(deadline) is int and 0 <= deadline < duration_ns for deadline in deadlines)
                 and deadlines[0] == 0 and all(MIN_INTERVAL_NS <= b-a <= MAX_INTERVAL_NS
                 for a, b in zip(deadlines, deadlines[1:]))
                 and duration_ns - deadlines[-1] <= MAX_INTERVAL_NS, 'Invalid deadline offsets')
        self._sender = sender
        self._lock = threading.Lock()
        self._running = self._closed = self._used = False
        self._count = len(frames)
        self._duration = duration_ns
        blob = b''.join(frames)
        self._blob = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        self._blob_size = len(blob)
        offsets, offset = [], 0
        for frame in frames:
            offsets.append(offset)
            offset += len(frame)
        self._offsets = (ctypes.c_uint64 * self._count)(*offsets)
        self._lengths = (ctypes.c_uint32 * self._count)(*map(len, frames))
        self._deadlines = (ctypes.c_int64 * self._count)(*deadlines)
        self._starts = (ctypes.c_int64 * self._count)()
        self._finishes = (ctypes.c_int64 * self._count)()
        self._result = _Result()
        self._flag = sender._library.etc_paced_sender_cancel_new()
        _require(self._flag, 'Cannot allocate sender cancellation flag')

    def cancel(self):
        with self._lock:
            if not self._closed:
                self._sender._library.etc_paced_sender_cancel_request(self._flag)

    def run_raw(self, fd):
        """Native result only; list/report conversion is deferred past callback end."""
        _require(type(fd) is int and fd >= 0, 'Sender descriptor must be a nonnegative integer')
        with self._lock:
            _require(not self._closed and not self._used, 'Plan is closed or already used')
            self._used = self._running = True
        try:
            code = self._sender._library.etc_paced_sender_run(fd, self._blob, self._blob_size,
                self._offsets, self._lengths, self._deadlines, self._count, self._duration,
                self._starts, self._finishes, self._flag, ctypes.byref(self._result))
            # Argument failures should be impossible after prepare, but retain
            # their status in the same result instead of dropping the evidence.
            if code and not self._result.error_code:
                self._result.error_code, self._result.error_errno = 1, code
            return self._result
        finally:
            with self._lock:
                self._running = False

    def report(self, result):
        _require(result is self._result and self._used and not self._running,
                 'Report requires the completed native result from this plan')
        _require(0 <= result.sent_count <= result.attempted_count <= self._count,
                 'Native result counts are invalid')
        errors = []
        if result.error_code:
            error_text = (os.strerror(result.error_errno) if result.error_errno else 'no errno')
            errors.append(f'Native sender {ERROR_NAMES.get(result.error_code, "unknown error")}'
                          f' at sequence {result.error_index}: {error_text}'
                          f' (status={result.error_code}, errno={result.error_errno},'
                          f' returned_bytes={result.returned_bytes})')
        return {'scheduled_start_ns': result.scheduled_start_ns or None,
                'send_window_end_ns': result.send_window_end_ns or None,
                'sent_starts': list(self._starts[:result.sent_count]),
                'sent_finishes': list(self._finishes[:result.sent_count]),
                'attempted_starts': list(self._starts[:result.attempted_count]),
                'attempted_finishes': list(self._finishes[:result.attempted_count]),
                'sent_count': result.sent_count, 'attempted_count': result.attempted_count,
                'errors': errors, 'native_result': {name: getattr(result, name) for name in RESULT_FIELDS}}

    def run(self, fd):
        return self.report(self.run_raw(fd))

    def close(self):
        with self._lock:
            _require(not self._running, 'Cannot free a sender plan during its native run')
            if not self._closed:
                self._sender._library.etc_paced_sender_cancel_free(self._flag)
                self._flag = None
                self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['build'])
    parser.add_argument('--repo', type=Path)
    parser.add_argument('--cc')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output-root', type=Path)
    args = parser.parse_args(argv)
    path = build_native_paced_sender(args.repo, args.cc, args.source, args.output_root)
    print(f'Native sender built: {path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
