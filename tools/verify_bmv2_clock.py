#!/usr/bin/env python3
"""Seal/check this project's rebuilt BMv2 elapsed-clock source and actual ELF.

No root, wall-clock changes, model fitting, traffic or Git operations. The
libtool wrapper hash alone is insufficient: it may remain unchanged on rebuild.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def function_body(disassembly, signature):
    pattern = r'^[0-9a-f]+ <' + re.escape(signature) + r'>:\n(.*?)(?=\n\n|\Z)'
    found = re.search(pattern, disassembly, re.M | re.S)
    require(found is not None, f'Compiled clock function unavailable: {signature}')
    return found.group(1)


def inspect_build(switch):
    require(not Path(switch).is_symlink(), 'Refusing a symlinked switch wrapper')
    switch = Path(switch).resolve()
    target = switch.parent
    paths = {'wrapper': switch, 'elf': target / '.libs/simple_switch',
             'header': target / 'simple_switch.h', 'source': target / 'simple_switch.cpp'}
    require(all(path.is_file() and not path.is_symlink() for path in paths.values()),
            'Expected local BMv2 wrapper, actual ELF and source files')
    header = paths['header'].read_text(encoding='utf-8')
    source = paths['source'].read_text(encoding='utf-8')
    require(re.search(r'using\s+clock\s*=\s*std::chrono::steady_clock\s*;', header),
            'BMv2 elapsed clock is not steady_clock')
    require(re.search(r'static_assert\s*\(\s*clock::is_steady', header),
            'Missing compile-time steady-clock assertion')
    epoch = re.search(r'SimpleSwitch::get_time_since_epoch_us\(\) const\s*\{([^}]+)\}', source)
    require(epoch and 'std::chrono::system_clock::now()' in epoch.group(1),
            'Wall-clock epoch API semantics changed')
    with paths['elf'].open('rb') as stream:
        require(stream.read(4) == b'\x7fELF', 'Actual .libs/simple_switch is not ELF')
    result = subprocess.run(['objdump', '-drC', '--no-show-raw-insn', str(paths['elf'])],
                            capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, f'Cannot inspect compiled clock calls: {result.stderr}')
    elapsed = function_body(result.stdout, 'SimpleSwitch::get_ts() const')
    epoch_body = function_body(result.stdout, 'SimpleSwitch::get_time_since_epoch_us() const')
    require('steady_clock::now()' in elapsed and 'system_clock::now()' not in elapsed,
            'Compiled get_ts() does not use the monotonic clock')
    require('system_clock::now()' in epoch_body, 'Compiled epoch API no longer uses wall time')
    return {'schema': 'bmv2-steady-clock-v1', 'elapsed_clock': 'std::chrono::steady_clock',
            'epoch_clock': 'std::chrono::system_clock', 'compiled_clock_verified': True,
            'switch': str(switch), 'artifacts': {name: {'path': str(path.resolve()),
                         'sha256': sha256_file(path)} for name, path in paths.items()},
            'compiled_functions': {'get_ts': elapsed, 'get_time_since_epoch_us': epoch_body}}


def verify_receipt(receipt_path, switch):
    """Fail before starting a child if executable/source differs from attested build."""
    receipt_path = Path(receipt_path).resolve()
    with receipt_path.open(encoding='utf-8') as stream:
        receipt = json.load(stream)
    require(receipt['schema'] == 'bmv2-steady-clock-v1' and receipt['compiled_clock_verified'] is True and
            receipt['elapsed_clock'] == 'std::chrono::steady_clock' and
            Path(receipt['switch']).resolve() == Path(switch).resolve(), 'Wrong clock-build receipt')
    switch = Path(switch).resolve()
    expected = {'wrapper': switch, 'elf': switch.parent / '.libs/simple_switch',
                'header': switch.parent / 'simple_switch.h', 'source': switch.parent / 'simple_switch.cpp'}
    require(set(receipt['artifacts']) == set(expected), 'Incomplete clock receipt')
    for name, artifact in receipt['artifacts'].items():
        path = Path(artifact['path'])
        require(not path.is_symlink() and path.resolve() == expected[name].resolve(),
                'Clock receipt artifact is not the actual local switch/source path')
        require(sha256_file(artifact['path']) == artifact['sha256'], 'Attested BMv2 binary/source changed')
    return dict(receipt, receipt_path=str(receipt_path), receipt_sha256=sha256_file(receipt_path))


def attest(switch, output_root):
    snapshot = inspect_build(switch)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    directory = root / timestamp
    directory.mkdir()
    snapshot['created_utc'] = timestamp
    snapshot['verification_source_sha256'] = sha256_file(__file__)
    path = directory / 'clock_receipt.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(snapshot, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print('CLOCK BUILD PASS — actual get_ts() uses steady_clock; epoch API remains system_clock.')
    print(f'Clock receipt: {path}')
    return path


def verify_clean_pilot(directory, receipt):
    """A full preparation requires a successful live pilot on this exact build."""
    directory = Path(directory).resolve()
    require(not (directory / 'failure.json').exists(), 'Pilot has a failure marker')
    with (directory / 'summary.json').open(encoding='utf-8') as stream:
        summary = json.load(stream)
    require(summary['status'] == 'native_pilot_passed' and summary['passed'] is True and
            summary.get('raw_clock_clean') is True and summary['native_clock'] is True and
            summary['cleanup_passed'] is True, 'Pilot did not pass parity AND raw-clock quality')
    for model in 'BC':
        current = summary['models'][model]
        quality = current.get('clock_quality') or {}
        require(current.get('parity_passed') is True and quality.get('clean') is True and
                quality.get('raw_backward_steps') == 0 and current['packets'] == 8 and
                current['decisions'] == 1, 'Pilot is missing clean eight-packet RF parity')
    required = {'provenance.json', 'interfaces.json'}
    required |= {f'RF_{model}/{name}.json' for model in 'BC'
                 for name in ('comparison', 'counter_query', 'transport')}
    require(isinstance(summary['output_sha256'], dict) and required <= set(summary['output_sha256']),
            'Pilot is missing sealed provenance, reports, transport or counters')
    for relative, expected in summary['output_sha256'].items():
        path = (directory / relative).resolve()
        require(path.is_relative_to(directory) and sha256_file(path) == expected, 'Pilot evidence changed')
    with (directory / 'provenance.json').open(encoding='utf-8') as stream:
        provenance = json.load(stream)
    actual = provenance['clock_source_receipt']
    require(actual['receipt_sha256'] == receipt['receipt_sha256'] and
            actual['artifacts'] == receipt['artifacts'], 'Pilot used a different clock build')
    return {'path': str(directory), 'summary_sha256': sha256_file(directory / 'summary.json'),
            'output_sha256': summary['output_sha256'], 'raw_clock_clean': True}


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--switch', type=Path,
                        default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--output-root', type=Path, default=repo / 'results/bmv2_clock_repair')
    parser.add_argument('--receipt', type=Path, help='Verify an existing receipt, without writing files')
    args = parser.parse_args(argv)
    try:
        if args.receipt:
            verify_receipt(args.receipt, args.switch)
            print('CLOCK RECEIPT PASS — source, wrapper and actual ELF hashes unchanged.')
        else:
            attest(args.switch, args.output_root)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
