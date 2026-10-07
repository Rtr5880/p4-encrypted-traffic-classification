#!/usr/bin/env python3
"""Attest the scoped queue-clock upgrade; do not reinterpret old native runs.

The v1 feature-clock verifier remains unchanged. This separate v2 receipt adds
the scheduler header and actual compiled PriRL enqueue/dequeue clock calls.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

import verify_bmv2_clock as feature_clock

require = feature_clock.require
sha256_file = feature_clock.sha256_file
SCHEMA = 'bmv2-feature-and-queue-steady-clock-v2'
OLD_RL = '''  // clock choice? switch to steady if observing re-ordering
  // using clock = std::chrono::steady_clock;
  using clock = std::chrono::high_resolution_clock;'''
NEW_RL = '''  // Queue deadlines measure elapsed time, not wall time. A host clock
  // correction must not postpone packets already assigned a send deadline.
  using clock = std::chrono::steady_clock;
  static_assert(clock::is_steady, "Rate-limited queue clock must be steady");'''
OLD_PRI = '''  // clock choice? switch to steady if observing re-ordering
  // in my Linux VM, it seems that both clocks behave the same (can sometimes
  // stop increasing for a bit but do not go backwards).
  // using clock = std::chrono::steady_clock;
  using clock = std::chrono::high_resolution_clock;'''
NEW_PRI = '''  // Priority-queue deadlines must also survive host wall-clock corrections.
  using clock = std::chrono::steady_clock;
  static_assert(clock::is_steady, "Priority rate-limited queue clock must be steady");'''


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def approved_upgrade(before, after):
    require(before.count(OLD_RL) == 1 and before.count(OLD_PRI) == 1,
            'Unexpected original scheduled-queue clock definitions')
    require(before.replace(OLD_RL, NEW_RL).replace(OLD_PRI, NEW_PRI) == after,
            'Queue header changed beyond the approved elapsed-clock upgrade')


def compiled_queue_functions(disassembly):
    functions = re.findall(r'^([0-9a-f]+) <([^\n]+)>:\n(.*?)(?=\n\n|\Z)', disassembly, re.M | re.S)
    result = {}
    for operation in ('push_front', 'pop_back'):
        candidates = [(name, body) for _, name, body in functions
                      if name.startswith('bm::QueueingLogicPriRL<std::unique_ptr<bm::Packet,')
                      and '>::' + operation + '(' in name]
        require(len(candidates) >= 1 and all('steady_clock::now()' in body for _, body in candidates),
                f'Compiled PriRL {operation} steady-clock call missing')
        require(all('system_clock::now()' not in body for _, body in candidates),
                f'Compiled PriRL {operation} still uses wall-clock deadlines')
        result[operation] = {'signature': candidates[0][0], 'disassembly': candidates[0][1]}
    return result


def inspect_queue_build(switch):
    snapshot = feature_clock.inspect_build(switch)
    queue = Path(switch).resolve().parents[2] / 'include/bm/bm_sim/queueing.h'
    require(queue.is_file() and not queue.is_symlink(), 'Queue header missing or symlinked')
    header = queue.read_text(encoding='utf-8')
    require(header.count('using clock = std::chrono::steady_clock;') == 2 and
            header.count('static_assert(clock::is_steady') == 2 and
            'using clock = std::chrono::high_resolution_clock;' not in header,
            'Both scheduled queue templates must use asserted steady clocks')
    result = subprocess.run(['objdump', '-drC', '--no-show-raw-insn', snapshot['artifacts']['elf']['path']],
                            capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, 'Cannot inspect compiled queue functions')
    snapshot['schema'] = SCHEMA
    snapshot['queue_clock'] = 'std::chrono::steady_clock'
    snapshot['compiled_queue_clock_verified'] = True
    snapshot['compiled_queue_functions'] = compiled_queue_functions(result.stdout)
    snapshot['artifacts']['queue_header'] = {'path': str(queue), 'sha256': sha256_file(queue)}
    return snapshot


def verify_receipt(path, switch):
    path = Path(path).resolve()
    receipt = read_json(path)
    require(receipt['schema'] == SCHEMA and receipt['compiled_clock_verified'] is True and
            receipt['compiled_queue_clock_verified'] is True and
            receipt['elapsed_clock'] == receipt['queue_clock'] == 'std::chrono::steady_clock',
            'Wrong feature/queue-clock receipt')
    switch = Path(switch).resolve()
    expected = {'wrapper': switch, 'elf': switch.parent / '.libs/simple_switch',
                'header': switch.parent / 'simple_switch.h', 'source': switch.parent / 'simple_switch.cpp',
                'queue_header': switch.parents[2] / 'include/bm/bm_sim/queueing.h'}
    require(Path(receipt['switch']).resolve() == switch and set(receipt['artifacts']) == set(expected),
            'Incomplete or different queue-clock build')
    for name, artifact in receipt['artifacts'].items():
        item = Path(artifact['path'])
        require(not item.is_symlink() and item.resolve() == expected[name].resolve() and
                sha256_file(item) == artifact['sha256'], 'Queue-clock source/binary changed')
    for item in receipt['upgrade_evidence'].values():
        require(sha256_file(item['path']) == item['sha256'], 'Queue-upgrade evidence changed')
    previous_path = receipt['upgrade_evidence']['previous_receipt']['path']
    previous = read_json(previous_path)
    require(previous == {key: value for key, value in receipt['previous_feature_clock_receipt'].items()
                         if key not in ('receipt_path', 'receipt_sha256')}, 'Previous receipt provenance changed')
    require(receipt['previous_feature_clock_receipt']['receipt_sha256'] == sha256_file(previous_path),
            'Previous receipt hash changed')
    for name in ('wrapper', 'header', 'source'):
        require(previous['artifacts'][name] == receipt['artifacts'][name],
                'Upgrade changed feature-clock source or wrapper')
    require(previous['artifacts']['elf']['sha256'] == receipt['upgrade_evidence']['previous_elf']['sha256'],
            'Prior executable backup does not match historical receipt')
    before = Path(receipt['upgrade_evidence']['previous_queue_header']['path']).read_text(encoding='utf-8')
    approved_upgrade(before, expected['queue_header'].read_text(encoding='utf-8'))
    feature_clock.verify_receipt(receipt['feature_clock_receipt']['path'], switch)
    require(sha256_file(receipt['feature_clock_receipt']['path']) == receipt['feature_clock_receipt']['sha256'],
            'Compatible feature-clock receipt changed')
    return dict(receipt, receipt_path=str(path), receipt_sha256=sha256_file(path))


def attest(args):
    snapshot = inspect_queue_build(args.switch)
    previous = read_json(args.previous_receipt)
    require(previous['schema'] == 'bmv2-steady-clock-v1' and previous['compiled_clock_verified'] is True,
            'Expected the previous verified feature-clock build')
    for name in ('header', 'source', 'wrapper'):
        require(previous['artifacts'][name] == snapshot['artifacts'][name],
                'Only queue header and executable may change')
    require(sha256_file(args.previous_elf) == previous['artifacts']['elf']['sha256'],
            'Original executable backup differs from prior receipt')
    approved_upgrade(args.previous_queue_header.read_text(encoding='utf-8'),
                     Path(snapshot['artifacts']['queue_header']['path']).read_text(encoding='utf-8'))
    tests = subprocess.run([str(args.queue_tests), snapshot['artifacts']['queue_header']['path']],
                           capture_output=True, text=True, timeout=10)
    require(tests.returncode == 0 and 'PASS all 14 bounded checks' in tests.stdout,
            'Real scheduled-queue regression tests failed: ' + tests.stdout + tests.stderr)
    root = args.output_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    directory = root / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    directory.mkdir()
    (directory / 'queue-tests.log').write_text(tests.stdout + tests.stderr, encoding='utf-8')
    compatibility = {key: value for key, value in snapshot.items()
                     if key not in ('queue_clock', 'compiled_queue_clock_verified', 'compiled_queue_functions')}
    compatibility['schema'] = 'bmv2-steady-clock-v1'
    compatibility['artifacts'] = {key: value for key, value in snapshot['artifacts'].items() if key != 'queue_header'}
    compatibility['created_utc'] = directory.name
    compatibility['verification_source_sha256'] = sha256_file(feature_clock.__file__)
    compatible_path = directory / 'feature_clock_receipt.json'
    compatible_path.write_text(json.dumps(compatibility, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    snapshot['feature_clock_receipt'] = {'path': str(compatible_path), 'sha256': sha256_file(compatible_path)}
    snapshot['previous_feature_clock_receipt'] = dict(previous,
        receipt_path=str(args.previous_receipt.resolve()), receipt_sha256=sha256_file(args.previous_receipt))
    evidence = {'previous_receipt': args.previous_receipt, 'previous_elf': args.previous_elf,
                'previous_queue_header': args.previous_queue_header,
                'queue_test_source': args.queue_test_source, 'queue_test_executable': args.queue_tests,
                'queue_test_log': directory / 'queue-tests.log', 'verifier_source': Path(__file__)}
    snapshot['upgrade_evidence'] = {name: {'path': str(item.resolve()), 'sha256': sha256_file(item)}
                                    for name, item in evidence.items()}
    snapshot['created_utc'] = directory.name
    snapshot['old_native_results_reinterpreted_as_new_binary'] = False
    path = directory / 'queue_clock_receipt.json'
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    verify_receipt(path, args.switch)
    print('QUEUE CLOCK BUILD PASS — compiled PriRL enqueue/dequeue and feature elapsed clocks are steady; epoch remains system clock.')
    print(f'Queue clock receipt: {path}')
    print(f'Compatible feature-clock receipt: {compatible_path}')
    return path


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--switch', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--previous-receipt', type=Path)
    parser.add_argument('--previous-elf', type=Path)
    parser.add_argument('--previous-queue-header', type=Path)
    parser.add_argument('--queue-tests', type=Path)
    parser.add_argument('--queue-test-source', type=Path)
    parser.add_argument('--output-root', type=Path, default=repo / 'results/bmv2_queue_clock_repair')
    args = parser.parse_args(argv)
    try:
        if args.receipt:
            verify_receipt(args.receipt, args.switch)
            print('QUEUE CLOCK RECEIPT PASS — attested source, executable and upgrade evidence unchanged.')
        else:
            require(all(getattr(args, name) for name in ('previous_receipt', 'previous_elf', 'previous_queue_header',
                                                       'queue_tests', 'queue_test_source')), 'Missing upgrade inputs')
            attest(args)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
