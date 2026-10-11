#!/usr/bin/env python3
"""Four normal-build modes, paired traffic blocks, and auditable load trials.

prepare and smoke are non-privileged. Only run creates private live veth links.
No fitting, model conversion, edits to frozen P4, or Git commands occur here.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shutil
import subprocess
import sys
import time
import uuid

import benchmark_transport as transport
import benchmark_workload as workload
import integrate_rf as integration
import native_prefix
import performance_resources as resources
import run_native_clock_pilot as ownership
import run_performance_pilot as pilot
import test_p4_features as helpers

require, write_json = helpers.require, helpers.write_json
SCHEMA = 'performance-benchmark-v1'
MODES = ('forwarding', 'features', 'rf_b', 'rf_c')
WORKLOADS = ('classification-heavy', 'cached-forwarding')
INITIAL_RATES = (100, 250, 500, 1000, 2000, 5000)
NORMAL = {'TEST_TIMESTAMPS': 0, 'DEBUG_REPORT': 0, 'FLOW_SLOTS': 65536}
FRAME_BYTES = 128
GATES = {'offered_rate_relative_tolerance': .02,
         'p99_send_lateness_floor_ns': 1_000_000,
         'maximum_send_lateness_floor_ns': 5_000_000,
         'short_gap_interval_fraction': .25,
         'maximum_short_input_gap_fraction': .01}
DISK_MIN_BYTES = 5 * 1024 ** 3
DISK_RESERVE_BYTES = 512 * 1024 ** 2
AVAILABLE_MIN_KIB = 1024 ** 2
RUNNER_RSS_LIMIT_MIB = 768


def hash_file(path):
    return native_prefix.sha256_file(Path(path))


def verify_seal(directory, mapping):
    directory = Path(directory).resolve()
    require(isinstance(mapping, dict) and mapping, 'Missing artifact seal')
    for name, expected in mapping.items():
        path = directory / name
        require(not path.is_symlink() and path.resolve().is_relative_to(directory)
                and path.is_file() and hash_file(path) == expected,
                f'Saved artifact changed or escaped its directory: {name}')


def plain_forwarding_source(source):
    """Keep the exact parser/deparser and eligibility preamble; remove state/RF.

    Eligibility does not drop these benchmark packets in any frozen mode.
    This is parser-matched plain forwarding, not an Ethernet-only fast path.
    Strict source anchors fail loudly if the frozen implementation changes.
    """
    start = source.index('control FeatureIngress(')
    apply_start = source.index('    apply {\n        meta.status = 0;', start)
    eligibility_end = source.index('        if (meta.eligible) {\n            meta.source_hi = 0;', apply_start)
    forwarding_start = source.index('#if DEBUG_REPORT\n        emit_report();', eligibility_end)
    tail_start = source.index('control FeatureEgress(', forwarding_start)
    forwarding = source[forwarding_start:tail_start]
    require(forwarding.count('emit_report();') == 1, 'Unexpected forwarding anchor')
    # DEBUG_REPORT=0 is an invariant; no synthetic reports exist in plain mode.
    forwarding = forwarding[forwarding.index('#else\n') + len('#else\n'):]
    forwarding = forwarding.replace('#endif\n', '', 1)
    preamble = source[apply_start:eligibility_end]
    return (source[:start] + '/* BENCHMARK BASELINE: no hash, state or classifier. */\n'
            'control FeatureIngress(inout headers_t hdr, inout metadata_t meta,\n'
            '                inout standard_metadata_t sm) {\n' + preamble + forwarding
            + source[tail_start:])


def validate_program(path, mode):
    data = integration.read_json(path)
    orders = [name for row in data['deparsers'] for name in row['order']]
    require(not any('report' in name for name in orders), 'Debug reporting must be disabled')
    registers = [row for row in data['register_arrays'] if row['name'] == 'FeatureIngress.flow_state']
    counters = [row for row in data['counter_arrays'] if row['name'] == 'FeatureIngress.rf_decisions']
    if mode == 'forwarding':
        require(not registers and not counters, 'Plain forwarding still has flow state/RF')
    else:
        require(len(registers) == 1 and registers[0]['size'] == 65536,
                'Stateful mode must use the same 65,536 slots')
        require((len(counters) == 1 and counters[0]['size'] == 6) if mode.startswith('rf_')
                else not counters, 'RF inference/counters do not match the mode')
    return {'debug_reports': False, 'deparser_order': orders,
            'stateful_features': mode != 'forwarding', 'rf_inference': mode.startswith('rf_'),
            'direction_extracted': mode != 'forwarding'}


def protocol_from_args(args):
    rates = list(args.rates)
    require(rates and len(set(rates)) == len(rates) and all(type(r) is int and 1 <= r <= 10000 for r in rates),
            'Rates must be distinct integers in [1,10000]')
    require(1 <= args.repetitions <= 20, 'Repetitions must be in [1,20]')
    require(math.isfinite(args.drain_seconds) and .05 <= args.drain_seconds <= 2,
            'Drain must be in [.05,2] seconds')
    require(not any(r > 5000 for r in rates) or args.extension_from is not None,
            'Rates above 5,000 require --extension-from a completed reliable initial run')
    return {'rates_pps': sorted(rates), 'workloads': list(WORKLOADS), 'modes': list(MODES),
            'duration_seconds': args.duration_seconds, 'warmup_seconds': args.warmup_seconds,
            'drain_seconds': args.drain_seconds, 'repetitions': args.repetitions, 'seed': args.seed,
            'frame_bytes': FRAME_BYTES, 'concurrency': 8, 'pacing_gates': dict(GATES),
            'clock_sample_seconds': .005, 'maximum_clock_sampling_gap_ns': 25_000_000,
            'maximum_clock_bracket_ns': 100_000, 'clock_offset_change_tolerance_ns': 1_000_000,
            'clock_bracket_backend': 'linux-native-three-read-v1' if getattr(args, 'clock_library', None) else 'python-three-read-v1',
            'sender_backend': 'linux-native-paced-send-v1' if getattr(args, 'sender_library', None) else 'python-paced-send-v1',
            'warmup_state_isolation': 'disjoint UDP keys AND disjoint CRC32 slots; fresh switch per trial',
            'direction_comparison': 'Both RF-B and RF-C extract all eight features; forest comparison only',
            'normal_definitions': dict(NORMAL), 'new_fits': 0, 'accuracy_scored': False}


def build_schedule(protocol, token):
    """Balance mode position by rotated randomized orders; randomize blocks.

    One block means one load/workload/repetition and byte-identical phase plans.
    Five repetitions have position counts differing by at most one per cell.
    """
    rng = random.Random(protocol['seed'])
    blocks = []
    for workload_index, name in enumerate(WORKLOADS):
        for rate in protocol['rates_pps']:
            order = list(MODES)
            rng.shuffle(order)
            for repetition in range(1, protocol['repetitions'] + 1):
                rotation = (repetition - 1) % len(MODES)
                block_id = f'{name}_{rate:05d}pps_r{repetition:02d}'
                blocks.append({'block_id': block_id, 'rate_pps': rate, 'workload': name,
                    'repetition': repetition, 'namespace': workload_index * 100 + repetition,
                    'run_id': token + ':' + block_id,
                    'modes': order[rotation:] + order[:rotation]})
    rng.shuffle(blocks)
    return blocks


def plans_for(block, protocol):
    return workload.build_phase_pair(block['rate_pps'], protocol['warmup_seconds'],
            protocol['duration_seconds'], block['workload'], block['run_id'],
            frame_bytes=protocol['frame_bytes'], namespace=block['namespace'])


def frame_hash(plan):
    digest = hashlib.sha256()
    for sequence in range(plan.packet_count):
        digest.update(plan.frame_for(sequence))
    return digest.hexdigest()


def validate_extension(run, protocol):
    import analyze_performance_benchmark as analysis
    summary, rows = analysis.load_run(run)
    decision = analysis.extension_eligibility(rows)
    require(decision['eligible'], 'Initial 5,000pps results do not satisfy controlled extension gates')
    old_protocol = summary['protocol']
    for key in ('duration_seconds', 'warmup_seconds', 'drain_seconds', 'frame_bytes', 'concurrency',
                'normal_definitions', 'pacing_gates', 'clock_sample_seconds',
                'maximum_clock_sampling_gap_ns', 'maximum_clock_bracket_ns', 'clock_offset_change_tolerance_ns',
                'clock_bracket_backend', 'sender_backend'):
        require(protocol[key] == old_protocol.get(key), f'Extension must preserve initial methodology: {key}')
    return {'run': str(Path(run).resolve()), 'summary_sha256': hash_file(Path(run) / 'summary.json'),
            'assessment': decision}


def native_reader(library):
    if library is None:
        return None
    from native_clock_bracket import NativeClockBracket
    return NativeClockBracket(library)


def native_sender(library):
    if library is None:
        return None
    from native_paced_sender import NativePacedSender
    return NativePacedSender(library)


def invalid_resource_report(message):
    return {'valid': False, 'cpu': {'valid': False, 'percent_one_core': None, 'seconds': None},
            'memory': {'valid': False, 'rss_max_sampled_mib': None, 'vmhwm_lifetime_mib': None},
            'errors': [message]}


def prepare(args, repo):
    protocol = protocol_from_args(args)
    clock_reader = native_reader(args.clock_library)
    paced_sender = native_sender(getattr(args, 'sender_library', None))
    blocks = build_schedule(protocol, uuid.uuid4().hex)
    # Validate every workload bound BEFORE building files, subprocesses or links.
    plan_rows = []
    for block in blocks:
        warm, measured = plans_for(block, protocol)
        plan_rows.append((block, warm, measured))
    old, _, receipt = pilot.load_prepared(args.pilot_prepared, args.switch)
    completed = integration.read_json(args.pilot_run / 'summary.json')
    require(completed['passed'] is True and completed['status'] == 'performance_pilot_passed',
            'A successful normal-build instrumentation pilot is required')
    verify_seal(args.pilot_run, completed['output_sha256'])
    provenance = integration.read_json(args.pilot_run / 'provenance.json')
    require(provenance['manifest_sha256'] == hash_file(args.pilot_prepared / 'manifest.json')
            and Path(provenance['prepared']).resolve() == args.pilot_prepared.resolve(),
            'Successful pilot and preparation are unrelated')
    extension = validate_extension(args.extension_from, protocol) if args.extension_from else None
    directory = ownership.new_directory(args.output_root or repo / 'results/performance_benchmark_preparation')
    try:
        feature_source = repo / 'p4/flow_features.p4'
        baseline = directory / 'benchmark_forwarding.p4'
        with baseline.open('x', encoding='utf-8') as stream:
            stream.write(plain_forwarding_source(feature_source.read_text(encoding='utf-8')))
        programs = {}
        for mode, source in (('forwarding', baseline), ('features', feature_source)):
            path = integration.compile_program(args.p4c, source, directory / (mode + '.json'),
                                                controlled=False, debug=False, slots=65536)
            programs[mode] = {'path': str(path), 'sha256': hash_file(path),
                              'validation': validate_program(path, mode)}
        # Reuse the exact sealed RF JSONs, not newly converted/trained forests.
        for mode, model in (('rf_b', 'B'), ('rf_c', 'C')):
            path = Path(old['programs'][model]['path'])
            programs[mode] = {'path': str(path), 'sha256': hash_file(path),
                              'validation': validate_program(path, mode)}
        if extension:
            initial = integration.read_json(Path(integration.read_json(args.extension_from / 'summary.json')['prepared_directory']) / 'manifest.json')
            verify_seal(Path(integration.read_json(args.extension_from / 'summary.json')['prepared_directory']), initial['artifact_hashes'])
            require(initial['clock_receipt_sha256'] == receipt['receipt_sha256'] and all(
                initial['programs'][mode]['sha256'] == programs[mode]['sha256'] for mode in ('features', 'rf_b', 'rf_c')),
                'Extension must use the same switch binary/clock receipt and four programs')
            # Derived baseline embeds its preparation's filename in source_info;
            # reuse the EXACT initial JSON, rather than comparing path metadata.
            original_plain = Path(initial['programs']['forwarding']['path'])
            require(hash_file(original_plain) == initial['programs']['forwarding']['sha256'], 'Initial forwarding baseline changed')
            programs['forwarding'] = dict(initial['programs']['forwarding'])
        for block, warm, measured in plan_rows:
            block['plan_file'] = 'plans/' + block['block_id'] + '.json'
            (directory / 'plans').mkdir(exist_ok=True)
            write_json(directory / block['plan_file'], {'warmup': warm.manifest(),
                'measurement': measured.manifest(), 'warmup_frames_sha256': frame_hash(warm),
                'measurement_frames_sha256': frame_hash(measured),
                'combined_allocated_slots': warm.flow_count + measured.flow_count,
                'warmup_measurement_slot_overlap': len(set(warm.slots) & set(measured.slots))})
        hashes = dict(old['input_sha256'])
        if clock_reader is not None:
            hashes.update(clock_reader.provenance['input_sha256'])
        if paced_sender is not None:
            hashes.update(paced_sender.provenance['input_sha256'])
        hashes.update({str(path.resolve()): hash_file(path) for path in (
            Path(__file__), Path(workload.__file__), Path(transport.__file__), Path(resources.__file__),
            repo / 'tools/analyze_performance_benchmark.py',
            args.pilot_prepared / 'manifest.json', args.pilot_run / 'summary.json', args.p4c)})
        for item in programs.values():
            hashes[item['path']] = item['sha256']
        manifest = {'schema_version': SCHEMA, 'status': 'prepared', 'protocol': protocol,
            'programs': programs, 'clock_receipt': old['clock_receipt'], 'input_sha256': hashes,
            'clock_library': str(args.clock_library.resolve()) if args.clock_library else None,
            'clock_reader_provenance': clock_reader.provenance if clock_reader is not None else None,
            'sender_library': str(args.sender_library.resolve()) if getattr(args, 'sender_library', None) else None,
            'sender_provenance': paced_sender.provenance if paced_sender is not None else None,
            'pilot_run': str(args.pilot_run.resolve()), 'pilot_prepared': str(args.pilot_prepared.resolve()),
            'schedule': blocks, 'extension': extension, 'expected_live_trials': len(blocks) * 4,
            'scheduled_traffic_seconds': len(blocks) * 4 * (protocol['warmup_seconds'] +
                   protocol['duration_seconds'] + protocol['drain_seconds'] * 2),
            'resource_limits': {'minimum_disk_bytes': DISK_MIN_BYTES,
                'disk_stop_reserve_bytes': DISK_RESERVE_BYTES,
                'minimum_available_memory_kib': AVAILABLE_MIN_KIB, 'runner_rss_limit_mib': RUNNER_RSS_LIMIT_MIB,
                'maximum_packets_warmup_plus_measurement': 500000, 'maximum_occupied_slots': 60000,
                'maximum_rate_pps': 10000, 'maximum_simultaneous_switches': 1},
            'new_fits': 0, 'clock_receipt_sha256': receipt['receipt_sha256']}
        manifest['artifact_hashes'] = pilot.seal(directory)
        write_json(directory / 'manifest.json', manifest)
    except BaseException as error:
        write_json(directory / 'failure.json', {'stage': 'prepare', 'error': str(error)})
        raise
    print(f'PREPARED: {len(blocks) * 4} trials; {manifest["scheduled_traffic_seconds"] / 60:.1f} scheduled minutes plus startup/evidence overhead.')
    print(f'Evidence saved to: {directory}')
    return directory


def load_prepared(directory, switch):
    directory = Path(directory).resolve()
    manifest = integration.read_json(directory / 'manifest.json')
    require(manifest['schema_version'] == SCHEMA and manifest['status'] == 'prepared'
            and not (directory / 'failure.json').exists() and manifest['new_fits'] == 0,
            'Wrong or failed benchmark preparation')
    verify_seal(directory, manifest['artifact_hashes'])
    ownership.verify_hashes(manifest['input_sha256'])
    receipt = pilot.verify_current_receipt(manifest['clock_receipt'], switch)
    require(receipt['receipt_sha256'] == manifest['clock_receipt_sha256'], 'Switch clock provenance changed')
    for mode, item in manifest['programs'].items():
        require(validate_program(item['path'], mode) == item['validation'], 'Normal program contract changed')
    require(set(manifest['programs']) == set(MODES), 'Four normal modes are required')
    reader = native_reader(manifest.get('clock_library'))
    require((reader.provenance if reader is not None else None) == manifest.get('clock_reader_provenance'),
            'Clock reader build/provenance changed')
    sender = native_sender(manifest.get('sender_library'))
    require((sender.provenance if sender is not None else None) == manifest.get('sender_provenance'),
            'Sender build/provenance changed')
    require(manifest['protocol'].get('sender_backend', 'python-paced-send-v1') ==
            ('linux-native-paced-send-v1' if sender is not None else 'python-paced-send-v1'),
            'Sender backend differs from the prepared protocol')
    return manifest, receipt


def cli_query(args, port, directory, query, filename):
    env = dict(os.environ)
    env['PYTHONPATH'] = str(args.switch.parents[2] / 'tools') + os.pathsep + env.get('PYTHONPATH', '')
    argv = [str(args.cli_python), str(args.cli), '--thrift-port', str(port)]
    result = subprocess.run(argv, input=query, capture_output=True, text=True, env=env, timeout=30)
    write_json(directory / filename, {'command': argv, 'input': query, 'returncode': result.returncode,
                                     'stdout': result.stdout, 'stderr': result.stderr})
    require(result.returncode == 0, 'Private counter/register query failed')
    return result.stdout


def read_counters(args, port, directory, filename):
    text = cli_query(args, port, directory, ''.join(
        f'counter_read FeatureIngress.rf_decisions {i}\n' for i in range(6)), filename)
    matches = re.findall(r'rf_decisions\[(\d+)\]=\s*\((\d+) bytes, (\d+) packets\)', text)
    require(len(matches) == 6 and {int(i) for i, _, _ in matches} == set(range(6)), 'Incomplete class counters')
    return [{'bytes': int(b), 'packets': int(p)} for _, b, p in sorted(matches, key=lambda v: int(v[0]))]


def counter_check(before, after, plan, mode):
    if not mode.startswith('rf_'):
        return {'passed': True, 'rf_inference_present': False, 'packets': None, 'bytes': None,
                'expected_packets': None, 'meaning': 'No classifier or RF decision counter in this mode'}
    delta = [{'bytes': a['bytes'] - b['bytes'], 'packets': a['packets'] - b['packets']}
             for b, a in zip(before, after)]
    packets, byte_count = sum(v['packets'] for v in delta), sum(v['bytes'] for v in delta)
    expected = plan.expected_classifications
    structurally_valid = all(v['bytes'] >= 0 and v['packets'] >= 0
        and v['bytes'] == v['packets'] * plan.frame_bytes for v in delta) and packets <= expected
    return {'passed': packets == expected and byte_count == expected * plan.frame_bytes
            and structurally_valid, 'structurally_valid': structurally_valid,
            'rf_inference_present': True, 'class_counter_deltas': delta, 'before': before, 'after': after,
            'packets': packets, 'bytes': byte_count, 'expected_packets': expected,
            'expected_bytes': expected * plan.frame_bytes,
            'meaning': 'Counter delta after disjoint warm-up: packet-eight inference events, not accuracy'}


def phase_counter_check(before, after, plan, mode, observation):
    check = counter_check(before, after, plan, mode)
    if not mode.startswith('rf_'):
        check['capacity_accounting_passed'] = True
        return check
    delivered_per_flow = {}
    for sequence, occurrences in enumerate(observation['per_packet']['output_occurrences']):
        if occurrences:
            flow_id = plan.flow_id_for(sequence)
            delivered_per_flow[flow_id] = delivered_per_flow.get(flow_id, 0) + 1
    minimum_proven = sum(count >= 8 for count in delivered_per_flow.values())
    deficit = check['expected_packets'] - check['packets']
    check.update({'minimum_proven_decisions': minimum_proven,
        'decision_deficit': deficit,
        'capacity_accounting_passed': check['structurally_valid'] and check['packets'] >= minimum_proven
            and (bool(observation['missing_output_sequences']) or deficit == 0),
        'capacity_accounting_meaning': 'Each distinct flow with at least eight exact output frames proves one inference event; '
            'deficits are permitted only with observed output loss and within this lower bound'})
    return check


def switch_argv(args, program, port, first, second, file_mode=False):
    prefix = [str(args.switch)] + (['--use-files', '1'] if file_mode else [])
    return prefix + ['-i', f'1@{first}', '-i', f'2@{second}', '--thrift-port', str(port),
        '--device-id', str(100000 + uuid.uuid4().int % 100000000),
        '--notifications-addr', 'ipc://notifications.ipc', '--log-console', '-L', 'warn', str(program)]


def compare_feature_reports(plans, reports):
    """Independent prefix arithmetic using the debug build's observed clock.

    Thrift's register read is i64 and cannot expose a 429-bit packed value.
    This auxiliary debug check never supplies a benchmark performance result.
    """
    require(len(reports) == sum(plan.packet_count for plan in plans), 'Incomplete feature reports')
    states, position = {}, 0
    for plan in plans:
        for sequence in range(plan.packet_count):
            row = reports[position]
            position += 1
            flow, ordinal = plan.flow_for(sequence), plan.packet_in_flow(sequence)
            slot = flow.slot
            state = states.setdefault(slot, {'last': None, 'gaps': [], 'count': 0})
            observed = row['observed_us']
            effective = max(observed, state['last']) if state['last'] is not None else observed
            if state['count'] < 8:
                if state['last'] is not None:
                    state['gaps'].append(effective - state['last'])
                state['count'] += 1
            state['last'] = effective
            count, gaps = state['count'], state['gaps']
            expected = {'slot': slot, 'count': min(ordinal, 8), 'status': 2 if ordinal == 8 else 1,
                'reason': 0, 'reverse_count': count // 2, 'direction_changes': max(0, count - 1),
                'size_min': plan.frame_bytes - 14, 'size_max': plan.frame_bytes - 14,
                'size_sum': (plan.frame_bytes - 14) * count,
                'iat_min': min(gaps) if gaps else 0, 'iat_max': max(gaps) if gaps else 0,
                'iat_sum': sum(gaps)}
            require(all(row[key] == value for key, value in expected.items()),
                    f'Auxiliary feature mismatch: phase={plan.phase}, sequence={sequence}, expected={expected}, observed={row}')
    return {'passed': True, 'reports': len(reports), 'distinct_slots': len(states),
        'decisions': sum(row['status'] == 2 for row in reports),
        'expected_decisions': sum(plan.expected_classifications for plan in plans),
        'eight_feature_values_verified': True,
        'meaning': 'Auxiliary DEBUG_REPORT=1 correctness only; NOT a normal-build performance trial'}


def feature_audit_smoke(args, repo, directory):
    program = integration.compile_program(repo.parent / 'p4c-build/p4c', repo / 'p4/flow_features.p4',
                                         directory / 'auxiliary_features.json', controlled=False, debug=True, slots=65536)
    results = {}
    for name in WORKLOADS:
        plans = workload.build_phase_pair(64, 1, 4, name, 'nonprivileged-smoke:' + name)
        frames = [p.frame_for(i) for p in plans for i in range(p.packet_count)]
        trial = directory / ('auxiliary_debug_' + name)
        trial.mkdir()
        helpers.write_pcap(trial / 'input_in.pcap', frames)
        helpers.write_pcap(trial / 'output_in.pcap', [])
        port = helpers.free_port()
        argv = switch_argv(args, program, port, 'input', 'output', True)
        write_json(trial / 'command.json', argv)
        with (trial / 'switch.log').open('x') as log:
            child = subprocess.Popen(argv, cwd=trial, stdout=log, stderr=subprocess.STDOUT)
            try:
                pilot.wait_ready(child, port)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    require(child.poll() is None, 'Auxiliary feature child exited')
                    output = helpers.read_pcap(trial / 'output_out.pcap', partial=True)
                    if len(output) == len(frames):
                        time.sleep(.2)
                        break
                    time.sleep(.03)
                else:
                    raise ValueError('Auxiliary feature packet-file test timed out')
            finally:
                ownership.stop_child(child)
        reports = [helpers.decode_report(frame) for frame in helpers.read_pcap(trial / 'output_out.pcap')]
        write_json(trial / 'reports.json', reports)
        results[name] = compare_feature_reports(plans, reports)
        write_json(trial / 'comparison.json', results[name])
        print(f'AUXILIARY DEBUG CHECK {name}: all eight features / slots / packet-eight events PASS')
    return results


def smoke(args, repo):
    manifest, receipt = load_prepared(args.prepared, args.switch)
    directory = ownership.new_directory(args.output_root or repo / 'results/performance_benchmark_checks')
    results = {}
    try:
        for name in WORKLOADS:
            warm, measured = workload.build_phase_pair(64, 1, 4, name, 'nonprivileged-smoke:' + name)
            frames = [p.frame_for(seq) for p in (warm, measured) for seq in range(p.packet_count)]
            for mode in MODES:
                trial = directory / (name + '_' + mode)
                trial.mkdir()
                helpers.write_pcap(trial / 'input_in.pcap', frames)
                helpers.write_pcap(trial / 'output_in.pcap', [])
                port = helpers.free_port()
                argv = switch_argv(args, manifest['programs'][mode]['path'], port, 'input', 'output', True)
                write_json(trial / 'command.json', argv)
                with (trial / 'switch.log').open('x') as log:
                    child = subprocess.Popen(argv, cwd=trial, stdout=log, stderr=subprocess.STDOUT)
                    try:
                        pilot.wait_ready(child, port)
                        deadline = time.monotonic() + 30
                        while time.monotonic() < deadline:
                            require(child.poll() is None, 'Private smoke child exited')
                            received = helpers.read_pcap(trial / 'output_out.pcap', partial=True)
                            if len(received) == len(frames):
                                time.sleep(.2)
                                break
                            require(len(received) <= len(frames), 'Extra smoke frames')
                            time.sleep(.03)
                        else:
                            raise ValueError('Packet-file smoke timed out')
                        counters = read_counters(args, port, trial, 'counter_query.json') if mode.startswith('rf_') else None
                    finally:
                        ownership.stop_child(child)
                require(helpers.read_pcap(trial / 'output_out.pcap') == frames, 'Smoke changed bytes/order')
                expected = warm.expected_classifications + measured.expected_classifications
                require(counters is None or (sum(c['packets'] for c in counters) == expected
                    and sum(c['bytes'] for c in counters) == expected * FRAME_BYTES), 'Smoke RF decisions mismatch')
                results[name + '_' + mode] = {'passed': True, 'packets': len(frames),
                    'unchanged_forwarded': len(frames), 'decisions': sum(c['packets'] for c in counters) if counters else None,
                    'expected_decisions': expected if counters else None,
                    'packed_register_cli_verified': False,
                    'warmup_measurement_slot_overlap': len(set(warm.slots) & set(measured.slots))}
                print(f'NORMAL SMOKE {name}, {mode}: {len(frames)}/{len(frames)} unchanged; RF counters PASS/applicable only')
        auxiliary = feature_audit_smoke(args, repo, directory)
        ownership.verify_hashes(manifest['input_sha256'])
        summary = {'schema_version': SCHEMA, 'status': 'packet_file_smoke_passed', 'passed': True,
            'paced': False, 'performance_measured': False, 'results': results,
            'auxiliary_debug_feature_checks': auxiliary,
            'prepared_manifest_sha256': hash_file(args.prepared / 'manifest.json'),
            'clock_receipt_sha256': receipt['receipt_sha256'], 'artifact_hashes': pilot.seal(directory)}
        write_json(directory / 'summary.json', summary)
    except BaseException as error:
        write_json(directory / 'failure.json', {'stage': 'smoke', 'error': str(error)})
        raise
    print(f'NON-PRIVILEGED SMOKE PASS — correctness only. Evidence saved to: {directory}')
    return directory


class MeasurementResources:
    """Boundary callbacks exclude socket setup, warm-up, drain and CLI work."""
    def __init__(self, switch_pid):
        self.monitors = {'bmv2': resources.ResourceSampler(switch_pid),
                         'runner': resources.ResourceSampler(os.getpid())}
        self.started = False
        self.stopped = False
        self.entered = []
        self.errors = []

    def start(self):
        self.started = True
        self.cpu_start = time.process_time()
        self.wall_start = time.monotonic()
        try:
            for key, monitor in self.monitors.items():
                monitor.__enter__()
                self.entered.append(key)
        except BaseException as error:
            self.errors.append(f'Resource sampler start failed: {error}')
            self.stop()
            raise

    def stop(self):
        if not self.started or self.stopped:
            return
        self.cpu_end, self.wall_end = time.process_time(), time.monotonic()
        for key in self.entered:
            try:
                self.monitors[key].__exit__(None, None, None)
            except BaseException as error:
                self.errors.append(f'{key} resource sampler stop failed: {error}')
        self.stopped = True

    def report(self):
        require(self.started and self.stopped, 'Resource window did not complete')
        result = {}
        for key, monitor in self.monitors.items():
            try:
                result[key] = monitor.summary() if key in self.entered else invalid_resource_report('Sampler did not enter')
            except (ValueError, RuntimeError, OSError) as error:
                result[key] = invalid_resource_report(str(error))
        if self.errors:
            for value in result.values():
                value['valid'] = False
                value.setdefault('errors', []).extend(self.errors)
        result.update({'runner_process_time_seconds': self.cpu_end - self.cpu_start,
            'callback_wall_seconds': self.wall_end - self.wall_start,
            'window_meaning': 'Callbacks bracket sending only, excluding warm-up, socket setup, drain and CLI; sampler entry/end snapshot offsets retained',
            'rss_limit_mib': RUNNER_RSS_LIMIT_MIB})
        return result


def flatten_metrics(measurement, resource, counters, plan):
    through = measurement['throughput']
    duration = through['actual_sender_window_seconds']
    output = measurement['captured_output_unique']
    latency = measurement['latency']['summary_us'] or {}
    cpu, mem = resource['bmv2']['cpu'], resource['bmv2']['memory']
    runner_cpu = resource['runner']['cpu']
    metrics = {'offered_pps': through['actual_offered_pps_over_window'],
        'received_pps': output / duration if duration and duration > 0 else None,
        'output_kernel_interarrival_pps': through['observed_output_kernel_interarrival_pps'],
        'ethernet_mbps': output * plan.frame_bytes * 8 / duration / 1e6 if duration and duration > 0 else None,
        'loss_fraction': measurement['observed_loss_fraction_after_drain'],
        'packets_sent': measurement['sent_packets'], 'packets_received': output,
        'packets_lost': len(measurement['missing_output_sequences']),
        'packets_duplicated': measurement['capture_counters']['output']['duplicates'],
        'packets_reordered': measurement['capture_counters']['output']['sequence_regressions'],
        'bmv2_cpu_one_core_percent': cpu['percent_one_core'] if cpu['valid'] else None,
        'bmv2_cpu_seconds': cpu['seconds'] if cpu['valid'] else None,
        'bmv2_rss_peak_mib': mem['rss_max_sampled_mib'] if mem['valid'] else None,
        'bmv2_hwm_mib': mem['vmhwm_lifetime_mib'] if mem['valid'] else None,
        'runner_cpu_one_core_percent': runner_cpu['percent_one_core'] if runner_cpu['valid'] else None,
        'runner_cpu_seconds': runner_cpu['seconds'] if runner_cpu['valid'] else None,
        'decisions': counters['packets'],
        'decision_rate_pps': counters['packets'] / duration if counters['packets'] is not None and duration else None,
        'pacing_valid': measurement['pacing_quality']['valid'],
        'clock_valid': measurement['latency']['clock_audit']['valid']}
    for output_name, input_name in [('min', 'minimum'), ('mean', 'mean'), ('median', 'median'),
                                   ('p95', 'p95'), ('p99', 'p99'), ('max', 'maximum')]:
        metrics['delay_' + output_name + '_us'] = latency.get(input_name)
    return metrics


def run_trial(args, program, mode, block, warm, measured, links, directory):
    directory.mkdir()
    warm_frames = [warm.frame_for(i) for i in range(warm.packet_count)]
    measured_frames = [measured.frame_for(i) for i in range(measured.packet_count)]
    helpers.write_pcap(directory / 'measurement_input.pcap', measured_frames)
    port = helpers.free_port()
    argv = switch_argv(args, program, port, links.names[0], links.names[2])
    write_json(directory / 'switch_command.json', argv)
    write_json(directory / 'provenance.json', {'mode': mode, 'block': block, 'switch_wrapper_sha256': hash_file(args.switch),
        'program_sha256': hash_file(program), 'topology': list(links.names), 'warmup': warm.manifest(),
        'measurement': measured.manifest(), 'warmup_frames_sha256': frame_hash(warm),
        'measurement_frames_sha256': frame_hash(measured), 'normal_definitions': NORMAL,
        'physical_direction': 'all frames host1 -> switch port1 -> port2 -> host2; logical endpoint direction alternates',
        'host_before_trial': host_snapshot()})
    with (directory / 'switch.log').open('x') as log:
        child = subprocess.Popen(argv, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        monitor = None
        try:
            monitor = MeasurementResources(child.pid)
            pilot.wait_ready(child, port)
            if warm_frames:
                warming = transport.run_phase(warm_frames, links.names[1], links.names[3], block['rate_pps'],
                    sequence_from_frame=warm.sequence_from_frame, drain_seconds=args.drain_seconds, gates=GATES,
                    clock_reader=getattr(args, 'clock_reader', None),
                    paced_sender=getattr(args, 'paced_sender', None))
                write_json(directory / 'warmup_measurement.json', warming)
            else:
                warming = None
            zero = [{'bytes': 0, 'packets': 0} for _ in range(6)]
            before = read_counters(args, port, directory, 'counter_before.json') if mode.startswith('rf_') else None
            warm_counts = phase_counter_check(zero, before, warm, mode, warming) if warming else counter_check(zero, before, warm, mode)
            write_json(directory / 'warmup_counter_check.json', warm_counts)
            measurement = transport.run_phase(measured_frames, links.names[1], links.names[3], block['rate_pps'],
                sequence_from_frame=measured.sequence_from_frame, drain_seconds=args.drain_seconds,
                gates=GATES, on_window_start=monitor.start, on_window_end=monitor.stop,
                clock_reader=getattr(args, 'clock_reader', None),
                paced_sender=getattr(args, 'paced_sender', None))
            write_json(directory / 'measurement.json', measurement)
            after = read_counters(args, port, directory, 'counter_after.json') if mode.startswith('rf_') else None
            counts = phase_counter_check(before, after, measured, mode, measurement)
        except transport.PhaseCallbackError as error:
            write_json(directory / 'partial_measurement.json', error.partial_report)
            raise
        finally:
            try:
                if monitor is not None:
                    monitor.stop()
            finally:
                ownership.stop_child(child)
    if monitor is not None and monitor.started and monitor.stopped:
        resource_report = monitor.report()
    else:
        # Socket/setup failures must retain raw invalid evidence, not fabricate
        # zero CPU/memory measurements or fail while comparing a missing RSS.
        invalid = invalid_resource_report('Measured resource window never started')
        resource_report = {'bmv2': invalid, 'runner': invalid}
    write_json(directory / 'resources.json', resource_report)
    write_json(directory / 'counter_check.json', counts)
    write_json(directory / 'packet_position_latency.json', pilot.phase_latency(measurement, measured))
    failures = list(measurement.get('capacity_quality_reasons', measurement['packet_delivery_reasons']))
    if not measurement['pacing_quality']['valid']:
        failures += ['Sender pacing quality gate failed']
    if not measurement['latency']['clock_audit']['valid']:
        failures += ['Clock audit quality gate failed']
    if not all(resource_report[key]['valid'] for key in ('bmv2', 'runner')):
        failures += ['Resource sampling failed']
    if not warm_counts.get('capacity_accounting_passed', warm_counts['passed']) or (warming
            and not warming['capacity_quality_valid']):
        failures += ['Warm-up measurement quality/decision accounting failed']
    # Lost outputs can reduce packet-eight triggers: report this consequence, not
    # a new classifier error. With no observed output loss, counts must be exact.
    if not counts['capacity_accounting_passed']:
        failures += ['RF counter delta violates byte/delta/packet-delivery bounds']
    runner_rss = resource_report['runner']['memory']['rss_max_sampled_mib']
    rss_exceeded = runner_rss is not None and runner_rss > RUNNER_RSS_LIMIT_MIB
    if rss_exceeded:
        failures += ['Runner exceeded the declared RSS budget']
    row = {'mode': mode, 'workload': block['workload'], 'rate_pps': block['rate_pps'],
        'repetition': block['repetition'], 'block_id': block['block_id'],
        'valid': not failures and measurement.get('capacity_quality_valid', measurement['packet_delivery_valid']),
        'failures': failures, 'metrics': flatten_metrics(measurement, resource_report, counts, measured),
        'measurement_file': 'measurement.json', 'resource_file': 'resources.json',
        'counters_file': 'counter_check.json', 'normal_build': True, 'debug_reports': False,
        'accuracy_scored': False, 'rss_budget_exceeded': rss_exceeded}
    write_json(directory / 'trial_summary.json', row)
    return row


def resource_preflight(repo, initial=True):
    free = shutil.disk_usage(repo).free
    floor = DISK_MIN_BYTES if initial else DISK_RESERVE_BYTES
    match = re.search(r'^MemAvailable:\s*(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)
    require(match and int(match.group(1)) >= AVAILABLE_MIN_KIB, 'Need at least 1GiB available WSL memory')
    require(free >= floor, 'Insufficient Linux result storage: need 5GiB before starting; retain 512MiB during execution')
    # The WSL filesystem is sparse. Its virtual free space is not host C: space.
    host_free = shutil.disk_usage('/mnt/c').free if Path('/mnt/c').is_dir() else None
    require(host_free is None or host_free >= floor, 'Insufficient physical C: space: need 5GiB before starting; retain 512MiB during execution')
    return {'linux_free_bytes': free, 'host_c_free_bytes': host_free, 'mem_available_kib': int(match.group(1))}


@contextmanager
def exclusive_run(repo):
    import fcntl
    path = repo / 'results/.performance-benchmark.lock'
    path.parent.mkdir(exist_ok=True)
    with path.open('a') as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another full performance benchmark owns the run lock; do not start a second copy')
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def host_snapshot():
    frequencies = {}
    for path in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/*'):
        if path.name in ('scaling_cur_freq', 'scaling_governor'):
            try:
                frequencies[str(path)] = path.read_text().strip()
            except OSError:
                frequencies[str(path)] = None
    return {'platform': platform.platform(), 'python': sys.version, 'cpu_count': os.cpu_count(),
            'runner_affinity': sorted(os.sched_getaffinity(0)), 'loadavg': list(os.getloadavg()),
            'proc_cpuinfo': Path('/proc/cpuinfo').read_text(), 'proc_meminfo': Path('/proc/meminfo').read_text(),
            'proc_version': Path('/proc/version').read_text(), 'frequency_observations': frequencies}


def run(args, repo):
    require(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Live benchmark requires your manual sudo launch')
    manifest, receipt = load_prepared(args.prepared, args.switch)
    args.clock_reader = native_reader(manifest.get('clock_library'))
    args.paced_sender = native_sender(manifest.get('sender_library'))
    args.drain_seconds = manifest['protocol']['drain_seconds']
    prerequisite = integration.read_json(args.smoke_run / 'summary.json')
    require(prerequisite['passed'] is True and prerequisite['status'] == 'packet_file_smoke_passed'
            and prerequisite['prepared_manifest_sha256'] == hash_file(args.prepared / 'manifest.json')
            and prerequisite['clock_receipt_sha256'] == receipt['receipt_sha256'], 'Missing bound four-mode smoke')
    verify_seal(args.smoke_run, prerequisite['artifact_hashes'])
    with exclusive_run(repo):
        limits = resource_preflight(repo)
        directory = ownership.new_directory(args.output_root or repo / 'results/performance_benchmark')
        results = []
        trials = []
        links = ownership.OwnedLinks(uuid.uuid4().hex[:6])
        write_json(directory / 'provenance.json', {'prepared_directory': str(args.prepared.resolve()),
            'prepared_manifest_sha256': hash_file(args.prepared / 'manifest.json'), 'clock_receipt': receipt,
            'smoke_run': str(args.smoke_run.resolve()), 'smoke_summary_sha256': hash_file(args.smoke_run / 'summary.json'),
            'initial_resources': limits, 'host_before': host_snapshot(), 'switch_log_level': 'warn'})
        try:
            with links:
                for block in manifest['schedule']:
                    warm, measured = plans_for(block, manifest['protocol'])
                    planned = integration.read_json(args.prepared / block['plan_file'])
                    require(warm.manifest() == planned['warmup'] and measured.manifest() == planned['measurement']
                            and frame_hash(warm) == planned['warmup_frames_sha256']
                            and frame_hash(measured) == planned['measurement_frames_sha256'], 'Paired traffic plan changed')
                    for mode in block['modes']:
                        resource_preflight(repo, initial=False)
                        relative = f'trial_{len(trials) + 1:03d}_{block["block_id"]}_{mode}'
                        print(f'Starting {len(trials)+1}/{manifest["expected_live_trials"]}: {mode}, {block["workload"]}, '
                              f'{block["rate_pps"]}pps; {manifest["protocol"]["warmup_seconds"]}s warm-up + '
                              f'{manifest["protocol"]["duration_seconds"]}s measurement.', flush=True)
                        row = run_trial(args, manifest['programs'][mode]['path'], mode, block,
                                        warm, measured, links, directory / relative)
                        trials.append(relative)
                        results.append(row)
                        print(f'  {row["metrics"]["packets_received"]}/{measured.packet_count} output; '
                              f'quality {"VALID" if row["valid"] else "INVALID"}; decisions={row["metrics"]["decisions"]}', flush=True)
                        require(not row['rss_budget_exceeded'], 'RSS budget exceeded; remaining trials aborted safely')
            require(not links.cleanup_errors, 'Owned topology cleanup reported errors')
            ownership.verify_hashes(manifest['input_sha256'])
            write_json(directory / 'host_after.json', host_snapshot())
            passed = all(row['valid'] for row in results)
            summary = {'schema_version': SCHEMA, 'status': 'benchmark_completed' if passed else 'benchmark_completed_with_invalid_trials',
                'prepared_directory': str(args.prepared.resolve()), 'protocol': manifest['protocol'],
                'trials': trials, 'attempted_trials': len(trials), 'valid_trials': sum(row['valid'] for row in results),
                'expected_trials': manifest['expected_live_trials'], 'cleanup_passed': True,
                'frozen_inputs_unchanged': True, 'accuracy_scored': False,
                'artifact_hashes': pilot.seal(directory)}
            write_json(directory / 'summary.json', summary)
        except BaseException as error:
            write_json(directory / 'failure.json', {'stage': 'run', 'error': str(error), 'completed_trials': trials,
                        'cleanup_errors': links.cleanup_errors})
            raise
    print(f'BENCHMARK SAVED — {summary["valid_trials"]}/{len(trials)} instrument-valid trials. Evidence: {directory}')
    print('Analyze this new evidence separately; invalid pacing/capture trials are not switch saturation claims.')
    return directory


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--switch', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--cli-python', type=Path, default=repo.parent / 'bmv2-venv/bin/python')
    parser.add_argument('--cli', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch_CLI')
    sub = parser.add_subparsers(dest='action', required=True)
    preparation = sub.add_parser('prepare')
    preparation.add_argument('--pilot-prepared', type=Path, default=repo / 'results/performance_pilot_preparation/20261007T215620Z_15a395a793')
    preparation.add_argument('--pilot-run', type=Path, default=repo / 'results/performance_pilot/20261007T220226Z_736832be56')
    preparation.add_argument('--p4c', type=Path, default=repo.parent / 'p4c-build/p4c')
    preparation.add_argument('--clock-library', type=Path, help='Sealed native three-read clock bracket library; all timing gates remain unchanged')
    preparation.add_argument('--sender-library', type=Path, help='Sealed native paced sender; original bytes/deadlines and all quality gates remain unchanged')
    preparation.add_argument('--rates', type=int, nargs='+', default=list(INITIAL_RATES))
    preparation.add_argument('--warmup-seconds', type=float, default=5)
    preparation.add_argument('--duration-seconds', type=float, default=20)
    preparation.add_argument('--drain-seconds', type=float, default=2)
    preparation.add_argument('--repetitions', type=int, default=5)
    preparation.add_argument('--seed', type=int, default=4022)
    preparation.add_argument('--extension-from', type=Path)
    preparation.add_argument('--output-root', type=Path)
    for name in ('smoke', 'run'):
        child = sub.add_parser(name)
        child.add_argument('--prepared', type=Path, required=True)
        child.add_argument('--output-root', type=Path)
        if name == 'run':
            child.add_argument('--smoke-run', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        {'prepare': prepare, 'smoke': smoke, 'run': run}[args.action](args, repo)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'BENCHMARK STOPPED: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
