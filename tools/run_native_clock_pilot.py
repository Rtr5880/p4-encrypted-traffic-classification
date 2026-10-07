#!/usr/bin/env python3
"""One real held-out N8 prefix, actual BMv2 ingress time, independent RF parity.

prepare: read frozen inputs and compile separate native debug builds (no root).
run: own temporary veths/private switches, eight packets/model, bounded cleanup.
This is correctness evidence, NOT accuracy, throughput or latency benchmarking.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid

import integrate_rf as integration
import native_prefix as prefix
import native_pilot_transport as transport
import prepare_rf_deployment as reference
import replay_real_pcaps as replay
import test_p4_features as helpers
import analyze_native_evaluation as native_analysis
import verify_bmv2_clock as clock_contract

require = helpers.require
write_json = helpers.write_json
DEPLOYMENT_RUN = '20260929T221518Z_a61fc37702'
BODY_OFFSET = 137  # Ethernet14 + feature71 + RF52; original IP begins here.


def new_directory(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    directory = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:10])
    directory.mkdir()
    return directory


def verify_hashes(hashes):
    for name, expected in hashes.items():
        path = Path(name)
        require(path.is_file() and prefix.sha256_file(path) == expected, f'Input changed/missing: {path}')


def predict(export, features):
    vector = [features[name] for name in export['feature_order']]
    leaves, _, scores = reference.predict_export(export, [vector])
    index = int(scores[0].argmax())
    return {'leaves': leaves[0].tolist(), 'scores': scores[0].tolist(),
            'prediction': index, 'class': export['classes'][index]}


def prepare(args, repo):
    require(math.isfinite(args.max_duration_seconds) and 0 < args.max_duration_seconds <= 2,
            'This bounded pilot supports at most a two-second prefix')
    switch = repo.parent / 'behavioral-model/targets/simple_switch/simple_switch'
    receipt = clock_contract.verify_receipt(args.clock_receipt, switch)
    bundle = prefix.prepare_prefix(repo, args.capture, args.max_duration_seconds)
    deployment = repo / 'results/rf_deployment' / DEPLOYMENT_RUN
    exports, _, _ = integration.load_deployment(deployment)
    source_paths = [Path(__file__), Path(prefix.__file__), Path(transport.__file__),
                    Path(integration.__file__), Path(reference.__file__), Path(replay.__file__),
                    Path(helpers.__file__), Path(replay.pilot.__file__), Path(replay.instances.__file__),
                    Path(replay.capture_io.__file__), repo / 'p4/flow_features.p4', repo / 'p4/rf-models.json',
                    repo / 'p4/rf_b.p4', repo / 'p4/rf_c.p4', deployment / 'summary.json',
                    Path(native_analysis.__file__), Path(clock_contract.__file__), args.clock_receipt]
    source_paths += [Path(item['path']) for item in receipt['artifacts'].values()]
    sealed = integration.read_json(deployment / 'summary.json')['output_sha256']
    source_paths += [deployment / name for name in sealed]
    bundle['input_sha256'].update({str(p.resolve()): prefix.sha256_file(p) for p in source_paths})
    bundle['original_predictions'] = {s: predict(exports[s], bundle['features_' + s]) for s in 'BC'}
    bundle['deployment'] = str(deployment)
    directory = new_directory(args.output_root or repo / 'results/native_clock_pilot_preparation')
    try:
        write_json(directory / 'prefix.json', bundle)
        programs = {}
        for s in 'BC':
            program = integration.compile_program(args.p4c, repo / f'p4/rf_{s.lower()}.p4',
                          directory / f'rf_{s.lower()}.json', controlled=False, debug=True)
            programs[s] = {'path': str(program), 'sha256': prefix.sha256_file(program)}
        write_json(directory / 'manifest.json', {'status': 'prepared', 'schema_version': 2,
                   'clock_source_receipt': str(args.clock_receipt.resolve()),
                   'clock_source_receipt_sha256': receipt['receipt_sha256'],
                   'prefix_sha256': prefix.sha256_file(directory / 'prefix.json'), 'programs': programs,
                   'p4c': str(args.p4c), 'p4c_sha256': prefix.sha256_file(args.p4c),
                   'compile_definitions': {'TEST_TIMESTAMPS': 0, 'DEBUG_REPORT': 1, 'FLOW_SLOTS': 65536}})
        verify_hashes(bundle['input_sha256'])
    except BaseException as error:
        write_json(directory / 'failure.json', {'error': str(error), 'stage': 'prepare'})
        raise
    print(f"Prepared one held-out prefix: {bundle['record']['record_id']}")
    print(f"Original frames: {[p['original_frame'] for p in bundle['packets']]}")
    print(f"Scheduled duration: {bundle['relative_us'][-1]} microseconds (no scaling)")
    print(f'PREPARATION PASS — no interfaces used, no training. Evidence saved to: {directory}')
    return directory


def load_prepared(directory):
    directory = Path(directory).resolve()
    require(not (directory / 'failure.json').exists(), 'Prepared pilot has a failure marker')
    manifest = integration.read_json(directory / 'manifest.json')
    require(manifest['status'] == 'prepared' and manifest.get('schema_version') == 2 and manifest['compile_definitions'] ==
            {'TEST_TIMESTAMPS': 0, 'DEBUG_REPORT': 1, 'FLOW_SLOTS': 65536}, 'Not a native debug preparation')
    require(prefix.sha256_file(directory / 'prefix.json') == manifest['prefix_sha256'], 'Prefix bundle changed')
    bundle = integration.read_json(directory / 'prefix.json')
    require(bundle['record']['partition'] == 'test' and bundle['record']['n'] == 8 and
            len(bundle['packets']) == 8 and bundle['native_clock_required'], 'Wrong pilot population')
    require(bundle['relative_us'][0] == 0 and bundle['relative_us'][-1] < 2_000_001,
            'Pilot must remain bounded at two seconds')
    verify_hashes(bundle['input_sha256'])
    verify_hashes({item['path']: item['sha256'] for item in manifest['programs'].values()})
    for item in manifest['programs'].values():
        require(Path(item['path']).resolve().is_relative_to(directory), 'Program outside preparation directory')
    exports, _, _ = integration.load_deployment(Path(bundle['deployment']))
    for s in 'BC':
        require(predict(exports[s], bundle['features_' + s]) == bundle['original_predictions'][s],
                'Original prediction changed')
    for packet in bundle['packets']:
        raw = bytes.fromhex(packet['raw_ip_hex'])
        require(hashlib.sha256(raw).hexdigest() == packet['sha256'], 'Saved original IP packet changed')
        require(len(raw) + BODY_OFFSET <= 9000, 'Debug frame would exceed dedicated link MTU')
    return bundle, manifest, exports


def output_key(frame):
    if frame[12:14] != b'\x88\xb6':
        return None
    helpers.decode_report(frame)
    integration.decode_rf(frame, 85)
    require(len(frame) >= BODY_OFFSET + 20, 'Missing unchanged IPv4 body')
    return frame[BODY_OFFSET:]


def write_observed_pcap(path, observations):
    """Packet bytes with userspace socket-read wall times, not kernel timestamps."""
    with Path(path).open('xb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        for row in observations:
            frame = bytes.fromhex(row['frame_hex'])
            seconds, nanoseconds = divmod(row['wall_ns'], 1_000_000_000)
            stream.write(struct.pack('<IIII', seconds, nanoseconds, len(frame), len(frame)))
            stream.write(frame)


def compare_native(bundle, export, frames):
    """Use only observed ingress time from P4; derive all expected state ourselves."""
    require(len(frames) == 8, 'Missing/extra native reports')
    reports = [helpers.decode_report(frame) for frame in frames]
    times = [row['observed_us'] for row in reports]
    quality = native_analysis.clock_quality(times)
    require(quality['valid_timestamps'] and quality['clock_progress'], quality['error'])
    oracle = replay.ReplayOracle(bundle['capture'], {4: io.StringIO(), 8: io.StringIO()},
                                io.StringIO(), idle_seconds=60, boundary_policy='idle-tcp')
    owners, rows, decision = {}, [], None
    for position, (saved, frame, report) in enumerate(zip(bundle['packets'], frames, reports, strict=True)):
        raw = bytes.fromhex(saved['raw_ip_hex'])
        require(output_key(frame) == raw, f'Packet {position + 1}: output IP bytes changed')
        # DO NOT pass reported size/IAT/direction/effective_us to the oracle.
        packet, tcp = prefix.decode_raw_packet(raw, saved['original_frame'], report['observed_us'] * 1000)
        expected, current, _, _, collision = replay.expectation(oracle, packet, tcp, owners, origin_us=0)
        require(not collision, 'Unexpected collision in isolated one-conversation pilot')
        expected['packet_id'] = struct.unpack_from('!H', raw, 4)[0]
        for name, value in expected.items():
            require(report[name] == value,
                    f'Packet {position + 1} frame {packet.frame}: {name} P4={report[name]} Python={value}')
        rf = integration.decode_rf(frame, 85)
        expected_rf = None
        if current is not None:
            require(position == 7 and decision is None, 'Classification must occur exactly once at packet eight')
            require(current['record_id'] == bundle['record']['record_id'], 'Reference instance identity changed')
            expected_rf = predict(export, current['features_C'])
            decision = dict(current, expected_rf=expected_rf)
        integration.check_rf(rf, export['feature_set'], expected_rf)
        rows.append({'position': position + 1, 'original_frame': packet.frame,
                     'feature_report': report, 'expected_fields': expected, 'rf_report': rf})
    audit = oracle.finish()
    require(decision is not None and audit['instances'] == 1 and audit['windows']['8']['records'] == 1,
            'Expected one isolated eight-packet instance and one decision')
    original = bundle['original_predictions'][export['feature_set']]
    gaps = [b - a for a, b in zip(times, times[1:])]
    original_gaps = [b - a for a, b in zip(bundle['relative_us'], bundle['relative_us'][1:])]
    return {'passed': quality['clean'], 'parity_passed': True, 'clock_quality': quality,
            'packets': 8, 'eligible_packets': 8, 'decisions': 1,
            'feature_mismatches': 0, 'instance_mismatches': 0, 'leaf_mismatches': 0,
            'score_mismatches': 0, 'class_mismatches': 0, 'decision': decision,
            'timing': {'original_iats_us': original_gaps, 'native_iats_us': gaps,
                       'native_minus_original_iats_us': [a - b for a, b in zip(gaps, original_gaps)],
                       'original_features_C': bundle['features_C'], 'native_features_C': decision['features_C']},
            'capture_time_prediction': original['class'], 'native_time_prediction': decision['expected_rf']['class'],
            'prediction_changed_with_native_timing': original['prediction'] != decision['expected_rf']['prediction'],
            'packet_checks': rows}


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    require(result.returncode == 0, f"Command failed ({' '.join(map(str, argv))}): {result.stderr}")
    return result.stdout


class OwnedLinks:
    """Only create/delete our new veth pairs; refuse names already in use."""
    def __init__(self, token, ip='ip', sysctl='sysctl'):
        require(re.fullmatch('[0-9a-f]{6}', token) is not None, 'Invalid link ownership token')
        self.ip, self.sysctl = ip, sysctl
        self.names = [f'np{token}{tail}' for tail in ('s1', 'h1', 's2', 'h2')]
        self.alias = 'etc-native-pilot:' + token
        self.owned, self.pairs, self.cleanup_errors = {}, [], []

    def inventory(self):
        return {row['ifname']: row for row in json.loads(command([self.ip, '-d', '-j', 'link', 'show']))}

    def __enter__(self):
        existing = self.inventory()
        require(not set(self.names) & existing.keys(), 'Dedicated pilot interface name already exists; refusing to touch it')
        try:
            for left, right in zip(self.names[::2], self.names[1::2]):
                command([self.ip, 'link', 'add', left, 'type', 'veth', 'peer', 'name', right])
                self.pairs.append((left, right))
                state = self.inventory()
                for name in (left, right):
                    self.owned[name] = {'ifindex': state[name]['ifindex'], 'ifalias': state[name].get('ifalias', '')}
                for name in (left, right):
                    command([self.ip, 'link', 'set', 'dev', name, 'alias', self.alias])
                    self.owned[name]['ifalias'] = self.alias
                    command([self.sysctl, '-w', f'net.ipv6.conf.{name}.disable_ipv6=1'])
                    command([self.sysctl, '-w', f'net.ipv4.conf.{name}.forwarding=0'])
                    command([self.ip, 'link', 'set', 'dev', name, 'mtu', '9000'])
                    command([self.ip, 'link', 'set', 'dev', name, 'up'])
            return self
        except BaseException:
            self.cleanup()
            raise

    def cleanup(self):
        for left, right in reversed(self.pairs):
            try:
                state = self.inventory()
                if left not in state and right not in state:
                    continue
                for name, peer in ((left, right), (right, left)):
                    row, owner = state.get(name), self.owned.get(name)
                    require(row is not None and owner is not None and row['ifindex'] == owner['ifindex'] and
                            row.get('ifalias', '') == owner['ifalias'] and
                            row.get('linkinfo', {}).get('info_kind') == 'veth' and
                            (row.get('link') == peer or row.get('link_index') == self.owned[peer]['ifindex']),
                            f'Interface ownership changed: {name}; not deleting it')
                command([self.ip, 'link', 'delete', 'dev', left])  # removes only this owned pair
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                self.cleanup_errors.append(str(error))

    def __exit__(self, *exception):
        self.cleanup()


def wait_ready(process, log_path, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        require(process.poll() is None, f'Private BMv2 child exited; inspect {log_path}')
        if 'Thrift server was started' in log_path.read_text(encoding='utf-8'):
            # BMv2 starts dataplane threads just after its Thrift-ready log.
            time.sleep(0.2)
            require(process.poll() is None, 'Private BMv2 child exited during startup')
            return
        time.sleep(0.03)
    raise ValueError('Private BMv2 startup timed out')


def stop_child(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def read_counters(args, port, directory):
    env = dict(os.environ)
    env['PYTHONPATH'] = str(args.switch.parents[2] / 'tools') + os.pathsep + env.get('PYTHONPATH', '')
    argv = [str(args.cli_python), str(args.switch.with_name('simple_switch_CLI')), '--thrift-port', str(port)]
    queries = ''.join(f'counter_read FeatureIngress.rf_decisions {i}\n' for i in range(6))
    result = subprocess.run(argv, input=queries, capture_output=True, text=True, env=env, timeout=15)
    write_json(directory / 'counter_query.json', {'command': argv, 'queries': queries,
               'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
    require(result.returncode == 0, 'Private switch CLI counter read failed')
    matches = re.findall(r'rf_decisions\[(\d+)\]=\s*\((\d+) bytes, (\d+) packets\)', result.stdout)
    require(len(matches) == 6 and {int(i) for i, _, _ in matches} == set(range(6)), 'Missing/duplicate RF counters')
    return {int(i): {'bytes': int(byte_count), 'packets': int(count)} for i, byte_count, count in matches}


def run_model(args, program, bundle, export, links, directory):
    directory.mkdir()
    port = helpers.free_port()
    argv = [str(args.switch), '-i', f'1@{links.names[0]}', '-i', f'2@{links.names[2]}',
            '--thrift-port', str(port), '--device-id', str(100000 + uuid.uuid4().int % 100000000),
            '--notifications-addr', 'ipc://notifications.ipc', '--log-console', '-L', 'info', str(program)]
    write_json(directory / 'switch_command.json', argv)
    # Locally-administered MACs tag this run; original raw IPv4 bytes stay intact.
    tag = bytes.fromhex('02' + uuid.uuid4().hex[:10] + '02' + uuid.uuid4().hex[:10])
    frames = [tag + b'\x08\x00' + bytes.fromhex(row['raw_ip_hex']) for row in bundle['packets']]
    with (directory / 'switch.log').open('x') as log:
        process = subprocess.Popen(argv, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_ready(process, directory / 'switch.log')
            observations = transport.replay_frames(frames, bundle['relative_us'], links.names[1], links.names[3],
                                args.timeout_seconds, key_from_output=output_key)
            write_json(directory / 'transport.json', observations)
            require(observations['transport_passed'], f"Transport failed: {observations['errors']}; inspect transport.json")
            output = [bytes.fromhex(row['frame_hex']) for row in observations['output_observations']]
            write_observed_pcap(directory / 'input.pcap', observations['input_observations'])
            write_observed_pcap(directory / 'output.pcap', observations['output_observations'])
            result = compare_native(bundle, export, output)
            counters = read_counters(args, port, directory)
            index = result['decision']['expected_rf']['prediction']
            require([counters[i]['packets'] for i in range(6)] == [int(i == index) for i in range(6)],
                    'Decision counters must show exactly one prediction in the oracle class')
            require([counters[i]['bytes'] for i in range(6)] ==
                    [len(frames[7]) if i == index else 0 for i in range(6)],
                    'Decision byte counters must count only the original packet-eight Ethernet frame')
            result['decision_counters'] = [counters[i] for i in range(6)]
            result['switch_pid'] = process.pid
            result['thrift_port'] = port
            write_json(directory / 'comparison.json', result)
            print(f"RF-{export['feature_set']}: 8/8 forwarded; one decision; features/leaves/scores/class parity PASS; "
                  f"raw clock regressions={result['clock_quality']['raw_backward_steps']}; "
                  f"clock {'PASS' if result['clock_quality']['clean'] else 'FAIL'}; native prediction={result['native_time_prediction']}", flush=True)
            return result
        finally:
            stop_child(process)


def restore_new_evidence_owner(directory):
    """Only this newly-created run, never preparation/input/repository trees."""
    if os.geteuid() != 0 or not os.environ.get('SUDO_UID'):
        return
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    for child in directory.rglob('*'):
        if not child.is_symlink():
            os.chown(child, uid, gid)
    os.chown(directory, uid, gid)


def smoke(args, repo):
    """Unpaced packet-file check on both rebuilt/native programs; not a live pilot."""
    bundle, manifest, exports = load_prepared(args.prepared)
    receipt = clock_contract.verify_receipt(manifest['clock_source_receipt'], args.switch)
    directory = new_directory(args.output_root or repo / 'results/native_clock_pilot_checks')
    try:
        tag = bytes.fromhex('020000000002020000000001')
        frames = [tag + b'\x08\x00' + bytes.fromhex(row['raw_ip_hex']) for row in bundle['packets']]
        results = {}
        for model in 'BC':
            child = directory / f'RF_{model}'
            output = helpers.run_switch(args.switch, Path(manifest['programs'][model]['path']),
                                        child, frames, 8, timeout=20)
            results[model] = compare_native(bundle, exports[model], output)
            write_json(child / 'comparison.json', results[model])
            require(results[model]['passed'], 'Unpaced integration clock quality failed')
        verify_hashes(bundle['input_sha256'])
        summary = {'status': 'native_clock_packet_file_check_passed', 'passed': True,
                   'live_pilot_passed': False, 'paced': False, 'accuracy_scored': False,
                   'performance_measured': False, 'clock_source_receipt': receipt,
                   'models': results, 'prepared': str(args.prepared.resolve())}
        write_json(directory / 'summary.json', summary)
    except BaseException as error:
        write_json(directory / 'failure.json', {'error': str(error)})
        raise
    print(f'PACKET-FILE CHECK PASS — not a paced live pilot. Evidence saved to: {directory}')
    return directory


def run(args, repo):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Run this stage with sudo in Ubuntu: raw sockets/new veths need root')
    require(math.isfinite(args.timeout_seconds) and 3 <= args.timeout_seconds <= 15,
            'Pilot timeout must be between three and fifteen seconds')
    for tool in (args.switch, args.cli_python, args.switch.with_name('simple_switch_CLI')):
        require(tool.is_file(), f'Required local tool missing: {tool}')
    require(shutil.which('ip') and shutil.which('sysctl'), 'iproute2/sysctl required')
    bundle, manifest, exports = load_prepared(args.prepared)
    require(prefix.sha256_file(manifest['clock_source_receipt']) == manifest['clock_source_receipt_sha256'],
            'Clock receipt changed after preparation')
    clock_receipt = clock_contract.verify_receipt(manifest['clock_source_receipt'], args.switch)
    directory = new_directory(args.output_root or repo / 'results/native_clock_pilot')
    links = OwnedLinks(uuid.uuid4().hex[:6])
    try:
        write_json(directory / 'provenance.json', {'prepared': str(args.prepared.resolve()),
                   'prepared_manifest_sha256': prefix.sha256_file(args.prepared / 'manifest.json'),
                   'switch_sha256': prefix.sha256_file(args.switch), 'cli_python': str(args.cli_python),
                   'clock_source_receipt': clock_receipt,
                   'record_id': bundle['record']['record_id'], 'native_clock': True,
                   'controlled_timestamps': False, 'debug_reports': True, 'interfaces': links.names,
                   'not_measured': ['accuracy', 'macro-F1', 'throughput', 'latency', 'CPU performance']})
        results = {}
        with links:
            write_json(directory / 'interfaces.json', links.owned)
            for s in 'BC':
                results[s] = run_model(args, Path(manifest['programs'][s]['path']), bundle, exports[s], links,
                                       directory / f'RF_{s}')
        require(not links.cleanup_errors, f'Owned-link cleanup failed: {links.cleanup_errors}')
        verify_hashes(bundle['input_sha256'])
        # Same raw prefix; separate native runs have different actual arrival times.
        shared_vectors = {run_name: {s: predict(exports[s], row['decision']['features_C']) for s in 'BC'}
                          for run_name, row in results.items()}
        compact = {s: {k: v for k, v in row.items() if k != 'packet_checks'} for s, row in results.items()}
        clean = all(row['clock_quality']['clean'] for row in results.values())
        summary = {'status': 'native_pilot_passed' if clean else 'native_pilot_clock_incomplete',
                   'passed': clean, 'raw_clock_clean': clean, 'pilot_only': True,
                   'accuracy_scored': False, 'performance_measured': False, 'native_clock': True,
                   'whole_capture_replay': False, 'record_id': bundle['record']['record_id'],
                   'models': compact, 'both_models_on_each_same_observed_vector': shared_vectors,
                   'cleanup_passed': True, 'limitations': bundle['limitations'] +
                   ['Debug headers add bytes/work; this is not a production performance build.',
                    'B/C live runs do not share identical native timing; shared-vector predictions are offline only.']}
        summary['output_sha256'] = {path.relative_to(directory).as_posix(): prefix.sha256_file(path)
                                    for path in sorted(directory.rglob('*')) if path.is_file() and not path.is_symlink()}
        write_json(directory / 'summary.json', summary)
        require(clean, 'Parity matched, but raw ingress clock quality failed; do not proceed to full evaluation')
        print(f'NATIVE PILOT PASS — correctness only, not accuracy/performance. Evidence saved to: {directory}')
    except BaseException as error:
        write_json(directory / 'failure.json', {'error': str(error), 'cleanup_errors': links.cleanup_errors})
        print(f'Failure evidence saved to: {directory}', file=sys.stderr)
        raise
    finally:
        restore_new_evidence_owner(directory)
    return directory


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    prep = actions.add_parser('prepare', help='Read one frozen prefix and compile; no root/traffic')
    prep.add_argument('--capture', default=prefix.DEFAULT_CAPTURE)
    prep.add_argument('--max-duration-seconds', type=float, default=2.0)
    prep.add_argument('--p4c', type=Path, default=repo.parent / 'p4c-build/p4c')
    prep.add_argument('--clock-receipt', type=Path, required=True, help='Attested steady-clock BMv2 build')
    prep.add_argument('--output-root', type=Path)
    for action in ('run', 'smoke'):
        live = actions.add_parser(action, help='Root: paced live pilot' if action == 'run' else 'Unpaced file-mode integration only')
        live.add_argument('--prepared', type=Path, required=True)
        live.add_argument('--switch', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
        live.add_argument('--cli-python', type=Path, default=repo.parent / 'bmv2-venv/bin/python')
        live.add_argument('--timeout-seconds', type=float, default=5.0)
        live.add_argument('--output-root', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare':
            prepare(args, repo)
        elif args.action == 'smoke':
            smoke(args, repo)
        else:
            run(args, repo)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted; owned child/interface cleanup attempted; inspect failure evidence.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
