#!/usr/bin/env python3
"""Normal-build RF-B/C instrumentation pilot, NOT a capacity benchmark.

prepare: seal clean-native prerequisite, normal builds and synthetic workloads.
smoke: non-root unpaced exact forwarding/counters (not live performance).
run: four private live trials, 256 frames at 100pps each; no accuracy scoring.
"""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import integrate_rf as integration
import native_prefix
import performance_resources as resources
import performance_transport as transport
import performance_workload as workload
import run_native_clock_pilot as ownership
import test_p4_features as helpers
import verify_bmv2_clock as clock_contract
import verify_bmv2_queue_clock as queue_contract

require, write_json = helpers.require, helpers.write_json
DEPLOYMENT_RUN = '20260929T221518Z_a61fc37702'
NORMAL_DEFINITIONS = {'TEST_TIMESTAMPS': 0, 'DEBUG_REPORT': 0, 'FLOW_SLOTS': 65536}
RATE_PPS = 100
FRAME_BYTES = 128
RECIPE = [('classification-heavy', 32, 8), ('cached-forwarding', 8, 32)]


def seal(directory):
    return {path.relative_to(directory).as_posix(): native_prefix.sha256_file(path)
            for path in sorted(directory.rglob('*')) if path.is_file() and not path.is_symlink()}


def verify_native_prerequisite(directory, receipt):
    """Require the completed 398/model native evaluation on this exact binary."""
    directory = Path(directory).resolve()
    summary = integration.read_json(directory / 'summary.json')
    require(not (directory / 'failure.json').exists() and summary['passed'] is True and
            summary['raw_clock_clean'] is True and summary['expected_cases_per_model'] == 398 and
            summary['verified_classified_evaluations'] == 796 and summary['cleanup_passed'] is True,
            'A complete clean native evaluation is required before performance instrumentation')
    require('provenance.json' in summary['output_sha256'], 'Native prerequisite provenance is not sealed')
    hashes = {str(directory / 'summary.json'): native_prefix.sha256_file(directory / 'summary.json')}
    for relative, expected in summary['output_sha256'].items():
        path = (directory / relative).resolve()
        require(path.is_relative_to(directory) and path.is_file() and
                native_prefix.sha256_file(path) == expected, 'Native prerequisite evidence changed')
        hashes[str(path)] = expected
    provenance = integration.read_json(directory / 'provenance.json')
    require(provenance['clock_source_receipt']['artifacts'] == receipt['artifacts'] and
            provenance['clock_source_receipt']['receipt_sha256'] == receipt['receipt_sha256'],
            'Completed native evaluation used a different clock build')
    return hashes


def validate_normal_program(path):
    program = integration.read_json(path)
    orders = [name for parser in program['deparsers'] for name in parser['order']]
    require(not any('report' in name for name in orders), 'Normal build still emits debug reports')
    counters = [row for row in program['counter_arrays'] if row['name'] == 'FeatureIngress.rf_decisions']
    require(len(counters) == 1 and counters[0]['size'] == 6, 'Normal build lost observable RF inference')
    return {'debug_report_headers_emitted': False, 'deparser_order': orders, 'rf_class_counter_bins': 6}


def make_plans(token):
    return [workload.build_workload(name, flows, length, f'{token}:{name}',
                                   frame_bytes=FRAME_BYTES, namespace=index)
            for index, (name, flows, length) in enumerate(RECIPE)]


def is_queue_receipt(receipt):
    return receipt.get('schema') == queue_contract.SCHEMA


def verify_current_receipt(path, switch):
    schema = integration.read_json(path)['schema']
    require(schema in ('bmv2-steady-clock-v1', queue_contract.SCHEMA), 'Unknown clock receipt schema')
    module = queue_contract if schema == queue_contract.SCHEMA else clock_contract
    return module.verify_receipt(path, switch)


def verify_historical_pipeline(native_run, repo):
    """Bind historical correctness to unchanged P4/models, NOT the new binary."""
    provenance = integration.read_json(native_run / 'provenance.json')
    prepared = Path(provenance['prepared'])
    manifest_path = prepared / 'manifest.json'
    require(native_prefix.sha256_file(manifest_path) == provenance['prepared_manifest_sha256'],
            'Historical native preparation changed')
    manifest = integration.read_json(manifest_path)
    population_path = prepared / 'population.json'
    require(native_prefix.sha256_file(population_path) == manifest['population_sha256'],
            'Historical native population changed')
    population = integration.read_json(population_path)
    hashes = {str(manifest_path): provenance['prepared_manifest_sha256'],
              str(population_path): manifest['population_sha256']}
    for name in ('flow_features.p4', 'rf_b.p4', 'rf_c.p4', 'rf-models.json'):
        path = (repo / 'p4' / name).resolve()
        expected = population['input_sha256'].get(str(path))
        require(expected is not None and native_prefix.sha256_file(path) == expected,
                'Queue upgrade must not change the frozen P4/model pipeline')
        hashes[str(path)] = expected
    return hashes


def verify_native_packetfile(directory, receipt):
    require(directory is not None, 'Queue-upgraded preparation requires a fresh native packet-file parity check')
    directory = Path(directory).resolve()
    summary = integration.read_json(directory / 'summary.json')
    require(not (directory / 'failure.json').exists() and summary['status'] ==
            'native_clock_packet_file_check_passed' and summary['passed'] is True and
            summary['paced'] is False and summary['accuracy_scored'] is False,
            'Missing fresh native packet-file parity')
    compatible = summary['clock_source_receipt']
    require(compatible['receipt_sha256'] == receipt['feature_clock_receipt']['sha256'] and
            compatible['artifacts'] == {key: value for key, value in receipt['artifacts'].items()
                                        if key != 'queue_header'}, 'Native packet-file check used another binary')
    for model in 'BC':
        row = summary['models'][model]
        require(row['passed'] is True and row['parity_passed'] is True and row['packets'] == 8 and
                row['decisions'] == 1 and row['clock_quality']['clean'] is True and
                all(row[key] == 0 for key in ('feature_mismatches', 'instance_mismatches',
                                             'leaf_mismatches', 'score_mismatches', 'class_mismatches')),
                'Native packet-file check lacks clean full feature/RF parity')
        require(integration.read_json(directory / f'RF_{model}/comparison.json') == row,
                'Native comparison and summary disagree')
    return {str(path): expected for relative, expected in seal(directory).items()
            for path in [directory / relative]}


def verify_normal_smoke(directory, prepared, receipt):
    require(directory is not None, 'Queue-upgraded live pilot requires --smoke-run from the fresh normal-build check')
    directory = Path(directory).resolve()
    summary = integration.read_json(directory / 'summary.json')
    require(not (directory / 'failure.json').exists() and summary['passed'] is True and
            summary['status'] == 'normal_performance_packet_file_passed' and
            summary['prepared_manifest_sha256'] == native_prefix.sha256_file(prepared / 'manifest.json') and
            summary['clock_receipt']['receipt_sha256'] == receipt['receipt_sha256'],
            'Normal smoke is not bound to this preparation and binary')
    for relative, expected in summary['output_sha256'].items():
        path = (directory / relative).resolve()
        require(path.is_relative_to(directory) and native_prefix.sha256_file(path) == expected,
                'Normal smoke evidence changed')
    for name in ('classification-heavy', 'cached-forwarding'):
        for model in 'BC':
            row = summary['results'][name + '_RF_' + model]
            count = 16 if name == 'classification-heavy' else 32
            require(row['packets'] == row['unchanged_forwarded_packets'] == count and row['decisions'] == 2,
                    'Fresh normal smoke did not pass exact forwarding/one-shot counters')
    return {'path': str(directory), 'summary_sha256': native_prefix.sha256_file(directory / 'summary.json'),
            'prepared_manifest_sha256': summary['prepared_manifest_sha256']}


def prepare(args, repo):
    switch = repo.parent / 'behavioral-model/targets/simple_switch/simple_switch'
    receipt = verify_current_receipt(args.clock_receipt, switch)
    baseline_receipt = receipt['previous_feature_clock_receipt'] if is_queue_receipt(receipt) else receipt
    hashes = verify_native_prerequisite(args.native_run, baseline_receipt)
    if is_queue_receipt(receipt):
        hashes.update(verify_historical_pipeline(args.native_run, repo))
        hashes.update(verify_native_packetfile(args.native_parity_run, receipt))
        hashes.update({item['path']: item['sha256'] for item in receipt['upgrade_evidence'].values()})
        hashes[receipt['feature_clock_receipt']['path']] = receipt['feature_clock_receipt']['sha256']
    deployment = repo / 'results/rf_deployment' / DEPLOYMENT_RUN
    integration.load_deployment(deployment)
    deployment_seal = integration.read_json(deployment / 'summary.json')['output_sha256']
    for relative, expected in deployment_seal.items():
        hashes[str((deployment / relative).resolve())] = expected
    source_paths = [Path(__file__), Path(workload.__file__), Path(transport.__file__),
                    Path(resources.__file__), Path(ownership.__file__), Path(clock_contract.__file__),
                    Path(integration.__file__), Path(helpers.__file__), Path(native_prefix.__file__),
                    Path(queue_contract.__file__),
                    args.clock_receipt, deployment / 'summary.json',
                    repo / 'p4/flow_features.p4', repo / 'p4/rf_b.p4', repo / 'p4/rf_c.p4',
                    repo / 'p4/rf-models.json']
    source_paths += [Path(row['path']) for row in receipt['artifacts'].values()]
    hashes.update({str(path.resolve()): native_prefix.sha256_file(path) for path in source_paths})
    directory = ownership.new_directory(args.output_root or repo / 'results/performance_pilot_preparation')
    try:
        token = uuid.uuid4().hex
        plans = make_plans(token)
        for plan in plans:
            frames = [plan.frame_for(seq) for seq in range(plan.packet_count)]
            require(plan.flow_count / RATE_PPS < 60 and plan.packet_count / RATE_PPS <= 60,
                    'Workload would exceed frozen idle or bounded-trial limits')
            helpers.write_pcap(directory / (plan.name + '.pcap'), frames)
            write_json(directory / (plan.name + '.json'), plan.manifest())
        programs = {}
        for model in 'BC':
            program = integration.compile_program(args.p4c, repo / f'p4/rf_{model.lower()}.p4',
                        directory / f'rf_{model.lower()}.json', controlled=False, debug=False)
            programs[model] = {'path': str(program), 'sha256': native_prefix.sha256_file(program),
                               'normal_build_check': validate_normal_program(program)}
        ownership.verify_hashes(hashes)
        manifest = {'schema': 'normal-rf-performance-pilot-v1', 'status': 'prepared',
                    'compile_definitions': NORMAL_DEFINITIONS, 'programs': programs,
                    'clock_receipt': str(args.clock_receipt.resolve()),
                    'native_run': str(args.native_run.resolve()), 'deployment': str(deployment),
                    'historical_native_on_same_binary': not is_queue_receipt(receipt),
                    'native_parity_run': str(args.native_parity_run.resolve()) if is_queue_receipt(receipt) else None,
                    'queue_clock_upgrade': is_queue_receipt(receipt),
                    'input_sha256': hashes, 'token': token, 'rate_pps': RATE_PPS,
                    'frame_bytes': FRAME_BYTES, 'models': ['B', 'C'], 'repetitions': 1,
                    'workloads': [plan.manifest() for plan in plans],
                    'expected_live_trials': 4, 'expected_live_packets': 1024,
                    'new_fits': 0, 'accuracy_scored': False, 'capacity_sweep': False,
                    'p4c_sha256': native_prefix.sha256_file(args.p4c)}
        manifest['output_sha256'] = seal(directory)
        write_json(directory / 'manifest.json', manifest)
    except BaseException as error:
        write_json(directory / 'failure.json', {'stage': 'prepare', 'error': str(error)})
        raise
    print('PERFORMANCE PREPARATION PASS — DEBUG_REPORT=0; TEST_TIMESTAMPS=0; frozen RF models unchanged.')
    print('Four pilot trials: 256 × 128-byte Ethernet frames at 100pps each; not a capacity sweep.')
    print(f'Evidence saved to: {directory}')
    return directory


def load_prepared(directory, switch):
    directory = Path(directory).resolve()
    manifest = integration.read_json(directory / 'manifest.json')
    require(not (directory / 'failure.json').exists() and manifest['status'] == 'prepared' and
            manifest['schema'] == 'normal-rf-performance-pilot-v1' and
            manifest['compile_definitions'] == NORMAL_DEFINITIONS and manifest['rate_pps'] == RATE_PPS and
            manifest['frame_bytes'] == FRAME_BYTES and manifest['new_fits'] == 0 and
            manifest['repetitions'] == 1 and manifest['capacity_sweep'] is False and
            manifest['accuracy_scored'] is False and manifest['models'] == ['B', 'C'] and
            manifest['expected_live_trials'] == 4 and manifest['expected_live_packets'] == 1024,
            'Wrong normal-build performance pilot contract')
    receipt = verify_current_receipt(manifest['clock_receipt'], switch)
    ownership.verify_hashes(manifest['input_sha256'])
    for relative, expected in manifest['output_sha256'].items():
        path = (directory / relative).resolve()
        require(path.is_relative_to(directory) and native_prefix.sha256_file(path) == expected,
                'Prepared normal-build artifact changed')
    baseline_receipt = receipt['previous_feature_clock_receipt'] if is_queue_receipt(receipt) else receipt
    verify_native_prerequisite(manifest['native_run'], baseline_receipt)
    require(manifest['historical_native_on_same_binary'] == (not is_queue_receipt(receipt)) and
            manifest['queue_clock_upgrade'] == is_queue_receipt(receipt), 'Native-binary provenance changed')
    if is_queue_receipt(receipt):
        verify_historical_pipeline(Path(manifest['native_run']), Path(__file__).resolve().parent.parent)
        verify_native_packetfile(manifest['native_parity_run'], receipt)
    plans = make_plans(manifest['token'])
    require([plan.manifest() for plan in plans] == manifest['workloads'], 'Prepared workload recipe changed')
    for plan in plans:
        require(helpers.read_pcap(directory / (plan.name + '.pcap')) ==
                [plan.frame_for(seq) for seq in range(plan.packet_count)], 'Prepared packet bytes changed')
    require(set(manifest['programs']) == {'B', 'C'}, 'Missing normal RF build')
    for model, item in manifest['programs'].items():
        path = Path(item['path']).resolve()
        require(path.is_relative_to(directory) and native_prefix.sha256_file(path) == item['sha256'] and
                validate_normal_program(path) == item['normal_build_check'], 'Normal RF program changed')
    return manifest, plans, receipt


def wait_ready(process, port):
    """Private Thrift readiness without enabling info/packet logging."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        require(process.poll() is None, 'Private normal-build switch exited during startup')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                pass
            time.sleep(.2)
            require(process.poll() is None, 'Private switch exited while settling')
            return
        except OSError:
            time.sleep(.02)
    raise ValueError('Private normal-build Thrift startup timed out')


def validate_counters(counters, plan):
    packets = sum(counters[index]['packets'] for index in range(6))
    byte_count = sum(counters[index]['bytes'] for index in range(6))
    expected_packets = plan.expected_classifications
    expected_bytes = expected_packets * plan.frame_bytes
    return {'passed': packets == expected_packets and byte_count == expected_bytes,
            'packets': packets, 'bytes': byte_count, 'expected_packets': expected_packets,
            'expected_bytes': expected_bytes, 'class_counters': [counters[index] for index in range(6)],
            'meaning': 'One-shot eighth-packet classifications, not verified activity labels or every forwarded packet'}


def phase_latency(report, plan):
    result = {}
    values = report['latency']['paired_kernel_timestamp_differences_ns']
    for phase, predicate in (
        ('prefix_packets_1_to_7', lambda n: n < 8),
        ('decision_packet_8', lambda n: n == 8),
        ('cached_packets_after_8', lambda n: n > 8)):
        samples = [value / 1000 for sequence, value in enumerate(values)
                   if value is not None and predicate(plan.packet_in_flow(sequence))]
        result[phase] = transport.summarize(samples) if report['latency']['valid'] else None
    return {'kernel_path_delay_us': result,
            'meaning': 'Workload packet positions, not isolated inference measurements; no causal RF-time subtraction'}


def run_trial(args, program, model, plan, links, directory):
    directory.mkdir()
    frames = [plan.frame_for(seq) for seq in range(plan.packet_count)]
    port = helpers.free_port()
    argv = [str(args.switch), '-i', f'1@{links.names[0]}', '-i', f'2@{links.names[2]}',
            '--thrift-port', str(port), '--device-id', str(100000 + uuid.uuid4().int % 100000000),
            '--notifications-addr', 'ipc://notifications.ipc', '--log-console', '-L', 'warn', str(program)]
    write_json(directory / 'switch_command.json', argv)
    with (directory / 'switch.log').open('x') as log:
        process = subprocess.Popen(argv, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_ready(process, port)
            generator_cpu_start = time.process_time()
            with resources.ResourceSampler(process.pid) as monitor:
                measurement = transport.run_trial(frames, links.names[1], links.names[3], RATE_PPS,
                                                   sequence_from_frame=plan.sequence_from_frame)
            generator_cpu_seconds = time.process_time() - generator_cpu_start
            resource_report = monitor.summary()
            write_json(directory / 'measurement.json', measurement)
            write_json(directory / 'resources.json', resource_report)
            counters = ownership.read_counters(args, port, directory)
            counter_check = validate_counters(counters, plan)
            write_json(directory / 'counter_check.json', counter_check)
            passed = measurement['pilot_passed'] and resource_report['valid'] and counter_check['passed']
            summary = {'model': model, 'workload': plan.name, 'passed': passed,
                       'measurement_valid': measurement['pilot_passed'],
                       'normal_build': True, 'debug_reports': False, 'native_clock': True,
                       'packets': measurement['sent_packets'], 'forwarded': measurement['captured_output_unique'],
                       'expected_packets': plan.packet_count, 'loss_fraction': measurement['observed_loss_fraction_after_drain'],
                       'expected_decisions': plan.expected_classifications, 'counter_check': counter_check,
                       'throughput': measurement['throughput'], 'latency': {key: value for key, value in
                        measurement['latency'].items() if key not in ('paired_kernel_timestamp_differences_ns', 'clock_audit')},
                       'clock_audit': {key: value for key, value in measurement['latency']['clock_audit'].items()
                                      if key != 'samples'},
                       'packet_phase_latency': phase_latency(measurement, plan),
                       'resources': {key: value for key, value in resource_report.items() if key != 'samples'},
                       'generator_and_capture_process_cpu_seconds': generator_cpu_seconds,
                       'generator_cpu_meaning': 'Runner CPU during setup/send/capture/drain; excludes separate BMv2 child CPU',
                       'switch_pid': process.pid, 'thrift_port': port,
                       'accuracy_scored': False, 'capacity_measured': False}
            write_json(directory / 'trial_summary.json', summary)
            rate = summary['throughput']['actual_offered_pps_over_window']
            rate_text = f'{rate:.2f}' if rate is not None else 'unavailable'
            print(f"RF-{model}, {plan.name}: {summary['forwarded']}/{plan.packet_count} forwarded; "
                  f"{counter_check['packets']}/{plan.expected_classifications} decisions; offered={rate_text}pps; "
                  f"delay {'VALID' if measurement['latency']['valid'] else 'INVALID'}; "
                  f"{'PILOT PASS' if passed else 'PILOT INCOMPLETE'}", flush=True)
            return summary
        except BaseException as error:
            write_json(directory / 'failure.json', {'model': model, 'workload': plan.name,
                       'error_type': type(error).__name__, 'error': str(error),
                       'expected_packets': plan.packet_count,
                       'expected_decisions': plan.expected_classifications})
            raise
        finally:
            ownership.stop_child(process)


def run(args, repo):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Use sudo in Ubuntu: private veths/raw sockets require root')
    require(shutil.which('ip') and shutil.which('sysctl'), 'iproute2/sysctl unavailable')
    manifest, plans, receipt = load_prepared(args.prepared, args.switch)
    smoke_gate = verify_normal_smoke(args.smoke_run, args.prepared, receipt) if is_queue_receipt(receipt) else None
    directory = ownership.new_directory(args.output_root or repo / 'results/performance_pilot')
    links = ownership.OwnedLinks(uuid.uuid4().hex[:6])
    rows, attempted, execution_error, completed = [], [], None, False
    try:
        write_json(directory / 'provenance.json', {'prepared': str(args.prepared.resolve()),
                   'manifest_sha256': native_prefix.sha256_file(args.prepared / 'manifest.json'),
                   'fresh_normal_smoke': smoke_gate,
                   'historical_native_on_same_binary': manifest.get('historical_native_on_same_binary', True),
                   'clock_receipt': receipt, 'debug_reports': False, 'native_clock': True,
                   'normal_compile_definitions': NORMAL_DEFINITIONS, 'rate_pps': RATE_PPS,
                   'frame_bytes': FRAME_BYTES, 'repetitions': 1, 'accuracy_scored': False,
                   'performance_instrumentation_pilot': True, 'capacity_sweep': False,
                   'host': {'kernel': os.uname().release, 'machine': os.uname().machine,
                            'logical_cpus': os.cpu_count()}, 'interfaces': links.names})
        print('Normal-build PERFORMANCE PILOT: four trials, 256 frames at 100pps each. No accuracy scoring.', flush=True)
        with links:
            write_json(directory / 'interfaces.json', links.owned)
            for index, plan in enumerate(plans):
                for model in ('BC' if index == 0 else 'CB'):
                    print(f'Starting RF-{model}, {plan.name}: {plan.packet_count/RATE_PPS:.2f}s offered window plus capture drain.', flush=True)
                    attempted.append({'model': model, 'workload': plan.name})
                    rows.append(run_trial(args, Path(manifest['programs'][model]['path']), model, plan,
                                          links, directory / f'{index+1:02d}_{plan.name}_RF_{model}'))
        require(not links.cleanup_errors, f'Private link cleanup failed: {links.cleanup_errors}')
        ownership.verify_hashes(manifest['input_sha256'])
        module = queue_contract if is_queue_receipt(receipt) else clock_contract
        module.verify_receipt(manifest['clock_receipt'], args.switch)
        completed = True
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        execution_error = str(error)
    except KeyboardInterrupt:
        execution_error = 'User interrupted; partial instrumentation evidence preserved'
    try:
        passed = completed and len(rows) == 4 and all(row['passed'] for row in rows) and not links.cleanup_errors
        summary = {'status': 'performance_pilot_passed' if passed else 'performance_pilot_incomplete',
                   'passed': passed, 'pilot_only': True, 'normal_build': True, 'debug_reports': False,
                   'accuracy_scored': False, 'capacity_sweep': False, 'repetitions': 1,
                   'expected_trials': 4, 'completed_trials': len(rows), 'execution_error': execution_error,
                   'attempted_trials': attempted,
                   'cleanup_passed': not links.cleanup_errors, 'trials': rows,
                   'limitations': [
                    'Synthetic constant-size collision-free UDP; not real media traffic or capacity/collision testing.',
                    'One low-rate repetition validates measurement plumbing, not maximum sustainable throughput.',
                    'Cached workload includes eight prefix packets per flow; only subsequent packets are cached.',
                    'Software kernel endpoint delay includes host/veth/BMv2 queues and scheduling, not isolated RF execution.',
                    'CLOCK_REALTIME software timestamps are valid only when the independent sampled clock audit passes.',
                    'Capture drops invalidate loss inference; target rate is not necessarily actual offered rate.',
                    'CPU window includes socket setup/send/drain; sampled RSS differs from lifetime VmHWM.',
                    'Results are platform-specific to this WSL/BMv2 host, not hardware-switch line-rate performance.']}
        if not passed:
            write_json(directory / 'failure.json', {'error': execution_error or 'At least one measurement/counter/resource check failed',
                       'completed_trials': len(rows), 'cleanup_errors': links.cleanup_errors})
        summary['output_sha256'] = seal(directory)
        write_json(directory / 'summary.json', summary)
        print(('PERFORMANCE PILOT PASS' if passed else 'PERFORMANCE PILOT INCOMPLETE') +
              f' — not a capacity benchmark. Evidence saved to: {directory}', flush=True)
        return directory, passed
    finally:
        ownership.restore_new_evidence_owner(directory)


def smoke(args, repo):
    manifest, _, receipt = load_prepared(args.prepared, args.switch)
    directory = ownership.new_directory(args.output_root or repo / 'results/performance_pilot_checks')
    cli_args = SimpleNamespace(switch=args.switch, cli_python=args.cli_python,
                               cli=args.switch.with_name('simple_switch_CLI'))
    try:
        results = {}
        # Two flows let us reuse the already-tested normal-counter helper.
        for index, name in enumerate(('classification-heavy', 'cached-forwarding')):
            plan = workload.build_workload(name, 2, 8 if index == 0 else 16,
                                           f'{manifest["token"]}:smoke:{name}', frame_bytes=FRAME_BYTES)
            frames = [plan.frame_for(seq) for seq in range(plan.packet_count)]
            for model in 'BC':
                result = integration.run_forwarding(cli_args, Path(manifest['programs'][model]['path']),
                         directory / f'{name}_RF_{model}', frames, ingress_port=1)
                results[f'{name}_RF_{model}'] = result
        ownership.verify_hashes(manifest['input_sha256'])
        write_json(directory / 'summary.json', {'status': 'normal_performance_packet_file_passed', 'passed': True,
                   'results': results, 'debug_reports': False, 'live_measurements': False,
                   'throughput_or_latency_measured': False, 'clock_receipt': receipt,
                   'prepared_manifest_sha256': native_prefix.sha256_file(args.prepared / 'manifest.json'),
                   'output_sha256': seal(directory)})
    except BaseException as error:
        write_json(directory / 'failure.json', {'error': str(error)})
        raise
    print(f'NORMAL-BUILD CHECK PASS — unchanged bytes and one-shot counters; not live performance. Evidence saved to: {directory}')
    return directory


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare', help='Normal builds + fixed workloads, no live traffic')
    prep.add_argument('--native-run', type=Path, required=True)
    prep.add_argument('--clock-receipt', type=Path, required=True)
    prep.add_argument('--native-parity-run', type=Path, help='Fresh non-root native feature/RF check, required for queue-upgraded binary')
    prep.add_argument('--p4c', type=Path, default=repo.parent / 'p4c-build/p4c')
    prep.add_argument('--output-root', type=Path)
    for action in ('run', 'smoke'):
        stage = sub.add_parser(action)
        stage.add_argument('--prepared', type=Path, required=True)
        stage.add_argument('--smoke-run', type=Path, help='Fresh sealed normal-build smoke, required for queue-upgraded live run')
        stage.add_argument('--switch', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
        stage.add_argument('--cli-python', type=Path, default=repo.parent / 'bmv2-venv/bin/python')
        stage.add_argument('--output-root', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare':
            prepare(args, repo)
        elif args.action == 'smoke':
            smoke(args, repo)
        else:
            _, passed = run(args, repo)
            return 0 if passed else 2
    except (ValueError, OSError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted; caller-owned resources were cleaned where possible.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
