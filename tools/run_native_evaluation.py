#!/usr/bin/env python3
"""All 398 frozen held-out N8 prefixes: native live RF-B/C accuracy and parity.

prepare: verify all original bytes/features, plan disjoint batches, native builds.
smoke: unpaced non-root packet-file integration ONLY; no accuracy/performance.
run: live native ingress clocks, every original case accounted, no model fitting.
"""
import argparse
from collections import Counter
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import numpy as np

import analyze_native_evaluation as analysis
import integrate_rf as integration
import native_evaluation_transport as transport
import native_prefix
import prepare_native_evaluation as preparation
import prepare_rf_deployment as reference
import run_native_clock_pilot as pilot_runner
import test_p4_features as helpers
import verify_bmv2_clock as clock_contract

require, write_json = helpers.require, helpers.write_json
EXPECTED_CASES = 398
CLASSES = ['CHAT', 'FT', 'MAIL', 'P2P', 'STREAMING', 'VOIP']
CLASS_SUPPORT = {'CHAT': 35, 'FT': 104, 'MAIL': 29, 'P2P': 48, 'STREAMING': 77, 'VOIP': 105}


def versions():
    return {'python': sys.version, 'executable': sys.executable,
            'numpy': importlib.metadata.version('numpy'), 'scikit-learn': importlib.metadata.version('scikit-learn')}


def write_jsonl(path, rows):
    with Path(path).open('x', encoding='utf-8') as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n')


def seal(directory):
    return {path.relative_to(directory).as_posix(): native_prefix.sha256_file(path)
            for path in sorted(directory.rglob('*')) if path.is_file() and not path.is_symlink()}


def label_of(case):
    return case.get('label', case['record']['label'])


def validate_population(population, plan):
    cases = population['cases']
    require(len(cases) == EXPECTED_CASES and population['classes'] == CLASSES, 'Frozen population/classes changed')
    by_id = {case['case_id']: case for case in cases}
    require(len(by_id) == EXPECTED_CASES, 'Duplicate original record IDs')
    require(dict(Counter(label_of(case) for case in cases)) == CLASS_SUPPORT, 'Frozen class supports changed')
    for case in cases:
        require(case['record']['partition'] == 'test' and case['record']['n'] == 8 and
                case['case_id'] == case['record']['record_id'] and len(case['packets']) == 8,
                'Not an unchanged held-out N8 record')
        require(case['relative_us'][0] == 0 and case['relative_us'] == sorted(case['relative_us']),
                'Invalid original prefix schedule')
        require(case['relative_us'][-1] == case['features_B']['iat_sum'], 'Original prefix span changed')
        for saved in case['packets']:
            body = bytes.fromhex(saved['raw_ip_hex'])
            require(hashlib.sha256(body).hexdigest() == saved['sha256'], 'Saved raw IP bytes changed')
            require(len(body) + 137 <= 9000, 'Original IP packet exceeds native debug link MTU; no silent exclusions')
    planned = []
    for batch in plan['batches']:
        entries = batch['cases']
        require(1 <= len(entries) <= 32, 'Unsafe empty/oversize batch')
        local = [by_id[entry['case_id']] for entry in entries]
        require(len({case['slot'] for case in local}) == len(local), 'Hash-slot conflict inside batch')
        require(len({json.dumps(case['wire_key'], sort_keys=True) for case in local}) == len(local),
                'Shared bidirectional tuple inside batch')
        require(len({case['record']['parent_candidate_conversation_id'] for case in local}) == len(local),
                'Shared parent inside batch')
        end = max(entry['start_offset_us'] + by_id[entry['case_id']]['relative_us'][-1] for entry in entries)
        require(end == batch['scheduled_span_us'] and end < 595_000_000, 'Batch span inconsistent/unsafe')
        require(all(type(entry['start_offset_us']) is int and 0 <= entry['start_offset_us'] <= 31_000_000
                    for entry in entries), 'Invalid independent prefix start offsets')
        planned.extend(entry['case_id'] for entry in entries)
    require(len(planned) == EXPECTED_CASES and set(planned) == set(by_id), 'Missing/duplicated planned records')
    return by_id


def prepare(args, repo):
    switch = repo.parent / 'behavioral-model/targets/simple_switch/simple_switch'
    receipt = clock_contract.verify_receipt(args.clock_receipt, switch)
    pilot = clock_contract.verify_clean_pilot(args.pilot_run, receipt)
    population = preparation.prepare_population(repo)
    plan = preparation.plan_batches(population['cases'], max_cases=args.batch_size,
                                    start_spacing_us=args.start_spacing_us)
    validate_population(population, plan)
    paths = [Path(__file__), Path(preparation.__file__), Path(analysis.__file__), Path(transport.__file__),
             Path(pilot_runner.__file__), Path(pilot_runner.transport.__file__),
             Path(native_prefix.__file__), Path(helpers.__file__)]
    paths += [Path(clock_contract.__file__), args.clock_receipt, args.pilot_run / 'summary.json']
    paths += [Path(item['path']) for item in receipt['artifacts'].values()]
    paths += [args.pilot_run / name for name in pilot['output_sha256']]
    population['input_sha256'].update({str(p.resolve()): native_prefix.sha256_file(p) for p in paths})
    directory = pilot_runner.new_directory(args.output_root or repo / 'results/native_evaluation_preparation')
    try:
        write_json(directory / 'population.json', population)
        write_json(directory / 'batch_plan.json', plan)
        programs = {}
        for model in 'BC':
            program = integration.compile_program(args.p4c, repo / f'p4/rf_{model.lower()}.p4',
                        directory / f'rf_{model.lower()}.json', controlled=False, debug=True)
            programs[model] = {'path': str(program), 'sha256': native_prefix.sha256_file(program)}
        pilot_runner.verify_hashes(population['input_sha256'])
        manifest = {'schema': 'native-evaluation-v2', 'status': 'prepared', 'cases': EXPECTED_CASES,
                    'clock_source_receipt': str(args.clock_receipt.resolve()),
                    'clock_source_receipt_sha256': receipt['receipt_sha256'], 'clean_pilot': pilot,
                    'expected_model_case_evaluations': 2 * EXPECTED_CASES, 'models': ['B', 'C'],
                    'population_sha256': native_prefix.sha256_file(directory / 'population.json'),
                    'batch_plan_sha256': native_prefix.sha256_file(directory / 'batch_plan.json'),
                    'programs': programs, 'versions': versions(), 'p4c': str(args.p4c),
                    'p4c_sha256': native_prefix.sha256_file(args.p4c),
                    'compile_definitions': {'TEST_TIMESTAMPS': 0, 'DEBUG_REPORT': 1, 'FLOW_SLOTS': 65536},
                    'new_fits': 0, 'new_hyperparameter_search': False, 'gap_scaling': False}
        write_json(directory / 'manifest.json', manifest)
    except BaseException as error:
        write_json(directory / 'failure.json', {'stage': 'prepare', 'error': str(error)})
        raise
    minutes = 2 * sum(batch['scheduled_span_us'] for batch in plan['batches']) / 60_000_000
    print(f'All {EXPECTED_CASES} frozen held-out N8 records preserved; {len(plan["batches"])} disjoint batches/model.')
    print(f'Both-model scheduled time: {minutes:.2f} minutes plus startup/capture/verification overhead; no gaps rescaled.')
    print(f'PREPARATION PASS — no traffic or fitting. Evidence saved to: {directory}')
    return directory


def load_prepared(directory):
    directory = Path(directory).resolve()
    require(not (directory / 'failure.json').exists(), 'Preparation has failure marker')
    manifest = integration.read_json(directory / 'manifest.json')
    require(manifest['status'] == 'prepared' and manifest['schema'] == 'native-evaluation-v2' and
            manifest['compile_definitions'] == {'TEST_TIMESTAMPS': 0, 'DEBUG_REPORT': 1, 'FLOW_SLOTS': 65536}
            and manifest['cases'] == EXPECTED_CASES and manifest['new_fits'] == 0 and
            manifest['gap_scaling'] is False, 'Wrong/full native preparation contract')
    for name, field in [('population.json', 'population_sha256'), ('batch_plan.json', 'batch_plan_sha256')]:
        require(native_prefix.sha256_file(directory / name) == manifest[field], f'Prepared {name} changed')
    population = integration.read_json(directory / 'population.json')
    plan = integration.read_json(directory / 'batch_plan.json')
    by_id = validate_population(population, plan)
    pilot_runner.verify_hashes(population['input_sha256'])
    receipt = clock_contract.verify_receipt(manifest['clock_source_receipt'],
                                           Path(population['deployment']).parents[3] /
                                           'behavioral-model/targets/simple_switch/simple_switch')
    require(receipt['receipt_sha256'] == manifest['clock_source_receipt_sha256'], 'Prepared clock receipt changed')
    pilot = clock_contract.verify_clean_pilot(manifest['clean_pilot']['path'], receipt)
    require(pilot == manifest['clean_pilot'], 'Prepared clean pilot changed')
    for model, artifact in manifest['programs'].items():
        path = Path(artifact['path']).resolve()
        require(model in 'BC' and path.is_relative_to(directory) and
                native_prefix.sha256_file(path) == artifact['sha256'], 'Native build missing/changed')
    require(set(manifest['programs']) == {'B', 'C'}, 'Missing native RF build')
    exports, _, _ = integration.load_deployment(Path(population['deployment']))
    require(all(export['classes'] == CLASSES for export in exports.values()), 'RF class order changed')
    for case in population['cases']:
        for model in 'BC':
            require(pilot_runner.predict(exports[model], case['features_C']) == case['original_predictions'][model],
                    f"Frozen capture-time RF prediction changed: {case['case_id']}/{model}")
    return population, plan, manifest, exports, by_id


def frame_plans(batch, by_id):
    plans, analysis_cases = [], {}
    salt = uuid.uuid4().bytes
    seen = set()
    for entry in batch['cases']:
        case = by_id[entry['case_id']]
        tag_bytes = hashlib.sha256(salt + case['case_id'].encode()).digest()
        tag = b'\x02' + tag_bytes[:5] + b'\x02' + tag_bytes[5:10]
        require(tag not in seen, 'Ethernet tag collision; refusing ambiguous replay')
        seen.add(tag)
        plans.append({'case_id': case['case_id'], 'frames': [tag + b'\x08\x00' + bytes.fromhex(p['raw_ip_hex'])
                      for p in case['packets']], 'relative_us': case['relative_us'],
                      'start_offset_us': entry['start_offset_us']})
        analysis_cases[case['case_id']] = dict(case, ethernet_tag_hex=tag.hex())
    return plans, analysis_cases


def failure_outcome(case, model, kind, error, *, attempted=True):
    return {'case_id': case['case_id'], 'original_record_id': case['case_id'], 'model': model,
            'label': label_of(case), 'transport_passed': False, 'parity_passed': False,
            'verification_passed': False, 'classified': False, 'prediction': None, 'class': None,
            'attempted': attempted, 'status': 'failed' if attempted else 'not_attempted',
            'failure_kind': kind, 'error': str(error)}


def analyze_transport(cases, observations, export):
    outcomes = []
    for case_id, case in cases.items():
        item = observations['cases'][case_id]
        if not item['transport_passed']:
            outcome = failure_outcome(case, export['feature_set'], 'transport_failure',
                      {'errors': item['errors'], 'missing_input_indices': item['missing_input_indices'],
                       'missing_output_indices': item['missing_output_indices']})
        else:
            frames = [bytes.fromhex(row['frame_hex']) for row in item['output_observations']]
            outcome = analysis.compare_case(case, export, frames)
            outcome['attempted'] = True
            outcome['transport_passed'] = True
            outcome['verification_passed'] = bool(outcome['parity_passed'])
        outcome['input_observed'] = len(item['input_observations'])
        outcome['output_observed'] = len(item['output_observations'])
        outcome['sent_packets'] = len(item['sent_logs'])
        outcome['send_lateness_us'] = [row['send_lateness_ns'] / 1000 for row in item['sent_logs']]
        outcomes.append(outcome)
    return outcomes


def check_counters(counters, outcomes, cases):
    """Reconcile exact counts/bytes only when all report streams are trustworthy."""
    if not all(row['transport_passed'] and row['parity_passed'] for row in outcomes):
        return {'checked': False, 'reason': 'Missing/corrupt reports prevent complete batch reconciliation',
                'actual': counters}
    expected_packets, expected_bytes = [0] * 6, [0] * 6
    for row in outcomes:
        if row['classified']:
            index = row['prediction']
            expected_packets[index] += 1
            expected_bytes[index] += 14 + len(bytes.fromhex(cases[row['case_id']]['packets'][7]['raw_ip_hex']))
    passed = ([counters[i]['packets'] for i in range(6)] == expected_packets and
              [counters[i]['bytes'] for i in range(6)] == expected_bytes)
    return {'checked': True, 'passed': passed, 'actual': counters,
            'expected_packets': expected_packets, 'expected_bytes': expected_bytes}


def batch_clock_quality(observations):
    """Check across cases too, correlated by input occurrence, not output order."""
    timeline = []
    expected = 8 * len(observations['cases'])
    for case_id, item in observations['cases'].items():
        by_index = {row['packet_index']: row for row in item['output_observations']}
        for incoming in item['input_observations']:
            index = incoming['packet_index']
            if index in by_index:
                report = helpers.decode_report(bytes.fromhex(by_index[index]['frame_hex']))
                timeline.append((incoming['monotonic_ns'], case_id, index, report['observed_us']))
    timeline.sort()
    quality = analysis.clock_quality([entry[3] for entry in timeline])
    quality['matched_packets'] = len(timeline)
    quality['expected_packets'] = expected
    quality['complete'] = len(timeline) == expected
    quality['clean'] = quality['clean'] and quality['complete']
    quality['ordering'] = 'Observed input monotonic order, correlated output occurrence index'
    for event in quality['events']:
        previous, current = timeline[event['position'] - 2:event['position']]
        event['previous_case_id'], event['case_id'] = previous[1], current[1]
        event['previous_packet_position'], event['packet_position'] = previous[2] + 1, current[2] + 1
    return quality


def run_batch(args, program, batch, by_id, export, links, directory):
    directory.mkdir()
    plans, cases = frame_plans(batch, by_id)
    write_json(directory / 'case_plan.json', [{'case_id': p['case_id'], 'ethernet_tag_hex': p['frames'][0][:12].hex(),
               'start_offset_us': p['start_offset_us'], 'relative_us': p['relative_us']} for p in plans])
    port = helpers.free_port()
    argv = [str(args.switch), '-i', f'1@{links.names[0]}', '-i', f'2@{links.names[2]}',
            '--thrift-port', str(port), '--device-id', str(100000 + uuid.uuid4().int % 100000000),
            '--notifications-addr', 'ipc://notifications.ipc', '--log-console', '-L', 'info', str(program)]
    write_json(directory / 'switch_command.json', argv)
    timeout = batch['scheduled_span_us'] / 1_000_000 + args.grace_seconds
    with (directory / 'switch.log').open('x') as log:
        process = subprocess.Popen(argv, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            pilot_runner.wait_ready(process, directory / 'switch.log')
            observations = transport.replay_batch(plans, links.names[1], links.names[3], timeout,
                                                  key_from_output=pilot_runner.output_key)
            write_json(directory / 'transport.json', observations)
            outcomes = analyze_transport(cases, observations, export)
            try:
                batch_quality = batch_clock_quality(observations)
            except (ValueError, KeyError, IndexError) as error:
                batch_quality = {'clean': False, 'error': str(error), 'complete': False}
            write_json(directory / 'batch_clock_quality.json', batch_quality)
            for side in ('input', 'output'):
                records = [row for item in observations['cases'].values() for row in item[side + '_observations']]
                pilot_runner.write_observed_pcap(directory / f'{side}.pcap', sorted(records, key=lambda r: r['monotonic_ns']))
            try:
                counters = pilot_runner.read_counters(args, port, directory)
                counter_check = check_counters(counters, outcomes, cases)
                if counter_check['checked'] and not counter_check['passed']:
                    for outcome in outcomes:
                        outcome.update(verification_passed=False, status='failed',
                                       failure_kind='batch_counter_mismatch', error='Six-class counts/bytes disagree')
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                counter_check = {'checked': False, 'error': str(error)}
                for outcome in outcomes:
                    outcome.update(verification_passed=False, status='failed', failure_kind='counter_query_failed', error=str(error))
            write_json(directory / 'counter_check.json', counter_check)
            for outcome in outcomes:
                outcome['batch_id'] = batch['batch_id']
                outcome['switch_pid'] = process.pid
                outcome['thrift_port'] = port
                # A missing case's deadline does not erase other fully verified cases.
                # Global issues still prevent declaring the overall stage fully passed.
                outcome['batch_transport_errors'] = observations.get('global_errors', [])
                outcome['batch_clock_quality'] = batch_quality
            write_jsonl(directory / 'outcomes.jsonl', outcomes)
            return outcomes
        finally:
            pilot_runner.stop_child(process)


def offline_shared_vectors(outcomes, exports):
    """Diagnostic only: both forests on each SAME observed vector, not two live results."""
    rows = []
    for outcome in outcomes:
        features = outcome.get('native_features_C', outcome.get('features_C'))
        if features is None and isinstance(outcome.get('decision'), dict):
            features = outcome['decision'].get('features_C')
        if (outcome.get('classified') and outcome.get('parity_passed') and
                outcome.get('verification_passed', True) and features is not None):
            rows.append({'case_id': outcome['case_id'], 'observed_in_model_run': outcome['model'],
                         'label': outcome['label'], 'features_C': features,
                         'offline_predictions': {s: pilot_runner.predict(exports[s], features) for s in 'BC'}})
    return rows


def native_model_fidelity(population, outcomes, exports):
    """Check sealed original sklearn models on their own new observed vectors.

    No fit, tuning, feature changes or new accuracy experiment occurs here.
    Pickle/joblib inputs are only our locally-created, SHA-256-sealed artifacts.
    """
    report = {}
    for model in 'BC':
        rows = [row for row in outcomes if row['model'] == model and
                row.get('transport_passed') and row.get('parity_passed') and
                row.get('verification_passed', True) and row.get('classified')]
        if not rows:
            report[model] = {'tested_vectors': 0, 'passed': None,
                             'reason': 'No verified classified native feature vectors'}
            continue
        path = (Path(population['deployment']) / f'n8_RF_{model}/model.joblib').resolve()
        require(str(path) in population['input_sha256'] and
                native_prefix.sha256_file(path) == population['input_sha256'][str(path)],
                'Original trusted RF artifact missing or changed; refusing deserialization')
        sklearn_model = reference.baseline.joblib.load(path)
        features = [row['features_C'] for row in rows]
        vectors = [[item[name] for name in exports[model]['feature_order']] for item in features]
        current = reference.verify_parity(sklearn_model, exports[model], vectors)
        current['case_ids_in_vector_order'] = [row['case_id'] for row in rows]
        current['model_sha256'] = population['input_sha256'][str(path)]
        report[model] = current
    return report


def distribution(values):
    values = list(values)
    if not values:
        return {'count': 0, 'mean': None, 'median': None, 'p95': None, 'p99': None, 'minimum': None, 'maximum': None}
    array = np.asarray(values, dtype=float)
    return {'count': len(values), 'mean': float(array.mean()), 'median': float(np.median(array)),
            'p95': float(np.percentile(array, 95)), 'p99': float(np.percentile(array, 99)),
            'minimum': float(array.min()), 'maximum': float(array.max())}


def timing_summary(outcomes):
    result = {}
    for model in 'BC':
        rows = [row for row in outcomes if row['model'] == model]
        verified = [row for row in rows if row.get('transport_passed') and row.get('parity_passed')
                    and row.get('verification_passed', True) and row.get('timing') is not None]
        deltas = [gap for row in verified for gap in row['timing']['native_minus_original_iats_us']]
        spans = [row['timing']['native_prefix_duration_us'] - row['timing']['original_prefix_duration_us']
                 for row in verified]
        result[model] = {'verified_timing_records': len(verified),
                         'signed_gap_deviation_us': distribution(deltas),
                         'absolute_gap_deviation_us': distribution(abs(value) for value in deltas),
                         'signed_prefix_span_deviation_us': distribution(spans),
                         'absolute_prefix_span_deviation_us': distribution(abs(value) for value in spans),
                         'sender_lateness_us_all_observed_sends': distribution(
                             value for row in rows for value in row.get('send_lateness_us', [])),
                         'observed_prefix_span_us': distribution(
                             row['timing']['native_prefix_duration_us'] for row in verified),
                         'meaning': 'Packet scheduling/ingress-clock deviations, NOT forwarding or RF execution latency'}
    return result


def finalize(directory, population, outcomes, exports, *, completed, cleanup_passed, execution_error=None,
             model_fidelity=None):
    intended = {(case['case_id'], model): case for case in population['cases'] for model in 'BC'}
    done = {(row['case_id'], row['model']) for row in outcomes}
    require(len(done) == len(outcomes) and done <= set(intended), 'Duplicate/unexpected model-case outcome')
    for case_id, model in sorted(set(intended) - done):
        outcomes.append(failure_outcome(intended[(case_id, model)], model, 'not_attempted',
                        execution_error or 'Evaluation did not complete', attempted=False))
    write_jsonl(directory / 'outcomes.jsonl', outcomes)
    write_jsonl(directory / 'offline_shared_vectors.jsonl', offline_shared_vectors(outcomes, exports))
    metrics = analysis.summarize(population['cases'], outcomes)
    metrics['timing_deviation'] = timing_summary(outcomes)
    metrics['input_integrity_and_execution_completed'] = completed and execution_error is None
    metrics['original_sklearn_to_integer_native_vector_parity'] = model_fidelity
    write_json(directory / 'metrics.json', metrics)
    good = [row for row in outcomes if row.get('transport_passed') and row.get('parity_passed') and
            row.get('verification_passed', True) and row.get('classified')]
    stage_transport_errors = sorted({error for row in outcomes for error in row.get('batch_transport_errors', [])})
    clock_clean = (len(outcomes) == 2 * EXPECTED_CASES and
                   all((row.get('clock_quality') or {}).get('clean') is True and
                       (row.get('batch_clock_quality', {'clean': True}) or {}).get('clean') is True
                       for row in outcomes))
    fidelity_ok = model_fidelity is None or all(model_fidelity[s].get('passed') is True for s in 'BC')
    passed = (completed and execution_error is None and cleanup_passed and fidelity_ok and clock_clean and
              len(good) == 2 * EXPECTED_CASES and not stage_transport_errors)
    summary = {'status': 'native_evaluation_passed' if passed else 'native_evaluation_incomplete',
               'passed': passed, 'native_clock': True, 'accuracy_scored': True, 'performance_measured': False,
               'whole_capture_replay': False, 'debug_reports': True, 'expected_cases_per_model': EXPECTED_CASES,
               'expected_model_case_evaluations': 2 * EXPECTED_CASES, 'verified_classified_evaluations': len(good),
               'execution_completed': completed, 'cleanup_passed': cleanup_passed, 'execution_error': execution_error,
               'stage_transport_errors': stage_transport_errors,
               'raw_clock_clean': clock_clean,
               'original_sklearn_to_integer_native_vector_parity': model_fidelity,
               'labels_verified': False, 'preliminary': True, 'new_fits': 0,
               'model_outcome_counts': {s: dict(Counter(row['status'] for row in outcomes if row['model'] == s)) for s in 'BC'},
               'metrics_file': 'metrics.json', 'limitations': [
                   'Isolated first-eight prefixes, concurrently batched with disjoint keys/slots, not whole-capture replay.',
                   'Different B/C native runs may have different jitter; shared-vector predictions are offline diagnostics only.',
                   'Capture-derived labels are not independently verified per-flow activity ground truth.',
                   'Previously inspected held-out set; no new independent test set or tuning.',
                   'Debug headers/work prevent performance conclusions; socket-read times are not switch latency.',
                   'Conditional accuracy/F1 do not silently count missing or unclassified instances as successful predictions.']}
    if not passed:
        write_json(directory / 'failure.json', {'error': execution_error or 'Some intended evaluations, raw-clock checks or model-fidelity checks did not pass',
                   'verified_classified': len(good), 'expected': 2 * EXPECTED_CASES, 'coverage_required_for_full_pass': 1.0})
    summary['output_sha256'] = seal(directory)
    write_json(directory / 'summary.json', summary)
    return summary, metrics


def run(args, repo):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Use sudo in Ubuntu for live raw sockets and private veths')
    require(math.isfinite(args.grace_seconds) and 2 <= args.grace_seconds <= 15, 'Grace period must be 2..15 seconds')
    require(shutil.which('ip') and shutil.which('sysctl'), 'iproute2/sysctl unavailable')
    for tool in (args.switch, args.cli_python, args.switch.with_name('simple_switch_CLI')):
        require(tool.is_file(), f'Required tool missing: {tool}')
    population, plan, manifest, exports, by_id = load_prepared(args.prepared)
    receipt = clock_contract.verify_receipt(manifest['clock_source_receipt'], args.switch)
    directory = pilot_runner.new_directory(args.output_root or repo / 'results/native_evaluation')
    outcomes, completed, execution_error = [], False, None
    interrupted = False
    links = pilot_runner.OwnedLinks(uuid.uuid4().hex[:6])
    try:
        write_json(directory / 'provenance.json', {'prepared': str(args.prepared.resolve()),
                   'prepared_manifest_sha256': native_prefix.sha256_file(args.prepared / 'manifest.json'),
                   'switch_sha256': native_prefix.sha256_file(args.switch), 'versions': versions(),
                   'clock_source_receipt': receipt,
                   'models': ['B', 'C'], 'native_clock': True, 'injected_timestamps': False,
                   'gap_scaling': False, 'interfaces': links.names, 'batch_size': max(len(b['cases']) for b in plan['batches']),
                   'model_order': 'B,C on even batches; C,B on odd batches', 'repetitions': 1,
                   'accuracy_labels': 'frozen provisional capture-derived six-class labels',
                   'grace_seconds': args.grace_seconds})
        print(f'Starting {len(plan["batches"])} batches/model; 398 cases/model, 796 evaluations. No fitting or gap scaling.', flush=True)
        with links:
            write_json(directory / 'interfaces.json', links.owned)
            for index, batch in enumerate(plan['batches']):
                for model in ('BC' if index % 2 == 0 else 'CB'):
                    target = directory / f'batch_{index + 1:03d}_RF_{model}'
                    print(f"Starting batch {index + 1}/{len(plan['batches'])}, RF-{model}: "
                          f"{len(batch['cases'])} cases; preserved schedule {batch['scheduled_span_us'] / 1_000_000:.2f}s "
                          '(progress next prints after this batch)', flush=True)
                    try:
                        current = run_batch(args, Path(manifest['programs'][model]['path']), batch, by_id,
                                            exports[model], links, target)
                    except KeyboardInterrupt:
                        # This batch started; do not describe its partly sent cases as never attempted.
                        outcomes.extend(failure_outcome(by_id[entry['case_id']], model, 'interrupted_batch',
                                        'Interrupted during this batch; complete native evidence unavailable')
                                        for entry in batch['cases'])
                        raise
                    except (ValueError, OSError, subprocess.SubprocessError) as error:
                        current = [failure_outcome(by_id[entry['case_id']], model, 'batch_execution_error', error)
                                   for entry in batch['cases']]
                        if target.is_dir() and not (target / 'batch_failure.json').exists():
                            write_json(target / 'batch_failure.json', {'error': str(error)})
                    outcomes.extend(current)
                    good = sum(row.get('transport_passed') and row.get('parity_passed') and
                               row.get('verification_passed', True) and row.get('classified') for row in current)
                    print(f"Batch {index + 1}/{len(plan['batches'])}, RF-{model}: verified/classified {good}/{len(current)}; total accounted {len(outcomes)}/796", flush=True)
            completed = True
        require(not links.cleanup_errors, f'Private-interface cleanup failed: {links.cleanup_errors}')
        pilot_runner.verify_hashes(population['input_sha256'])
    except KeyboardInterrupt:
        interrupted, execution_error = True, 'User interrupted; remaining original cases recorded as not_attempted'
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        execution_error = str(error)
    try:
        try:
            model_fidelity = native_model_fidelity(population, outcomes, exports)
        except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
            model_fidelity = {s: {'passed': False, 'error': str(error)} for s in 'BC'}
            execution_error = execution_error or f'Native original-model fidelity check failed: {error}'
        summary, _ = finalize(directory, population, outcomes, exports, completed=completed,
                              cleanup_passed=not links.cleanup_errors, execution_error=execution_error,
                              model_fidelity=model_fidelity)
        print(('NATIVE EVALUATION PASS' if summary['passed'] else 'NATIVE EVALUATION INCOMPLETE') +
              f" — coverage/parity accounted; preliminary capture-label accuracy. Evidence saved to: {directory}", flush=True)
        print(f'Metrics: {directory / "metrics.json"}', flush=True)
        return directory, summary['passed'], interrupted
    finally:
        pilot_runner.restore_new_evidence_owner(directory)


def smoke(args, repo):
    """All398 actual bytes through native builds, but unpaced file mode, no accuracy scoring."""
    population, plan, manifest, exports, by_id = load_prepared(args.prepared)
    directory = pilot_runner.new_directory(args.output_root or repo / 'results/native_evaluation_checks')
    counts = {'B': 0, 'C': 0}
    all_comparisons = []
    try:
        write_json(directory / 'provenance.json', {'mode': 'unpaced native-clock BMv2 packet-file integration',
                   'live_interfaces_used': False, 'accuracy_scored': False, 'performance_measured': False,
                   'prepared': str(args.prepared.resolve()), 'prepared_manifest_sha256': native_prefix.sha256_file(args.prepared / 'manifest.json'),
                   'switch_sha256': native_prefix.sha256_file(args.switch)})
        for index, batch in enumerate(plan['batches']):
            for model in 'BC':
                plans, cases = frame_plans(batch, by_id)
                events = sorted((p['start_offset_us'] + offset, rank, packet_index, p['frames'][packet_index])
                                for rank, p in enumerate(plans) for packet_index, offset in enumerate(p['relative_us']))
                frames = [event[3] for event in events]
                child = directory / f'batch_{index + 1:03d}_RF_{model}'
                output = helpers.run_switch(args.switch, Path(manifest['programs'][model]['path']), child,
                                            frames, len(frames), timeout=30)
                require(isinstance(output, list), 'Unexpected existing file-mode helper return type')
                grouped = {case_id: [] for case_id in cases}
                tags = {bytes.fromhex(case['ethernet_tag_hex']): case_id for case_id, case in cases.items()}
                for frame in output:
                    require(frame[:12] in tags, 'Unrecognized smoke output tag')
                    grouped[tags[frame[:12]]].append(frame)
                comparisons = [analysis.compare_case(cases[case_id], exports[model], rows)
                               for case_id, rows in grouped.items()]
                require(all(row['parity_passed'] and row['classified'] for row in comparisons),
                        f'Packet-file integration comparison failed, batch {index + 1}, RF-{model}')
                # Classes exist internally to check inference, but no aggregate accuracy/F1 here.
                write_jsonl(child / 'comparisons.jsonl', comparisons)
                counts[model] += len(comparisons)
                all_comparisons.extend(comparisons)
            print(f"Packet-file smoke batch {index + 1}/{len(plan['batches'])}: B/C integration PASS", flush=True)
        require(counts == {'B': EXPECTED_CASES, 'C': EXPECTED_CASES}, 'Smoke omitted frozen records')
        pilot_runner.verify_hashes(population['input_sha256'])
        fidelity = native_model_fidelity(population, all_comparisons, exports)
        write_json(directory / 'original_model_fidelity.json', fidelity)
        require(all(fidelity[s]['passed'] for s in 'BC'), 'Original RF/integer parity changed on smoke native vectors')
        write_json(directory / 'summary.json', {'status': 'native_packet_file_integration_passed', 'passed': True,
                   'cases': counts, 'packets_per_model': 8 * EXPECTED_CASES,
                   'feature_leaf_score_class_mismatches': 0, 'mode': 'unpaced packet-file integration',
                   'original_sklearn_to_integer_native_vector_parity_passed': True,
                   'live_interfaces_used': False, 'accuracy_scored': False, 'performance_measured': False,
                   'output_sha256': seal(directory)})
    except BaseException as error:
        write_json(directory / 'failure.json', {'error': str(error)})
        raise
    print(f'PACKET-FILE INTEGRATION PASS — not live accuracy/performance. Evidence saved to: {directory}', flush=True)
    return directory


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare', help='All398 original records and separate native builds; no traffic')
    prep.add_argument('--p4c', type=Path, default=repo.parent / 'p4c-build/p4c')
    prep.add_argument('--batch-size', type=int, default=32)
    prep.add_argument('--start-spacing-us', type=int, default=2000)
    prep.add_argument('--clock-receipt', type=Path, required=True)
    prep.add_argument('--pilot-run', type=Path, required=True, help='Clean live pilot on this exact clock build')
    prep.add_argument('--output-root', type=Path)
    for action in ('run', 'smoke'):
        stage = sub.add_parser(action, help='Live sudo evaluation' if action == 'run' else 'Non-root unpaced integration checks only')
        stage.add_argument('--prepared', type=Path, required=True)
        stage.add_argument('--switch', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
        stage.add_argument('--output-root', type=Path)
        if action == 'run':
            stage.add_argument('--cli-python', type=Path, default=repo.parent / 'bmv2-venv/bin/python')
            stage.add_argument('--grace-seconds', type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare':
            prepare(args, repo)
        elif args.action == 'smoke':
            smoke(args, repo)
        else:
            _, passed, interrupted = run(args, repo)
            return 130 if interrupted else (0 if passed else 2)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted. Existing evidence preserved; owned-resource cleanup attempted.', file=sys.stderr)
        return 130
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
