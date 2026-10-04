#!/usr/bin/env python3
"""Generate and verify RF-B/C inference in BMv2; no fitting or accuracy scoring.

Uses sealed development/numeric vectors, then synthetic packets through the
shared feature extractor. Packet-file tests do not measure live performance.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import uuid

import generate_rf_p4 as generator
import prepare_rf_deployment as reference
import rf_parity_probes as probes
import test_p4_features as feature_tests

require = feature_tests.require
digest = feature_tests.digest
write_json = feature_tests.write_json
RF_MAGIC = 0x52464952
VECTOR_MAGIC = 0x52465654


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def read_rows(path):
    with Path(path).open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def load_deployment(directory):
    """Verify sealed artifacts without loading pickle models or test data."""
    directory = Path(directory).resolve()
    require(not (directory / 'failure.json').exists(), 'Deployment has failure marker')
    summary = read_json(directory / 'summary.json')
    config = read_json(directory / 'run_config.json')
    require(config['new_test_predictions'] == 0 and config['new_hyperparameter_search'] is False,
            'Expected development-only selected RF deployment')
    required = {'feature_contract.json', 'run_config.json'}
    for s in ('B', 'C'):
        required.update({f'development_vectors_{s}.jsonl', f'n8_RF_{s}/forest_integer.json',
                         f'n8_RF_{s}/diagnostic_vectors.jsonl', f'n8_RF_{s}/parity.json',
                         f'n8_RF_{s}/model.joblib'})
    sealed = summary['output_sha256']
    require(required <= set(sealed), 'Required deployment artifacts are not sealed')
    for name, expected in sealed.items():
        path = (directory / name).resolve()
        require(path.is_relative_to(directory) and path.is_file(), 'Unsafe/missing sealed artifact')
        require(digest(path) == expected, f'Deployment artifact changed: {name}')
    exports, development, diagnostics = {}, {}, {}
    for s in ('B', 'C'):
        exports[s] = read_json(directory / f'n8_RF_{s}/forest_integer.json')
        reference.validate_export(exports[s])
        require(exports[s]['feature_set'] == s, 'Swapped export feature set')
        experiment = summary['experiments'][f'n8_RF_{s}']
        require(experiment['passed'] and experiment['development']['passed'] and
                experiment['diagnostic']['passed'], 'RF integer preparation did not pass')
        development[s] = read_rows(directory / f'development_vectors_{s}.jsonl')
        diagnostics[s] = read_rows(directory / f'n8_RF_{s}/diagnostic_vectors.jsonl')
        require(len(development[s]) == summary['development_records'] == config['development_records'],
                'Development population count changed')
        require(len(diagnostics[s]) == experiment['diagnostic']['tested_vectors'], 'Diagnostic count changed')
        rows = [r['features'] for r in development[s]]
        _, _, scores = reference.predict_export(exports[s], rows)
        require(scores.tolist() == [r['integer_scores'] for r in development[s]] and
                scores.argmax(axis=1).tolist() == [r['integer_class'] for r in development[s]],
                'Saved development integer predictions disagree with export')
    require([(r['record_id'], r['parent_group'], r['features']) for r in development['B']] ==
            [(r['record_id'], r['parent_group'], r['features'][:6]) for r in development['C']],
            'B/C development observations are not paired')
    return exports, development, diagnostics


def decode_rf(frame, offset):
    require(len(frame) >= offset + 52, 'Missing RF debug header')
    fields = struct.unpack_from('!IBBBB10H6I', frame, offset)
    magic, version, valid, model, prediction = fields[:5]
    require(magic == RF_MAGIC and version == 1, 'Unknown RF report format')
    require(valid in (0, 1), 'Invalid RF valid bit')
    return {'valid': valid, 'model': model, 'prediction': prediction,
            'leaves': list(fields[5:15]), 'scores': list(fields[15:21])}


def check_rf(report, feature_set, expected=None):
    """Compare intermediates first so a failure identifies its layer."""
    require(report['model'] == ('BC'.index(feature_set)), 'Wrong RF model identifier')
    if expected is None:
        require(report['valid'] == 0 and report['prediction'] == 255 and
                report['leaves'] == [0] * 10 and report['scores'] == [0] * 6,
                'RF ran or stale inference data leaked outside a decision event')
        return
    require(report['valid'] == 1, 'Missing packet-eight/vector classification')
    require(report['leaves'] == expected['leaves'], 'RF leaf ID mismatch')
    require(report['scores'] == expected['scores'], 'RF class-score sum mismatch')
    require(report['prediction'] == expected['prediction'], 'RF argmax/tie-break mismatch')


def padded(row):
    require(len(row) in (6, 8), 'Expected B or C feature vector')
    return list(row) + [0] * (8 - len(row))


def vector_frame(number, row, magic=VECTOR_MAGIC):
    return bytes.fromhex('02000000000202000000000188b7') + struct.pack('!II8I', magic, number, *padded(row))


def compare_vectors(export, rows, frames):
    require(len(frames) == len(rows), 'Missing/extra vector output packets')
    leaves, _, scores = reference.predict_export(export, rows)
    predictions = scores.argmax(axis=1).tolist()
    reports = []
    for i, (row, frame) in enumerate(zip(rows, frames, strict=True)):
        require(frame[12:14] == b'\x88\xb8', 'Not a vector test response')
        require(len(frame) >= 106, 'Truncated vector response')
        echo = struct.unpack_from('!II8I', frame, 14)
        require(echo == (VECTOR_MAGIC, i + 1, *padded(row)), 'Vector/order changed before inference')
        report = decode_rf(frame, 54)
        check_rf(report, export['feature_set'], {'leaves': leaves[i].tolist(),
                 'scores': scores[i].tolist(), 'prediction': predictions[i]})
        reports.append({'packet_id': i + 1, **report})
    return {'vectors': len(rows), 'leaf_mismatches': 0, 'score_mismatches': 0,
            'class_mismatches': 0, 'coverage': probes.coverage(export, rows)}, reports


def require_full_coverage(coverage):
    for kind in ('nodes', 'leaves', 'branches'):
        require(coverage[kind]['covered'] == coverage[kind]['reachable'] and
                not coverage['uncovered_' + kind], f'Missing reachable RF {kind} coverage')


def compare_integrated(export, events, frames, controlled, collision=False):
    feature_reports = [feature_tests.decode_report(f) for f in frames]
    result = feature_tests.compare(events, feature_reports, controlled, collision)
    decisions = result['decisions_detail']
    rows = [[r['features_C'][k] for k in export['feature_order']] for r in decisions]
    require(rows, 'Fixture produced no decision events')
    leaves, _, scores = reference.predict_export(export, rows)
    expected = {r['packet_id']: {'leaves': leaves[i].tolist(), 'scores': scores[i].tolist(),
                               'prediction': int(scores[i].argmax())} for i, r in enumerate(decisions)}
    reports = []
    for f, feature in zip(frames, feature_reports, strict=True):
        report = decode_rf(f, 85)  # Ethernet(14) + existing feature report(71).
        check_rf(report, export['feature_set'], expected.get(feature['packet_id']))
        reports.append({'feature_report': feature, 'rf_report': report})
    result.update({'leaf_mismatches': 0, 'score_mismatches': 0, 'class_mismatches': 0,
                   'decision_class_counts': [sum(r['prediction'] == i for r in expected.values()) for i in range(6)]})
    return result, reports


def native_events():
    return [feature_tests.event(i + 1, flow=20 + i % 2, stamp=1000 + i,
                reverse=i % 3 == 0, proto=6 if i % 2 else 17, size=70 + i,
                ip_options=i % 4 == 0, tcp_options=i % 2 == 1) for i in range(24)]


def compile_program(p4c, source, directory, controlled=False, debug=True, slots=65536):
    return feature_tests.compile_program(p4c, source, directory, controlled, debug, slots).resolve()


def run_forwarding(args, program, directory, frames, ingress_port):
    """Read counters while our own file-mode child is alive; never attach elsewhere."""
    directory.mkdir()
    feature_tests.write_pcap(directory / 'input_in.pcap', frames if ingress_port == 1 else [])
    feature_tests.write_pcap(directory / 'output_in.pcap', frames if ingress_port == 2 else [])
    output = directory / ('output_out.pcap' if ingress_port == 1 else 'input_out.pcap')
    port = feature_tests.free_port()
    command = [str(args.switch), '--use-files', '1', '-i', '1@input', '-i', '2@output',
               '--thrift-port', str(port), '--device-id', str(100000 + uuid.uuid4().int % 100000000),
               '--notifications-addr', 'ipc://notifications.ipc', '--log-console', '-L', 'warn', str(program)]
    write_json(directory / 'command.json', command)
    with (directory / 'switch.log').open('x') as log:
        process = subprocess.Popen(command, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 30
            complete = None
            while time.monotonic() < deadline:
                require(process.poll() is None, 'Private BMv2 forwarding child exited early')
                received = feature_tests.read_pcap(output, partial=True)
                require(len(received) <= len(frames), 'Extra forwarding packets')
                if len(received) == len(frames):
                    complete = complete or time.monotonic()
                    if time.monotonic() - complete >= .3:
                        break
                time.sleep(.03)
            else:
                raise ValueError('Normal-build forwarding timed out')
            env = dict(os.environ)
            env['PYTHONPATH'] = str(args.switch.parents[2] / 'tools') + os.pathsep + env.get('PYTHONPATH', '')
            cli_command = [str(args.cli_python), str(args.cli), '--thrift-port', str(port)]
            queries = ''.join(f'counter_read FeatureIngress.rf_decisions {i}\n' for i in range(6))
            cli = subprocess.run(cli_command, input=queries, capture_output=True, text=True, env=env, timeout=20)
            write_json(directory / 'counter_query.json', {'command': cli_command, 'input': queries,
                'returncode': cli.returncode, 'stdout': cli.stdout, 'stderr': cli.stderr})
            require(cli.returncode == 0, 'Counter CLI failed; inspect counter_query.json')
            matches = re.findall(r'rf_decisions\[(\d+)\]=\s*\((\d+) bytes, (\d+) packets\)', cli.stdout)
            require(len(matches) == 6 and {int(i) for i, _, _ in matches} == set(range(6)),
                    'Missing/duplicate six-class decision counter values')
            counts = {int(i): int(packets) for i, _, packets in matches}
            require(sum(counts.values()) == 2, 'Normal build must classify the two flows exactly once')
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    require(feature_tests.read_pcap(output) == frames, 'Normal forwarding changed packet bytes/order')
    return {'packets': len(frames), 'unchanged_forwarded_packets': len(frames),
            'decisions': sum(counts.values()), 'class_counters': [counts[i] for i in range(6)]}


def invalid_vector_check(args, export, program, directory):
    """Valid headers with invalid magic/domain must not execute inference."""
    zero = [0] * 8
    frames = [vector_frame(1, zero, magic=0)]
    for j, name in enumerate(reference.FEATURES['C']):
        row = zero.copy()
        row[j] = reference.DOMAINS[name]['max'] + 1
        frames.append(vector_frame(len(frames) + 1, row))
    # A valid final input also checks recovery after invalid vectors.
    frames.append(vector_frame(len(frames) + 1, zero))
    output = feature_tests.run_switch(args.switch, program, directory, frames, len(frames), timeout=30)
    for i, frame in enumerate(output):
        require(frame[12:14] == b'\x88\xb8' and frame[14:54] == frames[i][14:54],
                'Invalid-vector probe response ID/features/order changed')
        if i < len(output) - 1:
            check_rf(decode_rf(frame, 54), export['feature_set'])
    leaves, _, scores = reference.predict_export(export, [zero[:len(export['feature_order'])]])
    check_rf(decode_rf(output[-1], 54), export['feature_set'], {'leaves': leaves[0].tolist(),
              'scores': scores[0].tolist(), 'prediction': int(scores[0].argmax())})
    return {'rejected_vectors': len(frames) - 1, 'subsequent_valid_vectors': 1}


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=repo / 'p4/flow_features.p4')
    parser.add_argument('--p4c', type=Path, default=Path.home() / 'p4/p4c-build/p4c')
    parser.add_argument('--switch', type=Path, default=Path.home() / 'p4/behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--cli-python', type=Path, default=Path.home() / 'p4/bmv2-venv/bin/python')
    parser.add_argument('--cli', type=Path, default=Path.home() / 'p4/behavioral-model/targets/simple_switch/simple_switch_CLI')
    parser.add_argument('--output-root', type=Path, default=repo / 'results/rf_integration')
    args = parser.parse_args(argv)
    run = None
    try:
        for name in ('deployment', 'source', 'p4c', 'switch', 'cli', 'output_root'):
            setattr(args, name, getattr(args, name).expanduser().resolve())
        # Preserve symlinked venv executable path: resolving it selects system Python.
        args.cli_python = args.cli_python.expanduser().absolute()
        for path in (args.source, args.p4c, args.switch, args.cli_python, args.cli):
            require(path.is_file(), f'Required file missing: {path}')
        require(not args.output_root.is_relative_to(args.deployment), 'Output cannot be inside sealed deployment')
        exports, development, diagnostics = load_deployment(args.deployment)
        sources = sorted(Path(__file__).resolve().parent.glob('*.py')) + [args.source]
        sources += [args.deployment / 'summary.json']
        before = {str(p): digest(p) for p in sources}
        args.output_root.mkdir(parents=True, exist_ok=True)
        run = args.output_root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:10])
        run.mkdir()
        write_json(run / 'provenance.json', {'source_sha256': before, 'deployment': str(args.deployment),
            'p4c_sha256': digest(args.p4c), 'switch_sha256': digest(args.switch),
            'new_fits': 0, 'test_records_scored': 0, 'mode': 'BMv2 packet-file correctness, unpaced',
            'not_tested': ['real capture replay', 'live interfaces', 'throughput/latency',
                           'hardware resources', 'full original floating RF domain equivalence', 'clock wrap']})
        results = {}
        base = args.source.read_text(encoding='utf-8')
        for s, export in exports.items():
            folder = run / ('RF_' + s)
            folder.mkdir()
            programs = generator.generate_sources(export, base)
            paths = {}
            for variant, source in programs.items():
                paths[variant] = folder / (variant + '.p4')
                paths[variant].write_text(source, encoding='utf-8')
            print(f'RF-{s}: compiling direct-feature classifier...', flush=True)
            vector_program = compile_program(args.p4c, paths['vectors'], folder / 'vectors.json')
            branch_rows = probes.branch_probes(export)
            blocks = {'development': [r['features'] for r in development[s]],
                      'saved_diagnostic': [r['features'] for r in diagnostics[s]], 'path_probes': branch_rows}
            rows = [r for block in blocks.values() for r in block]
            write_json(folder / 'vector_inputs.json', {'counts': {k: len(v) for k, v in blocks.items()}, 'features': rows})
            output = feature_tests.run_switch(args.switch, vector_program, folder / 'vectors',
                        [vector_frame(i + 1, r) for i, r in enumerate(rows)], len(rows), timeout=60)
            vector_result, vector_reports = compare_vectors(export, rows, output)
            require_full_coverage(vector_result['coverage'])
            vector_result['populations'] = {k: len(v) for k, v in blocks.items()}
            write_json(folder / 'vector_reports.json', vector_reports)
            model_results = {'vectors': vector_result,
                             'invalid_vectors': invalid_vector_check(args, export, vector_program, folder / 'invalid_vectors')}
            print(f"PASS RF-{s} vectors: {len(rows)}; leaves, scores and classes match.", flush=True)
            for mode, controlled, slots in [('controlled', True, 65536), ('native_clock', False, 65536), ('collision', True, 1)]:
                print(f'RF-{s}: compiling/running integrated {mode}...', flush=True)
                program = compile_program(args.p4c, paths['integrated'], folder / (mode + '.json'), controlled, True, slots)
                events = feature_tests.fixtures() if mode == 'controlled' else (
                    feature_tests.collision_fixture() if mode == 'collision' else native_events())
                write_json(folder / (mode + '_inputs.json'), events)
                frames = [feature_tests.wire_packet(e, controlled) for e in events]
                output = feature_tests.run_switch(args.switch, program, folder / mode, frames, len(frames), timeout=30)
                result, reports = compare_integrated(export, events, output, controlled, mode == 'collision')
                model_results[mode] = result
                write_json(folder / (mode + '_reports.json'), reports)
                print(f"PASS RF-{s} {mode}: {result['packets']} packets, {result['decisions']} decisions.", flush=True)
            print(f'RF-{s}: checking normal forwarding and actual inference counters...', flush=True)
            program = compile_program(args.p4c, paths['integrated'], folder / 'normal.json', False, False)
            compiled = read_json(program)
            require(any(c['name'] == 'FeatureIngress.rf_decisions' for c in compiled['counter_arrays']),
                    'Normal build has lost observable decision counters')
            frames = [feature_tests.wire_packet(e, False) for e in native_events()]
            for port in (1, 2):
                mode = f'forwarding_port{port}'
                model_results[mode] = run_forwarding(args, program, folder / mode, frames, port)
            results[s] = model_results
            write_json(folder / 'summary.json', model_results)
        print('Checking explicit tie, maximum-score and soft-vote fixtures in BMv2...', flush=True)
        synthetic = probes.synthetic_export()
        fixture_source = run / 'synthetic_vectors.p4'
        fixture_source.write_text(generator.generate_sources(synthetic, base)['vectors'], encoding='utf-8')
        program = compile_program(args.p4c, fixture_source, run / 'synthetic_vectors.json')
        rows = probes.synthetic_vectors()
        output = feature_tests.run_switch(args.switch, program, run / 'synthetic_vectors',
                    [vector_frame(i + 1, row) for i, row in enumerate(rows)], len(rows))
        synthetic_result, reports = compare_vectors(synthetic, rows, output)
        require([r['prediction'] for r in reports] == [0, 2, 5, 1], 'Synthetic tie/soft-vote expectation failed')
        require(reports[2]['scores'][5] == 10 * reference.SCALE, 'Max accumulator fixture failed')
        write_json(run / 'synthetic_fixture.json', {'export': synthetic, 'features': rows, 'reports': reports})
        require(before == {str(p): digest(p) for p in sources}, 'Input source changed during verification')
        load_deployment(args.deployment)  # Recheck sealed artifacts at completion.
        output_hashes = {str(p.relative_to(run)): digest(p) for p in sorted(run.rglob('*')) if p.is_file()}
        write_json(run / 'summary.json', {'status': 'rf_integration_passed', 'models': results,
            'synthetic_classifier': synthetic_result, 'new_fits': 0, 'test_records_scored': 0,
            'real_capture_replay_verified': False, 'live_performance_measured': False,
            'scope': 'Integer RF execution parity and synthetic feature-to-class integration, not classification accuracy',
            'output_sha256': output_hashes})
        print(f'RF INTEGRATION PASS — no retraining or new accuracy estimate.\nEvidence saved to: {run}')
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        if run is not None:
            write_json(run / 'failure.json', {'error': str(error), 'usable_as_success': False})
        print(f'ERROR: {error}\nEvidence: {run}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
