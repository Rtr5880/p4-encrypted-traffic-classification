#!/usr/bin/env python3
"""Bounded four-mode/two-workload RAW calibration, never a full sweep.

prepare and smoke are nonprivileged. run requires the user's explicit sudo
launch. No fitting, frozen P4 edits, clock adjustments or service changes.
"""
import argparse
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import uuid

import run_performance_benchmark as legacy
import run_performance_pilot as pilot
import integrate_rf as integration
import run_native_clock_pilot as ownership
import raw_benchmark_transport as transport
import raw_clock
import native_raw_paced_sender as sender_module
from raw_performance_resources import RawMeasurementResources

SCHEMA = 'raw-performance-calibration-v3'
require, write_json, hash_file = legacy.require, legacy.write_json, legacy.hash_file


def calibration_protocol(rates):
    require(type(rates) is list and 1 <= len(rates) <= 2 and len(set(rates)) == len(rates)
            and all(type(rate) is int and rate in (100, 1000) for rate in rates),
            'This bounded calibration supports only 100 and/or 1000pps, one repetition; no full sweep')
    return {'name': SCHEMA, 'rates_pps': sorted(rates), 'modes': list(legacy.MODES),
        'workloads': list(legacy.WORKLOADS), 'duration_seconds': 20, 'warmup_seconds': 5,
        'drain_seconds': 2, 'repetitions': 1, 'seed': 4022, 'frame_bytes': legacy.FRAME_BYTES,
        'concurrency': 8, 'normal_definitions': legacy.NORMAL,
        'pacing_gates': dict(legacy.GATES), 'clock_domain': 'CLOCK_MONOTONIC_RAW',
        'pacing_limit_basis': 'Prespecified engineering heuristics; not published or empirically validated universal measurement-validity bounds',
        'pacing_violation_action': 'Continue bounded acquisition; retain PASS/WARNING conformance separately; no automatic average-rate invalidation',
        'measurement_integrity_failure_action': 'Stop bounded acquisition; retain all attempted evidence',
        'comparison_basis': 'Qualified achieved loads and disclosed pacing distributions, not identical targets; existing 2% tolerance is descriptive screening only, not an equivalence gate',
        'sender_backend': sender_module.BACKEND_NAME, 'clock_sample_seconds': .005,
        'maximum_clock_sampling_gap_ns': 25_000_000, 'maximum_clock_bracket_ns': 100_000,
        'raw_rate_tolerance_ppm': 1000, 'qualification_minimum_span_seconds': 180,
        'qualification': 'Independent query-only network references before, during and after load; all-provider conservative bounds required',
        'reference_query_scheduling': 'Nonblocking measurement-window notifications; worker targets +2 RAW seconds; actual observed valid windows remain authoritative',
        'local_trial_summary_file': 'trial_summary.json',
        'qualified_trial_summary_file': 'qualified_trial_summary.json',
        'kernel_forwarding_latency_qualified': False, 'isolated_inference_latency_measured': False,
        'kernel_arrival_pacing_qualified': False,
        'direction_comparison': 'RF-B and RF-C both extract direction; deployed forest comparison only',
        'warmup_state_isolation': 'fresh switch; disjoint UDP keys AND disjoint CRC32 slots',
        'rate_meaning': 'successful sends / RAW window; delivered outputs include bounded drain / RAW offered window',
        'cpu_meaning': 'OS-accounted CPU seconds / RAW resource window, one-core convention; not independently calibrated CPU accounting',
        'new_fits': 0, 'accuracy_scored': False, 'maximum_trials': 16}


def source_inputs(repo):
    names = ('run_raw_performance_calibration.py', 'raw_benchmark_transport.py',
             'raw_clock.py', 'raw_clock_bracket.c', 'native_raw_paced_sender.py',
             'raw_paced_sender.c', 'raw_performance_resources.py', 'analyze_raw_performance.py')
    return {str((repo / 'tools' / name).resolve()): hash_file(repo / 'tools' / name) for name in names}


def prepare(args, repo):
    protocol = calibration_protocol(args.rates)
    base, receipt = legacy.load_prepared(args.base_prepared, args.switch)
    directory = ownership.new_directory(repo / 'results/raw_performance_calibration_preparation')
    try:
        clock_library = raw_clock.build_raw_clock_reader(repo=repo,
            output_root=directory / 'clock_backend')
        reader = raw_clock.RawClockReader(clock_library)
        sender_library = sender_module.build_native_raw_paced_sender(repo=repo,
            output_root=directory / 'sender_backend')
        sender = sender_module.NativeRawPacedSender(sender_library)
        blocks = legacy.build_schedule(protocol, uuid.uuid4().hex)
        # Ascending calibration loads; balanced mode order remains randomized.
        blocks.sort(key=lambda block: block['rate_pps'])
        for block in blocks:
            warm, measured = legacy.plans_for(block, protocol)
            block['plan_file'] = 'plans/' + block['block_id'] + '.json'
            (directory / 'plans').mkdir(exist_ok=True)
            write_json(directory / block['plan_file'], {'warmup': warm.manifest(),
                'measurement': measured.manifest(), 'warmup_frames_sha256': legacy.frame_hash(warm),
                'measurement_frames_sha256': legacy.frame_hash(measured),
                'warmup_measurement_slot_overlap': len(set(warm.slots) & set(measured.slots))})
        hashes = dict(base['input_sha256'])
        hashes.update(source_inputs(repo))
        hashes.update(reader.provenance['input_sha256'])
        hashes.update(sender.provenance['input_sha256'])
        hashes[str((args.base_prepared / 'manifest.json').resolve())] = hash_file(args.base_prepared / 'manifest.json')
        manifest = {'schema_version': SCHEMA, 'status': 'prepared', 'protocol': protocol,
            'programs': deepcopy(base['programs']), 'base_prepared': str(args.base_prepared.resolve()),
            'base_prepared_sha256': hash_file(args.base_prepared / 'manifest.json'),
            'clock_receipt': base['clock_receipt'], 'clock_receipt_sha256': receipt['receipt_sha256'],
            'input_sha256': hashes, 'raw_clock_library': str(clock_library),
            'raw_clock_provenance': reader.provenance, 'raw_sender_library': str(sender_library),
            'raw_sender_provenance': sender.provenance, 'schedule': blocks,
            'expected_live_trials': len(blocks) * 4, 'new_fits': 0,
            'scheduled_phase_seconds': len(blocks) * 4 * 29}
        manifest['artifact_hashes'] = pilot.seal(directory)
        write_json(directory / 'manifest.json', manifest)
    except BaseException as error:
        write_json(directory / 'failure.json', {'stage': 'prepare', 'error': str(error)})
        raise
    print(f'RAW CALIBRATION PREPARED: {manifest["expected_live_trials"]} trials; '
          f'{manifest["scheduled_phase_seconds"] / 60:.1f} scheduled minutes plus startup/evidence overhead.')
    print(f'Prepared: {directory}')
    return directory


def load_prepared(args):
    path = args.prepared.resolve()
    manifest = integration.read_json(path / 'manifest.json')
    require(manifest['schema_version'] == SCHEMA and manifest['status'] == 'prepared'
            and not (path / 'failure.json').exists(), 'Wrong or failed RAW calibration preparation')
    legacy.verify_seal(path, manifest['artifact_hashes'])
    ownership.verify_hashes(manifest['input_sha256'])
    require(manifest['protocol'] == calibration_protocol(manifest['protocol']['rates_pps']),
            'Prepared RAW protocol changed')
    base, receipt = legacy.load_prepared(Path(manifest['base_prepared']), args.switch)
    require(base['programs'] == manifest['programs'] and
            receipt['receipt_sha256'] == manifest['clock_receipt_sha256'], 'Four frozen programs/binary changed')
    reader = raw_clock.RawClockReader(manifest['raw_clock_library'])
    sender = sender_module.NativeRawPacedSender(manifest['raw_sender_library'])
    require(reader.provenance == manifest['raw_clock_provenance'] and
            sender.provenance == manifest['raw_sender_provenance'], 'RAW backend provenance changed')
    return manifest, receipt, reader, sender


def smoke(args, repo):
    manifest, receipt, reader, sender = load_prepared(args)
    old_args = SimpleNamespace(**vars(args))
    old_args.prepared = Path(manifest['base_prepared'])
    old_args.output_root = repo / 'results/raw_performance_packet_file_checks'
    # Existing exact-byte forwarding/counter smoke runs only BMv2 packet files.
    checked = legacy.smoke(old_args, repo)
    old_summary = integration.read_json(checked / 'summary.json')
    directory = ownership.new_directory(repo / 'results/raw_performance_calibration_checks')
    summary = {'schema_version': SCHEMA, 'status': 'raw_packet_file_smoke_passed',
        'passed': True, 'performance_measured': False, 'live_interfaces_accessed': False,
        'raw_sender_live_pacing_qualified': False,
        'prepared_manifest_sha256': hash_file(args.prepared / 'manifest.json'),
        'clock_receipt_sha256': receipt['receipt_sha256'], 'legacy_check': str(checked),
        'legacy_check_sha256': hash_file(checked / 'summary.json'),
        'results': old_summary['results']}
    write_json(directory / 'summary.json', summary)
    print(f'RAW NONPRIVILEGED SMOKE PASS — not timing qualification. Smoke: {directory}')
    return directory


def flatten_metrics(observation, resource, counts, plan):
    duration = observation['throughput']['raw_sender_window_seconds']
    bcpu, bmem = resource['bmv2']['cpu'], resource['bmv2']['memory']
    rcpu = resource['runner']['cpu']
    outputs = observation['captured_output_unique']
    return {'target_pps': observation['throughput']['target_offered_pps'],
        'offered_pps': observation['throughput']['actual_offered_pps_over_window'],
        'delivered_pps': outputs / duration if duration and duration > 0 else None,
        'delivered_ethernet_mbps': outputs * plan.frame_bytes * 8 / duration / 1e6 if duration and duration > 0 else None,
        'raw_window_seconds': duration,
        'packets_sent': observation['sent_packets'], 'packets_received': outputs,
        'packets_lost': len(observation['missing_output_sequences']),
        'loss_fraction': observation['observed_loss_fraction_after_drain'],
        'packets_duplicated': observation['capture_counters']['output']['duplicates'],
        'packets_reordered': observation['capture_counters']['output']['sequence_regressions'],
        'decisions': counts['packets'],
        'decision_rate_pps': counts['packets'] / duration if counts['packets'] is not None and duration and duration > 0 else None,
        'bmv2_cpu_one_core_percent': bcpu['percent_one_core'] if bcpu['valid'] else None,
        'bmv2_cpu_seconds': bcpu['seconds'] if bcpu['valid'] else None,
        'runner_cpu_one_core_percent': rcpu['percent_one_core'] if rcpu['valid'] else None,
        'runner_cpu_seconds': rcpu['seconds'] if rcpu['valid'] else None,
        'bmv2_rss_peak_mib': bmem['rss_max_sampled_mib'] if bmem['valid'] else None,
        'bmv2_hwm_mib': bmem['vmhwm_lifetime_mib'] if bmem['valid'] else None}


def start_measurement_window(resource_monitor, qualifier, packet_count, rate_pps, *, mode, workload):
    """Nonblocking scheduling hint; never substitutes for observed sender clocks."""
    resource_monitor.start()
    if qualifier is not None:
        start = transport.raw_now_ns()
        qualifier.notify_measurement_window(start, start + round(packet_count / rate_pps * 1e9),
                                           rate_pps, mode=mode, workload=workload)


def pacing_verdict(observation):
    pacing = observation['pacing_quality']
    return {'status': 'PASS' if pacing['valid'] else 'WARNING',
            'warnings': list(pacing['reasons']), 'engineering_heuristics': True}


def pacing_distribution(observation):
    pacing = observation['pacing_quality']
    fields = ('send_lateness_summary_ns', 'send_completion_lateness_summary_ns',
              'sender_interpacket_gap_summary_ns', 'sender_short_gap_fraction',
              'nominal_interval_ns', 'p99_send_lateness_limit_ns',
              'maximum_send_lateness_limit_ns', 'thresholds')
    return {name: deepcopy(pacing[name]) for name in fields}


def run_trial(args, program, mode, block, warm, measured, links, directory, *, qualifier=None):
    directory.mkdir()
    port = legacy.helpers.free_port()
    argv = legacy.switch_argv(args, program, port, links.names[0], links.names[2])
    write_json(directory / 'provenance.json', {'mode': mode, 'block': block,
        'switch_binary_sha256': hash_file(args.switch), 'program_sha256': hash_file(program),
        'topology': list(links.names), 'warmup': warm.manifest(), 'measurement': measured.manifest(),
        'warmup_frames_sha256': legacy.frame_hash(warm), 'measurement_frames_sha256': legacy.frame_hash(measured),
        'normal_definitions': legacy.NORMAL, 'protocol': SCHEMA,
        'clock_domains': {'elapsed': 'CLOCK_MONOTONIC_RAW', 'kernel_timestamp': 'CLOCK_REALTIME'},
        'physical_direction': 'host1 -> port1 -> port2 -> host2; logical endpoint direction alternates',
        'host_before_trial': legacy.host_snapshot()})
    write_json(directory / 'switch_command.json', argv)
    frames = [measured.frame_for(i) for i in range(measured.packet_count)]
    legacy.helpers.write_pcap(directory / 'measurement_input.pcap', frames)
    resource_monitor = None
    with (directory / 'switch.log').open('x') as log:
        child = subprocess.Popen(argv, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
        try:
            pilot.wait_ready(child, port)
            resource_monitor = RawMeasurementResources(child.pid, runner_rss_limit_mib=legacy.RUNNER_RSS_LIMIT_MIB)
            warming = transport.run_phase([warm.frame_for(i) for i in range(warm.packet_count)],
                links.names[1], links.names[3], block['rate_pps'], sequence_from_frame=warm.sequence_from_frame,
                drain_seconds=2, gates=legacy.GATES, clock_reader=args.raw_reader.read,
                paced_sender=args.raw_sender)
            write_json(directory / 'warmup_measurement.json', warming)
            before = legacy.read_counters(args, port, directory, 'counter_before.json') if mode.startswith('rf_') else None
            zero = [{'bytes': 0, 'packets': 0} for _ in range(6)]
            warm_counts = legacy.phase_counter_check(zero, before, warm, mode, warming)
            write_json(directory / 'warmup_counter_check.json', warm_counts)
            def begin_measurement():
                start_measurement_window(resource_monitor, qualifier, measured.packet_count,
                    block['rate_pps'], mode=mode, workload=block['workload'])

            observation = transport.run_phase(frames, links.names[1], links.names[3], block['rate_pps'],
                sequence_from_frame=measured.sequence_from_frame, drain_seconds=2, gates=legacy.GATES,
                on_window_start=begin_measurement, on_window_end=resource_monitor.stop,
                clock_reader=args.raw_reader.read, paced_sender=args.raw_sender)
            write_json(directory / 'measurement.json', observation)
            after = legacy.read_counters(args, port, directory, 'counter_after.json') if mode.startswith('rf_') else None
            counts = legacy.phase_counter_check(before, after, measured, mode, observation)
        except transport.PhaseCallbackError as error:
            write_json(directory / 'partial_measurement.json', error.partial_report)
            raise
        finally:
            try:
                if resource_monitor is not None:
                    resource_monitor.stop()
            finally:
                ownership.stop_child(child)
    resources = resource_monitor.report()
    write_json(directory / 'resources.json', resources)
    write_json(directory / 'counter_check.json', counts)
    gates = dict(observation['metric_validity'])
    gates['classification_rate'] = (mode.startswith('rf_') and gates['delivered_throughput']
                                    and counts['capacity_accounting_passed'])
    gates['classification_counts'] = (mode.startswith('rf_') and gates['packet_accounting']
                                      and counts['capacity_accounting_passed'])
    gates['resources'] = all(resources[key]['valid'] for key in ('bmv2', 'runner'))
    gates['cpu'] = all(resources[key]['cpu']['valid'] for key in ('bmv2', 'runner'))
    gates['cpu_accounting'] = gates['cpu']
    gates['memory'] = all(resources[key]['memory']['valid'] for key in ('bmv2', 'runner'))
    rss = resources['runner']['memory']['rss_max_sampled_mib']
    failures = list(observation['measurement_integrity_reasons'])
    if not warming['measurement_integrity_valid'] or not warm_counts['capacity_accounting_passed']:
        failures.append('Disjoint warm-up measurement integrity/counter accounting failed')
    if not gates['resources']:
        failures.append('RAW resource-window sampling failed')
    if not counts['capacity_accounting_passed']:
        failures.append('RF counter bytes/decision bounds failed')
    if rss is not None and rss > legacy.RUNNER_RSS_LIMIT_MIB:
        failures.append('Runner RSS exceeded its declared limit')
    warm_pacing, measured_pacing = pacing_verdict(warming), pacing_verdict(observation)
    conformance = ('PASS' if warm_pacing['status'] == measured_pacing['status'] == 'PASS' else 'WARNING')
    row = {'mode': mode, 'workload': block['workload'], 'rate_pps': block['rate_pps'],
        'repetition': 1, 'block_id': block['block_id'], 'valid': not failures,
        'instrument_valid_before_rate_qualification': not failures,
        'metric_validity': gates, 'failures': failures,
        'warmup_quality_reasons': list(warming['measurement_integrity_reasons']),
        'measurement_quality_reasons': list(observation['measurement_integrity_reasons']),
        'verdicts': {
            'measurement_integrity': {'status': 'PASS' if not failures else 'FAIL', 'failures': failures[:]},
            'independent_raw_qualification': {'status': 'NOT_EVALUATED', 'absolute_rate_claims_qualified': False},
            'sender_pacing_conformance': {'status': conformance, 'warmup': warm_pacing, 'measurement': measured_pacing}},
        'pacing_distributions': {'warmup': pacing_distribution(warming), 'measurement': pacing_distribution(observation)},
        'uniform_load_claim_eligible': False, 'saturation_claim_eligible': False,
        'metrics': flatten_metrics(observation, resources, counts, measured),
        'measurement_file': 'measurement.json', 'resources_file': 'resources.json',
        'counters_file': 'counter_check.json', 'normal_build': True, 'debug_reports': False,
        'kernel_forwarding_latency_qualified': False, 'accuracy_scored': False,
        'rate_window': {'start_raw_ns': observation['scheduling']['started_raw_ns'],
                        'end_raw_ns': observation['scheduling']['send_window_end_raw_ns'],
                        'target_pps': block['rate_pps'], 'mode': mode, 'workload': block['workload']}}
    write_json(directory / 'trial_summary.json', row)
    return row


def apply_rate_qualification(rows, passed, qualification=None):
    for row in rows:
        row['raw_rate_qualified'] = passed
        if 'verdicts' in row:
            row['verdicts']['independent_raw_qualification'] = {
                'status': qualification.get('status', 'INCONCLUSIVE') if qualification else ('PASS' if passed else 'INCONCLUSIVE'),
                'absolute_rate_claims_qualified': passed,
                'scope': 'Campaign-average coarse independent rate bounds; not a separate certificate for each 20-second trial'}
        if not passed:
            row['valid'] = False
            row['failures'].append('Independent RAW elapsed-rate/load qualification did not pass')
        if not passed or not row.get('instrument_valid_before_rate_qualification', row['valid']):
            for metric in ('offered_load', 'delivered_throughput', 'classification_rate', 'cpu'):
                row['metric_validity'][metric] = False


def run(args, repo):
    require(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Use the documented manual sudo command for live calibration')
    manifest, receipt, args.raw_reader, args.raw_sender = load_prepared(args)
    checked = integration.read_json(args.smoke_run / 'summary.json')
    require(checked['passed'] and checked['status'] == 'raw_packet_file_smoke_passed'
            and checked['prepared_manifest_sha256'] == hash_file(args.prepared / 'manifest.json')
            and checked['clock_receipt_sha256'] == receipt['receipt_sha256'], 'Missing bound RAW smoke check')
    old_check = integration.read_json(Path(checked['legacy_check']) / 'summary.json')
    require(hash_file(Path(checked['legacy_check']) / 'summary.json') == checked['legacy_check_sha256'], 'Smoke receipt changed')
    legacy.verify_seal(Path(checked['legacy_check']), old_check['artifact_hashes'])
    with legacy.exclusive_run(repo):
        limits = legacy.resource_preflight(repo)
        directory = ownership.new_directory(repo / 'results/raw_performance_calibration')
        links = ownership.OwnedLinks(uuid.uuid4().hex[:6])
        rows, trials = [], []
        qualifier = raw_clock.RateQualification(reader=args.raw_reader.read)
        write_json(directory / 'provenance.json', {'prepared_directory': str(args.prepared.resolve()),
            'prepared_manifest_sha256': hash_file(args.prepared / 'manifest.json'),
            'clock_receipt': receipt, 'raw_sender_provenance': args.raw_sender.provenance,
            'raw_clock_provenance': args.raw_reader.provenance,
            'smoke_run': str(args.smoke_run.resolve()), 'initial_resources': limits,
            'host_before': legacy.host_snapshot(), 'synchronization_changed': False,
            'observer_effect': 'Query-only NTP runs in the runner during calibration; every reference query is retained and its window overlap reported.'})
        aborted = None
        try:
            qualifier.start()
            require(all(item.get('valid') and item.get('query_brackets_valid')
                        for item in qualifier.records)
                    and len(qualifier.pins) == len(raw_clock.PROVIDERS),
                    'Initial independent reference acquisition failed; stop before live traffic rather than spend the calibration on an already-inconclusive rate qualification')
            with links:
                for block in manifest['schedule']:
                    warm, measured = legacy.plans_for(block, manifest['protocol'])
                    planned = integration.read_json(args.prepared / block['plan_file'])
                    require(warm.manifest() == planned['warmup'] and measured.manifest() == planned['measurement']
                            and legacy.frame_hash(warm) == planned['warmup_frames_sha256']
                            and legacy.frame_hash(measured) == planned['measurement_frames_sha256'], 'Paired traffic plan changed')
                    for mode in block['modes']:
                        legacy.resource_preflight(repo, initial=False)
                        relative = f'trial_{len(rows)+1:03d}_{block["block_id"]}_{mode}'
                        print(f'RAW calibration {len(rows)+1}/{manifest["expected_live_trials"]}: '
                              f'{mode}, {block["workload"]}, {block["rate_pps"]}pps; 5s warm-up + 20s measurement.', flush=True)
                        row = run_trial(args, manifest['programs'][mode]['path'], mode, block,
                                        warm, measured, links, directory / relative, qualifier=qualifier)
                        rows.append(row)
                        trials.append(relative)
                        print(f'  {row["metrics"]["packets_received"]}/{measured.packet_count} output; '
                              f'measurement integrity {"PASS" if row["valid"] else "FAIL"}; '
                              f'pacing {row["verdicts"]["sender_pacing_conformance"]["status"]}; '
                              f'decisions={row["metrics"]["decisions"]}; kernel latency UNQUALIFIED.', flush=True)
                        for phase in ('warmup', 'measurement'):
                            for warning in row['verdicts']['sender_pacing_conformance'][phase]['warnings']:
                                print(f'  PACING WARNING ({phase}): {warning}', flush=True)
                        if not row['valid']:
                            for reason in row['failures']:
                                print(f'  LOCAL GATE FAILURE: {reason}', flush=True)
                            for reason in row.get('warmup_quality_reasons', []):
                                print(f'  WARM-UP: {reason}', flush=True)
                            aborted = 'A hard capture/clock/resource/counter integrity requirement failed; bounded attempt stopped'
                            break
                    if aborted:
                        break
        except BaseException as error:
            aborted = f'{type(error).__name__}: {error}'
        finally:
            qualifier.stop()
        windows = [row['rate_window'] for row in rows if row['instrument_valid_before_rate_qualification']]
        qualification = qualifier.report(
            min((row['rate_window']['start_raw_ns'] for row in rows), default=None),
            max((row['rate_window']['end_raw_ns'] for row in rows), default=None),
            load_windows=windows)
        qualification['qualifying_queries_by_measurement_window'] = [
            dict(window, qualifying_query_counts_by_provider={
                provider: sum(bool(query.get('valid') and query.get('query_brackets_valid') and
                    query.get('provider') == provider and query['before'][0] >= window['start_raw_ns'] and
                    query['after'][4] <= window['end_raw_ns']) for query in qualification.get('queries', []))
                for provider in raw_clock.PROVIDERS}) for window in windows]
        write_json(directory / 'clock_rate_qualification.json', qualification)
        qualified = qualification.get('passed', qualification.get('status') == 'PASS') is True
        unchanged = True
        try:
            ownership.verify_hashes(manifest['input_sha256'])
        except (OSError, ValueError, RuntimeError) as error:
            unchanged = False
            aborted = f'Input provenance verification failed: {error}'
        # Local summaries are immutable diagnostic evidence. Never recreate or
        # overwrite them after applying the campaign's independent qualification.
        qualified_rows = deepcopy(rows)
        if not unchanged:
            for row in qualified_rows:
                row['valid'] = row['instrument_valid_before_rate_qualification'] = False
                row['failures'].append(aborted)
                row['verdicts']['measurement_integrity'] = {'status': 'FAIL', 'failures': row['failures'][:]}
        apply_rate_qualification(qualified_rows, qualified, qualification)
        for relative, row in zip(trials, qualified_rows):
            write_json(directory / relative / 'qualified_trial_summary.json', row)
        write_json(directory / 'host_after.json', legacy.host_snapshot())
        passed = (not aborted and qualified and len(rows) == manifest['expected_live_trials']
                  and all(row['valid'] for row in qualified_rows) and unchanged and not links.cleanup_errors)
        warning_trials = sum(row['verdicts']['sender_pacing_conformance']['status'] == 'WARNING' for row in rows)
        summary = {'schema_version': SCHEMA, 'status': ('raw_calibration_completed_with_pacing_warnings' if warning_trials else 'raw_calibration_passed') if passed else 'raw_calibration_incomplete',
            'passed': passed, 'raw_rate_qualified': qualified, 'protocol': manifest['protocol'],
            'prepared_directory': str(args.prepared.resolve()), 'trials': trials,
            'expected_trials': manifest['expected_live_trials'], 'attempted_trials': len(rows),
            'valid_trials': sum(row['valid'] for row in qualified_rows), 'abort_reason': aborted,
            'pacing_warning_trials': warning_trials,
            'verdicts': {
                'measurement_integrity': {'status': 'PASS' if not aborted and unchanged and not links.cleanup_errors and all(row['valid'] for row in rows) else 'FAIL'},
                'independent_raw_qualification': {'status': qualification.get('status', 'INCONCLUSIVE')},
                'sender_pacing_conformance': {'status': 'WARNING' if warning_trials else 'PASS'}},
            'uniform_load_claim_eligible': False, 'saturation_claim_eligible': False,
            'local_trial_summary_file': 'trial_summary.json',
            'qualified_trial_summary_file': 'qualified_trial_summary.json',
            'cleanup_errors': links.cleanup_errors, 'frozen_inputs_unchanged': unchanged,
            'clock_rate_qualification': qualification, 'kernel_forwarding_latency_qualified': False,
            'decision': 'Review qualified average-rate results, achieved-load comparability and pacing warnings before deciding on a separately approved bounded repeated sweep' if passed
                        else 'Review per-metric integrity and independent-reference failures; preserve counts and warnings. Do not selectively rerun or loosen numerical limits.',
            'new_fits': 0, 'accuracy_scored': False, 'artifact_hashes': pilot.seal(directory)}
        write_json(directory / 'summary.json', summary)
    print(f'RAW CALIBRATION {"PASS" if passed else "INCOMPLETE"}: {summary["valid_trials"]}/{len(rows)} qualified trials.')
    print(f'Independent RAW qualification: {qualification.get("status", "INCONCLUSIVE")}.')
    print(f'Sender pacing conformance: {summary["verdicts"]["sender_pacing_conformance"]["status"]}; '
          f'{warning_trials} warning trial(s); unchanged engineering limits. No uniform-load/saturation claim.')
    for provider, result in qualification.get('providers', {}).items():
        print(f'  {provider}: {result.get("status", "INCONCLUSIVE")}; '
              f'accepted highest-load queries={result.get("representative_load_queries", 0)}; '
              f'reasons={result.get("reasons", [])}')
    print(f'Evidence: {directory}\nKernel forwarding/inference latency remains unqualified; no full sweep launched.')
    return directory


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--switch', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--cli-python', type=Path, default=repo.parent / 'bmv2-venv/bin/python')
    parser.add_argument('--cli', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch_CLI')
    sub = parser.add_subparsers(dest='action', required=True)
    child = sub.add_parser('prepare')
    child.add_argument('--base-prepared', type=Path, default=repo / 'results/performance_benchmark_preparation/20261008T161308Z_9376ba1935')
    child.add_argument('--rates', type=int, nargs='+', default=[100, 1000])
    for action in ('smoke', 'run'):
        child = sub.add_parser(action)
        child.add_argument('--prepared', type=Path, required=True)
        if action == 'run':
            child.add_argument('--smoke-run', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = {'prepare': prepare, 'smoke': smoke, 'run': run}[args.action](args, repo)
        if args.action == 'run' and not integration.read_json(result / 'summary.json')['passed']:
            return 2
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'RAW CALIBRATION STOPPED: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
