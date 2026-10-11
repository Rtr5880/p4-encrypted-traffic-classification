#!/usr/bin/env python3
"""One bounded, independently qualified continuation of the sealed v5 schedule.

The original failed first trial is read-only historical evidence. This new
execution session attempts original positions 2..160 once, in their sealed
order. Acquisition, clocks, numerical gates and frozen programs are reused.
Only a completed local integrity failure's operational stop policy changes.
"""
import argparse
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import uuid

import run_raw_performance_benchmark as runner

SCHEMA = 'raw-performance-benchmark-continuation-v6'
require, write_json, hash_file = runner.require, runner.write_json, runner.hash_file
run_trial = runner.run_trial
ORIGINAL_PREPARATION = 'results/raw_performance_benchmark_preparation/20261008T222805Z_7060abb5c4'
HISTORICAL_RUN = 'results/raw_performance_benchmark/20261008T223313Z_9752ce54b5'


def continuation_policy():
    return dict(name=SCHEMA, maximum_clock_sampling_gap_ns=25_000_000,
        maximum_clock_bracket_ns=100_000, raw_rate_tolerance_ppm=1000,
        qualification_minimum_span_seconds=180, pacing_gates=dict(runner.legacy.GATES),
        maximum_consecutive_integrity_failures=3, same_code_failure_count=4,
        same_code_window_completed_trials=8,
        recurring_failure_scope='Completed continuation-session trials only; historical trial 1 does not seed a new-session streak',
        completed_integrity_failure_action='Retain INVALID and all raw evidence; continue unless safety or recurring-failure stop applies',
        pacing_warning_action='Retain WARNING; does not count as measurement-integrity failure',
        immediate_stop='Acquisition exception, failed cleanup/environment/provenance/evidence check, declared resource exhaustion or unsafe execution',
        retry_policy='One suffix execution only; no trial-1 retry, replacement, reordering or subsequent continuation',
        qualification_scope='New session independently qualified; historical timing verdict never changed or promoted',
        kernel_forwarding_latency_qualified=False, isolated_inference_latency_measured=False)


def remaining_schedule(schedule):
    runner.validate_schedule(runner.benchmark_protocol(list(runner.FINAL_RATES)), schedule)
    result = []
    for ordinal, (block, mode) in enumerate(
            ((block, mode) for block in schedule for mode in block['modes']), 1):
        if ordinal == 1:
            continue
        result.append(dict(ordinal=ordinal, original_schedule_ordinal=ordinal,
            block=deepcopy(block), mode=mode,
            trial_directory=f'trial_{ordinal:03d}_{block["block_id"]}_{mode}'))
    require(len(result) == 159, 'The continuation must be exactly original positions 2..160')
    return result


def integrity_codes(row):
    concrete = list(row.get('measurement_quality_reasons', [])) + list(row.get('warmup_quality_reasons', []))
    # A generic warm-up wrapper must not combine different underlying failures
    # into a misleading recurring code. Preserve the original strings in rows.
    failures = set(row.get('failures', []))
    if row.get('warmup_quality_reasons'):
        failures.discard('Disjoint warm-up measurement integrity/counter accounting failed')
    return set(concrete) | failures


def operational_stop(rows):
    if not rows:
        return None
    if any('Runner RSS exceeded its declared limit' in reason for reason in rows[-1].get('failures', [])):
        return 'Immediate safety stop: declared runner RSS limit exceeded'
    valid = lambda row: row['instrument_valid_before_rate_qualification']
    if len(rows) >= 3 and all(not valid(row) for row in rows[-3:]):
        return 'Recurring integrity stop: three consecutive completed continuation trials are INVALID'
    window = rows[-8:]
    codes = set().union(*(integrity_codes(row) for row in window if not valid(row)))
    for code in sorted(codes):
        if sum(not valid(row) and code in integrity_codes(row) for row in window) >= 4:
            return f'Recurring integrity stop: same failure in four of the last eight completed trials: {code}'
    return None


def verify_history(source_root, original_prepared, switch):
    """Verify original source and all its seals without writing inside it."""
    import analyze_raw_performance as analysis
    root, summary, rows, verified = analysis.verify_run(source_root)
    require(summary['schema_version'] == runner.SCHEMA and summary['attempted_trials'] == 1
            and summary['completed_trials'] == 1 and len(rows) == 1 and not summary['partial_trials'],
            'Continuation is authorized only after the original one completed attempt')
    require(summary['cleanup_errors'] == [] and summary['frozen_inputs_unchanged'] is True
            and not rows[0]['valid'] and not rows[0]['instrument_valid_before_rate_qualification'],
            'Original cleanup/provenance/failed trial identity changed')
    require(rows[0]['metrics']['packets_sent'] == 20000
            and rows[0]['metrics']['packets_received'] == 19950
            and rows[0]['metrics']['packets_lost'] == 50,
            'The approved historical 50-packet non-delivery evidence changed')
    original, receipt, reader, sender = runner.load_prepared(
        SimpleNamespace(prepared=Path(original_prepared), switch=switch))
    schedule = runner.integration.read_json(root / 'schedule.json')
    require(schedule['schedule'] == original['schedule'] and schedule['protocol'] == original['protocol'],
            'Original sealed schedule disagrees with its preparation')
    provenance = runner.integration.read_json(root / 'provenance.json')
    require(Path(provenance['prepared_directory']).resolve() == Path(original_prepared).resolve()
            and provenance['prepared_manifest_sha256'] == hash_file(Path(original_prepared) / 'manifest.json'),
            'Historical preparation binding changed')
    first_block, first_mode = original['schedule'][0], original['schedule'][0]['modes'][0]
    first_attempt = summary['attempts'][0]
    require(first_attempt['ordinal'] == 1 and first_attempt['mode'] == first_mode
            and first_attempt['block_id'] == first_block['block_id']
            and first_attempt['trial_directory'] == f'trial_001_{first_block["block_id"]}_{first_mode}',
            'Historical first attempt is not original scheduled position 1')
    historical = dict(source_root=str(root.resolve()), summary_sha256=verified['summary_sha256'],
        schema_version=runner.SCHEMA, prepared_directory=str(Path(original_prepared).resolve()),
        prepared_manifest_sha256=hash_file(Path(original_prepared) / 'manifest.json'),
        preserved_artifacts=verified['artifact_hashes_verified'], trials=summary['trials'],
        attempted_trials=1, completed_trials=1, original_verdicts_unchanged=True,
        original_missing_output_packets=50, timing_requalified=False)
    return historical, original, receipt, reader, sender


def source_inputs(repo):
    return {str((repo / 'tools' / name).resolve()): hash_file(repo / 'tools' / name)
            for name in ('continue_raw_performance_benchmark.py', 'analyze_raw_performance_continuation.py')}


def prepare(args, repo):
    historical, original, receipt, reader, sender = verify_history(args.source_run, args.original_prepared, args.switch)
    directory = runner.ownership.new_directory(repo / 'results/raw_performance_continuation_preparation')
    write_json(directory / 'historical_campaign.json', historical)
    write_json(directory / 'schedule.json', dict(schema_version=SCHEMA,
        protocol=original['protocol'], schedule=original['schedule']))
    suffix = remaining_schedule(original['schedule'])
    write_json(directory / 'remaining_schedule.json', suffix)
    inputs = dict(original['input_sha256'])
    inputs.update(source_inputs(repo))
    inputs[str((args.original_prepared / 'manifest.json').resolve())] = historical['prepared_manifest_sha256']
    inputs[str((args.source_run / 'summary.json').resolve())] = historical['summary_sha256']
    manifest = dict(schema_version=SCHEMA, status='prepared', original_prepared=str(args.original_prepared.resolve()),
        historical_campaign=historical, protocol=deepcopy(original['protocol']),
        continuation_policy=continuation_policy(), schedule=deepcopy(original['schedule']),
        remaining_schedule=suffix, expected_trials=160, expected_session_trials=159,
        expected_live_trials=159, scheduled_phase_seconds=159 * 29,
        programs=deepcopy(original['programs']), input_sha256=inputs,
        raw_clock_library=original['raw_clock_library'], raw_clock_provenance=reader.provenance,
        raw_sender_library=original['raw_sender_library'], raw_sender_provenance=sender.provenance,
        clock_receipt_sha256=receipt['receipt_sha256'], prior_calibration_receipts=original['prior_calibration_receipts'],
        artifact_hashes=runner.pilot.seal(directory))
    write_json(directory / 'manifest.json', manifest)
    print(f'CONTINUATION PREPARED: original positions 2..160; 159 trials; {159 * 29 / 60:.1f} scheduled minutes plus overhead.\nPrepared: {directory}')
    return directory


def load_prepared(args):
    directory = args.prepared.resolve()
    manifest = runner.integration.read_json(directory / 'manifest.json')
    require(manifest['schema_version'] == SCHEMA and manifest['status'] == 'prepared', 'Wrong continuation preparation')
    runner.legacy.verify_seal(directory, manifest['artifact_hashes'])
    runner.ownership.verify_hashes(manifest['input_sha256'])
    historical, original, receipt, reader, sender = verify_history(
        Path(manifest['historical_campaign']['source_root']), Path(manifest['original_prepared']), args.switch)
    require(manifest['historical_campaign'] == historical and manifest['protocol'] == original['protocol']
            and manifest['schedule'] == original['schedule']
            and manifest['remaining_schedule'] == remaining_schedule(original['schedule'])
            and manifest['continuation_policy'] == continuation_policy()
            and manifest['programs'] == original['programs']
            and manifest['expected_trials'] == 160 and manifest['expected_session_trials'] == 159
            and manifest['expected_live_trials'] == 159 and manifest['scheduled_phase_seconds'] == 4611,
            'Historical binding, original trial identities or continuation policy changed')
    require(runner.integration.read_json(directory / 'historical_campaign.json') == historical
            and runner.integration.read_json(directory / 'schedule.json')['schedule'] == original['schedule']
            and runner.integration.read_json(directory / 'remaining_schedule.json') == manifest['remaining_schedule'],
            'Continuation plan files disagree with sealed manifest')
    require(reader.provenance == manifest['raw_clock_provenance'] and sender.provenance == manifest['raw_sender_provenance']
            and manifest['raw_clock_library'] == original['raw_clock_library']
            and manifest['raw_sender_library'] == original['raw_sender_library']
            and manifest['prior_calibration_receipts'] == original['prior_calibration_receipts']
            and receipt['receipt_sha256'] == manifest['clock_receipt_sha256'], 'RAW backend/binary provenance changed')
    return manifest, receipt, reader, sender


def smoke(args, repo):
    manifest, receipt, _, _ = load_prepared(args)
    old = SimpleNamespace(**vars(args))
    old.prepared = Path(manifest['original_prepared'])
    checked = runner.smoke(old, repo)
    directory = runner.ownership.new_directory(repo / 'results/raw_performance_continuation_checks')
    summary = dict(schema_version=SCHEMA, status='continuation_packet_file_smoke_passed', passed=True,
        prepared_manifest_sha256=hash_file(args.prepared / 'manifest.json'),
        original_prepared_manifest_sha256=manifest['historical_campaign']['prepared_manifest_sha256'],
        clock_receipt_sha256=receipt['receipt_sha256'], original_check=str(checked),
        original_check_sha256=hash_file(checked / 'summary.json'),
        results=runner.integration.read_json(checked / 'summary.json')['results'],
        performance_measured=False, live_interfaces_accessed=False, raw_sender_live_pacing_qualified=False)
    write_json(directory / 'summary.json', summary)
    print(f'CONTINUATION NONPRIVILEGED SMOKE PASS — exact normal builds, no live pacing claim.\nSmoke: {directory}')
    return directory


def verify_smoke(args, receipt):
    summary = runner.integration.read_json(args.smoke_run / 'summary.json')
    require(summary['schema_version'] == SCHEMA and summary['passed']
            and summary['status'] == 'continuation_packet_file_smoke_passed'
            and summary['prepared_manifest_sha256'] == hash_file(args.prepared / 'manifest.json')
            and summary['clock_receipt_sha256'] == receipt['receipt_sha256'], 'Missing bound continuation smoke')
    old = Path(summary['original_check'])
    require(hash_file(old / 'summary.json') == summary['original_check_sha256'], 'Original smoke receipt changed')
    old_summary = runner.integration.read_json(old / 'summary.json')
    legacy_root = Path(old_summary['legacy_check'])
    require(hash_file(legacy_root / 'summary.json') == old_summary['legacy_check_sha256'], 'Packet-file smoke receipt changed')
    runner.legacy.verify_seal(legacy_root, runner.integration.read_json(legacy_root / 'summary.json')['artifact_hashes'])


def active_switch_pids():
    active = []
    for path in Path('/proc').glob('[0-9]*/comm'):
        try:
            if path.read_text().strip() == 'simple_switch':
                active.append(int(path.parent.name))
        except FileNotFoundError:
            pass  # An unrelated process can exit during the read-only inventory.
    return sorted(active)


def verify_boundary(args, manifest, links=None):
    runner.legacy.resource_preflight(Path(__file__).resolve().parent.parent, initial=False)
    # Between—not during—measurements. Reuse all sealed original source, model,
    # binary and evidence hashes; no timing workaround or observer is added.
    runner.ownership.verify_hashes(manifest['input_sha256'])
    history = manifest['historical_campaign']
    root = Path(history['source_root'])
    require(hash_file(root / 'summary.json') == history['summary_sha256'], 'Historical root changed')
    runner.legacy.verify_seal(root, runner.integration.read_json(root / 'summary.json')['artifact_hashes'])
    require(not active_switch_pids(), 'BMv2 cleanup/environment check failed: a simple_switch process is still active')
    if links is not None:
        require(not links.cleanup_errors, 'Owned-link cleanup error reported')
        inventory = links.inventory()
        for name in links.names:
            require(name in inventory and inventory[name]['ifindex'] == links.owned[name]['ifindex']
                    and inventory[name].get('ifalias', '') == links.alias
                    and 'UP' in inventory[name].get('flags', []), 'Dedicated link ownership/state changed')
    return dict(frozen_and_source_hashes_verified=True, historical_seal_verified=True,
        active_switch_pids=[], owned_link_state_verified=links is not None, resource_preflight_passed=True)


def claim_session(repo, history, directory):
    claims = repo / 'results/raw_performance_continuation_claims'
    claims.mkdir(exist_ok=True)
    path = claims / (history['summary_sha256'] + '.json')
    write_json(path, dict(schema_version=SCHEMA, source_run=history['source_root'],
        source_summary_sha256=history['summary_sha256'], execution_session=str(directory.resolve()),
        retry_permitted=False))  # Exclusive creation: a second suffix acquisition is refused.
    return str(path.resolve())


def seal_trial_evidence(directory):
    seal = dict(artifact_hashes=runner.pilot.seal(directory))
    write_json(directory / 'trial_evidence_seal.json', seal)
    runner.legacy.verify_seal(directory, seal['artifact_hashes'])
    return seal


def run(args, repo):
    require(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Use the documented manual sudo command')
    manifest, receipt, args.raw_reader, args.raw_sender = load_prepared(args)
    verify_smoke(args, receipt)
    with runner.legacy.exclusive_run(repo):
        limits = runner.legacy.resource_preflight(repo)
        initial_state = verify_boundary(args, manifest)
        directory = runner.ownership.new_directory(repo / 'results/raw_performance_continuation')
        claim = claim_session(repo, manifest['historical_campaign'], directory)
        session_id = directory.name
        links = runner.ownership.OwnedLinks(uuid.uuid4().hex[:6])
        rows, trials, attempts = [], [], []
        qualifier = runner.raw_clock.RateQualification(reader=args.raw_reader.read)
        write_json(directory / 'historical_campaign.json', manifest['historical_campaign'])
        write_json(directory / 'schedule.json', dict(schema_version=SCHEMA, protocol=manifest['protocol'], schedule=manifest['schedule']))
        write_json(directory / 'provenance.json', dict(prepared_directory=str(args.prepared.resolve()),
            prepared_manifest_sha256=hash_file(args.prepared / 'manifest.json'),
            execution_session_id=session_id, separately_executed_session=True, execution_claim=claim,
            historical_campaign=manifest['historical_campaign'], original_prepared=manifest['original_prepared'],
            continuation_policy=manifest['continuation_policy'], initial_environment=initial_state,
            initial_resources=limits, host_before=runner.legacy.host_snapshot(), clock_receipt=receipt,
            raw_sender_provenance=args.raw_sender.provenance, raw_clock_provenance=args.raw_reader.provenance,
            synchronization_changed=False, smoke_run=str(args.smoke_run.resolve()),
            measurement_profile='Unchanged v5 run_trial and calibrated RAW transport; v6 continuation orchestration only'))
        (directory / 'attempts').mkdir()
        aborted = None
        try:
            qualifier.start()
            require(all(item.get('valid') and item.get('query_brackets_valid') for item in qualifier.records)
                    and len(qualifier.pins) == len(runner.raw_clock.PROVIDERS), 'Initial independent reference acquisition failed; no traffic launched')
            with links:
                for item in manifest['remaining_schedule']:
                    ordinal, block, mode, relative = item['ordinal'], item['block'], item['mode'], item['trial_directory']
                    state = verify_boundary(args, manifest, links)
                    warm, measured = runner.legacy.plans_for(block, manifest['protocol'])
                    planned = runner.integration.read_json(Path(manifest['original_prepared']) / block['plan_file'])
                    require(warm.manifest() == planned['warmup'] and measured.manifest() == planned['measurement']
                            and runner.legacy.frame_hash(warm) == planned['warmup_frames_sha256']
                            and runner.legacy.frame_hash(measured) == planned['measurement_frames_sha256'], 'Original matched traffic bytes changed')
                    print(f'RAW continuation original trial {ordinal}/160 (session {len(attempts)+1}/159): {mode}, {block["workload"]}, {block["rate_pps"]}pps; 5s warm-up + 20s measurement.', flush=True)
                    attempt = dict(ordinal=ordinal, original_schedule_ordinal=ordinal, session_ordinal=len(attempts)+1,
                        execution_session_id=session_id, trial_directory=relative, mode=mode,
                        workload=block['workload'], rate_pps=block['rate_pps'], block_id=block['block_id'],
                        repetition=block['repetition'], status='started',
                        start_receipt=f'attempts/attempt_{ordinal:03d}_start.json', result_receipt=f'attempts/attempt_{ordinal:03d}_result.json')
                    write_json(directory / attempt['start_receipt'], dict(attempt, boundary_environment=state))
                    attempts.append(attempt)
                    try:
                        row = run_trial(args, manifest['programs'][mode]['path'], mode, block, warm, measured,
                                        links, directory / relative, qualifier=qualifier)
                        seal_trial_evidence(directory / relative)
                    except BaseException as error:
                        attempt['status'] = 'exception'
                        write_json(directory / attempt['result_receipt'], dict(attempt=deepcopy(attempt), status='exception',
                            error_type=type(error).__name__, error=str(error), trial_directory_exists=(directory / relative).is_dir(),
                            measurements_fabricated=False))
                        raise
                    attempt['status'] = 'completed'
                    write_json(directory / attempt['result_receipt'], dict(attempt=deepcopy(attempt), status='completed',
                        measurement_integrity=deepcopy(row['verdicts']['measurement_integrity']),
                        sender_pacing_conformance=deepcopy(row['verdicts']['sender_pacing_conformance']),
                        local_summary_sha256=hash_file(directory / relative / 'trial_summary.json'),
                        trial_evidence_seal_sha256=hash_file(directory / relative / 'trial_evidence_seal.json'),
                        trial_directory_exists=True, measurements_fabricated=False))
                    rows.append(row)
                    trials.append(relative)
                    print(f'  {row["metrics"]["packets_received"]}/{measured.packet_count} output; measurement integrity {"PASS" if row["valid"] else "INVALID"}; pacing {row["verdicts"]["sender_pacing_conformance"]["status"]}; decisions={row["metrics"]["decisions"]}; kernel latency UNQUALIFIED.', flush=True)
                    for reason in row['failures']:
                        print(f'  INTEGRITY FAILURE (retained, not waived): {reason}', flush=True)
                    for phase in ('warmup', 'measurement'):
                        for warning in row['verdicts']['sender_pacing_conformance'][phase]['warnings']:
                            print(f'  PACING WARNING ({phase}): {warning}', flush=True)
                    verify_boundary(args, manifest, links)
                    aborted = operational_stop(rows)
                    if aborted:
                        print(f'  OPERATIONAL STOP: {aborted}', flush=True)
                        break
        except BaseException as error:
            aborted = f'{type(error).__name__}: {error}'
        finally:
            qualifier.stop()
        windows = [row['rate_window'] for row in rows if row['instrument_valid_before_rate_qualification']]
        qualification = qualifier.report(min((row['rate_window']['start_raw_ns'] for row in rows), default=None),
            max((row['rate_window']['end_raw_ns'] for row in rows), default=None), load_windows=windows)
        qualification['qualifying_queries_by_measurement_window'] = [dict(window,
            qualifying_query_counts_by_provider={provider: sum(bool(query.get('valid') and query.get('query_brackets_valid')
                and query.get('provider') == provider and query['before'][0] >= window['start_raw_ns']
                and query['after'][4] <= window['end_raw_ns']) for query in qualification.get('queries', []))
                for provider in runner.raw_clock.PROVIDERS}) for window in windows]
        qualification['execution_session_id'] = session_id
        qualification['historical_session_included'] = False
        write_json(directory / 'clock_rate_qualification.json', qualification)
        qualified = qualification.get('passed', qualification.get('status') == 'PASS') is True
        unchanged = True
        try:
            verify_boundary(args, manifest)
            for relative in trials:
                seal = runner.integration.read_json(directory / relative / 'trial_evidence_seal.json')
                runner.legacy.verify_seal(directory / relative, seal['artifact_hashes'])
        except (OSError, ValueError, RuntimeError) as error:
            unchanged = False
            aborted = f'Final evidence/environment/provenance verification failed: {error}'
        qualified_rows = deepcopy(rows)
        if not unchanged or links.cleanup_errors:
            for row in qualified_rows:
                row['valid'] = row['instrument_valid_before_rate_qualification'] = False
                row['failures'].append(aborted or 'Owned-link cleanup failed')
                row['verdicts']['measurement_integrity'] = dict(status='FAIL', failures=row['failures'][:])
        runner.apply_rate_qualification(qualified_rows, qualified, qualification)
        for attempt, relative, row in zip((a for a in attempts if a['status'] == 'completed'), trials, qualified_rows):
            row.update(original_schedule_ordinal=attempt['ordinal'], execution_session_id=session_id)
            row['verdicts']['independent_raw_qualification']['scope'] = 'This separate continuation session only; historical trial 1 is excluded'
            write_json(directory / relative / 'qualified_trial_summary.json', row)
        write_json(directory / 'host_after.json', runner.legacy.host_snapshot())
        acquisition_complete = len(attempts) == len(rows) == 159 and not aborted and not links.cleanup_errors and unchanged
        passed = acquisition_complete and qualified and all(row['valid'] for row in qualified_rows)
        warnings = sum(row['verdicts']['sender_pacing_conformance']['status'] == 'WARNING' for row in rows)
        summary = dict(schema_version=SCHEMA, status='continuation_acquisition_complete' if acquisition_complete else 'continuation_incomplete',
            passed=passed, acquisition_complete=acquisition_complete, execution_session_id=session_id,
            separately_executed_session=True, raw_rate_qualified=qualified, protocol=manifest['protocol'],
            continuation_policy=manifest['continuation_policy'], historical_campaign=manifest['historical_campaign'],
            expected_trials=160, expected_session_trials=159, prepared_directory=str(args.prepared.resolve()),
            original_prepared=manifest['original_prepared'], schedule_file='schedule.json', trials=trials,
            attempted_trials=len(attempts), completed_trials=len(rows), attempts=deepcopy(attempts),
            campaign_attempted_trials=1+len(attempts), campaign_completed_trials=1+len(rows),
            valid_trials=sum(row['valid'] for row in qualified_rows), abort_reason=aborted,
            partial_trials=[a['trial_directory'] for a in attempts if a['status'] != 'completed'], pacing_warning_trials=warnings,
            verdicts=dict(measurement_integrity=dict(status='PASS' if unchanged and not links.cleanup_errors and all(row['valid'] for row in rows) else 'FAIL'),
                independent_raw_qualification=dict(status=qualification.get('status', 'INCONCLUSIVE')),
                sender_pacing_conformance=dict(status=('WARNING' if warnings else 'PASS') if rows else 'NOT_EVALUATED')),
            local_trial_summary_file='trial_summary.json', qualified_trial_summary_file='qualified_trial_summary.json',
            cleanup_errors=links.cleanup_errors, frozen_inputs_unchanged=unchanged, clock_rate_qualification=qualification,
            kernel_forwarding_latency_qualified=False, isolated_inference_latency_measured=False,
            uniform_load_claim_eligible=False, saturation_claim_eligible=False,
            historical_trial_requalified=False, new_fits=0, accuracy_scored=False,
            decision='Close bounded acquisition; analyze available eligible evidence and freeze performance. No retries, latency or capacity claims.',
            artifact_hashes=runner.pilot.seal(directory))
        write_json(directory / 'summary.json', summary)
    print(f'CONTINUATION {"ACQUISITION COMPLETE" if acquisition_complete else "INCOMPLETE"}: {len(attempts)}/159 attempted, {len(rows)}/159 completed, {summary["valid_trials"]} qualified; original trial 1 remains INVALID.')
    print(f'Independent RAW qualification for this session: {qualification.get("status", "INCONCLUSIVE")}; pacing warning trials={warnings}.\nEvidence: {directory}')
    return directory


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--switch', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--cli-python', type=Path, default=repo.parent / 'bmv2-venv/bin/python')
    parser.add_argument('--cli', type=Path, default=repo.parent / 'behavioral-model/targets/simple_switch/simple_switch_CLI')
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--original-prepared', type=Path, default=repo / ORIGINAL_PREPARATION)
    p.add_argument('--source-run', type=Path, default=repo / HISTORICAL_RUN)
    for action in ('smoke', 'run'):
        p = sub.add_parser(action)
        p.add_argument('--prepared', type=Path, required=True)
        if action == 'run':
            p.add_argument('--smoke-run', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = dict(prepare=prepare, smoke=smoke, run=run)[args.action](args, repo)
        if args.action == 'run':
            import analyze_raw_performance_continuation as analysis
            print(f'Combined, session-aware final analysis: {analysis.analyze(result)}')
            if not runner.integration.read_json(result / 'summary.json')['passed']:
                return 2
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'CONTINUATION STOPPED: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
