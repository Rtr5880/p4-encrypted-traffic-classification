#!/usr/bin/env python3
"""One bounded synthetic live demonstration; historical research is read-only.

launch runs as ordinary user: dashboard reuse -> sealed prepare -> file smoke
-> explicit terminal sudo worker. Only run touches live veths/AF_PACKET.
"""
import argparse
from contextlib import contextmanager,nullcontext
from copy import deepcopy
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import uuid

import integrate_rf as integration
import run_performance_benchmark as legacy
import run_performance_pilot as pilot
import run_native_clock_pilot as ownership
import run_raw_performance_calibration as calibration
import live_demo_transport as demo_transport

SCHEMA='live-synthetic-demo-v1'
DEFAULT_RAW_PREP='results/raw_performance_calibration_preparation/20261008T201210Z_31ccc28561'
MODES=legacy.MODES
RATES=(100,250,500,1000)
WORKLOADS=legacy.WORKLOADS
require,write_json,hash_file=legacy.require,legacy.write_json,legacy.hash_file


def demo_protocol(mode,rate,workload):
    require(mode in MODES,'Mode must be forwarding, features, rf_b or rf_c')
    require(type(rate)is int and rate in RATES,'Demo rate must be 100, 250, 500 or 1000pps')
    require(workload in WORKLOADS,'Unknown supported synthetic workload')
    p=calibration.calibration_protocol([100])
    p.update(name=SCHEMA,modes=[mode],rates_pps=[rate],workloads=[workload],maximum_trials=1,
             telemetry_interval_seconds=1,observer_effect='Streamlit and asynchronous demo telemetry coexist on this host; no historical qualification inherited',
             demo_only=True,expected_independent_qualification='INCONCLUSIVE for default short demo: unchanged minimum 180-second reference span')
    return p


def make_block(protocol,token):
    mode=protocol['modes'][0];rate=protocol['rates_pps'][0];workload=protocol['workloads'][0]
    name=f'{workload}_{rate:05d}pps_r01'
    return dict(block_id=name,rate_pps=rate,workload=workload,repetition=1,namespace=1,
                run_id=token+':'+name,modes=[mode])


def source_hashes(repo):
    files=[repo/'tools'/n for n in ('run_live_demo.py','live_demo_transport.py','live_telemetry.py')]
    files.extend(repo/p for p in ('dashboard/app.py','dashboard/components.py','dashboard/views/live.py',
                                  'dashboard/live_evidence.py','tools/dashboard_process.py','requirements-dashboard.txt'))
    return {str(p.resolve()):hash_file(p) for p in files}


def source_closure(source,repo):
    """Fresh demo provenance, NOT a weakened historical calibration loader.

    The historical offline analyzer is never executed by this one-trial demo.
    Its old/current identity is recorded explicitly and its CURRENT hash is
    pinned in the new demo preparation. Every other historical source remains
    strict, including frozen P4/models, runtime, switch and native backends.
    """
    analyzer=str((repo/'tools/analyze_raw_performance.py').resolve())
    strict={k:v for k,v in source['input_sha256'].items() if k!=analyzer}
    ownership.verify_hashes(strict)
    require(analyzer in source['input_sha256'] and Path(analyzer).is_file(),'Historical unused analyzer identity missing')
    current=hash_file(analyzer)
    note={'path':analyzer,'historical_sha256':source['input_sha256'][analyzer],
          'current_sha256':current,'changed':current!=source['input_sha256'][analyzer],
          'reason':'Offline aggregate analyzer is not executed by synthetic demo; current identity pinned in new demo manifest',
          'historical_manifest_modified':False,'historical_calibration_requalified':False}
    return dict(strict,**{analyzer:current}),note


def load_source(args,repo,path=None):
    prepared=Path(path or args.source_prepared).resolve()
    source=integration.read_json(prepared/'manifest.json')
    require(source.get('schema_version')==calibration.SCHEMA and source.get('status')=='prepared'
            and not (prepared/'failure.json').exists(),'Unexpected historical preparation source')
    legacy.verify_seal(prepared,source['artifact_hashes'])
    closure,note=source_closure(source,repo)
    base,receipt=legacy.load_prepared(Path(source['base_prepared']),args.switch)
    require(base['programs']==source['programs'] and receipt['receipt_sha256']==source['clock_receipt_sha256'],
            'Frozen normal programs/binary receipt changed')
    require(hash_file(Path(source['base_prepared'])/'manifest.json')==source['base_prepared_sha256'],'Original normal preparation changed')
    reader=calibration.raw_clock.RawClockReader(source['raw_clock_library'])
    sender=calibration.sender_module.NativeRawPacedSender(source['raw_sender_library'])
    require(reader.provenance==source['raw_clock_provenance'] and sender.provenance==source['raw_sender_provenance'],
            'Sealed native sender/clock provenance changed')
    source=deepcopy(source);source['input_sha256']=closure;source['historical_unused_analysis_source']=note
    return source,receipt,reader,sender


def prepare(args,repo):
    protocol=demo_protocol(args.mode,args.rate,args.workload)
    source,receipt,reader,sender=load_source(args,repo)
    directory=ownership.new_directory(repo/'results/live_demo_preparation')
    block=make_block(protocol,uuid.uuid4().hex)
    warm,measured=legacy.plans_for(block,protocol)
    plan={'warmup':warm.manifest(),'measurement':measured.manifest(),
          'warmup_frames_sha256':legacy.frame_hash(warm),'measurement_frames_sha256':legacy.frame_hash(measured),
          'warmup_measurement_slot_overlap':len(set(warm.slots)&set(measured.slots))}
    require(plan['warmup_measurement_slot_overlap']==0,'Warm-up state must remain disjoint')
    write_json(directory/'plan.json',plan)
    hashes=dict(source['input_sha256']);hashes.update(source_hashes(repo))
    hashes[str(Path(args.source_prepared).resolve()/'manifest.json')]=hash_file(Path(args.source_prepared)/'manifest.json')
    manifest={'schema_version':SCHEMA,'status':'prepared','protocol':protocol,'block':block,
              'source_prepared':str(Path(args.source_prepared).resolve()),'source_prepared_sha256':hash_file(Path(args.source_prepared)/'manifest.json'),
              'programs':deepcopy(source['programs']),'input_sha256':hashes,'new_fits':0,
              'clock_receipt_sha256':receipt['receipt_sha256'],'normal_definitions':legacy.NORMAL,
              'raw_clock_provenance':reader.provenance,'raw_sender_provenance':sender.provenance,
              'historical_unused_analysis_source':source['historical_unused_analysis_source'],
              'scheduled_traffic_seconds':29,'privileged_execution_performed':False}
    manifest['artifact_hashes']=pilot.seal(directory)
    write_json(directory/'manifest.json',manifest)
    print(f'LIVE DEMO PREPARED: {args.mode}, {args.rate}pps, {args.workload}; 5s warm-up + 20s measurement.\nPrepared: {directory}',flush=True)
    return directory


def load_prepared(args,repo):
    directory=Path(args.prepared).resolve();m=integration.read_json(directory/'manifest.json')
    require(m.get('schema_version')==SCHEMA and m.get('status')=='prepared' and m.get('new_fits')==0,'Wrong demo preparation')
    legacy.verify_seal(directory,m['artifact_hashes']);ownership.verify_hashes(m['input_sha256'])
    p=m['protocol'];require(p==demo_protocol(p['modes'][0],p['rates_pps'][0],p['workloads'][0]),'Demo protocol changed')
    source,receipt,reader,sender=load_source(args,repo,m['source_prepared'])
    require(source['programs']==m['programs'] and reader.provenance==m['raw_clock_provenance']
            and sender.provenance==m['raw_sender_provenance'],'Frozen program/backend changed')
    require(source['historical_unused_analysis_source']==m['historical_unused_analysis_source'],'New demo analyzer provenance changed')
    require(hash_file(Path(m['source_prepared'])/'manifest.json')==m['source_prepared_sha256'],'Source preparation changed')
    warm,measured=legacy.plans_for(m['block'],p)
    plan=integration.read_json(directory/'plan.json')
    require(plan['warmup']==warm.manifest() and plan['measurement']==measured.manifest()
            and plan['warmup_frames_sha256']==legacy.frame_hash(warm)
            and plan['measurement_frames_sha256']==legacy.frame_hash(measured),'Demo workload plan changed')
    return m,receipt,reader,sender,warm,measured


def file_smoke_frames(name):
    """Reuse existing generated bytes, ≤64 total frames prevents queue bursts.

    Cached case selects two complete 32-packet flows from the unchanged
    eight-conversation workload. Heavy selects eight complete 8-packet flows.
    This is program/counter correctness only, not pacing or state-warmup proof.
    """
    _,plan=legacy.workload.build_phase_pair(64,1,4,name,'live-demo-file-smoke:'+name)
    sequences=list(range(64)) if name=='classification-heavy' else [
        i for i in range(plan.packet_count) if plan.flow_id_for(i)<2]
    frames=[plan.frame_for(i) for i in sequences]
    counts={}
    for i in sequences:
        flow=plan.flow_id_for(i);counts[flow]=counts.get(flow,0)+1
    require(len(frames)==64,'Bounded file smoke requires exactly 64 frames')
    return frames,sum(n>=8 for n in counts.values()),counts


def smoke(args,repo):
    m,receipt,reader,sender,_,_=load_prepared(args,repo)
    directory=ownership.new_directory(repo/'results/live_demo_checks')
    results={}
    try:
        for name in WORKLOADS:
            frames,expected,per_flow=file_smoke_frames(name)
            for mode in MODES:
                trial=directory/(name+'_'+mode);trial.mkdir()
                legacy.helpers.write_pcap(trial/'input_in.pcap',frames)
                legacy.helpers.write_pcap(trial/'output_in.pcap',[])
                port=legacy.helpers.free_port()
                argv=legacy.switch_argv(args,m['programs'][mode]['path'],port,'input','output',True)
                write_json(trial/'command.json',argv)
                with (trial/'switch.log').open('x') as log:
                    child=subprocess.Popen(argv,cwd=trial,stdout=log,stderr=subprocess.STDOUT)
                    try:
                        pilot.wait_ready(child,port)
                        deadline=time.monotonic()+30
                        while time.monotonic()<deadline:
                            require(child.poll() is None,'Private demo file-smoke child exited')
                            received=legacy.helpers.read_pcap(trial/'output_out.pcap',partial=True)
                            if len(received)==len(frames):break
                            require(len(received)<=len(frames),'Extra file-smoke outputs')
                            time.sleep(.03)
                        else:raise ValueError('Bounded demo file smoke timed out')
                        counters=legacy.read_counters(args,port,trial,'counter_query.json') if mode.startswith('rf_') else None
                    finally:ownership.stop_child(child)
                require(legacy.helpers.read_pcap(trial/'output_out.pcap')==frames,'Demo smoke changed bytes/order')
                require(counters is None or (sum(c['packets'] for c in counters)==expected
                    and sum(c['bytes'] for c in counters)==expected*legacy.FRAME_BYTES),'Demo smoke RF counter mismatch')
                results[name+'_'+mode]={'passed':True,'packets':64,'unchanged_forwarded':64,
                    'decisions':sum(c['packets'] for c in counters) if counters else None,
                    'expected_decisions':expected if counters else None,'selected_flow_packet_counts':per_flow,
                    'native_pacing_exercised':False,'warmup_state_exercised':False}
                print(f'LIVE FILE SMOKE {name}, {mode}: 64/64 unchanged; decisions={results[name+"_"+mode]["decisions"]}',flush=True)
        ownership.verify_hashes(m['input_sha256'])
    except BaseException as exc:
        write_json(directory/'failure.json',{'stage':'file-smoke','error':f'{type(exc).__name__}: {exc}'})
        raise
    write_json(directory/'summary.json',dict(schema_version=SCHEMA,status='live_demo_file_smoke_passed',passed=True,
        prepared_manifest_sha256=hash_file(Path(args.prepared)/'manifest.json'),
        results=results,artifact_hashes=pilot.seal(directory),
        smoke_scope='64 frames per workload/mode, fresh file switch; existing generated bytes and classifier counters only',
        preserved_prior_smoke_failure='results/live_demo_packet_file_checks/20261010T005621Z_ead1cd0c9e',
        bounded_smoke_reason='Legacy 320-frame unpaced file burst lost 29 middle outputs; frozen egress queue unchanged. New 64-frame smoke is not pacing/performance validation.',
        live_interfaces_accessed=False,performance_measured=False,raw_sender_live_pacing_qualified=False))
    print(f'LIVE DEMO NONPRIVILEGED SMOKE PASS. Checks: {directory}',flush=True)
    return directory


def verify_smoke(args):
    s=integration.read_json(Path(args.smoke_run)/'summary.json')
    require(s.get('schema_version')==SCHEMA and s.get('passed') is True
        and s.get('prepared_manifest_sha256')==hash_file(Path(args.prepared)/'manifest.json'),'Demo smoke does not bind this preparation')
    legacy.verify_seal(Path(args.smoke_run),s['artifact_hashes'])
    require(len(s['results'])==8 and all(r.get('passed') and r.get('packets')==64 for r in s['results'].values()),
            'Incomplete normal-build demo file smoke')


@contextmanager
def demo_lock(repo):
    import fcntl
    folder=repo/'results/live_demo_control';folder.mkdir(parents=True,exist_ok=True)
    with (folder/'launch.lock').open('a') as stream:
        try:fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Another live demo launch owns the lock')
        try:yield
        finally:fcntl.flock(stream.fileno(),fcntl.LOCK_UN)


def resolve_run_directory(repo,path):
    root=(repo/'results/live_demo').resolve();requested=Path(path).absolute()
    require(not requested.is_symlink() and requested.resolve()==requested,'Run directory cannot be a symlink or resolve through one')
    directory=requested.resolve()
    require(directory.parent==root and directory.is_dir(),'Run directory must be a fresh immediate live_demo child')
    require(not any(directory.iterdir()),'Refuse nonempty live demo directory; no evidence overwrite')
    return directory


def reclaim_ownership(directory):
    """Only our validated new demo subtree; never historical research paths."""
    if not os.environ.get('SUDO_UID'):return
    uid,gid=int(os.environ['SUDO_UID']),int(os.environ['SUDO_GID'])
    for p in [directory,*directory.rglob('*')]:
        if not p.is_symlink():os.chown(p,uid,gid)
    for p in (directory.parent/'current.json',):
        if p.is_file() and not p.is_symlink():os.chown(p,uid,gid)


def demo_artifact_seal(directory):
    """Hash only completed static evidence, never growing telemetry/temp files."""
    selected=[directory/name for name in ('provenance.json','clock_rate_qualification.json')]
    trial=directory/'trial_001'
    if trial.is_dir():selected.extend(p for p in trial.rglob('*') if p.is_file() and not p.is_symlink())
    return {p.relative_to(directory).as_posix():hash_file(p) for p in sorted(selected)
            if p.is_file() and not p.is_symlink() and not p.name.startswith('.') and not p.name.endswith('.tmp')}


def run(args,repo):
    require(os.geteuid()==0,'The demo worker requires explicit terminal sudo authorization')
    # Acquire the existing campaign guard BEFORE publishing an active pointer.
    # A conflicting manual worker cannot replace a genuine active run's UI.
    with legacy.exclusive_run(repo):
        oldmask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:return _run_locked(args,repo)
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,oldmask)


def _run_locked(args,repo):
    require(os.geteuid()==0,'The demo worker requires explicit terminal sudo authorization')
    from live_telemetry import TelemetryWriter
    m,receipt,reader,sender,warm,measured=load_prepared(args,repo);verify_smoke(args)
    directory=resolve_run_directory(repo,args.run_directory)
    protocol=m['protocol'];mode=protocol['modes'][0];block=m['block'];run_id=directory.name
    qualifier=calibration.raw_clock.RateQualification(reader=reader.read)
    writer=TelemetryWriter(directory,run_id,dict(mode=mode,workload=block['workload'],rate_pps=block['rate_pps'],
        warmup_seconds=5,measurement_seconds=20,total_trials=1,observer_effect='Streamlit and demo telemetry active on same WSL host',
        dashboard_pid=args.dashboard_pid,demo_only=True,kernel_latency_qualified=False))
    observer=demo_transport.DemoObserver(writer,qualifier)
    args.raw_reader=reader;args.raw_sender=demo_transport.ObservedSender(sender,observer)
    links=ownership.OwnedLinks(uuid.uuid4().hex[:6]);rows=[];error=None;interrupted=threading.Event()
    signal_stop=threading.Event()
    def watch_signals():
        while not signal_stop.is_set():
            pending=signal.sigtimedwait({signal.SIGINT,signal.SIGTERM},.2)
            if pending:
                interrupted.set();observer.cancel();writer.emit('interruption_requested',phase='stopping',signal=pending.si_signo)
    watcher=threading.Thread(target=watch_signals,name='demo-cancellation',daemon=True);watcher.start()
    observer.start()
    summary=None
    try:
        with nullcontext():
            legacy.resource_preflight(repo)
            write_json(directory/'provenance.json',dict(schema_version=SCHEMA,prepared=str(Path(args.prepared).resolve()),
                prepared_manifest_sha256=hash_file(Path(args.prepared)/'manifest.json'),source_input_sha256=m['input_sha256'],
                normal_definitions=legacy.NORMAL,topology='private owned two-veth topology',
                observer_effect='1Hz JSON telemetry and Streamlit coexist; provisional demo measurements, no historical qualification inherited',
                dashboard_pid=args.dashboard_pid,host_before=legacy.host_snapshot(),synchronization_changed=False,
                owned_child_cleanup='Signals blocked for dedicated cancellation watcher; existing bounded stop_child may escalate only its owned Popen child to SIGKILL',
                demo_observer_injection_scope='Dedicated single-trial worker process; existing RAW transport source/native C unchanged'))
            writer.emit('experiment_started',phase='preparing',trial=1,total_trials=1)
            qualifier.start()
            require(len(qualifier.pins)==len(calibration.raw_clock.PROVIDERS)
                and all(q.get('valid') and q.get('query_brackets_valid') for q in qualifier.records),'Initial independent reference acquisition failed; no traffic launched')
            require(not interrupted.is_set(),'Interrupted before switch startup')
            with links:
                writer.emit('switch_starting',phase='preparing',trial=1,total_trials=1)
                with observer.scoped(calibration):
                    row=calibration.run_trial(args,m['programs'][mode]['path'],mode,block,warm,measured,links,
                                              directory/'trial_001',qualifier=qualifier)
                rows.append(row)
                row['metrics']['expected_decisions']=measured.expected_classifications if mode.startswith('rf_') else None
                final_measurement=integration.read_json(directory/'trial_001/measurement.json')
                row['capture_integrity']={'packet_accounting_valid':final_measurement['metric_validity']['packet_accounting'],
                    'capture_statistics':final_measurement['capture_statistics'],
                    'capture_counters':final_measurement['capture_counters'],
                    'path_non_delivery':final_measurement['path_non_delivery']}
                writer.emit('trial_completed',phase='finalizing',trial=1,trial_summary=row)
    except BaseException as exc:
        error=f'{type(exc).__name__}: {exc}'
        writer.emit('experiment_error',phase='finalizing',error=error)
    finally:
        try:observer.stop()
        except (RuntimeError,OSError) as exc:error=f'Observer cleanup failed: {exc}'
        try:qualifier.stop() if qualifier._thread is not None else None
        except (RuntimeError,OSError) as exc:error=f'Clock reference cleanup failed: {exc}'
        signal_stop.set();watcher.join(1)
        if watcher.is_alive():error='Cancellation watcher did not stop'
        if observer.errors:error='Demo telemetry observation failed: '+'; '.join(observer.errors)
        qualification=qualifier.report(load_windows=[r['rate_window'] for r in rows if r['instrument_valid_before_rate_qualification']])
        write_json(directory/'clock_rate_qualification.json',qualification)
        qualified=qualification.get('passed',qualification.get('status')=='PASS') is True
        effective=deepcopy(rows);calibration.apply_rate_qualification(effective,qualified,qualification)
        unchanged=True
        try:ownership.verify_hashes(m['input_sha256'])
        except (OSError,ValueError,RuntimeError) as exc:unchanged=False;error=f'Frozen input verification failed: {exc}'
        if not unchanged or links.cleanup_errors:
            for r in effective:
                r['valid']=False
                r['failures'].append(error or 'Owned topology cleanup failed')
                r['metric_validity']={key:False for key in r['metric_validity']}
        status='interrupted' if interrupted.is_set() else 'failed' if error or links.cleanup_errors or not unchanged else 'completed'
        summary=dict(schema_version=SCHEMA,status=status,demo_only=True,run_id=run_id,evidence=str(directory),
            trials=effective,acquired_trials=len(rows),expected_trials=1,error=error,cleanup_errors=links.cleanup_errors,
            frozen_inputs_unchanged=unchanged,independent_raw_qualification=qualification.get('status','INCONCLUSIVE'),
            short_demo_qualification_expected_inconclusive=True,kernel_forwarding_latency_qualified=False,
            isolated_inference_latency_measured=False,accuracy_scored=False,observer_effect_recorded=True,
            telemetry_observer_errors=observer.errors,execution_completed=error is None and not interrupted.is_set(),
            artifact_hashes=demo_artifact_seal(directory),
            telemetry_artifacts_excluded_from_scientific_seal=['events.jsonl','snapshot.json'])
        write_json(directory/'summary.json',summary)
        try:writer.close(status=status,final_summary=summary,error=error,final_summary_file='summary.json')
        finally:reclaim_ownership(directory)
    print(f'LIVE DEMO {summary["status"].upper()}: evidence {directory}\nIndependent clock: {summary["independent_raw_qualification"]}; latency UNQUALIFIED. Dashboard stays open.',flush=True)
    return directory


def launch(args,repo):
    require(os.geteuid()!=0,'Launch as your normal Ubuntu user; only the worker uses sudo')
    from dashboard_process import ensure_dashboard
    with demo_lock(repo):
        dashboard=ensure_dashboard(repo,port=args.port)
        print(f'Dashboard: http://localhost:{args.port} — select Live Experiment Monitor',flush=True)
        prepared=prepare(args,repo);args.prepared=prepared;smoke_run=smoke(args,repo)
        directory=ownership.new_directory(repo/'results/live_demo')
        command=['sudo',str(repo/'.venv/bin/python'),'-B',str(Path(__file__).resolve()),
                 '--switch',str(args.switch),'--cli-python',str(args.cli_python),'--cli',str(args.cli),
                 'run','--prepared',str(prepared),'--smoke-run',str(smoke_run),'--run-directory',str(directory)]
        pid=dashboard.get('pid')
        if pid:command+=['--dashboard-pid',str(pid)]
        print('Terminal authorization required for the one bounded BMv2 demo; no browser privileged control.',flush=True)
        child=subprocess.Popen(command,cwd=repo)
        try:return child.wait()
        except KeyboardInterrupt:
            print('Cancellation requested. Waiting for the bounded worker to preserve evidence and clean up owned resources...',flush=True)
            try:child.wait(timeout=60)
            except subprocess.TimeoutExpired:
                print('Worker cleanup is not yet confirmed; do not launch another demo. Dashboard remains open.',file=sys.stderr)
            return 130


def main(argv=None):
    repo=Path(__file__).resolve().parent.parent
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--switch',type=Path,default=repo.parent/'behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--cli-python',type=Path,default=repo.parent/'bmv2-venv/bin/python')
    parser.add_argument('--cli',type=Path,default=repo.parent/'behavioral-model/targets/simple_switch/simple_switch_CLI')
    sub=parser.add_subparsers(dest='action',required=True)
    for action in ('prepare','launch'):
        p=sub.add_parser(action);p.add_argument('--mode',choices=MODES,default='rf_c');p.add_argument('--rate',type=int,choices=RATES,default=250)
        p.add_argument('--workload',choices=WORKLOADS,default='classification-heavy')
        p.add_argument('--source-prepared',type=Path,default=repo/DEFAULT_RAW_PREP)
        p.add_argument('--port','--dashboard-port',dest='port',type=int,default=8501)
    for action in ('smoke','run'):
        p=sub.add_parser(action);p.add_argument('--prepared',type=Path,required=True)
        if action=='run':
            p.add_argument('--smoke-run',type=Path,required=True);p.add_argument('--run-directory',type=Path,required=True)
            p.add_argument('--dashboard-pid',type=int)
    args=parser.parse_args(argv)
    try:
        result={'prepare':prepare,'smoke':smoke,'run':run,'launch':launch}[args.action](args,repo)
        if args.action=='launch':return result
        if args.action=='run':
            status=integration.read_json(result/'summary.json')['status']
            return 130 if status=='interrupted' else 2 if status=='failed' else 0
        return 0
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        print(f'LIVE DEMO STOPPED: {error}',file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
