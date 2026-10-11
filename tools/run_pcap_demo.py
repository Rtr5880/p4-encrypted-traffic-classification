#!/usr/bin/env python3
"""Bounded real-PCAP native-clock demonstration, not an accuracy experiment.

launch is ordinary-user prepare/file-smoke/dashboard reuse; only the manually
authorized sudo worker creates private veths and replays actual packets.
"""
import argparse
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import uuid

import integrate_rf as integration
import run_native_clock_pilot as native
import run_performance_benchmark as legacy
import run_live_demo as synthetic
import pcap_demo_replay as replay

SCHEMA='live-pcap-classification-demo-v1'
MODES=('rf_b','rf_c','compare')
CURRENT_NATIVE_PREP='results/native_clock_pilot_preparation/20261007T215405Z_dcb5a49d72'
require,write_json,hash_file=legacy.require,legacy.write_json,legacy.hash_file


def selected_models(mode):
    require(mode in MODES,'PCAP mode must be rf_b, rf_c or compare')
    return ['B','C'] if mode=='compare' else ['B' if mode=='rf_b' else 'C']


def source_hashes(repo):
    paths=[repo/p for p in ('tools/run_pcap_demo.py','tools/pcap_demo_replay.py','tools/pcap_demo_examples.py',
        'tools/live_telemetry.py','tools/dashboard_process.py','dashboard/app.py','dashboard/views/live.py','dashboard/views/pcap_live.py',
        'dashboard/live_evidence.py','requirements-dashboard.txt','tools/raw_performance_resources.py','tools/live_demo_transport.py')]
    paths+=[Path(module.__file__) for module in (native,native.transport,native.prefix,integration,native.reference,
                                               native.helpers,native.native_analysis,native.clock_contract,legacy,synthetic,replay,
                                               native.replay,native.replay.instances,native.replay.capture_io)]
    return {str(p.resolve()):hash_file(p) for p in paths}


def validate_bundle(bundle):
    require(bundle.get('native_clock_required') is True and len(bundle.get('packets',[]))==8,'Demo needs exactly eight native-clock prefix packets')
    require(bundle['record']['partition']=='test' and bundle['record']['n']==8,'Example must retain held-out N8 provenance')
    offsets=bundle['relative_us']
    require(len(offsets)==8 and offsets[0]==0 and offsets==sorted(offsets) and 0<offsets[-1]<=2_000_000,
            'Selected prefix must have unscaled, ordered within-prefix offsets ≤2 seconds')
    for packet in bundle['packets']:
        raw=bytes.fromhex(packet['raw_ip_hex'])
        require(hashlib.sha256(raw).hexdigest()==packet['sha256'],'Original IPv4 bytes changed')
        require(raw and raw[0]>>4==4,'Only original raw IPv4 prefixes are supported')
    require(set(bundle['native_programs'])=={'B','C'},'Both frozen native debug programs required')


def prepare(args,repo):
    from pcap_demo_examples import prepare_example
    models=selected_models(args.mode);bundle=prepare_example(repo,args.example);validate_bundle(bundle)
    native.verify_hashes(bundle['input_sha256'])
    exports,_,_=integration.load_deployment(Path(bundle['deployment']))
    require(all(exports[m]['classes']==replay.CLASSES and len(exports[m]['trees'])==10 for m in 'BC'),'Frozen six-class ten-tree model contract changed')
    current_path=repo/CURRENT_NATIVE_PREP
    current=integration.read_json(current_path/'manifest.json')
    require(current.get('status')=='prepared' and current.get('compile_definitions')==
            {'TEST_TIMESTAMPS':0,'DEBUG_REPORT':1,'FLOW_SLOTS':65536},'Unexpected current native clock attestation source')
    receipt=native.clock_contract.verify_receipt(current['clock_source_receipt'],args.switch)
    require(receipt['receipt_sha256']==current['clock_source_receipt_sha256'],'Current clock receipt identity changed')
    directory=native.new_directory(repo/'results/pcap_demo_preparation')
    write_json(directory/'prefix.json',bundle)
    hashes=dict(bundle['input_sha256']);hashes.update(source_hashes(repo))
    hashes.update({v['path']:v['sha256'] for v in bundle['native_programs'].values()})
    hashes.update({item['path']:item['sha256'] for item in receipt['artifacts'].values()})
    hashes[str((current_path/'manifest.json').resolve())]=hash_file(current_path/'manifest.json')
    hashes[str(Path(current['clock_source_receipt']).resolve())]=receipt['receipt_sha256']
    manifest={'schema_version':SCHEMA,'status':'prepared','example':args.example,'mode':args.mode,'models':models,
        'prefix_sha256':hash_file(directory/'prefix.json'),'programs':bundle['native_programs'],
        'clock_receipt':current['clock_source_receipt'],'clock_receipt_sha256':receipt['receipt_sha256'],
        'current_native_attestation_source':str(current_path),
        'historical_source_clock_receipt':bundle['clock_receipt'],
        'historical_source_receipt_is_not_current_attestation':True,
        'input_sha256':hashes,'compile_definitions':{'TEST_TIMESTAMPS':0,'DEBUG_REPORT':1,'FLOW_SLOTS':65536},
        'native_clock':True,'controlled_timestamps':False,'frozen_models_changed':False,'new_fits':0,
        'maximum_models':2,'eligible_packets_per_model':8,'within_flow_timing_scaled':False,
        'monitoring_protocol':'pcap-demo-monitoring-v1','monitoring_periodic_seconds':1.0,
        'resource_window_definition':replay.RESOURCE_WINDOW,'qualified_performance_metrics':False,
        'observer_effect':'Live dashboard and asynchronous debug-report telemetry may perturb native arrival times; each model is verified against its own actual ingress times'}
    manifest['artifact_hashes']={'prefix.json':hash_file(directory/'prefix.json')}
    write_json(directory/'manifest.json',manifest)
    print(f'PCAP DEMO PREPARED: {args.example}, {args.mode}; same eight original packets; no timing scaling.\nPrepared: {directory}',flush=True)
    return directory


def load_prepared(args,repo):
    directory=Path(args.prepared).resolve();m=integration.read_json(directory/'manifest.json')
    require(m.get('schema_version')==SCHEMA and m.get('status')=='prepared' and m.get('new_fits')==0,'Wrong PCAP demonstration preparation')
    require(m['models']==selected_models(m['mode']),'Prepared models changed')
    legacy.verify_seal(directory,m['artifact_hashes']);native.verify_hashes(m['input_sha256'])
    require(hash_file(directory/'prefix.json')==m['prefix_sha256'],'Sealed prefix changed')
    bundle=integration.read_json(directory/'prefix.json');validate_bundle(bundle)
    require(bundle['native_programs']==m['programs'],'Frozen native programs changed')
    receipt=native.clock_contract.verify_receipt(m['clock_receipt'],args.switch)
    require(receipt['receipt_sha256']==m['clock_receipt_sha256'],'Attested switch clock/binary changed')
    exports,_,_=integration.load_deployment(Path(bundle['deployment']))
    require(all(exports[k]['classes']==replay.CLASSES and len(exports[k]['trees'])==10 for k in 'BC'),'Class/tree mapping changed')
    return m,bundle,exports,receipt


def smoke(args,repo):
    m,bundle,exports,receipt=load_prepared(args,repo)
    directory=native.new_directory(repo/'results/pcap_demo_checks');results={}
    frames=[bytes.fromhex('0200000000020200000000010800')+bytes.fromhex(p['raw_ip_hex']) for p in bundle['packets']]
    try:
        for model in m['models']:
            child=directory/f'RF_{model}'
            output=native.helpers.run_switch(args.switch,Path(m['programs'][model]['path']),child,frames,8,timeout=20)
            result=native.compare_native(bundle,exports[model],output)
            require(result['passed'],'Native debug packet-file parity/clock check failed')
            write_json(child/'comparison.json',result)
            results[model]={'passed':True,'packets':8,'feature_mismatches':result['feature_mismatches'],
                'leaf_mismatches':result['leaf_mismatches'],'score_mismatches':result['score_mismatches'],
                'class_mismatches':result['class_mismatches'],'file_native_prediction':result['native_time_prediction']}
            print(f'PCAP FILE SMOKE RF-{model}: 8/8 feature/leaf/score/prediction parity PASS (not paced live replay).',flush=True)
        native.verify_hashes(m['input_sha256'])
    except BaseException as exc:
        write_json(directory/'failure.json',{'error':f'{type(exc).__name__}: {exc}'});raise
    summary={'schema_version':SCHEMA,'status':'pcap_demo_file_smoke_passed','passed':True,'models':results,
        'prepared_manifest_sha256':hash_file(Path(args.prepared)/'manifest.json'),
        'live_interfaces_accessed':False,'accuracy_scored':False,'performance_measured':False,
        'artifact_hashes':{p.relative_to(directory).as_posix():hash_file(p) for p in directory.rglob('*') if p.is_file() and not p.is_symlink()}}
    write_json(directory/'summary.json',summary)
    print(f'PCAP DEMO NONPRIVILEGED SMOKE PASS. Checks: {directory}',flush=True)
    return directory


def verify_smoke(args):
    s=integration.read_json(Path(args.smoke_run)/'summary.json')
    require(s.get('schema_version')==SCHEMA and s.get('passed') is True
            and s['prepared_manifest_sha256']==hash_file(Path(args.prepared)/'manifest.json'),'PCAP smoke does not bind preparation')
    legacy.verify_seal(Path(args.smoke_run),s['artifact_hashes'])


def run(args,repo):
    require(os.geteuid()==0,'PCAP worker needs explicit Ubuntu terminal sudo authorization')
    with legacy.exclusive_run(repo):
        prior=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:return _run_locked(args,repo)
        finally:
            # Consume owned-worker cancellation signals before restoring the
            # original mask, so repeated Ctrl+C cannot interrupt final cleanup.
            while signal.sigtimedwait({signal.SIGINT,signal.SIGTERM},0) is not None:pass
            signal.pthread_sigmask(signal.SIG_SETMASK,prior)


def watch_cancellation(observer,writer,stop,wait=None):
    wait=signal.sigtimedwait if wait is None else wait
    while not stop.is_set():
        pending=wait({signal.SIGINT,signal.SIGTERM},.2)
        if pending:
            observer.cancel()
            writer.emit('interruption_requested',phase='stopping',signal=pending.si_signo)


def preserve_model_result(results,model,result,observer):
    """Retain the native comparison before optional observer finalization."""
    results[model]=result
    observer.complete_model(model,result)


def _run_locked(args,repo):
    from live_telemetry import TelemetryWriter
    m,bundle,exports,receipt=load_prepared(args,repo);verify_smoke(args)
    require(native.math.isfinite(args.timeout_seconds) and 3<=args.timeout_seconds<=15,
            'Bounded PCAP timeout must be between three and fifteen seconds')
    directory=synthetic.resolve_run_directory(repo,args.run_directory)
    tag=bytes.fromhex('02'+uuid.uuid4().hex[:10]+'02'+uuid.uuid4().hex[:10])
    example=deepcopy(bundle['selected_example']);example.update(relative_us=bundle['relative_us'],
        capture=bundle['capture']['filename'],capture_hint=bundle['record']['label'],
        source_frame_numbers=[p['original_frame'] for p in bundle['packets']])
    metadata={'demo_kind':'pcap','mode':m['mode'],'selected_example':m['example'],'total_trials':len(m['models']),
        'native_clock':True,'source_example':example,
        'monitoring_protocol':'pcap-demo-monitoring-v1','resource_window_definition':replay.RESOURCE_WINDOW,
        'observer_effect':'Streamlit/debug-report telemetry active; actual BMv2 ingress times supply parity reference'}
    writer=TelemetryWriter(directory,directory.name,metadata);observer=replay.ReplayObserver(writer,bundle,exports,tag)
    observer.configure_runtime(args.switch,m['programs'],directory)
    links=native.OwnedLinks(uuid.uuid4().hex[:6]);results={};error=None;interrupted=False
    execution_error=None;cleanup_issues=[]
    signal_stop=threading.Event();watcher=threading.Thread(target=watch_cancellation,args=(observer,writer,signal_stop),
                                                        name='pcap-demo-cancellation',daemon=True)
    try:
        watcher.start();observer.start()
        legacy.resource_preflight(repo)
        write_json(directory/'provenance.json',{'schema_version':SCHEMA,'prepared':str(Path(args.prepared).resolve()),
            'prepared_manifest_sha256':hash_file(Path(args.prepared)/'manifest.json'),'source_sha256':m['input_sha256'],
            'clock_source_receipt':receipt,'source_example':metadata['source_example'],'programs':m['programs'],
            'native_clock':True,'controlled_timestamps':False,'same_ipv4_prefix_for_models':True,
            'same_ethernet_wrapping_for_models':True,'within_flow_offsets_us':bundle['relative_us'],
            'within_flow_timing_scaled':False,'replay_is_new_live_capture':False,'dashboard_pid':args.dashboard_pid,
            'observer_effect':metadata['observer_effect'],'host_before':legacy.host_snapshot(),
            'owned_child_cleanup':'Signals blocked for dedicated cancellation watcher; existing bounded stop_child may escalate only owned Popen child to SIGKILL',
            'monitoring_protocol':'pcap-demo-monitoring-v1','resource_window_definition':replay.RESOURCE_WINDOW,
            'resource_sampling_seconds':1.0,'resource_observations_qualified':False,
            'capture_socket_drop_statistics':'Unavailable in unchanged native pilot; not assumed zero',
            'not_measured':['accuracy','macro-F1','throughput','forwarding latency','isolated RF latency','qualified CPU percentages']})
        writer.emit('pcap_experiment_started',phase='preparing',source_example=metadata['source_example'],total_trials=len(m['models']))
        with links:
            write_json(directory/'interfaces.json',links.owned)
            with observer.scoped():
                for ordinal,model in enumerate(m['models'],1):
                    if observer.cancelled.is_set():raise KeyboardInterrupt('PCAP demonstration cancelled')
                    observer.begin_model(model,trial=ordinal)
                    result=native.run_model(args,Path(m['programs'][model]['path']),bundle,exports[model],links,directory/f'RF_{model}')
                    # Native comparison is authoritative even if subsequent
                    # presentation/telemetry finalization fails.
                    preserve_model_result(results,model,result,observer)
        native.verify_hashes(m['input_sha256'])
    except KeyboardInterrupt as exc:
        interrupted=True;observer.cancel();error=str(exc) or 'Cancellation requested';execution_error=error
        writer.emit('interruption_requested',phase='stopping',error=error)
    except BaseException as exc:
        error=f'{type(exc).__name__}: {exc}';execution_error=error;writer.emit('producer_error',phase='finalizing',error=error)
    finally:
        try:observer.stop()
        except (RuntimeError,OSError) as exc:cleanup_issues.append(f'Observer cleanup failed: {exc}')
        signal_stop.set()
        if watcher.ident is not None:watcher.join(1)
        if watcher.is_alive():cleanup_issues.append('PCAP cancellation watcher did not stop')
        interrupted=interrupted or observer.cancelled.is_set()
        all_issues=([execution_error] if execution_error else [])+cleanup_issues+list(links.cleanup_errors)+list(observer.errors)
        error='; '.join(all_issues) if all_issues else None
        write_json(directory/'observed_packets.json',{'source':'Actual matched native pilot capture observations',
                                                     'diagnostic_timestamps_not_latency':True,'packets':observer.packet_events})
        monitoring=observer.monitoring_evidence()
        write_json(directory/'pcap_monitoring.json',monitoring)
        status='interrupted' if interrupted else 'failed' if error or links.cleanup_errors else 'completed'
        normalized={};shared_vectors={};normalization_errors=[]
        for model,result in results.items():
            try:
                normalized[model]=replay.normalized_result(model,bundle,exports[model],result)
                shared_vectors[model]={target:native.predict(exports[target],result['decision']['features_C']) for target in 'BC'}
            except (ValueError,KeyError,TypeError,IndexError) as exc:
                normalization_errors.append(f'RF-{model}: {type(exc).__name__}: {exc}')
        if normalization_errors:
            error='; '.join(([error] if error else [])+normalization_errors)
            if not interrupted:status='failed'
        summary={'schema_version':SCHEMA,'demo_kind':'pcap','status':status,'run_id':directory.name,'evidence':str(directory),
            'mode':m['mode'],'example':m['example'],'source_example':metadata['source_example'],
            'classification_results':normalized,'both_models_on_each_observed_vector':shared_vectors,
            'pcap_monitoring':monitoring['pcap_monitoring'],'monitoring_errors':monitoring['monitoring_errors'],
            'monitoring_source':str(directory/'pcap_monitoring.json'),
            'partial_classification_results':{k:v for k,v in observer.results.items() if k not in normalized},
            'models_completed':len(results),'models_expected':len(m['models']),'error':error,'cleanup_errors':links.cleanup_errors,
            'execution_error':execution_error,'observer_cleanup_errors':cleanup_issues,'normalization_errors':normalization_errors,
            'completed_model_sources':{model:str(directory/f'RF_{model}/comparison.json') for model in results},
            'same_prefix_and_schedule_for_models':True,'different_native_ingress_times_possible':True,
            'parity_is_not_activity_accuracy':True,'native_clock':True,'controlled_timestamps':False,
            'accuracy_scored':False,'performance_measured':False,'kernel_forwarding_latency_qualified':False,
            'isolated_inference_latency_measured':False,'telemetry_observer_errors':observer.errors,
            'artifact_hashes':{p.relative_to(directory).as_posix():hash_file(p) for p in directory.rglob('*')
                if p.is_file() and not p.is_symlink() and (p.relative_to(directory).parts[0] in ('RF_B','RF_C')
                  or p.name in ('provenance.json','interfaces.json','observed_packets.json','pcap_monitoring.json'))},
            'limitations':bundle['limitations']+['Stored PCAP replay is not fresh network acquisition.',
                'Separate model runs observe different native times; compare is not a direction-only statistical ablation.',
                replay.RESOURCE_WINDOW,
                'CPU percentages are provisional Linux OS-accounting/RAW observations, not independently qualified physical utilization.',
                'Short replay prefixes may have only real start/end observations; no synthetic trend points are generated.',
                'Capture socket drops are unavailable; tagged packet accounting is not a causal BMv2 loss certificate.',
                'Capture hints and displayed predictions are not independently verified activity ground truth.']}
        write_json(directory/'summary.json',summary)
        try:writer.close(status=status,final_summary=summary,error=error,final_summary_file='summary.json')
        finally:synthetic.reclaim_ownership(directory)
    print(f'PCAP DEMO {status.upper()}: {len(results)}/{len(m["models"])} model replays completed. Evidence: {directory}',flush=True)
    return directory


def launch(args,repo):
    require(os.geteuid()!=0,'Launch as ordinary Ubuntu user; only PCAP worker uses sudo')
    from dashboard_process import ensure_dashboard
    with synthetic.demo_lock(repo):
        dashboard=ensure_dashboard(repo,port=args.dashboard_port)
        print(f'Dashboard: http://localhost:{args.dashboard_port} — Live Experiment Monitor / Real PCAP',flush=True)
        prepared=prepare(args,repo);args.prepared=prepared;check=smoke(args,repo)
        directory=native.new_directory(repo/'results/live_demo')
        command=['sudo',str(repo/'.venv/bin/python'),'-B',str(Path(__file__).resolve()),
            '--switch',str(args.switch),'--cli-python',str(args.cli_python),'run','--prepared',str(prepared),
            '--smoke-run',str(check),'--run-directory',str(directory)]
        if dashboard.get('pid'):command+=['--dashboard-pid',str(dashboard['pid'])]
        print('Terminal sudo authorization starts only this bounded real-PCAP replay.',flush=True)
        child=subprocess.Popen(command,cwd=repo)
        try:return child.wait()
        except KeyboardInterrupt:
            print('Waiting for PCAP worker to preserve partial evidence and clean up owned resources...',flush=True)
            try:child.wait(timeout=30)
            except subprocess.TimeoutExpired:print('Cleanup not confirmed; do not start a competing demo.',file=sys.stderr)
            return 130


def main(argv=None):
    repo=Path(__file__).resolve().parent.parent
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--switch',type=Path,default=repo.parent/'behavioral-model/targets/simple_switch/simple_switch')
    parser.add_argument('--cli-python',type=Path,default=repo.parent/'bmv2-venv/bin/python')
    sub=parser.add_subparsers(dest='action',required=True)
    for action in ('prepare','launch'):
        p=sub.add_parser(action);p.add_argument('--mode',choices=MODES,default='compare');p.add_argument('--example',default='voip')
        p.add_argument('--dashboard-port',type=int,default=8501)
    for action in ('smoke','run'):
        p=sub.add_parser(action);p.add_argument('--prepared',type=Path,required=True)
        if action=='run':
            p.add_argument('--smoke-run',type=Path,required=True);p.add_argument('--run-directory',type=Path,required=True)
            p.add_argument('--dashboard-pid',type=int);p.add_argument('--timeout-seconds',type=float,default=5)
    args=parser.parse_args(argv)
    try:
        result={'launch':launch,'prepare':prepare,'smoke':smoke,'run':run}[args.action](args,repo)
        if args.action=='launch':return result
        if args.action=='run':
            status=integration.read_json(result/'summary.json')['status']
            return 130 if status=='interrupted' else 2 if status=='failed' else 0
        return 0
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        print(f'PCAP DEMO STOPPED: {exc}',file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
