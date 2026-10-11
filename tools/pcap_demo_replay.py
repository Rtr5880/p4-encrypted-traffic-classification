"""Bounded demo observations around the unchanged native-clock PCAP pilot.

Only authentic matched packet reports are queued. A separate decoder thread
publishes progress; no file/JSON work is done in the capture/send path.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import queue
import threading
import time

import integrate_rf as integration
import run_native_clock_pilot as native
import raw_performance_resources as resources
from live_demo_transport import cpu_observation

CLASSES=['CHAT','FT','MAIL','P2P','STREAMING','VOIP']
FEATURE_NAMES=['size_min','size_max','size_sum','iat_min','iat_max','iat_sum',
               'reverse_packet_count','direction_change_count']
RESOURCE_WINDOW=('Replay invocation: socket setup, original-offset packet sends and bounded capture drain; '
                 'excludes BMv2 startup/model loading, Python parity verification and CLI counter reads. '
                 'Not isolated RF inference cost or a qualified performance measurement.')


def resource_point(previous,current,ticks,phase,previous_phase=None,valid=True):
    """One actual /proc snapshot and its actual OS-tick/RAW interval, never interpolated."""
    interval_phase=phase if previous is None or previous_phase==phase else 'mixed'
    cpu=cpu_observation(previous,current,ticks) if valid else None
    valid=bool(valid and (previous is None or cpu is not None))
    return {'valid':bool(valid),'qualified':False,'phase':phase,'cpu_interval_phase':interval_phase,
        'cpu_window_label':f'{previous_phase} → {phase}' if interval_phase=='mixed' else phase,
        'sample_raw_ns':current['raw_ns'],
        'window_start_raw_ns':previous['raw_ns'] if previous else None,'window_end_raw_ns':current['raw_ns'],
        'cpu_percent_one_core':cpu if valid else None,
        'rss_mib':current.get('rss_kib')/1024 if valid and current.get('rss_kib') is not None else None,
        'vmhwm_lifetime_mib':current.get('vmhwm_kib')/1024 if valid and current.get('vmhwm_kib') is not None else None,
        'cpu_meaning':resources.CPU_CAVEAT,'window_label':RESOURCE_WINDOW}


def transport_accounting(report):
    """Preserve exact tagged-match accounting without certifying socket-drop absence."""
    observed_count=lambda key:len(report[key]) if isinstance(report.get(key),list) else None
    return {'sent_packets':observed_count('sent_logs'),
        'input_observed':observed_count('input_observations'),
        'output_observed':observed_count('output_observations'),
        'missing_input_indices':deepcopy(report.get('missing_input_indices')),
        'missing_output_indices':deepcopy(report.get('missing_output_indices')),
        'transport_passed':report.get('transport_passed'), 'errors':deepcopy(report.get('errors',[])),
        'expected_decisions':1,'decisions':None,'counters_verified':None,
        'capture_socket_drops':None,
        'capture_reliability_note':'Native pilot does not query PACKET_STATISTICS. Missing tagged observations do not establish causal BMv2 loss.'}


def feature_values(report):
    return {name:report[native.helpers.FEATURE_NAMES.get(name,name)] for name in FEATURE_NAMES}


def normalized_result(model,bundle,export,result):
    packets=result['packet_checks'];decision=result['decision'];last=packets[-1]
    feature=feature_values(last['feature_report']);rf=last['rf_report'];python=decision['expected_rf']
    return {'feature_set':model,'status':'verified' if result['passed'] else 'clock_incomplete',
        'capture':bundle['capture']['filename'],'record_id':bundle['record']['record_id'],
        'capture_hint':bundle['record']['label'],'label_basis':'capture_activity_hint; not independently verified per-flow ground truth',
        'eligible_packets_observed':len(packets),'packet_eight_triggered':rf['valid']==1,
        'features_B':{k:feature[k] for k in FEATURE_NAMES[:6]},'features_C':feature,
        'features_used':{k:feature[k] for k in export['feature_order']},'feature_order':export['feature_order'],
        'leaf_ids':rf['leaves'],'scores':rf['scores'],'class_order':list(export['classes']),
        'python_leaf_ids':python['leaves'],'python_scores':python['scores'],
        'p4_prediction':export['classes'][rf['prediction']],'python_prediction':python['class'],
        'capture_time_prediction':result['capture_time_prediction'],
        'reference_capture_prediction':result['capture_time_prediction'],
        'prediction_changed_with_native_timing':result['prediction_changed_with_native_timing'],
        'parity':{'feature':result['feature_mismatches']==0,'leaf':result['leaf_mismatches']==0,
                  'score':result['score_mismatches']==0,'prediction':result['class_mismatches']==0},
        'native_times_us':[p['feature_report']['observed_us'] for p in packets],
        'native_iats_us':result['timing']['native_iats_us'],
        'capture_iats_us':result['timing']['original_iats_us'],
        'clock_quality':result['clock_quality'],'decision_counters':result.get('decision_counters'),
        'packet_reports':packets,'source_frame_numbers':[p['original_frame'] for p in bundle['packets']],
        'native_clock':True,'controlled_capture_time':False,'accuracy_scored':False,'performance_measured':False,
        'score_meaning':'Six fixed-point accumulated RF class scores; argmax, not probability confidence or accuracy'}


class ReplayObserver:
    def __init__(self,writer,bundle,exports,mac_tag,resource_factory=None):
        if len(mac_tag)!=12:raise ValueError('MAC pair tag must be exactly twelve bytes')
        self.writer,self.bundle,self.exports,self.mac_tag=writer,bundle,exports,mac_tag
        self.queue=queue.Queue(maxsize=32);self.results={};self.model=None
        self.stop_event=threading.Event();self.cancelled=threading.Event();self.errors=[];self.thread=None
        self.packet_events=[]
        self.lock=threading.Lock();self.observed={'B':{'input':0,'output':0},'C':{'input':0,'output':0}}
        self.sample_lock=threading.Lock();self.monitoring={};self.resource_reports={};self.resource_handles={}
        self.resource_factory=resources.RawMeasurementResources if resource_factory is None else resource_factory
        self.runtime=None;self.owned_processes={};self.boundaries={};self.previous_resources={};self.last_resource_ns={}
        self.traffic_masks={};self.monitoring_errors=[]

    def configure_runtime(self,switch,programs,directory):
        self.runtime={'switch':str(Path(switch).resolve()),'programs':programs,'directory':Path(directory).resolve()}

    def set_phase(self,model,phase):
        with self.lock:
            if model not in self.monitoring:return
            if self.cancelled.is_set() and phase!='stopping':return
            self.monitoring[model]['phase']=phase
            self.boundaries.setdefault(model,[]).append({'raw_ns':resources.raw_clock_ns(),'phase':phase})

    def phase_at(self,model,raw_ns):
        with self.lock:bounds=list(self.boundaries.get(model,[]))
        return next((b['phase'] for b in reversed(bounds) if b['raw_ns']<=raw_ns),'setup')

    def monitoring_error(self,model,error):
        message=f'RF-{model}: {type(error).__name__}: {error}'
        with self.lock:
            self.monitoring_errors.append(message)
            if model in self.monitoring:self.monitoring[model]['monitoring_errors'].append(message)

    def publish_monitoring(self):
        """Read cached sampler snapshots off the packet path; serialized boundary/periodic updates."""
        with self.sample_lock:
            with self.lock:handles=list(self.resource_handles.items())
            for model,handle in handles:
                updates=[]
                for role,monitor in handle.monitors.items():
                    with monitor._lock:cached=deepcopy(monitor._samples);errors=list(monitor._errors)
                    identity_valid=len({sample['start_time_ticks'] for sample in cached})<=1
                    for sample in cached:
                        identity=(model,role)
                        if sample['raw_ns']<=self.last_resource_ns.get(identity,-1):continue
                        prior=self.previous_resources.get(identity);phase=self.phase_at(model,sample['raw_ns'])
                        prior_phase=self.phase_at(model,prior['raw_ns']) if prior else None
                        point=resource_point(prior,sample,monitor.clock_ticks_per_second,phase,prior_phase,not errors and identity_valid)
                        self.previous_resources[identity]=sample;self.last_resource_ns[identity]=sample['raw_ns']
                        with self.lock:self.monitoring[model]['resources'][role]=point
                        updates.append({'raw_ns':sample['raw_ns'],'phase':phase,'resources':{role:point}})
                with self.lock:
                    self.monitoring[model]['resource_samples'].extend(sorted(updates,key=lambda x:x['raw_ns']))
                    self.monitoring[model]['resource_samples']=self.monitoring[model]['resource_samples'][-60:]
            with self.lock:payload=deepcopy(self.monitoring)
            self.writer.emit('pcap_monitoring_observed',phase='stopping' if self.cancelled.is_set() else 'replaying',
                             pcap_monitoring=payload)

    def safe_publish_monitoring(self,model):
        try:self.publish_monitoring()
        except (OSError,ValueError,RuntimeError) as exc:self.monitoring_error(model,exc)

    def monitoring_snapshot(self):
        with self.lock:return deepcopy(self.monitoring)

    def start_resources(self,model):
        self.set_phase(model,'replay')
        if self.runtime is None:return  # Pure adapter tests do not launch a switch.
        try:
            process=self.owned_processes.get(model)
            if process is None or process.poll() is not None:raise RuntimeError('Owned BMv2 child is not running')
            handle=self.resource_factory(process.pid)
            with self.lock:self.resource_handles[model]=handle
            for monitor in handle.monitors.values():monitor.interval_seconds=1.0
            handle.start();self.publish_monitoring()
        except (OSError,ValueError,RuntimeError) as exc:self.monitoring_error(model,exc)

    def stop_resources(self,model):
        handle=self.resource_handles.get(model)
        if handle is None:return
        try:
            handle.stop();report=handle.report()
            report['inherited_window_meaning']=report.get('window_meaning');report['window_meaning']=RESOURCE_WINDOW
            report['independently_qualified']=False
            for role in ('bmv2','runner'):
                row=report.get(role,{})
                row['inherited_window_definition']=row.get('window_definition');row['window_definition']=RESOURCE_WINDOW
                for sample in row.get('samples',[]):sample['demo_phase']=self.phase_at(model,sample['raw_ns'])
                for issue in row.get('errors',[]):self.monitoring_error(model,RuntimeError(f'{role} sampler: {issue}'))
            self.resource_reports[model]=report;self.publish_monitoring()
            with self.lock:
                for role in ('bmv2','runner'):
                    row=report.get(role,{})
                    if role in self.monitoring[model]['resources']:
                        latest=self.monitoring[model]['resources'][role]
                        latest.update(valid=row.get('valid') is True,
                            window_cpu_percent_one_core=row.get('cpu',{}).get('percent_one_core'),
                            replay_window_start_raw_ns=row.get('raw_window_start_ns'),
                            replay_window_end_raw_ns=row.get('raw_window_end_ns'))
        except (OSError,ValueError,RuntimeError) as exc:self.monitoring_error(model,exc)

    def record_match(self,model,role,index):
        """Constant-size counters only; decoder/JSON/resource work stays off capture path."""
        with self.lock:
            mask=1<<index
            self.traffic_masks[model][role]|=mask
            self.observed[model][role]=self.traffic_masks[model][role].bit_count()
            input_mask,output_mask=self.traffic_masks[model]['input'],self.traffic_masks[model]['output']
            self.monitoring[model]['traffic']={'input_observed':input_mask.bit_count(),
                'output_observed':output_mask.bit_count(),'pending_output':(input_mask & ~output_mask).bit_count()}
            complete=input_mask==255 and output_mask==255 and self.monitoring[model]['phase']=='replay'
        if complete:self.set_phase(model,'drain')

    def monitoring_evidence(self):
        with self.lock:rows=deepcopy(self.monitoring);bounds=deepcopy(self.boundaries)
        reports=deepcopy(self.resource_reports)
        for model,handle in self.resource_handles.items():
            if model in reports:continue
            reports[model]={'valid':False,'partial':True,'window_meaning':RESOURCE_WINDOW}
            for role,monitor in handle.monitors.items():
                with monitor._lock:
                    reports[model][role]={'valid':False,'samples':deepcopy(monitor._samples),'errors':deepcopy(monitor._errors)}
        return {'schema_version':'pcap-demo-monitoring-v1','pcap_monitoring':rows,
            'resource_reports':reports,'phase_boundaries':bounds,
            'monitoring_errors':list(self.monitoring_errors),'window_definition':RESOURCE_WINDOW,
            'periodic_interval_seconds':1.0,'qualified_performance':False,'capture_socket_drops_available':False}

    def start(self):
        self.thread=threading.Thread(target=self._work,name='pcap-demo-observer',daemon=True);self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(3)
        if self.thread and self.thread.is_alive():raise RuntimeError('PCAP observer did not stop')

    def cancel(self):
        self.cancelled.set()
        if self.model:self.set_phase(self.model,'stopping')

    def begin_model(self,model,trial=None):
        self.model=model
        with self.lock:
            self.monitoring[model]={'model':model,'phase':'setup','expected_packets':8,
                'window_label':RESOURCE_WINDOW,'traffic':{'input_observed':0,'output_observed':0,'pending_output':0},
                'completed_accounting':None,'resources':{},'resource_samples':[], 'monitoring_errors':[]}
            self.traffic_masks[model]={'input':0,'output':0}
            self.boundaries[model]=[{'raw_ns':resources.raw_clock_ns(),'phase':'setup'}]
        self.results[model]={'feature_set':model,'status':'collecting','capture':self.bundle['capture']['filename'],
            'capture_hint':self.bundle['record']['label'],'record_id':self.bundle['record']['record_id'],
            'eligible_packets_observed':0,'native_clock':True,'controlled_capture_time':False,
            'source_frame_numbers':[p['original_frame'] for p in self.bundle['packets']],
            'label_basis':'capture_activity_hint; not independently verified per-flow ground truth'}
        self.writer.emit('pcap_model_started',phase='replaying',model=model,trial=trial or 'BC'.index(model)+1,
                         classification_results=deepcopy(self.results),pcap_monitoring=self.monitoring_snapshot())

    def complete_model(self,model,result):
        # Native run_model already verified these counter values. Retain them
        # before optional queue/presentation finalization can fail.
        counters=result.get('decision_counters')
        with self.lock:
            accounting=self.monitoring[model].get('completed_accounting')
            if accounting is not None and isinstance(counters,list) and len(counters)==6:
                accounting.update(decisions=sum(row['packets'] for row in counters),counters_verified=True,
                                  classification_trigger_counters=deepcopy(counters))
        end=time.monotonic()+3
        while self.queue.unfinished_tasks:
            if not self.thread.is_alive() or time.monotonic()>end:raise RuntimeError('PCAP observation queue did not drain')
            time.sleep(.01)
        self.results[model]=normalized_result(model,self.bundle,self.exports[model],result)
        self.set_phase(model,'completed');self.safe_publish_monitoring(model)
        self.writer.emit('pcap_classification_verified',phase='accounting',model=model,
                         classification_results=deepcopy(self.results),pcap_monitoring=self.monitoring_snapshot())

    def _work(self):
        next_publication=time.monotonic()+1.0
        while not self.stop_event.is_set() or not self.queue.empty():
            if time.monotonic()>=next_publication:
                try:self.publish_monitoring()
                except (OSError,ValueError,RuntimeError) as exc:self.monitoring_error(self.model or '?',exc)
                next_publication=time.monotonic()+1.0
            try:item=self.queue.get(timeout=.1)
            except queue.Empty:continue
            try:
                model,role,index,frame,monotonic_ns,wall_ns=item
                self.packet_events.append({'model':model,'role':role,'packet_position':index+1,'frame_hex':frame.hex(),
                                           'capture_monotonic_ns':monotonic_ns,'capture_wall_ns':wall_ns})
                if role=='output':
                    feature=native.helpers.decode_report(frame);rf=integration.decode_rf(frame,85)
                    row=self.results[model]
                    row.update(eligible_packets_observed=feature['count'],status='classified_unverified' if rf['valid'] else 'collecting',
                               latest_feature_report=feature,latest_source_frame=self.bundle['packets'][index]['original_frame'])
                    if rf['valid']:
                        row.update(packet_eight_triggered=True,features_C=feature_values(feature),
                                   features_used={k:feature_values(feature)[k] for k in self.exports[model]['feature_order']},
                                   leaf_ids=rf['leaves'],scores=rf['scores'],class_order=self.exports[model]['classes'],
                                   p4_prediction=self.exports[model]['classes'][rf['prediction']],parity=None)
                    self.writer.emit('pcap_packet_observed',phase='replaying',model=model,packet_position=index+1,
                        classification_results=deepcopy(self.results),
                        pcap_monitoring=self.monitoring_snapshot(),
                        packet_progress={m:{'model':m,'input_observed':counts['input'],
                            'output_observed':counts['output'],'expected_packets':8,
                            'eligible_packets':self.results.get(m,{}).get('eligible_packets_observed',0)}
                            for m,counts in self.observed.items() if m in self.results})
            except Exception as exc:
                self.errors.append(f'{type(exc).__name__}: {exc}')
                self.writer.emit('producer_error',phase='replaying',error=self.errors[-1])
            finally:self.queue.task_done()

    @contextmanager
    def scoped(self):
        observer=self;transport=native.transport
        original_matcher,original_replay,original_due=transport.CaptureMatcher,transport.replay_frames,transport.due_index
        original_subprocess=native.subprocess
        class OwnedSubprocess:
            def __getattr__(self,name):return getattr(original_subprocess,name)
            def Popen(self,argv,*args,**kwargs):
                if observer.cancelled.is_set():raise KeyboardInterrupt('Cancelled before owned switch startup')
                context=observer.runtime;model=observer.model
                if context is None:raise RuntimeError('Owned subprocess context is not configured')
                expected=Path(context['programs'][model]['path']).resolve()
                expected_cwd=context['directory']/f'RF_{model}'
                if (str(Path(argv[0]).resolve())!=context['switch'] or Path(argv[-1]).resolve()!=expected
                        or Path(kwargs.get('cwd','')).resolve()!=expected_cwd):
                    raise RuntimeError('Refusing subprocess outside the owned PCAP model command/directory')
                process=original_subprocess.Popen(argv,*args,**kwargs)
                observer.owned_processes[model]=process
                return process
        class ObservedMatcher(original_matcher):
            def observe(self,role,frame,*args):
                if observer.cancelled.is_set():raise KeyboardInterrupt('PCAP demo cancellation requested')
                observations=self.input_observations if role=='input' else self.output_observations
                before=len(observations);super().observe(role,frame,*args)
                if len(observations)>before:
                    observer.record_match(observer.model,role,observations[-1]['packet_index'])
                    try:observer.queue.put_nowait((observer.model,role,observations[-1]['packet_index'],frame,args[-2],args[-1]))
                    except queue.Full:observer.errors.append('Bounded PCAP observation queue overflow')
        def replay_frames(frames,*args,**kwargs):
            if observer.cancelled.is_set():raise KeyboardInterrupt('Interrupted before replay; no packets launched')
            # Exact same wrapping/IPv4 bytes across B and C, not random model tags.
            frames=[observer.mac_tag+frame[12:] for frame in frames]
            observer.writer.emit('pcap_replay_started',phase='replaying',model=observer.model,
                planned_offsets_us=list(args[0]) if args else list(kwargs.get('relative_us',[])))
            model=observer.model;observer.start_resources(model)
            try:
                report=original_replay(frames,*args,**kwargs)
                with observer.lock:observer.monitoring[model]['completed_accounting']=transport_accounting(report)
                return report
            finally:
                # Stop while the exact owned PID is still alive, before native
                # parity/counter reads and native.run_model's child cleanup.
                observer.stop_resources(model);observer.set_phase(model,'verification');observer.safe_publish_monitoring(model)
        def due_index(*args,**kwargs):
            if observer.cancelled.is_set():raise KeyboardInterrupt('PCAP cancellation latched before next packet send')
            return original_due(*args,**kwargs)
        transport.CaptureMatcher,transport.replay_frames,transport.due_index=ObservedMatcher,replay_frames,due_index
        if observer.runtime is not None:native.subprocess=OwnedSubprocess()
        try:yield
        finally:
            transport.CaptureMatcher,transport.replay_frames,transport.due_index=original_matcher,original_replay,original_due
            native.subprocess=original_subprocess
