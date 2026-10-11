"""Optional, demo-only observation of unchanged RAW transport.

Scoped class injection is restricted to one dedicated worker process/trial.
No C sender ABI or frozen source is edited. Packet handlers update scalars;
one separate observer copies compact snapshots and queues telemetry ~1 Hz.
"""
from contextlib import contextmanager
import threading
import time
import struct

import raw_benchmark_transport as transport
import raw_performance_resources as resources


def cpu_observation(previous, current, ticks):
    if not previous or not current or ticks<=0:
        return None
    duration=(current['raw_ns']-previous['raw_ns'])/1e9
    delta=sum(current[k]-previous[k] for k in ('utime_ticks','stime_ticks'))
    if duration<=0 or delta<0 or current['start_time_ticks']!=previous['start_time_ticks']:
        return None
    return 100*delta/ticks/duration


class DemoObserver:
    def __init__(self,writer,qualifier=None,interval=1.0):
        if interval<.5:
            raise ValueError('Demo telemetry interval must be at least 0.5 seconds')
        self.writer,self.qualifier,self.interval=writer,qualifier,interval
        self.lock=threading.Lock();self.stop_event=threading.Event()
        self.sample_lock=threading.Lock()
        self.cancel_requested=threading.Event()
        self.ledger=self.audit=self.resource=None;self.phase='preparing'
        self.phase_start=None;self.previous_traffic=None;self.previous_resources={}
        self.latest_resource_values={};self.errors=[]
        self.thread=None;self.active_plan=None

    def emit(self,event,**fields):
        return self.writer.emit(event,trial=1,total_trials=1,**fields)

    def start(self):
        self.thread=threading.Thread(target=self._loop,name='demo-telemetry-observer',daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(2)
        if self.thread and self.thread.is_alive():
            raise RuntimeError('Demo telemetry observer did not stop')

    def cancel(self):
        self.cancel_requested.set()
        with self.lock:
            self.phase='stopping'
            plan=self.active_plan
        if plan is not None:plan.cancel()

    def _loop(self):
        while not self.stop_event.wait(self.interval):
            try:self.sample()
            except Exception as exc:
                self.errors.append(f'{type(exc).__name__}: {exc}')
                self.emit('producer_error',phase=self.phase,error=f'{type(exc).__name__}: {exc}',measurement_changed=False)

    def sample(self):
        with self.sample_lock:return self._sample()

    def _sample(self):
        now=transport.raw_now_ns()
        with self.lock:
            ledger,audit,resource,phase,start=self.ledger,self.audit,self.resource,self.phase,self.phase_start
        sample={'traffic':{},'resources':{},'clock':{},'provisional':True,'raw_ns':now,'phase':phase,
                'phase_elapsed_seconds':(now-start)/1e9 if start else None}
        if ledger is not None:
            with ledger.snapshot_lock:
                traffic=dict(ledger.live_counts)
                traffic['input_duplicates']=ledger.counters['input']['duplicates']
                traffic['output_duplicates']=ledger.counters['output']['duplicates']
                traffic['input_reordered']=ledger.counters['input']['sequence_regressions']
                traffic['output_reordered']=ledger.counters['output']['sequence_regressions']
                traffic['corrupted_frames']=sum(ledger.counters[k]['corrupted_frames'] for k in ('input','output'))
            previous=self.previous_traffic
            dt=(now-previous['raw_ns'])/1e9 if previous else None
            traffic.update(input_observed_pps=(traffic['input_unique']-previous['input_unique'])/dt if dt and dt>0 else None,
                           output_observed_pps=(traffic['output_unique']-previous['output_unique'])/dt if dt and dt>0 else None,
                           exact_sender_count=None,capture_socket_drops=None,
                           interpretation='Userspace exact-frame capture observations; pending is not loss; exact sender and socket accounting finalize after phase')
            self.previous_traffic=dict(traffic,raw_ns=now)
            sample['traffic']=traffic
        if resource is not None and phase in ('measurement','draining'):
            for name,monitor in resource.monitors.items():
                with monitor._lock:
                    current=dict(monitor._samples[-1]) if monitor._samples else None
                if current:
                    previous=self.previous_resources.get(name)
                    if previous and previous['raw_ns']==current['raw_ns']:
                        sample['resources'][name]=dict(self.latest_resource_values.get(name,{}))
                        continue
                    sample['resources'][name]={'cpu_percent_one_core':cpu_observation(previous,current,monitor.clock_ticks_per_second),
                        'rss_mib':current['rss_kib']/1024,'vmhwm_lifetime_mib':current['vmhwm_kib']/1024,
                        'cpu_user_ticks':current['utime_ticks'],'cpu_system_ticks':current['stime_ticks'],
                        'sample_raw_ns':current['raw_ns'],'provisional':True,'qualified':False,
                        'interpretation':'OS-accounted interval CPU / RAW; one-core convention; demo-only, unqualified'}
                    self.previous_resources[name]=current
                    self.latest_resource_values[name]=dict(sample['resources'][name])
        if audit is not None:
            with audit.snapshot_lock:sample['clock']=dict(audit.live_health)
            sample['clock'].update(status='OBSERVING',final_verdict=False,independent_qualification='PENDING',
                                   maximum_allowed_gap_ms=25,maximum_allowed_bracket_us=100)
        if self.qualifier is not None:
            with self.qualifier._lock:
                records=list(self.qualifier.records)
            sample['reference_queries']={'attempted':len(records),'valid':sum(bool(r.get('valid')) for r in records),
                                         'failed':sum(not bool(r.get('valid')) for r in records),'final_verdict':False}
        with self.lock:
            sample['phase']=self.phase
            self.emit('sample',phase=self.phase,sample=sample)

    @contextmanager
    def scoped(self,calibration):
        observer=self
        original_phase=transport.run_phase
        original_ledger=transport.CaptureLedger
        original_audit=transport.RawClockAudit
        original_resource=calibration.RawMeasurementResources
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError('Demo observer scope requires dedicated main worker thread')

        class ObservedLedger(original_ledger):
            def __init__(self,*args,**kwargs):
                super().__init__(*args,**kwargs)
                self.snapshot_lock=threading.Lock()
                self.live_counts={'input_unique':0,'output_unique':0,'matched':0,'pending':0}
                self.live_seen={role:bytearray(len(self.frames)) for role in ('input','output')}
                with observer.lock:observer.ledger=self

            def observe(self,role,frame,*args,**kwargs):
                try:seq=self.sequence_from_frame(frame)
                except (ValueError,TypeError,KeyError,IndexError,struct.error):seq=None
                valid=type(seq)is int and 0<=seq<len(self.frames)
                super().observe(role,frame,*args,**kwargs)
                if valid and self.counts[role][seq]>0:
                    other='output' if role=='input' else 'input'
                    with self.snapshot_lock:
                        if self.live_seen[role][seq]:return
                        self.live_seen[role][seq]=1
                        self.live_counts[role+'_unique']+=1
                        if self.live_seen[other][seq]:
                            self.live_counts['matched']+=1
                            if role=='output':self.live_counts['pending']-=1
                        elif role=='input':self.live_counts['pending']+=1

        class ObservedAudit(original_audit):
            def __init__(self,*args,**kwargs):
                super().__init__(*args,**kwargs);self.snapshot_lock=threading.Lock();self.previous=None
                self.live_health={'samples':0,'maximum_sample_gap_ms':0,'maximum_read_bracket_us':0,'raw_regressions':0}
                with observer.lock:observer.audit=self

            def observe(self,*row):
                super().observe(*row)
                with self.snapshot_lock:
                    self.live_health['samples']+=1
                    self.live_health['maximum_read_bracket_us']=max(self.live_health['maximum_read_bracket_us'],(row[4]-row[0])/1000)
                    if self.previous:
                        self.live_health['maximum_sample_gap_ms']=max(self.live_health['maximum_sample_gap_ms'],(row[4]-self.previous[4])/1e6)
                        self.live_health['raw_regressions']+=int(row[0]<self.previous[4])
                    self.previous=row

        class ObservedResources(original_resource):
            def __init__(self,*args,**kwargs):
                super().__init__(*args,**kwargs)
                with observer.lock:observer.resource=self

            def stop(self):
                if self.stopped or not self.started:return
                super().stop()
                with observer.lock:
                    if not observer.cancel_requested.is_set():observer.phase='draining'
                observer.emit('drain_started',phase=observer.phase)

        def observed_phase(*args,**kwargs):
            if observer.cancel_requested.is_set():
                raise KeyboardInterrupt('Cancellation latched; no subsequent phase traffic launched')
            measured=kwargs.get('on_window_start') is not None
            phase='measurement' if measured else 'warmup'
            with observer.sample_lock:
                with observer.lock:
                    observer.phase=phase;observer.phase_start=transport.raw_now_ns()
                    observer.ledger=observer.audit=None;observer.previous_traffic=None;observer.previous_resources={};observer.latest_resource_values={}
            observer.emit('measurement_started' if measured else 'warmup_started',phase=phase,
                          phase_started_raw_ns=observer.phase_start)
            result=original_phase(*args,**kwargs)
            observer.sample()
            observer.emit('phase_completed',phase='stopping' if observer.cancel_requested.is_set() else phase,finished_phase=phase,phase_result={
                'sent_packets':result['sent_packets'],'input_unique':result['captured_input_unique'],
                'output_unique':result['captured_output_unique'],'measurement_integrity':result['measurement_integrity'],
                'pacing':result['raw_pacing_conformance_status'],'raw_clock_audit':{k:v for k,v in result['raw_clock_audit'].items() if k!='samples'},
                'capture_statistics':result['capture_statistics'],'metric_validity':result['metric_validity']})
            if not measured:observer.emit('warmup_completed',phase='stopping' if observer.cancel_requested.is_set() else 'preparing')
            return result

        transport.CaptureLedger,transport.RawClockAudit=ObservedLedger,ObservedAudit
        transport.run_phase=observed_phase
        calibration.RawMeasurementResources=ObservedResources
        try:yield
        finally:
            transport.run_phase=original_phase;transport.CaptureLedger=original_ledger
            transport.RawClockAudit=original_audit;calibration.RawMeasurementResources=original_resource


class ObservedSender:
    """Cancellation access only; immutable native sender semantics retained."""
    def __init__(self,sender,observer):self.sender,self.observer=sender,observer
    @property
    def provenance(self):return self.sender.provenance
    def prepare(self,*args,**kwargs):
        plan=self.sender.prepare(*args,**kwargs)
        plan=ObservedPlan(plan,self.observer)
        with self.observer.lock:self.observer.active_plan=plan
        if self.observer.cancel_requested.is_set():plan.cancel()
        return plan


class ObservedPlan:
    """Publish compact exact native results after C returns, before drain.

    No sender-array decoding, new packet callbacks or altered native deadlines.
    """
    def __init__(self,plan,observer):
        self.plan,self.observer=plan,observer
        self.phase=observer.phase
    def run_raw(self,fd):
        result=self.plan.run_raw(fd)
        duration=(result.send_window_end_ns-result.scheduled_start_ns)/1e9
        stats={'sent_packets':int(result.sent_count),'attempted_packets':int(result.attempted_count),
               'raw_sender_window_seconds':duration,'offered_pps':result.sent_count/duration if duration>0 else None,
               'qualified':False,'clock_domain':'CLOCK_MONOTONIC_RAW','source':'Completed native sender result; no historical certificate inherited'}
        if self.phase=='measurement':
            with self.observer.lock:
                if not self.observer.cancel_requested.is_set():self.observer.phase='draining'
            self.observer.emit('measurement_completed',phase=self.observer.phase,sender_statistics=stats)
        else:self.observer.emit('warmup_sender_completed',phase=self.observer.phase,sender_statistics=stats)
        return result
    def report(self,result):return self.plan.report(result)
    def cancel(self):return self.plan.cancel()
    def close(self):
        self.plan.close()
        with self.observer.lock:
            if self.observer.active_plan is self:self.observer.active_plan=None
