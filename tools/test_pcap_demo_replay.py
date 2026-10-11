import struct
import os
import threading
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import pcap_demo_replay as demo

TAG=bytes.fromhex('020000000002020000000001')


class Writer:
    def __init__(self):self.events=[]
    def emit(self,event,**fields):self.events.append((event,fields));return True


def report_frame(position,raw,model='C'):
    fields={name:0 for name,_ in demo.native.helpers.FIELDS}
    fields.update(magic=0x45544352,version=1,status=2 if position==8 else 1,count=position,
                  observed_us=1000+position*100,effective_us=1000+position*100,
                  size_min=20,size_max=20,size_sum=20*position,iat_min=100,iat_max=100,iat_sum=100*(position-1),
                  reverse_count=position//2,direction_changes=position-1)
    feature=b''.join(fields[name].to_bytes(length,'big') for name,length in demo.native.helpers.FIELDS)
    rf=struct.pack('!IBBBB10H6I',demo.integration.RF_MAGIC,1,int(position==8),'BC'.index(model),5 if position==8 else 255,
                   *([1]*10 if position==8 else [0]*10),*([0,0,0,0,0,100] if position==8 else [0]*6))
    return TAG+b'\x88\xb6'+feature+rf+raw


def bundle_fixture():
    return {'capture':{'filename':'actual_capture.pcap'},'record':{'record_id':'frozen_record','label':'VOIP'},
            'packets':[{'original_frame':i+1} for i in range(8)]}


class PcapReplayTests(unittest.TestCase):
    def test_actual_report_features_direction_names(self):
        raw=b'\x45'+b'\x00'*19;frame=report_frame(8,raw)
        report=demo.native.helpers.decode_report(frame)
        features=demo.feature_values(report)
        self.assertEqual(features['reverse_packet_count'],4)
        self.assertEqual(features['direction_change_count'],7)
        self.assertEqual(features['size_sum'],160)
        self.assertEqual(len(features),8)

    def test_native_prediction_parity_not_capture_accuracy(self):
        raw=b'\x45'+b'\x00'*19
        checks=[{'feature_report':demo.native.helpers.decode_report(report_frame(i+1,raw)),
                 'rf_report':demo.integration.decode_rf(report_frame(i+1,raw),85)} for i in range(8)]
        result={'packet_checks':checks,'decision':{'expected_rf':{'class':'VOIP','leaves':[1]*10,'scores':[0,0,0,0,0,100]}},'passed':True,
                'feature_mismatches':0,'leaf_mismatches':0,'score_mismatches':0,'class_mismatches':0,
                'capture_time_prediction':'CHAT','prediction_changed_with_native_timing':True,
                'timing':{'native_iats_us':[100]*7,'original_iats_us':[90]*7},'clock_quality':{'clean':True}}
        export={'classes':demo.CLASSES,'feature_order':demo.FEATURE_NAMES}
        normalized=demo.normalized_result('C',bundle_fixture(),export,result)
        self.assertEqual(normalized['p4_prediction'],'VOIP');self.assertEqual(normalized['python_prediction'],'VOIP')
        self.assertTrue(all(normalized['parity'].values()));self.assertFalse(normalized['accuracy_scored'])
        self.assertTrue(normalized['prediction_changed_with_native_timing'])
        self.assertEqual(len(normalized['leaf_ids']),10);self.assertEqual(len(normalized['scores']),6)

    def test_only_actual_matched_output_updates_packet_progress(self):
        bundle=bundle_fixture();exports={m:{'classes':demo.CLASSES,'feature_order':demo.FEATURE_NAMES} for m in 'BC'}
        writer=Writer();observer=demo.ReplayObserver(writer,bundle,exports,TAG);observer.start();observer.begin_model('C')
        raw=[b'\x45'+bytes([i])+b'\x00'*18 for i in range(8)]
        frames=[TAG+b'\x08\x00'+p for p in raw]
        try:
            with observer.scoped():
                matcher=demo.native.transport.CaptureMatcher(frames,demo.native.output_key)
                # Unrelated output cannot fabricate a packet-progress event.
                matcher.observe('output',b'x'*200,0,1,1)
                for i in range(8):
                    matcher.observe('input',frames[i],demo.native.transport.PACKET_OUTGOING,100+i,200+i)
                    matcher.observe('output',report_frame(i+1,raw[i]),0,300+i,400+i)
            observer.stop()
            events=[p for e,p in writer.events if e=='pcap_packet_observed']
            self.assertEqual(len(events),8);self.assertEqual([p['packet_position'] for p in events],list(range(1,9)))
            last=events[-1]['classification_results']['C']
            self.assertEqual(last['eligible_packets_observed'],8);self.assertEqual(last['p4_prediction'],'VOIP')
            self.assertIsNone(last['parity']);self.assertEqual(last['status'],'classified_unverified')
            self.assertEqual(len(observer.packet_events),16)
        finally:observer.stop()

    def test_original_transport_restored_on_exception(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG)
        transport=demo.native.transport;original=(transport.CaptureMatcher,transport.replay_frames)
        with self.assertRaises(ValueError):
            with observer.scoped():raise ValueError('fixture')
        self.assertEqual((transport.CaptureMatcher,transport.replay_frames),original)

    def test_shared_exact_wrapping_does_not_change_ip_or_schedule(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG)
        observer.begin_model('B');frames=[b'\x02'*12+b'\x08\x00'+b'\x45'+b'\x00'*19]
        schedule=[0]
        with patch.object(demo.native.transport,'replay_frames',return_value={}) as original:
            with observer.scoped():demo.native.transport.replay_frames(frames,schedule,'in','out',5,key_from_output=lambda _:None)
        args=original.call_args.args
        self.assertEqual(args[0][0][:12],TAG);self.assertEqual(args[0][0][14:],frames[0][14:])
        self.assertIs(args[1],schedule)

    def test_cancellation_prevents_replay_before_socket_access(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG);observer.cancel()
        with patch.object(demo.native.transport,'replay_frames') as original:
            with observer.scoped():
                with self.assertRaises(KeyboardInterrupt):demo.native.transport.replay_frames([],[],'in','out',5,key_from_output=lambda _:None)
            original.assert_not_called()

    def test_cancel_latch_is_checked_before_next_packet_send(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG)
        with patch.object(demo.native.transport,'due_index') as original:
            with observer.scoped():
                observer.cancel()
                with self.assertRaises(KeyboardInterrupt):demo.native.transport.due_index(0,[0],1,2)
            original.assert_not_called()

    def test_missing_packet_eight_has_no_fabricated_prediction_or_parity(self):
        bundle=bundle_fixture();exports={m:{'classes':demo.CLASSES,'feature_order':demo.FEATURE_NAMES} for m in 'BC'}
        writer=Writer();observer=demo.ReplayObserver(writer,bundle,exports,TAG);observer.start();observer.begin_model('C',trial=1)
        raw=[b'\x45'+bytes([i])+b'\x00'*18 for i in range(8)]
        frames=[TAG+b'\x08\x00'+p for p in raw]
        try:
            with observer.scoped():
                matcher=demo.native.transport.CaptureMatcher(frames,demo.native.output_key)
                for i in range(7):matcher.observe('output',report_frame(i+1,raw[i]),0,300+i,400+i)
            observer.stop();row=observer.results['C']
            self.assertEqual(row['eligible_packets_observed'],7)
            self.assertEqual(row['status'],'collecting')
            self.assertNotIn('p4_prediction',row);self.assertNotIn('parity',row)
            self.assertEqual(writer.events[0][1]['trial'],1)
        finally:observer.stop()

    def test_actual_resource_point_cpu_delta_and_cross_phase_label(self):
        previous={'raw_ns':1_000_000_000,'utime_ticks':2,'stime_ticks':1,'start_time_ticks':9}
        current=dict(previous,raw_ns=2_000_000_000,utime_ticks=3,stime_ticks=2,rss_kib=2048,vmhwm_kib=3072)
        point=demo.resource_point(previous,current,100,'drain','replay')
        self.assertEqual(point['cpu_percent_one_core'],2.0)
        self.assertEqual(point['rss_mib'],2.0);self.assertEqual(point['sample_raw_ns'],current['raw_ns'])
        self.assertEqual(point['cpu_interval_phase'],'mixed');self.assertEqual(point['cpu_window_label'],'replay → drain')
        self.assertFalse(point['qualified'])
        self.assertIsNone(demo.resource_point(None,current,100,'replay')['cpu_percent_one_core'])
        self.assertIsNone(demo.resource_point(previous,current,100,'drain','replay',False)['rss_mib'])

    def test_tagged_pending_counts_handle_output_before_input_without_negative(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG);observer.begin_model('B')
        observer.set_phase('B','replay');observer.record_match('B','output',0)
        self.assertEqual(observer.monitoring['B']['traffic']['pending_output'],0)
        observer.record_match('B','input',0);observer.record_match('B','input',0)
        self.assertEqual(observer.monitoring['B']['traffic'],{'input_observed':1,'output_observed':1,'pending_output':0})
        for i in range(1,8):observer.record_match('B','input',i);observer.record_match('B','output',i)
        self.assertEqual(observer.monitoring['B']['phase'],'drain')
        self.assertEqual(observer.monitoring['B']['traffic']['output_observed'],8)

    def test_transport_accounting_missing_indices_preserved_socket_drops_unavailable(self):
        report={'sent_logs':[{},{}],'input_observations':[{}],'output_observations':[],
                'missing_input_indices':[1],'missing_output_indices':[0,1],'transport_passed':False,'errors':['missed']}
        accounting=demo.transport_accounting(report)
        self.assertEqual(accounting['sent_packets'],2);self.assertEqual(accounting['missing_output_indices'],[0,1])
        self.assertFalse(accounting['transport_passed']);self.assertIsNone(accounting['capture_socket_drops'])
        self.assertIsNone(accounting['decisions']);self.assertIsNone(accounting['counters_verified'])
        missing=demo.transport_accounting({})
        self.assertIsNone(missing['sent_packets']);self.assertIsNone(missing['input_observed']);self.assertIsNone(missing['output_observed'])
        self.assertEqual(demo.transport_accounting({'sent_logs':[]})['sent_packets'],0)

    def test_resource_snapshots_are_deduplicated_not_retimestamped(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG);observer.begin_model('B')
        observer.set_phase('B','replay');now=demo.resources.raw_clock_ns()
        monitor=SimpleNamespace(_lock=threading.Lock(),_errors=[],clock_ticks_per_second=100,
            _samples=[{'raw_ns':now,'utime_ticks':1,'stime_ticks':1,'start_time_ticks':9,'rss_kib':1024,'vmhwm_kib':2048}])
        observer.resource_handles['B']=SimpleNamespace(monitors={'bmv2':monitor})
        observer.publish_monitoring();observer.publish_monitoring();observer.set_phase('B','verification');observer.publish_monitoring()
        row=observer.monitoring['B'];self.assertEqual(len(row['resource_samples']),1)
        self.assertEqual(row['resources']['bmv2']['sample_raw_ns'],now)
        self.assertEqual(row['resources']['bmv2']['phase'],'replay')
        self.assertIsNone(row['resources']['bmv2']['cpu_percent_one_core'])

    def test_scoped_owned_pid_resource_window_ends_before_native_verification(self):
        order=[];handles=[]
        class FakeResources:
            def __init__(self,pid):
                self.pid=pid;self.started=self.stopped=False;handles.append(self)
                self.monitors={role:SimpleNamespace(_lock=threading.Lock(),_samples=[],_errors=[],
                    interval_seconds=.1,clock_ticks_per_second=100) for role in ('bmv2','runner')}
            def sample(self,phase):
                for monitor in self.monitors.values():
                    monitor._samples.append({'phase':phase,'raw_ns':demo.resources.raw_clock_ns(),
                        'utime_ticks':1,'stime_ticks':1,'start_time_ticks':9,'rss_kib':1024,'vmhwm_kib':2048})
            def start(self):self.started=True;order.append('start');self.sample('start')
            def stop(self):self.stopped=True;order.append('stop');self.sample('end')
            def report(self):
                return {role:{'valid':True,'samples':list(monitor._samples),'errors':[],
                    'cpu':{'percent_one_core':0.0},'window_definition':'old benchmark scope'}
                    for role,monitor in self.monitors.items()}
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG,resource_factory=FakeResources)
        observer.configure_runtime('/owned/switch',{'B':{'path':'/owned/b.json'}},'/owned/run');observer.begin_model('B')
        process=SimpleNamespace(pid=4321,poll=lambda:None)
        original_subprocess=demo.native.subprocess
        report={'sent_logs':[{}]*8,'input_observations':[{}]*8,'output_observations':[{}]*8,
            'transport_passed':True,'errors':[],'missing_input_indices':[],'missing_output_indices':[]}
        def replay(*args,**kwargs):
            order.append('replay');self.assertTrue(handles[0].started);self.assertFalse(handles[0].stopped)
            observer.set_phase('B','drain');return report
        with patch.object(original_subprocess,'Popen',return_value=process) as popen,\
             patch.object(demo.native.transport,'replay_frames',side_effect=replay):
            with observer.scoped():
                owned=demo.native.subprocess.Popen(['/owned/switch','/owned/b.json'],cwd='/owned/run/RF_B')
                demo.native.transport.replay_frames([TAG+b'\x08\x00'+b'\x45'+b'\x00'*19],[0],'in','out',5,key_from_output=lambda _:None)
                order.append('verification');self.assertTrue(handles[0].stopped)
                self.assertIs(owned,process)
                with self.assertRaises(RuntimeError):demo.native.subprocess.Popen(['/unowned/switch','/owned/b.json'],cwd='/owned/run/RF_B')
            self.assertEqual(popen.call_count,1)
        self.assertIs(demo.native.subprocess,original_subprocess)
        self.assertEqual(order,['start','replay','stop','verification'])
        self.assertEqual(handles[0].pid,4321)
        self.assertTrue(all(m.interval_seconds==1.0 for m in handles[0].monitors.values()))
        self.assertEqual(observer.monitoring['B']['completed_accounting']['output_observed'],8)
        self.assertEqual(observer.monitoring['B']['phase'],'verification')
        self.assertEqual(observer.resource_reports['B']['window_meaning'],demo.RESOURCE_WINDOW)
        self.assertEqual(len(observer.monitoring['B']['resource_samples']),4)

    def test_monitoring_start_failure_does_not_change_original_transport_result(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG,
            resource_factory=lambda pid:(_ for _ in ()).throw(OSError('sampler unavailable')))
        observer.configure_runtime('/owned/switch',{'B':{'path':'/owned/b.json'}},'/owned/run');observer.begin_model('B')
        observer.owned_processes['B']=SimpleNamespace(pid=4321,poll=lambda:None)
        report={'transport_passed':True,'sent_logs':[{}]*8,'input_observations':[{}]*8,'output_observations':[{}]*8}
        with patch.object(demo.native.transport,'replay_frames',return_value=report):
            with observer.scoped():
                actual=demo.native.transport.replay_frames([TAG+b'\x08\x00'],[0],'in','out',5,key_from_output=lambda _:None)
        self.assertIs(actual,report);self.assertIn('sampler unavailable',observer.monitoring_errors[0])
        self.assertEqual(observer.monitoring['B']['resources'],{})

    def test_cancellation_persists_stopping_phase_and_no_resource_replay_start(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG);observer.begin_model('C');observer.cancel()
        observer.set_phase('C','verification')
        self.assertEqual(observer.monitoring['C']['phase'],'stopping')
        with patch.object(demo.native.transport,'replay_frames') as original:
            with observer.scoped():
                with self.assertRaises(KeyboardInterrupt):demo.native.transport.replay_frames([],[],'in','out',5,key_from_output=lambda _:None)
        original.assert_not_called();self.assertEqual(observer.resource_handles,{})

    def test_sampler_pid_reuse_does_not_produce_cpu_interval(self):
        previous={'raw_ns':1_000_000_000,'utime_ticks':1,'stime_ticks':1,'start_time_ticks':9}
        current=dict(previous,raw_ns=2_000_000_000,utime_ticks=2,start_time_ticks=10,rss_kib=1024)
        point=demo.resource_point(previous,current,100,'replay','replay')
        self.assertIsNone(point['cpu_percent_one_core']);self.assertIsNone(point['rss_mib']);self.assertFalse(point['valid'])

    def test_reused_real_resource_component_records_only_actual_start_end_points(self):
        # Both roles intentionally refer to this test process; this checks the
        # reused sampler API, not BMv2 performance or a live packet experiment.
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG)
        observer.configure_runtime('/owned/switch',{'B':{'path':'/owned/b.json'}},'/owned/run');observer.begin_model('B')
        observer.owned_processes['B']=SimpleNamespace(pid=os.getpid(),poll=lambda:None)
        try:
            observer.start_resources('B');observer.set_phase('B','drain');observer.stop_resources('B')
            report=observer.resource_reports['B']
            self.assertFalse(report['independently_qualified']);self.assertEqual(report['window_meaning'],demo.RESOURCE_WINDOW)
            for role in ('bmv2','runner'):
                self.assertTrue(report[role]['valid']);self.assertEqual(report[role]['sample_count'],2)
                self.assertEqual(report[role]['interval_seconds'],1.0)
                self.assertEqual([p['demo_phase'] for p in report[role]['samples']],['replay','drain'])
                self.assertTrue(report[role]['sampler_thread_stopped'])
                self.assertEqual(observer.monitoring['B']['resources'][role]['cpu_interval_phase'],'mixed')
            self.assertEqual(len(observer.monitoring['B']['resource_samples']),4)
        finally:
            observer.stop_resources('B')

    def test_authoritative_counters_survive_decoder_queue_failure(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG);observer.begin_model('B')
        observer.monitoring['B']['completed_accounting']=demo.transport_accounting({'transport_passed':True})
        observer.queue.put(('undecoded',));observer.thread=SimpleNamespace(is_alive=lambda:False)
        counters=[{'packets':int(i==5),'bytes':154 if i==5 else 0} for i in range(6)]
        with self.assertRaises(RuntimeError):observer.complete_model('B',{'decision_counters':counters})
        row=observer.monitoring['B']['completed_accounting']
        self.assertEqual(row['decisions'],1);self.assertTrue(row['counters_verified'])
        self.assertEqual(row['classification_trigger_counters'],counters)

    def test_monitor_report_failure_keeps_original_transport_exception(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG);observer.begin_model('B')
        observer.start_resources=lambda model:None
        handle=SimpleNamespace(monitors={},stop=unittest.mock.Mock(),report=unittest.mock.Mock(side_effect=RuntimeError('report failed')))
        observer.resource_handles['B']=handle
        with patch.object(demo.native.transport,'replay_frames',side_effect=ValueError('original transport failure')):
            with observer.scoped():
                with self.assertRaisesRegex(ValueError,'original transport failure'):
                    demo.native.transport.replay_frames([TAG+b'\x08\x00'],[0],'in','out',5,key_from_output=lambda _:None)
        handle.stop.assert_called_once()
        self.assertIn('report failed',observer.monitoring_errors[0])
        self.assertEqual(observer.monitoring['B']['phase'],'verification')
        self.assertTrue(observer.monitoring_evidence()['resource_reports']['B']['partial'])

    def test_concurrent_publications_preserve_one_actual_point(self):
        observer=demo.ReplayObserver(Writer(),bundle_fixture(),{},TAG);observer.begin_model('B');observer.set_phase('B','replay')
        monitor=SimpleNamespace(_lock=threading.Lock(),_errors=[],clock_ticks_per_second=100,
            _samples=[{'raw_ns':demo.resources.raw_clock_ns(),'utime_ticks':1,'stime_ticks':1,
                       'start_time_ticks':9,'rss_kib':1024,'vmhwm_kib':2048}])
        observer.resource_handles['B']=SimpleNamespace(monitors={'bmv2':monitor})
        threads=[threading.Thread(target=observer.publish_monitoring) for _ in range(4)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(1);self.assertFalse(thread.is_alive())
        self.assertEqual(len(observer.monitoring['B']['resource_samples']),1)


if __name__=='__main__':unittest.main()
