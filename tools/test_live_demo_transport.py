import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import live_demo_transport as live
import raw_benchmark_transport as transport


class Writer:
    def __init__(self):self.events=[]
    def emit(self,event,**fields):self.events.append((event,fields));return True


class TransportObserverTests(unittest.TestCase):
    def test_cpu_accounting_raw_delta_one_core(self):
        a=dict(raw_ns=1_000_000_000,utime_ticks=10,stime_ticks=5,start_time_ticks=1)
        b=dict(raw_ns=2_000_000_000,utime_ticks=30,stime_ticks=10,start_time_ticks=1)
        self.assertEqual(live.cpu_observation(a,b,100),25.0)
        self.assertIsNone(live.cpu_observation(None,b,100))
        self.assertIsNone(live.cpu_observation(a,dict(b,raw_ns=a['raw_ns']),100))
        self.assertIsNone(live.cpu_observation(a,dict(b,start_time_ticks=2),100))
        self.assertIsNone(live.cpu_observation(a,dict(b,utime_ticks=0),100))

    def test_scope_restores_original_classes_even_after_error(self):
        calibration=SimpleNamespace(RawMeasurementResources=object)
        phase,ledger,audit=transport.run_phase,transport.CaptureLedger,transport.RawClockAudit
        observer=live.DemoObserver(Writer())
        with self.assertRaises(ValueError):
            with observer.scoped(calibration):
                self.assertIsNot(transport.CaptureLedger,ledger)
                raise ValueError('controlled fixture')
        self.assertIs(transport.run_phase,phase);self.assertIs(transport.CaptureLedger,ledger)
        self.assertIs(transport.RawClockAudit,audit);self.assertIs(calibration.RawMeasurementResources,object)

    def test_constant_unique_pending_match_accounting(self):
        calibration=SimpleNamespace(RawMeasurementResources=object);writer=Writer();observer=live.DemoObserver(writer)
        base=transport.CaptureLedger
        def observe(ledger,role,frame,*args,**kwargs):
            ledger.counts[role][frame[-1]]+=1
            if ledger.counts[role][frame[-1]]>1:ledger.counters[role]['duplicates']+=1
        frames=[b'x'*59+bytes([i]) for i in range(2)]
        with patch.object(base,'observe',observe):
            with observer.scoped(calibration):
                ledger=transport.CaptureLedger(frames,lambda f:f[-1])
                ledger.observe('input',frames[0]);self.assertEqual(ledger.live_counts['pending'],1)
                ledger.observe('input',frames[0]);self.assertEqual(ledger.live_counts['input_unique'],1)
                ledger.observe('output',frames[0]);self.assertEqual(ledger.live_counts['pending'],0)
                ledger.observe('output',frames[1]);ledger.observe('input',frames[1])
                self.assertEqual(ledger.live_counts,{'input_unique':2,'output_unique':2,'matched':2,'pending':0})
                observer.sample()
                sample=writer.events[-1][1]['sample']
                self.assertEqual(sample['traffic']['input_duplicates'],1)
                self.assertIsNone(sample['traffic']['exact_sender_count'])
                self.assertIsNone(sample['traffic']['capture_socket_drops'])
                self.assertTrue(sample['provisional'])

    def test_simultaneous_input_output_never_double_matches(self):
        calibration=SimpleNamespace(RawMeasurementResources=object);observer=live.DemoObserver(Writer())
        base=transport.CaptureLedger;barrier=live.threading.Barrier(2)
        def parent_observe(ledger,role,frame,*args,**kwargs):
            ledger.counts[role][0]=1
            barrier.wait(timeout=2)
        frames=[b'x'*59+b'\x00']
        with patch.object(base,'observe',parent_observe):
            with observer.scoped(calibration):
                ledger=transport.CaptureLedger(frames,lambda f:0)
                threads=[live.threading.Thread(target=ledger.observe,args=(role,frames[0])) for role in ('input','output')]
                for thread in threads:thread.start()
                for thread in threads:thread.join(3);self.assertFalse(thread.is_alive())
                self.assertEqual(ledger.live_counts,{'input_unique':1,'output_unique':1,'matched':1,'pending':0})

    def test_boundary_and_periodic_samples_are_serialized(self):
        observer=live.DemoObserver(Writer())
        threads=[live.threading.Thread(target=lambda:[observer.sample() for _ in range(10)]) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(3);self.assertFalse(thread.is_alive())
        values=[fields['sample']['raw_ns'] for event,fields in observer.writer.events if event=='sample']
        self.assertEqual(len(values),20);self.assertEqual(values,sorted(values))

    def test_live_clock_health_is_observations_not_final_pass(self):
        observer=live.DemoObserver(Writer());calibration=SimpleNamespace(RawMeasurementResources=object)
        with observer.scoped(calibration):
            audit=transport.RawClockAudit()
            audit.observe(100,100,100,100,120);audit.observe(30_000_120,30_000_120,30_000_120,30_000_120,30_000_140)
            observer.sample();clock=observer.writer.events[-1][1]['sample']['clock']
            self.assertEqual(clock['status'],'OBSERVING')
            self.assertFalse(clock['final_verdict'])
            self.assertGreater(clock['maximum_sample_gap_ms'],25)

    def test_resource_read_uses_existing_cache_not_new_proc_sample(self):
        observer=live.DemoObserver(Writer());observer.phase='measurement'
        row=dict(raw_ns=1000,utime_ticks=1,stime_ticks=1,start_time_ticks=1,rss_kib=1024,vmhwm_kib=2048)
        monitor=SimpleNamespace(_lock=live.threading.Lock(),_samples=[row],clock_ticks_per_second=100)
        observer.resource=SimpleNamespace(monitors={'bmv2':monitor})
        observer.sample();r=observer.writer.events[-1][1]['sample']['resources']['bmv2']
        self.assertEqual(r['rss_mib'],1);self.assertFalse(r['qualified']);self.assertIsNone(r['cpu_percent_one_core'])

    def test_cancel_is_retained_for_next_native_plan(self):
        observer=live.DemoObserver(Writer());observer.cancel()
        class Plan:
            cancelled=False
            def cancel(self):self.cancelled=True
        class Sender:
            provenance={'original':True}
            def prepare(self):return Plan()
        wrapped=live.ObservedSender(Sender(),observer);plan=wrapped.prepare()
        self.assertTrue(plan.plan.cancelled);self.assertEqual(wrapped.provenance,{'original':True})

    def test_native_result_published_before_report_conversion(self):
        observer=live.DemoObserver(Writer());observer.phase='measurement'
        class Plan:
            def run_raw(self,fd):
                return SimpleNamespace(scheduled_start_ns=1_000_000_000,send_window_end_ns=2_000_000_000,
                                       sent_count=250,attempted_count=250)
            def report(self,result):raise AssertionError('Must not decode native arrays to publish compact statistics')
        plan=live.ObservedPlan(Plan(),observer);result=plan.run_raw(7)
        event,payload=observer.writer.events[-1]
        self.assertEqual(event,'measurement_completed')
        self.assertEqual(payload['sender_statistics']['sent_packets'],250)
        self.assertEqual(payload['sender_statistics']['offered_pps'],250)
        self.assertFalse(payload['sender_statistics']['qualified'])
        self.assertEqual(observer.phase,'draining')

    def test_cancel_latch_refuses_subsequent_phase_before_traffic(self):
        observer=live.DemoObserver(Writer());calibration=SimpleNamespace(RawMeasurementResources=object)
        with patch.object(transport,'run_phase') as original:
            with observer.scoped(calibration):
                observer.cancel()
                with self.assertRaises(KeyboardInterrupt):transport.run_phase([],'one','two',250)
            original.assert_not_called()

    def test_reject_high_frequency_telemetry(self):
        with self.assertRaises(ValueError):live.DemoObserver(Writer(),interval=.1)


if __name__=='__main__':unittest.main()
