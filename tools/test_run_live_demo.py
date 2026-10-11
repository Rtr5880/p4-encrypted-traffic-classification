import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,MagicMock

sys.path.insert(0,str(Path(__file__).resolve().parent))
import run_live_demo as demo


class DemoRunnerTests(unittest.TestCase):
    def test_mode_rate_workload_bounded(self):
        for mode in demo.MODES:
            for rate in demo.RATES:
                for workload in demo.WORKLOADS:
                    p=demo.demo_protocol(mode,rate,workload)
                    self.assertEqual((p['maximum_trials'],p['warmup_seconds'],p['duration_seconds']),(1,5,20))
                    self.assertTrue(p['demo_only'])
        for bad in [('all',250,'classification-heavy'),('rf_c',5000,'classification-heavy'),
                    ('rf_c',True,'classification-heavy'),('rf_c',250,'real-pcap')]:
            with self.assertRaises(ValueError):demo.demo_protocol(*bad)

    def test_thresholds_and_qualification_unchanged(self):
        p=demo.demo_protocol('rf_c',250,'classification-heavy')
        self.assertEqual(p['maximum_clock_sampling_gap_ns'],25_000_000)
        self.assertEqual(p['maximum_clock_bracket_ns'],100_000)
        self.assertEqual(p['pacing_gates'],demo.legacy.GATES)
        self.assertEqual(p['qualification_minimum_span_seconds'],180)
        self.assertEqual(p['raw_rate_tolerance_ppm'],1000)
        self.assertFalse(p['kernel_forwarding_latency_qualified'])

    def test_plans_disjoint_and_bounded_for_every_supported_rate(self):
        for rate in demo.RATES:
            p=demo.demo_protocol('rf_c',rate,'classification-heavy');block=demo.make_block(p,'test-token')
            warm,measured=demo.legacy.plans_for(block,p)
            self.assertEqual((warm.packet_count,measured.packet_count),(rate*5,rate*20))
            self.assertFalse(set(warm.slots)&set(measured.slots))
            self.assertEqual(block['modes'],['rf_c'])

    def test_nonempty_history_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder);root=repo/'results/live_demo';root.mkdir(parents=True)
            run=root/'run1';run.mkdir()
            self.assertEqual(demo.resolve_run_directory(repo,run),run)
            (run/'original.txt').write_text('preserve')
            with self.assertRaises(ValueError):demo.resolve_run_directory(repo,run)
            other=repo/'historical';other.mkdir()
            with self.assertRaises(ValueError):demo.resolve_run_directory(repo,other)

    def test_competing_launch_lock_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder)
            with demo.demo_lock(repo):
                with self.assertRaises(ValueError):
                    with demo.demo_lock(repo):pass
            with demo.demo_lock(repo):pass

    def test_normaluser_run_cannot_launch_privileged_worker(self):
        with patch.object(demo.os,'geteuid',return_value=1000):
            with self.assertRaises(ValueError):demo.run(SimpleNamespace(),Path('/unused'))

    def test_root_launcher_rejected_before_dashboard(self):
        with patch.object(demo.os,'geteuid',return_value=0):
            with self.assertRaises(ValueError):demo.launch(SimpleNamespace(),Path('/unused'))

    def test_worker_lock_precedes_any_telemetry_or_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder)
            with demo.legacy.exclusive_run(repo),patch.object(demo.os,'geteuid',return_value=0),patch.object(demo,'_run_locked') as run:
                with self.assertRaises(ValueError):demo.run(SimpleNamespace(),repo)
                run.assert_not_called()

    def test_fresh_source_closure_rebinds_only_unused_analyzer(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder);(repo/'tools').mkdir()
            analyzer=repo/'tools/analyze_raw_performance.py';analyzer.write_text('new offline analyzer')
            runtime=repo/'tools/raw_paced_sender.c';runtime.write_text('frozen runtime')
            source={'input_sha256':{str(analyzer):'0'*64,str(runtime):demo.hash_file(runtime)}}
            closure,note=demo.source_closure(source,repo)
            self.assertEqual(closure[str(analyzer)],demo.hash_file(analyzer))
            self.assertTrue(note['changed']);self.assertFalse(note['historical_manifest_modified'])
            self.assertFalse(note['historical_calibration_requalified'])
            self.assertEqual(source['input_sha256'][str(analyzer)],'0'*64)
            runtime.write_text('changed runtime')
            with self.assertRaises(ValueError):demo.source_closure(source,repo)

    def test_demo_seal_never_opens_growing_telemetry_or_atomic_temp(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder);(p/'trial_001').mkdir()
            for name in ('events.jsonl','snapshot.json','.snapshot.json.atomic.tmp','provenance.json','clock_rate_qualification.json'):
                (p/name).write_text('fixture')
            (p/'trial_001/measurement.json').write_text('fixture')
            seal=demo.demo_artifact_seal(p)
            self.assertEqual(set(seal),{'provenance.json','clock_rate_qualification.json','trial_001/measurement.json'})

    def test_file_smoke_is_bounded_and_exercises_cached_packets(self):
        frames,expected,counts=demo.file_smoke_frames('classification-heavy')
        self.assertEqual((len(frames),expected),(64,8));self.assertEqual(set(counts.values()),{8})
        frames,expected,counts=demo.file_smoke_frames('cached-forwarding')
        self.assertEqual((len(frames),expected),(64,2));self.assertEqual(set(counts.values()),{32})


if __name__=='__main__':unittest.main()
