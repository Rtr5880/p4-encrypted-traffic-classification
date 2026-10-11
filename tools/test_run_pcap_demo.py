import hashlib
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import run_pcap_demo as demo


class PcapRunnerTests(unittest.TestCase):
    def test_selected_single_and_paired_models(self):
        self.assertEqual(demo.selected_models('compare'),['B','C'])
        self.assertEqual(demo.selected_models('rf_b'),['B']);self.assertEqual(demo.selected_models('rf_c'),['C'])
        with self.assertRaises(ValueError):demo.selected_models('forwarding')

    def test_prefix_preserves_eight_heldout_native_packets(self):
        raw=b'\x45'+b'\x00'*19
        bundle={'native_clock_required':True,'record':{'partition':'test','n':8},
            'packets':[{'raw_ip_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest()} for _ in range(8)],
            'relative_us':[0,10,20,30,40,50,60,70],'native_programs':{'B':{},'C':{}}}
        demo.validate_bundle(bundle)
        for invalid in ({'relative_us':[0]*8},{'native_clock_required':False},
                        {'record':{'partition':'development','n':8}},{'packets':bundle['packets'][:7]},
                        {'relative_us':[0,10,20,30,40,50,60,2_000_001]}):
            with self.assertRaises(ValueError):demo.validate_bundle(dict(bundle,**invalid))

    def test_modified_raw_bytes_are_rejected(self):
        raw=b'\x45'+b'\x00'*19
        b={'native_clock_required':True,'record':{'partition':'test','n':8},
            'packets':[{'raw_ip_hex':raw.hex(),'sha256':'0'*64} for _ in range(8)],
            'relative_us':list(range(8)),'native_programs':{'B':{},'C':{}}}
        with self.assertRaises(ValueError):demo.validate_bundle(b)

    def test_nonprivileged_worker_rejected_before_execution(self):
        with patch.object(demo.os,'geteuid',return_value=1000):
            with self.assertRaises(ValueError):demo.run(SimpleNamespace(),Path('/unused'))

    def test_root_launcher_is_rejected(self):
        with patch.object(demo.os,'geteuid',return_value=0):
            with self.assertRaises(ValueError):demo.launch(SimpleNamespace(),Path('/unused'))

    def test_same_existing_experiment_lock_prevents_synthetic_conflict(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder)
            with demo.legacy.exclusive_run(repo),patch.object(demo.os,'geteuid',return_value=0),patch.object(demo,'_run_locked') as worker:
                with self.assertRaises(ValueError):demo.run(SimpleNamespace(),repo)
                worker.assert_not_called()

    def test_repeated_stop_signals_only_latch_and_emit(self):
        import threading
        stop=threading.Event();observer=SimpleNamespace(cancel=unittest.mock.Mock());writer=SimpleNamespace(emit=unittest.mock.Mock())
        signals=iter([SimpleNamespace(si_signo=2),SimpleNamespace(si_signo=15)])
        def wait(*unused):
            try:return next(signals)
            except StopIteration:stop.set();return None
        demo.watch_cancellation(observer,writer,stop,wait=wait)
        self.assertEqual(observer.cancel.call_count,2);self.assertEqual(writer.emit.call_count,2)

    def test_mask_is_restored_even_on_worker_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            repo=Path(folder)
            with patch.object(demo.os,'geteuid',return_value=0),patch.object(demo.signal,'pthread_sigmask',return_value={99}) as mask,\
                 patch.object(demo.signal,'sigtimedwait',return_value=None),patch.object(demo,'_run_locked',side_effect=RuntimeError('fixture')):
                with self.assertRaises(RuntimeError):demo.run(SimpleNamespace(),repo)
                self.assertEqual(mask.call_args_list[-1].args,(demo.signal.SIG_SETMASK,{99}))

    def test_actual_completed_model_survives_observer_failure(self):
        result={'parity_passed':True,'clock_quality':{'clean':True},'native_time_prediction':'VOIP'}
        results={};observer=SimpleNamespace(complete_model=unittest.mock.Mock(side_effect=RuntimeError('observer failed')))
        with self.assertRaises(RuntimeError):demo.preserve_model_result(results,'B',result,observer)
        self.assertIs(results['B'],result)

    def test_demo_pins_reused_resource_sources_without_changing_them(self):
        repo=Path(demo.__file__).resolve().parent.parent
        hashes=demo.source_hashes(repo)
        for filename in ('raw_performance_resources.py','live_demo_transport.py'):
            path=(repo/'tools'/filename).resolve()
            self.assertEqual(hashes[str(path)],demo.hash_file(path))


if __name__=='__main__':unittest.main()
