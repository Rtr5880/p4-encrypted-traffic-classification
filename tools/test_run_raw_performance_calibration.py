"""Bounded protocol, equal traffic, qualification and metric contracts."""
from copy import deepcopy
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_raw_performance_calibration as runner


class CalibrationTests(unittest.TestCase):
    def test_protocol_cannot_become_full_sweep(self):
        for rates in ([5000], [100, 1000, 5000], [], [100, 100], [True]):
            with self.assertRaises(ValueError):
                runner.calibration_protocol(rates)
        protocol = runner.calibration_protocol([100, 1000])
        self.assertEqual(protocol['repetitions'], 1)
        self.assertEqual(protocol['maximum_trials'], 16)
        self.assertFalse(protocol['kernel_forwarding_latency_qualified'])

    def test_same_plans_and_isolated_warmup_for_every_mode(self):
        protocol = runner.calibration_protocol([100, 1000])
        blocks = runner.legacy.build_schedule(protocol, 'offline-contract')
        self.assertEqual(len(blocks) * 4, 16)
        for block in blocks:
            warm, measured = runner.legacy.plans_for(block, protocol)
            self.assertFalse(set(warm.slots) & set(measured.slots))
            self.assertEqual(measured.packet_count, block['rate_pps'] * 20)
            expected = 248 if block['rate_pps'] == 100 and block['workload'] == 'classification-heavy' else None
            if expected:
                self.assertEqual(measured.expected_classifications, expected)
            baseline = runner.legacy.frame_hash(measured)
            for _ in block['modes']:
                self.assertEqual(runner.legacy.frame_hash(runner.legacy.plans_for(block, protocol)[1]), baseline)

    def test_unqualified_rates_withheld_counts_memory_retained(self):
        row = {'valid': True, 'failures': [], 'metric_validity': dict(offered_load=True,
            delivered_throughput=True, classification_rate=True, cpu=True, memory=True,
            packet_accounting=True, kernel_forwarding_latency=False)}
        rows = [deepcopy(row)]
        runner.apply_rate_qualification(rows, False)
        self.assertFalse(rows[0]['valid'])
        for gate in ('offered_load', 'delivered_throughput', 'classification_rate', 'cpu'):
            self.assertFalse(rows[0]['metric_validity'][gate])
        self.assertTrue(rows[0]['metric_validity']['memory'])
        self.assertTrue(rows[0]['metric_validity']['packet_accounting'])
        self.assertFalse(rows[0]['metric_validity']['kernel_forwarding_latency'])

    def test_qualification_does_not_promote_locally_invalid_metrics(self):
        row = {'valid': False, 'failures': ['bad RAW clock'], 'metric_validity': {'offered_load': False}}
        runner.apply_rate_qualification([row], True)
        self.assertFalse(row['valid'])
        self.assertFalse(row['metric_validity']['offered_load'])

    def test_failed_warmup_integrity_quarantines_rates_but_preserves_counts(self):
        row = {'valid': False, 'instrument_valid_before_rate_qualification': False,
               'failures': ['warm-up capture loss'], 'metric_validity': dict(
                   offered_load=True, delivered_throughput=True, classification_rate=True,
                   cpu=True, classification_counts=True, cpu_accounting=True, memory=True)}
        runner.apply_rate_qualification([row], True)
        for name in ('offered_load', 'delivered_throughput', 'classification_rate', 'cpu'):
            self.assertFalse(row['metric_validity'][name])
        for name in ('classification_counts', 'cpu_accounting', 'memory'):
            self.assertTrue(row['metric_validity'][name])

    def test_each_mode_notifies_only_the_measured_window_without_querying(self):
        for mode in runner.legacy.MODES:
            events = []
            resources = SimpleNamespace(start=lambda: events.append('resource_start'))
            qualifier = SimpleNamespace(notify_measurement_window=lambda *a, **kw:
                events.append((a, kw)))
            with patch.object(runner.transport, 'raw_now_ns', return_value=10_000_000_000):
                runner.start_measurement_window(resources, qualifier, 20_000, 1000,
                                                mode=mode, workload='classification-heavy')
            self.assertEqual(events, ['resource_start',
                ((10_000_000_000, 30_000_000_000, 1000), dict(mode=mode, workload='classification-heavy'))])


class CampaignFinalizationTests(unittest.TestCase):
    """Mock only external work; exercise actual exclusive JSON writes and seal."""

    def exercise(self, *, fail_first=False, qualified=True, warn_first=False, provenance_failed=False):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            args = SimpleNamespace(prepared=repo / 'prepared', smoke_run=repo / 'smoke')
            protocol = runner.calibration_protocol([100])
            block = runner.legacy.build_schedule(protocol, 'finalization-regression')[0]
            block['modes'] = ['rf_b', 'rf_c']
            block['plan_file'] = 'plan.json'
            warm, measured = runner.legacy.plans_for(block, protocol)
            plan = dict(warmup=warm.manifest(), measurement=measured.manifest(),
                        warmup_frames_sha256=runner.legacy.frame_hash(warm),
                        measurement_frames_sha256=runner.legacy.frame_hash(measured))
            manifest = dict(protocol=protocol, schedule=[block], expected_live_trials=2,
                            programs={name: {'path': '/synthetic.json'} for name in block['modes']},
                            input_sha256={})
            receipt = dict(receipt_sha256='hash')
            smoke = dict(passed=True, status='raw_packet_file_smoke_passed',
                         prepared_manifest_sha256='hash', clock_receipt_sha256='hash',
                         legacy_check=str(repo / 'old_smoke'), legacy_check_sha256='hash')
            local_payloads, calls, links_created, qualifiers_created = {}, [], [], []

            class Links:
                def __init__(self, name):
                    self.cleanup_errors = []
                    self.cleaned = False
                    links_created.append(self)
                def __enter__(self):
                    return self
                def __exit__(self, *unused):
                    self.cleaned = True

            class Qualifier:
                def __init__(self, **unused):
                    self.records = [{'valid': True, 'query_brackets_valid': True}]
                    self.pins = {name: {} for name in runner.raw_clock.PROVIDERS}
                    self.stopped = False
                    qualifiers_created.append(self)
                def start(self):
                    pass
                def stop(self):
                    self.stopped = True
                def report(self, start, end, *, load_windows):
                    self.windows = load_windows
                    return dict(passed=qualified, status='PASS' if qualified else 'INCONCLUSIVE')

            def read_json(path):
                if path == args.smoke_run / 'summary.json':
                    return smoke
                if path == repo / 'old_smoke' / 'summary.json':
                    return dict(artifact_hashes={})
                if path == args.prepared / 'plan.json':
                    return plan
                raise AssertionError(f'Unexpected external read: {path}')

            def trial(*positional, qualifier=None):
                mode, directory = positional[2], positional[-1]
                self.assertIs(qualifier, qualifiers_created[0])
                directory.mkdir()
                valid = not (fail_first and not calls)
                calls.append(mode)
                row = dict(mode=mode, workload=block['workload'], rate_pps=100,
                    block_id=block['block_id'], repetition=1, valid=valid,
                    instrument_valid_before_rate_qualification=valid,
                    failures=[] if valid else ['RAW warm-up capture integrity failed'],
                    metric_validity=dict(offered_load=True, delivered_throughput=True,
                        packet_accounting=True, classification_rate=True, classification_counts=True,
                        cpu=True, cpu_accounting=True, resources=True, memory=True,
                        kernel_forwarding_latency=False),
                    metrics=dict(packets_received=measured.packet_count, decisions=measured.expected_classifications),
                    rate_window=dict(start_raw_ns=1_000_000_000, end_raw_ns=21_000_000_000,
                                     target_pps=100, mode=mode, workload=block['workload']))
                warning = warn_first and len(calls) == 1
                row['verdicts'] = dict(
                    measurement_integrity=dict(status='PASS' if valid else 'FAIL', failures=row['failures'][:]),
                    independent_raw_qualification=dict(status='NOT_EVALUATED', absolute_rate_claims_qualified=False),
                    sender_pacing_conformance=dict(status='WARNING' if warning else 'PASS',
                        warmup=dict(status='WARNING' if warning else 'PASS', warnings=['warm-up completion above unchanged maximum'] if warning else []),
                        measurement=dict(status='PASS', warnings=[])))
                runner.write_json(directory / 'trial_summary.json', row)
                local_payloads[directory.name] = (directory / 'trial_summary.json').read_bytes()
                return row

            with patch.object(runner.os, 'geteuid', return_value=0), \
                 patch.object(runner, 'load_prepared', return_value=(manifest, receipt,
                     SimpleNamespace(read=lambda: None, provenance={}), SimpleNamespace(provenance={}))), \
                 patch.object(runner.integration, 'read_json', side_effect=read_json), \
                 patch.object(runner, 'hash_file', return_value='hash'), \
                 patch.object(runner.legacy, 'verify_seal'), \
                 patch.object(runner.legacy, 'exclusive_run', side_effect=lambda _: nullcontext()), \
                 patch.object(runner.legacy, 'resource_preflight', return_value={}), \
                 patch.object(runner.legacy, 'host_snapshot', return_value={}), \
                 patch.object(runner.ownership, 'OwnedLinks', Links), \
                 patch.object(runner.ownership, 'verify_hashes', side_effect=ValueError('changed frozen input') if provenance_failed else None), \
                 patch.object(runner.raw_clock, 'RateQualification', Qualifier), \
                 patch.object(runner, 'run_trial', side_effect=trial):
                output = runner.run(args, repo)

            summary = json.loads((output / 'summary.json').read_text())
            self.assertTrue(links_created[0].cleaned)
            self.assertTrue(qualifiers_created[0].stopped)
            self.assertTrue((output / 'host_after.json').is_file())
            self.assertEqual(summary['attempted_trials'], 1 if fail_first else 2)
            self.assertEqual(summary['passed'], not fail_first and qualified and not provenance_failed)
            self.assertEqual(summary['raw_rate_qualified'], qualified)
            self.assertEqual(summary['frozen_inputs_unchanged'], not provenance_failed)
            self.assertEqual(summary['pacing_warning_trials'], 1 if warn_first else 0)
            self.assertFalse(summary['uniform_load_claim_eligible'])
            self.assertFalse(summary['saturation_claim_eligible'])
            self.assertEqual(summary['qualified_trial_summary_file'], 'qualified_trial_summary.json')
            for name in summary['trials']:
                self.assertEqual((output / name / 'trial_summary.json').read_bytes(), local_payloads[name])
                original = json.loads(local_payloads[name])
                final = json.loads((output / name / 'qualified_trial_summary.json').read_text())
                self.assertNotIn('raw_rate_qualified', original)
                self.assertEqual(original['verdicts']['independent_raw_qualification']['status'], 'NOT_EVALUATED')
                self.assertEqual(final['raw_rate_qualified'], qualified)
                self.assertEqual(final['verdicts']['independent_raw_qualification']['status'], 'PASS' if qualified else 'INCONCLUSIVE')
                self.assertEqual(final['verdicts']['sender_pacing_conformance'], original['verdicts']['sender_pacing_conformance'])
                for filename in ('trial_summary.json', 'qualified_trial_summary.json'):
                    self.assertIn(f'{name}/{filename}', summary['artifact_hashes'])
                if fail_first or not qualified or provenance_failed:
                    self.assertFalse(final['metric_validity']['offered_load'])
                    self.assertTrue(final['metric_validity']['classification_counts'])
                if provenance_failed:
                    self.assertEqual(final['verdicts']['measurement_integrity']['status'], 'FAIL')
                    self.assertFalse(final['valid'])
                    self.assertTrue(original['valid'])
                    self.assertIn('provenance', ' '.join(final['failures']))
            self.assertEqual(len(qualifiers_created[0].windows), 0 if fail_first else 2)
            if fail_first:
                self.assertIn('hard capture', summary['abort_reason'])
                self.assertEqual(calls, ['rf_b'])

    def test_successful_campaign_finalizes_without_recreating_local_summaries(self):
        self.exercise()

    def test_failed_quality_gate_stops_and_still_finalizes(self):
        self.exercise(fail_first=True)

    def test_inconclusive_external_qualification_finalizes_and_withholds_rates(self):
        self.exercise(qualified=False)

    def test_pacing_warning_is_preserved_but_does_not_stop_qualified_campaign(self):
        self.exercise(warn_first=True)

    def test_final_provenance_failure_quarantines_rates_without_changing_local_evidence(self):
        self.exercise(provenance_failed=True)


if __name__ == '__main__':
    unittest.main()
