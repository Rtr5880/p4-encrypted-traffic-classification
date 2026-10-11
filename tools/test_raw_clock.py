"""Synthetic RAW-clock contracts; no network requests, services or benchmarks."""
import struct
from pathlib import Path
import platform
import shutil
import tempfile
import unittest
from unittest.mock import patch

import raw_clock as clock


def sample(raw, bracket=40, wall_step=0):
    mono = 2_000_000_000 + int(raw * 0.97415)
    return (raw, mono, 1_767_225_600_000_000_000 + mono + wall_step, mono + 10, raw + bracket)


def network_records(span=200, ppm=0, error_ns=10_000_000):
    records = []
    for index, seconds in enumerate((0, span * 0.3, span)):
        raw = 1_000_000_000 + round(seconds * 1e9 * (1 + ppm / 1e6))
        for provider in clock.PROVIDERS:
            records.append({'provider': provider, 'address': '192.0.2.1',
                'query_index': index, 'valid': True, 'query_brackets_valid': True,
                'before': list(sample(raw)), 'after': list(sample(raw + 1_000_000)),
                'server_transmit_ns': 1_767_225_600_000_000_000 + round(seconds * 1e9),
                'advertised_error_bound_ns': error_ns})
    return records


def qualified(records, span=200):
    return clock.qualification_report(records, start_raw_ns=3_000_000_000,
        end_raw_ns=max(record['before'][0] for record in records if record.get('valid')) - 1_000_000_000,
        load_windows=[{
            'start_raw_ns': int(span * 0.2 * 1e9),
            'end_raw_ns': int(span * 0.4 * 1e9), 'target_pps': 1000}])


def ntp_timestamp(unix_ns):
    return struct.pack('!II', unix_ns // 10**9 + clock.NTP_EPOCH,
                       unix_ns % 10**9 * 2**32 // 10**9)


def reply(nonce=b'12345678'):
    packet = bytearray(48)
    packet[0], packet[1] = 0x24, 2
    packet[3] = 236  # -20, approximately one microsecond precision.
    packet[8:12] = struct.pack('!I', 100)
    packet[24:32] = nonce
    packet[32:40] = ntp_timestamp(1_767_225_600_000_000_000)
    packet[40:48] = ntp_timestamp(1_767_225_600_001_000_000)
    return packet


@unittest.skipUnless(platform.system() == 'Linux' and shutil.which('cc'), 'Linux native reader build required')
class NativeReaderTests(unittest.TestCase):
    def test_native_reader_build_abi_domain_and_absolute_seals(self):
        with tempfile.TemporaryDirectory(prefix='raw_reader_contract_') as name:
            repo = Path(name)
            (repo / 'tools').mkdir()
            shutil.copyfile(Path(clock.__file__).with_name('raw_clock_bracket.c'), repo / 'tools/raw_clock_bracket.c')
            library = clock.build_raw_clock_reader(repo=repo)
            reader = clock.RawClockReader(library)
            row = reader.read()
            self.assertEqual(len(row), 5)
            self.assertTrue(all(type(value) is int for value in row))
            self.assertLessEqual(row[0], row[4])
            self.assertLessEqual(row[1], row[3])
            self.assertEqual(reader.provenance['clock_sequence'], clock.CLOCK_SEQUENCE)
            self.assertTrue(all(Path(path).is_absolute() for path in reader.provenance['input_sha256']))
            for path, expected in reader.provenance['input_sha256'].items():
                self.assertEqual(clock.sha256_file(path), expected)


class AuditTests(unittest.TestCase):
    def audit(self, times=(0, 5_000_000, 10_000_000, 15_000_000)):
        audit = clock.RawClockAudit()
        for raw in times:
            audit.observe(*sample(raw))
        return audit

    def test_legacy_rate_and_wall_steps_do_not_hide_or_invalidate_raw(self):
        audit = clock.RawClockAudit()
        for index, raw in enumerate((0, 5_000_000, 10_000_000, 15_000_000)):
            audit.observe(*sample(raw, wall_step=1_000_000_000 if index >= 2 else 0))
        report = audit.report(1_000_000, 14_000_000)
        self.assertTrue(report['valid'])
        self.assertEqual(len(report['samples']), 4)
        self.assertTrue(report['realtime_minus_raw_steps_diagnostic'])
        self.assertFalse(report['absolute_rate_qualified'])

    def test_wide_native_bracket_not_filtered(self):
        audit = self.audit()
        audit.samples[1] = sample(5_000_000, bracket=100_001)
        report = audit.report()
        self.assertFalse(report['valid'])
        self.assertEqual(report['maximum_read_bracket_ns'], 100_001)
        self.assertEqual(len(report['samples']), 4)

    def test_wide_bracket_outside_window_is_still_retained_failure(self):
        audit = self.audit()
        audit.observe(*sample(2_000_000_000, bracket=100_001))
        report = audit.report(1_000_000, 14_000_000)
        self.assertFalse(report['valid'])
        self.assertEqual(report['maximum_read_bracket_ns'], 100_001)

    def test_sampling_gap_limit_not_relaxed(self):
        report = self.audit((0, 5_000_000, 31_000_001)).report()
        self.assertFalse(report['valid'])
        self.assertIn('raw_clock_sample_gap_over_25ms', report['reasons'])

    def test_raw_regression(self):
        report = self.audit((0, 5_000_000, 4_000_000)).report()
        self.assertFalse(report['valid'])
        self.assertEqual(report['raw_regressions'], 1)

    def test_missing_measurement_edge_is_invalid(self):
        report = self.audit().report(-1, 14_000_000)
        self.assertFalse(report['valid'])
        self.assertIn('raw_audit_missing_window_brackets', report['reasons'])

    def test_sampler_requires_native_reader(self):
        with self.assertRaises(RuntimeError):
            clock.RawClockAudit().sample()
        audit = clock.RawClockAudit(bracket_reader=lambda: sample(0))
        audit.sample()
        self.assertEqual(len(audit.samples), 1)

    def test_invalid_window_and_observation(self):
        with self.assertRaises(ValueError):
            self.audit().report(0, 0)
        with self.assertRaises(ValueError):
            self.audit().observe(0, 1, 2)


class RateTests(unittest.TestCase):
    def test_zero_rate_error_passes_three_providers(self):
        report = qualified(network_records())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(len(report['queries']), 9)
        for provider in report['providers'].values():
            self.assertEqual(provider['valid_queries'], 3)
            self.assertEqual(provider['representative_load_queries'], 1)
            self.assertLess(provider['raw_rate']['upper_ppm'], 1000)

    def test_old_monotonic_error_fails(self):
        report = qualified(network_records(ppm=-25850))
        self.assertEqual(report['status'], 'FAIL')
        self.assertLess(report['providers'][clock.PROVIDERS[0]]['raw_rate']['upper_ppm'], -1000)

    def test_positive_and_negative_qualified_errors(self):
        for error in (-500, 500):
            with self.subTest(ppm=error):
                self.assertEqual(qualified(network_records(ppm=error))['status'], 'PASS')

    def test_uncertainty_not_confused_with_a_fail_or_a_pass(self):
        report = qualified(network_records(error_ns=1_000_000_000))
        self.assertEqual(report['status'], 'INCONCLUSIVE')

    def test_short_span_inconclusive(self):
        report = qualified(network_records(span=30), span=30)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertIn('reference_span_under_180_seconds', report['providers'][clock.PROVIDERS[0]]['reasons'])

    def test_short_span_suspected_rate_error_stays_inconclusive(self):
        report = qualified(network_records(span=30, ppm=-25850), span=30)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertTrue(report['providers'][clock.PROVIDERS[0]]['raw_rate']['outside_1000ppm'])

    def test_unavailable_provider_keeps_all_failures(self):
        records = [record for record in network_records() if record['provider'] != clock.PROVIDERS[-1]]
        records.append({'provider': clock.PROVIDERS[-1], 'query_index': -1,
                        'valid': False, 'error': 'DNS blocked'})
        report = qualified(records)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(len(report['queries']), 7)
        self.assertEqual(report['providers'][clock.PROVIDERS[-1]]['failed_queries'], 1)

    def test_any_wide_query_bracket_is_not_silently_dropped(self):
        records = network_records()
        records[3]['query_brackets_valid'] = False
        report = qualified(records)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(len(report['queries']), 9)
        self.assertEqual(report['providers'][clock.PROVIDERS[0]]['invalid_bracket_queries'], 1)

    def test_endpoint_queries_must_surround_campaign(self):
        report = clock.qualification_report(network_records(), start_raw_ns=0,
            end_raw_ns=190_000_000_000, load_windows=[{
                'start_raw_ns': 50_000_000_000, 'end_raw_ns': 70_000_000_000, 'target_pps': 1000}])
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertFalse(report['providers'][clock.PROVIDERS[0]]['campaign_covered'])

    def test_low_load_queries_do_not_qualify_highest_load(self):
        report = clock.qualification_report(network_records(), start_raw_ns=3_000_000_000,
            end_raw_ns=199_000_000_000, load_windows=[{
                'start_raw_ns': 50_000_000_000, 'end_raw_ns': 70_000_000_000, 'target_pps': 100}, {
                'start_raw_ns': 100_000_000_000, 'end_raw_ns': 130_000_000_000, 'target_pps': 1000}])
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(report['representative_load_target_pps'], 1000)
        self.assertEqual(report['providers'][clock.PROVIDERS[0]]['representative_load_queries'], 0)

    def test_independent_rate_is_not_taken_from_previous_evidence(self):
        report = clock.qualification_report([])
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertFalse(report['valid'])
        self.assertTrue(report['previous_qualification_not_reused'])

    def test_interval_arithmetic_nonpositive_span(self):
        with self.assertRaises(ValueError):
            clock.rate_bounds([0, 1], [0, 1], [0, 1], [0, 1])


class NtpTests(unittest.TestCase):
    def test_valid_response_advertised_uncertainty(self):
        parsed = clock.parse_ntp(reply(), b'12345678')
        self.assertEqual(parsed['stratum'], 2)
        self.assertGreater(parsed['advertised_error_bound_ns'], 0)
        self.assertGreaterEqual(parsed['server_transmit_ns'], parsed['server_receive_ns'])

    def test_malformed_short_or_wrong_nonce(self):
        for packet, nonce in [(b'123', b'12345678'), (reply(), b'abcdefgh')]:
            with self.subTest(length=len(packet)), self.assertRaises(ValueError):
                clock.parse_ntp(packet, nonce)

    def test_unsynchronized_kiss_of_death_and_wrong_mode(self):
        for field, value in [(0, 0xE4), (0, 0x23), (1, 0), (1, 16)]:
            packet = reply()
            packet[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                clock.parse_ntp(packet, b'12345678')

    def test_server_timestamp_order_rejected(self):
        packet = reply()
        packet[32:40] = ntp_timestamp(1_767_225_601_000_000_000)
        with self.assertRaises(ValueError):
            clock.parse_ntp(packet, b'12345678')

    def test_timeout_keeps_request_and_observation(self):
        with patch('raw_clock.socket.socket') as mocked:
            sock = mocked.return_value.__enter__.return_value
            sock.send.return_value = 48
            sock.recv.side_effect = TimeoutError('test timeout')
            result = clock.network_query(clock.PROVIDERS[0], '192.0.2.1', lambda: sample(0), 3)
        self.assertFalse(result['valid'])
        self.assertIn('request_hex', result)
        self.assertIn('before', result)
        self.assertIn('TimeoutError', result['error'])

    def test_parse_failure_retains_raw_response(self):
        with patch('raw_clock.socket.socket') as mocked:
            sock = mocked.return_value.__enter__.return_value
            sock.send.return_value = 48
            sock.recv.return_value = b'bad'
            result = clock.network_query(clock.PROVIDERS[0], '192.0.2.1', lambda: sample(0), 3)
        self.assertFalse(result['valid'])
        self.assertEqual(result['response_hex'], b'bad'.hex())
        self.assertIn('after', result)

    def test_qualification_import_and_configuration_do_not_acquire(self):
        with patch('raw_clock.network_query') as mocked:
            qualifier = clock.RateQualification(reader=lambda: sample(0))
            mocked.assert_not_called()
        self.assertFalse(qualifier.report()['valid'])
        with self.assertRaises(ValueError):
            clock.RateQualification(reader=lambda: sample(0), interval_seconds=1)


class MeasurementSchedulingTests(unittest.TestCase):
    """Virtual RAW deadlines and synthetic replies, never live network traffic."""
    def ready_qualifier(self):
        qualifier = clock.RateQualification(reader=lambda: sample(0))
        qualifier._thread = object()
        qualifier._ready.set()
        qualifier.pins = {provider: {'address': '192.0.2.1'} for provider in clock.PROVIDERS}
        return qualifier

    def test_notification_is_nonblocking_and_independent_of_periodic_phase(self):
        qualifier = self.ready_qualifier()
        with patch('raw_clock.network_query') as query:
            identifier = qualifier.notify_measurement_window(10 * 10**9, 30 * 10**9,
                1000, mode='rf_b', workload='classification-heavy')
            query.assert_not_called()
        self.assertEqual(identifier, 1)
        self.assertEqual(qualifier._next_work(11 * 10**9, 100 * 10**9), ('wait', None))
        work, request = qualifier._next_work(12 * 10**9, 100 * 10**9)
        self.assertEqual(work, 'measurement_window')
        self.assertEqual(request['actual_round_start_raw_ns'], 12 * 10**9)
        self.assertEqual(request['target_pps'], 1000)

    def test_imminent_load_round_prevents_duplicate_autonomous_round(self):
        qualifier = self.ready_qualifier()
        qualifier.notify_measurement_window(29 * 10**9, 49 * 10**9, 100)
        self.assertEqual(qualifier._next_work(30 * 10**9, 30 * 10**9), ('wait', None))
        work, request = qualifier._next_work(31 * 10**9, 30 * 10**9)
        self.assertEqual(work, 'measurement_window')
        # A claimed request cannot dispatch a second load round.
        self.assertEqual(qualifier._next_work(31 * 10**9, 61 * 10**9), ('wait', None))
        self.assertEqual(request['status'], 'acquiring')

    def test_expired_window_is_recorded_not_acquired_as_if_loaded(self):
        qualifier = self.ready_qualifier()
        qualifier.notify_measurement_window(10 * 10**9, 30 * 10**9, 1000)
        with patch('raw_clock.network_query') as query:
            self.assertEqual(qualifier._next_work(23 * 10**9, 100 * 10**9), ('wait', None))
            query.assert_not_called()
        self.assertEqual(qualifier._window_requests[0]['status'], 'not_acquired')
        self.assertIn('missed', qualifier._window_requests[0]['reason'])

    def test_duplicate_short_inactive_and_invalid_notifications_rejected(self):
        inactive = clock.RateQualification(reader=lambda: sample(0))
        with self.assertRaises(RuntimeError):
            inactive.notify_measurement_window(0, 20 * 10**9, 100)
        qualifier = self.ready_qualifier()
        for start, end, rate in [(0, 5 * 10**9, 100), (-1, 20 * 10**9, 100),
                                 (0, 20 * 10**9, 0), (0.0, 20 * 10**9, 100)]:
            with self.subTest(start=start, end=end, rate=rate), self.assertRaises(ValueError):
                qualifier.notify_measurement_window(start, end, rate)
        qualifier.notify_measurement_window(0, 20 * 10**9, 100)
        with self.assertRaises(ValueError):
            qualifier.notify_measurement_window(0, 20 * 10**9, 100)

    def test_load_query_failure_is_preserved_and_not_promoted(self):
        qualifier = self.ready_qualifier()
        qualifier.notify_measurement_window(10 * 10**9, 30 * 10**9, 1000)
        _, request = qualifier._next_work(12 * 10**9, 100 * 10**9)
        with patch('raw_clock.network_query', side_effect=lambda provider, address, reader, index:
                   {'provider': provider, 'query_index': index, 'valid': False, 'error': 'timeout'}):
            qualifier._round(1, kind='measurement_window', window_request=request)
        self.assertEqual(len(qualifier.records), 3)
        self.assertTrue(all(record['requested_measurement_schedule_id'] == 1
                            for record in qualifier.records))
        report = clock.qualification_report(qualifier.records, start_raw_ns=10 * 10**9,
            end_raw_ns=30 * 10**9, load_windows=[{'start_raw_ns': 10 * 10**9,
                'end_raw_ns': 30 * 10**9, 'target_pps': 1000}])
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertTrue(all(provider['failed_queries'] == 1
                            for provider in report['providers'].values()))

    def test_requested_window_metadata_cannot_promote_an_outside_query(self):
        records = network_records()
        for record in records:
            record.update(acquisition_kind='measurement_window',
                          requested_measurement_schedule_id=1, requested_target_pps=1000)
        report = clock.qualification_report(records, start_raw_ns=3 * 10**9,
            end_raw_ns=199 * 10**9, load_windows=[{'start_raw_ns': 100 * 10**9,
                'end_raw_ns': 120 * 10**9, 'target_pps': 1000}])
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertTrue(all(provider['representative_load_queries'] == 0
                            for provider in report['providers'].values()))

    def test_worker_completes_all_providers_inside_notified_window(self):
        state = {'raw': 0, 'loaded': 0}
        qualifier = self.ready_qualifier()
        qualifier.reader = lambda: sample(state['raw'])
        qualifier.notify_measurement_window(10 * 10**9, 30 * 10**9, 1000,
                                            mode='rf_c', workload='cached-forwarding')

        class VirtualWake:
            def clear(self):
                pass

            def set(self):
                pass

            def wait(self, seconds):
                state['raw'] += round(seconds * 10**9)

        qualifier._wake = VirtualWake()

        def synthetic_query(provider, address, reader, index):
            before = reader()
            state['raw'] += 1_000_000
            after = reader()
            if index == 1:
                state['loaded'] += 1
                if state['loaded'] == len(clock.PROVIDERS):
                    qualifier._stop.set()
            return {'provider': provider, 'address': address, 'query_index': index,
                'valid': True, 'query_brackets_valid': True, 'before': list(before),
                'after': list(after), 'server_transmit_ns': 1_767_225_600_000_000_000 + state['raw'],
                'advertised_error_bound_ns': 1_000_000}

        with patch('raw_clock.resolve_ipv4', return_value=('192.0.2.1', ['192.0.2.1'])), \
                patch('raw_clock.network_query', side_effect=synthetic_query):
            qualifier._worker()
        loaded = [item for item in qualifier.records if item['acquisition_kind'] == 'measurement_window']
        self.assertEqual(len(loaded), 3)
        self.assertEqual({item['provider'] for item in loaded}, set(clock.PROVIDERS))
        self.assertTrue(all(10 * 10**9 <= item['before'][0] <= item['after'][4] < 30 * 10**9
                            for item in loaded))
        self.assertEqual(len(qualifier.records), 9)  # Initial + measured load + final.
        self.assertEqual(qualifier._window_requests[0]['status'], 'acquired')
        # Twenty seconds of observations cannot relax the unchanged 180-second gate.
        report = clock.qualification_report(qualifier.records, start_raw_ns=10 * 10**9,
            end_raw_ns=12 * 10**9, load_windows=[{'start_raw_ns': 10 * 10**9,
                'end_raw_ns': 30 * 10**9, 'target_pps': 1000}])
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertTrue(all('reference_span_under_180_seconds' in provider['reasons']
                            for provider in report['providers'].values()))


class VirtualCampaignQualificationTests(unittest.TestCase):
    """Run the actual worker over virtual RAW time, never network or wall sleeps.

    These tests prove worker/report integration, not live WSL clock accuracy.
    Both provider acquisition and wake delays are deterministic test doubles;
    no external synchronization state is read or changed.
    """
    WINDOWS = [
        {'start_raw_ns': 10 * 10**9, 'end_raw_ns': 30 * 10**9,
         'target_pps': 100, 'mode': 'forwarding', 'workload': 'classification-heavy'},
        {'start_raw_ns': 190 * 10**9, 'end_raw_ns': 210 * 10**9,
         'target_pps': 1000, 'mode': 'rf_c', 'workload': 'cached-forwarding'},
    ]

    def campaign(self, *, timeout=False, wide_bracket=False, miss_high_window=False):
        state = {'raw': 0}
        qualifier = clock.RateQualification(reader=lambda: sample(state['raw']))

        class FinishedVirtualThread:
            def is_alive(self):
                return False

        # Simulate the ready worker only for queuing before direct dispatch.
        # The actual _worker implementation runs below; this avoids threads.
        qualifier._thread = FinishedVirtualThread()
        qualifier._ready.set()
        for window in self.WINDOWS:
            qualifier.notify_measurement_window(window['start_raw_ns'], window['end_raw_ns'],
                window['target_pps'], mode=window['mode'], workload=window['workload'])

        class VirtualWake:
            def clear(self):
                pass

            def set(self):
                pass

            def wait(self, seconds):
                state['raw'] += round(seconds * 10**9)
                if miss_high_window and 189 * 10**9 <= state['raw'] < 220 * 10**9:
                    state['raw'] = 220 * 10**9
                if state['raw'] >= 240 * 10**9:
                    qualifier._stop.set()

        qualifier._wake = VirtualWake()

        def synthetic_query(provider, address, reader, index):
            before = reader()
            highest_load = 190 * 10**9 <= before[0] < 210 * 10**9
            if timeout and highest_load and provider == clock.PROVIDERS[0]:
                state['raw'] += clock.NETWORK_QUERY_TIMEOUT_SECONDS * 10**9
                return {'provider': provider, 'address': address, 'query_index': index,
                        'before': list(before), 'valid': False,
                        'error': 'TimeoutError: deterministic under-load timeout'}
            state['raw'] += 1_000_000
            after = reader()
            if wide_bracket and highest_load and provider == clock.PROVIDERS[0]:
                after = sample(state['raw'], bracket=clock.MAX_BRACKET_NS + 1)
            bracket_ok = all(0 <= item[4] - item[0] <= clock.MAX_BRACKET_NS
                             for item in (before, after))
            return {'provider': provider, 'address': address, 'query_index': index,
                'valid': True, 'query_brackets_valid': bracket_ok,
                'before': list(before), 'after': list(after),
                'server_transmit_ns': 1_767_225_600_000_000_000 + state['raw'],
                'advertised_error_bound_ns': 100_000}

        with patch('raw_clock.resolve_ipv4', return_value=('192.0.2.1', ['192.0.2.1'])), \
                patch('raw_clock.network_query', side_effect=synthetic_query):
            qualifier._worker()
        return qualifier

    def report(self, qualifier, windows=None):
        return qualifier.report(start_raw_ns=10 * 10**9, end_raw_ns=210 * 10**9,
                                load_windows=self.WINDOWS if windows is None else windows)

    def test_actual_worker_qualifies_high_load_over_full_bounded_campaign(self):
        qualifier = self.campaign()
        report = self.report(qualifier)
        self.assertEqual(report['status'], 'PASS')
        self.assertTrue(report['worker_finished'])
        self.assertIsNone(report['worker_error'])
        self.assertEqual(report['representative_load_target_pps'], 1000)
        self.assertEqual(len(report['measurement_query_schedule']), 2)
        self.assertTrue(all(item['status'] == 'acquired'
                            for item in report['measurement_query_schedule']))
        for item in report['providers'].values():
            self.assertGreaterEqual(item['valid_queries'], 3)
            self.assertEqual(item['representative_load_queries'], 1)
            self.assertGreaterEqual(item['raw_rate']['reference_elapsed_lower_seconds'], 180)
            self.assertGreaterEqual(item['raw_rate']['lower_ppm'], -1000)
            self.assertLessEqual(item['raw_rate']['upper_ppm'], 1000)
            self.assertTrue(item['campaign_covered'])
        for window in self.WINDOWS:
            measured = [item for item in report['queries']
                        if item.get('requested_target_pps') == window['target_pps']]
            self.assertEqual(len(measured), len(clock.PROVIDERS))
            self.assertTrue(all(window['start_raw_ns'] <= item['before'][0]
                                <= item['after'][4] <= window['end_raw_ns']
                                for item in measured))
            self.assertTrue(all(item['query_brackets_valid'] for item in measured))
        # All periodic, initial, measured and final queries are retained.
        self.assertEqual(len(report['queries']), len(qualifier.records))
        self.assertIn('periodic', {item['acquisition_kind'] for item in report['queries']})

    def test_stale_high_load_notification_cannot_be_relabelled_as_qualified(self):
        qualifier = self.campaign(miss_high_window=True)
        report = self.report(qualifier)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(report['measurement_query_schedule'][1]['status'], 'not_acquired')
        self.assertTrue(all(item['representative_load_queries'] == 0
                            for item in report['providers'].values()))
        self.assertTrue(all('no_valid_query_bracketed_inside_a_measured_load_window'
                            in item['reasons'] for item in report['providers'].values()))

    def test_notification_hints_cannot_override_actual_valid_measurement_windows(self):
        qualifier = self.campaign()
        # The caller's actual valid windows do not contain the hinted +2s round.
        actual = [dict(self.WINDOWS[1], start_raw_ns=200 * 10**9,
                       end_raw_ns=210 * 10**9)]
        report = self.report(qualifier, actual)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertTrue(all(item['representative_load_queries'] == 0
                            for item in report['providers'].values()))

    def test_warmup_reference_observations_do_not_qualify_measured_load(self):
        qualifier = self.campaign()
        # A warm-up clock window at this rate is not passed as a measured window.
        # Only the recorded actual measurement window is authoritative.
        measured = [dict(self.WINDOWS[1], start_raw_ns=195 * 10**9,
                         end_raw_ns=210 * 10**9)]
        report = self.report(qualifier, measured)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(report['measured_window_query_counts'][0]['complete_query_count'], 0)

    def test_under_load_wide_native_bracket_prevents_campaign_pass(self):
        qualifier = self.campaign(wide_bracket=True)
        report = self.report(qualifier)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        provider = report['providers'][clock.PROVIDERS[0]]
        self.assertEqual(provider['invalid_bracket_queries'], 1)
        self.assertIn('one_or_more_native_query_brackets_failed_100us_gate', provider['reasons'])
        excluded = [item for item in report['queries']
                    if item.get('valid') and not item.get('query_brackets_valid')]
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]['after'][4] - excluded[0]['after'][0], 100_001)

    def test_under_load_timeout_is_retained_and_prevents_campaign_pass(self):
        qualifier = self.campaign(timeout=True)
        report = self.report(qualifier)
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        provider = report['providers'][clock.PROVIDERS[0]]
        self.assertEqual(provider['failed_queries'], 1)
        self.assertIn('one_or_more_reference_acquisitions_failed', provider['reasons'])
        failures = [item for item in report['queries'] if not item.get('valid')]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]['acquisition_kind'], 'measurement_window')
        self.assertEqual(failures[0]['requested_target_pps'], 1000)


if __name__ == '__main__':
    unittest.main()
