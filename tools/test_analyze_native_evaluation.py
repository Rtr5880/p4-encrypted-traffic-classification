"""In-memory native analysis fixtures: no fitting, traffic or file writes."""
import copy
import hashlib
import io
import struct
import unittest

import analyze_native_evaluation as analysis
import native_prefix as prefix
import prepare_rf_deployment as reference
import replay_real_pcaps as replay
import rf_parity_probes as probes
import test_p4_features as helpers


def forest(model='B'):
    export = probes.synthetic_export()
    if model == 'C':
        export['feature_set'] = 'C'
        export['feature_order'] = list(reference.FEATURES['C'])
        export['domains'] = {name: copy.deepcopy(reference.DOMAINS[name]) for name in export['feature_order']}
    reference.validate_export(export)
    return export


def case_fixture(case_id='case_001', original_index=1):
    packets, decoded = [], []
    for index in range(8):
        event = helpers.event(100 + index, flow=20, stamp=1000 + index * 1000,
                              reverse=index % 2 == 1, size=60 + index, proto=17)
        raw = helpers.wire_packet(event, controlled=False)[14:]
        packet, _ = prefix.decode_raw_packet(raw, event['number'], event['stamp'] * 1000)
        decoded.append(packet)
        packets.append({'original_frame': event['number'], 'raw_ip_hex': raw.hex(),
                        'timestamp_ns': event['stamp'] * 1000,
                        'sha256': hashlib.sha256(raw).hexdigest()})
    b, c = prefix.feature_statistics(decoded)
    capture = {'capture_id': 'folder/fixture.pcap', 'filename': 'fixture.pcap',
               'sha256': '0' * 64, 'initial_class': 'CHAT'}
    instance_id = 'original_parent:instances-v1:idle-tcp:60s:' + str(original_index)
    return {'case_id': case_id, 'slot': replay.slot_for(decoded[0]), 'capture': capture,
            'record': {'record_id': instance_id + ':n8', 'instance_id': instance_id,
                       'instance_index': original_index, 'partition': 'test', 'n': 8, 'label': 'CHAT'},
            'features_B': b, 'features_C': c, 'relative_us': [index * 1000 for index in range(8)],
            'packets': packets, 'ethernet_tag_hex': '020000000002020000000001',
            'original_predictions': {model: analysis._prediction(forest(model), c) for model in 'BC'}}


def frames_for(case, export, times=None):
    times = times or [100000 + value for value in case['relative_us']]
    oracle = replay.ReplayOracle(case['capture'], {4: io.StringIO(), 8: io.StringIO()}, io.StringIO())
    owners, frames = {}, []
    for saved, now in zip(case['packets'], times, strict=True):
        raw = bytes.fromhex(saved['raw_ip_hex'])
        packet, tcp = prefix.decode_raw_packet(raw, saved['original_frame'], now * 1000)
        expected, current, _, _, _ = replay.expectation(oracle, packet, tcp, owners, origin_us=0)
        expected.update(magic=0x45544352, version=1, reserved=0, observed_us=now,
                        packet_id=struct.unpack_from('!H', raw, 4)[0])
        report = b''.join(expected[name].to_bytes(length, 'big') for name, length in helpers.FIELDS)
        prediction = analysis._prediction(export, current['features_C']) if current else None
        rf = struct.pack('!IBBBB10H6I', analysis.integration.RF_MAGIC, 1, int(current is not None),
                         'BC'.index(export['feature_set']), prediction['prediction'] if prediction else 255,
                         *(prediction['leaves'] if prediction else [0] * 10),
                         *(prediction['scores'] if prediction else [0] * 6))
        frames.append(bytes.fromhex(case['ethernet_tag_hex']) + b'\x88\xb6' + report + rf + raw)
    oracle.finish()
    return frames


def outcome(case, model, prediction=None, valid=True, status=None):
    prediction = analysis.CLASSES.index(case['record']['label']) if prediction is None else prediction
    return {'model': model, 'case_id': case['case_id'], 'record_id': case['record']['record_id'],
            'label': case['record']['label'], 'attempted': True,
            'transport_passed': valid, 'parity_passed': valid, 'classified': valid,
            'prediction': prediction if valid else None,
            'class': analysis.CLASSES[prediction] if valid else None,
            'status': status or ('verified_classified' if valid else 'failed'),
            'failure_kind': None if valid else 'transport_failure', 'error': None}


class CompareTests(unittest.TestCase):
    def test_both_models_full_intermediate_parity(self):
        case = case_fixture()
        for model in 'BC':
            with self.subTest(model=model):
                export = forest(model)
                result = analysis.compare_case(case, export, frames_for(case, export))
                self.assertTrue(result['parity_passed'], result)
                self.assertTrue(result['transport_passed'])
                self.assertTrue(result['classified'])
                self.assertEqual(result['class'], 'CHAT')
                self.assertEqual(result['features_C'], case['features_C'])
                self.assertEqual(len(result['packet_checks']), 8)
                self.assertEqual(result['oracle_audit']['instances'], 1)
                self.assertEqual(result['timing']['native_minus_original_iats_us'], [0] * 7)
                self.assertTrue(result['clock_quality']['clean'])
                self.assertEqual(result['clock_quality']['raw_backward_steps'], 0)
                self.assertEqual(result['timing']['effective_native_iats_us'], [1000] * 7)

    def test_original_later_id_is_retained_but_local_index_is_one(self):
        case = case_fixture(original_index=17)
        result = analysis.compare_case(case, forest(), frames_for(case, forest()))
        self.assertTrue(result['parity_passed'], result)
        self.assertEqual(result['record_id'], case['record']['record_id'])
        self.assertNotEqual(result['decision']['record_id'], result['record_id'])
        self.assertEqual(result['decision']['original_record_id'], result['record_id'])
        self.assertTrue(result['decision']['record_id'].endswith(':1:n8'))

    def test_native_idle_split_is_verified_unclassified_not_fake_success(self):
        case = case_fixture()
        times = [100000, 101000, 102000, 103000, 60103000, 60104000, 60105000, 60106000]
        result = analysis.compare_case(case, forest(), frames_for(case, forest(), times))
        self.assertTrue(result['parity_passed'], result)
        self.assertFalse(result['classified'])
        self.assertIsNone(result['prediction'])
        self.assertEqual(result['status'], 'verified_unclassified')
        self.assertEqual(result['failure_kind'], 'native_boundaries_prevented_n8')
        self.assertEqual(result['oracle_audit']['instances'], 2)
        self.assertEqual(result['oracle_decisions'], 0)

    def test_timing_changes_are_diagnostic_not_parity_failures(self):
        case = case_fixture()
        times = [100000 + value + index * 50 for index, value in enumerate(case['relative_us'])]
        result = analysis.compare_case(case, forest(), frames_for(case, forest(), times))
        self.assertTrue(result['parity_passed'], result)
        self.assertEqual(result['timing']['iat_deviation_sum_us'], 350)
        self.assertEqual(result['timing']['max_absolute_iat_deviation_us'], 50)
        self.assertEqual(result['timing']['native_prefix_duration_us'], 7350)

    def test_equal_native_timestamps_are_allowed_with_clock_progress(self):
        case = case_fixture()
        times = [100000, 100000, 101000, 102000, 103000, 104000, 105000, 106000]
        result = analysis.compare_case(case, forest(), frames_for(case, forest(), times))
        self.assertTrue(result['parity_passed'], result)
        self.assertEqual(result['features_C']['iat_min'], 0)
        self.assertTrue(result['clock_quality']['clean'])
        self.assertEqual(result['clock_quality']['raw_equal_steps'], 1)

    def test_backward_raw_time_reports_events_and_checks_full_clamped_parity(self):
        case = case_fixture()
        times = [100000, 101000, 99000, 100500, 104000, 105000, 106000, 107000]
        effective = [100000, 101000, 101000, 101000, 104000, 105000, 106000, 107000]
        for model in 'BC':
            with self.subTest(model=model):
                export = forest(model)
                result = analysis.compare_case(case, export, frames_for(case, export, times))
                self.assertTrue(result['transport_passed'], result)
                self.assertTrue(result['parity_passed'], result)
                self.assertTrue(result['classified'])
                self.assertEqual(len(result['packet_checks']), 8)
                self.assertEqual(result['features_C']['iat_min'], 0)
                quality = result['clock_quality']
                self.assertFalse(quality['clean'])
                self.assertTrue(quality['valid_timestamps'])
                self.assertTrue(quality['clock_progress'])
                self.assertEqual(quality['raw_backward_steps'], 1)
                self.assertEqual(quality['max_backward_step_us'], 2000)
                self.assertEqual(quality['timestamp_adjustments'], 2)
                self.assertEqual(quality['max_clamp_adjustment_us'], 2000)
                self.assertEqual(quality['events'], [{'position': 3,
                    'previous_observed_us': 101000, 'observed_us': 99000,
                    'raw_gap_us': -2000, 'backward_step_us': 2000,
                    'effective_us': 101000, 'clamp_adjustment_us': 2000}])
                timing = result['timing']
                self.assertEqual(timing['observed_ingress_us'], times)
                self.assertEqual(timing['effective_ingress_us'], effective)
                self.assertEqual(timing['native_iats_us'], [1000, -2000, 1500, 3500, 1000, 1000, 1000])
                self.assertEqual(timing['raw_native_iats_us'], timing['native_iats_us'])
                self.assertEqual(timing['effective_native_iats_us'], [1000, 0, 0, 3000, 1000, 1000, 1000])
                self.assertEqual(timing['clamp_adjustments_us'], [0, 0, 2000, 500, 0, 0, 0, 0])
                self.assertEqual([row['expected_fields']['effective_us'] for row in result['packet_checks']], effective)

    def test_multiple_backward_steps_are_counted_without_counting_recovery_as_regression(self):
        quality = analysis.clock_quality([100000, 102000, 101999, 101998, 102001, 103000, 104000, 105000])
        self.assertFalse(quality['clean'])
        self.assertEqual(quality['raw_backward_steps'], 2)
        self.assertEqual([row['position'] for row in quality['events']], [3, 4])
        self.assertEqual(quality['max_backward_step_us'], 1)
        self.assertEqual(quality['max_clamp_adjustment_us'], 2)

    def test_backward_clock_never_bypasses_state_or_rf_comparisons(self):
        case, export = case_fixture(), forest()
        times = [100000, 101000, 102000, 101999, 104000, 105000, 106000, 107000]
        valid = frames_for(case, export, times)
        feature_offset = 14 + sum(length for name, length in helpers.FIELDS[:
                                  [name for name, _ in helpers.FIELDS].index('effective_us')])
        for offset, reason in [(feature_offset, 'state_mismatch'), (85 + 8, 'rf_mismatch'),
                               (85 + 28, 'rf_mismatch'), (85 + 7, 'rf_mismatch')]:
            with self.subTest(offset=offset):
                frames = list(valid)
                frame = bytearray(frames[-1]); frame[offset] ^= 1; frames[-1] = bytes(frame)
                result = analysis.compare_case(case, export, frames)
                self.assertFalse(result['parity_passed'])
                self.assertFalse(result['classified'])
                self.assertFalse(result['clock_quality']['clean'])
                self.assertEqual(result['failure_kind'], reason)

    def test_zero_and_constant_native_clocks_remain_failures(self):
        case, export = case_fixture(), forest()
        for times in ([0] * 8, [100000] * 8, [0, 1000, 2000, 3000, 4000, 5000, 6000, 7000]):
            with self.subTest(times=times):
                result = analysis.compare_case(case, export, frames_for(case, export, times))
                self.assertFalse(result['parity_passed'])
                self.assertFalse(result['classified'])
                self.assertFalse(result['clock_quality']['clean'])
                self.assertEqual(result['failure_kind'], 'clock_validation')
                self.assertTrue(result['error'])

    def test_public_clock_quality_rejects_malformed_timestamp_ranges(self):
        for times in ([], [0, 1], [-1, 1], [1, 2**48], [1, 1.5], [True, 2]):
            with self.subTest(times=times):
                quality = analysis.clock_quality(times)
                self.assertFalse(quality['valid_timestamps'])
                self.assertFalse(quality['clean'])
                self.assertTrue(quality['error'])

    def test_changed_native_prediction_is_valid_inference_not_parity_failure(self):
        case, export = case_fixture(), forest()
        for tree in export['trees']:
            tree['nodes'][0].update(feature_index=3, threshold_float64=1000.0, cut=1000)
        reference.validate_export(export)
        case['original_predictions']['B'] = analysis._prediction(export, case['features_C'])
        times = [100000 + index * 1100 for index in range(8)]
        result = analysis.compare_case(case, export, frames_for(case, export, times))
        self.assertTrue(result['parity_passed'], result)
        self.assertTrue(result['classified'])
        self.assertTrue(result['prediction_changed_with_native_timing'])
        self.assertEqual(result['capture_time_class'], 'CHAT')
        self.assertEqual(result['class'], 'MAIL')
        self.assertEqual(result['prediction_change_reason'],
                         'native_observed_timing_changes_with_same_frozen_model')

    def test_wrong_features_leaf_score_prediction_fail_separately(self):
        case, export = case_fixture(), forest()
        valid = frames_for(case, export)
        # Byte positions are derived from the actual feature schema.
        feature_offset = 14 + sum(length for name, length in helpers.FIELDS[:
                                  [name for name, _ in helpers.FIELDS].index('size_sum')])
        mutations = [(feature_offset, 'state_mismatch'), (85 + 8, 'rf_mismatch'),
                     (85 + 28, 'rf_mismatch'), (85 + 7, 'rf_mismatch')]
        for offset, reason in mutations:
            with self.subTest(offset=offset):
                frames = list(valid)
                frame = bytearray(frames[-1]); frame[offset] ^= 1; frames[-1] = bytes(frame)
                result = analysis.compare_case(case, export, frames)
                self.assertFalse(result['parity_passed'])
                self.assertFalse(result['classified'])
                self.assertTrue(result['transport_passed'])
                self.assertEqual(result['failure_kind'], reason)
                self.assertTrue(result['error'])

    def test_raw_bytes_tag_order_missing_clock_and_slot_errors_fail(self):
        case, export = case_fixture(), forest()
        valid = frames_for(case, export)
        mutated = bytearray(valid[-1]); mutated[-1] ^= 1
        wrong_tag = bytearray(valid[-1]); wrong_tag[0] ^= 1
        constant = frames_for(case, export, [100000] * 8)
        inputs = [valid[:-1], valid[:-1] + [bytes(mutated)], valid[:-1] + [bytes(wrong_tag)],
                  [valid[1], valid[0]] + valid[2:], constant]
        for frames in inputs:
            with self.subTest(length=len(frames)):
                result = analysis.compare_case(case, export, frames)
                self.assertFalse(result['parity_passed'])
                self.assertTrue(result['error'])
        wrong = copy.deepcopy(case); wrong['slot'] ^= 1
        result = analysis.compare_case(wrong, export, valid)
        self.assertFalse(result['parity_passed'])
        self.assertEqual(result['failure_kind'], 'state_oracle')


class SummaryTests(unittest.TestCase):
    def test_backward_clock_stays_in_diagnostic_metrics_but_summary_is_nonclean(self):
        case = case_fixture()
        times = [100000, 101000, 99000, 100500, 104000, 105000, 106000, 107000]
        rows = []
        for model in 'BC':
            export = forest(model)
            rows.append(analysis.compare_case(case, export, frames_for(case, export, times)))
        result = analysis.summarize([case], rows)
        for model in 'BC':
            metric = result['models'][model]
            self.assertEqual(metric['verified_classified_records'], 1)
            self.assertEqual(metric['native_conditional_metrics']['records'], 1)
            self.assertFalse(metric['clock_quality']['clean'])
            self.assertEqual(metric['clock_quality']['raw_backward_steps'], 1)
        self.assertFalse(result['clock_quality']['clean'])
        self.assertEqual(result['clock_quality']['reported_records'], 2)
        self.assertEqual(result['clock_quality']['raw_backward_steps'], 2)
        self.assertEqual(result['clock_quality']['timestamp_adjustments'], 4)
        self.assertEqual(len(result['clock_quality']['events']), 2)
        self.assertEqual(result['clock_quality']['events'][0]['case_id'], case['case_id'])
        self.assertEqual(result['clock_quality']['events'][0]['record_id'], case['record']['record_id'])

    def test_summary_cannot_certify_unknown_or_missing_clock_evidence(self):
        case = case_fixture()
        result = analysis.summarize([case], [outcome(case, model) for model in 'BC'])
        self.assertFalse(result['clock_quality']['clean'])
        self.assertEqual(result['clock_quality']['missing_records'], 2)

    def test_clean_clock_summary_requires_all_intended_outcomes(self):
        case = case_fixture()
        rows = []
        for model in 'BC':
            export = forest(model)
            rows.append(analysis.compare_case(case, export, frames_for(case, export)))
        result = analysis.summarize([case], rows)
        self.assertTrue(result['clock_quality']['clean'])
        self.assertEqual(result['clock_quality']['clean_records'], 2)
        self.assertEqual(result['clock_quality']['raw_backward_steps'], 0)

    def test_all_failed_has_no_accuracy_and_zero_coverage(self):
        case = case_fixture()
        result = analysis.summarize([case], [outcome(case, model, valid=False) for model in 'BC'])
        for model in 'BC':
            metric = result['models'][model]
            self.assertEqual(metric['classification_coverage'], 0)
            self.assertEqual(metric['correct_decision_rate_over_expected_population'], 0)
            self.assertIsNone(metric['native_conditional_metrics']['accuracy'])
            self.assertIsNone(metric['native_conditional_metrics']['macro_f1'])
        self.assertIsNone(result['common_paired_population']['C_minus_B_accuracy'])

    def test_fixed_six_classes_missing_classes_do_not_disappear(self):
        case = case_fixture()
        result = analysis.summarize([case], [outcome(case, model) for model in 'BC'])
        metric = result['models']['B']['native_conditional_metrics']
        self.assertEqual(metric['accuracy'], 1)
        self.assertAlmostEqual(metric['macro_f1'], 1 / 6)
        self.assertEqual(metric['per_class']['VOIP']['support'], 0)
        self.assertEqual(metric['per_class']['VOIP']['f1'], 0)
        self.assertEqual(len(metric['confusion_matrix']), 6)

    def test_common_pair_and_correct_decision_rate_use_different_denominators(self):
        first, second = case_fixture('a'), case_fixture('b', original_index=2)
        second['record']['label'] = 'VOIP'
        for model in 'BC':
            second['original_predictions'][model]['class'] = 'VOIP'
            second['original_predictions'][model]['prediction'] = 5
        rows = [outcome(first, 'B'), outcome(first, 'C', prediction=1),
                outcome(second, 'B', valid=False), outcome(second, 'C')]
        result = analysis.summarize([first, second], rows)
        b, c = result['models']['B'], result['models']['C']
        self.assertEqual(b['native_conditional_metrics']['accuracy'], 1)
        self.assertEqual(b['classification_coverage'], .5)
        self.assertEqual(b['correct_decision_rate_over_expected_population'], .5)
        self.assertEqual(c['native_conditional_metrics']['accuracy'], .5)
        paired = result['common_paired_population']
        self.assertEqual(paired['case_ids'], ['a'])
        self.assertEqual(paired['native_metrics']['C']['accuracy'], 0)
        self.assertEqual(paired['paired_correctness']['B_correct_C_wrong'], 1)
        self.assertEqual(b['excluded_support_by_class']['VOIP'], 1)
        self.assertEqual(c['native_vs_capture']['prediction_changes'], 1)
        self.assertEqual(c['native_vs_capture']['paired_correctness']['capture_correct_native_wrong'], 1)
        self.assertEqual(c['native_vs_capture']['prediction_agreement_rate'], .5)

    def test_correct_native_abstention_is_not_in_accuracy(self):
        case = case_fixture()
        row = outcome(case, 'B', valid=False)
        row.update(transport_passed=True, parity_passed=True, status='verified_unclassified',
                   failure_kind='native_boundaries_prevented_n8')
        result = analysis.summarize([case], [row, outcome(case, 'C')])
        self.assertEqual(result['models']['B']['verified_parity_records'], 1)
        self.assertEqual(result['models']['B']['verified_unclassified_records'], 1)
        self.assertIsNone(result['models']['B']['native_conditional_metrics']['accuracy'])

    def test_counter_verification_failure_excludes_otherwise_valid_prediction(self):
        case = case_fixture()
        row = outcome(case, 'B'); row.update(verification_passed=False, failure_kind='batch_counter_mismatch')
        result = analysis.summarize([case], [row, outcome(case, 'C')])
        self.assertEqual(result['models']['B']['verified_parity_records'], 1)
        self.assertEqual(result['models']['B']['verification_failed_records'], 1)
        self.assertEqual(result['models']['B']['verified_classified_records'], 0)
        self.assertEqual(result['common_paired_population']['records'], 0)

    def test_missing_duplicate_unknown_and_unverified_outcomes_rejected(self):
        case = case_fixture()
        valid = [outcome(case, model) for model in 'BC']
        cases = [valid[:1], valid + [valid[0]], valid + [dict(valid[0], case_id='unknown')],
                 [dict(valid[0], parity_passed=False), valid[1]],
                 [dict(valid[0], prediction=99), valid[1]]]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                analysis.summarize([case], rows)
        with self.assertRaises(ValueError):
            analysis.summarize([case, case], valid)


if __name__ == '__main__':
    unittest.main()
