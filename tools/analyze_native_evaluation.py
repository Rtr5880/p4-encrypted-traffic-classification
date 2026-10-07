#!/usr/bin/env python3
"""Pure analysis for frozen held-out prefixes replayed with native BMv2 time.

No traffic, fitting, file writes, label inference or test-population selection.
An original record ID is provenance; the isolated switch/oracle starts at local
instance 1 even when the original capture record had a later instance index.
"""
from collections import Counter
import io
import struct

from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support)

import integrate_rf as integration
import native_prefix as prefix
import prepare_rf_deployment as reference
import replay_real_pcaps as replay
import test_p4_features as helpers


CLASSES = tuple(reference.baseline.CLASSES)
BODY_OFFSET = 137
require = helpers.require


def _prediction(export, features):
    row = [features[name] for name in export['feature_order']]
    leaves, _, scores = reference.predict_export(export, [row])
    prediction = int(scores[0].argmax())
    return {'prediction': prediction, 'class': export['classes'][prediction],
            'leaves': leaves[0].tolist(), 'scores': scores[0].tolist()}


def _effective_times(times):
    """Existing extractor/P4 policy: each parent's effective time is running max."""
    effective, maximum = [], 0
    for now in times:
        maximum = max(maximum, now)
        effective.append(maximum)
    return effective


def clock_quality(times):
    """Keep raw clock defects independent of state/forest parity validation."""
    valid = bool(times) and all(type(now) is int and 0 < now < 2**48 for now in times)
    if not valid:
        return {'clean': False, 'valid_timestamps': False, 'clock_progress': False,
                'raw_backward_steps': 0, 'events': [], 'raw_equal_steps': 0,
                'max_backward_step_us': 0, 'clamped_packets': 0,
                'timestamp_adjustments': 0,
                'max_clamp_adjustment_us': 0,
                'error': 'Native ingress timestamps must be positive 48-bit integers'}
    effective = _effective_times(times)
    adjustments = [fixed - raw for fixed, raw in zip(effective, times, strict=True)]
    events = [{'position': position, 'previous_observed_us': previous,
               'observed_us': now, 'raw_gap_us': now - previous,
               'backward_step_us': previous - now,
               'effective_us': effective[position - 1],
               'clamp_adjustment_us': adjustments[position - 1]}
              for position, (previous, now) in enumerate(zip(times, times[1:]), 2)
              if now < previous]
    progress = max(times) > min(times)
    return {'clean': progress and not events, 'valid_timestamps': True,
            'clock_progress': progress, 'raw_backward_steps': len(events),
            'events': events,
            'raw_equal_steps': sum(a == b for a, b in zip(times, times[1:])),
            'max_backward_step_us': max((row['backward_step_us'] for row in events), default=0),
            'clamped_packets': sum(value > 0 for value in adjustments),
            'timestamp_adjustments': sum(value > 0 for value in adjustments),
            'max_clamp_adjustment_us': max(adjustments),
            'error': None if progress else 'Native ingress clock is constant'}


def _timing(case, times):
    original = list(case['relative_us'])
    require(len(original) == len(times) == 8 and original[0] == 0 and
            original == sorted(original), 'Invalid original eight-packet schedule')
    original_gaps = [b - a for a, b in zip(original, original[1:])]
    native_gaps = [b - a for a, b in zip(times, times[1:])]
    effective = _effective_times(times)
    effective_gaps = [b - a for a, b in zip(effective, effective[1:])]
    effective_deviations = [a - b for a, b in zip(effective_gaps, original_gaps)]
    deviations = [a - b for a, b in zip(native_gaps, original_gaps)]
    absolute = [abs(value) for value in deviations]
    return {'original_iats_us': original_gaps, 'native_iats_us': native_gaps,
            'native_minus_original_iats_us': deviations,
            'absolute_iat_deviations_us': absolute,
            'iat_deviation_sum_us': sum(deviations),
            'absolute_iat_deviation_sum_us': sum(absolute),
            'mean_absolute_iat_deviation_us': sum(absolute) / 7,
            'max_absolute_iat_deviation_us': max(absolute),
            'original_prefix_duration_us': original[-1],
            'native_prefix_duration_us': times[-1] - times[0],
            'observed_ingress_us': times,
            'raw_native_iats_us': native_gaps,
            'effective_ingress_us': effective,
            'effective_native_iats_us': effective_gaps,
            'effective_minus_original_iats_us': effective_deviations,
            'effective_absolute_iat_deviations_us': [abs(value) for value in effective_deviations],
            'effective_prefix_duration_us': effective[-1] - effective[0],
            'clamp_adjustments_us': [fixed - raw for fixed, raw in zip(effective, times, strict=True)],
            'native_iats_semantics': 'Raw observed consecutive gaps; negative gaps are preserved',
            'effective_iats_semantics': 'Existing per-parent running-max clamp used by P4 and oracle',
            'meaning': 'Ingress inter-arrival/observation timing, not forwarding or inference latency'}


def compare_case(case, export, frames):
    """Return success/failure evidence, deriving state from raw IP + observed time.

    Exactly eight reports are required for verified parity. A legitimate native
    timeout can split these packets and yield zero N8 decisions: that is verified
    but unclassified, not a classifier mismatch or a fabricated prediction.
    The receiver must first associate frames with this case's Ethernet tag.
    ``ethernet_tag_hex`` optionally verifies that independently supplied tag.
    Raw clock regressions are reported separately. The oracle receives raw time
    and applies its existing running-max clamp; regressions cannot bypass any
    packet, intermediate-state, leaf, score or prediction parity comparison.
    """
    model = export.get('feature_set')
    record = case.get('record', {})
    outcome = {'model': model, 'case_id': case.get('case_id'),
               'record_id': record.get('record_id'), 'label': record.get('label', case.get('label')),
               'attempted': True, 'transport_passed': False, 'parity_passed': False,
               'classified': False, 'prediction': None, 'class': None,
               'status': 'failed', 'error': None, 'failure_kind': None,
               'packet_checks': [], 'timing': None, 'clock_quality': None}
    stage = 'input_validation'
    try:
        reference.validate_export(export)
        require(model in ('B', 'C') and tuple(export['classes']) == CLASSES,
                'Unsupported model or frozen class order')
        require(outcome['label'] in CLASSES and record.get('partition') == 'test'
                and record.get('n') == 8, 'Case is not a labelled frozen held-out N8 record')
        require(isinstance(outcome['case_id'], str) and outcome['case_id'] and
                isinstance(outcome['record_id'], str) and outcome['record_id'], 'Missing immutable case/record ID')
        require(len(case['packets']) == len(frames) == 8, 'Missing/extra native output reports')
        require(all(type(frame) is bytes for frame in frames), 'Output frames must be bytes')
        require(all(frame[:12] == frames[0][:12] for frame in frames), 'Case Ethernet tag changed')
        if 'ethernet_tag_hex' in case:
            tag = bytes.fromhex(case['ethernet_tag_hex'])
            require(len(tag) == 12 and all(frame[:12] == tag for frame in frames), 'Wrong expected Ethernet tag')
        stage = 'frame_decode'
        reports = [helpers.decode_report(frame) for frame in frames]
        rf_reports = [integration.decode_rf(frame, 85) for frame in frames]
        times = [row['observed_us'] for row in reports]
        stage = 'clock_validation'
        outcome['clock_quality'] = clock_quality(times)
        require(outcome['clock_quality']['valid_timestamps'] and
                outcome['clock_quality']['clock_progress'], outcome['clock_quality']['error'])
        outcome['timing'] = _timing(case, times)
        stage = 'packet_bytes'
        for position, (saved, frame) in enumerate(zip(case['packets'], frames, strict=True), 1):
            require(frame[BODY_OFFSET:] == bytes.fromhex(saved['raw_ip_hex']),
                    f'Packet {position}: original IP bytes changed/order changed')
        outcome['transport_passed'] = True
        oracle = replay.ReplayOracle(case['capture'], {4: io.StringIO(), 8: io.StringIO()},
                                     io.StringIO(), idle_seconds=60, boundary_policy='idle-tcp')
        owners, decisions = {}, []
        for position, (saved, frame, report, rf) in enumerate(
                zip(case['packets'], frames, reports, rf_reports, strict=True), 1):
            stage = 'packet_bytes'
            raw = bytes.fromhex(saved['raw_ip_hex'])
            require(frame[BODY_OFFSET:] == raw, f'Packet {position}: original IP bytes changed/order changed')
            stage = 'state_oracle'
            packet, tcp = prefix.decode_raw_packet(raw, saved['original_frame'], report['observed_us'] * 1000)
            require(replay.slot_for(packet) == case['slot'], f'Packet {position}: prepared CRC slot disagrees')
            expected, current, _, local_id, collision = replay.expectation(
                oracle, packet, tcp, owners, origin_us=0)
            require(not collision, 'Unexpected within-case collision')
            expected['packet_id'] = struct.unpack_from('!H', raw, 4)[0]
            stage = 'state_mismatch'
            for name, value in expected.items():
                require(report[name] == value,
                        f'Packet {position}: {name} P4={report[name]} Python={value}')
            require(report['reserved'] == 0, f'Packet {position}: unexpected report reserved field')
            expected_rf = None
            if current is not None:
                expected_rf = _prediction(export, current['features_C'])
                decisions.append(dict(current, original_record_id=outcome['record_id'],
                                      position=position, expected_rf=expected_rf))
            stage = 'rf_mismatch'
            integration.check_rf(rf, model, expected_rf)
            outcome['packet_checks'].append({'position': position, 'original_frame': packet.frame,
                'feature_report': report, 'expected_fields': expected, 'rf_report': rf,
                'local_instance_id': local_id})
        audit = oracle.finish()
        require(len(decisions) <= 1 and audit['windows']['8']['records'] == len(decisions),
                'Unexpected isolated-prefix decision accounting')
        outcome.update(transport_passed=True, parity_passed=True, packets_checked=8,
                       unchanged_ip_packets=8, oracle_audit=audit, oracle_decisions=len(decisions),
                       feature_mismatches=0, instance_mismatches=0, leaf_mismatches=0,
                       score_mismatches=0, class_mismatches=0, error=None)
        original = case['original_predictions'][model]
        outcome['capture_time_prediction'] = original['prediction']
        outcome['capture_time_class'] = original['class']
        if decisions:
            decision = decisions[0]
            require(decision['position'] == 8, 'Classification did not occur at the eighth prefix packet')
            prediction = decision['expected_rf']
            outcome.update(classified=True, prediction=prediction['prediction'],
                           status='verified_classified', failure_kind=None, decision=decision,
                           features_B=decision['features_B'], features_C=decision['features_C'])
            outcome['class'] = prediction['class']
            changed = prediction['prediction'] != original['prediction']
            outcome['prediction_changed_with_native_timing'] = changed
            outcome['prediction_change_reason'] = ('native_observed_timing_changes_with_same_frozen_model'
                                                    if changed else 'prediction_unchanged')
            outcome['original_vs_native_leaf_changes'] = sum(a != b for a, b in
                zip(original['leaves'], prediction['leaves'], strict=True))
            outcome['original_vs_native_score_changes'] = sum(a != b for a, b in
                zip(original['scores'], prediction['scores'], strict=True))
        else:
            outcome.update(status='verified_unclassified', failure_kind='native_boundaries_prevented_n8',
                           prediction_changed_with_native_timing=None,
                           prediction_change_reason='no_native_n8_prediction_to_compare', decision=None)
        return outcome
    except (ValueError, KeyError, TypeError, IndexError, struct.error, AssertionError) as error:
        outcome.update(parity_passed=False, classified=False,
                       prediction=None, status='failed', error=str(error), failure_kind=stage)
        outcome['class'] = None
        return outcome


def _metrics(labels, predictions):
    """Fixed six-class metrics; an empty population has no score, never 100%."""
    require(len(labels) == len(predictions), 'Metric labels/predictions are not paired')
    require(all(value in CLASSES for value in labels + predictions), 'Unknown metric class')
    if not labels:
        return {'records': 0, 'accuracy': None, 'macro_f1': None, 'weighted_f1': None,
                'macro_precision': None, 'macro_recall': None, 'class_order': list(CLASSES),
                'confusion_matrix': [[0] * 6 for _ in range(6)],
                'per_class': {name: {'precision': None, 'recall': None, 'f1': None, 'support': 0}
                              for name in CLASSES}}
    precision, recall, f1, supports = precision_recall_fscore_support(
        labels, predictions, labels=list(CLASSES), zero_division=0)
    return {'records': len(labels), 'accuracy': float(accuracy_score(labels, predictions)),
            'macro_f1': float(f1.mean()), 'weighted_f1': float((f1 * supports).sum() / len(labels)),
            'macro_precision': float(precision.mean()), 'macro_recall': float(recall.mean()),
            'class_order': list(CLASSES),
            'confusion_matrix': confusion_matrix(labels, predictions, labels=list(CLASSES)).tolist(),
            'per_class': {name: {'precision': float(precision[i]), 'recall': float(recall[i]),
                                  'f1': float(f1[i]), 'support': int(supports[i])}
                          for i, name in enumerate(CLASSES)}}


def _summarize_clock_quality(rows):
    """Unknown/missing clocks never certify a clean run; parity stays separate."""
    rows = list(rows)
    reported = [row for row in rows if isinstance(row.get('clock_quality'), dict)]
    quality = [row['clock_quality'] for row in reported]
    return {'clean': len(reported) == len(rows) and bool(rows) and
                     all(value.get('clean') is True for value in quality),
            'expected_records': len(rows), 'reported_records': len(reported),
            'missing_records': len(rows) - len(reported),
            'clean_records': sum(value.get('clean') is True for value in quality),
            'nonclean_records': sum(value.get('clean') is not True for value in quality),
            'invalid_timestamp_records': sum(value.get('valid_timestamps') is not True for value in quality),
            'nonprogressing_records': sum(value.get('valid_timestamps') is True and
                                          value.get('clock_progress') is not True for value in quality),
            'raw_backward_steps': sum(value.get('raw_backward_steps', 0) for value in quality),
            'max_backward_step_us': max((value.get('max_backward_step_us', 0) for value in quality), default=0),
            'timestamp_adjustments': sum(value.get('timestamp_adjustments', 0) for value in quality),
            'max_clamp_adjustment_us': max((value.get('max_clamp_adjustment_us', 0) for value in quality), default=0),
            'events': [dict(event, model=row.get('model'), case_id=row.get('case_id'),
                            record_id=row.get('record_id')) for row in reported
                       for event in row['clock_quality'].get('events', [])],
            'meaning': 'Raw ingress clock quality; independent of clamped feature/forest parity'}


def summarize(population, outcomes):
    """Account for every intended B/C case, including failed/unclassified ones.

    The caller freezes/asserts the intended 398 records; accepting small fixture
    populations here makes denominator tests possible without fitting any model.
    Scores are proportions, not percentages. No failed case is silently dropped
    from coverage, although conditional classification metrics use valid cases.
    """
    require(population and len(CLASSES) == 6, 'Expected a nonempty frozen six-class population')
    cases = {case['case_id']: case for case in population}
    require(len(cases) == len(population), 'Duplicate intended case IDs')
    require(len({case['record']['record_id'] for case in population}) == len(population),
            'Duplicate intended original record IDs')
    for case in population:
        require(case['record']['partition'] == 'test' and case['record']['n'] == 8 and
                case['record']['label'] in CLASSES, 'Population contains non-held-out/unknown records')
    indexed = {'B': {}, 'C': {}}
    for outcome in outcomes:
        model, identity = outcome['model'], outcome['case_id']
        require(model in indexed and identity in cases, 'Unexpected model/case outcome')
        require(identity not in indexed[model], 'Duplicate case/model outcome')
        case = cases[identity]
        require(outcome['label'] == case['record']['label'], 'Outcome label differs from frozen population')
        if 'record_id' in outcome:
            require(outcome['record_id'] == case['record']['record_id'], 'Outcome original record ID changed')
        if outcome.get('classified'):
            require(outcome.get('transport_passed') is True and outcome.get('parity_passed') is True,
                    'Unverified classification must not enter metrics')
            prediction = outcome.get('prediction')
            require(type(prediction) is int and 0 <= prediction < 6 and
                    outcome.get('class') == CLASSES[prediction], 'Invalid class prediction')
        indexed[model][identity] = outcome
    require(all(set(rows) == set(cases) for rows in indexed.values()),
            'Every intended case needs exactly one outcome for both models, including failures')
    ids = sorted(cases)
    total = len(ids)
    supports = {name: sum(case['record']['label'] == name for case in population) for name in CLASSES}

    def eligible(model):
        return [identity for identity in ids if indexed[model][identity].get('transport_passed') is True
                and indexed[model][identity].get('parity_passed') is True
                and indexed[model][identity].get('verification_passed', True) is True
                and indexed[model][identity].get('classified') is True]

    def metrics_for(model, selected, capture=False):
        labels = [cases[identity]['record']['label'] for identity in selected]
        predictions = [(cases[identity]['original_predictions'][model]['class'] if capture else
                        indexed[model][identity]['class']) for identity in selected]
        return _metrics(labels, predictions)

    def transitions(model, selected):
        changes, correct = [], Counter()
        for identity in selected:
            truth = cases[identity]['record']['label']
            old = cases[identity]['original_predictions'][model]['class']
            new = indexed[model][identity]['class']
            correct['both_correct' if old == truth and new == truth else
                    'capture_wrong_native_correct' if old != truth and new == truth else
                    'capture_correct_native_wrong' if old == truth and new != truth else 'both_wrong'] += 1
            if old != new:
                changes.append({'case_id': identity, 'record_id': cases[identity]['record']['record_id'],
                                'label': truth, 'capture_prediction': old, 'native_prediction': new})
        return {'matched_records': len(selected), 'prediction_changes': len(changes),
                'prediction_change_rate': len(changes) / len(selected) if selected else None,
                'prediction_agreement_rate': 1 - len(changes) / len(selected) if selected else None,
                'capture_to_native_prediction_matrix': confusion_matrix(
                    [cases[identity]['original_predictions'][model]['class'] for identity in selected],
                    [indexed[model][identity]['class'] for identity in selected],
                    labels=list(CLASSES)).tolist() if selected else [[0] * 6 for _ in range(6)],
                'paired_correctness': {name: correct[name] for name in
                    ('both_correct', 'capture_wrong_native_correct', 'capture_correct_native_wrong', 'both_wrong')},
                'changed_records': changes}

    per_model, admitted = {}, {}
    for model in 'BC':
        selected = admitted[model] = eligible(model)
        metric = metrics_for(model, selected)
        excluded = [identity for identity in ids if identity not in selected]
        correct = sum(indexed[model][identity]['class'] == cases[identity]['record']['label'] for identity in selected)
        counts = Counter(row.get('status', 'unspecified') for row in indexed[model].values())
        per_model[model] = {'expected_records': total, 'attempted_records': sum(
            row.get('attempted', True) is True for row in indexed[model].values()),
            'transport_complete_records': sum(row.get('transport_passed') is True for row in indexed[model].values()),
            'verified_parity_records': sum(row.get('parity_passed') is True for row in indexed[model].values()),
            'verification_failed_records': sum(row.get('verification_passed', True) is not True
                                               for row in indexed[model].values()),
            'verified_unclassified_records': sum(row.get('parity_passed') is True and
                                                 row.get('classified') is not True for row in indexed[model].values()),
            'verified_classified_records': len(selected), 'classification_coverage': len(selected) / total,
            'correct_decisions': correct, 'correct_decision_rate_over_expected_population': correct / total,
            'status_counts': dict(sorted(counts.items())), 'native_conditional_metrics': metric,
            'clock_quality': _summarize_clock_quality(indexed[model].values()),
            'capture_time_metrics_on_same_records': metrics_for(model, selected, capture=True),
            'native_vs_capture': transitions(model, selected),
            'included_case_ids': selected, 'excluded_case_ids': excluded,
            'excluded_records': [{'case_id': identity, 'record_id': cases[identity]['record']['record_id'],
                'label': cases[identity]['record']['label'],
                'failure_kind': indexed[model][identity].get('failure_kind'),
                'error': indexed[model][identity].get('error')} for identity in excluded],
            'excluded_support_by_class': {name: sum(cases[identity]['record']['label'] == name
                                                   for identity in excluded) for name in CLASSES}}
    common = sorted(set(admitted['B']) & set(admitted['C']))
    paired = Counter()
    different = 0
    for identity in common:
        truth = cases[identity]['record']['label']
        b, c = indexed['B'][identity]['class'], indexed['C'][identity]['class']
        different += b != c
        paired['both_correct' if b == truth and c == truth else
               'B_wrong_C_correct' if b != truth and c == truth else
               'B_correct_C_wrong' if b == truth and c != truth else 'both_wrong'] += 1
    paired_metrics = {model: metrics_for(model, common) for model in 'BC'}
    return {'schema_version': 1, 'accuracy_scored': True, 'preliminary': True,
            'labels_verified_per_flow': False, 'performance_measured': False,
            'scope': 'Frozen held-out isolated prefixes; actual ingress timing; conditional metrics with explicit coverage',
            'expected_records_per_model': total, 'expected_case_model_outcomes': 2 * total,
            'population_support_by_class': supports, 'class_order': list(CLASSES), 'models': per_model,
            'clock_quality': _summarize_clock_quality(row for model in 'BC' for row in indexed[model].values()),
            'common_paired_population': {'records': len(common), 'coverage': len(common) / total,
                'case_ids': common, 'excluded_case_ids': [identity for identity in ids if identity not in common],
                'native_metrics': paired_metrics,
                'capture_time_metrics_on_same_records': {model: metrics_for(model, common, True) for model in 'BC'},
                'native_vs_capture': {model: transitions(model, common) for model in 'BC'},
                'prediction_disagreements': different,
                'paired_correctness': {name: paired[name] for name in
                    ('both_correct', 'B_wrong_C_correct', 'B_correct_C_wrong', 'both_wrong')},
                'C_minus_B_accuracy': (paired_metrics['C']['accuracy'] - paired_metrics['B']['accuracy']) if common else None,
                'C_minus_B_macro_f1': (paired_metrics['C']['macro_f1'] - paired_metrics['B']['macro_f1']) if common else None},
            'limitations': ['B/C native runs have different actual arrival times; a difference is not a pure direction effect.',
                'Clock-quality events are reported independently of parity; conditional diagnostic accuracy does not certify a clean clock.',
                'No-decision/transport failures are excluded from conditional accuracy, never from coverage denominators.',
                'Labels remain capture-derived; this is not independent per-flow activity ground truth.',
                'Fixed six-class macro averages retain zero-support classes with zero division set to zero.',
                'Debug reports/userspace captures are not throughput or latency benchmarks.']}
