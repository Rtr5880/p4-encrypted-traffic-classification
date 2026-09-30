#!/usr/bin/env python3
"""Refit the agreed N8 RF-B/C pair and test an integer inference reference.

No PCAP processing, hyperparameter search, test scoring, or P4 generation.
The original baseline implementation and its sealed input files stay unchanged.
"""
import argparse
import math
from pathlib import Path
import sys

import numpy as np

import train_capture_baseline as baseline
import tune_capture_baseline as tuning

FEATURES = {'B': list(baseline.B), 'C': list(baseline.C)}
PARAMETERS = {'max_depth': 7, 'n_estimators': 10}
SCALE = 2**24
VERSION = 'rf-integer-reference-v1'
# Individual inference domains, not a promise that every combination describes
# a real flow. Each of the seven gaps must be below the 60-second idle boundary.
DOMAINS = {
    'size_min': {'min': 0, 'max': 65535, 'bits': 16},
    'size_max': {'min': 0, 'max': 65535, 'bits': 16},
    'size_sum': {'min': 0, 'max': 8 * 65535, 'bits': 19},
    'iat_min': {'min': 0, 'max': 59999999, 'bits': 32},
    'iat_max': {'min': 0, 'max': 59999999, 'bits': 32},
    'iat_sum': {'min': 0, 'max': 7 * 59999999, 'bits': 32},
    'reverse_packet_count': {'min': 0, 'max': 7, 'bits': 3},
    'direction_change_count': {'min': 0, 'max': 7, 'bits': 3},
}
require = baseline.require


def integer_cut(threshold, upper):
    """Largest in-domain integer taking sklearn's left (float32 <=) branch.

    -1 means always right; upper means always left. These are constant branches
    for a P4 generator, NOT a request to encode -1 in an unsigned P4 field.
    """
    require(isinstance(threshold, (float, int, np.floating)) and
            not isinstance(threshold, bool) and math.isfinite(threshold), 'Invalid threshold')
    require(type(upper) is int and 0 <= upper < 2**32, 'Invalid domain maximum')
    lo, hi = -1, upper + 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if float(np.float32(mid)) <= threshold:
            lo = mid
        else:
            hi = mid
    return lo


def export_forest(model, feature_set):
    """Preserve sklearn probability leaves, replacing float-input predicates."""
    require(feature_set in FEATURES, 'Unknown feature set')
    require(isinstance(model, baseline.RandomForestClassifier), 'Expected RandomForestClassifier')
    require(model.n_outputs_ == 1 and model.n_features_in_ == len(FEATURES[feature_set]), 'Unexpected RF dimensions')
    require(np.array_equal(model.classes_, np.arange(6)), 'Unexpected RF class order')
    require(all(model.get_params()[k] == v for k, v in PARAMETERS.items()), 'Unselected RF configuration')
    require(model.class_weight == 'balanced' and model.max_features == 'sqrt' and
            model.bootstrap is True and model.random_state == baseline.SEED,
            'RF weighting, feature sampling, bootstrap or seed changed')
    result = {'schema_version': VERSION, 'feature_set': feature_set,
              'feature_order': FEATURES[feature_set], 'classes': list(baseline.CLASSES),
              'domains': {k: DOMAINS[k] for k in FEATURES[feature_set]},
              'score_scale': SCALE, 'parameters': PARAMETERS, 'trees': []}
    for estimator in model.estimators_:
        require(np.array_equal(estimator.classes_, np.arange(6)), 'Tree class order differs')
        tree, nodes = estimator.tree_, []
        for i in range(tree.node_count):
            if tree.children_left[i] == -1:
                # sklearn 1.9.1 stores normalized, class-weighted probabilities.
                # Export verbatim: renormalizing again can perturb near ties.
                p = np.asarray(tree.value[i][0], dtype=np.float64)
                require(p.shape == (6,) and np.isfinite(p).all() and (p >= 0).all()
                        and (p <= 1 + 1e-12).all() and abs(float(p.sum()) - 1) < 1e-12,
                        'Expected normalized six-class probability leaves')
                nodes.append({'kind': 'leaf', 'probabilities': p.tolist(),
                              'scores': np.rint(p * SCALE).astype(np.int64).tolist()})
            else:
                index, threshold = int(tree.feature[i]), float(tree.threshold[i])
                upper = DOMAINS[FEATURES[feature_set][index]]['max']
                nodes.append({'kind': 'split', 'feature_index': index,
                              'threshold_float64': threshold, 'cut': integer_cut(threshold, upper),
                              'left': int(tree.children_left[i]), 'right': int(tree.children_right[i])})
        result['trees'].append({'nodes': nodes})
    validate_export(result)
    return result


def validate_export(export):
    """Reject malformed trees and any unannounced representation change."""
    require(export['schema_version'] == VERSION, 'Unsupported RF export version')
    feature_set = export['feature_set']
    require(feature_set in FEATURES and export['feature_order'] == FEATURES[feature_set], 'Feature order changed')
    require(export['classes'] == list(baseline.CLASSES), 'Class order changed')
    require(export['domains'] == {k: DOMAINS[k] for k in FEATURES[feature_set]}, 'Feature domains changed')
    require(type(export['score_scale']) is int and export['score_scale'] == SCALE, 'Score scale changed')
    require(export['parameters'] == PARAMETERS and len(export['trees']) == 10, 'Expected depth-7 ten-tree export')
    for tree in export['trees']:
        nodes = tree['nodes']
        require(isinstance(nodes, list) and 1 <= len(nodes) <= 255, 'Invalid node count')
        seen, stack = set(), [(0, 0)]
        while stack:
            node_id, depth = stack.pop()
            require(type(node_id) is int and 0 <= node_id < len(nodes), 'Invalid child index')
            require(node_id not in seen and depth <= 7, 'Cycle/shared child or excessive depth')
            seen.add(node_id)
            node = nodes[node_id]
            if node['kind'] == 'leaf':
                p, scores = node['probabilities'], node['scores']
                require(isinstance(p, list) and len(p) == 6 and all(type(v) in (float, int) and
                        math.isfinite(v) and 0 <= v <= 1 + 1e-12 for v in p) and
                        abs(sum(p) - 1) < 1e-12, 'Invalid probability leaf')
                require(isinstance(scores, list) and len(scores) == 6 and
                        all(type(v) is int and 0 <= v <= SCALE for v in scores), 'Invalid integer leaf score')
                require(scores == [int(round(pv * SCALE)) for pv in p], 'Quantization mismatch')
            else:
                require(node['kind'] == 'split', 'Unknown node kind')
                j = node['feature_index']
                require(type(j) is int and 0 <= j < len(FEATURES[feature_set]), 'Invalid feature index')
                upper = DOMAINS[FEATURES[feature_set][j]]['max']
                require(type(node['cut']) is int and node['cut'] == integer_cut(node['threshold_float64'], upper),
                        'Integer threshold does not preserve float32 predicate')
                stack.extend(((node['left'], depth + 1), (node['right'], depth + 1)))
        require(len(seen) == len(nodes), 'Unreachable tree nodes')


def validate_vectors(export, vectors):
    """Do not coerce floats/bools into integers or silently wrap out-of-range data."""
    values = vectors.tolist() if isinstance(vectors, np.ndarray) else vectors
    require(isinstance(values, list) and values, 'Expected nonempty row list')
    for row in values:
        require(isinstance(row, list) and len(row) == len(export['feature_order']), 'Wrong feature vector width')
        for name, value in zip(export['feature_order'], row, strict=True):
            require(type(value) is int, f'{name}: expected an integer, not a coerced float/bool')
            domain = export['domains'][name]
            require(domain['min'] <= value <= domain['max'], f'{name}: outside frozen domain')
    return np.asarray(values, dtype=np.int64)


def predict_export(export, vectors):
    """Return native node IDs, mean float probabilities and integer score sums.

    Both classifiers use argmax (lowest class index on ties). Integer prediction
    requires no division by tree count or softmax and is suitable for P4.
    """
    validate_export(export)
    x = validate_vectors(export, vectors)
    leaves = np.empty((len(x), len(export['trees'])), dtype=np.int64)
    probabilities = np.zeros((len(x), 6), dtype=np.float64)
    scores = np.zeros((len(x), 6), dtype=np.int64)
    for row_id, row in enumerate(x):
        for tree_id, tree in enumerate(export['trees']):
            node_id, nodes = 0, tree['nodes']
            while nodes[node_id]['kind'] == 'split':
                node = nodes[node_id]
                node_id = node['left'] if row[node['feature_index']] <= node['cut'] else node['right']
            leaf = nodes[node_id]
            leaves[row_id, tree_id] = node_id
            probabilities[row_id] += leaf['probabilities']
            scores[row_id] += leaf['scores']
    require(int(scores.max()) <= 10 * SCALE < 2**32, 'Score accumulator overflow')
    return leaves, probabilities / len(export['trees']), scores


def verify_parity(model, export, vectors):
    leaves, probabilities, scores = predict_export(export, vectors)
    x = validate_vectors(export, vectors)
    native = model.predict_proba(x)
    native_prediction = np.argmax(native, axis=1)
    float_prediction = np.argmax(probabilities, axis=1)
    fixed_prediction = np.argmax(scores, axis=1)
    margins = np.sort(native, axis=1)[:, -1] - np.sort(native, axis=1)[:, -2]
    mismatches = np.flatnonzero(native_prediction != fixed_prediction)
    report = {
        'tested_vectors': len(x),
        'leaf_mismatches': int(np.count_nonzero(model.apply(x) != leaves)),
        'max_probability_error': float(np.max(np.abs(native - probabilities))),
        'float_prediction_mismatches': int(np.count_nonzero(native_prediction != float_prediction)),
        'integer_prediction_mismatches': len(mismatches),
        'max_quantized_probability_error': float(np.max(np.abs(native - scores / (10 * SCALE)))),
        'near_tie_vectors': int(np.count_nonzero(margins <= 1 / SCALE + 1e-12)),
        'mismatch_samples': [{'vector_index': int(i), 'features': x[i].tolist(),
                              'native_class': int(native_prediction[i]), 'integer_class': int(fixed_prediction[i]),
                              'native_margin': float(margins[i])} for i in mismatches[:10]],
    }
    report['passed'] = (report['leaf_mismatches'] == report['float_prediction_mismatches'] ==
                        report['integer_prediction_mismatches'] == 0 and report['max_probability_error'] <= 1e-12
                        and report['max_quantized_probability_error'] <= 0.5 / SCALE + 1e-12)
    return report


def diagnostic_vectors(export, development):
    """In-domain numeric probes, NOT extra observations or physical flow traces."""
    x = validate_vectors(export, development)
    upper = [export['domains'][k]['max'] for k in export['feature_order']]
    rng = np.random.default_rng(314159)
    vectors = [[0] * len(upper), upper]
    vectors.extend([[int(rng.integers(0, bound + 1)) for bound in upper] for _ in range(1024)])
    predicate_checks = 0
    for tree in export['trees']:
        for node in tree['nodes']:
            if node['kind'] != 'split':
                continue
            j, cut = node['feature_index'], node['cut']
            candidates = {0, upper[j], cut - 1, cut, cut + 1, 2**24 - 1, 2**24, 2**24 + 1}
            for value in sorted(candidates):
                if not 0 <= value <= upper[j]:
                    continue
                require((float(np.float32(value)) <= node['threshold_float64']) == (value <= cut),
                        'Boundary predicate parity failed')
                predicate_checks += 1
                row = x[predicate_checks % len(x)].tolist()
                row[j] = value
                vectors.append(row)
    return vectors, predicate_checks


def frozen_contract(policy):
    require(policy['idle_seconds'] == 60 and policy['boundary_policy'] == 'idle-tcp' and
            policy['hard_timeout'] is None and policy['features_B'] == FEATURES['B'] and
            policy['features_C'] == FEATURES['C'], 'Extraction semantics changed; review before deployment')
    return {'version': VERSION, 'n': 8, 'parameters': PARAMETERS, 'classes': list(baseline.CLASSES),
            'features': FEATURES, 'domains': DOMAINS, 'extraction_policy': policy,
            'first_packet_iat': 'absent; exactly seven gaps for eight packets',
            'prediction_policy': 'once per instance at eligible packet 8; freeze prefix features',
            'after_prediction': 'keep refreshing last-seen and TCP boundary state; no periodic reclassification',
            'direction': 'first eligible sender of each instance is forward; retain previous direction bit',
            'score_scale': SCALE, 'score_rounding': 'nearest, ties to even, each leaf/class independently',
            'score_width_bits': 32, 'max_class_score': 10 * SCALE,
            'class_tie_break': 'lowest class index', 'float_input_semantics': 'sklearn float32 conversion before splits',
            'live_timestamp_plan': 'BMv2 48-bit ingress microseconds; clock-wrap/replay parity not yet implemented',
            'replay_adapter_plan': 'wrap raw IPv4 in Ethernet; size remains IPv4 ip.len, never Ethernet frame length',
            'p4_verified': False, 'features_verified_in_bmv2': False,
            'remaining_p4_checks': ['eligibility/parser parity', 'TCP and idle-boundary parity',
                                    'hash collisions and state isolation', 'timestamp wrap and replay timing',
                                    'exact packet-8 trigger', 'integer classifier execution parity']}


def load_inputs(prepared, tuning_run):
    """Read test rows ONLY for integrity/group checks; never return them to fit."""
    tables, manifest = baseline.load_prepared(prepared)
    require(not (tuning_run / 'failure.json').exists(), 'Tuning run is marked failed')
    config = baseline.read_json(tuning_run / 'run_config.json')
    summary = baseline.read_json(tuning_run / 'summary.json')
    cv_results = baseline.read_json(tuning_run / 'cv_results.json')
    require(summary['development_only'] is True and summary['completed_fits'] == 216 and
            summary['test_records_scored'] == 0, 'Expected completed development-only tuning')
    require(config['prepared_manifest_sha256'] == baseline.digest(prepared / 'manifest.json') and
            config['input_payload_sha256'] == manifest['payload_sha256'], 'Tuning/preparation provenance mismatch')
    require(config['environment'] == baseline.environment() and config['training_config'] == baseline.CONFIG,
            'Tuning environment/configuration mismatch')
    sources = {'baseline': baseline.__file__, 'tuning': tuning.__file__, 'validator': baseline.validator.__file__}
    require(config['source_sha256'] == {k: baseline.digest(p) for k, p in sources.items()}, 'Tuning source changed')
    policy = manifest['extraction_policy']
    for name, sha in policy['source_sha256'].items():
        require(Path(name).name == name and baseline.digest(Path(__file__).parent / name) == sha,
                'Extraction source changed since feature generation')
    selected = {}
    for feature_set in FEATURES:
        name = 'n8_RF_' + feature_set
        choices = [c for c in summary['experiments'][name]['candidates'] if c['parameters'] == PARAMETERS]
        require(len(choices) == 1 and math.isfinite(choices[0]['mean_macro_f1']), 'Chosen candidate missing')
        fold_choices = [c for c in cv_results[name] if c['parameters'] == PARAMETERS]
        require(len(fold_choices) == 1, 'Chosen candidate lacks fold evidence')
        expected = tuning.candidate_summary(fold_choices[0])
        require(all(choices[0].get(k) == v for k, v in expected.items()), 'Candidate summary/fold evidence mismatch')
        selected[name] = choices[0]
    rows = [r for r in tables[8] if r['partition'] == 'development']
    require(rows and all(r['partition'] == 'development' for r in rows), 'Development partition missing')
    excluded = sum(r['partition'] == 'test' for r in tables[8])
    return rows, manifest, selected, excluded, frozen_contract(policy)


def prepare(prepared, tuning_run, output_root, check_only=False):
    prepared, tuning_run = Path(prepared).expanduser().resolve(), Path(tuning_run).expanduser().resolve()
    output_root = Path(output_root).expanduser().resolve()
    require(not any(output_root.is_relative_to(p) for p in (prepared, tuning_run)), 'Output must be outside input evidence')
    input_files = [prepared / name for name in ('manifest.json', 'groups.json', 'table_n4.jsonl', 'table_n8.jsonl', 'split_summary.json')]
    input_files += [tuning_run / name for name in ('run_config.json', 'summary.json', 'cv_results.json')]
    source_files = sorted(Path(__file__).parent.glob('*.py'))
    before = {str(p): baseline.digest(p) for p in input_files + source_files}
    rows, manifest, selected, excluded, contract = load_inputs(prepared, tuning_run)
    vectors = {s: [[r['features_' + s][k] for k in FEATURES[s]] for r in rows] for s in FEATURES}
    for s in FEATURES:
        validate_vectors({'feature_order': FEATURES[s], 'domains': DOMAINS}, vectors[s])
    require(vectors['B'] == [r[:6] for r in vectors['C']], 'B/C population/features not paired')
    print(f'Preflight PASS: N8 development={len(rows)}, excluded test={excluded}; RF-B/C depth=7, trees=10.', flush=True)
    if check_only:
        print('CHECK ONLY: no fits, predictions or output files created.')
        return None
    directory = baseline.new_directory(output_root)
    try:
        baseline.write_json(directory / 'feature_contract.json', contract)
        baseline.write_json(directory / 'run_config.json', {
            'version': VERSION, 'environment': baseline.environment(), 'input_and_source_sha256': before,
            'prepared_directory': str(prepared), 'tuning_directory': str(tuning_run),
            'parameters': PARAMETERS, 'training_config': baseline.CONFIG, 'selected_development_cv': selected,
            'development_records': len(rows), 'excluded_test_records': excluded,
            'selection_reason': 'User-selected matched compact pair, not highest-score or test-driven selection',
            'new_test_predictions': 0, 'new_hyperparameter_search': False,
            'preliminary': True, 'disclaimer': baseline.DISCLAIMER})
        results = {}
        for feature_set in FEATURES:
            name = 'n8_RF_' + feature_set
            print(f'Refitting {name} on {len(rows)} development rows only...', flush=True)
            x, y = baseline.matrix(rows, feature_set)
            model = baseline.make_model('RF', PARAMETERS)
            seconds = baseline.fit_model(model, 'RF', x, y)
            child = directory / name
            child.mkdir()
            path, reloaded = baseline.save_and_reload(model, 'RF', child)
            require(np.array_equal(model.apply(x), reloaded.apply(x)) and
                    np.allclose(model.predict_proba(x), reloaded.predict_proba(x), rtol=0, atol=1e-12),
                    'Model reload changed inference')
            export = export_forest(reloaded, feature_set)
            baseline.write_json(child / 'forest_integer.json', export)
            export = baseline.read_json(child / 'forest_integer.json')
            development_parity = verify_parity(reloaded, export, vectors[feature_set])
            probes, predicate_checks = diagnostic_vectors(export, vectors[feature_set])
            diagnostic_parity = verify_parity(reloaded, export, probes)
            _, _, scores = predict_export(export, vectors[feature_set])
            baseline.write_rows(directory / f'development_vectors_{feature_set}.jsonl', [
                {'record_id': r['record_id'], 'parent_group': r['parent_candidate_conversation_id'],
                 'features': v, 'integer_class': int(np.argmax(score)), 'integer_scores': score.tolist()}
                for r, v, score in zip(rows, vectors[feature_set], scores, strict=True)])
            baseline.write_rows(child / 'diagnostic_vectors.jsonl', [{'features': row} for row in probes])
            result = {'model_size': baseline.complexity(model, 'RF'), 'fit_seconds': seconds,
                      'model_sha256': baseline.digest(path), 'model_bytes': path.stat().st_size,
                      'export_sha256': baseline.digest(child / 'forest_integer.json'),
                      'feature_order': FEATURES[feature_set], 'class_order': list(baseline.CLASSES),
                      'development': development_parity, 'diagnostic': diagnostic_parity,
                      'split_predicate_boundary_checks': predicate_checks, 'p4_verified': False,
                      'passed': development_parity['passed'] and diagnostic_parity['passed']}
            baseline.write_json(child / 'parity.json', result)
            results[name] = result
            print(f"{name}: development integer mismatches={development_parity['integer_prediction_mismatches']}; "
                  f"diagnostic mismatches={diagnostic_parity['integer_prediction_mismatches']}; "
                  f"leaves={result['model_size']['leaves']}", flush=True)
        require(before == {str(p): baseline.digest(p) for p in input_files + source_files}, 'Input/source changed during run')
        require(all(r['passed'] for r in results.values()),
                'RF parity gate failed; inspect parity.json before P4 conversion. No success summary issued.')
        output_hashes = {str(p.relative_to(directory)): baseline.digest(p) for p in sorted(directory.rglob('*')) if p.is_file()}
        baseline.write_json(directory / 'summary.json', {
            'status': 'rf_reference_verified_on_tested_vectors', 'version': VERSION, 'preliminary': True,
            'development_records': len(rows), 'test_records_scored': 0, 'p4_verified': False,
            'universal_prediction_equivalence_proved': False,
            'experiments': results, 'output_sha256': output_hashes, 'disclaimer': baseline.DISCLAIMER})
        print(f'RF REFERENCE PASS — observed conversion parity, not classification accuracy or P4 verification.\nEvidence saved to: {directory}')
        return directory
    except BaseException as error:
        baseline.write_json(directory / 'failure.json', {'error': str(error), 'usable_for_p4': False})
        print(f'Incomplete RF preparation; inspect evidence: {directory}', file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--tuning-run', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, default=Path.home() / 'p4/etc-training/results/rf_deployment')
    parser.add_argument('--check-only', action='store_true', help='Validate inputs/selection; no fitting/output')
    args = parser.parse_args(argv)
    try:
        prepare(args.prepared, args.tuning_run, args.output_root, args.check_only)
        return 0
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, KeyboardInterrupt) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
