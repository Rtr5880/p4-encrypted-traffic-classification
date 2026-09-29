#!/usr/bin/env python3
"""Development-only refinement of the frozen, preliminary B/C baseline.

Reuse the original baseline implementation without editing it or its input
manifest. No PCAP processing, feature changes, test scoring or final refitting.
"""
import argparse
import json
from pathlib import Path
import sys

import train_capture_baseline as baseline

VERSION = 'development-tuning-v1'
BASELINE_PARAMETERS = {'max_depth': 5, 'n_estimators': 10}


def configuration_id(parameters):
    return f"depth{parameters['max_depth']}_count{parameters['n_estimators']}"


def load_development(prepared):
    """Inspect sealed inputs for integrity, then expose ONLY development rows.

    The original validator reads both partitions to check disjointness. Reading
    for integrity is not evaluating test predictions: test rows are discarded
    here, before any call to matrix(), fitting, prediction or model selection.
    """
    tables, manifest = baseline.load_prepared(prepared)
    development = {n: [r for r in tables[n] if r['partition'] == 'development']
                   for n in baseline.WINDOWS}
    excluded = {str(n): sum(r['partition'] == 'test' for r in tables[n])
                for n in baseline.WINDOWS}
    for n, rows in development.items():
        baseline.require(rows and all(r['partition'] == 'development' for r in rows),
                         f'N{n}: unexpected development input')
    return development, manifest, excluded


def candidate_summary(result):
    """Summarize model complexity measured on CV fits, not full-data models."""
    folds = result['folds']
    baseline.require(len(folds) == baseline.FOLDS, 'Incomplete fold results')
    counts = {fold['model_size']['trees'] for fold in folds}
    baseline.require(len(counts) == 1, 'Inconsistent tree counts between folds')
    return {
        'configuration_id': configuration_id(result['parameters']),
        'parameters': result['parameters'],
        'mean_macro_f1': result['mean_macro_f1'],
        'std_macro_f1': result['std_macro_f1'],
        'trees_per_fold_model': counts.pop(),
        'max_observed_fold_depth': max(f['model_size']['max_depth'] for f in folds),
        'mean_fold_leaves': sum(f['model_size']['leaves'] for f in folds) / len(folds),
        'mean_fold_nodes': sum(f['model_size']['nodes'] for f in folds) / len(folds),
        'total_fold_fit_seconds': sum(f['fit_seconds'] for f in folds),
        'is_original_configuration': result['parameters'] == BASELINE_PARAMETERS,
    }


def mark_tradeoffs(summaries):
    """Mark non-dominated score/complexity choices without inventing a budget.

    A dominates B only if score is >=, all three cost proxies are <=, and at
    least one comparison is strict. These proxies are NOT actual P4 resource use.
    """
    costs = ('trees_per_fold_model', 'max_observed_fold_depth', 'mean_fold_leaves')
    for candidate in summaries:
        def dominates(other):
            no_worse = (other['mean_macro_f1'] >= candidate['mean_macro_f1'] and
                        all(other[k] <= candidate[k] for k in costs))
            better = (other['mean_macro_f1'] > candidate['mean_macro_f1'] or
                      any(other[k] < candidate[k] for k in costs))
            return no_worse and better
        candidate['on_score_complexity_frontier'] = not any(dominates(other) for other in summaries)
    return summaries


def paired_comparison(results):
    """Compare direction at MATCHED hyperparameters, not just different winners."""
    pairs = {}
    for n in baseline.WINDOWS:
        for algorithm in ('RF', 'XGB'):
            name = f'n{n}_{algorithm}'
            left = {configuration_id(r['parameters']): r for r in results[name + '_B']}
            right = {configuration_id(r['parameters']): r for r in results[name + '_C']}
            baseline.require(set(left) == set(right), 'Unpaired B/C search configurations')
            entries = []
            for key, b in left.items():
                c = right[key]
                baseline.require([f['fold'] for f in b['folds']] == [f['fold'] for f in c['folds']],
                                 'Unpaired B/C fold results')
                entries.append({'configuration_id': key, 'parameters': b['parameters'],
                    'B_mean_macro_f1': b['mean_macro_f1'], 'C_mean_macro_f1': c['mean_macro_f1'],
                    'C_minus_B_mean_macro_f1': c['mean_macro_f1'] - b['mean_macro_f1'],
                    'C_minus_B_by_fold': [cf['macro_f1'] - bf['macro_f1']
                                          for bf, cf in zip(b['folds'], c['folds'], strict=True)]})
            pairs[name] = entries
    return pairs


def report_text(summary, comparisons):
    lines = ['# Development-only tuning: preliminary', '', baseline.DISCLAIMER, '',
        'The test partition was checked for input integrity but NOT scored, fitted or used for selection.',
        'No new final model was refitted or exported. Existing baseline models/results are unchanged.', '',
        '## Highest mean validation scores', '',
        '| Experiment | Baseline CV F1 | Best CV F1 | Change | Depth limit | Trees/rounds parameter | Actual trees/fold | Mean leaves/fold |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for name, experiment in summary['experiments'].items():
        best = experiment['best_validation_candidate']
        original = experiment['original_configuration']
        p = best['parameters']
        lines.append(f"| {name} | {original['mean_macro_f1']:.4f} | {best['mean_macro_f1']:.4f} | "
                     f"{best['mean_macro_f1'] - original['mean_macro_f1']:+.4f} | {p['max_depth']} | "
                     f"{p['n_estimators']} | {best['trees_per_fold_model']} | {best['mean_fold_leaves']:.1f} |")
    lines += ['', 'The original depth-5/count-10 configuration is rerun on the SAME development folds.',
        'The best score cannot be lower than that rerun baseline because it is included in the search.',
        'Selected validation scores are tuning evidence, not an unbiased estimate of final performance.',
        'Fold standard deviations are descriptive, not confidence intervals. Small differences may not be robust.', '',
        '## All configurations', '',
        'Frontier=yes means no evaluated candidate has an equal/higher mean score and equal/lower values',
        'for tree count, maximum observed fold depth and mean fold leaves, with at least one strict advantage.',
        'This is a comparison aid, NOT a hardware-fit claim or automatic deployment choice.']
    for name, experiment in summary['experiments'].items():
        lines += ['', f'### {name}', '',
            '| Configuration | CV macro-F1 | Fold SD | Actual trees | Max fold depth | Mean leaves | Frontier |',
            '| --- | ---: | ---: | ---: | ---: | ---: | --- |']
        for candidate in experiment['candidates']:
            lines.append(f"| {candidate['configuration_id']} | {candidate['mean_macro_f1']:.4f} | "
                         f"{candidate['std_macro_f1']:.4f} | {candidate['trees_per_fold_model']} | "
                         f"{candidate['max_observed_fold_depth']} | {candidate['mean_fold_leaves']:.1f} | "
                         f"{'yes' if candidate['on_score_complexity_frontier'] else 'no'} |")
    lines += ['', '## Direction comparison at matched configurations', '',
        'A best-tuned B versus best-tuned C comparison may also change hyperparameters.',
        'Use these matched-configuration differences to isolate the feature-set comparison more clearly.', '',
        '| Pair | Configuration | B CV macro-F1 | C CV macro-F1 | C minus B |',
        '| --- | --- | ---: | ---: | ---: |']
    for name, entries in comparisons.items():
        for entry in entries:
            lines.append(f"| {name} | {entry['configuration_id']} | {entry['B_mean_macro_f1']:.4f} | "
                         f"{entry['C_mean_macro_f1']:.4f} | {entry['C_minus_B_mean_macro_f1']:+.4f} |")
    lines += ['', 'N4 and N8 have different eligible populations; this is not a controlled packet-budget comparison.',
        'Capture-derived labels and shared captures remain limitations; P2P has only one source capture.',
        'The old test scores have already been inspected. Do not claim a fresh blind final evaluation from this tuning.',
        'Actual P4 resource use, numeric conversion and replay parity remain unverified.']
    return '\n'.join(lines) + '\n'


def tune(prepared, output_root, check_only=False):
    directory = None
    try:
        prepared = Path(prepared).expanduser().resolve()
        baseline.require(not Path(output_root).expanduser().resolve().is_relative_to(prepared),
                         'Tuning output must be outside the prepared input directory')
        # Fingerprint first, then load/validate: detect changes during validation as well.
        initial_manifest_sha = baseline.digest(prepared / 'manifest.json')
        development, manifest, excluded = load_development(prepared)
        baseline.require(baseline.digest(prepared / 'manifest.json') == initial_manifest_sha,
                         'Prepared manifest changed while being read')
        candidates = baseline.grid('compact')
        experiments = len(baseline.WINDOWS) * 2 * 2
        expected_fits = experiments * len(candidates) * baseline.FOLDS
        for n, rows in development.items():
            print(f'N{n}: {len(rows)} development rows; {excluded[str(n)]} test rows excluded from fitting/scoring.')
        print(f'Plan: {experiments} experiments x {len(candidates)} configurations x {baseline.FOLDS} folds = {expected_fits} fits.')
        print('No test scoring, final refitting, feature changes or PCAP processing.')
        if check_only:
            print('TUNING PREFLIGHT PASS — no models fitted and no output created.')
            return None

        directory = baseline.new_directory(output_root)
        code_paths = {'tuning': Path(__file__), 'baseline': Path(baseline.__file__),
                      'validator': Path(baseline.validator.__file__)}
        fingerprints = {name: baseline.digest(path) for name, path in code_paths.items()}
        config = {'status': 'planned', 'version': VERSION, 'preliminary': True,
            'development_only': True, 'test_records_scored': 0, 'final_models_refitted': 0,
            'prepared_directory': str(prepared), 'prepared_manifest_sha256': initial_manifest_sha,
            'input_payload_sha256': manifest['payload_sha256'],
            'source_preparation_search': manifest['search'], 'tuning_search': 'compact',
            'candidates': candidates, 'original_configuration': BASELINE_PARAMETERS,
            'expected_fits': expected_fits, 'training_config': baseline.CONFIG,
            'environment': baseline.environment(), 'source_sha256': fingerprints,
            'development': {str(n): baseline.subset_summary(rows) for n, rows in development.items()},
            'test_rows_excluded': excluded,
            'selection_rule': 'Highest mean development-fold macro-F1; exact ties prefer lower count then depth.',
            'complexity_basis': 'Observed CV-fit tree count, maximum depth, and mean leaves; NOT measured P4 resources.',
            'disclaimer': baseline.DISCLAIMER}
        baseline.write_json(directory / 'run_config.json', config)
        results, experiment_summaries = {}, {}
        with (directory / 'cv_progress.jsonl').open('x', encoding='utf-8') as log_file:
            for n in baseline.WINDOWS:
                for algorithm in ('RF', 'XGB'):
                    for feature_set in ('B', 'C'):
                        name = f'n{n}_{algorithm}_{feature_set}'
                        completed = 0
                        def log(result):
                            nonlocal completed
                            completed += 1
                            log_file.write(json.dumps({'experiment': name, **result}, allow_nan=False) + '\n')
                            log_file.flush()
                            print(f"{name} [{completed}/{len(candidates)}] {configuration_id(result['parameters'])}: "
                                  f"CV macro-F1={result['mean_macro_f1']:.4f}", flush=True)
                        best, entries = baseline.select_configuration(
                            development[n], feature_set, algorithm, candidates, log)
                        baseline.require(len(entries) == len(candidates), 'Incomplete candidate search')
                        summaries = mark_tradeoffs([candidate_summary(entry) for entry in entries])
                        selected = next(s for s in summaries if s['parameters'] == best['parameters'])
                        original = next(s for s in summaries if s['is_original_configuration'])
                        results[name] = entries
                        experiment_summaries[name] = {
                            'best_validation_candidate': selected, 'original_configuration': original,
                            'candidates': summaries,
                            'direction_comparison': 'Use matched hyperparameters in paired_comparison.json.'}

        # Hash checks only: never call the baseline train()/test-prediction path.
        baseline.require(baseline.digest(prepared / 'manifest.json') == initial_manifest_sha,
                         'Prepared manifest changed during tuning')
        for name, expected in manifest['payload_sha256'].items():
            baseline.require(baseline.digest(prepared / name) == expected,
                             f'Prepared payload changed during tuning: {name}')
        baseline.require(fingerprints == {name: baseline.digest(path) for name, path in code_paths.items()},
                         'Source code changed during tuning')
        completed_fits = sum(len(r['folds']) for entries in results.values() for r in entries)
        baseline.require(completed_fits == expected_fits, 'Unexpected completed fit count')
        comparisons = paired_comparison(results)
        summary = {'status': 'tuning_complete', 'version': VERSION, 'preliminary': True,
            'development_only': True, 'test_records_scored': 0, 'final_models_refitted': 0,
            'completed_fits': completed_fits, 'experiments': experiment_summaries,
            'disclaimer': baseline.DISCLAIMER}
        baseline.write_json(directory / 'cv_results.json', results)
        baseline.write_json(directory / 'paired_comparison.json', comparisons)
        with (directory / 'report.md').open('x', encoding='utf-8') as file:
            file.write(report_text(summary, comparisons))
        # Success marker is last; failures must not look like complete evaluations.
        baseline.write_json(directory / 'summary.json', summary)
        print('\nVALIDATION LEADERS — not final deployment selections:')
        for name, experiment in experiment_summaries.items():
            best = experiment['best_validation_candidate']
            original = experiment['original_configuration']
            print(f"{name}: baseline CV={original['mean_macro_f1']:.4f}; best CV={best['mean_macro_f1']:.4f}; "
                  f"{best['configuration_id']}; trees={best['trees_per_fold_model']}; "
                  f"mean fold leaves={best['mean_fold_leaves']:.1f}")
        print(f'TUNING COMPLETE — DEVELOPMENT ONLY. Results: {directory}')
        return directory
    except BaseException as error:
        if directory is not None:
            baseline.write_json(directory / 'failure.json', {'error': str(error), 'preliminary': True})
            print(f'Incomplete tuning output; do not use: {directory}', file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--output-root', type=Path,
                        default=Path.home() / 'p4/etc-training/results/baseline_tuning')
    parser.add_argument('--check-only', action='store_true', help='Verify inputs and show fit plan without training/writing')
    args = parser.parse_args(argv)
    try:
        tune(args.prepared, args.output_root, args.check_only)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, KeyboardInterrupt) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
