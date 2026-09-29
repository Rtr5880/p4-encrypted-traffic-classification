#!/usr/bin/env python3
"""Prepare/train a PRELIMINARY six-class, capture-labelled RF/XGBoost baseline.

One entry point, two explicit stages. Never reads PCAPs or changes extraction
outputs. Parent-disjoint does NOT mean capture/session-disjoint or P4-verified.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
import uuid

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.utils.class_weight import compute_sample_weight
import xgboost
from xgboost import XGBClassifier

import validate_instance_output as validator

CLASSES = ('CHAT', 'FT', 'MAIL', 'P2P', 'STREAMING', 'VOIP')
B, C = validator.B, validator.C
WINDOWS = (4, 8)
VERSION = 'capture-baseline-v1'
SEED = 42
FOLDS = 3
DISCLAIMER = ('PRELIMINARY: six capture-derived activity hints; no BROWSING label; '
              'parent-conversation-disjoint, NOT capture/session-disjoint; '
              'no verified activity ground truth or in-switch deployment.')
CONFIG = {'seed': SEED, 'test_outer_folds': 5, 'test_fold_index': 0,
          'development_folds': FOLDS, 'threads': 2, 'xgb_learning_rate': 0.1,
          'primary_metric': 'unweighted macro-F1 across all six classes',
          'class_weighting': 'inverse frequency from fitting rows ONLY',
          'rf_max_features': 'sqrt', 'rf_bootstrap': True,
          'xgb_tree_method': 'hist', 'xgb_device': 'cpu',
          'xgb_multi_strategy': 'one_output_per_tree', 'xgb_num_parallel_tree': 1,
          'xgb_subsample': 1.0, 'xgb_colsample_bytree': 1.0,
          'xgb_min_child_weight': 1.0, 'xgb_reg_lambda': 1.0,
          'early_stopping': False, 'scaling': None, 'resampling': None}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
        f.write('\n')


def write_rows(path, values):
    with Path(path).open('x', encoding='utf-8') as f:
        for value in values:
            f.write(json.dumps(value, sort_keys=True, allow_nan=False) + '\n')


def read_rows(path):
    return list(validator.rows(Path(path)))


def environment():
    return {'python': platform.python_version(), 'numpy': np.__version__,
            'sklearn': sklearn.__version__, 'xgboost': xgboost.__version__,
            'joblib': joblib.__version__}


def new_directory(root):
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:10])
    path.mkdir(exist_ok=False)
    return path


def grid(search):
    if search == 'fixed':
        return [{'max_depth': 5, 'n_estimators': 10}]
    require(search == 'compact', 'Unknown search mode')
    return [{'max_depth': d, 'n_estimators': t} for d in (3, 5, 7) for t in (5, 10, 20)]


def source_paths(run, summary):
    paths = [run / 'summary.json', run / 'policy.json']
    for capture in summary['captures']:
        child = run / capture['evidence_directory']
        require(child.resolve().parent == run, 'Capture directory escaped extraction run')
        paths.extend(child / name for name in ('source.json', 'instances.jsonl', 'features_n4.jsonl', 'features_n8.jsonl'))
    return paths


def load_extraction(run):
    """Stage 1: keep the six capture hints; never invent flow-level ground truth."""
    run = Path(run).expanduser().resolve()
    require(not (run / 'failure.json').exists(), 'Extraction run is marked failed')
    summary = read_json(run / 'summary.json')
    paths = source_paths(run, summary)
    before = {str(p.relative_to(run)): digest(p) for p in paths}
    validation = validator.validate_run(run)
    policy = read_json(run / 'policy.json')
    require(policy['label_policy'] == 'capture-only' and policy['labels_verified'] is False,
            'This baseline requires explicitly provisional capture-only labels')
    tables = {n: [] for n in WINDOWS}
    for capture in summary['captures']:
        child = run / capture['evidence_directory']
        for n in WINDOWS:
            for r in read_rows(child / f'features_n{n}.jsonl'):
                require(r['label'] in CLASSES and r['label_basis'] == 'capture_activity_hint', 'Unexpected class or label basis')
                tables[n].append({key: r[key] for key in
                    ('record_id', 'instance_id', 'parent_candidate_conversation_id', 'capture_id',
                     'capture_sha256', 'n', 'label', 'label_basis', 'features_B', 'features_C')})
    for n in WINDOWS:
        tables[n].sort(key=lambda r: r['record_id'])
    require(before == {str(p.relative_to(run)): digest(p) for p in paths}, 'Extraction files changed while being read')
    return tables, {'extraction_run': str(run), 'extraction_sha256': before,
                    'extraction_validation': validation, 'extraction_policy': policy}


def validate_tables(tables):
    """Stage 2: strict feature allowlists; metadata never enters the matrix."""
    parent_meta, instance_meta = {}, {}
    all_ids = set()
    for n in WINDOWS:
        require(tables[n], f'No N{n} records')
        require(set(r['label'] for r in tables[n]) == set(CLASSES), f'N{n}: expected all six classes')
        for r in tables[n]:
            require(r['n'] == n and r['label_basis'] == 'capture_activity_hint', 'Invalid record/label policy')
            require(r['record_id'] not in all_ids, 'Duplicate record ID')
            all_ids.add(r['record_id'])
            require(r['record_id'] == f"{r['instance_id']}:n{n}", 'Record/instance ID mismatch')
            require(set(r['features_B']) == set(B) and set(r['features_C']) == set(C), 'Unexpected model feature')
            for name, f in (('B', B), ('C', C)):
                require(all(type(r[f'features_{name}'][k]) is int and 0 <= r[f'features_{name}'][k] < 2**48 for k in f),
                        'Features must be nonnegative bounded integers; no imputation')
            require(r['features_B'] == {k: r['features_C'][k] for k in B}, 'B/C feature mismatch')
            parent = r['parent_candidate_conversation_id']
            meta = (r['capture_id'], r['capture_sha256'], r['label'])
            require(parent not in parent_meta or parent_meta[parent] == meta, 'Parent has conflicting provenance/label')
            parent_meta[parent] = meta
            if n == 4:
                require(r['instance_id'] not in instance_meta, 'Repeated N4 instance')
                instance_meta[r['instance_id']] = (parent, meta)
            else:
                require(instance_meta.get(r['instance_id']) == (parent, meta), 'N8 lacks matching N4 provenance')
    return parent_meta


def make_splits(tables):
    """Stage 3: derive ONE group assignment from N4; inherit it for N8/B/C."""
    validate_tables(tables)
    rows = tables[4]
    y = np.array([CLASSES.index(r['label']) for r in rows])
    groups = np.array([r['parent_candidate_conversation_id'] for r in rows])
    x = np.zeros((len(rows), 1))  # Labels/groups only; no feature values influence splitting.
    for label in CLASSES:
        require(len(set(groups[y == CLASSES.index(label)])) >= 5, f'{label}: fewer than five parent groups')
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    development, test = next(outer.split(x, y, groups))  # Predeclared fold 0, no seed shopping.
    assignments = {}
    for i in test:
        assignments[groups[i]] = {'partition': 'test', 'validation_fold': None}
    inner = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED + 1)
    for fold, (_, valid) in enumerate(inner.split(x[development], y[development], groups[development])):
        for i in development[valid]:
            group = groups[i]
            value = {'partition': 'development', 'validation_fold': fold}
            require(group not in assignments or assignments[group] == value, 'Conflicting parent split')
            assignments[group] = value
    require(set(assignments) == set(groups), 'Unassigned parent group')
    for n in WINDOWS:
        for r in tables[n]:
            r.update(assignments[r['parent_candidate_conversation_id']])
    check_splits(tables, assignments)
    return assignments


def subset_summary(rows):
    return {'records': len(rows), 'parents': len(set(r['parent_candidate_conversation_id'] for r in rows)),
            'captures': len(set(r['capture_id'] for r in rows)), 'classes': dict(sorted(Counter(r['label'] for r in rows).items()))}


def check_splits(tables, assignments):
    parents = validate_tables(tables)
    require(set(parents) == set(assignments), 'Group manifest contains missing/extra parents')
    summaries = {}
    for n in WINDOWS:
        rows = tables[n]
        for r in rows:
            a = assignments[r['parent_candidate_conversation_id']]
            require({'partition': r['partition'], 'validation_fold': r['validation_fold']} == a, 'Row/group split mismatch')
            require(a['partition'] in ('development', 'test'), 'Invalid partition')
            require((a['partition'] == 'test' and a['validation_fold'] is None) or
                    (a['partition'] == 'development' and type(a['validation_fold']) is int and 0 <= a['validation_fold'] < FOLDS), 'Invalid validation fold')
        dev = [r for r in rows if r['partition'] == 'development']
        test = [r for r in rows if r['partition'] == 'test']
        def complete(part, name):
            require(set(r['label'] for r in part) == set(CLASSES), f'N{n} {name}: a class is absent; stop and review groups')
        complete(dev, 'development'); complete(test, 'test')
        test_groups = set(r['parent_candidate_conversation_id'] for r in test)
        dev_groups = set(r['parent_candidate_conversation_id'] for r in dev)
        require(not (test_groups & dev_groups), 'Test/development parent overlap')
        fold_summaries = []
        for f in range(FOLDS):
            fitting = [r for r in dev if r['validation_fold'] != f]
            validation = [r for r in dev if r['validation_fold'] == f]
            complete(fitting, f'fold {f} training'); complete(validation, f'fold {f} validation')
            require(not (set(r['parent_candidate_conversation_id'] for r in fitting) &
                         set(r['parent_candidate_conversation_id'] for r in validation)), 'Training/validation parent overlap')
            fold_summaries.append({'fold': f, 'training': subset_summary(fitting), 'validation': subset_summary(validation)})
        summaries[str(n)] = {'all': subset_summary(rows), 'development': subset_summary(dev),
                              'test': subset_summary(test), 'folds': fold_summaries}
    return summaries


def prepare(extraction_run, output_root, search='fixed'):
    directory = None
    try:
        require(not Path(output_root).expanduser().resolve().is_relative_to(Path(extraction_run).expanduser().resolve()), 'Output root must be outside extraction evidence')
        tables, provenance = load_extraction(extraction_run)
        assignments = make_splits(tables)
        summary = check_splits(tables, assignments)
        directory = new_directory(output_root)
        for n in WINDOWS:
            write_rows(directory / f'table_n{n}.jsonl', tables[n])
        write_json(directory / 'groups.json', assignments)
        write_json(directory / 'split_summary.json', summary)
        payload = {name: digest(directory / name) for name in ('table_n4.jsonl', 'table_n8.jsonl', 'groups.json', 'split_summary.json')}
        write_json(directory / 'manifest.json', {'status': 'prepared', 'version': VERSION,
            'preliminary': True, 'labels_verified': False, 'capture_disjoint': False,
            'classes': list(CLASSES), 'features_B': list(B), 'features_C': list(C),
            'config': CONFIG, 'search': search, 'candidates': grid(search),
            'payload_sha256': payload, 'environment': environment(), 'script_sha256': digest(__file__),
            'validator_sha256': digest(validator.__file__), 'disclaimer': DISCLAIMER, **provenance})
        for n in WINDOWS:
            s = summary[str(n)]
            print(f"N{n}: {s['all']['records']} rows; development={s['development']['records']}; test={s['test']['records']}")
        print('PREPARATION PASS: six classes in every partition/fold; parent groups separate; shared B/C and N4/N8 assignments.')
        print(f'Prepared directory: {directory}')
        print(f'Search mode: {search}; no model has been trained. {DISCLAIMER}')
        return directory
    except BaseException as e:
        if directory is not None:
            write_json(directory / 'failure.json', {'error': str(e), 'preliminary': True})
        raise


def load_prepared(directory):
    directory = Path(directory).expanduser().resolve()
    require(not (directory / 'failure.json').exists(), 'Prepared run is marked failed')
    manifest = read_json(directory / 'manifest.json')
    require(manifest['status'] == 'prepared' and manifest['version'] == VERSION, 'Unsupported prepared dataset')
    require(manifest['classes'] == list(CLASSES) and manifest['features_B'] == list(B) and manifest['features_C'] == list(C), 'Schema changed')
    require(manifest['preliminary'] is True and manifest['labels_verified'] is False and manifest['capture_disjoint'] is False, 'Invalid research claim')
    require(manifest['config'] == CONFIG and manifest['candidates'] == grid(manifest['search']), 'Configuration changed; prepare again')
    require(manifest['environment'] == environment(), 'ML environment changed; prepare again')
    require(manifest['script_sha256'] == digest(__file__) and manifest['validator_sha256'] == digest(validator.__file__), 'Code changed; prepare again')
    names = {'table_n4.jsonl', 'table_n8.jsonl', 'groups.json', 'split_summary.json'}
    require(set(manifest['payload_sha256']) == names, 'Unexpected payload file list')
    for name, expected in manifest['payload_sha256'].items():
        require(digest(directory / name) == expected, f'Prepared file changed: {name}')
    tables = {n: read_rows(directory / f'table_n{n}.jsonl') for n in WINDOWS}
    summary = check_splits(tables, read_json(directory / 'groups.json'))
    require(summary == read_json(directory / 'split_summary.json'), 'Split summary mismatch')
    return tables, manifest


def matrix(rows, feature_set):
    require(feature_set in ('B', 'C'), 'Unknown feature set')
    names = B if feature_set == 'B' else C
    x = np.array([[r[f'features_{feature_set}'][k] for k in names] for r in rows], dtype=np.float64)
    y = np.array([CLASSES.index(r['label']) for r in rows], dtype=np.int64)
    require(x.shape == (len(rows), len(names)) and np.isfinite(x).all(), 'Invalid training matrix')
    return x, y


def make_model(algorithm, candidate):
    if algorithm == 'RF':
        return RandomForestClassifier(**candidate, class_weight='balanced', max_features='sqrt',
                                      bootstrap=True, random_state=SEED, n_jobs=CONFIG['threads'])
    require(algorithm == 'XGB', 'Unknown learner')
    return XGBClassifier(**candidate, objective='multi:softprob', num_class=len(CLASSES),
        learning_rate=CONFIG['xgb_learning_rate'], tree_method='hist', device='cpu',
        multi_strategy='one_output_per_tree', num_parallel_tree=1, subsample=1.0,
        colsample_bytree=1.0, min_child_weight=1.0, reg_lambda=1.0,
        random_state=SEED, n_jobs=CONFIG['threads'], eval_metric='mlogloss')


def fit_model(model, algorithm, x, y):
    require(set(y.tolist()) == set(range(len(CLASSES))), 'Fitting rows missing a class')
    start = time.perf_counter()
    if algorithm == 'XGB':
        model.fit(x, y, sample_weight=compute_sample_weight(class_weight='balanced', y=y), verbose=False)
    else:
        model.fit(x, y)  # RF calculates class_weight internally from this fitting set.
    return time.perf_counter() - start


def complexity(model, algorithm):
    if algorithm == 'RF':
        trees = model.estimators_
        # Some sklearn tree statistics are numpy integers, which JSON cannot
        # encode. Convert the summary (not the model) to native Python integers.
        return {'trees': len(trees), 'max_depth': int(max(t.tree_.max_depth for t in trees)),
                'leaves': int(sum(t.tree_.n_leaves for t in trees)),
                'nodes': int(sum(t.tree_.node_count for t in trees))}
    trees = model.get_booster().get_dump(dump_format='json')
    leaves = nodes = depth = 0
    for tree in trees:
        stack = [(json.loads(tree), 0)]
        while stack:
            node, d = stack.pop(); nodes += 1; depth = max(depth, d)
            if 'leaf' in node:
                leaves += 1
            else:
                stack.extend((child, d + 1) for child in node['children'])
    return {'trees': len(trees), 'max_depth': depth, 'leaves': leaves, 'nodes': nodes,
            'boosting_rounds': model.get_booster().num_boosted_rounds()}


def select_configuration(rows, feature_set, algorithm, candidates, log):
    """Only development rows are accepted; test scores cannot select a model."""
    require(all(r['partition'] == 'development' for r in rows), 'Test rows reached model selection')
    results = []
    for candidate in candidates:
        fold_results = []
        for f in range(FOLDS):
            fitting = [r for r in rows if r['validation_fold'] != f]
            validation = [r for r in rows if r['validation_fold'] == f]
            x, y = matrix(fitting, feature_set); vx, vy = matrix(validation, feature_set)
            model = make_model(algorithm, candidate)
            seconds = fit_model(model, algorithm, x, y)
            score = float(f1_score(vy, model.predict(vx), labels=list(range(len(CLASSES))), average='macro', zero_division=0))
            fold_results.append({'fold': f, 'macro_f1': score, 'fit_seconds': seconds, 'model_size': complexity(model, algorithm)})
        result = {'parameters': candidate, 'folds': fold_results,
                  'mean_macro_f1': float(np.mean([f['macro_f1'] for f in fold_results])),
                  'std_macro_f1': float(np.std([f['macro_f1'] for f in fold_results]))}
        results.append(result); log(result)
    # Deterministic exact-score ties prefer fewer trees/rounds, then lower depth.
    best = min(results, key=lambda r: (-r['mean_macro_f1'], r['parameters']['n_estimators'], r['parameters']['max_depth']))
    return best, results


def save_and_reload(model, algorithm, directory):
    if algorithm == 'RF':
        path = directory / 'model.joblib'
        joblib.dump(model, path)
        reloaded = joblib.load(path)  # Only this freshly-created trusted artifact.
    else:
        path = directory / 'model.ubj'
        model.save_model(path)
        reloaded = XGBClassifier(); reloaded.load_model(path)
    return path, reloaded


def plot_confusion(cm, destination, title):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    figure, axis = plt.subplots(figsize=(8, 6), layout='constrained')
    axis.imshow(cm, cmap='Blues', vmin=0)
    axis.set(xticks=range(len(CLASSES)), yticks=range(len(CLASSES)), xticklabels=CLASSES,
             yticklabels=CLASSES, xlabel='Predicted capture-derived class', ylabel='Capture-derived label',
             title=title + '\nPRELIMINARY — parent-disjoint, not capture-disjoint')
    plt.setp(axis.get_xticklabels(), rotation=35, ha='right')
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            axis.text(j, i, str(cm[i, j]), ha='center', va='center', color='white' if cm[i, j] > cm.max() / 2 else 'black')
    figure.savefig(destination, dpi=150); plt.close(figure)


def train(prepared, output_root):
    directory = None
    try:
        prepared = Path(prepared).expanduser().resolve()
        require(not Path(output_root).expanduser().resolve().is_relative_to(prepared), 'Training output must be outside prepared dataset')
        tables, manifest = load_prepared(prepared)
        directory = new_directory(output_root)
        write_json(directory / 'run_config.json', {'prepared_directory': str(prepared), 'prepared_manifest_sha256': digest(prepared / 'manifest.json'),
            'environment': environment(), 'script_sha256': digest(__file__), 'disclaimer': DISCLAIMER, 'preparation': manifest})
        plans, cv_results = {}, {}
        with (directory / 'cv_progress.jsonl').open('x', encoding='utf-8') as log_file:
            # Freeze ALL eight selections before inspecting ANY test predictions.
            for n in WINDOWS:
                dev = [r for r in tables[n] if r['partition'] == 'development']
                for algorithm in ('RF', 'XGB'):
                    for feature_set in ('B', 'C'):
                        name = f'n{n}_{algorithm}_{feature_set}'
                        print(f'Validation search: {name} ({len(manifest["candidates"])} candidate(s))', flush=True)
                        def log(result):
                            log_file.write(json.dumps({'experiment': name, **result}) + '\n'); log_file.flush()
                        best, results = select_configuration(dev, feature_set, algorithm, manifest['candidates'], log)
                        plans[name] = {'n': n, 'algorithm': algorithm, 'feature_set': feature_set, **best}
                        cv_results[name] = results
        write_json(directory / 'selection.json', plans)
        write_json(directory / 'cv_results.json', cv_results)
        # Recheck sealed inputs before final fitting/evaluation.
        _, fresh_manifest = load_prepared(prepared)
        require(fresh_manifest == manifest, 'Prepared manifest changed during search')
        metrics = {}
        for name, selected in plans.items():
            n, algorithm, feature_set = selected['n'], selected['algorithm'], selected['feature_set']
            dev = [r for r in tables[n] if r['partition'] == 'development']
            test = [r for r in tables[n] if r['partition'] == 'test']
            x, y = matrix(dev, feature_set); tx, ty = matrix(test, feature_set)
            model = make_model(algorithm, selected['parameters'])
            seconds = fit_model(model, algorithm, x, y)
            prediction = model.predict(tx)
            probabilities = model.predict_proba(tx)
            child = directory / name; child.mkdir()
            path, reloaded = save_and_reload(model, algorithm, child)
            require(np.array_equal(prediction, reloaded.predict(tx)), 'Reloaded model predictions changed')
            require(np.allclose(probabilities, reloaded.predict_proba(tx), rtol=0, atol=1e-12), 'Reloaded model probabilities changed')
            cm = confusion_matrix(ty, prediction, labels=list(range(len(CLASSES))))
            result = {'preliminary': True, 'selected_parameters': selected['parameters'],
                'validation_macro_f1_mean': selected['mean_macro_f1'], 'validation_macro_f1_std': selected['std_macro_f1'],
                'test_accuracy': float(accuracy_score(ty, prediction)),
                'test_macro_f1': float(f1_score(ty, prediction, labels=list(range(len(CLASSES))), average='macro', zero_division=0)),
                'per_class_report': classification_report(ty, prediction, labels=list(range(len(CLASSES))), target_names=list(CLASSES), output_dict=True, zero_division=0),
                'confusion_matrix': cm.tolist(), 'class_order': list(CLASSES), 'final_fit_seconds': seconds,
                'test_records': len(test), 'model_size': complexity(model, algorithm),
                'model_bytes': path.stat().st_size, 'model_sha256': digest(path), 'reload_parity': True,
                'feature_order': list(B if feature_set == 'B' else C), 'disclaimer': DISCLAIMER}
            write_json(child / 'metrics.json', result)
            write_rows(child / 'test_predictions.jsonl', [{'record_id': r['record_id'], 'parent_group': r['parent_candidate_conversation_id'],
                'label': r['label'], 'prediction': CLASSES[int(p)], 'probabilities': prob.tolist()}
                for r, p, prob in zip(test, prediction, probabilities, strict=True)])
            plot_confusion(cm, child / 'confusion_matrix.png', name)
            metrics[name] = result
            print(f"{name}: validation macro-F1={selected['mean_macro_f1']:.4f}; test macro-F1={result['test_macro_f1']:.4f}; trees={result['model_size']['trees']}", flush=True)
        report = ['# Preliminary capture-labelled development baseline', '', DISCLAIMER, '',
            '| Experiment | Validation macro-F1 | Test macro-F1 | Test accuracy | Trees | Depth | Leaves |',
            '| --- | ---: | ---: | ---: | ---: | ---: | ---: |']
        for name, m in metrics.items():
            s = m['model_size']
            report.append(f"| {name} | {m['validation_macro_f1_mean']:.4f} | {m['test_macro_f1']:.4f} | {m['test_accuracy']:.4f} | {s['trees']} | {s['max_depth']} | {s['leaves']} |")
        report += ['', 'Validation standard deviations are descriptive fold variation, not confidence intervals.',
            'N4/N8 contain different eligible instance sets; their accuracy difference is not a controlled packet-budget effect.',
            'Model-library floating-point splits and XGBoost scores have NOT been verified against integer/fixed-point P4 inference.',
            'All eight selections were fixed before test predictions. Do not tune further based on these test results.',
            'No BROWSING class. Class labels are capture hints, not verified flow-level activity.']
        with (directory / 'report.md').open('x', encoding='utf-8') as f:
            f.write('\n'.join(report) + '\n')
        write_json(directory / 'summary.json', {'status': 'training_complete', 'preliminary': True,
            'experiments': metrics, 'disclaimer': DISCLAIMER})
        print(f'TRAINING COMPLETE — PRELIMINARY. Results: {directory}')
        return directory
    except BaseException as e:
        if directory is not None:
            write_json(directory / 'failure.json', {'error': str(e), 'preliminary': True})
            print(f'Incomplete training output; do not use: {directory}', file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='stage', required=True)
    p = sub.add_parser('prepare', help='Validate labels, build tables and freeze splits; no fitting')
    p.add_argument('--extraction-run', type=Path, required=True)
    p.add_argument('--output-root', type=Path, default=Path.home() / 'p4/etc-training/results/baseline_preparation')
    p.add_argument('--search', choices=('fixed', 'compact'), default='fixed', help='Freeze the candidate list BEFORE any model sees test data')
    t = sub.add_parser('train', help='Grouped validation, final development fit, held-out evaluation')
    t.add_argument('--prepared', type=Path, required=True)
    t.add_argument('--output-root', type=Path, default=Path.home() / 'p4/etc-training/results/baseline_training')
    args = parser.parse_args(argv)
    try:
        if args.stage == 'prepare':
            prepare(args.extraction_run, args.output_root, args.search)
        else:
            train(args.prepared, args.output_root)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, KeyboardInterrupt) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
