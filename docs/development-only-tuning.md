# Development-only RF/XGBoost tuning

## Purpose

The original depth-5/count-10 baseline is preserved. Tuning compares nine
configurations using only the existing development folds. It does not process
PCAPs, change features or labels, calculate new held-out test scores, or export
new final models. We are investigating performance versus complexity, not
trying to force a 95% result.

All results remain preliminary: capture-derived labels, parent-disjoint but
not capture/session-disjoint splits. P2P has only one source capture. We have
already examined the old test set; these tuning scores are not a fresh blind
estimate of final generalisation performance.

## How the experiment works

| Parameter | Values | Meaning |
| --- | --- | --- |
| `max_depth` | 3, 5, 7 | Maximum number of decision levels within a tree |
| `n_estimators` | 5, 10, 20 | RF tree count; XGBoost boosting-round count |

We keep the learning rate, class weighting, two CPU threads, random seeds,
feature sets, records and folds from the baseline. With six classes and the
chosen XGBoost strategy, 20 rounds produce 120 trees, not 20.

```text
N4 and N8, separately
   x RF and XGBoost
   x feature sets B and C
   = 8 experiments

Each experiment: 9 configurations x 3 development folds = 27 fits
Total: 216 fits, zero test scoring, zero final model refits
```

For each configuration, two development folds fit the model and the third
validates it. This rotates three times, yielding three macro-F1 scores. Their
mean ranks configurations. An exact tie prefers fewer trees/rounds, then lower
depth. A chosen maximum is a validation leader, not automatically a deployment
selection or an unbiased accuracy estimate.

The original configuration is included, so the best observed validation mean
cannot be lower than its rerun baseline. This does not guarantee improvement
on unseen data. Fold standard deviations are descriptive, not confidence
intervals. N4/N8 have different eligible populations.

## Code to read in VS Code

Ubuntu directory: `/home/geleza/p4/etc-training`.

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training/tools/tune_capture_baseline.py \
     /home/geleza/p4/etc-training/tools/test_tune_capture_baseline.py \
     /home/geleza/p4/etc-training/docs/development-only-tuning.md
```

`cd` selects the project. `code` opens the implementation, tests and this guide;
it does not execute the files. The following Python commands use the full venv
interpreter path, so activation is optional.

Read these functions in the tuning script:

1. `load_development()`: verifies the existing preparation through the baseline
   validator, then returns only development rows. The validator reads the test
   partition for integrity/class-coverage/group checks, not prediction scoring.
2. `tune()`: runs the fixed grid and saves progress after each configuration.
   It calls the existing baseline `select_configuration()` fitting routine.
3. `candidate_summary()` and `mark_tradeoffs()`: summarise actual CV-model
   complexity and identify alternatives not dominated on score and all three
   complexity measures. These are not measured P4 hardware resources.
4. `paired_comparison()`: compares B with C at identical hyperparameters and
   folds. Comparing differently tuned winners also changes hyperparameters,
   so it answers a different question from a matched feature ablation.

The baseline script is intentionally not edited: its source fingerprint is
part of the sealed prepared-data manifest. No manifest is altered to bypass
that protection.

## Commands

Run the focused tests from `/home/geleza/p4/etc-training`:

```bash
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover \
  -s /home/geleza/p4/etc-training/tools \
  -p 'test_tune_capture_baseline.py' -v
```

The tests use synthetic data, including a real 216-fit RF/XGB run guarded so
that passing any test row to the model matrix fails. They check feature-path
isolation, unchanged inputs, candidate pairing, complexity accounting and
failure handling. They do not produce research results. Expect `OK`.

Check the real input without fitting or writing output:

```bash
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/tune_capture_baseline.py \
  --prepared /home/geleza/p4/etc-training/results/baseline_preparation/20260929T124705Z_4c1cb93953 \
  --check-only
```

Expect 2,019 N4 development rows and 1,683 N8 development rows; 507 and 398
test rows are excluded from fitting/scoring. Expect `TUNING PREFLIGHT PASS`.

Run the actual tuning with the same command but without `--check-only`:

```bash
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/tune_capture_baseline.py \
  --prepared /home/geleza/p4/etc-training/results/baseline_preparation/20260929T124705Z_4c1cb93953
```

The output shows 72 progress lines (one per three-fold configuration result),
then eight validation leaders. Wait for `TUNING COMPLETE — DEVELOPMENT ONLY`
and the saved path. If a verified run is already complete, there is no need to
rerun it: each invocation creates a separate evidence directory.

## Saved evidence

Under `/home/geleza/p4/etc-training/results/baseline_tuning/`, each run saves:

- `run_config.json`: grid, versions, input/code fingerprints, split counts.
- `cv_progress.jsonl`: incremental completed candidate results.
- `cv_results.json`: all 216 fold scores, fitting times and measured model sizes.
- `paired_comparison.json`: matched B/C differences for every configuration.
- `report.md`: readable score/complexity and direction-comparison tables.
- `summary.json`: success marker and validation leaders; written last.

Failed runs receive `failure.json` and must not be treated as complete. The
original preparation, extraction evidence, baseline models and baseline test
scores are not overwritten.

Tree count, actual depth and leaves are resource proxies. More trees or more
leaves can make an offline improvement less attractive for P4. The frontier
flag just highlights trade-offs; it does not select a deployable model.

## Git checkpoint and next decision

Review and commit the three baseline source/test/guide files plus these three
tuning files. Generated results and model artifacts remain excluded by the
existing Git ignore rules. Never add PCAPs, the venv, secrets or raw results
with a force-add. A short aggregate checkpoint note can be committed separately
to record the run and findings without packet/flow identities.

After reviewing validation scores and complexity, select a compact B/C pair
with an explicit rule. A later step will refit that chosen pair on development
data and prepare a numeric reference for P4 export/replay checks. This tuning
command intentionally does not silently perform those later steps.
