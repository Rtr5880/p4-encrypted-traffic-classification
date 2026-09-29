# Preliminary six-class training baseline

This continues the validated flow-instance extractor without changing it or
reading PCAPs again. It is **not** the final scientific accuracy evaluation.

## Where to work

All commands below are for **Ubuntu/WSL**, in:

```text
/home/geleza/p4/etc-training
```

Start with:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training
```

`cd` selects the project directory; `code` opens that directory in VS Code.
The commands use the full virtual-environment Python path, so they work with
or without `(.venv)` in your prompt. No installation is needed.

Open these files in VS Code:

- `/home/geleza/p4/etc-training/tools/train_capture_baseline.py`: implementation.
- `/home/geleza/p4/etc-training/tools/test_train_capture_baseline.py`: synthetic tests.
- `/home/geleza/p4/etc-training/docs/capture-baseline-training.md`: this guide.

## The four steps

```text
Validated extracted records (originals unchanged)
    |
    +-- 1. Keep six provisional capture-derived labels
    +-- 2. Build N4/N8 tables with paired B/C features
    +-- 3. Freeze parent-group splits and verify class coverage
    |       preparation ends here; no models fitted
    |
    +-- 4. Three-fold development validation -> final fit -> held-out test
```

### 1. Labels: what we are actually predicting

The six labels are CHAT, FT, MAIL, P2P, STREAMING and VOIP. They are inherited
from the capture's activity hint. A VOIP capture can contain background traffic;
its label does not prove that each extracted instance carries voice. BROWSING
is not assigned. We do not relabel port 443 as browsing.

This baseline tests the training pipeline and the direction-feature comparison
under these provisional labels. It does not establish final multimedia accuracy.

### 2. Training tables: what the models may see

| Feature set | Model inputs, in order |
| --- | --- |
| B | size_min, size_max, size_sum, iat_min, iat_max, iat_sum |
| C | The same six, then reverse_packet_count, direction_change_count |

Packet size means IPv4 `ip.len` in bytes. IAT is integer microseconds, with
N-1 gaps for N packets; no artificial initial zero. These are the extractor's
existing features, not newly calculated features. Forward means the first
eligible sender of the instance. Short instances were already excluded.

`load_extraction()` verifies the existing extraction output before reading it.
`validate_tables()` checks pairing and feature names. `matrix()` constructs the
numeric array using only the explicit feature list. Capture names, addresses,
IDs, labels and split assignments are never supplied as predictor features.

N4 and N8 are separate experiments, not pooled rows. Each record contains both
B and C, preventing differences in their eligible rows.

### 3. Grouped splitting: what stays together

`make_splits()` uses the parent conversation ID, not just the instance ID.
All timeout/RST-created instances under one parent stay together.

```text
One parent conversation
    instance 1: N4/B, N4/C, N8/B, N8/C  --+
    instance 2: N4/B, N4/C              --+--> same partition and fold
```

The predeclared first fold of five-way StratifiedGroupKFold is the test set
(approximately 20%, not necessarily exactly 20% of rows). The remaining
development data get three grouped validation folds. Every development record
is used once for validation and twice for fitting within that three-fold cycle.

Assignments are derived from N4 and inherited by N8. Every partition and each
training/validation fold must contain all six classes. Failure stops preparation;
the script does not repeatedly try seeds until a desirable score appears.

These splits are **parent-disjoint, not capture-disjoint or verified
session-disjoint**. P2P comes from one capture, so a fully capture-disjoint split
cannot put P2P in both training and testing. Shared capture conditions remain
a possible source of optimism. Grouping addresses one leakage risk; it does not
prevent all leakage or ordinary model overfitting.

### 4. Fit and evaluate

The default `fixed` mode uses depth 5 and 10 trees/rounds for all comparisons.
It produces eight final models: RF/XGB x B/C x N4/N8. Three-fold validation
assesses each fixed configuration; it is not a hyperparameter search in this
mode. This requires 24 validation fits plus eight final fits.

An optional `--search compact` preparation mode fixes a nine-configuration
grid: depths 3/5/7 x trees/rounds 5/10/20. It selects by development macro-F1,
with exact-score ties preferring fewer trees/rounds, then lower depth. Choose
the mode **before** examining held-out test scores; do not switch modes because
of disappointing test results. The compact mode needs 224 fits in total.

RF uses balanced class weights. XGBoost gets equivalent per-row weights derived
only from the labels in the current fitting subset. Validation and test scores
remain unweighted. There is no scaling, resampling, early stopping or GPU use;
fitting uses two CPU threads. Library defaults not explicitly overridden are
fixed by the recorded package versions and the saved models' parameters.

XGBoost uses one tree per class per round: six classes and ten rounds means
60 trees, not ten. Actual tree count, depth, nodes, leaves and serialized file
size are measured. These are useful complexity measures, not a P4 resource
budget or proof of deployability.

`select_configuration()` accepts only development rows. All eight selections
are saved before any held-out prediction is evaluated. Each selected model is
refit using all development rows and then evaluated on its test rows.

## Commands and what they do

First, run the focused tests in `/home/geleza/p4/etc-training`:

```bash
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover \
  -s /home/geleza/p4/etc-training/tools \
  -p 'test_train_capture_baseline.py' -v
```

These use synthetic data to test grouping, pairing, input integrity, class
weights, real RF/XGB fitting, model save/reload and failure handling. Their
scores are not dataset results. Success ends with `OK`.

Next, prepare from the existing validated extraction:

```bash
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/train_capture_baseline.py prepare \
  --extraction-run /home/geleza/p4/etc-training/results/flow_instances/20260929T111314Z_e8151a1c48
```

This validates saved arithmetic/accounting, creates paired tables and freezes
splits. It does not retrain, reread PCAPs or alter original evidence. Expect
`PREPARATION PASS` and a new `Prepared directory:` path. Open that directory's
`split_summary.json` to review class counts and its `manifest.json` for features,
configuration, versions and provenance. Preparation does not verify labels.

To train, replace the quoted example path below with the exact printed
preparation directory. Do not type the placeholder literally:

```bash
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/train_capture_baseline.py train \
  --prepared '/home/geleza/p4/etc-training/results/baseline_preparation/REPLACE_WITH_PRINTED_RUN'
```

This performs development validation, final fitting, held-out evaluation and
save/reload checks. It prints each experiment's scores and a results directory.
Wait for `TRAINING COMPLETE — PRELIMINARY`; partial output after an error is not
a completed evaluation. Share the eight score lines and final results path.

## Outputs and interpretation

Each experiment saves a model, `metrics.json`, `test_predictions.jsonl`, and
`confusion_matrix.png`. The run root contains `report.md`, `summary.json`,
`selection.json`, `cv_results.json`, `cv_progress.jsonl`, and `run_config.json`.
Metrics include accuracy, macro-F1, per-class precision/recall/F1 and support.
Confusion matrices have true capture-derived classes in rows and predictions
in columns. Compare B and C within the same N and learner.

Fold standard deviations are descriptive variation, not confidence intervals.
N4 and N8 have different eligible instance sets, so their score difference is
not purely the effect of observing four more packets. Likewise, a positive
C-minus-B difference on this one split is not proof of a general improvement.

Saved/reloaded model predictions must agree. This is Python-model parity only;
floating-point tree thresholds and boosted scores still need a separate,
explicit integer/fixed-point P4 conversion and inference-parity evaluation.

Preparation records SHA-256 fingerprints of source inputs, prepared payloads,
code and package versions. If the code or ML environment changes, prepare
again; do not manually edit the manifest to bypass the checks. New runs use
new directories and do not overwrite old results. A failure leaves `failure.json`.

The existing Git ignore rules keep generated `results/` and model artifacts
out of the repository. Only the new source, tests and this guide need review
for a later commit. Nothing here commits or pushes automatically. Only load
your own trusted serialized RF/joblib models; untrusted pickle/joblib files
can execute code.
