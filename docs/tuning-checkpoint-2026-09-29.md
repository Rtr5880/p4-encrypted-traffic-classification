# Baseline and development-tuning checkpoint — 29 September 2026

## Status

The existing six-class capture-labelled baseline is preserved. The first
development-only tuning run completed, with no feature changes, no new test
scores and no new final models. This note records aggregate results only;
packet captures, per-instance records and generated models remain outside Git.

Evidence directories under `/home/geleza/p4/etc-training/results/`:

- Preparation: `baseline_preparation/20260929T124705Z_4c1cb93953`.
- Original baseline: `baseline_training/20260929T171836Z_164b1c299f`.
- Development-only tuning: `baseline_tuning/20260929T190215Z_8fb596d3f3`.

These paths are local provenance references, not files shipped with this repo.

## Experiment and checks

- B: size minimum/maximum/sum and IAT minimum/maximum/sum.
- C: B plus reverse-packet count and direction-change count.
- N4/N8 remain separate. Original parent-group assignments and folds reused.
- N4: 2,019 development records; 507 test records excluded from scoring/fitting.
- N8: 1,683 development records; 398 test records excluded from scoring/fitting.
- Fixed grid: depth 3/5/7 x trees/rounds 5/10/20.
- Eight experiments x nine configurations x three folds = 216 fits.
- No automatic final-model refitting, export or deployment selection.
- All 173 automated tests passed, including 15 new tuning tests.
- Independent audit reconciled 72 candidate results and 216 fold results.
- The original depth-5/count-10 configuration reproduced all original baseline
  development-fold macro-F1 scores to within 1e-12.
- Fingerprints of 47 preparation/baseline files matched before and after tuning.
- Total measured fitting time: approximately 6.36 seconds, excluding other work.

## Highest mean development macro-F1 within this grid

These are **validation** values, not held-out accuracy. The baseline column is
the original configuration evaluated on the same development folds.

| Experiment | Baseline CV F1 | Best CV F1 | Fold SD of best | Actual trees | Mean fold leaves |
| --- | ---: | ---: | ---: | ---: | ---: |
| N4 RF-B | 0.7305 | 0.7832 | 0.0105 | 20 | 1247.3 |
| N4 RF-C | 0.7242 | 0.7791 | 0.0144 | 20 | 1305.3 |
| N4 XGB-B | 0.7809 | 0.8003 | 0.0134 | 120 | 3904.3 |
| N4 XGB-C | 0.7816 | 0.7995 | 0.0202 | 120 | 3808.7 |
| N8 RF-B | 0.7327 | 0.8079 | 0.0042 | 20 | 929.3 |
| N8 RF-C | 0.7620 | 0.8312 | 0.0151 | 20 | 1034.3 |
| N8 XGB-B | 0.8133 | 0.8444 | 0.0154 | 120 | 3026.3 |
| N8 XGB-C | 0.8130 | 0.8489 | 0.0154 | 120 | 3081.0 |

All eight leaders used depth limit 7 and count parameter 20. XGBoost uses six
trees per round in this six-class configuration, hence 120 actual trees. These
leaders are at the tested grid boundary; they are not globally optimal models
or confirmed P4 deployment choices. Model sizes above describe fold-trained
models, not an exported final refit.

At these matched depth-7/count-20 settings, C-minus-B mean validation F1 was
-0.0041 (N4 RF), -0.0008 (N4 XGB), +0.0233 (N8 RF) and +0.0045 (N8 XGB).
Direction's benefit remains conditional on window/learner. Small differences
are not established statistical improvements. Fold SD is not a confidence
interval.

## Interpretation and next step

The search demonstrates that the original small configuration was not the
highest-scoring one within this grid on these development folds. Its inclusion
in the grid guarantees the selected validation maximum cannot be lower; this
does not guarantee improved unseen-data performance.

The next decision is a compact B/C pair balancing development performance and
model cost, followed by a separately recorded development-data refit and P4
conversion/parity work. For example, N8 RF-C has CV F1 0.8312 with 20 trees,
whereas N8 XGB-C has 0.8489 with 120 trees; actual P4 table/state costs still
need to be measured. This note does not select one or claim deployability.

Limitations remain: capture-derived rather than independently verified activity
labels; parent-disjoint, not capture/session-disjoint evaluation; one P2P capture;
different eligible populations for N4/N8; and an already-inspected old test set.
Selection and reporting must not mistake tuning validation scores for final
generalisation evidence. No new result establishes in-switch accuracy.
