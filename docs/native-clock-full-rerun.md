# Fresh full native-clock rerun — 7 October 2026

The corrected switch and the clean LIVE pilot have passed their checks. The
fresh full preparation and non-root all-record integration checks are complete.
**The paced full live rerun has not run yet.** The student runs it below.

## Already verified

- Clean live pilot: `/home/geleza/p4/etc-training/results/native_clock_pilot/20261007T181437Z_f0e10808b5`.
- Corrected clock receipt: `/home/geleza/p4/etc-training/results/bmv2_clock_repair/20261007T180912Z/clock_receipt.json`.
- Actual compiled BMv2 ELF still matches the verified `steady_clock` build.
- Fresh preparation: `/home/geleza/p4/etc-training/results/native_evaluation_preparation/20261007T182217Z_a93176dc1f`.
- Unpaced packet-file integration: `/home/geleza/p4/etc-training/results/native_evaluation_checks/20261007T182340Z_c77dc801a7`.
- Both models checked all **398 cases / 3,184 packets** in packet-file mode, with
  zero state/feature/leaf/score/prediction mismatches. Original frozen sklearn
  models also matched integer inference on these newly observed vectors.
- No model fitting, hyperparameter selection, relabelling, new features or
  split changes. Original within-prefix gaps are not scaled.

The fresh manifest uses `native-evaluation-v2` and binds the preparation to
that exact live pilot, clock receipt, source files, original packets and native
P4 builds. Do not reuse the old pre-repair full preparation.

## Population and scope

| Frozen provisional class | Cases per model |
|---|---:|
| CHAT | 35 |
| FT | 104 |
| MAIL | 29 |
| P2P | 48 |
| STREAMING | 77 |
| VOIP | 105 |
| **Total** | **398** |

RF-B and RF-C receive the same 398 original N=8 held-out examples: **796
model-case evaluations and 6,368 total intended packets**. The models remain
ten-tree, depth-seven RFs. B consumes six size/IAT statistics; C adds reverse
packet count and direction-change count. The running-max feature policy is
unchanged; raw regressions are separately audited.

There are 13 batches/model, up to 32 cases/batch. Keys, parent IDs and CRC slots
are disjoint within a batch, and each batch/model starts a fresh switch. Different
prefixes overlap in time, but every original within-prefix gap is preserved.
This is isolated-prefix evaluation, not a replay of all original background
traffic or a natural collision-capacity benchmark.

## What YOU run now

Use **one Ubuntu/WSL terminal**. Execute in:

```text
geleza@DESKTOP-8QLC84Q:~/p4/etc-training$
```

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/run_native_evaluation.py run \
  --prepared /home/geleza/p4/etc-training/results/native_evaluation_preparation/20261007T182217Z_a93176dc1f
```

Purpose: evaluate all frozen held-out prefixes using actual ingress timestamps
from the corrected switch. The runner captures real outputs, independently
reconstructs state/inference and computes preliminary classification metrics.

The explicit Python path chooses the project environment; activation is not
required. Enter your Ubuntu sudo password yourself. Root access is needed for
private veth interfaces and raw sockets. No manually started T1/T2 switch or CLI
session is necessary. The script manages and cleans only its own resources.

Do not start a second copy while it is running. About **11.78 minutes of packet
scheduling** are planned for both models combined, plus loading, switch startup,
capture draining, counter queries and verification. This is not an exact ETA.

The first scheduled batch takes **135.93 seconds per model**; the second takes
72.45 seconds per model. A pause after the new message below is therefore normal:

```text
Starting batch 1/13, RF-B: 32 cases; preserved schedule 135.93s
(progress next prints after this batch)
```

Expected successful batch completion:

```text
Batch 1/13, RF-B: verified/classified 32/32; total accounted 32/796
```

The final batch has 14 cases/model. A complete accepted run should end with:

```text
NATIVE EVALUATION PASS
Evidence saved to: /home/geleza/p4/etc-training/results/native_evaluation/...
Metrics: .../metrics.json
```

Paste the final terminal output and exact new evidence directory into the chat.
The output goes to a NEW unique directory; earlier incomplete and pilot results
are not overwritten. `NATIVE EVALUATION INCOMPLETE` also retains useful evidence:
do not delete it or silently remove failed cases. Report it for investigation.

## What we must inspect after the rerun

| Area | Required check |
|---|---|
| Population | All 398 original IDs accounted for each model; no hidden exclusions. |
| Delivery | Eight input/output occurrences per case; missing/corrupt/reordered frames reported. |
| Parity | Matching state, features, ten leaves, six scores and class on observed-time oracle. |
| RF fidelity | Original sklearn model agrees with the integer export on newly observed vectors. |
| Clock quality | No raw regressions within a case OR across the input-ordered batch. |
| Timing fidelity | Gap/span deviations remain plausible across short and long prefixes. |
| Classification | Accuracy, macro/weighted F1, per-class P/R/F1 and confusion matrices. |
| Fair comparisons | Same case IDs for B/C and capture/native changes. |
| Counters | All six class packet/byte totals reconcile. |
| Cleanup | Owned children stopped and temporary links removed. |

`summary.json` includes `raw_clock_clean`; `metrics.json` includes per-case/model
clock quality and timing statistics. Each batch has `batch_clock_quality.json`,
`transport.json`, `counter_check.json` and packet reports.

A stage PASS requires full classified/parity coverage, clean clocks, numerical
fidelity, successful execution and cleanup. A backward clock can now be
parity-valid under the existing running-max policy, but it still prevents a
clean full-stage PASS. Missing quality evidence is not treated as clean.

The timing review must go beyond the zero-regression count: examine signed and
absolute IAT deviations, median/p95/p99/maximum, sender lateness, first-to-eighth
span errors and longer prefixes. We have not invented an arbitrary universal
jitter tolerance. A large deviation requires investigation even if the raw
clock stayed monotonic. Scheduling/IAT deviations are NOT forwarding or RF
execution latency.

## Research limitations and next boundary

Capture-derived labels are still provisional flow activity hints; the held-out
set was already inspected. Separate live B/C runs have different actual timing.
Same-vector Python predictions are diagnostics, not additional live outputs.

These builds still use `DEBUG_REPORT=1`, `TEST_TIMESTAMPS=0`, `FLOW_SLOTS=65536`.
Debug headers/work mean this is not a normal-build performance benchmark. The
performance benchmark and timing-robust model refinement remain postponed until
the complete native evidence has been reviewed. A clean clock does not promise
that STREAMING/FT accuracy will automatically increase.

No new commits or pushes were made. This preparation reused tested source;
all new clock/evaluation sources and guides remain uncommitted for review.
