# Native-clock evaluation of all 398 held-out prefixes

> Historical pre-repair handoff. BMv2 and the validators were corrected on
> 7 October 2026. Do not reuse the old preparation/commands below for a new run.
> Follow [the clock repair and fresh pilot guide](native-clock-repair.md) first.
> Full preparation now requires a verified clean live pilot and clock receipt.

This stage replays the opening eight eligible packets from **every frozen N8
test record** through RF-B and RF-C using BMv2's actual ingress timestamps.
It does not train, tune, relabel or change the models. It is an isolated-prefix
classification/correctness evaluation, **not a throughput or latency benchmark**.

## Verified handoff on 7 October 2026

- All 398 frozen held-out records passed original-byte/feature preparation.
- Both native-clock debug P4 builds compiled successfully.
- The complete project unit suite ran 365 tests: 364 passed, one optional
  Scapy-dependent test was skipped in the training environment. The new live
  transport itself does not require Scapy.
- Non-root packet-file integration checked **398 RF-B and 398 RF-C cases**
  (3,184 packets per model), with zero state/feature/leaf/score/class mismatches.
- Original frozen scikit-learn models also matched their integer references
  on all 398 observed packet-file vectors for each model.
- The **paced live evaluation has not run yet**. Ubuntu requires your sudo
  password; enter it yourself when running Step 3 below. Do not send it to chat.

Verified preparation:

```text
/home/geleza/p4/etc-training/results/native_evaluation_preparation/20261007T165532Z_e495756512
```

Verified unpaced integration evidence:

```text
/home/geleza/p4/etc-training/results/native_evaluation_checks/20261007T165714Z_cf24f22d80
```

Start at **Step 3: Run** below. Source files, tests and the guide remain
uncommitted so you can review them first.

```text
398 frozen test records, original packet bytes and within-prefix gaps
                  |
       separately replay RF-B and RF-C
                  |
 actual BMv2 ingress times + independent Python state/inference oracle
                  |
 coverage + parity + preliminary capture-label classification metrics
```

## Where to run every command

Use an **Ubuntu/WSL terminal**, with this project directory:

```text
geleza@DESKTOP-8QLC84Q:~/p4/etc-training$
```

Each command below starts with `cd` to make the directory explicit. A virtual
environment is not a directory you must work inside: the explicit
`/home/geleza/p4/etc-training/.venv/bin/python` selects the training environment
whether your prompt currently shows `(.venv)` or not. Do not run these commands
in Windows PowerShell, `p4c`, or `smoke-test`.

There is no requirement to install Scapy. The live sender/capture uses Linux
AF_PACKET sockets through Python's standard library. `sudo` is needed only for
the live `run` stage, because it creates private virtual interfaces and opens
raw packet sockets.

## What is included

| Frozen provisional label | Test records |
|---|---:|
| CHAT | 35 |
| FT | 104 |
| MAIL | 29 |
| P2P | 48 |
| STREAMING | 77 |
| VOIP | 105 |
| **Total per model** | **398** |

RF-B and RF-C each receive these same 398 original records: **796 model-case
evaluations and 3,184 intended input packets per model**. No record is silently
removed because it is TCP, unidirectional, longer than two seconds, or a later
instance. The small pilot's structural restrictions do not apply here.

The default plan has **13 batches per model**, with at most 32 independent
prefixes in a batch. A batch cannot contain repeated bidirectional tuples,
parent-conversation IDs or CRC state slots. Every batch/model starts a fresh
private switch, so one prefix cannot inherit another instance's old state.

Prefixes overlap in time to avoid an approximately 83-minute sequential replay
per model. Original gaps **within each prefix** are preserved; the start offset
between independent prefixes is scheduling metadata. No gaps are compressed or
scaled, and no packet is padded, duplicated or trimmed to force classification.
The default plan schedules approximately **11.78 minutes across both models**,
plus switch startup, capture draining, counter queries and verification.
The preparation output records the exact plan and scheduled duration.

This deliberately omits full-capture background traffic, previous packets and
later packets. Do not describe it as chronological replay of all 29 captures or
as a measurement of natural deployment collision coverage.

## The source files to review

Open the project in VS Code from the Ubuntu terminal:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training
```

| File under `/home/geleza/p4/etc-training` | Purpose |
|---|---|
| `tools/prepare_native_evaluation.py` | Verifies all frozen records and original packet bytes; plans disjoint batches. |
| `tools/native_evaluation_transport.py` | Schedules sends and captures exact tagged packets, detecting loss, corruption, duplicates and reordering. |
| `tools/analyze_native_evaluation.py` | Independently reconstructs native-time state and RF inference; calculates metrics with explicit denominators. |
| `tools/run_native_evaluation.py` | Implements `prepare`, `smoke` and `run`; manages private switches, counters, evidence and cleanup. |
| `tools/test_prepare_native_evaluation.py` | Tests population preservation, raw-byte checks and batching rules. |
| `tools/test_native_evaluation_transport.py` | Tests transport accounting and scheduling without live traffic. |
| `tools/test_analyze_native_evaluation.py` | Tests parity, native boundary changes, failed-case accounting and metric denominators. |
| `tools/test_run_native_evaluation.py` | Tests stage integration, counter checks, evidence and orchestration. |

The new source, tests and this guide remain **uncommitted for review**. Raw
captures, environments, generated results and builds should not be added to Git.

To run the new non-live tests yourself:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover \
  -s /home/geleza/p4/etc-training/tools \
  -p 'test_*native_evaluation*.py' \
  -v
```

This checks the implementation's fixture behaviour. It does **not** send live
traffic or produce the 398-record native accuracy results.

## 1. Prepare: original data checks and separate native builds

Run in the Ubuntu terminal, without `sudo`:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/run_native_evaluation.py prepare
```

Preparation reads the frozen split, extraction records, original PCAPs and
deployed RF artifacts. It confirms the same 398 test records, reproduces their
original B/C features, seals input hashes, and compiles **separate** native debug
builds with:

```text
TEST_TIMESTAMPS=0   actual switch ingress time; no injected capture timestamps
DEBUG_REPORT=1     feature/leaf/score reports for correctness checks
FLOW_SLOTS=65536   unchanged state-table configuration
```

The existing P4 sources, model files, test assignments and earlier evidence are
not overwritten. This stage creates a new evidence directory. Expect a
`PREPARATION PASS` message, a 398-record/13-batch count with defaults, and:

```text
Evidence saved to: /home/geleza/p4/etc-training/results/native_evaluation_preparation/...
```

**The preparation below was created and verified on 7 October 2026.** Reuse it
for the remaining commands; rerunning preparation is not necessary while the
frozen inputs and source remain unchanged. If you deliberately create a new
preparation later, substitute its printed evidence directory.

```text
/home/geleza/p4/etc-training/results/native_evaluation_preparation/20261007T165532Z_e495756512
```

## 2. Smoke: unpaced packet-file integration, not live evaluation

Run without `sudo`, using the actual prepared directory:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/run_native_evaluation.py smoke \
  --prepared /home/geleza/p4/etc-training/results/native_evaluation_preparation/20261007T165532Z_e495756512
```

This checks all 398 original prefixes per model through the compiled BMv2
programs in **packet-file mode**. It verifies packet bytes, state, features,
leaves, scores and classes against the actual timestamps of that file-mode run.
It does not open live interfaces, preserve real-time pacing or score aggregate
accuracy/F1. Native-clock file-mode timestamps are not a substitute for live
packet-arrival timing.

The checks also compare the integer inference representation against the
original frozen scikit-learn RF on the observed vectors. Only the already
hash-verified, trusted model artifacts created by this project are loaded; no
downloaded or untrusted model files are used, and no model is fitted again.

Expect `PACKET-FILE INTEGRATION PASS` and a new directory under:

```text
/home/geleza/p4/etc-training/results/native_evaluation_checks/
```

If this check was already run and verified on the unchanged sources/preparation,
you can proceed to the live stage. A smoke pass is an integration prerequisite,
not proof of live classification quality or runtime performance.

## 3. Run: live native-clock evaluation

Use one Ubuntu terminal. No manual T1/T2 switch or CLI session is needed; the
runner creates its own private switch children and reads their counters.

```bash
cd /home/geleza/p4/etc-training
sudo /home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/run_native_evaluation.py run \
  --prepared /home/geleza/p4/etc-training/results/native_evaluation_preparation/20261007T165532Z_e495756512
```

The password prompt is for your **Ubuntu sudo password**, not GitHub. `sudo`
grants the runner access to temporary veth interfaces and raw packet sockets.
It still uses the explicit project environment's Python and the frozen models.

The runner:

1. Creates only new, uniquely named temporary veth pairs.
2. Starts one private BMv2 process per batch/model with a private Thrift port.
3. Sends all eight unchanged IP packets per prefix at their original relative gaps.
4. Captures and associates reports using case-specific Ethernet tags, not potentially repeated IPv4 IDs.
5. Reconstructs expected state and inference using actual BMv2 ingress times.
6. Reconciles all six decision-counter packet and byte totals when complete reports permit it.
7. Stops only its own child processes and removes only ownership-verified temporary links.

Your existing `p1_*` demonstration interfaces and other running switches are not
reconfigured or killed. No packets are intentionally routed onto an external
network. Root-created evidence is returned to the invoking student's ownership.

B/C run order alternates between batches to reduce a systematic order effect.
This initial evaluation has **one repetition**; it does not establish repeated-run
confidence intervals.

Expect progress such as:

```text
Batch 1/13, RF-B: verified/classified 32/32; total accounted 32/796
```

The last batch may have fewer cases. A complete pass requires all 796 intended
model-case evaluations to be verified and classified, successful cleanup and no
unresolved execution/transport or original-model fidelity errors. Final evidence goes under:

```text
/home/geleza/p4/etc-training/results/native_evaluation/
```

If the run reports `NATIVE EVALUATION INCOMPLETE`, the evidence is still useful:
inspect the explicit missing, failed, unclassified or unattempted cases. Do not
present the reduced population as an unexplained 398-record success. Ctrl+C
requests bounded cleanup; cases never reached are recorded as `not_attempted`.

## What the independent parity check means

For each case, the Python oracle gets **only the observed ingress timestamp**
from P4. It independently decodes the original raw IP/TCP/UDP packet bytes and
reconstructs eligibility, session boundaries, packet counts and all eight shared
features. It does not copy reported feature values or effective timestamps into
its expected result.

At actual oracle decision events, it compares:

```text
instance state + eight extracted features
                 -> ten tree leaf IDs
                 -> six fixed-point probability score sums
                 -> final predicted class
```

RF-B consumes the six size/IAT features; RF-C consumes those six plus reverse
packet count and direction-change count. Both use the frozen ten-tree RF
probability-aggregation classifier, not hard majority voting.

An additional numerical-fidelity check compares the original sealed
scikit-learn model with the integer reference on newly observed native vectors,
including tree leaves, probabilities and predictions. The
`original_sklearn_to_integer_native_vector_parity` report records this result;
a conversion disagreement prevents a full pass. It is a check of the existing
classifier, not retraining or tuning.

The **original record ID** identifies the frozen held-out example. A fresh
isolated switch/oracle starts its local instance counter at 1. An original
later instance therefore has a different local ID, while its immutable source
record ID remains attached to the outcome. That is expected, not leaked state.

Native timing can legitimately change a tree path or class. A prediction change
is not a parity bug if Python and P4 agree when using the **same actual ingress
times**. A native gap crossing the 60-second idle threshold can instead split a
prefix, preventing any eight-packet decision. Such a case may have correct state
parity but be explicitly **unclassified**; it remains in the coverage denominator.

## Reading the saved results

| Artifact inside the live evidence directory | What to inspect |
|---|---|
| `summary.json` | Complete/incomplete status, expected 796 evaluations, cleanup, limitations and output hashes. |
| `metrics.json` | RF-B/C coverage, accuracy, macro-F1, per-class precision/recall/F1, confusion matrices, matched comparisons and timing deviations. |
| `outcomes.jsonl` | One outcome for every original record/model, including failures and unattempted cases. |
| `offline_shared_vectors.jsonl` | Both frozen forests evaluated in Python on each same observed feature vector; diagnostic only. |
| `batch_.../transport.json` | Sender/capture accounting, duplicates, loss, scheduling lateness and raw reports. |
| `batch_.../counter_check.json` | Actual versus expected six-class counter totals, or why reconciliation could not be completed. |
| `batch_.../switch.log` | Private switch startup or failure diagnostics. |
| `provenance.json` | Environment, switch hash, preparation, run order and timing/build choices. |

For metrics, keep these denominators separate:

| Measurement | Denominator |
|---|---|
| Classification coverage | All **398 intended records** for that model. |
| Conditional accuracy / F1 | Only that model's verified, classified records. |
| Correct-decision rate | Correct verified decisions divided by **398**, including abstentions/failures in the expected population. |
| Main paired RF-B/C comparison | The same intersection of verified, classified record IDs for both models. |
| Capture-time versus native-time comparison | Exactly the same available record IDs; never a different population. |

An empty verified/classified population has **no accuracy/F1 value**, not a
perfect score. Failed cases are excluded from conditional metrics but never
silently removed from coverage. Fixed six-class reporting keeps class order and
supports explicit, including classes with zero available support.

Per-class confusion-matrix rows are reference labels and columns are predictions.
Changes from capture-time inference include errors corrected and errors newly
introduced; a model can improve overall while worsening a particular class.

## What these results do not establish

- Labels are provisional capture-activity labels, not independently verified activity for every flow.
- The held-out set was already inspected in previous work. This is not a new untouched external benchmark.
- No fitting, hyperparameter search or feature selection is performed; do not tune to the new test scores.
- Separate B/C live runs have slightly different arrival timing. Their native accuracy difference is not a perfectly controlled direction-only effect.
- `offline_shared_vectors.jsonl` helps compare the two forests on identical observed vectors, but its predictions are **offline diagnostics**, not additional live switch outputs.
- Scheduling/ingress IAT deviations and first-to-eighth observation durations are **not forwarding latency or RF inference time**.
- Debug headers add packet bytes and work. Throughput, packet loss under increasing offered load, forwarding latency, CPU and memory benchmarking require the later normal `DEBUG_REPORT=0` stage.
- Results describe this BMv2/WSL computer, not physical-switch line-rate performance.

After the live evaluation, review the complete evidence and metrics before
moving to the separately scoped performance benchmark. Leave the new sources
uncommitted until you have reviewed them and explicitly choose to commit.
