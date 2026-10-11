# Stage 3 - real-PCAP native BMv2 classification demonstration

This stage adds a real-capture classification workflow to the **same** dashboard
and Live Experiment Monitor. The existing synthetic demonstration is preserved.
It does not implement the remaining historical pages or a new benchmark.

## Directory and launch commands

Use your ordinary Ubuntu/WSL terminal, without sudo on Make:

```bash
cd /home/geleza/p4/etc-training
make dashboard-pcap-examples
```

The example-list command reads the bounded metadata-derived catalogue and prints
available IDs and launch instructions. It does not start BMv2 or send packets.

The simplest manual launch is:

```bash
make dashboard-live DEMO=pcap
```

For the PCAP workflow the default is `MODE=compare EXAMPLE=voip`: one selected
held-out eight-packet prefix is replayed separately through RF-B and RF-C.

Explicit selections:

```bash
make dashboard-live DEMO=pcap MODE=rf_b EXAMPLE=voip
make dashboard-live DEMO=pcap MODE=rf_c EXAMPLE=streaming
make dashboard-live DEMO=pcap MODE=compare EXAMPLE=chat
```

Supported model modes are `rf_b`, `rf_c` and `compare`. Catalogue selectors are
`chat`, `ft`, `mail`, `p2p`, `streaming` and `voip`, associated with saved
capture-derived activity hints. They request examples with that provenance,
**not a promised classifier prediction**. Availability is governed by the
existing valid-prefix rules; missing eligible examples are reported rather than
manufactured. There is no automatic whole-dataset or `all` replay.

The current pinned catalogue illustrates why the hint/prediction distinction
matters:

| Example | Capture activity hint | Saved capture-time RF-B / RF-C prediction |
|---|---|---|
| `chat` | CHAT | FT / FT |
| `ft` | FT | FT / FT |
| `mail` | MAIL | P2P / P2P |
| `p2p` | P2P | FT / FT |
| `streaming` | STREAMING | STREAMING / STREAMING |
| `voip` | VOIP | VOIP / VOIP |

These are the catalogue's existing capture-time reference values, **not new
native replay results**. Native timing can change a displayed prediction. The
catalogue deliberately does not choose each class's example by a desired model
outcome, and this small selected demonstration cannot estimate model accuracy.

The launch command safely starts or reuses the same normal-user Streamlit app,
prepares and verifies a new bounded demonstration, and requests terminal sudo
authorization only for its worker. The browser never requests passwords or
launches privileged traffic. A virtual-environment activation is unnecessary:
Make uses the existing `.venv/bin/python` directly.

## Browser workflow

Open **http://localhost:8501** in your existing browser window. Select
**Live Experiment Monitor**, then the real encrypted-PCAP classification view.
The synthetic and PCAP workflows share this page; they are not two applications.
The app stays open after the demonstration so you can inspect the result.

The initial privileged replay is for you to run manually. Unit tests and
nonprivileged packet-file smoke checks cannot establish that actual live-veth
integration succeeds. Do not describe Stage 3 as fully integration-verified
until this trial has completed and its saved evidence has been reviewed.

## What is actually replayed

The primary workflow reuses native-clock pilot/batch infrastructure:

```text
Pinned real PCAP -> one valid held-out N8 prefix -> unchanged raw IPv4 bytes
              -> Ethernet wrapper -> private live veth -> actual BMv2/P4
              -> native feature/leaf/score report -> Python verification
              -> safe final counter read -> saved demonstration evidence
```

Original IPv4 bytes are preserved. Ethernet wrapping allows the raw-IP captures
to pass through the existing Ethernet parser. Feature packet size remains the
original IPv4 `ip.len`, not Ethernet length. The classifier triggers at the
eighth eligible packet, using the frozen feature definitions and ten-tree
fixed-point probability aggregation.

Original within-prefix timing gaps schedule transmission. The feature extractor
uses **actual switch-observed native ingress timestamps**. Packets are not
arbitrarily delayed to animate the screen. Any pause between independent
completed demonstrations is outside their feature windows.

This is replay of stored capture bytes, not capture of new live Internet traffic.
Only the selected opening prefix is sent: background flows and subsequent
packets are omitted. Debug reports support correctness inspection but add bytes
and processing, so this is not a normal-build performance experiment.

## Reading the classification display

| Display | Interpretation |
|---|---|
| Capture/example and activity hint | Saved capture provenance; not independently established per-flow media ground truth. |
| Packet progression | Actual eligible observations where available. It may jump from zero to eight between browser refreshes for a short flow; there is no fabricated animation. |
| Predicted class | The actual P4 decision from CHAT, FT, MAIL, P2P, STREAMING or VOIP. It need not equal the requested example hint. |
| Six class scores | Actual fixed-point RF score totals; not an isolated inference-duration measurement. |
| Eight extracted feature values | Native-switch features; RF-B uses its six size/IAT inputs, RF-C additionally uses the two direction inputs. |
| Ten leaf IDs | Leaves reached by the deployed frozen forest. |
| Python/P4 verification | Reference computation on the relevant observed feature/timestamp data, with feature/leaf/score/class agreement where recorded. |
| Per-class counters | Actual safe boundary reads after classification; absence before the read is not a zero-count claim. |
| Hint agreement | Descriptive comparison with a provisional capture activity label, not independently verified classification accuracy. |

The original capture-time reference and the native-time reference are different
quantities. Arrival timing can change IAT features and therefore predictions.
The dashboard retains that distinction and does not compare P4's native feature
vector to original capture IAT as though it were a timing bug.

In `MODE=compare`, RF-B and RF-C receive the same original prefix in separate
switch executions. They do **not** necessarily observe identical native IATs.
A paired live prediction difference alone is therefore not a controlled estimate
of the contribution of direction. The frozen historical paired model evaluation
remains the evidence for the research ablation.

## Live versus final information

During execution, actual phase/observation events update automatically through
the existing bounded telemetry stream. Completed classification events preserve
the features, leaves, scores, prediction and verification result. Some parity
checks and CLI counters are only definitive at a completed-flow boundary; the
UI labels them accordingly. Delayed or missing classification reports remain
pending or failed rather than becoming invented predictions.

These prefixes are intentionally short. A browser refreshing about once per
second may not show each individual packet separately. Final flow cards and
score plots remain visible after completion, including mismatches or failures.

## Bounded replay monitoring extension

The primary display remains the actual classification: source activity hint,
eight-packet progress, prediction, six scores and Python/P4 verification. A
compact secondary monitoring section shows real packet accounting and available
OS resource observations for the **same** short native replay. The commands and
selected prefix are unchanged; this extension is not a new performance campaign.

Packet counts are associated with their individual RF-B or RF-C replay:

- Live input and output counters mean matched capture observations for that
  model, not global switch traffic.
- Pending input/output matches are unreconciled observations, not lost packets.
- Final sent counts and matching/accounting are definitive only after the replay
  and existing capture drain complete.
- Duplicates, reordering, modified/tagged frames or missing observations are
  retained as actual transport diagnostics. An unavailable capture-socket-drop
  measurement must remain unavailable; it is not assumed to be zero.
- Classification counters remain safe boundary queries. They count one decision
  at packet eight, not eight independent classified flows or semantic accuracy.

Resource cards show sampled BMv2/worker RSS in MiB and OS-accounted CPU where
available. The displayed phase and saved sampling-window identity define exactly
which part of the replay a value covers. Do not interpret resource observations
from preparation, startup, replay, drain or accounting as interchangeable. A
short-lived process, failed read or missing sample is displayed as unavailable,
not substituted with zero.

The implemented sampler window starts at the native replay invocation **after
BMv2 readiness** and stops while that exact owned switch process is still alive,
before Python parity checks, CLI counter reads and switch termination. It covers
socket setup, original-offset packet transmission and bounded capture drain.
It excludes model loading/startup and later verification/accounting. The full
resource reports, observed phase boundaries and final packet accounting are
saved separately in `pcap_monitoring.json` and sealed with the new demo evidence.
Actual resource samples are taken approximately once per second, with real
start/end observations retained for short windows.

CPU percentages use the one-core convention and the saved RAW elapsed interval:

```text
provisional CPU % = 100 * (change in process user + system CPU ticks)
                         / (SC_CLK_TCK * RAW elapsed seconds)
```

The numerator is Linux OS accounting, not independently calibrated physical CPU
time. Values can exceed 100% for a multithreaded process. For these short flows,
accounting-tick quantization can materially affect the result. All such CPU
percentages remain **provisional/demo-only**, with no inherited historical
qualification. RSS is sampled resident memory, not a guaranteed exact peak;
process-lifetime high-water marks are distinct from the current model window.

A current CPU observation can describe the latest actual interval rather than
the entire replay-window average. If that interval crosses from replay into
drain, it must be labeled as mixed; it is not replay-only CPU. The full saved
report retains the separately computed whole-window aggregate. Neither value
measures isolated inference execution.

During replay the card identifies its last observed interval. After completion
it uses the valid whole replay/capture-window CPU aggregate when available,
with that scope stated explicitly. An invalid final resource window hides the
affected role's cards and history graphs; earlier provisional points are not
promoted into a valid completed measurement.

A time-series graph is shown only when at least two **actual, distinct** samples
exist in the same model/resource window. Otherwise the UI shows the available
card values and explains that the prefix is too short for a meaningful curve.
It does not connect RF-B to RF-C, interpolate across phases/windows, pad data,
invent zero samples or extend traffic duration just to populate a chart. The
0.181390-second default VOIP prefix can finish between browser refreshes; that
is expected, not evidence of a stuck dashboard.

Use the unchanged twenty-second synthetic demonstration for sustained live
CPU/memory time-series visualization. The real-PCAP workflow prioritizes actual
classification and short-flow accounting instead of artificially creating a
long performance trace.

These observations describe the instrumented debug replay and its observer
activity. They do **not** isolate RF inference cost, establish direction-feature
overhead, qualify absolute throughput, or provide an ASIC performance estimate.
Frozen research measurements remain separate and unchanged. The first genuine
privileged integration test, including any available resource cards/graphs, is
still for you to execute manually and for us to verify from its saved evidence.

No kernel forwarding-delay percentiles, isolated RF latency, absolute throughput
qualification, maximum capacity or new representative accuracy estimate is
established by this bounded PCAP demonstration.

## Isolation and cancellation

New evidence is written under a separate `results/live_demo/<run_id>` directory.
The frozen models, P4 sources, historical correctness/native/performance runs,
clock settings and numerical gates are not modified or requalified. Preparation
and smoke receipts are bound to the new demo's inputs; old seals are not bypassed.

The synthetic and PCAP launchers use the common experiment-lock strategy. A
second competing run is refused instead of sharing active switch state or
overwriting telemetry. Private interfaces and switch children remain owned by
the worker; there is no manual T1/T2/T3 or `RuntimeCmd:` requirement.

Press **Ctrl+C in the Ubuntu launch terminal** to request cancellation. Wait for
the bounded worker to retain partial evidence and clean up its owned resources.
Do not start another copy during cleanup. The dashboard itself remains open.

```bash
make dashboard-status
make dashboard-stop
```

Status reports the owned dashboard and current telemetry state. Stop targets
only the owned dashboard, not the experiment worker or unrelated services.

## Preserve synthetic operation and run focused tests

The original synthetic selection remains unchanged:

```bash
make dashboard-live MODE=rf_c RATE=250 WORKLOAD=classification-heavy
```

It defaults to `DEMO=synthetic`. PCAP commands do not use `RATE` or `WORKLOAD` to
rescale recorded intra-flow timing.

Focused nonprivileged regression commands:

```bash
make dashboard-test
make dashboard-live-test
make dashboard-pcap-test
```

The third target names the PCAP catalogue, runner, presentation and Makefile
dispatch test modules. The dispatch tests use Make dry-runs and cannot launch
sudo, a switch or packet sender. The shared process manager is unchanged.

Stage 4 historical pages and broad reproduction targets remain deferred. Do not
commit or push this stage without the subsequent project approval.
