# Stage 2 - one dashboard with a bounded live BMv2 demonstration

Stage 2 adds the synthetic monitoring vertical slice only. It retains the same
Streamlit application and frozen historical pages. The browser remains
read-only: privileged experiments are authorized in the Ubuntu terminal.

Stage 3 now adds a separate real-PCAP classification workflow in the same live
page. See [dashboard-stage3.md](dashboard-stage3.md); the synthetic commands and
scientific limitations below remain unchanged.

## Directory and environment

Run these commands in your ordinary Ubuntu/WSL terminal:

```bash
cd /home/geleza/p4/etc-training
```

No virtual-environment activation is required: Make uses the existing
`.venv/bin/python`. Do **not** prefix Make commands with sudo. Only the worker
launched after preparation and checks requests sudo in this terminal.

## Open or reuse the same dashboard

```bash
make dashboard
make dashboard-status
```

`make dashboard` starts the dashboard detached or safely reuses the existing
owned app. It prints **http://localhost:8501**. Open that URL in your Windows
browser and select **Live Experiment Monitor**. You do not need another
dashboard, browser window, manual BMv2 terminal or `RuntimeCmd:` session.

The manager verifies user ID, PID start time, exact Streamlit command, listening
socket and HTTP health. It can adopt the exact healthy Stage 1 app owned by the
same user; an unrelated service on the port is not stopped or replaced.

```bash
make dashboard-evidence-status
```

This separate read-only command checks the pinned historical files and schemas.
Verified file identity is not a new scientific PASS or clock qualification.

## Launch your first genuine trial manually

Default RF-C trial:

```bash
make dashboard-live
```

Explicit selection:

```bash
make dashboard-live MODE=rf_c RATE=250 WORKLOAD=classification-heavy
```

Alternative:

```bash
make dashboard-live MODE=rf_b RATE=500 WORKLOAD=cached-forwarding
```

These commands start/reuse the normal-user dashboard, validate bounded inputs,
prepare a new demo, execute nonprivileged smoke checks and then request terminal
sudo authorization for the experiment worker. The worker processes real packets
through the selected compiled P4/BMv2 configuration. It uses five seconds of
disjoint warm-up, twenty seconds of measurement and capture drain/accounting.

Supported modes are `forwarding`, `features`, `rf_b` and `rf_c`. Supported rates
are the bounded common range 100, 250, 500 and 1,000 pps. Supported workloads are
`classification-heavy` and `cached-forwarding`. One selected trial is the
default; no historical 160-trial campaign is restarted.

The first privileged live integration trial is for **you** to execute. Passing
unit tests and packet-file smoke checks does not establish that the real live
charts work until this manual trial succeeds.

## What you should see

The Live Monitor shows preparation, switch startup, warm-up, measurement,
drain/accounting and terminal completion/failure. Approximately one-second
samples update packet-observation and resource charts automatically.

| During the run | Scientific meaning |
|---|---|
| Captured input/output counts and rates | Actual userspace capture observations; rates are provisional/demo-only. |
| Pending matches | Packets not yet reconciled, **not** declared lost. |
| BMv2 and runner CPU trends | OS-accounted one-core percentages, provisional unless the independent timing requirements pass. |
| BMv2 and runner RSS | Sampled resident memory in MiB; not a guaranteed exact peak. |
| Resource warm-up gap | Resource observations may not be collected during warm-up; absent data is not zero. |
| Exact sender and pacing statistics | Available after the sending phase, not invented during native C sending. |
| RF per-class counters and completion | Collected at safe phase/trial boundaries, not polled once per packet. Synthetic predictions do not measure classification accuracy. |
| Final delivery and capture drops | Declared only after drain and validated matching/accounting. Capture loss is separate from observed path non-delivery. |
| Final measurement and clock verdicts | Preserve existing gates; no old calibration certificate is inherited. |

New runs use a separate `results/live_demo/<run_id>` directory. Append-only JSONL
events and atomic snapshots are presentation telemetry. Authoritative saved
measurement, counter and resource evidence remains the source of truth. The
dashboard handles incomplete records and stale/interrupted sessions without
fabricating final verdicts. It remains open and preserves available graphs when
the trial finishes or the browser is closed and reopened.

This short session may be independently timing-INCONCLUSIVE because the
existing reference protocol requires a longer observation span. Simultaneous
Streamlit activity and telemetry are recorded as potential observer effects.
No qualified forwarding-delay percentiles, isolated RF latency, maximum capacity
or synthetic classification accuracy are claimed.

## Implemented telemetry architecture

The existing RAW capture ledger and resource samplers are observed only inside
the dedicated single-trial demo process. Approximately once per second, a
separate observer copies scalar capture counts and the existing resource cache.
It does not rescan packet arrays or poll the switch CLI during measurement.
A bounded queue sends these small records to one background JSONL writer.

Each run has its own sequential event stream, atomically replaced snapshot,
session and Linux boot identity. The separate current-run pointer lets the same
read-only Streamlit fragment find a run when the browser is reopened. RAW is the
elapsed/heartbeat domain; wall time is only a display label. Queue drops, I/O
failures and stale or interrupted sessions are explicit, not silently repaired.
CPU/RSS graphs use the original resource-sample timestamps and do not add fake
drain-phase points from retained readings. Cards can retain last-known values.

## Source changes and verification

Created files (all under `/home/geleza/p4/etc-training`):

```text
tools/dashboard_process.py
tools/live_telemetry.py
tools/live_demo_transport.py
tools/run_live_demo.py
dashboard/live_evidence.py
tools/test_dashboard_process.py
tools/test_live_telemetry.py
tools/test_live_demo_transport.py
tools/test_run_live_demo.py
tools/test_live_dashboard.py
docs/dashboard-stage2.md
```

Modified Stage 1 additions only: `Makefile`, `dashboard/app.py`,
`dashboard/views/live.py`, `tools/test_dashboard_app.py` and the Stage 1 guide.
No new dashboard dependencies were required. Existing research runners, native
C sender, frozen models/P4, synchronization and measurement thresholds were
not changed. Nothing was committed or pushed.

Implementation checks passed: 58 retained Stage 1 tests, 86 Stage 2 tests, all
24 pinned evidence files, and eight nonprivileged normal-build packet-file smoke
cases (512/512 exact frames, with matching applicable RF counters).

The ready preparation and smoke checks are:

```text
/home/geleza/p4/etc-training/results/live_demo_preparation/20261010T010153Z_ba51641da7
/home/geleza/p4/etc-training/results/live_demo_checks/20261010T010205Z_b652e30b7e
```

Their final seals verified 370 current source/input hashes and the four frozen
normal-build programs. The default live plan contains 1,250 disjoint warm-up
packets, 5,000 measurement packets and 624 expected RF packet-eight decisions.
Warm-up and measurement share no state-table slots. Launching through Make
creates a fresh sealed preparation/check/run rather than overwriting these.

An initial legacy 320-frame immediate packet-file burst failed and remains
preserved at:

```text
/home/geleza/p4/etc-training/results/live_demo_packet_file_checks/20261010T005621Z_ead1cd0c9e
```

The demo-specific smoke is explicitly a smaller 64-frame byte/counter check,
with one logical concurrent flow for its cached-forwarding case so cached
packets are exercised. It is not a timing, load or warm-up-state qualification.
The actual live workload still uses the original eight-flow concurrency and
unchanged native pacing. No switch queue was changed to make a test pass.

The historical source preparation also references a changed, unused offline
aggregate-analysis script. Fresh demo provenance records its original/current
hashes and pins its current identity; every frozen/runtime input remains strict.
The old manifest was not modified and the historical calibration was not
retroactively requalified.

The first privileged BMv2/telemetry integration trial has **not** been run by the
assistant. True chart updates, actual delivery, cancellation under live load and
final runtime verdicts must still be checked after your manual demonstration.

## Stop and interrupt safely

While `make dashboard-live` is running, press **Ctrl+C in that Ubuntu terminal**
to request worker cancellation. The launcher forwards the interruption to its
owned worker; the worker retains partial evidence and attempts owned-switch and
private-interface cleanup. Do not launch another copy while cleanup completes.
Inspect the terminal message and `make dashboard-status` afterward.

The dashboard remains open after a demo. To stop **only** the owned dashboard:

```bash
make dashboard-stop
```

That command does not stop a running experiment worker or any unrelated
service. If you stop the browser/server during a demo, the worker can continue;
use the launch terminal for cancellation. Start the dashboard again to inspect
the preserved telemetry and results.

## Focused verification

```bash
make dashboard-test
make dashboard-live-test
```

The first target retains the named Stage 1 regression modules. The second runs
only the Stage 2 telemetry, worker-orchestration, manager and live-view tests.
They do not start privileged BMv2 experiments. Process-manager startup tests use
an ephemeral localhost port and stop only their owned Streamlit child.

Port override, when needed:

```bash
make dashboard DASHBOARD_PORT=8502
make dashboard-live DASHBOARD_PORT=8502 MODE=rf_c RATE=250
make dashboard-stop DASHBOARD_PORT=8502
```

The real-PCAP live classification demonstration, detailed remaining historical
pages, full benchmark launch, broad reproduction targets and Git commits are
deferred. Stage 2 does not alter frozen models, P4 behavior, synchronization,
numerical quality thresholds or historical evidence.
