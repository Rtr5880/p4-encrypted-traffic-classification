# Reduced WSL RAW performance calibration

This is one bounded implementation/calibration attempt, not the 240-trial sweep.
No models are retrained. Frozen P4, original benchmark sources and historical
evidence remain unchanged. The synchronization service stays enabled; no clock
setting, service stop, frequency correction, priority change or Git command is
part of this protocol.

## What changed and why

New files sit beside the old harness. `run_raw_performance_calibration.py` reuses
the sealed normal-build forwarding, features, RF-B and RF-C JSON programs from
the existing preparation. It does not regenerate forests or edit P4 source.

The measurement paths are explicitly separate:

```
RAW sender deadlines -> exact same four-mode traffic -> output frame accounting
        |                                                   |
        +------------ qualified RAW elapsed denominator ----+

REALTIME kernel timestamps -> retained diagnostic evidence -> no latency claim
```

`raw_paced_sender.c` uses immutable RAW deadlines. Linux supports the relative
MONOTONIC sleep used as a wake aid, capped at 1 ms; after every wake the sender
reads RAW again. A packet cannot be sent before its RAW deadline. There is no
fixed 2.585% correction, busy-spin, deadline rebasing, retry burst or filtering of
late observations. Interrupted sleeps, RAW regression, cancellation, excessive
non-progress or an expired phase fail closed. Actual send times remain evidence.

`raw_benchmark_transport.py` preserves exact packet matching, input completeness,
zero capture-drop requirements and kernel/read-queue accounting. Supported-clock
waits are only wake aids; measured sender/resource/drain durations use RAW.
`raw_clock.py` retains the native five-read audit and independent query-only
network references. `raw_performance_resources.py` reports RAW resource windows.
`analyze_raw_performance.py` verifies hashes and writes a fresh analysis folder.

## Fixed calibration scope

| Item | Value |
|---|---|
| Configurations | forwarding, features, rf_b, rf_c |
| Workloads | classification-heavy, cached-forwarding |
| Offered loads | 100 and 1,000 pps, ascending load blocks |
| Replications | one; calibration is not statistical performance evidence |
| Trial count | maximum 16 |
| Warm-up / measurement | 5 / 20 RAW seconds |
| Capture drain | requested 2 RAW seconds per phase, actual duration retained |
| Topology/frame size | unchanged private veth topology, 128 Ethernet bytes |
| Estimated duration | 7.7 scheduled phase minutes; allow roughly 10–15 minutes with startup, counters and evidence |
| State separation | fresh switch; disjoint warm-up/measurement UDP keys AND CRC32 slots |
| Resource safeguards | original 768 MiB runner RSS limit, disk/memory preflight, one switch at a time, shared exclusive run lock |

At the largest calibration load (1,000 pps), each trial contains 5,000 warm-up
frames plus 20,000 measurement frames. The classification-heavy plan allocates
632 warm-up flows and 2,504 measurement flows (3,136 combined), below the
4,096-flow bound; the 25,000 combined frames are below the 100,000-packet bound.
The sealed plan confirms zero warm-up/measurement slot overlap. Partially filled
eight-flow blocks are included in packet accounting but are not counted as
completed eight-packet classification events.

All modes within a block receive byte-identical immutable plans. Logical packet
direction alternates while physical traffic traverses the same ingress/egress
path. Both RF-B and RF-C extract direction; their comparison is deployed-forest
overhead, not standalone direction extraction cost. Original BMv2 ingress timing
and 60-second P4 idle rules are unchanged. These short flow blocks do not qualify
physical feature-IAT accuracy or classification accuracy.

## Gates and metric definitions

| Metric | Definition/acceptance |
|---|---|
| Achieved offered pps | successful sends / actual RAW sender window; within 2% target |
| Sender lateness | p99 <= max(1 ms, one interval); max <= max(5 ms, three intervals) |
| RAW sender burst fraction | <=1% of send-start gaps below one quarter nominal interval |
| RAW clock audit | no regression; every native read bracket <=100 us; measured-window audit gaps <=25 ms; complete endpoint coverage |
| Input/capture integrity | every sent frame captured at input, exact bytes/IDs, no malformed/duplicate trial frames, zero socket drops and kernel socket count equals recvmsg accounting |
| Output delivery/loss | unique matched outputs / RAW offered window, including documented bounded drain; missing outputs are path non-delivery, not automatically BMv2 drops |
| Ethernet Mb/s | delivered frame bytes x8 / RAW offered seconds /1e6; no physical-wire overhead claim |
| Decision rate | verified six-bin decision-counter delta / RAW offered window; counters checked after drain, warm-up removed |
| CPU | OS-accounted /proc user+system ticks / SC_CLK_TCK, then divided by each RAW resource window; one-core percent can exceed100%; CPU numerator not independently frequency-qualified |
| Memory | sampled RSS maximum versus process-lifetime VmHWM, in MiB; lifetime HWM may include warm-up |

### Independent loaded RAW qualification

The calibration queries three separately operated references (Cloudflare,
Google and Ubuntu). DNS is bounded, each selected IPv4 address is pinned for the
campaign, and all requests/responses/failures are retained. Queries never set
the clock or change synchronization. Queries continue approximately every30 RAW
seconds and a final round follows traffic. Their runner CPU/network overhead is
explicitly recorded through query-window overlap counts.

For **each provider**, require at least three valid queries, >=180 seconds of
reference span, first/last endpoints surrounding the measured campaign, valid
queries inside a highest-load measurement window and a conservative RAW rate
interval entirely inside +/-1,000 ppm. The interval includes the entire local
request/response span and advertised upstream uncertainty; it is not a95% CI,
assumed symmetric network path or traceable SI certificate. Missing references,
failed requests, wide query brackets or insufficient precision yield INCONCLUSIVE,
not an invented pass. Initial reference acquisition failure stops before live
traffic. These are **campaign-average coarse rate bounds under representative
load**, not separate +/-0.1% frequency certificates for each20-second trial.

### What is deliberately not qualified

Kernel packet timestamps remain CLOCK_REALTIME. Their original continuity,
ordering, negative-delay, missing-timestamp and kernel-input-burst warnings are
saved under `kernel_timestamp_diagnostics`, `legacy_kernel_arrival_pacing` and
`legacy_protocol_verdict`. They are never relabelled as passing the old protocol.
The old kernel-arrival burst requirement is not applicable as RAW sender-pacing
proof; application sending is a different observation point and does not certify
the packet-arrival spacing seen by BMv2.

No kernel forwarding-delay p50/p95/p99, isolated inference delay, ASIC performance,
classification accuracy or maximum switch capacity is reported. Realtime samples
are not discarded or globally rescaled. RAW output receive/read times are capture
completion diagnostics, not forwarding latency.

## Run the manual calibration

Use an ordinary Ubuntu WSL terminal, not the BMv2 `RuntimeCmd:` CLI.
Directory: `/home/geleza/p4/etc-training`.
The absolute virtual-environment Python path makes activation optional.

The installed version passed 151 nonprivileged unit/regression tests. Its fresh
packet-file smoke passed all eight configurations/workloads (320/320 unchanged
frames each), RF counters and auxiliary eight-feature/slot/packet-eight checks.
These checks did not send live interface traffic or qualify timing performance.

Prepared evidence:
`/home/geleza/p4/etc-training/results/raw_performance_calibration_preparation/20261008T190202Z_6e56402828`

Smoke wrapper:
`/home/geleza/p4/etc-training/results/raw_performance_calibration_checks/20261008T190231Z_bbde963de3`

Underlying exact packet-file smoke:
`/home/geleza/p4/etc-training/results/raw_performance_packet_file_checks/20261008T190216Z_1e8b1b8fdb`

Run **one** command below. It starts/stops only its
owned private switches/links, prints each trial and stops on a local quality
failure. Do not suspend/reboot the laptop, start another run or add unrelated
heavy workloads. A normal Windows/WSL background environment remains a limitation.

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_raw_performance_calibration.py run \
  --prepared /home/geleza/p4/etc-training/results/raw_performance_calibration_preparation/20261008T190202Z_6e56402828 \
  --smoke-run /home/geleza/p4/etc-training/results/raw_performance_calibration_checks/20261008T190231Z_bbde963de3
```

The command verifies sealed inputs, obtains initial query-only external clock
references, runs the bounded calibration, and saves a fresh result folder.
`sudo` is needed for its private packet interfaces; it does not change clocks,
services, models or synchronization settings. Activation of `.venv` is optional
because the Python executable is specified explicitly. Do not run the old
`run_performance_benchmark.py` command for this attempt.

After completion, use `analyze_raw_performance.py --run <printed Evidence path>`.
It verifies the saved SHA256 manifest and creates a new `analysis_*` folder with
`report.json`, `report.md` and, where plotting is available, descriptive figures.
It does not alter raw evidence. Paste the terminal output and evidence directory
for review before any further calibration or full sweep.

## Decision after the attempt

PASS requires every planned local trial plus current independent RAW rate/load
qualification and unchanged frozen inputs. Rates and CPU percentages are withheld
from qualified aggregates if the independent rate qualification fails or is
inconclusive. Verified packet/decision counts, OS-accounted CPU numerators and
memory can remain separately valid. Kernel forwarding latency always remains
unqualified, including after a successful RAW calibration.

A pass supports considering a separately approved reduced sweep at calibrated
rates only; it does not qualify5,000pps or the old240-trial full protocol. On a
failure, retain the actual reason and stop this attempt. Do not loosen gates,
repeat opportunistically until a pass, disable synchronization or start a custom
kernel instrumentation project. Review whether a qualified native Linux machine
is the appropriate next step.
