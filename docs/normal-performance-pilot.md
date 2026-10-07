# Normal-build RF performance pilot

**Updated rerun instructions:** the first live pilot detected a wall-clock
correction. A subsequent scoped queue-clock fix changed the executable, so the
old preparation/command below is historical and must not be reused. Use
`/home/geleza/p4/etc-training/docs/queue-clock-repair.md` for the fresh verified
preparation, normal-smoke gate and manual run command. Models/P4 are unchanged.

## What this stage does

The clean native-clock evaluation established correctness and preliminary
capture-label accuracy for all 398 held-out instances per model. This separate
stage checks whether our performance measurements are usable before a repeated
load sweep. It does not train models or produce new accuracy/F1 results.

The frozen RF-B and RF-C programs are compiled into separate new directories with
`TEST_TIMESTAMPS=0`, `DEBUG_REPORT=0`, and `FLOW_SLOTS=65536`. No debug feature,
leaf or score headers are emitted. The six existing RF decision counters remain,
so a normal build can still demonstrate one decision per eight-packet flow.
The P4 source, RF models, feature definitions and old evidence are unchanged.

| Workload, per model | Flow layout | Frames | Expected RF decisions |
| --- | --- | ---: | ---: |
| Classification-heavy | 32 new flows, 8 packets each | 256 | 32 |
| Cached-forwarding | 8 new flows, 32 packets each | 256 | 8 |

Both use 128-byte Ethernet frames without FCS, carrying 114-byte IPv4 packets.
The first eight packets are included in the cached workload; the remaining 24
packets per flow are after classification. This is not a pure pre-warmed cache
measurement. Each trial gets a fresh switch process and empty flow state.

RF-B/C use identical deterministic packet bytes and the same target schedule.
The ordering is B then C for the first workload, C then B for the second. All
flows use unique keys and deliberately non-colliding state slots. Logical
direction alternates inside each flow, but all frames physically enter port 1
and leave port 2. This pilot does not benchmark hash collisions or both physical
directions. Synthetic frames have no verified media labels.

## What has already been checked

- Full project regression suite: 452 tests run, 451 passed, one optional Scapy
  test skipped. No live raw-socket performance trial was run by that suite.
- Normal RF-B/C compilation: passed; generated JSON has no report headers in
  the deparser and retains six decision-counter bins.
- Non-root packet-file smoke check: four private runs, all 96 frames forwarded
  byte-for-byte, two decisions per run, eight decisions in total. This is not a
  live latency/throughput measurement.
- Frozen P4 and existing real-PCAP replay source hashes remain unchanged.
- The new source/tests/guide are uncommitted for review. No Git push was made.

Prepared pilot:

`/home/geleza/p4/etc-training/results/performance_pilot_preparation/20261007T211440Z_2fd48de9b7`

Smoke evidence:

`/home/geleza/p4/etc-training/results/performance_pilot_checks/20261007T211522Z_80584641c9/summary.json`

The preparation binds the clean native evaluation, corrected BMv2 clock receipt,
RF deployment, source and generated packet/build files by hashes. A changed
input is rejected rather than silently rerunning with a different design.

## Your next manual command

Use **one Ubuntu/WSL shell**, in **`/home/geleza/p4/etc-training`**. An active
virtual environment is optional: the explicit Python path below selects the
correct training environment even under sudo.

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/run_performance_pilot.py run \
  --prepared /home/geleza/p4/etc-training/results/performance_pilot_preparation/20261007T211440Z_2fd48de9b7
```

`cd` selects the project directory. `sudo` permits new private veth pairs and
raw Ethernet sockets. `run` starts the four measurements. `--prepared` selects
the already-checked normal builds and workload contract: no compilation,
retraining or tuning happens during measurement.

You do **not** need to start BMv2 in T1, open its CLI in T2, or send traffic in
T3. This runner manages private switch children, Thrift ports and veth links;
it reads counters after each measured window. It does not reuse or delete
`p1_host1`, `p1_host2`, `p1_sw1`, or `p1_sw2`, and does not stop other switches.
For a quieter measurement, stop only your own old manual demo using Ctrl+C in
its original terminal and avoid downloads/other benchmarks during this run.

There are four offered-traffic windows, each 2.56 seconds at a target of 100
packets/s, plus 0.3 seconds of capture drain and process/setup/query overhead.
The runner prints before and after each trial. Do not launch a second copy if
one trial is still running. Ctrl+C requests cleanup of this run's owned
resources and preserves partial evidence.

Expected successful trial lines have:

```text
RF-B, classification-heavy: 256/256 forwarded; 32/32 decisions; ... delay VALID; PILOT PASS
RF-C, classification-heavy: 256/256 forwarded; 32/32 decisions; ... delay VALID; PILOT PASS
RF-C, cached-forwarding: 256/256 forwarded; 8/8 decisions; ... delay VALID; PILOT PASS
RF-B, cached-forwarding: 256/256 forwarded; 8/8 decisions; ... delay VALID; PILOT PASS
PERFORMANCE PILOT PASS — not a capacity benchmark. Evidence saved to: ...
```

The actual offered rate is printed, not assumed equal to 100pps. If the result
is incomplete, preserve it and paste the output/evidence path. Do not treat
missing timestamps, capture drops or counter failures as successful metrics.

## How to read the measurements

| Quantity | Evidence/meaning | Important limit |
| --- | --- | --- |
| Offered load | Successful sends / actual sender window; also sender interpacket rate | A requested rate is not proof of achieved load |
| Output rate | `(N-1)/(last-first)` using output kernel timestamps | Only reported when timestamp validation passes |
| Frame bit rate | Actual Ethernet bytes sent × 8 / sender window | No preamble, FCS or interframe gap; not physical wire rate |
| Observed loss | Sent sequence IDs missing at output after the bounded drain | Requires complete input capture and zero capture-socket drops |
| Path delay | Output kernel timestamp minus input kernel timestamp, paired by unique sequence | Includes host/veth, BMv2 queues, processing and scheduling; not RF-only inference time |
| Delay distribution | Minimum, median, p95, p99, maximum and mean, plus packet-position groups | Prefix/decision/cached groups are descriptive, not a causal inference-time subtraction |
| BMv2 CPU | Process CPU seconds and percentage of one core over socket setup/send/drain | Multithreaded CPU can exceed 100%; compilation/startup/CLI query excluded |
| BMv2 memory | Baseline/final/sampled peak RSS and separate lifetime VmHWM | Sampled peak is not a continuously measured peak or model-only memory |
| Runner CPU | Sender/capture/monitor process CPU in the same interval | Separate from the BMv2 child; instrumentation still competes for host resources |

Two capture sockets run concurrently with the paced sender. Every tagged frame
is checked against the prepared bytes; duplicates, corrupt/malformed frames,
missing sequences and capture errors are counted. `PACKET_STATISTICS` socket
drops make loss attribution invalid rather than being labelled switch loss.
See the [Linux packet socket reference](https://man7.org/linux/man-pages/man7/packet.7.html).

Delay uses actual kernel software timestamps via `SO_TIMESTAMPING` with
`RX_SOFTWARE | SOFTWARE`. It deliberately does not substitute the time Python
read a packet. Missing ancillary timestamps invalidate latency. This avoids
the documented possible `SO_TIMESTAMPNS` receive-time fallback when an skb
has no earlier software timestamp. See the
[Linux timestamping documentation](https://docs.kernel.org/networking/timestamping.html).

These endpoint timestamps use CLOCK_REALTIME, while our corrected BMv2 feature
clock uses a steady clock. Therefore a separate sampled realtime/monotonic audit
is still necessary for latency: detected backward timestamps, negative delays,
offset changes of at least 1ms, or excessively wide audit brackets invalidate
the delay summary. Packet counts remain visible. The 10ms sampled audit cannot
exclude an unobserved step-and-reversal between samples; its maximum sample gap
is retained. A passed pilot is not a proof of sub-microsecond timing precision.

## Evidence you will get

A new, unique directory under:

`/home/geleza/p4/etc-training/results/performance_pilot/`

- `summary.json`: overall outcome, completed/attempted trials and key metrics.
- `provenance.json`: normal-build flags, binary receipt, input preparation and host.
- Per-trial `trial_summary.json`: rates, loss, latency groups, CPU/RSS, counters.
- Per-trial `measurement.json`: per-packet kernel timestamps, exact-frame
  accounting, capture statistics, sender deadlines and clock audit.
- Per-trial `resources.json`: raw /proc resource samples and interpretation.
- Per-trial `counter_check.json` and `counter_query.json`: all six bins and
  expected one-shot decision/byte totals. Decision-counter bytes count only
  the eighth frames, not total forwarded bytes.
- Per-trial `switch_command.json` and `switch.log`: private process invocation.
- `failure.json` if incomplete. Evidence is retained, not overwritten.

## Review the code yourself

In your Ubuntu shell, from **`/home/geleza/p4/etc-training`**:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training
```

In VS Code, these files divide the implementation into reviewable pieces:

- `tools/run_performance_pilot.py`: prerequisite checks, separate compilation,
  private switch lifecycle, trial order, decision accounting and saved reports.
- `tools/performance_workload.py`: deterministic IPv4/UDP frames, payload
  sequence tags, bidirectional keys and collision-free slots.
- `tools/performance_transport.py`: pacing, concurrent capture, kernel
  timestamp/delivery/clock checks, rates and delay distributions.
- `tools/performance_resources.py`: robust /proc parsing, PID identity checks,
  bounded CPU/RSS sampling and unknown-value handling.
- `tools/test_performance_*.py` and `tools/test_run_performance_pilot.py`:
  47 new unit tests; no hidden live interface benchmark.

To rerun just those unit tests, from **`/home/geleza/p4/etc-training`**:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -B -m unittest discover \
  -s /home/geleza/p4/etc-training/tools -p 'test_performance_*.py'
/home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/test_run_performance_pilot.py
```

The first command runs the 39 workload/transport/resource tests; the second
runs eight runner contract tests. The runner tests mock traffic and switches,
so any printed pilot outcome in these tests is fixture evidence, not a live
performance result. Unit checks need no sudo.

## After the live pilot passes

Review all four real trial reports for usable timestamps, zero capture drops,
forwarding/decision accounting and sane resource measurements. Then implement
the repeated offered-load sweep, with rates/frame sizes/repetitions fixed in
advance and actual offered-rate validation at every point. That sweep is a
separate next step, not already implemented or completed by this pilot.

Do not report this one low-rate repetition as maximum sustainable throughput,
hardware line rate, isolated RF latency, or new multimedia classification
accuracy. Results are specific to this WSL/BMv2 software-switch environment.
