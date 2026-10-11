# Four-mode normal-build BMv2 performance benchmark

## Scope and interpretation

This is a synthetic, controlled load experiment on the existing WSL/BMv2
implementation. It measures the virtual forwarding path, offered-load reliability,
process resources and packet-eight RF decision frequency. It does **not** score
encrypted-traffic classification accuracy, isolate inference latency, establish
ASIC feasibility or claim a maximum capacity before saturation is observed.

The frozen forests, feature definitions and original evidence are not changed.
RF-B uses six size/IAT inputs; RF-C uses those six plus two direction inputs.
**Both deployed RF pipelines already extract all eight features.** RF-C minus
RF-B therefore compares the deployed forests and their associated model data,
not the standalone cost of extracting direction. The shared feature-only mode
also computes direction; a direction-free extractor would be a separate experiment.

## Fixed matrix

| Quantity | Protocol |
|---|---|
| Modes | Parser-matched plain forwarding; shared feature extraction only; frozen RF-B; frozen RF-C |
| Workloads | Classification-heavy: 8 packets per fresh instance; mostly cached-forwarding: 32 packets per instance |
| Initial offered rates | 100, 250, 500, 1,000, 2,000, 5,000 packets/s |
| Repetitions | Five independent fresh-switch trials per cell: 240 trials total |
| Trial traffic | Five-second warm-up, twenty-second measured window; up to two-second capture drain after each phase |
| Packet format | Identical 128-byte Ethernet/IPv4/UDP frames for all four modes within each paired block |
| Classifier builds | Native ingress timestamps; DEBUG_REPORT=0; TEST_TIMESTAMPS=0; 65,536 flow slots |
| Runtime | Same verified clock-corrected BMv2 executable, warning-level logging, private two-veth topology |
| Ordering | Seed 4022; randomized blocks; rotated randomized mode order, position counts differing by at most one across five repetitions |

All packets physically enter port 1 and leave port 2. The logical source and
destination endpoints alternate to exercise bidirectional flow state. This is
not a physical full-duplex or multiport capacity test.

Eight fresh flows are interleaved in a block, then replaced by the next eight.
Decision events are distributed through the traffic rather than occurring only
at the start. Classification-heavy performs inference once per eight packets;
the 32-packet workload performs inference once and then forwards 24 later packets
without another inference event. Prefix packets 1–7 still update features.
Final blocks may be partial: manifests record their exact counts, short prefixes,
expected packet-eight events and cached packet counts. No rounding or invented
complete-flow counts are used.

## Sender and clock acceptance gates

Let T = 1/rate seconds. The measured phase must satisfy:

- Actual offered count/window rate within ±2% of the requested rate.
- p99 monotonic send-deadline lateness ≤ max(1 ms, T).
- Maximum send-deadline lateness ≤ max(5 ms, 3T).
- At most 1% of adjacent input kernel timestamps have a gap below 0.25T.
- Complete successful-send/input association, usable kernel timestamps and no
  input timestamp/sequence regressions.

These gates are fixed before observing the full sweep. Failure is a generator
quality result, not evidence of switch saturation. No catch-up burst is silently
accepted; raw timing arrays and gate failures remain in the saved evidence.

A separate thread requests CLOCK_REALTIME/MONOTONIC audit samples every 5 ms.
Samples must bracket the entire measured sender window. Maximum sampling gap
in that bracketed window is 25 ms; maximum clock-read bracket is 100 µs.
Observed offset displacement at or above 1 ms, realtime regressions or monotonic
regressions invalidate timing. Sampling continues through capture drain to
detect a wall-clock step that could affect late output timestamps. The gap gate
is scoped to the measured sender window, not CLI work or subsequent idle time.
Periodic sampling cannot exclude a clock step and reversal between samples.

Delay uses Linux SO_TIMESTAMPING RX_SOFTWARE|SOFTWARE (option 37, flags 24) on
the input host endpoint PACKET_OUTGOING observation and the output host endpoint
PACKET_HOST/OTHERHOST observation. No userspace-receive-time fallback is allowed.
The difference includes the veth/host path, BMv2 queueing, processing and scheduling.

The recommended clock-audit collector now takes MONOTONIC -> REALTIME ->
MONOTONIC reads within one native C call to reduce Python work inside the read
bracket. It is still preemptible. There are no retries, sample filtering or gate
changes; all raw observations remain saved. Kernel packet timestamp capture is
unchanged. Preparation must explicitly bind the compiled collector using
`--clock-library`; its source, compiler, library and receipt hashes are frozen
alongside the rest of the instrumentation. Use a new preparation/smoke pair,
not older source-sealed preparations made before this collector refinement.

## Bounds, collisions and warm-up isolation

### Native sender calibration refinement (after the 1,000 pps gate failures)

The previous eight-trial 1,000 pps calibration is retained unchanged: all 160,000
measured frames were forwarded, but two trials exceeded the fixed 5 ms maximum
send-lateness gate (7.624 ms and 7.191 ms). The short send syscall brackets at
those events show that the delays occurred before the send, not inside a slow
send syscall. Python/WSL scheduling interference is plausible, not proved.

The optional `--sender-library` binds a sealed native C sender. It runs the
entire bounded deadline/send loop in one `ctypes.CDLL` call, releasing the Python
GIL while capture, clock and resource workers continue. This is not a correction
to timer drift: the previous Python sender already used absolute offsets, and
Python 3.12's sleep uses native OS timers. The change removes per-packet Python
execution and GIL reacquisition from the critical path.

Frames, lengths, deadline offsets, successful and attempted send timestamps,
and atomic cancellation storage are prepared before resource callbacks. The
sender uses `CLOCK_MONOTONIC` absolute sleeps and the existing nonblocking raw
socket. A send error aborts without retry; lateness/catch-up is neither filtered
nor hidden. Native array decoding occurs after resource sampling stops. The
sender remains preemptible: it makes no guarantee against OS scheduling delays.
There is no busy-spin, priority/affinity change, system-service change, or change
to the pacing/clock gates, packet bytes, P4 programs or frozen RF models.

The source, compiler, ABI receipt and library hashes become prepared inputs.
New preparations and smoke checks are required. Do not combine pre-refinement
trials with this instrumentation as if the methodology were identical; use the
same native sender for all four modes in a new repeated sweep. First repeat the
eight-trial 1,000 pps calibration; proceed to 2,000 then 5,000 only when the prior
stage's warm-up and measured quality/delivery/accounting checks pass. Retain
failures rather than repeating until an attractive run appears.

The old pilot's 4,096-flow and 100,000-packet limits are not relaxed in place.
Separate benchmark modules support at most 500,000 packets **combined across
warm-up and measurement**, at most 60,000 allocated distinct state slots, at most
10,000 pps, warm-up up to ten seconds, and measurement up to sixty seconds.
Every preparation validates all bounds before opening interfaces or starting traffic.

At 5,000 pps the two phases contain 25,000 + 100,000 packets. Classification-heavy
allocates 3,128 warm-up slots and 12,504 measured slots: 15,632 in total. Each is
selected using the same full bidirectional UDP key and CRC32 mapping as P4.
Warm-up and measurement have different tuple keys, MAC/payload phase tags **and
disjoint hash slots**. Fresh switch processes separate all trials. Slots are never
recycled merely because a timeout elapsed: the frozen collision protection retains
tuple tags, so recycling would not be safe.

Warm-up frames are observed in a separate capture phase and saved separately.
After warm-up is drained, the six RF counters are read outside the measured
window. Their values are the measured phase's baseline. The post-measurement
counter **delta**, not the cumulative count, is checked against exact packet-eight
events and triggering Ethernet bytes. Plain/feature-only modes have no RF
classifier or RF decision counters; their RF decision fields are null, not fake zeros.

Warm-up requires valid capture/pacing/clock quality and consistent RF accounting.
Lossless traffic must produce the exact expected RF event count. With trustworthy
output loss, a deficit is permitted only within delivery bounds: every distinct
flow with at least eight exact output packets proves at least one RF decision.
Negative deltas, excess decisions or bytes inconsistent with 128-byte triggers
are invalid even when some outputs are missing. The same rules apply to measured
counter deltas. Genuine warm-up loss is retained as capacity evidence; it does
not automatically invalidate the disjoint measured phase.
Warm-up CPU, latency and events do not contribute to measured metrics. Its disjoint
state can still affect process caches and RSS, deliberately warming that process.
It does not alter a measured flow's packet count, prefix or classification state.

## Measurement and validity

Each phase uses persistent nonblocking raw sockets and prebuilt frames. Exact
bytes and dense sequence IDs associate both captures; duplicates, corrupt frames,
unexpected sequences, reorder observations and capture-socket drops are recorded.
Kernel PACKET_STATISTICS packet counts must agree with userspace read accounting;
unread socket backlog must not be called BMv2 loss.

Measurement-quality validity is separate from complete-delivery/latency validity.
True missing outputs after the bounded drain can be an instrument-valid load
result when every input is observed, capture accounting is clean and pacing/
clocks are valid. Such trials stay in capacity summaries. Full-trial latency is
withheld if pairs are incomplete; loss is not silently erased. Missing outputs
alone do not identify the exact queue/process responsible for the drop.

Primary delivered/output pps = unique output packets observed after bounded
drain / actual measured sender-window seconds. Ethernet Mbps uses the same
denominator and 128×8 bits per frame, excluding preamble, FCS and interframe gap.
This count/window quantity can overstate output **during** the offered window
if a substantial queue drains later; report the supplementary kernel output
interarrival rate `(outputs-1)/(last output time-first output time)` and drain
completion alongside it. Neither establishes physical wire rate.

Forwarding delay minimum, mean, median, p95, p99 and maximum are per-trial
statistics over usable paired timestamps. Packet positions 1–7, 8, and after 8
are separately summarized. Position differences are **not isolated inference
time** and cannot be interpreted as causal RF cost by subtracting percentiles.

BMv2 and runner CPU/RSS samplers enter after capture/socket setup and leave
immediately after the sending interval, before drain or CLI queries. CPU is
/proc process tick delta divided by each sampler's actual wall interval: 100%
means one occupied core; a multithreaded process can exceed 100%. Tick precision
and sampler boundary offsets remain in resource files. Runner CPU includes send,
capture, clock audit and sampler work, but not the separate BMv2 process.
RSS is sampled every 100 ms; its maximum is a sampled-window peak. VmHWM is
process-lifetime high-water RSS, including startup and warm-up, not a measured
window-only maximum. Missing resource data invalidates resource results rather
than becoming zero.

Require at least 1 GiB MemAvailable throughout and 5 GiB free on both Linux storage
and physical host C: before live execution. Before each trial, retain a 512 MiB
disk stop reserve; do not require the initial 5 GiB to remain unused as evidence
accumulates. The default matrix's raw timing arrays and measurement PCAPs are
expected to consume approximately 3–4 GiB; actual size depends on recorded events.
One switch runs at a time. Runner
sampled RSS above 768 MiB stops remaining trials safely, preserving evidence.
This is a sampled send-window safety budget, not an OS-enforced instant or
whole-run memory limit. Serialization and analysis can peak outside that window.
Keep the laptop plugged in; do not change Windows/WSL resource allocation,
affinity, power mode or background workload between configurations. Available
load, affinity, frequency/governor and memory observations are saved. Thermal
and host scheduling effects cannot be completely eliminated in WSL.

## Evidence and statistical analysis

Preparation seals the exact RF normal JSONs from the successful pilot, the
unmodified feature source, new derived parser-matched forwarding source,
compiler/runtime receipt, recipes, frame-stream hashes, bounds and schedule.
RF forests are reused without fitting or conversion. Non-root packet-file smoke
tests all eight normal mode/workload combinations, exact forwarding bytes/order
and RF decisions. Thrift CLI register reads cannot expose the entire 429-bit
packed state (the API returns a signed 64-bit value). A separately compiled,
debug-report-only **auxiliary correctness build** verifies all eight features,
slot isolation, prefix counts and packet-eight events from observed native
timestamps; it is never a measured benchmark mode. This is correctness evidence,
**not** live pacing or performance validation.

Each live trial saves switch command/log, provenance, original measurement PCAP,
warm-up observations, before/after counters and deltas, per-packet timestamps,
send deadlines/lateness/gaps, clock audit, socket counters/buffers, CPU/RSS samples,
packet-position delay summaries and quality reasons. The full run seals all
artifacts; source/model hashes are checked again after execution. No old evidence
is overwritten, and an exclusive run lock prevents a duplicate benchmark.

Analysis creates a **separate new directory**, preserving the raw run. It exports
per-trial and grouped CSV/JSON, a methods/results report and publication-ready
300 dpi PNG plus PDF figures. Figures include offered/delivered rate, latency
median/p95/p99, CPU, RSS, paired B/C differences and quality failures.

Attempted and valid repetition counts are always disclosed. Statistics use
independent **trials**, not correlated individual packets, as confidence samples.
Report per-trial summaries, median/mean, sample SD/range and seeded bootstrap
95% confidence intervals. B/C comparisons pair identical traffic-block IDs;
percent difference = 100×(C-B)/B. Zero denominators and unavailable metrics are
explicitly excluded only from the affected metric. Fewer than five valid pairs
are exploratory; five trials still support only limited uncertainty estimates.
Invalid quality trials remain in failure tables rather than being quietly retried.

## Saturation and controlled extension

5,000 pps is the **initial upper rate**, not a claim about maximum throughput.
Suspect saturation only at instrument-valid loads: reproducible output shortfall
or loss, plateauing kernel output rate, growing queues/drain and latency tails.
CPU utilization alone neither proves nor excludes saturation. A quality failure
can instead mean this Python generator/capture setup cannot test that load reliably.

If all modes/workloads at 5,000 have five instrument-valid zero-loss, zero-duplicate,
zero-reorder trials with delivered rate at least 98% of target, review output
interarrival rate, drain and latency trends. A separate explicit preparation can
then request 7,500 and 10,000 pps using `--extension-from` the completed initial
run. The automated gate is necessary, **not sufficient evidence of no saturation**;
human review of the initial results precedes any extension. Extension never runs
automatically and uses identical packets, binary, definitions and methodology.
If the generator fails its gate, improve/replace it in a separately versioned
experiment rather than relaxing thresholds retrospectively.

## Execution duration and instructions

The initial matrix has 240 trials. Warm-up + measurement + two full drains gives
116 scheduled minutes. Private-switch startup, CLI checks, preparation, JSON
serialization and hashing add overhead: budget approximately 2–3 hours. Do not
start another copy, suspend the laptop or use it heavily while measuring.

All following commands belong in **Ubuntu**, directory
`/home/geleza/p4/etc-training`. Activation is optional because the exact training
Python executable is specified. Use VS Code to review the new modules first:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training/tools/run_performance_benchmark.py
code /home/geleza/p4/etc-training/docs/performance-benchmark.md
```

Preparation verifies old prerequisites and freezes new recipes/builds; it sends
no live traffic. Smoke uses BMv2 packet-file mode without sudo and is not a
performance measurement:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_performance_benchmark.py prepare \
  --clock-library /home/geleza/p4/etc-training/results/native_clock_bracket/20261008T004640Z_249a014d58734f02bf35392205bc77dd/libetc_clock_bracket.so

# Replace these TWO paths with the preparation and successful smoke directories.
/home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_performance_benchmark.py smoke \
  --prepared /absolute/path/printed/by/prepare

sudo /home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_performance_benchmark.py run \
  --prepared /absolute/path/printed/by/prepare \
  --smoke-run /absolute/path/printed/by/smoke
```

Only the last command creates private live interfaces and performs the full
benchmark. It does not attach to or kill your existing manual switch. Ctrl+C
stops the owned child and removes only owned links, preserving completed trials
and diagnostic failure evidence. A stopped/incomplete run is not a complete matrix.

After completion, export statistics and figures as your ordinary Ubuntu user:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/analyze_performance_benchmark.py \
  --run /absolute/path/printed/by/the/full/run
```

Dashboard and Makefile work is deliberately deferred until these results have
been finalized. No commit or push is performed by the benchmark tools.
