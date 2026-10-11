# Final repeated RAW performance benchmark (v5)

This is the approved final experiment, not another calibration or a new measurement
framework. The native RAW sender, clock auditor, external-reference worker,
capture transport, resource sampler, numerical limits and frozen normal BMv2
programs are unchanged. The v3/v4 runners and all historical evidence remain intact.

## Fixed protocol

| Setting | Final value |
|---|---|
| Configurations | Forwarding, features, RF-B, RF-C |
| Workloads | Classification-heavy, cached-forwarding |
| Offered targets | 100, 250, 500, 1,000 pps |
| Repetitions | Five per configuration/workload/rate |
| Matched blocks | Forty; four configurations per block |
| Total trials | 160 |
| Phases | Five RAW seconds warm-up; twenty RAW seconds measurement |
| Capture drain | Two RAW seconds after each phase |
| Traffic | Existing 128-byte Ethernet recipes; identical packet bytes within each matched block |
| Normal definitions | TEST_TIMESTAMPS=0, DEBUG_REPORT=0, FLOW_SLOTS=65,536 |
| Ordering | Seed 4022; shuffled blocks and rotated randomized configuration order |
| State isolation | Fresh switch per trial; disjoint warm-up/measurement flow keys and hash slots |

Each mode occupies each order position exactly ten times across forty blocks.
Within a rate/workload cell, five repetitions necessarily have position counts
1/1/1/2, not perfect four-way balance. Block order and traffic identities are
sealed before acquisition; there is no outcome-dependent reordering.

Both RF-B and RF-C already extract direction features. Their comparison concerns
the deployed forests, not the standalone cost of extracting direction. Fresh
state removes carry-over; the five runs are separately acquired repetitions, not
proof that host scheduling conditions are statistically independent.

## Three verdicts and stopping rules

1. **Measurement integrity:** hard capture, packet, RAW audit, resource, counter,
   provenance and resource-preflight requirements remain unchanged. The first
   hard failure, acquisition exception or interruption stops acquisition.
2. **Independent RAW clock qualification:** the same query-only providers and
   conservative +/-1,000-ppm requirements apply to this campaign. Previous
   qualification is a prerequisite, not a replacement for under-load qualification.
   Initial acquisition failure stops before traffic. Later failed queries remain
   evidence and can make the final rate verdict FAIL/INCONCLUSIVE; unsupported
   rate and elapsed-normalized CPU percentages are withheld.
3. **Sender-pacing conformance:** PASS/WARNING remains separate. A warning does
   not stop acquisition or automatically invalidate reliable counts or qualified
   average rates. All warm-up and measurement distributions remain visible.

Unchanged engineering limits: offered target agreement within 2%; p99 lateness
<=max(1 ms, one interval); maximum lateness <=max(5 ms, three intervals); short
send-start gaps below one-quarter interval <=1%. RAW auditing requires zero
regressions, <=100-us clock brackets, <=25-ms maximum sampling gaps and endpoint
coverage. No threshold is relaxed, and outliers are not removed.

There is **no retry, resume, replacement trial or selective block completion**.
Every attempted trial gets immutable start/result receipts. An exception preserves
partial files without inventing a numerical result or pacing verdict. Every planned
block is reported, including unattempted modes, interrupted blocks and missing
repetitions. Acquisition-complete and qualification-complete blocks are distinct.
The single-run lock and private interface ownership/cleanup are unchanged.

## Supported measurements and final analysis

The command automatically invokes the existing offline analyzer after saving the
campaign, including when acquisition is incomplete. It writes a separate analysis
directory rather than altering observations. It verifies seals and supplies:

- Achieved offered pps, delivered pps and Ethernet Mb/s over the RAW offered window.
- Reliable sent/output/non-delivery, duplication and reordering accounting.
- RF decision counts, decisions/s and observed/planned decision completion fraction.
- Linux OS-accounted CPU seconds and RAW-normalized one-core percentages.
- Sampled RSS maxima and process-lifetime high-water memory, kept distinct.
- Trial-level medians, minima/maxima, sample SD, IQR and available sample counts.
- All six within-block configuration pairs, with absolute/relative differences,
  achieved-load differences and pacing-warning disclosure.
- Supported-metric figures in PNG/PDF/SVG, showing trial variability and sample counts.

Identical targets are not proof of comparability. The existing descriptive 2%
cross-mode achieved-load-spread screen is retained; it is not an equivalence test
or a new acquisition gate. Unqualified, incomplete or load-mismatched blocks do
not enter paired performance summaries, and their observations remain diagnostic
evidence. Warning trials remain visible and are not selectively removed.

Missing observations are never filled with zeros. Memory and count validity are
reported separately from elapsed-rate qualification. Packet non-delivery is not
automatically attributed to BMv2; capture/instrumentation loss invalidates that
inference. Delivered throughput includes the documented bounded drain and is not
instantaneous egress or physical wire rate. CPU is OS-accounted, not independently
calibrated physical CPU time. Classification completion is not classification accuracy.

Kernel forwarding latency p50/p95/p99 and isolated RF inference latency remain
**unqualified**. No uniform-arrival, maximum-capacity, saturation, statistical
significance or inherent speed-ranking conclusion is automatically asserted.

The prior 2,000-pps results, including trial 21's integrity failure, are linked as
supplementary calibration evidence. They are neither overwritten nor pooled into
the final repeated results. The old 16-trial calibration and 21-attempt higher-rate
campaign are seal-verified during preparation and before the final launch.

## Duration, limits and manual launch

Scheduled phases and drains total **4,640 seconds (77.3 minutes)**. Allow roughly
90-110 minutes including fresh-switch startup, CLI checks and evidence/analysis.
The exact overhead is not guaranteed. Keep the laptop plugged in and awake, avoid
unrelated heavy work, and run one copy.

Campaign traffic totals 1,480,000 measured packets plus 370,000 warm-up packets.
At 1,000 pps, the largest per-trial recipe has 25,000 combined packets and 3,136
combined hash slots. Existing limits remain 500,000 packets, 60,000 occupied slots,
768 MiB runner RSS, at least 1 GiB available WSL memory, 5 GiB initial disk space
and 512 MiB stop reserve. Previous artifact sizes suggest approximately 1.3 GiB
for acquisition; allow 1.5-2 GiB including preparation and analysis.

Execute only the verified launch command supplied after readiness checks, in an
ordinary Ubuntu shell in `/home/geleza/p4/etc-training`, not `RuntimeCmd:`. The
explicit virtual-environment Python path makes activation optional. `sudo` grants
packet-interface access; it does not authorize synchronization or clock changes.
The sealed preparation and successful normal-build smoke receipt are required.

If the campaign stops, preserve its evidence and paste the output. Do not rerun a
failed cell or create a replacement passing dataset. Once results are reviewed,
freeze performance evaluation and proceed to the Streamlit dashboard and Makefile.

## Verified readiness and exact command

- **298 installed nonprivileged regression tests passed**, zero failures, errors
  or skips. Live campaign acquisition is mocked in campaign tests, not launched.
- **8/8 normal-build packet-file smoke combinations passed**, each forwarding
  320/320 byte-identical frames. RF counters and auxiliary feature/slot/packet-eight
  checks passed. This is correctness checking, not live timing qualification.
- All forty blocks and 160 trials are sealed. Each mode occupies each position
  ten times. Forty-six preparation artifacts and 71 underlying smoke artifacts
  verified, together with the preparation/smoke receipt binding.
- The calibrated sender, clock, capture, resource and historical runner hashes
  remain unchanged. Frozen model/program/base-input hashes verified. Historical
  calibration seals verified for all 195 + 298 artifacts, including trial 21's
  original failure; neither campaign is pooled into final results.
- Report/figure rendering was tested with synthetic unit-test fixtures only.
  Those values are not benchmark results and are excluded from the research data.

Prepared directory:
`/home/geleza/p4/etc-training/results/raw_performance_benchmark_preparation/20261008T222805Z_7060abb5c4`

Bound smoke directory:
`/home/geleza/p4/etc-training/results/raw_performance_benchmark_checks/20261008T223022Z_8ad08d61d2`

Underlying normal packet-file checks:
`/home/geleza/p4/etc-training/results/raw_performance_packet_file_checks/20261008T223007Z_1e44c7ff08`

In an ordinary **Ubuntu WSL shell**, execute:

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_raw_performance_benchmark.py run \
  --prepared /home/geleza/p4/etc-training/results/raw_performance_benchmark_preparation/20261008T222805Z_7060abb5c4 \
  --smoke-run /home/geleza/p4/etc-training/results/raw_performance_benchmark_checks/20261008T223022Z_8ad08d61d2
```

`cd` selects the project. The explicit Python executable selects its virtual
environment without activation. `-B` avoids bytecode writes. The two paths bind
the immutable trial schedule to its successful smoke checks. The runner creates
and cleans its own switch instances and interfaces, qualifies RAW timing under
load, preserves every attempted trial, and invokes offline analysis after saving.

New campaign evidence goes under
`/home/geleza/p4/etc-training/results/raw_performance_benchmark/`.
The terminal prints the exact evidence directory and its separate `analysis_...`
directory containing report.json, report.md and supported-metric figures.

The privileged final campaign has **not** been launched. No source commit/push,
frozen-program modification or synchronization change was performed.
