# RAW calibration v3: three independent verdicts

This is the approved, bounded 16-trial calibration, not a capacity benchmark or
the 240-trial sweep. No frozen RF models, P4 programs, old acquisition evidence,
synchronization settings or original benchmark sources are changed. No fitting,
Git commit/push, automatic privileged calibration or selective retry is involved.

## What v3 means

| Verdict | Meaning | Consequence |
|---|---|---|
| Measurement integrity PASS / FAIL | Complete successful sender evidence, valid RAW boundaries/audit, reliable exact frame/capture accounting, RF counter checks, resources and provenance | A hard failure stops acquisition and invalidates affected claims; retain all attempted evidence |
| Independent RAW qualification PASS / FAIL / INCONCLUSIVE | Current query-only independent references, including observations within actual valid highest-load measurement windows | Absolute pps, Mb/s, decision rate and RAW-normalized CPU percentages require PASS; counts and memory remain separately assessable |
| Sender conformance PASS / WARNING | Prespecified engineering limits for intended-load agreement, deadline lateness and short gaps | A warning does not stop acquisition or automatically invalidate reliable counts or independently qualified average rates; preserve distributions and both phase warnings |

The original numerical thresholds are unchanged:

- Intended-load agreement: within 2% of the target.
- p99 send-start and completion upper-bound lateness: <= max(1 ms, one interval).
- Maximum lateness: <= max(5 ms, three intervals).
- Short send-start gaps (<one quarter interval): <=1% of gaps.
- RAW audit: no regression, all native read brackets <=100 us, measurement audit
  gaps <=25 ms, complete endpoint coverage.
- Independent references: all three providers; >=3 valid queries/provider;
  >=180-second reference span; before/after campaign coverage; qualifying
  observations inside actual highest-load valid measurement windows; complete
  conservative rate bounds within +/-1,000 ppm. Failed requests and bad brackets
  remain evidence and do not silently disappear.

The pacing constants are engineering heuristics, not published or empirically
validated universal boundaries of measurement validity. Passing them does not
prove uniform BMv2 ingress spacing. Warnings do not establish uniform-load or
saturation performance. Historical v1/v2 trial verdicts are not relabelled.

## Fixed experiment

Four configurations: plain forwarding, feature-only, RF-B and RF-C. Two workloads:
classification-heavy and cached-forwarding. Target rates: 100 and 1,000 pps.
One repetition each: exactly 16 planned trials. All use the same frozen normal
program artifacts, BMv2 binary, isolated private veth topology, byte-identical
plans within each block and 128-byte Ethernet frames.

Each trial uses five RAW seconds of warm-up and twenty RAW seconds of measurement,
with a bounded two-RAW-second capture drain after each phase. New switch instances
and disjoint UDP keys AND CRC slots separate warm-up from measurement. At the
highest calibration load there are 25,000 combined frames and 3,136 allocated
flows, within the existing 100,000-frame and 4,096-flow bounds. Partial eight-flow
blocks are counted as traffic but not completed packet-eight classifications.

Both RF-B and RF-C already extract directional statistics. Their comparison
isolates the deployed forests, not the standalone cost of direction extraction.

The native sender retains immutable RAW deadlines, supported relative sleep wake
aids (capped at 1 ms), RAW rechecks, and all attempted send observations. There
are no frequency corrections, busy-spins, deadline rebasing or packet-send retries.

## Reference scheduling and its validation

The measurement-start callback queues a nonblocking notification. A separate
worker aims for a provider round about two RAW seconds into each measured window.
Notifications are only scheduling hints: qualification counts queries using
their actual full observed brackets inside actual integrity-valid sender windows.
Initial, periodic and final queries, timeouts, brackets and scheduling records
are all retained. They never adjust the clock or change synchronization.

Deterministic nonprivileged tests exercise actual worker dispatch over 240 virtual
RAW seconds, all providers, the >=180-second span, under-load containment, stale
notifications, timeouts and invalid brackets. These tests verify logic, **not
actual WSL timing or external network reliability**. The manual calibration must
verify real qualifying observations under the same clock-quality requirements.

## Metrics and comparisons

- Achieved application offered pps: successful sends / observed RAW offered window.
- Delivered pps and Ethernet Mb/s: unique matched outputs (including bounded
  drain) / the RAW offered window. This is offered-window-normalized delivery,
  not instantaneous kernel egress service rate or physical-wire capacity.
- Missing outputs with complete input and reliable capture accounting are path
  non-delivery after bounded drain. They are not automatically BMv2 drops.
  Socket drops, unread queues or corrupted/incomplete capture invalidate loss
  attribution instead of being counted as switch losses.
- RF decisions: six-bin counter delta after disjoint warm-up. No activity-accuracy
  scoring is performed here.
- CPU: Linux OS-accounted user+system ticks / SC_CLK_TCK, normalized by the RAW
  resource window using a one-core convention. The CPU accounting numerator is
  not independently calibrated physical CPU time.
- Memory: sampled measurement-window RSS peak and lifetime VmHWM, in MiB. Lifetime
  HWM may include warm-up; sampling cannot prove every instantaneous peak.

The analyzer keeps qualified averages from warning trials instead of silently
removing outliers. It reports achieved offered rates for all four modes in each
balanced block, normalized spread and warm-up/measurement pacing distributions.
The existing 2% tolerance is reused only for a **descriptive engineering load
screen**, not a new acquisition gate or statistical equivalence criterion.
Identical target rates alone never establish comparability; mismatched loads or
traffic shapes cannot support an inherent model-speed or overhead conclusion.
One trial per configuration does not establish statistically significant ranking.

Kernel software timestamps remain CLOCK_REALTIME. All original diagnostic samples
and validity warnings stay separate. No p50/p95/p99 kernel forwarding delay,
isolated inference latency, uniform-load, saturation, ASIC or maximum-capacity
claim is produced.

## Evidence and preservation

Each trial writes immutable local `trial_summary.json` plus original phase files,
resource/counter reports, commands and provenance. Campaign qualification creates
a separate `qualified_trial_summary.json`, never rewrites the local summary.
Final provenance verification precedes qualified claims. The root summary seals
all artifacts; the analyzer verifies seals and writes a fresh analysis folder.

The old nine-trial acquisition remains unchanged. Its isolated 5.113093-ms warm-up
event remains a historical failed trial, not a retrospectively passed v3 trial.
The separate recovery report preserves its eight local passes, one local failure
and inconclusive independent qualification. No original outlier was removed.

## Manual launch

Use an ordinary Ubuntu WSL terminal in `/home/geleza/p4/etc-training`, not the
BMv2 `RuntimeCmd:` CLI. The absolute `.venv/bin/python` path makes activation
optional. Use only the fresh v3 paths below, not an old guide.

Verified readiness:

- Installed final nonprivileged regression suite: **197 tests passed**.
- Fresh normal-build packet-file smoke: **8/8 combinations passed**, each with
  320/320 byte-identical forwarded frames; RF counters and auxiliary feature,
  slot and packet-eight checks passed.
- New preparation/source/compiled-helper input seals verified; unchanged numerical
  thresholds confirmed; original 102 historical files and nine notification
  endpoints verified unchanged.
- Frozen P4/model inputs and original benchmark source hashes unchanged.
  Time synchronization remains active/enabled; no clock setting changed.

Preparation:
`/home/geleza/p4/etc-training/results/raw_performance_calibration_preparation/20261008T201210Z_31ccc28561`

Bound smoke:
`/home/geleza/p4/etc-training/results/raw_performance_calibration_checks/20261008T201253Z_12974697ad`

Underlying exact packet-file checks:
`/home/geleza/p4/etc-training/results/raw_performance_packet_file_checks/20261008T201238Z_625a389723`

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_raw_performance_calibration.py run \
  --prepared /home/geleza/p4/etc-training/results/raw_performance_calibration_preparation/20261008T201210Z_31ccc28561 \
  --smoke-run /home/geleza/p4/etc-training/results/raw_performance_calibration_checks/20261008T201253Z_12974697ad
```

Purpose: verify sealed inputs, query independent timing references and run only
the bounded 16-trial calibration, saving fresh phase, counter, resource, clock
and three-verdict evidence. `sudo` permits private packet interfaces, not clock
adjustments. Initial reference failure stops before traffic; hard measurement
integrity failure stops the campaign. Pacing warnings alone continue with their
full observations. The terminal prints each provider's accepted highest-load
query count after qualification; JSON also records qualifying observations by
provider for every actual valid measured window.

Allow roughly 10-15 minutes (7.7 minutes of scheduled phases plus setup, queries,
counters and evidence). Keep the laptop awake, run one copy only and avoid
unrelated heavy workloads. A pacing WARNING is retained and acquisition continues;
a hard integrity error stops this bounded attempt. Do not rerun selectively to
obtain a pass or loosen any numerical limit.

Paste the full output and the new Evidence directory afterward. We will inspect
all three verdicts, actual under-load reference observations and four-mode achieved
load/pacing comparability, then decide once on the bounded repeated sweep or an
explicit limitation. The dashboard and Makefile follow the finalized results.

No privileged run or full sweep has been launched by the assistant.
