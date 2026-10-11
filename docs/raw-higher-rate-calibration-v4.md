# Bounded higher-rate RAW calibration (v4)

This is the approved single 32-trial qualification attempt, not the 240-trial
benchmark. Use an ordinary Ubuntu WSL shell in `/home/geleza/p4/etc-training`,
not BMv2's `RuntimeCmd:` CLI. The explicit virtual-environment Python path
makes shell activation optional.

## Fixed matrix and preservation

| Component | Fixed setting |
|---|---|
| Modes | Forwarding, features, RF-B, RF-C |
| Workloads | Classification-heavy, cached-forwarding |
| Target rates | 250, 500, 2,000, 5,000 pps, ascending |
| Repetitions | One; exactly 32 planned trials |
| Phases | 5 RAW seconds warm-up, 20 RAW seconds measurement |
| Drain | 2 RAW seconds after each phase |
| Traffic | Existing collision-free recipes, 128-byte Ethernet frames |
| Builds | Existing frozen normal JSONs, DEBUG_REPORT=0, TEST_TIMESTAMPS=0, 65,536 slots |

The new `tools/run_raw_higher_rate_calibration.py` is a separate v4 entry point.
The v3 runner, native RAW sender, capture transport, clock auditing, independent
reference implementation, resource measurement, frozen RF models and P4 programs
are unchanged. The analyzer adds explicit v4 and attempt-ledger support while
preserving v1-v3 interpretation. Previous evidence is never rewritten.

The four configurations use the same bytes and methodology within every paired
block. Fresh switches and distinct flow keys AND CRC slots separate warm-up and
measurement. At 5,000 pps there are 25,000 warm-up plus 100,000 measured packets:
125,000 combined, below the existing 500,000-packet generator limit.
Classification-heavy occupies 15,632 distinct combined slots; cached-forwarding
occupies 3,912. Both are below the 60,000-slot safety bound. Expected measured RF
decisions are 12,496 and 3,128 respectively; partial opening prefixes explain why
not every allocated flow generates a decision.

Both RF-B and RF-C extract direction. This compares deployed forests, not the
isolated cost of direction extraction. No accuracy scoring or model fitting occurs.

## Same three verdicts and numerical requirements

| Verdict | Interpretation |
|---|---|
| Measurement integrity PASS/FAIL | Hard capture, packet, RAW audit, resource, counter and provenance requirements; failure stops the bounded attempt |
| Independent RAW qualification PASS/FAIL/INCONCLUSIVE | Absolute rates and RAW-normalized CPU percentages require independently qualified elapsed time |
| Sender-pacing conformance PASS/WARNING | Engineering conformance reported separately; warnings do not delete valid counts or qualified average rates |

Unchanged limits: target agreement within 2%; p99 start/completion lateness
<= max(1 ms, one interval); maximum <= max(5 ms, three intervals); short send-start
gaps (<one quarter interval) <=1%. These are engineering heuristics, not universal
scientific boundaries. A PASS is not a uniform-arrival or saturation certificate.

RAW auditing retains zero regressions, native brackets <=100 us, audit gaps
<=25 ms and endpoint coverage. Independent qualification retains all three query-only
providers, at least three valid observations/provider, at least 180 seconds of
span, endpoint coverage and complete conservative bounds within +/-1,000 ppm.
Highest-load observations must be fully contained in actual integrity-valid
measurement windows. Notifications targeting +2 RAW seconds are scheduling hints,
not substitutes for observed containment. All queries and failures remain evidence.

No clock corrections, synchronization changes, frequency compensation, sender
redesign, threshold relaxation, selective retries or rates above 5,000 are allowed.

## Evidence, exceptions and unavailable metrics

An immutable start receipt is written before every attempted trial, followed by a
separate completed/error receipt. The campaign summary reconciles attempted,
completed numerical and partial trials. An exception before a complete measurement
does not create a fictional zero-valued row or disappear from accounting.

Every completed trial keeps its original `trial_summary.json`. Campaign clock
qualification writes a separate `qualified_trial_summary.json`; it never recreates
the local summary. Raw phase observations, pacing arrays and warnings, counters,
resource windows, kernel timestamps, provenance and partial failure files remain
sealed. An incomplete attempt has no invented pacing verdict; campaign pacing
describes completed observations only.

Offered pps is successful sends / RAW offered duration. Delivered pps and Ethernet
Mb/s use unique outputs, including bounded drain, / the same duration; these are
not instantaneous egress or wire-rate measurements. Non-delivery is attributable
to the measured path only when input and capture accounting are reliable, and
is not automatically BMv2 loss. Capture/socket loss invalidates that inference.
CPU uses Linux-accounted ticks / RAW resource duration; the tick numerator is not
independently calibrated physical CPU time. Memory retains sampled RSS and lifetime
VmHWM separately. Kernel forwarding/inference latency remains unqualified: no
validated p50/p95/p99 forwarding delay or isolated RF inference latency is reported.

## Readiness and manual launch

Verified readiness:

- Installed nonprivileged regression suite: **288 tests passed**, zero skips,
  failures or errors. Campaign tests mock live acquisition; no privileged traffic
  was launched by the tests.
- Six measurement/qualification functions have identical Python ASTs to v3.
  The protocol dictionaries differ only in version name, exact rates and maximum
  trial count. Preparation and input seals verified.
- Complete normal-build packet-file smoke: **8/8 combinations passed**, each with
  320/320 byte-identical forwarded frames. RF decision counters were 40/40 for
  classification-heavy and 16/16 for the smoke's short cached recipe. Auxiliary
  feature, slot and packet-eight correctness checks passed.
- The first smoke stopped after RF-C produced 315/320 frames in an unpaced file
  burst. It remains at
  `/home/geleza/p4/etc-training/results/raw_performance_packet_file_checks/20261008T214118Z_49995f5498`.
  One complete identical smoke repeat passed; no timeout, gate, queue-depth,
  sender or frozen-program change was made. Transient egress queue overflow is
  plausible but not proven by this saved trial. The first failure was not relabelled.
- Frozen P4/models and original RAW sender/clock/transport/v3 runner hashes stayed
  unchanged; 195 artifacts from the completed v3 calibration were reverified.

Packet-file smoke verifies correctness, not live pacing, network references or
runtime performance. The failed and successful smoke attempts are both preserved.

Preparation:
`/home/geleza/p4/etc-training/results/raw_higher_rate_calibration_preparation/20261008T214101Z_0f836afa74`

Bound smoke:
`/home/geleza/p4/etc-training/results/raw_higher_rate_calibration_checks/20261008T214425Z_429f8e0dae`

Successful underlying packet-file checks:
`/home/geleza/p4/etc-training/results/raw_performance_packet_file_checks/20261008T214409Z_5b75e25d0d`

Run the following in the ordinary Ubuntu WSL terminal. `cd` selects the project
directory. The explicit Python path selects the training environment without
requiring activation; `-B` avoids writing Python bytecode. `sudo` allows the
private packet interfaces, not clock adjustments. The two arguments bind the
sealed preparation to its successful smoke receipt. The runner performs exactly
the fixed calibration and writes fresh evidence; it cannot launch 240 trials.

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/run_raw_higher_rate_calibration.py run \
  --prepared /home/geleza/p4/etc-training/results/raw_higher_rate_calibration_preparation/20261008T214101Z_0f836afa74 \
  --smoke-run /home/geleza/p4/etc-training/results/raw_higher_rate_calibration_checks/20261008T214425Z_429f8e0dae
```

Allow approximately 16-20 minutes plus setup/evidence overhead (15.5 scheduled
minutes). Keep the laptop awake, run one copy, and avoid unrelated heavy activity.
Do not start a selective retry after any failure. Paste the entire terminal output
and the new Evidence directory so all three verdicts, actual reference windows,
achieved-load comparability and warnings can be reviewed once before the final
240-trial go/no-go decision. If qualification fails, use the highest defensible
common qualified range; do not begin another troubleshooting cycle.

The privileged calibration is for the user to launch. No full sweep, commit or
push is authorized by this preparation stage. Dashboard and Makefile work follows
the finalized performance evidence.
