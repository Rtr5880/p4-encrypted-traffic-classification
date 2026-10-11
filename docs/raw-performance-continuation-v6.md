# Final RAW benchmark: one bounded continuation session (v6)

This is an orchestration amendment, not a new measurement system. It imports
the unchanged v5 `run_trial` and reuses its RAW sender, capture, audit, resources,
counter checks, frozen normal-build programs and byte-identical traffic plans.

## What stays unchanged

The original session at
`/home/geleza/p4/etc-training/results/raw_performance_benchmark/20261008T223313Z_9752ce54b5`
remains read-only. Its first trial is forwarding, classification-heavy,
1,000 pps, repetition 4: 20,000 input packets and 19,950 output packets, with
50 observed path non-deliveries. Its integrity failure, pacing warning and
inconclusive timing qualification are never overwritten or promoted.

The original sealed 40-block, 160-position schedule is retained exactly.
The new session starts at position 2 (`rf_b`, same block as the failed first
trial) and ends at position 160. It makes 159 new attempts, once each, without
retrying position 1, regenerating traffic identities or reordering modes.
The two sessions are explicitly identified in provenance and final analysis.

Numerical gates remain unchanged: maximum RAW audit sampling gap 25 ms,
maximum clock-read bracket 100 microseconds, independent rate qualification
within 1,000 ppm with at least 180 seconds of reference span, and every
existing packet/capture/resource/counter and sender-pacing threshold.

## Acquisition stopping policy, declared before execution

An isolated completed local integrity failure is retained as **INVALID** and
acquisition proceeds only after cleanup, evidence, inputs, environment and
resource checks. It is not downgraded to a pacing warning.

Stop the continuation for either recurring pattern:

- Three consecutive completed continuation trials are integrity-invalid.
- The same concrete integrity failure occurs in four of the last eight
  completed continuation trials. Concrete warm-up failure codes count too;
  a generic warm-up wrapper does not merge unrelated failures.

These are operational safeguards, not statistical tests or relaxed measurement
requirements. The historical trial does not seed a streak in a separately
executed session. Pacing warnings do not count toward an integrity streak.

Stop immediately for an acquisition exception, corrupted evidence, changed
frozen/source inputs, failed process/link cleanup or state checks, unsafe
execution, or declared resource exhaustion. Existing disk/available-memory
preflight and runner RSS limits remain in force. An invalid resource sampling
window is not itself proof of resource exhaustion; it remains an integrity
failure and counts toward recurrence.

There is one exclusive execution claim per historical campaign. A second
suffix launch is refused, including after an interrupted continuation. This
prevents selective replacements or another open-ended retry cycle. All attempted
start/result receipts, partial artifacts, warnings and failures are retained.

## Independent qualification and final interpretation

The continuation obtains its own initial, under-load and final independent
reference queries. Only its integrity-valid measurement windows support its
qualification. Old windows are not imported. No old elapsed-rate observations
are rehabilitated by a new clock certificate.

Local trial summaries are immutable. Separate qualified summaries apply the
new-session clock certificate and mask unsupported rates/CPU normalization.
Each completed trial retains all three verdicts: measurement integrity,
independent RAW qualification and sender-pacing conformance.

Acquisition completion does not mean every measurement is qualified. Even if
all 159 new trials qualify, original trial 1 is still invalid, so the combined
campaign cannot be described as 160/160 passing. Final tables show actual valid
sample counts per metric, configuration, workload and rate. Paired comparisons
use supported matched repetitions and disclose achieved offered load and
pacing differences; missing repetitions are not replaced or imputed.

Reliable packet counts, accounting and memory observations can remain usable
where their own gates pass. Preserve the distinction between path non-delivery
and capture loss; no loss is automatically attributed to BMv2.

Forwarding delay p50/p95/p99 and isolated RF inference latency remain
unqualified. Complete delivery at 1,000 pps is not maximum capacity or a
saturation result. Both RF variants already extract direction: the comparison
is between deployed forests, not the isolated cost of direction extraction.

## Nonprivileged verification and manual launch

All commands are run in Ubuntu/WSL, directory
`/home/geleza/p4/etc-training`. An activated virtual environment is optional
because the commands name its Python interpreter explicitly.

Preparation and packet-file smoke checks do not create live interfaces or
launch offered-load traffic. They bind the sealed original schedule, failed
trial, unchanged four normal builds, RAW libraries and new orchestration code.

Verified preparation:
`/home/geleza/p4/etc-training/results/raw_performance_continuation_preparation/20261008T225430Z_b3e069db13`

Verified smoke receipt:
`/home/geleza/p4/etc-training/results/raw_performance_continuation_checks/20261008T225505Z_785f295115`

The relevant installed regression suite passed all **324 tests**, without
failures, errors or skips. The eight normal-build packet-file trials each
forwarded 320/320 unchanged frames; RF counter checks and two auxiliary debug
feature/slot/packet-eight checks passed. These establish harness/build
correctness, not live sender pacing or new clock qualification.

Run this once in your Ubuntu terminal:

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python -B \
  /home/geleza/p4/etc-training/tools/continue_raw_performance_benchmark.py run \
  --prepared /home/geleza/p4/etc-training/results/raw_performance_continuation_preparation/20261008T225430Z_b3e069db13 \
  --smoke-run /home/geleza/p4/etc-training/results/raw_performance_continuation_checks/20261008T225505Z_785f295115
```

This starts the separate execution session, performs fresh safety and
independent-reference checks, then manages switches and traffic automatically.
The first traffic line identifies original trial 2: RF-B, classification-heavy,
1,000 pps, repetition 4. Do not re-run the old v5 command; that would repeat
original position 1. No separate BMv2 or CLI terminal is needed for this runner.

Allow 76.85 minutes of scheduled phases (159 x 29 seconds) plus switch startup,
boundary checks, evidence writing and analysis. Plan about 90–115 minutes;
execution can stop earlier under the declared safeguards. Keep the laptop
powered, avoid sleep/hibernation and substantial competing workloads, and do
not start another benchmark. This is standard environmental control, not a
request to change synchronization or clocks.

The command returns a nonzero status if any new trial is unqualified or the
continuation is incomplete. Inspect the saved summary rather than assuming a
nonzero exit means evidence was lost. The combined analysis is written to a
new analysis directory, with historical evidence linked and independently
verified. After this one bounded session, analyze the available data and close
performance evaluation; no automatic privileged retries are performed.
