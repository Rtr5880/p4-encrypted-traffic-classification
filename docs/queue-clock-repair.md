# Egress queue clock repair and fresh performance rerun

The scoped queue-clock fix is applied and the local BMv2 simple_switch target
has been rebuilt. Your next action is the fresh live performance pilot below.
No RF model, feature, label, packet-count policy or frozen split was changed;
no retraining or Git commit/push was performed.

## Why the first pilot was incomplete

The preserved pilot at
`/home/geleza/p4/etc-training/results/performance_pilot/20261007T212707Z_a187129aef`
forwarded all 1,024 frames unchanged, produced all 80 expected decisions, and
had zero capture drops. Its first RF-B classification-heavy trial recorded a
wall-clock offset correction of about -632.6ms. Its latency was correctly
withheld. The other three timing trials passed.

`detected_offset_changes: 213` counted samples remaining displaced from the
initial offset; it did not establish 213 separate jumps. All 31 stored evidence
hashes still match after this repair. That directory was not rewritten.

The earlier feature-clock repair protected P4 ingress timestamps but did not
change the scheduler's separate clock alias. BMv2's egress queue used
`high_resolution_clock`, which aliases adjustable `system_clock` on this
toolchain. Its next release deadline is computed from both the current time
and the previous deadline; a backward correction can leave the previous
deadline in the future. This is a scheduler/platform issue, not RF inference
complexity. The initiator of the host correction was not established.

## Exactly what changed

Only one additional BMv2 source file changed:

`/home/geleza/p4/behavioral-model/include/bm/bm_sim/queueing.h`

Both scheduled queue templates, `QueueingLogicRL` and `QueueingLogicPriRL`, now
use `std::chrono::steady_clock`, with compile-time `clock::is_steady`
assertions. SimpleSwitch uses the priority template. The second template was
updated consistently because it has the same elapsed-deadline requirement.
No FIFO ordering, priorities, capacity or rate-setting rules were changed.

| Clock use | After repair | Purpose |
| --- | --- | --- |
| P4/BMv2 elapsed timestamps | steady clock, unchanged | Feature IAT and elapsed durations |
| Egress release deadlines | steady clock, newly corrected | Queue scheduling unaffected by backward wall-time corrections |
| Calendar-time API and kernel software capture stamps | wall clock, unchanged | Epoch timestamps; capture latency still needs its independent quality audit |

This fix does NOT make Linux socket timestamps monotonic. A future wall-clock
step can still invalidate kernel-timestamp latency, and the validator will
continue to reject it. No clock service was disabled, host time changed, kernel
timestamp replaced with userspace read time, or tolerance relaxed.

Only the local simple_switch target was rebuilt with two workers; no system
installation or repository reset was performed. Existing unrelated BMv2
changes were preserved.

Reproducible patch, already applied (do not apply it again):

`/home/geleza/p4/etc-training/patches/bmv2-queue-steady-clock.patch`

The exact prior header and 86MB executable are recoverable under:

`C:/Users/user/OneDrive/Documents/EEE4022/tmp/queue_clock_repair/before/`

## Verification completed

- 14 C++ queue checks passed as ordinary WSL user geleza: both clock contracts,
  FIFO/unlimited queues, positive-rate release, independent queues/workers and
  priorities, full-queue rejection and move preservation. Tests did not change
  the host clock or inject artificial clock jumps.
- The actual compiled PriRL enqueue and dequeue functions call
  `steady_clock::now()` rather than `system_clock::now()`. The dequeue wait
  calls `pthread_cond_clockwait`. Existing compiled `get_ts()` still uses a
  steady clock; the calendar-time API still uses a system clock.
- Fresh non-root native packet-file parity: RF-B and RF-C each forwarded eight
  original real packets, classified once, and had zero feature/instance/leaf/
  score/class mismatches. This is unpaced correctness evidence, NOT a live
  pilot or new accuracy/performance result.
- Fresh normal-build packet-file smoke: 96/96 frames unchanged and eight
  expected decisions across four private runs. Debug reports are disabled.
- Full Python regression suite: 477 tests run, 476 passed, one optional test
  skipped. Unit-test fixture output is not a live benchmark result.
- Frozen P4 source hashes remain unchanged. No new accuracy result is claimed.

New queue-clock receipt:

`/home/geleza/p4/etc-training/results/bmv2_queue_clock_repair/20261007T215248Z/queue_clock_receipt.json`

New actual ELF SHA-256:

`30124d75968f2415a62c5ed379cbb278be8d86f40e62b7a22b81a9772a1de929`

The old ELF is kept with SHA-256:

`5cf33df6dfae54757a4d30d9088cf872141b889a61bcfb313b9e816e18e60727`

The verifier checks the actual executable, queue header, feature-clock source,
wrapper, approved exact header diff, previous executable backup and test
evidence. Checking only the wrapper would miss the rebuild.

## Historical evaluation versus the new executable

The 398-instance-per-model native evaluation remains valid historical evidence
for its ORIGINAL executable. We did not rerun those 796 cases on the new build
or relabel its provenance as the new binary.

The fresh preparation records `historical_native_on_same_binary: false` and
`queue_clock_upgrade: true`. It checks the historical evaluation's sealed
preparation/population and unchanged P4/model hashes, then requires fresh
native parity on this new binary. Live performance also requires fresh normal
smoke bound to the exact prepared manifest and queue-clock receipt.

Old preparations/receipts will reject the changed binary/source, as intended.
Use the NEW paths below, not the previous pilot command or edited JSON.

## Your exact manual rerun

Use ONE **Ubuntu/WSL terminal**, in **`/home/geleza/p4/etc-training`**. An active
venv is optional because the command selects its Python explicitly. You do not
need to start separate BMv2 or CLI terminals.

```bash
cd /home/geleza/p4/etc-training

sudo /home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/run_performance_pilot.py run \
  --prepared /home/geleza/p4/etc-training/results/performance_pilot_preparation/20261007T215620Z_15a395a793 \
  --smoke-run /home/geleza/p4/etc-training/results/performance_pilot_checks/20261007T215750Z_883ef4a266
```

`cd` selects the project. `sudo` permits temporary owned veths/raw sockets.
`--prepared` selects the fresh normal RF-B/C builds and unchanged synthetic
workload. `--smoke-run` proves their non-root forwarding/counter smoke already
passed on this exact binary/preparation. Neither argument starts training.

The same four 100pps trials each send 256 frames: heavy workloads expect 32
decisions/model; mostly cached workloads expect eight. Scheduled traffic totals
10.24 seconds, plus setup/drain/query/cleanup overhead. Avoid other benchmarks
or downloads; do not run a second copy while the first is active.

Successful completion requires all four lines to report `delay VALID` and
`PILOT PASS`, followed by `PERFORMANCE PILOT PASS`. If a kernel wall-clock event
still causes `INCOMPLETE`, preserve the run and paste its output. Do not keep
retrying until a preferred number appears or loosen the audit.

New evidence is saved under
`/home/geleza/p4/etc-training/results/performance_pilot/` in a unique directory.
This remains an instrumentation pilot, not a capacity sweep, RF-only latency
measurement, hardware line-rate result or media-accuracy evaluation.

## Review/recheck the source

From an **Ubuntu shell in `/home/geleza/p4/etc-training`**:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training
```

Review `tools/verify_bmv2_queue_clock.py` (compiled-code/receipt checks),
`tools/queue_clock_tests.cpp` (real C++ queue tests),
`tools/test_verify_bmv2_queue_clock.py` (20 receipt/compiled-call tests),
`tools/test_performance_queue_gate.py` (five provenance/smoke-gate tests), and
the new queue-upgrade gates in `tools/run_performance_pilot.py`.

For a read-only receipt check, from the SAME project directory:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/verify_bmv2_queue_clock.py \
  --receipt /home/geleza/p4/etc-training/results/bmv2_queue_clock_repair/20261007T215248Z/queue_clock_receipt.json
```

This verifies hashes and the recorded upgrade without sending traffic or
changing clocks. Keep the backup/test files referenced by the receipt until
we intentionally archive the evidence; deleting them invalidates this gate.
