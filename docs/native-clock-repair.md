# BMv2 native-clock repair — 7 October 2026

The clock source has been corrected and rebuilt. The next student action is the
**paced one-prefix pilot**, not the full evaluation or a performance benchmark.
RF-B/RF-C, first-eight eligibility, the six/eight feature definitions, running-max
clamping, labels and frozen split remain unchanged. No retraining was performed.

## What failed and what was changed

The incomplete full run is preserved at:

```text
/home/geleza/p4/etc-training/results/native_evaluation/20261007T170152Z_63d7d652b1
```

Its original summary, metrics, failure marker, captures and hashes were NOT
rewritten. It remains diagnostic evidence of the old adjustable-clock build.

The local C++ toolchain maps `high_resolution_clock` to `system_clock`. The old
BMv2 elapsed timestamp therefore followed wall-clock corrections. Saved traffic
showed backward ingress timestamps and compression of longer intervals, not
packet loss. The clock-adjustment initiator was not established; we did not
disable time services, change WSL configuration or set the host clock.

In `/home/geleza/p4/behavioral-model/targets/simple_switch/simple_switch.h`:

```cpp
using clock = std::chrono::steady_clock;
static_assert(clock::is_steady, "SimpleSwitch elapsed clock must be steady");
```

`steady_clock` measures monotonic elapsed time; its origin is not a calendar
date. `get_ts()` remains `clock::now() - start`, converted to microseconds.
Ingress, egress and queue durations consequently share the monotonic domain.

The control-plane epoch API intentionally remains wall-clock time:

```cpp
// simple_switch.cpp, get_time_since_epoch_us()
auto tp = std::chrono::system_clock::now();
```

Only these two BMv2 source files changed: eight inserted lines, two removed.
The existing unrelated untracked `proto/cpp_out/` and GRPC config file were
preserved. We rebuilt only the local `simple_switch` target, using two build
workers; there was no installation or reset of the BMv2 repository.

The reproducible patch is:

```text
/home/geleza/p4/etc-training/patches/bmv2-simple-switch-steady-clock.patch
```

It is already applied to this local checkout. Do not apply it a second time.
The original header, source and executable were backed up under
`C:/Users/user/OneDrive/Documents/EEE4022/tmp/clock_repair/before/`.

## Validator correction: two independent checks

```text
Raw observed ingress timestamps
    |                              |
Clock-quality audit                Existing running-max state/oracle
regressions, equal steps,           effective_time = max(previous, raw)
maximum backward step              features -> leaves -> scores -> class
    |                              |
clock clean?                       parity correct?
    +------------------------------+
       A complete stage requires BOTH
```

`tools/analyze_native_evaluation.py` now evaluates feature and RF parity even
when raw time goes backwards. It does not substitute reported features or
reported effective time into the oracle. Positive 48-bit timestamps and genuine
clock progress are still required; all-zero/constant/malformed clocks fail.

`clock_quality` reports raw regression events and clamp adjustments separately.
The timing output retains negative raw gaps and also reports nonnegative
effective gaps. We have not hidden the clock issue by silently clamping logs.

Parity-valid predictions under bad timing remain available as diagnostic
classification metrics. However, `raw_clock_clean: false` prevents a complete
pilot/full-stage PASS. Missing clock evidence cannot certify cleanliness.
The full evaluator also checks across different cases, associating reports by
input capture order and packet occurrence rather than output ordering.

New batch-start messages display the original scheduled span before waiting, so
a 136-second batch no longer looks like an unexplained freeze.

## The executable was checked, not only the wrapper

The executable normally launched by your runners is a libtool wrapper. Its
hash did not change on rebuilding, while the actual `.libs/simple_switch` did.
`tools/verify_bmv2_clock.py` inspects the compiled `get_ts()` function and verifies
that it calls `steady_clock::now()`. It separately verifies that the compiled
epoch API calls `system_clock::now()`.

Clock-build receipt:

```text
/home/geleza/p4/etc-training/results/bmv2_clock_repair/20261007T180912Z/clock_receipt.json
```

Actual ELF SHA-256 after repair:

```text
5cf33df6dfae54757a4d30d9088cf872141b889a61bcfb313b9e816e18e60727
```

Preparations seal the receipt, actual executable, wrapper and clock source
hashes. A subsequent rebuild/source change invalidates that preparation. This
prevents accidentally testing a stale or different switch binary.

To check the receipt yourself in an **Ubuntu terminal**:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/verify_bmv2_clock.py \
  --receipt /home/geleza/p4/etc-training/results/bmv2_clock_repair/20261007T180912Z/clock_receipt.json
```

Purpose: confirm that the verified source and actual compiled switch have not
changed. No interfaces, traffic, root permission or training are involved.

## Verification already completed

- Scoped BMv2 rebuild succeeded.
- Actual elapsed-clock and wall-clock-epoch compiled calls were verified.
- Project suite: **405 tests run; 404 passed, one optional Scapy test skipped**.
- New regression tests include correct clamping under backward raw timestamps,
  corrupt state/leaf/score rejection, raw-clock stage failure, cross-case clock
  events, changed-binary receipts and a required clean live-pilot gate.
- A fresh one-prefix preparation was created with unchanged original IP bytes,
  frames and scheduling offsets; native P4 builds compiled for both models.
- Unpaced non-root packet-file integration passed for both models: eight
  packets, one decision each, zero state/feature/leaf/score/class mismatches,
  clean raw clocks. This is NOT the paced live pilot or an accuracy benchmark.

Fresh pilot preparation:

```text
/home/geleza/p4/etc-training/results/native_clock_pilot_preparation/20261007T180929Z_49b07bd31f
```

Packet-file verification evidence:

```text
/home/geleza/p4/etc-training/results/native_clock_pilot_checks/20261007T181027Z_7200bcf0c1
```

The selected prefix is the same eight original frames as the earlier pilot:
14653, 14674, 14683, 14707, 14742, 14745, 14754 and 14755. Its intended span is
181,390 microseconds. No packets are padded or rescaled.

## What YOU run next: paced live pilot

Use **one Ubuntu/WSL terminal** in this directory:

```text
geleza@DESKTOP-8QLC84Q:~/p4/etc-training$
```

```bash
cd /home/geleza/p4/etc-training
sudo /home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/run_native_clock_pilot.py run \
  --prepared /home/geleza/p4/etc-training/results/native_clock_pilot_preparation/20261007T180929Z_49b07bd31f
```

Purpose: send the original eight-packet prefix through each frozen RF model
using the corrected switch's actual ingress clock and confirm complete parity.
`sudo` is required for private virtual interfaces and raw sockets; enter your
Ubuntu password yourself and do not send it in chat. The explicit Python path
selects the correct virtual environment regardless of whether the prompt shows
`(.venv)`. You do not need a manually started switch or separate T1/T2 sessions.

Expect each model to report:

```text
8/8 forwarded; one decision; features/leaves/scores/class parity PASS;
raw clock regressions=0; clock PASS
```

The final acceptance target is `NATIVE PILOT PASS`. The predicted class can
change with ordinary native scheduling jitter; correctness means agreement with
the oracle on the actual observed features, not a guaranteed class label.

Evidence is written to a NEW directory under:

```text
/home/geleza/p4/etc-training/results/native_clock_pilot/
```

Review `summary.json` and `RF_B/comparison.json`, `RF_C/comparison.json`:

- `passed: true`, `raw_clock_clean: true` in the summary.
- `parity_passed: true` and `clock_quality.clean: true` for each model.
- `clock_quality.raw_backward_steps: 0` and no raw regression events.
- Eight captured packets, one decision, matching six class counters and bytes.
- Successful temporary-interface/process cleanup.

Paste the terminal output and the new evidence directory back to the chat.
Do not immediately start the old full-evaluation command.

## What follows AFTER the clean pilot

The full preparation now requires both `--clock-receipt` and `--pilot-run`.
It verifies the clean live pilot and its evidence hashes against this exact
binary before preparing all 398 frozen cases. A packet-file smoke check does
not qualify as a live pilot. The old full preparation is intentionally rejected
by the new schema/source checks; it remains available as historical evidence.

After reviewing your clean pilot, we will supply the exact new full-preparation
and run commands using its real evidence path. No model changes or timing-bin
refinement are part of this clock repair.

Zero raw regressions on one short prefix are an initial check, not proof that
all long intervals are accurate. The full run must also show no cross-case clock
regressions and sensible observed-versus-intended timing over longer prefixes.
Ordinary scheduling jitter will still exist, and FTPS minimum-IAT sensitivity
may persist. That is a later development-data modelling experiment.

The performance benchmark remains postponed until native clock quality and
full-run parity are clean. All new/updated project sources, tests, patch and
documentation remain uncommitted for student review; no Git pushes were made.
