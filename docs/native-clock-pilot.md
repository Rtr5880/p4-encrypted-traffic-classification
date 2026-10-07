# Native-clock correctness pilot

> Historical pre-repair guide. For the rebuilt steady-clock switch and current
> exact commands, use [the clock repair guide](native-clock-repair.md).
> A fresh pilot preparation with `--clock-receipt` is now required; earlier
> preparation/result directories are preserved as historical evidence.

This stage uses one existing held-out N=8 record from the real ISCX VPN capture.
It does not retrain, retune, change features, move split assignments, or change
the committed P4/model sources. XGBoost stays offline.

## What is different from controlled replay?

Controlled replay supplied the original capture timestamps to P4. This pilot
does **not** supply any timestamps to P4. Its input is ordinary Ethernet/IPv4;
BMv2 uses its actual ingress clock. The sender aims for the original relative
packet gaps, but Linux/WSL scheduling can change the actual gaps.

```
Original eight IP packets + original relative gaps
                    |
            persistent raw sender
                    |
          private native-clock BMv2
                    |
       P4 state / features / RF debug reports
                    |
Original IP bytes + observed ingress times --> independent Python oracle
                    |
     compare state, features, leaves, scores and class
```

Only P4's `observed_us` supplies the actual clock value to the oracle. Expected
sizes, tuples, TCP flags, session boundaries, effective times and features are
reconstructed independently. Reported features are never used as expected
features. A changed prediction relative to the original PCAP-time prediction
is an observation, not automatically a bug.

## Files to review in VS Code

From **Ubuntu**, regardless of whether the venv is currently active:

```bash
cd /home/geleza/p4/etc-training
code tools/run_native_clock_pilot.py tools/native_prefix.py tools/native_pilot_transport.py docs/native-clock-pilot.md
```

- `native_prefix.prepare_prefix`: verifies frozen input hashes and selects a
  first-observed, first-instance, bidirectional held-out prefix. Selection uses
  protocol, duration and stable ID, not labels or whether predictions are right.
- `native_prefix.decode_raw_packet`: reads outer IPv4/TCP/UDP directly from the
  original bytes; preserves original payload and checksums.
- `native_pilot_transport.replay_frames`: opens both capture sockets before
  sending, uses one persistent sender and a monotonic schedule, and checks byte
  preservation/order/multiplicity. IPv4 identification is not assumed unique.
- `run_native_clock_pilot.compare_native`: compares per-packet state and all
  eight C features, then ten leaves, six Q24 score totals and predicted class.
  RF-B consumes its usual six-feature subset.
- `OwnedLinks`, `run_model`: create only private new veth pairs, start only
  private child switches, query their six decision counters automatically, and
  clean up only resources whose ownership still matches.

## Step 1 — run the tests

Execute in **Ubuntu**, directory **`/home/geleza/p4/etc-training`**:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover -s tools -p 'test_native*.py' -v
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover -s tools -p 'test_run_native_clock_pilot.py' -v
```

The explicit Python path uses the training environment even without `(.venv)`
in your prompt. These tests exercise fixtures, deliberately corrupted reports,
mocked network setup and cleanup. They do not send live traffic. Passing unit
tests does not mean the live native-clock test has passed.

## Step 2 — prepare and compile without sudo

Execute in the same **Ubuntu directory**:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python tools/run_native_clock_pilot.py prepare
```

This reads one capture and frozen extraction/split/model artifacts, verifies
their checksums, saves the eight unchanged IP packets, and compiles separate
native **debug** RF-B/RF-C builds. It leaves the committed P4 files unchanged.

Compilation definitions are `TEST_TIMESTAMPS=0`, `DEBUG_REPORT=1`,
`FLOW_SLOTS=65536`. Preparation does not require root, create interfaces or send
packets. Expect `PREPARATION PASS` and an `Evidence saved to:` directory.

Use that exact preparation directory in Step 3. Each preparation has a unique
directory; do not use a previous failed preparation.

## Step 3 — run the bounded live pilot

Execute in the same **Ubuntu directory**. Replace `PREPARATION_DIRECTORY` with
the complete path printed in Step 2 (not the results root):

```bash
cd /home/geleza/p4/etc-training
sudo /home/geleza/p4/etc-training/.venv/bin/python tools/run_native_clock_pilot.py run \
  --prepared PREPARATION_DIRECTORY
```

`sudo` is needed for Linux raw sockets and temporary veth creation, not for ML
training. The script runs B then C, each in a fresh private switch with empty
flow state and its own Thrift port. No manual CLI terminal is necessary. Your
existing `p1_*` demo links and switch are not stopped or reconfigured.

Both logical IP directions go through the same physical ingress. This is
intentional: the existing debug build always forwards to port 2; packet
direction features still come from IP/port endpoints, not interface direction.

Expected success lines:

```
RF-B: 8/8 forwarded; one decision; features/leaves/scores/class parity PASS; ...
RF-C: 8/8 forwarded; one decision; features/leaves/scores/class parity PASS; ...
NATIVE PILOT PASS — correctness only, not accuracy/performance. Evidence saved to: ...
```

Each model must have exactly one decision at packet eight. The six counter
packet totals must add to one and select the Python-oracle class. Counter bytes
must equal the triggering input Ethernet frame length, not debug-output length.
No collision is expected with this isolated single-conversation prefix.

If it fails, preserve the evidence directory and send the error plus
`failure.json`; do not rerun repeatedly or change the model to force a pass.
Ctrl+C triggers cleanup of the owned child and interfaces; forced process kill
or machine shutdown cannot guarantee cleanup. Ownership changes make cleanup
refuse deletion and report the problem rather than touch someone else's link.

## Reading the evidence

Each live run saves `summary.json` and per-model `RF_B/` and `RF_C/` folders:

- `comparison.json`: each packet's reported/expected state, decision features,
  leaves, scores and predicted class; original vs native IATs/features.
- `counter_query.json`: exact CLI queries and six counter readings.
- `transport.json`: scheduling lateness, sent/observed packets, missing indices,
  ordering/duplication errors and actual socket-read observations.
- `input.pcap`, `output.pcap`: observed bytes with userspace socket-read wall
  timestamps. These are diagnostic timestamps, not kernel capture timestamps
  or valid switch-latency measurements.
- `switch.log`, `switch_command.json`: startup/child-process evidence.

The default structural selection is a single 181,390 us UDP prefix. Its final
capture gap is only 59 us: do not expect a Python sender on WSL to reproduce
every original IAT exactly. The native oracle uses the actual reported times.

RF-B and RF-C run separately, so their actual arrival times can differ. The
summary also evaluates both frozen forests offline on each observed vector;
this exposes timing effects without falsely calling the two live timings
identical. It is not a direction-accuracy experiment on one example.

## Acceptance and limitations

Acceptance: 8/8 packets observed and forwarded per model; one packet-eight
decision; zero state/feature/leaf/score/class mismatches against the native
oracle; counters agree; original frozen inputs unchanged; owned cleanup passes.

This proves only bounded live native-clock correctness for one real prefix.
It does **not** establish six-class accuracy, macro-F1, full-dataset native
coverage, whole-capture timing/session reproduction, throughput, loss under
load, forwarding latency, RF execution latency, or hardware feasibility.

The debug output adds 123 bytes beyond an ordinary Ethernet/IP frame and extra
work. Dedicated links use MTU 9000, no addresses and IPv6 disabled before UP.
Real performance testing needs separate normal builds without debug headers.
Raw captures and generated evidence remain ignored by Git; review and commit
the new source/tests/guide only after the live pilot is understood.

## Verified handoff, 6 October 2026

The current preparation is already compiled and checked:

`/home/geleza/p4/etc-training/results/native_clock_pilot_preparation/20261005T222609Z_fa8d38947a`

You can use it directly without repeating Step 2:

```bash
cd /home/geleza/p4/etc-training
sudo /home/geleza/p4/etc-training/.venv/bin/python tools/run_native_clock_pilot.py run \
  --prepared /home/geleza/p4/etc-training/results/native_clock_pilot_preparation/20261005T222609Z_fa8d38947a
```

All 36 new fixture/fault-injection tests passed. The full suite ran 308 tests:
307 passed and one existing optional test was skipped. Both native programs
also passed real-prefix **unpaced packet-file** smoke tests, each with eight
reports, one decision, preserved IP bytes and zero state/feature/leaf/score/class
mismatches. Reproducible, checksum-sealed smoke evidence is saved at:

`/home/geleza/p4/etc-training/results/native_clock_pilot_checks/20261005T222946Z_5877bbca0e`

**The live veth replay is not yet run.** It needs your Ubuntu sudo password.
No native accuracy or performance result is being claimed. New source, tests
and this guide are uncommitted for review; existing P4/model sources are intact.
