# Controlled real-PCAP replay: RF-B and RF-C

This stage sends the actual captured IPv4 bytes through the committed P4 feature
extractor and RF classifier. It checks correctness and classification coverage.
The model files, feature definitions, training splits and committed P4 sources
are the existing ones. No fitting, tuning, accuracy calculation or native-clock
performance measurement is performed by this runner.

All commands below belong in an **Ubuntu/WSL shell**, in:

`/home/geleza/p4/etc-training`

The absolute Python executable selects your training environment. The prompt
does not need to show `(.venv)`. Do not paste these commands at `RuntimeCmd:` or
into PowerShell. No `sudo` is required: these checks use private packet-file
BMv2 processes and do not use the live veth interfaces or port 9090.

## What the two paths compare

```text
Original inventoried capture (read-only, original packet order)
    |
    +--> TShark fields --> existing Python flow-instance extractor
    |                       |
    |                       +--> compare with saved N8 extraction records
    |                       +--> independent hash-slot ownership prediction
    |                       +--> expected features and integer RF results
    |
    +--> independent PCAP/PCAPNG byte reader
            |
            +--> Ethernet + test timestamp header + unchanged IPv4 bytes
                    |
                    +--> private BMv2 RF-B process --> compare every report
                    +--> fresh BMv2 RF-C process   --> compare every report
```

The Python reference decides eligibility through the same TShark fields and
decoder as the original extraction. The adapter sends every source packet,
including rejected packets and packets arriving after number eight. It does not
prefilter traffic using the expected result. This makes an eligibility mismatch
visible instead of removing the troublesome packet before P4 receives it.

## Your three steps

### 1. Open the source and run the focused tests

Enter the repository and open the guide and runner in VS Code:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training/tools/replay_real_pcaps.py \
  /home/geleza/p4/etc-training/tools/pcap_replay_io.py \
  /home/geleza/p4/etc-training/docs/real-pcap-replay.md
```

The runner contains the experiment logic. The I/O helper reads classic PCAP and
PCAPNG and follows BMv2's growing output without repeatedly loading it into RAM.

For a first code walkthrough, read `wrap_packet` and `expectation` together.
`wrap_packet` adds the packet number and controlled time around the original
bytes; it never uses an expected class. `expectation` asks the existing Python
extractor what state that packet should produce and independently predicts its
hash slot. Then read `verify_frame`, which compares the actual switch report to
that expected state before comparing tree leaves, score sums and class.

Run the focused tests from this same Ubuntu directory:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover \
  -s /home/geleza/p4/etc-training/tools -p 'test_*replay*.py' -v
```

These tests deliberately exercise malformed captures, partial output records,
backward timestamps, flow boundaries and damaged parity reports. A successful
test run runs **30 tests** and ends with `OK`. These tests verify the replay machinery; Step 2 executes
the actual compiled P4 classifiers on real traffic.

### 2. Repeat the first complete capture yourself

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/replay_real_pcaps.py \
  --capture vpn_hangouts_audio2.pcap
```

This command verifies the capture hash, compiles both existing model variants
with controlled timestamps and debug reports, reconstructs the Python reference,
and replays all 479,063 packets once through RF-B and once through RF-C. Each
model starts with fresh flow state. It does not require a separate CLI terminal.

You will see progress during preparation and replay. Successful completion ends
with:

```text
CONTROLLED REAL-PCAP PARITY PASS — RF-B and RF-C.
Evidence saved to: /home/geleza/p4/etc-training/results/real_pcap_replay/<unique-run>
```

An error stops the run and writes `failure.json`; that directory is incomplete
evidence. A pass requires every expected packet and decision to be accounted for.
Missing outputs are failures, never treated as collision exclusions.

### 3. Scale correctness checks to the included captures

After the single-capture run passes, this command processes the **29 included
captures** from your inventory, sequentially, through both model variants:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/replay_real_pcaps.py \
  --all-included
```

This includes both dataset folders and respects the existing exclusions. A
fresh process is used for every capture/model pair, matching capture-scoped
offline identities. This is an evaluation of separate capture workloads, not
one continuous multi-capture deployment with persistent state.

To investigate a specific capture without repeating all of them, use its exact
inventory filename with `--capture`. The option may be repeated, for example:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python \
  /home/geleza/p4/etc-training/tools/replay_real_pcaps.py \
  --capture vpn_email2b.pcap
```

Email2b is useful for the known one-microsecond backward step. Each command
creates a new evidence directory. The runner streams packets and compresses
its created PCAP evidence after verifying a lossless gzip round trip. The
original dataset remains unchanged. It checks available space on both WSL and
the Windows drive because WSL's virtual disk size can overstate physical space.

Research accuracy is the later, separate stage: use the existing held-out test
assignments and the common classified population for B/C comparisons. This
runner deliberately stops at correctness and coverage.

## Reading the results

Each `capture_NNN/preparation.json` contains the Python counts and collision
prediction. Each `capture_NNN/RF_B/summary.json` and `RF_C/summary.json` contains
the verified BMv2 counts. The top-level `summary.json` collects all selected
captures and seals output files with SHA-256 hashes.

| Quantity | Meaning |
|---|---|
| `packets_checked` | Every original packet produced a corresponding checked report |
| `expected_n8_instances` | Reference instances with at least eight eligible packets |
| `collision_packets` | Eligible packets belonging to a tuple whose slot has another owner |
| `collision_excluded_parents` | Distinct excluded bidirectional parent tuples |
| `collision_excluded_n8_instances` | Classifiable instances belonging to those excluded parents |
| `expected_classifications` | N8 instances remaining after instance-level collision exclusions |
| `classification_coverage` | Expected classifications divided by expected N8 instances |
| `predicted_class_counts` | Decisions made in each class; no ground-truth comparison |
| `*_mismatches` | Must all be zero for a pass |

The required equality is an equality of **instance/decision IDs**, as well as
counts:

```text
all expected N8 instances - collision-excluded N8 instances
    = observed packet-eight classifications
```

Collision packet counts cannot be subtracted from instance counts. Short
instances are reported separately; they should never produce a decision.

`decisions.jsonl` records the exact original `record_id`, parent ID, packet number,
all eight features, ten leaf IDs, six score sums and predicted class. These IDs
will let the later evaluation join predictions to the already frozen splits.
The complete compressed output PCAP retains the per-packet debug evidence.

## Timing, ordering and direction

Original timestamps are represented exactly as integer nanoseconds. The injected
value is `timestamp_ns // 1000 - origin_us`, where `origin_us` is the smallest
whole-microsecond timestamp in that capture. Flooring occurs before subtraction.
The constant offset keeps values within the 48-bit header while preserving all
microsecond differences and backward steps. P4 and Python apply their existing
per-parent running maximum; no packet sorting or timestamp rewriting occurs in
the source PCAP.

The raw IP packet is preceded by 14 Ethernet bytes and a 14-byte test header.
Neither header contributes to `ip.len`. The debug output replaces the test
header with feature and RF reports, followed by the original IP packet. Its
length and SHA-256 are checked on every output packet.

The entire bidirectional capture enters one replay input in original order.
Direction still comes from the first eligible sender of each instance and the
packet endpoints. Ingress-port choice does not define direction. Sending the
two directions through separate file inputs could reorder packets because BMv2
merges those inputs by PCAP timestamps.

The named pipe/FIFO feeds at most 32 outstanding packets and waits for their
reports. This bounds replay bursts below the switch's default egress queue
capacity. The waiting is part of the correctness harness; it is not a speed,
throughput or latency result. P4 uses the injected timestamp, not wall-clock
spacing between these batches.

## What to read in the code

All files are under `/home/geleza/p4/etc-training`.

- `tools/replay_real_pcaps.py`: `wrap_packet` preserves IP bytes and sets time;
  `expectation` computes reference flow state and collisions; `verify_frame`
  checks each report; `run_replay` owns the private BMv2 process and FIFO.
- `tools/pcap_replay_io.py`: `iter_capture` recognizes the real file format;
  `PcapTailReader` resumes partial records while BMv2 writes them.
- `tools/test_replay_real_pcaps.py`: deliberately incorrect feature, tree, score,
  class and packet outputs must be rejected by the checker.
- `tools/test_pcap_replay_io.py`: independently constructed PCAP/PCAPNG fixtures
  exercise format and timestamp edge cases.

The Python oracle keeps the original string-sorted parent key so saved IDs stay
stable. The P4 hash uses numerically ordered IPv4 endpoint/port pairs and CRC32;
the checker computes that slot independently and checks the reported slot.

This implementation never reclaims a hash slot during a run. An idle timeout or
RST resets an instance belonging to its resident tuple, not the slot's owner.
Colliding traffic must leave that resident state unchanged. All subsequent
resident packet reports remain subject to the same exact state checks.

Python and P4 can name a rejection differently. For example, Python detects
multiple headers in an ICMP error quoting another IP packet; P4 rejects its
unsupported outer ICMP protocol. The required agreement is the eligibility
decision. Both reason counts remain in the evidence. Any eligibility mismatch,
including an issue caused by capture truncation or a nested protocol, fails the
run for investigation instead of silently changing the filter.

## Verification performed during implementation

The final source version passed both complete captures in this evidence run:

`/home/geleza/p4/etc-training/results/real_pcap_replay/20261004T195816Z_58c0a8fb8a`

`capture_001` is Hangouts audio2; `capture_002` is Email2b. Both have separate
RF-B and RF-C reports. Across the two models and captures, **995,874 packet
reports** were checked. Earlier implementation runs remain available and were
not overwritten.

| Capture | Packets checked per model | Reference N8 instances | Collision-excluded N8 instances | Decisions per model | Coverage |
|---|---:|---:|---:|---:|---:|
| vpn_hangouts_audio2.pcap | 479,063 | 142 | 1 | 141 | 99.30% |
| vpn_email2b.pcap | 18,874 | 78 | 0 | 78 | 100% |

Both RF-B and RF-C had zero eligibility, state, feature, leaf, score, class,
packet-byte or decision-completeness mismatches. Every N8 reference record was
also matched to the original validated extraction. The 99.30% is classification
coverage, not accuracy against the provisional capture labels.

The Hangouts collision affected one parent, one N8 instance and 25 packets.
The other 141 N8 instances classified exactly once. Both variants excluded the
same instance, and colliding traffic did not change resident-flow state.

Email2b exercised the known backward step: one timestamp adjustment of 1,000 ns,
plus five idle-timeout boundaries. All 78 N8 instances classified. Its N8 count
belongs to the final idle/TCP-aware extraction, which is different from the
earlier conversation-only pilot.

During review, malformed-report error handling was improved: a second failed
decode no longer obscures the original mismatch. A new test checks that even a
truncated report produces readable failure diagnostics. The packet, feature and
RF semantics are unchanged by that diagnostic improvement.

The final focused suite passed all **30 tests**. The complete training-environment
regression suite ran **272 tests: 271 passed and one was skipped** because Scapy
is installed in `bmv2-venv`. The eight manual-demo tests, including that Scapy
frame-construction test, passed separately in `bmv2-venv`.

## Full-dataset controlled replay completed

The user-run expansion passed all **29 included captures** for both RF-B and
RF-C. Evidence is saved in:

`/home/geleza/p4/etc-training/results/real_pcap_replay/20261005T182524Z_ba953271f7`

Each model checked **4,111,471 original packets** and produced **2,078 decisions**
from **2,081 reference N8 instances**. Three collision-excluded N8 instances
account for the difference, giving **99.86% N8 classification coverage**. There
were zero eligibility, instance, feature, leaf, score, class, packet-byte or
decision-completeness mismatches. All **398 frozen held-out N8 records** produced
decisions; the three exclusions belong to development data.

The replay runner still does not score activity-label accuracy or measure
native-clock performance. The next implementation stage is native-clock
classification evaluation followed by normal-build performance benchmarking;
the completed controlled replay must not be treated as a throughput benchmark.
