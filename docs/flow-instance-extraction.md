# Candidate flow-instance extraction: inspect, run, test

## Where everything lives

All commands below run in an **Ubuntu/WSL terminal**, at:

```text
/home/geleza/p4/etc-training
```

The Python commands use the full `.venv/bin/python` path. An active `(.venv)`
prompt is therefore optional: both prompts run exactly the same interpreter.
Do not run these commands in PowerShell or from the p4c source directory.

```bash
cd /home/geleza/p4/etc-training
pwd
code tools/extract_flow_instances.py tools/validate_instance_output.py tools/test_extract_flow_instances.py tools/test_flow_instance_runner.py docs/flow-instance-extraction.md
```

`cd` selects the project; `pwd` confirms it; `code` opens the actual source,
tests and this guide in VS Code. In Windows Explorer the project is at:

```text
\\wsl.localhost\Ubuntu\home\geleza\p4\etc-training
```

The original `tools/extract_feature_pilot.py` and timeout auditor are unchanged.
The new extractor imports their decoder/inventory helpers, so retain those files.
No raw capture is edited. Each extraction creates a new output directory.

## What changed and why

The pilot had one candidate conversation per capture-scoped bidirectional
5-tuple (IP addresses, ports, protocol), regardless of inactivity or tuple reuse.
This version divides that parent into explicit **candidate instances**, and
emits one opening N4 record and one opening N8 record when enough eligible
packets exist. It does not emit a new window every four/eight packets.

```text
capture + bidirectional 5-tuple (parent grouping identity)
    |
    +-- instance 1 -- first 4/8 eligible packets --> paired B/C records
    |                later packets refresh last-seen, features stay frozen
    |
    +-- idle >= 60 seconds OR fresh bare SYN --> instance 2, reset features
    |
    +-- RST belongs to current instance, then closes it
```

Sixty seconds is a provisional development choice from the timeout audit,
not a proven application-session boundary or accuracy-optimal value. There is
**no hard timeout** and no periodic reclassification. Continuous traffic can
last longer than 60 seconds; even reaching packet 8 can take longer than 60
seconds when each individual gap is below the idle threshold.

Two modes make the effect of TCP rules measurable:

| Mode | Idle boundary | TCP boundary hints | Purpose |
| --- | --- | --- | --- |
| `idle-only` | Gap >= configured seconds | Ignored | Regression against prior audit |
| `idle-tcp` (default) | Same rule | Fresh bare SYN / RST | Candidate-instance development |

Both modes extract and validate the same TCP fields and retain eligible TCP
ACKs/control packets/retransmissions. This is not a payload-only extractor.

### Exact TCP rules, including limitations

- A bare SYN has SYN set, and ACK/FIN/RST clear. A new opening signature
  (endpoint and raw initial sequence number) starts a new candidate instance.
- A repeated opening signature stays in the instance as a possible SYN
  retransmission. The reverse endpoint's SYN while only opening SYNs have been
  seen is retained as a possible simultaneous open.
- If SYN+ACK is observed first, its acknowledgement supplies a candidate peer
  initial sequence number for recognizing a matching late SYN. SYN+ACK alone
  does not split an instance.
- RST is counted in the existing instance, then closes it. Later packets form
  an explicitly marked `after_tcp_rst` candidate even without a new SYN. They
  may be late/control-tail packets, not a verified new connection.
- A FIN alone does not immediately expire state: TCP can close one direction
  while the reverse direction remains active. Even after both FIN directions,
  final ACKs stay together; a subsequent bare SYN starts a new candidate.
- Idle expiry takes priority when idle and a fresh SYN coincide. UDP uses idle
  only. Capture end flushes all remaining instances, including short ones.

This is NOT a full TCP implementation: no sequence receive-window validation,
RST acceptability checks, complete handshake/FIN-ACK tracking or TIME-WAIT.
Same-ISN tuple reuse and delayed segments can remain ambiguous. Preserve the
parent grouping ID; candidate instance IDs do not prove independent sessions.

TCP reference: [RFC 9293, closing a connection](https://datatracker.ietf.org/doc/html/rfc9293#section-3.6).
Field reference: [Wireshark TCP display fields](https://www.wireshark.org/docs/dfref/t/tcp.html).

## Fixed feature contract

| B: six model inputs | C: eight model inputs |
| --- | --- |
| size_min, size_max, size_sum | All six B values, unchanged |
| iat_min, iat_max, iat_sum | reverse_packet_count, direction_change_count |

One row holds BOTH feature dictionaries, avoiding separate extraction/split
paths for B and C. N4 and N8 are separate experiments; do not concatenate them
as independent examples and split them randomly.

- Size means IPv4 `ip.len` in bytes, not payload or Ethernet-frame size.
- Process capture order. Correct backwards time using a running maximum in
  integer nanoseconds **per parent tuple**, then floor timestamps to microseconds
  before subtraction. The PCAP is not rewritten. Log correction counts.
- First eligible packet in EACH instance defines forward; it need not be the
  client or the actual start of the application's session.
- The first packet has no IAT. N4 uses three real gaps; N8 uses seven. Real
  zero gaps remain. Sums avoid division by three/seven in P4.
- First-N snapshots freeze; later packets refresh idle state but don't change
  already frozen features. Short instances are counted, not padded with zeros.
- IDs, addresses, ports, flags, timestamps, class labels and capture names are
  diagnostics/provenance only, NEVER additional model inputs.

## Understand these portions of the code

1. `decode_fields`: reuses eligibility rules and strictly parses the additional
   TCP flags/sequence fields. Unknown Boolean text does not silently become zero.
2. `Prefix.add`: updates min/max/sum and direction counts incrementally; saves
   independent snapshots at 4 and 8. Diagnostic packet traces are offline only.
3. `Instance.fresh_syn` and `observe_tcp`: isolate the documented TCP heuristics
   so you can inspect/replace them without changing feature arithmetic.
4. `Extractor.add`: corrects per-parent time, decides whether to close/start an
   instance, adds the arriving packet, then closes after RST when applicable.
5. `Extractor.close`: exports short-instance metadata or paired features,
   retaining capture and parent IDs for future grouped evaluation.
6. `validate_instance_output.py`: independently recomputes the features from
   saved trace arrays and checks B/C pairing, N4/N8 shared prefixes, IDs and totals.

## Run the controlled tests first

**Terminal: Ubuntu/WSL. Directory: `/home/geleza/p4/etc-training`. Venv optional.**

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover -s tools -p 'test_*.py' -v
```

This runs the original pilot/inventory tests, timeout tests and new instance
tests. These are synthetic controlled inputs with known expected answers,
not fabricated empirical results. Expected ending: `Ran ... tests` and `OK`.
They test exact idle equality, state resets, real zero gaps, backwards time,
short flows, frozen prefixes, SYN repetitions, RST, FIN half-close, decoder
failures, hash mismatch and deliberate output corruption. They do NOT prove
activity labels, complete TCP session identification or live switch equivalence.

## Small real-capture run before all 29

**Same Ubuntu directory and interpreter.**

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python tools/extract_flow_instances.py \
  --capture vpn_hangouts_audio2.pcap \
  --capture vpn_email2b.pcap \
  --capture vpn_skype_audio1.pcap \
  --idle-seconds 60 \
  --boundary-policy idle-tcp
```

These cover the hand-checked Hangouts trace, the email timestamp reversal and
a VoIP capture sensitive to idle splitting. Expected: per-capture instance/N4/N8
counts, end reasons and `INSTANCE EXTRACTION COMPLETE`. This reads PCAPs;
it does not capture live traffic, train a model or change originals.

The printed `Evidence saved to:` value is the exact run directory. Copy that
path into the validator's `--run` argument, for example using a shell variable:

```bash
read -r -p "Paste the Evidence saved to directory: " INSTANCE_RUN
/home/geleza/p4/etc-training/.venv/bin/python tools/validate_instance_output.py --run "$INSTANCE_RUN"
```

At the prompt paste only the full `/home/geleza/.../results/flow_instances/...`
directory, without quotes, then press Enter. The validator reads outputs only.
Expected: `VALIDATION PASS`. If it fails, keep the evidence and stop; don't
train on partial files. An extraction failure writes `failure.json`, which the
validator rejects even if some feature files exist.

## Full included dataset

After tests and the small real run pass, use **the same Ubuntu directory**:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python tools/extract_flow_instances.py \
  --all-included \
  --idle-seconds 60 \
  --boundary-policy idle-tcp
```

This streams all 29 included files across BOTH original folders. The inventory
still excludes the two VoIPbuster files. It verifies hashes, processes one
capture at a time and never loads all packet bodies into memory. Parent state
is bounded by an explicit 50,000-tuple guard (failure, not silent data loss).
Use the same `read`/validator commands with this NEW printed output directory.

Optional controlled comparisons: rerun with `--boundary-policy idle-only` to
separate TCP effects, or `--idle-seconds 120` for timeout sensitivity. Do not
select the policy by repeatedly inspecting final test accuracy.

## Output map and remaining gate

```text
results/flow_instances/<timestamp_run-id>/
    policy.json                 definitions, source hashes, feature allowlists
    summary.json                completed-run counts and diagnostics
    capture_001/                summary.json maps this to its source filename
        source.json             input fingerprint + TShark command
        instances.jsonl         ALL candidate instances, including short ones
        features_n4.jsonl        one paired B/C record per eligible N4 instance
        features_n8.jsonl        one paired B/C record per eligible N8 instance
        field_parse_errors.jsonl
        tshark.stderr.log
```

`training_ready` remains **false** deliberately. Still to settle: flow-level
activity labels/background traffic (including BROWSING), grouping/split
feasibility, and later offline-to-P4 feature/inference parity. Keep all instances
from one parent tuple together in a split; also assess capture/session-level
dependence. Capture-disjoint stratification is constrained by classes such as
P2P having only one capture. Do not promise a universally feasible K-fold split.

Your research comparison remains B versus C, each trained with RF and XGBoost
on the same retained instances and same split for a given N. Neither model has
been trained by this step. No source files have been committed or pushed for you.

## Verification actually performed on 28 September 2026

The complete WSL test suite passed: **134 tests**, comprising the previous 82
and 52 new tests. Separate real-capture runs were completed and checked:

| Capture | Idle-only instances | Idle + TCP instances | N4 records (both modes) | N8 records (both modes) |
| --- | ---: | ---: | ---: | ---: |
| vpn_hangouts_audio2.pcap | 145 | 356 | 145 | 142 |
| vpn_email2b.pcap | 80 | 138 | 80 | 78 |
| vpn_skype_audio1.pcap | 892 | 896 | 220 | 124 |
| Total | 1,117 | 1,390 | 445 | 344 |

TCP mode run:
`/home/geleza/p4/etc-training/results/flow_instances/20260928T200532Z_5d0fa30e2e`

Idle-only comparison run:
`/home/geleza/p4/etc-training/results/flow_instances/20260928T200614Z_55b0f195ed`

Both passed the standalone validator. The idle-only counts and packet rejection
counts exactly matched the corresponding captures in the prior 29-capture audit
`/home/geleza/p4/etc-training/results/idle_timeout/20260928T191514Z_1c15085f83`.
All paired feature rows in these three captures were identical across the two
new modes when matched by parent identity and first frame. The TCP rules changed
short-instance accounting, not eligible first-N features in this sample.

All 145 N4 and 142 N8 Hangouts feature rows also matched the original saved
pilot exactly. These checks verify regression and arithmetic on this sample;
they do not demonstrate correct activity labels or universal TCP-session truth.
The full 29-capture run of the NEW extractor has not been run on your behalf.
