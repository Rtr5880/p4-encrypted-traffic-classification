# Shared P4 feature extraction: correctness prototype

This stage implements feature extraction in BMv2, **not Random Forest inference**.
The existing extraction, training and RF-conversion files remain unchanged. No
new accuracy score is produced. Compilation and execution must be confirmed by
the saved test evidence; the existence of this guide is not a test result.

## Verified checkpoint — 30 September 2026

All five actual BMv2 executions passed. Use this completed evidence directory:

```text
/home/geleza/p4/etc-training/results/p4_features/20260930T115414Z_69fc80fe17
```

| Test | Input packets | Result |
| --- | ---: | --- |
| Controlled timestamps and TCP/idle rules | 176 | 165 eligible, 11 rejected; 18 N8 events; zero feature/state mismatches |
| Native switch timestamps, packet-file mode | 24 | 2 N8 events; zero feature/state mismatches |
| Forced single-slot collision | 36 | 18 admitted, 18 collisions rejected from extraction; resident state intact; 2 events |
| Normal forwarding, port 1 to 2 | 24 | Bytes and order unchanged |
| Normal forwarding, port 2 to 1 | 24 | Bytes and order unchanged |

The controlled run includes two short instances, correctly producing no N8
event. Reports are checked for completeness, uniqueness and order. The tests
exercise maximum size/IAT sums, zero/backwards gaps, idle expiry, post-eight
refresh, SYN retransmissions, simultaneous open, SYN+ACK ACK-number wrap,
both-FIN handling, and RST on packet eight. These are synthetic correctness
fixtures, not new training examples or a real-dataset classification evaluation.

The earlier 204 regression tests also passed with the new runner present.
Source and saved output hashes were checked. No original tracked source was
changed and these new P4-stage files have not been committed automatically.

## Files and purpose

- `p4/flow_features.p4`: parser, bidirectional state, first-eight statistics,
  optional diagnostic output, and two-port forwarding.
- `tools/test_p4_features.py`: compiles five test cases, sends synthetic packets
  through the real BMv2 process, and compares results with the existing Python
  `extract_flow_instances.Extractor` oracle.
- `docs/rf-deployment-preparation.md`: preceding model/feature specification and
  Python integer RF conversion. It remains the source of model-selection context.

## Frozen feature and instance rules

Model B uses `size_min`, `size_max`, `size_sum`, `iat_min`, `iat_max`, `iat_sum`.
Model C adds `reverse_packet_count` and `direction_change_count`. This shared
prototype maintains all eight statistics; it does **not** establish B-versus-C
state or performance costs. Direction-disabled B measurements require a later
explicit variant.

Size is the IPv4 `total_len` field, including IP/transport headers, not Ethernet
length or payload length. The first eligible sender of each instance is forward;
this does not necessarily identify the client. Both directions share one tuple.

Eight eligible packets produce one decision event. There are seven real IATs:
no artificial initial zero, but genuine zero gaps are retained. Statistics freeze
after packet eight; every later eligible packet still refreshes last-seen time
and TCP state. Short instances are not padded. There is no hard timeout or
periodic reclassification.

Time uses integer microseconds and a per-parent running maximum. Flooring the
offline integer-nanosecond timestamps to microseconds before supplying test
timestamps preserves the feature-time rule. Idle expiry is `gap >= 60,000,000`
microseconds; the arriving packet belongs to the new instance. Idle takes
priority over a fresh SYN. Parent time survives instance resets, including RST.

TCP boundary handling matches the candidate-instance policy, not a complete TCP
session tracker: repeated opening SYN signatures remain together; a changed bare
SYN can start an instance; possible simultaneous open is retained. An opening
SYN+ACK can infer the peer ISN as ACK minus one modulo 2^32. First observed ISNs
are preserved. FIN does not immediately close an instance; both FIN directions
make a later bare SYN start another. RST is included before closing, so RST on
packet eight still produces a decision. A subsequent packet can start a
continuation without a SYN. No receive-window or RST-acceptability validation is
claimed. UDP uses the idle rule only.

## Numeric storage and bounded state

| Quantity | Domain for an eight-packet prefix | Current P4 storage |
|---|---|---|
| Size min/max | At most 65,535 bytes | 16 bits each |
| Size sum | At most 524,280 bytes | 32 bits |
| IAT min/max | 0 through 59,999,999 microseconds | 32 bits each |
| IAT sum | At most 419,999,993 microseconds | 32 bits |
| Reverse/change counts | 0 through 7 | 4 bits each |
| Prefix count | Saturates at 8 | 4 bits |

The earlier 19-bit size-sum and 3-bit direction-count widths are sufficient
mathematical minima; this implementation deliberately uses wider storage. One
entry is **429 packed bits**, including tuple tags, clock, TCP and feature state.
That is a logical P4 representation, not a measured memory footprint or proof of
hardware feasibility. Timestamp storage is 48 bits; clock wrap is not tested.

CRC32 maps the full canonical bidirectional tuple into 65,536 slots. Full tuple
tags are compared before use. A collision never overwrites the resident entry:
feature processing is skipped and diagnostic mode reports the collision. Normal
two-port forwarding continues. Slots are not dynamically evicted, even after RST
or idle expiry; reset the switch between independent captures. This is a finite
capacity prototype. Any collision changes the admitted evaluation population
and must be reported, not counted as successful classification.

## Parser, test clock and reports

The parser supports Ethernet/IPv4 with IPv4 options, TCP with TCP options, and
UDP. It excludes fragments, port-53 traffic, identical endpoints, unsupported
protocols and detected malformed/truncated headers from feature updates.
Raw-IP captures require a later explicit Ethernet replay adapter. This parser
does not reproduce TShark's deep payload dissection or reject bad checksums; do
not claim identical eligibility for every arbitrary captured packet yet.

Defaults are `TEST_TIMESTAMPS=0` and `DEBUG_REPORT=0`: ordinary packets use
`ingress_global_timestamp` and are forwarded between ports 1 and 2. Controlled
tests enable both flags. A compile-time guard forbids test timestamps without
debug reporting. Controlled input uses EtherType `0x88b5`, ASCII magic `ETCT`, a
32-bit packet ID and a 48-bit integer-microsecond timestamp before IPv4. Use a
documented origin that fits 48 bits; timestamps are never floating-point seconds.

Debug output uses EtherType `0x88b6` and a 71-byte report header. It reports the
packet identity, timestamps, slot/instance, status and all eight feature values.
The test fixtures require a report for every input, including rejected/collision
packets, to detect missing or duplicate output. Debug packets replace ordinary
forwarding output and are not application-transparent traffic.

## Run and inspect: Ubuntu/WSL

Run from **`/home/geleza/p4/etc-training`**, not Windows PowerShell. No `sudo` is
needed; no real interfaces or dataset PCAPs are used. The explicit interpreter
path selects the project venv even when the prompt does not show `(.venv)`.

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training/p4/flow_features.p4 /home/geleza/p4/etc-training/tools/test_p4_features.py /home/geleza/p4/etc-training/docs/p4-feature-extraction.md
/home/geleza/p4/etc-training/.venv/bin/python /home/geleza/p4/etc-training/tools/test_p4_features.py
```

This compiles/runs `controlled`, `native_clock`, `collision`, `forwarding` and
`forwarding_reverse` (the last two use the same normal-forwarding configuration).
Controlled tests compare known timestamps with Python. Native-clock tests use
the ingress timestamps reported by BMv2 for the oracle, not original PCAP times.
Collision tests force a single slot. Forwarding tests check unchanged bytes/order
in both directions: port 1 to 2 and port 2 to 1.
Debugging is disabled for forwarding tests. BMv2 `--use-files` replays **without pacing**; none of
these modes measures live-interface latency, throughput or original-capture IAT.

The runner creates a new directory under
`/home/geleza/p4/etc-training/results/p4_features/` with source/binary hashes,
compiled JSON, compiler logs, synthetic inputs, input/output PCAPs, reports and
`summary.json` on success or `failure.json` on failure. It stops only its own
BMv2 child process. Keep the complete evidence directory; do not treat a partial
run as success. Source files are not committed automatically.

For learning, read `FeatureParser`, then tuple canonicalization in ingress, then
`unpack_state`, `begin_instance`, `update_prefix`, `observe_tcp`, `pack_state` and
the enclosing `@atomic` read/modify/write block. This order follows a packet from
parsing to a state update. The next stage is RF leaf/score/class inference after
feature parity is established; this stage cannot validate those later levels.

## Integration issues fixed during this stage

1. **P4 type-name collisions.** Names such as `Parser` and `Ingress` already
   exist in `v1model.p4`; using them again caused compiler errors. All custom
   pipeline blocks now have the `Feature` prefix. The program then compiled.
2. **Compiler output location.** The `p4c` driver treats `-o` as an output
   directory, not the JSON filename expected by the first runner version. The
   runner now uses a dedicated build directory and loads `flow_features.json`
   from it. No change to model or feature definitions was needed.
3. **Unix socket path length.** The deeper reverse-test evidence path exceeded
   nanomsg's Unix-domain socket path limit and caused a BMv2 startup assertion.
   The runner now binds `ipc://notifications.ipc` relative to each process's
   unique working directory. This keeps tests isolated while keeping the socket
   address short. Earlier failed evidence remains clearly marked by `failure.json`.
