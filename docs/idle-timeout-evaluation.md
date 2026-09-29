# Idle-timeout sensitivity evaluation

## Purpose and status

The unchanged pilot is checkpointed at commit `7ad7bb9`. This separate evaluator
imports its decoder and fingerprint helpers. It does not modify the pilot,
captures, manifest, feature definitions, Git history or GitHub repository.
It produces diagnostics, not a feature dataset and not trained RF/XGBoost models.

Compare no timeout with exploratory idle thresholds of 30, 60 and 120 seconds.
These are sensitivity-test candidates, not values prescribed by Akem or a chosen
deployment policy. This audit alone cannot establish the best timeout.

## Terminal, directory and environment

- Terminal: Ubuntu / WSL (or VS Code's Ubuntu terminal).
- Project directory: `/home/geleza/p4/etc-training`.
- Venv: optional with the absolute Python path below; the interpreter is selected
  explicitly. Do not enter the `.venv` directory.
- Scripts: `/home/geleza/p4/etc-training/tools`.
- Results: `/home/geleza/p4/etc-training/results/idle_timeout` (Git-ignored).
- No `sudo`, new installation or GitHub authentication is needed for the audit.

First run the synthetic regression suite. `cd` selects the project folder;
`unittest` runs all tests, including the original pilot tests. It does not read
the real captures or train a model.

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover -s tools -p 'test_*.py' -v
```

To reproduce the two-capture diagnostic evaluation:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python tools/evaluate_idle_timeouts.py \
  --capture vpn_hangouts_audio2.pcap \
  --capture vpn_email2b.pcap \
  --idle-seconds 30 60 120
```

Each `--capture` selects an inventoried file; `--idle-seconds` selects the
candidate thresholds. The no-timeout reference is always included. One TShark
pass per capture supplies all policies. Originals remain unchanged. Each run
creates a unique results directory, so earlier evidence is not overwritten.

After reviewing the small audit, the same tool can evaluate all 29 included
captures from both data folders, sequentially. The two excluded VoIPBuster files
remain excluded. This is a preprocessing audit, not bulk feature extraction:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python tools/evaluate_idle_timeouts.py \
  --all-included \
  --idle-seconds 30 60 120
```

## Exactly what counts as a boundary

1. Keep the pilot's packet eligibility rules: single Raw-IP IPv4 TCP/UDP layer,
   existing header/length checks, no fragments/truncation/port 53. Retain eligible
   ACKs, retransmissions and control packets. No new application-label heuristic.
2. Group by capture identity and a bidirectional five-tuple. Its two directions
   share one clock. Different captures never share state.
3. Derive monotonic time using the per-tuple running maximum in integer
   nanoseconds. Floor each effective timestamp to microseconds, then subtract.
   Use the SAME parent-tuple clock for every tested policy, across boundaries.
4. Before adding a packet, compare its gap from the previous eligible packet
   with the timeout. **Gap >= timeout** ends the old candidate instance.
   The arriving packet is packet 1 of the new instance, with no inherited IAT.
5. All eligible packets refresh last-seen, including those arriving after N.
   A busy instance is not reset merely because its total age exceeds a threshold.
6. Freeze one opening prefix at N=4 and one at N=8 for the separate experiments.
   No rolling windows, periodic classification or hard timeout is implemented.
7. At capture end, account for unfinished instances. This is right-censoring,
   not proof that a TCP connection or application session ended.

The audit counts potential prefixes and their observation delays; it does not
calculate or export B/C feature vectors. Their agreed definitions remain intact.
When the final extractor is implemented, direction must reset to the first
eligible sender of each instance, not be inherited from an earlier instance.

## Example (synthetic, not a result from the dataset)

Packets of one bidirectional tuple arrive at seconds:

```text
0  1  2  3  .......... 65  66  67  68
            62-second gap

No timeout:   one instance  -> one N4 record; one N8 record
60s timeout:  two instances -> two N4 records; zero N8 records
                              each instance has only four packets
```

N=4 and N=8 are separate experiments, not two predictions in one deployed model.

## Reading the outputs

`summary.json` is written only when ALL selected captures finish successfully.
It records counts separately per capture and provisional capture class:

- **Instances:** candidate segments under that policy, not verified sessions.
- **N4/N8 records:** instances reaching N eligible packets, one record each.
- **N4/N8 short:** instances ending with fewer than N eligible packets.
- **Original prefixes split:** opening no-timeout prefixes containing an idle
  boundary. This is distinct from the total number of new-instance records.
- **Observation delay:** first-to-Nth effective packet time, not CPU inference
  time. Sum, maximum and fixed histogram counts are supplied. Histogram upper
  bounds are inclusive; the final bucket is overflow. Mean is sum / records,
  only when records > 0. This descriptive mean is NOT a model feature.
- **Packets in eligible instances:** all eligible packets belonging to instances
  that reach N, including those after N; not just packets used for the prefix.
- **Short at capture end:** may reflect the capture stopping early; report this
  separately from short instances closed when a later packet reveals an idle gap.

`policy.json` records thresholds, exact rules, TShark version and source hashes.
Each `capture_XXX` directory has `source.json`, an `instances.jsonl` trace and
TShark/field-conversion diagnostics. Instance traces include parent IDs, frame
numbers and decision frames for hand checks. They are local diagnostic metadata,
NOT classifier inputs. Instance order reflects closure, not sorted start times.
Do not add these generated diagnostics or credential files to Git.

If a run fails, `failure.json` marks its directory as incomplete; it has no
successful top-level summary. Do not use partial instance traces as final results.

## Limits and next decisions

This isolates idle-timeout sensitivity. It does NOT yet handle TCP SYN/FIN/RST,
tuple reuse without an idle gap, a switch state table, collisions, eviction or
live BMv2 timing. Timeout-defined instances are not automatically independent
sessions. Preserve parent/capture provenance for leakage-aware grouped splits.

More records do not imply better labels or higher accuracy. Capture-only labels
remain provisional, and browsing ground truth remains unresolved. Review every
included capture before choosing a policy; the two pilot captures alone do not
justify a dataset-wide choice. Do not tune this choice on final test accuracy.

No hard timeout or periodic reclassification is introduced. After reviewing the
audit, settle idle/connection-boundary and labelling rules, implement them in a
separate extractor with matching P4 semantics, and then build the training data.
