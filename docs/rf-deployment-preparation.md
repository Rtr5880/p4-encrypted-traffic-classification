# RF deployment preparation: frozen contract and integer reference

## Verified checkpoint — 30 September 2026, local time

This stage has already run successfully. You do **not** need to refit again
just to move to P4. The final evidence directory is:

```text
/home/geleza/p4/etc-training/results/rf_deployment/20260929T221518Z_a61fc37702
```

The directory name uses UTC, hence the previous calendar date. An earlier
successful development run remains preserved; use the directory above for
the next stage because it records the final source and test hashes.

| Reference | Development vectors | Diagnostic vectors | Integer prediction mismatches | Trees | Maximum depth | Leaves |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RF-B | 1,683 | 4,225 | 0 in both sets | 10 | 7 | 486 |
| RF-C | 1,683 | 4,828 | 0 in both sets | 10 | 7 | 601 |

Native versus exported leaf IDs and floating predictions also matched.
Diagnostic vectors are numeric boundary/random probes, not additional real
flows. No test-set predictions were calculated; all 398 held-out N8 rows were
excluded from refitting and prediction checks. All 31 new tests and all 204
tests in the complete regression suite passed. Saved input, source and output
hashes were rechecked. Existing tracked files were unchanged; this stage's
source, tests and guide are not automatically committed.

These are conversion-correctness results, not a new accuracy or macro-F1
measurement. P4/BMv2 feature extraction, inference and replay remain unverified.

## What this stage does

We keep XGBoost as an **offline comparator** and prepare only Random Forest
B/C for P4. Both use N=8, maximum depth 7 and 10 trees. This is a final refit on
development data, not another hyperparameter search. Saved development CV
macro-F1 was 0.79857 for B and 0.82088 for C; these are not refitted-model test
scores. No new test-set predictions or classification metrics are requested.

```text
Validated paired N8 records + frozen development/test assignments
                   |
         development rows only
                   |
       RF-B refit       RF-C refit
                   |
       Integer thresholds + fixed-point leaf probabilities
                   |
       Python conversion/parity checks
                   |
       Later: P4 features, inference and packet replay
```

B and C retain identical instances and split assignments. Their only input
difference is the two direction features. The six labels remain CHAT, FT,
MAIL, P2P, STREAMING and VOIP, in that order. They are provisional
capture-derived activity hints, not independently verified per-flow labels.
Parent-disjoint evaluation is not capture/session-disjoint evaluation; P2P
has only one source capture. BROWSING is absent. These limitations remain.

## Frozen features and instance rules

| Inputs, in order | Meaning | Planned unsigned width | Maximum allowed value |
| --- | --- | ---: | ---: |
| size_min, size_max | IPv4 `ip.len`, bytes | 16 each | 65,535 each |
| size_sum | Sum of eight IP lengths | 19 | 524,280 |
| iat_min, iat_max | Minimum/maximum of seven gaps, microseconds | 32 each | 59,999,999 each |
| iat_sum | Sum of seven gaps, microseconds | 32 | 419,999,993 |
| reverse_packet_count (C only) | Packets opposite the first eligible sender | 3 | 7 |
| direction_change_count (C only) | Changes between successive packet directions | 3 | 7 |

The stored widths are deliberately not always the smallest possible widths.
The exporter rejects out-of-domain values rather than silently wrapping them.

- Process packets in capture order. Per parent tuple, replace a backwards
  timestamp with the running maximum in integer nanoseconds; floor timestamps
  to microseconds **before** subtracting. Originals are unchanged.
- Each instance's first eligible packet defines forward. It need not be the
  client or the real application-session start. Its IAT is absent, not zero;
  genuine zero gaps among the following seven packets are retained.
- An idle gap **greater than or equal to 60 seconds** starts a new instance.
  There is no hard timeout or periodic reclassification. Every eligible packet
  refreshes last-seen time, even after the opening eight-packet features freeze.
- RST is included in the current instance, then closes it. A fresh bare SYN can
  start a new instance; repeated opening signatures are treated as possible
  retransmissions. FIN does not immediately close state. The exact heuristics
  and limitations remain those in `docs/flow-instance-extraction.md` and its
  implementation, not a claim of complete TCP session reconstruction.
- Instances with fewer than eight eligible packets are excluded, not padded.
  Since an idle-sized gap splits an instance, each retained gap is below
  60,000,000 microseconds, giving the IAT bounds above.
- The existing raw-IP/IPv4 TCP-or-UDP eligibility and port-53 exclusion remain.
  Eligible ACK/control packets and retransmissions still count. Packet headers
  and provenance identify flows but are not additional classifier inputs.

For future BMv2 replay, raw-IP packets need an appropriate link-layer wrapper.
Adding Ethernet must **not** change the size feature: it stays `ip.len`.
Planned state includes a 4-bit packet counter, a previous-direction bit and a
48-bit microsecond switch timestamp. Clock wrap, replay timing, flow-table
collisions and faithful instance-rule implementation are still to be tested
in P4. A width choice alone does not establish feature parity.

## Why conversion is more than copying tree thresholds

Scikit-learn RF prediction averages **leaf class-probability vectors**, then
chooses the highest-probability class. It does not simply give each tree one
hard class vote. The exporter preserves that aggregation structure.

Scikit-learn also converts prediction inputs to float32. Large integer IATs
can therefore round before comparison. `integer_cut` searches for the largest
allowed integer whose float32 value satisfies the original `<= threshold`
branch. For example, a threshold of 16,777,216 admits integer 16,777,217 after
float32 rounding; simply flooring the threshold would send it the wrong way.

Each leaf probability becomes an integer using scale **2^24 = 16,777,216**,
round-to-nearest, ties-to-even, independently per class. The ten tree scores
are summed per class; their maximum is 167,772,160, within unsigned 32 bits.
Division by ten is unnecessary for argmax. Ties select the lowest class index,
matching the fixed class order. Quantized leaf scores need not sum exactly to
the scale. Quantization can change a close decision, so it must be measured.

Checks distinguish exact tree-routing agreement, floating-reference agreement
and fixed-point prediction agreement. Passing observed development and
diagnostic vectors is not proof for every possible input. Neither conversion
parity nor later P4 parity means 100% classification accuracy.

## Open and run it: Ubuntu/WSL, not PowerShell

**Directory for every command below: `/home/geleza/p4/etc-training`.** The
absolute interpreter path selects the training venv, whether or not your prompt
shows `(.venv)`. `cd` selects the project; `code` opens the actual source and guide.

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training/tools/prepare_rf_deployment.py /home/geleza/p4/etc-training/docs/rf-deployment-preparation.md
```

First run the read-only preflight. It verifies prepared inputs and the selected
saved tuning configurations without fitting models or creating a result run.

```bash
/home/geleza/p4/etc-training/.venv/bin/python /home/geleza/p4/etc-training/tools/prepare_rf_deployment.py \
  --prepared /home/geleza/p4/etc-training/results/baseline_preparation/20260929T124705Z_4c1cb93953 \
  --tuning-run /home/geleza/p4/etc-training/results/baseline_tuning/20260929T190215Z_8fb596d3f3 \
  --check-only
```

Remove `--check-only` to refit B/C once and check their exported references:

```bash
/home/geleza/p4/etc-training/.venv/bin/python /home/geleza/p4/etc-training/tools/prepare_rf_deployment.py \
  --prepared /home/geleza/p4/etc-training/results/baseline_preparation/20260929T124705Z_4c1cb93953 \
  --tuning-run /home/geleza/p4/etc-training/results/baseline_tuning/20260929T190215Z_8fb596d3f3
```

Input integrity verification reads prepared partitions, but only development
rows reach model fitting or prediction checks. Existing results are preserved.

To run just the new tests from `/home/geleza/p4/etc-training`:

```bash
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover \
  -s /home/geleza/p4/etc-training/tools \
  -p 'test_prepare_rf_deployment.py' -v
```

These use small synthetic data to exercise thresholds, rounding, input guards
and failure handling. They do not retrain on the real capture-derived data.
The real-data parity results are saved by the preparation run separately.

Each execution creates its own run below `results/rf_deployment/`:

```text
<new-run>/
  feature_contract.json              frozen semantics and numeric domains
  run_config.json                    inputs, configuration and provenance
  development_vectors_B/C.jsonl       development-only reference inputs
  n8_RF_B/ and n8_RF_C/
    model.joblib                     fitted native model; trusted local use only
    forest_integer.json              exported trees and fixed-point scores
    parity.json                      actual comparisons and disagreements
    diagnostic_vectors.jsonl         saved numeric probes, not packet traces
  summary.json                       written only when required checks pass
  failure.json                       written instead if the run fails
```

Read any failure and keep its evidence; do not treat partial artifacts as a
successful conversion. Model files/results remain ignored by Git; source,
tests and this guide can be reviewed and committed separately. Nothing in this
stage automatically commits, pushes or generates P4 code.

## Code-reading guide and completion boundary

- `integer_cut`: reproduces float32 split semantics using bounded integer cuts.
- `export_forest`: exports each tree and its normalized leaf probabilities.
- `predict_export`: traverses the export and aggregates floating/fixed scores.
- `verify_parity`: compares native predictions, routes and exported results.
- `prepare`: verifies provenance, selects development rows, refits and saves.

This stage finishes when both exported RF references pass their recorded checks.
The next stage is shared P4 feature extraction, followed by RF inference and
replay. Compilation, packet-level feature parity, switch predictions and BMv2
runtime measurements are separate deliverables, not established by this script.
