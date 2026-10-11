# In-Switch Encrypted Traffic Classification

EEE4022S research project using P4/BMv2, with offline Random Forest and
XGBoost experiments to compare early traffic-classification features.

## Research comparison

- **B (six features):** minimum, maximum and sum of IPv4 packet lengths;
  minimum, maximum and sum of inter-arrival times.
- **C (eight features):** B plus reverse-packet count and direction-change count.
- Separate first-four and first-eight eligible-packet experiments. IATs use
  N-1 gaps, without an artificial initial zero. Sizes are bytes and IATs are
  integer microseconds.
- One first-N record per flow instance per experiment. Periodic reclassification
  is outside the baseline scope. Both feature configurations use the same
  observations, preprocessing policies and evaluation splits.

## Current milestone: first complete research dashboard

One Streamlit application provides seven substantive pages: Overview,
Classification, P4 Correctness, Native Clock Evaluation, Performance Evaluation,
Live Experiment Monitor and Experiment History. Historical headlines use explicit
hash-pinned evidence, not the newest run. Both terminal-authorized live workflows
remain available: bounded synthetic monitoring and stored real-PCAP RF-B/RF-C
classification. The browser cannot launch privileged traffic or train models.

Run as the normal Ubuntu user in **`/home/geleza/p4/etc-training`**:

```bash
cd /home/geleza/p4/etc-training
make help
make status
make dashboard
```

`make status` reports owned process state and verifies pinned research files.
`make dashboard` starts or reuses the owned server and prints its URL; open
**http://localhost:8501** yourself. Make uses the existing `.venv/bin/python`, so
activation is optional. Do not run the dashboard with sudo.

`make dashboard-stop` stops only the owned dashboard, not an experiment.
Cancel a demo with Ctrl+C in its launching Ubuntu terminal; its runner handles
owned-process/interface cleanup and preserves evidence.

Read [the consolidated operating guide](docs/dashboard-stage4.md) for all 13
targets, health meanings, portability, troubleshooting and the supervisor walkthrough.

### Manual bounded demonstrations

From the same directory, choose one command at a time:

```bash
make demo MODE=rf_c RATE=250 WORKLOAD=classification-heavy
make demo DEMO=pcap MODE=compare EXAMPLE=voip
```

Each announces its scope, prepares new inputs, runs nonprivileged smoke checks
and requests terminal sudo for the bounded BMv2 worker. The original
`make dashboard-live` interface is unchanged. Synthetic rates are targets
(100/250/500/1000 pps); real-PCAP timing is not controlled by `RATE`.
PCAP replay uses stored captured bytes, not newly intercepted Internet traffic.

### Research interpretation

The frozen deployment uses N=8, ten RF trees and maximum depth seven. Both P4
variants maintain direction state; their runtime comparison is not the standalone
cost of direction extraction. RF inference sums fixed-point class probabilities,
not hard majority votes. Lowest class index wins ties.

Six activity classes are capture-derived hints, not verified per-flow ground
truth. Held-out grouping is parent-conversation-disjoint, not fully capture/session
disjoint. Parity is implementation correctness, not classification accuracy.
Native B/C executions may experience different arrivals. The qualified 16-trial
RAW calibration is separate from the 160-trial campaign with inconclusive clock
qualification; repeated absolute rates/CPU percentages and kernel forwarding
latency remain unqualified. No ASIC or maximum-capacity claim is made.

## Historical initial pilot checkpoint

The capture inventory covers 31 files across both local VPN capture folders:
29 included and two VoIPBuster files excluded under the recorded baseline policy.
Raw data are not included in this repository.

The initial pilot extractor and tests were preserved before adding idle-timeout
evaluation. That pilot groups bidirectional five-tuples within each
capture, **without timeout/reset handling**. These groups are candidate
conversations, not validated application sessions or training-ready records.

Real-capture pilot results reported on 28 September 2026:

| Capture | Candidate conversations | N=4 records | N=8 records |
| --- | ---: | ---: | ---: |
| `vpn_hangouts_audio2.pcap` | 145 | 145 | 142 |
| `vpn_email2b.pcap` | 75 | 75 | 73 |

The Hangouts example was hand-checked against selected original packet records.
The email pilot reported one backwards timestamp and one 1,000 ns calculation
adjustment; no emitted first-N prefix required an adjustment. PCAPs are never
rewritten. Capture-only class labels remain provisional.

These early pilot results did not claim a trained classifier or in-switch
deployment. Later extraction, training, deployment and validation superseded that
milestone; the original captures and historical evidence remain unchanged.

## Initial extraction files

- `tools/build_capture_inventory.py`: inventories and fingerprints captures.
- `tools/extract_feature_pilot.py`: reads one inventoried capture and emits
  pilot features, traces and audit summaries.
- `tools/test_*.py`: arithmetic, decoder, inventory and runner regression tests.

## Local environment and focused dashboard tests

Work in Ubuntu/WSL. The existing Python environment is `.venv` in the project
root. TShark is required for capture workflows. Dashboard dependencies are pinned
in `requirements-dashboard.txt`; use the existing environment. Do not commit it.

From the project root:

```bash
cd /home/geleza/p4/etc-training
make test
```

This runs three explicitly named dashboard/live groups: historical pages/evidence/
startup, synthetic monitoring/lifecycle, and real-PCAP adapters/UI. It is not the
entire research suite, dataset replay, training or performance sweep. Tests use
temporary fixtures and may start an owned temporary Streamlit server; no sudo or
privileged traffic is requested.

Historical example for the one-capture pilot, not required for the dashboard:

```bash
.venv/bin/python tools/extract_feature_pilot.py \
  --manifest "$HOME/p4/etc-training/metadata/capture_inventory.json" \
  --capture vpn_hangouts_audio2.pcap \
  --label-policy capture-only \
  --output-root "$HOME/p4/etc-training/pilot_results"
```

This verifies the capture fingerprint, reads one original capture without
modifying it, and creates a new local results directory. It does not train a model.

## Evidence dependencies and portability

Git contains code and registries, not the approximately 11 GiB results tree, raw
PCAPs or frozen model outputs. A fresh clone therefore needs separately supplied
reviewed evidence. Do not force-add or duplicate the whole results directory.

`config/dashboard-evidence.json` pins scientific artifacts;
`config/dashboard-history.json` catalogues historical runs. The external performance
export currently lives at:

```text
/mnt/c/Users/user/OneDrive/Documents/EEE4022/output/performance_evaluation/20261009_complete_campaign_final
```

Portable configuration, set before dashboard startup (only overrides you need):

```bash
export ETC_PROJECT_ROOT=/absolute/path/to/reviewed-project-evidence
export ETC_EXTERNAL_EVIDENCE_ROOT=/absolute/path/to/reviewed-performance-export
export ETC_DASHBOARD_REGISTRY=/absolute/path/to/reviewed-dashboard-evidence.json
export ETC_DASHBOARD_HISTORY_REGISTRY=/absolute/path/to/reviewed-dashboard-history.json
make dashboard
```

Files must still match their pinned hashes. Missing/corrupted artifacts produce
explicit unavailable states, never zeros or automatically recomputed headlines.
See the consolidated guide for restart, evidence-bundle and live-demo limitations.

The Windows scripts were the source for this initial import. After this
checkpoint, the working copies are the files in this WSL repository; avoid
editing one copy and executing the other.

## Provenance and limitations

The initial capture mapping references the associated
[NOMS2024 implementation](https://github.com/gfraysse/NOMS2024_Encrypted_Traffic_Classification/blob/main/iscxvpn2016-vpn-classifier.py).
This is not a claim to reproduce every detail of the later journal paper.
The optional port-based browsing rule is a heuristic, not verified activity
ground truth. BMv2 software results do not establish hardware line-rate performance.
