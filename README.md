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

## Current baseline checkpoint

The capture inventory covers 31 files across both local VPN capture folders:
29 included and two VoIPBuster files excluded under the recorded baseline policy.
Raw data are not included in this repository.

The pilot extractor and tests are preserved here before adding idle-timeout
evaluation. The pilot currently groups bidirectional five-tuples within each
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

No trained classifier, final data split or in-switch ML deployment is claimed.

## Files

- `tools/build_capture_inventory.py`: inventories and fingerprints captures.
- `tools/extract_feature_pilot.py`: reads one inventoried capture and emits
  pilot features, traces and audit summaries.
- `tools/test_*.py`: arithmetic, decoder, inventory and runner regression tests.

## Local environment and tests

Work in Ubuntu/WSL. The existing Python environment is `.venv` in the project
root. TShark is required to read captures; the pilot and tests otherwise use
Python's standard library. Do not commit the virtual environment.

From the project root:

```bash
source .venv/bin/activate
python -m unittest discover -s tools -p 'test_*.py' -v
```

This selects the existing environment and runs the automated tests; it does
not read real captures or train a model. Runner/inventory tests create and
clean up their own synthetic temporary fixtures.

To rerun the existing one-capture pilot from the Linux copy:

```bash
python tools/extract_feature_pilot.py \
  --manifest "$HOME/p4/etc-training/metadata/capture_inventory.json" \
  --capture vpn_hangouts_audio2.pcap \
  --label-policy capture-only \
  --output-root "$HOME/p4/etc-training/pilot_results"
```

This verifies the capture fingerprint, reads one original capture without
modifying it, and creates a new local results directory. It does not train a model.

## Next work

Evaluate candidate idle-timeout policies, then freeze instance-boundary and
labelling rules before bulk extraction. Keep the current pilot checkpoint
unchanged while the evaluation is reviewed. Related instances must remain
appropriately grouped for leakage-aware model evaluation.

The Windows scripts were the source for this initial import. After this
checkpoint, the working copies are the files in this WSL repository; avoid
editing one copy and executing the other.

## Provenance and limitations

The initial capture mapping references the associated
[NOMS2024 implementation](https://github.com/gfraysse/NOMS2024_Encrypted_Traffic_Classification/blob/main/iscxvpn2016-vpn-classifier.py).
This is not a claim to reproduce every detail of the later journal paper.
The optional port-based browsing rule is a heuristic, not verified activity
ground truth. BMv2 software results do not establish hardware line-rate performance.
