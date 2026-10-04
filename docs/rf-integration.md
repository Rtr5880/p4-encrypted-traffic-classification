# RF-B / RF-C integration in P4 and BMv2

## What this stage does

The selected Random Forests now execute inside BMv2, after the shared P4 feature
extractor reaches the eighth eligible packet of an instance. RF-B uses the six
size/IAT statistics; RF-C adds reverse-packet count and direction-change count.
Both have ten trees and a selected maximum depth of seven.

This stage does **not** retrain, tune, introduce features, or score the held-out
test set. It reads the sealed deployment at:

`/home/geleza/p4/etc-training/results/rf_deployment/20260929T221518Z_a61fc37702`

The committed feature-only checkpoint remains unchanged:

`/home/geleza/p4/etc-training/p4/flow_features.p4`

Stable, byte-identical copies of the tested integrated programs are available at
`/home/geleza/p4/etc-training/p4/rf_b.p4` and
`/home/geleza/p4/etc-training/p4/rf_c.p4`. Their provenance is recorded in
`/home/geleza/p4/etc-training/p4/rf-models.json`. These are generated deployment
snapshots: change the generator and regenerate/retest instead of hand-editing
their model constants.

## Verified result (30 September 2026)

Final evidence directory:

`/home/geleza/p4/etc-training/results/rf_integration/20260930T203044Z_43a729a87f`

The full Python regression suite passed **234 tests**. Both generated classifiers
compiled and ran successfully in BMv2. All sealed output hashes were checked.

| Classifier evidence | RF-B | RF-C |
|---|---:|---:|
| Saved development vectors | 1,683 | 1,683 |
| Saved numeric diagnostic vectors | 4,225 | 4,828 |
| Additional path-constrained vectors | 944 | 1,166 |
| Total vectors tested in BMv2 | 6,852 | 7,677 |
| Leaves reached / reachable | 486 / 486 | 601 / 601 |
| Branch edges reached / reachable | 952 / 952 | 1,182 / 1,182 |
| Leaf, score or predicted-class mismatches | 0 | 0 |

For **each** model, the controlled integrated fixture passed 176 packets with
18 decisions; the native-clock fixture passed 24 packets with two decisions;
and the one-slot collision fixture passed 36 packets with two decisions and
18 colliding packets excluded from classification. The normal-build tests
forwarded 24 unchanged packets in each direction and confirmed exactly two
classifications per run using the decision counters. The four explicit
tie/max-score/soft-vote fixtures also passed in BMv2.

These are correctness results. They do not replace the earlier macro-F1 results
and do not establish real-capture or live-network accuracy.

## The actual packet path

```text
IPv4 TCP/UDP packet
    |
    v
Eligibility + bidirectional flow key + existing session rules
    |
    v
Shared state: size/IAT statistics and direction statistics
    |
    +-- Not eligible packet 8 --> no RF decision
    |
    +-- Exactly eligible packet 8
           |
           v
       Ten P4 decision trees
           |
           v
       Six accumulated integer probability scores
           |
           v
       Highest score, lowest class index on ties
           |
           +-- increment that class's decision counter
           +-- debug build: emit features, leaves, scores and prediction
```

RF-B and RF-C are separate compiled variants of the same extraction design, not
two classifiers running simultaneously. The classification is one-shot per
instance. Prefix features freeze at eight packets; the existing last-seen and
TCP state keep updating so later boundaries still work.

Normal forwarding is still port 1 to port 2, and port 2 to port 1. The class does
not yet change the forwarding policy and is not cached for every later packet.
The per-class counters make inference observable even without debug headers;
otherwise a compiler could remove classifier work that has no observable use.

## Why probability scores, not majority votes

The exported offline model aggregates each tree's class probabilities. Replacing
that with one hard class vote per tree could change its predictions.

Each leaf therefore supplies six integers: its probabilities independently
rounded to a scale of `2^24`. P4 sums these across ten trees into six unsigned
32-bit accumulators. The maximum possible class sum is:

```text
10 * 2^24 = 167,772,160 < 2^28
```

There is no need to divide by ten to select the largest sum. The argmax starts
with class zero and replaces the winner only for a **strictly larger** score.
The fixed class order is CHAT, FT, MAIL, P2P, STREAMING, VOIP.

The integer split thresholds come from the existing exporter, including its
handling of sklearn's float32 input conversion. The P4 generator must not simply
round the original floating thresholds again. Constant predicates at the domain
edges are handled explicitly; no unsigned `-1` threshold is emitted.

The integer conversion previously matched native sklearn predictions on the
saved development and diagnostic vectors. This is tested-vector evidence, not a
proof that Q24 rounding cannot change an arbitrarily close floating-point tie.

## How the trees are represented

The generator emits static P4 conditional tree paths with constant leaf actions.
Leaf actions retain the original node IDs and add the six exported scores. Both
the direct-vector and integrated programs contain the same generated classifier.

No CLI table population is required for this encoding. Replacing a model means
regenerating and compiling a new program. This is a BMv2 implementation choice,
not a reproduction of Akem's precise table encoding, nor proof of suitability
for a physical switch's pipeline or resource limits.

## Three different kinds of evidence

| Check | Input | What it establishes |
|---|---|---|
| Classifier parity | Saved development vectors, numeric diagnostics and path-constrained probes | P4 reaches the expected ten leaves, computes the six sums and predicts the expected integer-reference class |
| Integrated parity | Synthetic TCP/UDP packets with controlled or native switch timestamps | The shared extractor's eight feature values and subsequent RF execution agree with Python |
| Normal forwarding | Ordinary packets, no debug headers | Packet bytes/order are preserved and two flows produce exactly two observable decisions |

The direct-vector program deliberately bypasses feature extraction. Some numeric
probes are not physically possible flow statistics. They test classifier code,
not traffic classification accuracy.

The path probes obey all ancestor predicates, so they genuinely reach the
branches they target. Their coverage report distinguishes total, reachable,
covered and infeasible nodes/branches/leaves. Missing reachable coverage fails
the final runner. Complete branch coverage is still not exhaustive testing of
every possible combination of feature values and class-score ties.

Four additional diagnostic-only forest inputs check ties at classes 0/1 and
2/4, the maximum class-score sum, and a case where six hard tree votes favor
class 0 but probability aggregation correctly selects class 1. This synthetic
forest never replaces either trained research model.

The invalid-vector tests cover bad magic, each of the eight upper bounds and a
subsequent valid vector. They verify echoed IDs/features/order as well as invalid
outputs. Unit tests intentionally corrupt report features, leaves, scores and
predictions to ensure the checker rejects the corresponding failure.

### Packet cases covered by the integrated checks

The existing feature fixtures retain backwards/equal timestamps, idle resets,
interleaving, seven-packet short instances, post-eight traffic, rejected packets,
SYN retransmissions/new SYNs, FIN state, RST on packet eight, IP/TCP options and
maximum supported feature values. A one-slot build deliberately creates hash
collisions and verifies that colliding traffic neither classifies nor overwrites
the resident flow's state.

Native-clock packet-file tests use actual reported BMv2 ingress timestamps in
the Python oracle. Packet-file replay is unpaced: it does not preserve a PCAP's
original inter-arrival times. These checks are not live-interface measurements.
Normal-build counter tests check decision totals; they do not claim that a
different native-clock run has identical per-class counts to the debug run.

## Where to read the code

All paths below are in Ubuntu, rooted at `/home/geleza/p4/etc-training`.

| File | Start here to understand it |
|---|---|
| `/home/geleza/p4/etc-training/tools/generate_rf_p4.py` | `_classifier`: tree branches, leaf scores and argmax; `_integrated`: the packet-eight hook and counters |
| `/home/geleza/p4/etc-training/tools/integrate_rf.py` | `load_deployment`: sealed input checks; `compare_vectors` and `compare_integrated`: parity checks; `run_forwarding`: counters and byte preservation |
| `/home/geleza/p4/etc-training/tools/rf_parity_probes.py` | `branch_probes`: ancestor-constrained test inputs; `coverage`: independently count exercised paths |
| `/home/geleza/p4/etc-training/tools/test_generate_rf_p4.py` | Generator invariants and unchanged checkpoint |
| `/home/geleza/p4/etc-training/tools/test_integrate_rf.py` | Deliberately damaged reports must fail |
| `/home/geleza/p4/etc-training/tools/test_rf_parity_probes.py` | Reachability, numeric boundaries, ties and aggregation examples |

The runner writes generated source into each unique evidence directory, including
`RF_B/integrated.p4`, `RF_C/integrated.p4` and their vector-only variants. Its
summary seals source, outputs, compiler and switch provenance with SHA-256 hashes.
Failed runs receive `failure.json` and must not be reported as a passing run.

The integrated debug output contains the existing 71-byte feature report followed
by a 52-byte RF report (after the Ethernet header). The latter records magic,
version, valid flag, model ID, predicted class, ten 16-bit native leaf IDs and six
32-bit score sums. Non-decision packets carry valid=0, predicted class=255, and
zero leaves/scores. Class zero therefore cannot be confused with "no decision".

## Commands to review and repeat the checks

Run these in your **Ubuntu/WSL terminal**, not PowerShell. The explicit Python
path selects the training virtual environment, so the prompt need not show
`(.venv)` and you do not need to reinstall anything.

First enter the repository and open the new code/guide in VS Code:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training/tools/generate_rf_p4.py \
  /home/geleza/p4/etc-training/tools/integrate_rf.py \
  /home/geleza/p4/etc-training/docs/rf-integration.md
```

Run the Python regression tests. These test the existing pipeline plus the new
generator, probes and verification logic; this command alone does not run BMv2:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python -m unittest discover \
  -s tools -p 'test_*.py'
```

Run actual P4 compilation and isolated BMv2 correctness tests:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/etc-training/.venv/bin/python tools/integrate_rf.py \
  --deployment results/rf_deployment/20260929T221518Z_a61fc37702
```

This creates a new directory below
`/home/geleza/p4/etc-training/results/rf_integration`, prints its exact path, and
does not overwrite previous evidence. It uses packet-file mode without sudo,
starts only its own switch processes on separate ports, queries their counters,
then stops those processes. Existing switches/interfaces are not modified.

No new model fit, hyperparameter search, or test-set accuracy scoring occurs.
Do not report the vector count as a new traffic dataset size or interpret parity
as 100% traffic-classification accuracy.

## Remaining before the final evaluation

Controlled replay of real captures still needs validation: raw-IP wrapping,
timestamp origin/units, eligibility, flow/session boundaries, hash-collision
coverage, features, and predictions. Live throughput/latency, clock wrap and
physical-switch feasibility are not established by this stage.

Accuracy remains subject to the original six capture-derived labels and
parent-conversation-disjoint evaluation limitations. No BROWSING class or
independently verified voice/video ground truth is created by RF integration.

Source changes are left for review; no commit or push is performed automatically.
