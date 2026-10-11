# Research Console — first complete version operating guide

This is the current operating guide. The Stage 1–3 documents remain historical
records; their earlier foundation/manual-integration wording is not the current
application status. The existing Synthetic BMv2 Demo Execution and Health Guide
Word document is retained in the Windows project output directory.

## 1. Working directory, Python and startup

Use an ordinary Ubuntu/WSL terminal, **without sudo**, in:

```bash
cd /home/geleza/p4/etc-training
make help
make status
make dashboard
```

Purpose:

- `help` explains only implemented targets and supported selectors.
- `status` checks the owned dashboard/live state and hash/schema-pinned research
  evidence. A missing artifact produces a nonzero evidence-check exit, not a
  substitute run.
- `dashboard` starts or safely reuses the owned Streamlit server; it prints
  **http://localhost:8501**. Open that link in the Windows browser. It does not
  automatically open another browser or start BMv2.

Make uses `/home/geleza/p4/etc-training/.venv/bin/python` directly. An activated
venv is fine but not required. Do not execute these commands from `p4c`,
`p4c-build`, `behavioral-model`, the parent `p4` directory or Windows PowerShell.
The Python override is `PYTHON=/absolute/path/to/compatible/python`.

If port 8501 is occupied by an unrelated service, do not kill it. Use:

```bash
make dashboard DASHBOARD_PORT=8502
```

Open the reported port and use the same `DASHBOARD_PORT` for later status, demos
and shutdown. The manager refuses ownership conflicts; it never takes over an
unrelated server. Do not run several copies unnecessarily.

## 2. The 13 implemented Make targets

All commands run from `/home/geleza/p4/etc-training` as the normal user.

| Target | Exact scope | Privileged operation? |
|---|---|---|
| `make help` | Print supported commands, options and deferred scope | No |
| `make dashboard` | Start/reuse the owned loopback Streamlit server | No; refuses a root dashboard |
| `make dashboard-status` | Owned dashboard and live telemetry state | No |
| `make dashboard-evidence-status` | Research registry hashes and supported schemas | No; read-only |
| `make dashboard-stop` | Stop only the owned dashboard server | No; does not cancel traffic |
| `make dashboard-live` | One synthetic or real-PCAP demo, fresh preparation and smoke before worker | Terminal sudo for bounded worker |
| `make dashboard-test` | Named historical-page/evidence/navigation/startup tests | No |
| `make dashboard-live-test` | Named synthetic monitoring/lifecycle regressions | No |
| `make dashboard-pcap-examples` | Read-only example catalogue | No replay |
| `make dashboard-pcap-test` | Named PCAP UI/adapters/dispatch regressions | No |
| `make test` | The preceding three test groups, explicitly named | No; not the whole research suite |
| `make status` | Process status plus pinned research-evidence verification | No |
| `make demo` | Announces scope and delegates to `dashboard-live` with the same selectors | Terminal sudo for bounded worker |

`make test` does not perform unittest discovery, fit a model, extract the dataset,
rerun the native population or launch a performance sweep. Tests create temporary
fixtures and may start/clean up an owned temporary Streamlit HTTP server. Some
existing focused integration tests use nonprivileged packet-file BMv2 checks;
they do not authorize privileged interface traffic.

### Deferred wrappers — intentionally not Make targets

| Name | Existing tool or future boundary |
|---|---|
| `figures` | The existing continuation analyzer can create a new report/PNG/PDF/SVG directory from an explicitly selected acquisition root; no new wrapper in this version |
| `replay-all` | `tools/replay_real_pcaps.py --all-included` already supports controlled file-port replay; needs original captures and frozen preparation inputs |
| `native-pilot` | Existing pilot has prepare/smoke/run; preparation requires an attested clock receipt, live run requires sudo |
| `native-full` | Existing native evaluation needs preparation and verified pilot evidence; full 398/model replay is not a demonstration |
| `benchmark` | Acquisition and continuation are distinct sealed workflows; no automatic retry, resume or new sweep |
| `reproduce-eval` | A comprehensive saved-analysis reproduction contract is not yet implemented |
| `reproduce-all` | No single safe workflow spanning preprocessing, training, export and privileged experiments exists |

Do not assume the names above work or run an analysis with a different protocol's
runner. The final repeated campaign uses the v6 continuation analyzer, not the
original v5 stop-on-integrity runner. These wrappers can be added only if needed
and separately scoped. Stage 4 does not reopen performance investigation.

## 3. Synthetic demonstration

From the normal Ubuntu terminal in the repository root, manually choose:

```bash
make demo MODE=rf_c RATE=250 WORKLOAD=classification-heavy
```

This prepares one bounded normal-build demonstration, smoke-checks the four
configurations/two workloads without live privilege, then asks for terminal sudo
authorization. You may cancel at that prompt. It runs five seconds of warm-up
separately from twenty seconds of measurement, plus setup/drain overhead.
Select **Live Experiment Monitor → Synthetic performance** in the same dashboard.

Supported independent selectors:

| Selector | Values |
|---|---|
| `MODE` | `forwarding`, `features`, `rf_b`, `rf_c` |
| `RATE` | `100`, `250`, `500`, `1000` target packets/s |
| `WORKLOAD` | `classification-heavy`, `cached-forwarding` |

Classification-heavy uses new eight-packet flow blocks and therefore more RF
inference events per transmitted packet. Cached-forwarding uses longer instances:
the first eight packets produce one decision, and later packets forward using
the classified state. Boundary/tail instances mean expected decisions should
come from saved workload/counter accounting, not blind division of packet counts.
Plain forwarding and feature-only modes have no RF decisions; that is not zero
classification accuracy or a failure.

For example, a separate cached demonstration is:

```bash
make demo MODE=rf_c RATE=1000 WORKLOAD=cached-forwarding
```

Run one at a time. Target pps differs from achieved load. Synthetic packets have
no verified multimedia activity label, so their predicted classes are not an
accuracy experiment. Both RF-B and RF-C already extract directional state; their
runtime difference does not isolate the cost of that extraction.

## 4. Real captured-PCAP classification demonstration

List the source-derived examples, then manually launch a paired comparison:

```bash
cd /home/geleza/p4/etc-training
make dashboard-pcap-examples
make demo DEMO=pcap MODE=compare EXAMPLE=voip
```

Use `MODE=rf_b` or `MODE=rf_c` for one classifier. The explicit example keys are
listed by the catalogue, not guessed or selected because a prediction is correct.
Synthetic `RATE` and `WORKLOAD` do not change PCAP prefix timing.

The runner uses the same selected eight eligible original IPv4 packets for B/C,
wraps them for the existing Ethernet topology and runs the classifiers
sequentially. It does not intercept a new Internet call or decrypt content.
Each native run has its own actual ingress timing. Prediction differences may
reflect timing as well as forest/feature differences; do not claim identical
arrivals or an isolated direction effect from separate native executions.

The PCAP tab preserves:

- Capture identity, capture-derived activity hint, source packet/flow provenance.
- B's six features versus C's eight, ten leaves and six integer class scores.
- Python native-vector reference, predicted class and P4 parity.
- Side-by-side agreement/disagreement and observed timing differences.
- Actual packet/flow completion, resource observations and experiment health.

Short examples may produce only a few resource samples. The UI does not stretch
packet timing, interpolate missing samples or call setup/idle CPU inference cost.

## 5. Shutdown, interruption and troubleshooting

```bash
make dashboard-status
make dashboard-stop
```

Stopping the dashboard does **not** stop a live worker. To cancel an experiment,
press **Ctrl+C in its launching Ubuntu terminal**, wait for the runner's cleanup
and inspect its saved status. Do not use broad process kills or remove private
interfaces manually unless a precise cleanup issue has been diagnosed.

The process manager uses an owned-server record; a foreground shell Ctrl+C is
not the standard shutdown method for this managed dashboard. After code or
evidence-root configuration changes, when no demo is active, stop/restart the
owned server to load the new process environment. The server disables file
watching; merely editing a module does not guarantee the running process reloads.

| Symptom | Safe interpretation/action |
|---|---|
| Evidence unavailable/corrupt | Inspect the displayed exact path/hash/schema; restore the reviewed artifact or configure its root; never substitute another run |
| A running dashboard uses old code/settings | Ensure no active demo; stop/restart only the owned dashboard |
| Port occupied | Use another explicit port or resolve ownership; do not kill unrelated processes |
| Browser remains on completed demo | Completed evidence is deliberately retained; a new terminal-authorized demo changes live state |
| Stale telemetry | Check owned process/boot/heartbeat status; do not interpret stale values as current traffic |
| Counter absent in forwarding/features mode | RF inference is not enabled in those configurations |
| Independent clock inconclusive in a short demo | Completion/local correctness may still be supported; absolute timing-based rates remain provisional |
| A health failure appears | Preserve it; review its exact reason rather than retuning thresholds or selectively rerunning |

Demo launch always creates fresh source-bound preparation after code changes.
Historical preparations/manifests must never be edited to match newer code.

## 6. Scientific health and metric labels

| Label | Defensible meaning |
|---|---|
| File identity VERIFIED | Saved bytes match the pinned SHA-256 and supported schema; not scientific PASS |
| Execution COMPLETED | The runner finished; not proof that every measurement is valid |
| Measurement integrity PASS/FAIL | Existing packet/capture/clock-window/instrumentation checks passed/failed; retain metric-specific gates |
| Independent RAW clock PASS | Independent elapsed-rate reference requirements passed for that execution session |
| Independent RAW clock INCONCLUSIVE | Available observations/uncertainty did not establish qualification; not inherited from another calibration |
| Sender pacing PASS/WARNING | Existing numerical engineering-conformance limits met/exceeded; warnings retained separately from hard integrity failures |
| UNAVAILABLE | Evidence/value/verdict is absent or unsupported; never fabricate a zero or PASS |
| Kernel latency UNQUALIFIED | No qualified forwarding p50/p95/p99 or isolated RF execution latency claim |
| Python/P4 parity PASS | The switch follows the numerical reference on the supported population; not activity accuracy |

A pacing warning does not automatically invalidate reliable counts, but does
not support uniform-load/saturation claims. Capture loss must remain distinct
from observed path non-delivery. CPU work is OS-accounted; it is not an isolated
RF cost or independently qualified physical CPU time. Both RF deployments
maintain directional state.

The qualified 16-trial calibration, the 160-trial linked-session campaign and
supplementary higher-rate trial failures are distinct. The repeated campaign's
independent qualification remained inconclusive; valid count/resource summaries
must not promote its absolute rates or CPU percentages. Maximum tested load is
not established maximum switch capacity. BMv2 results are not ASIC performance.

## 7. Seven-page supervisor walkthrough

1. **Overview:** explain the question, shared extractor and B/C input difference;
   distinguish classification accuracy, implementation correctness and runtime.
2. **Classification:** select capture time; compare paired held-out metrics,
   matrices and per-class support. Switch to native timing and inspect an error.
3. **P4 Correctness:** show 29-capture accounting, three N8 collision exclusions,
   short-instance coverage and one feature/leaf/score/prediction comparison.
4. **Native Clock Evaluation:** inspect original versus observed IATs and a
   changed prediction. Explain why this is not forwarding delay.
5. **Performance Evaluation:** contrast qualified calibration with the repeated
   campaign and its unqualified timing metrics. Retain invalid trials visibly.
6. **Live Experiment Monitor:** manually authorize one synthetic demo or paired
   PCAP example in the terminal. Explain that a stored encrypted capture is replayed.
7. **Experiment History:** filter FAIL/INCONCLUSIVE, inspect original trial1 and
   continuation separately; selecting a record never changes research headlines.

All six class labels remain capture-derived activity hints, not independently
verified per-flow truth. The 398-case held-out population is parent-conversation
disjoint, not fully capture/session disjoint. BROWSING is absent; STREAMING does
not establish separate audio/video truth. Confusion normalization is a displayed
transformation of saved counts, not a new model evaluation.

## 8. Evidence dependencies and portability

The Git checkout does not contain raw captures, ignored frozen model/results
directories, the installed virtual environment or external report export.
Do not copy or commit the 11 GiB results tree to make the dashboard portable.
Supply only an explicitly reviewed artifact bundle if another machine needs it.

The registry file `config/dashboard-evidence.json` names exact research roles,
paths and hashes. Native/controlled detail files must also be named in their
verified parent seals. `config/dashboard-history.json` explicitly catalogues
summaries and recovery reports; it is not a newest-run or best-run selector.
Future demos are visible through live telemetry but are not silently promoted
into pinned research results or the historical catalogue.

Current external performance-export root:

```text
/mnt/c/Users/user/OneDrive/Documents/EEE4022/output/performance_evaluation/20261009_complete_campaign_final
```

Optional portable overrides, in Ubuntu **before server startup**:

```bash
export ETC_PROJECT_ROOT=/absolute/path/to/reviewed-project-evidence
export ETC_EXTERNAL_EVIDENCE_ROOT=/absolute/path/to/reviewed-performance-export
export ETC_DASHBOARD_REGISTRY=/absolute/path/to/reviewed-dashboard-evidence.json
export ETC_DASHBOARD_HISTORY_REGISTRY=/absolute/path/to/reviewed-dashboard-history.json
make dashboard
```

`ETC_PROJECT_ROOT` relocates the **historical loader's** project-relative evidence,
not the operational source repository or live-demo runner inputs. Its directory
must preserve the registry's relative layout. `ETC_EXTERNAL_EVIDENCE_ROOT` must
contain the pinned external dashboard summary. Registry overrides select explicit
reviewed catalogues; they never disable hashing. Use only overrides required for
your machine. A fresh clone without evidence still starts with explicit missing
panels, but cannot display research findings.

The read-only dashboard never trains or writes replacements for missing files.
Raw PCAP paths are needed for privileged demos, not historical detail browsing.
Version pins live in `requirements-dashboard.txt`; dashboard startup does not
install packages or rebuild P4/BMv2. Streamlit secrets are explicitly ignored;
never stage an entire secrets/config directory indiscriminately.

## 9. Acceptance and future Git checkpoint

Stage 4 acceptance requires seven substantive pages, bounded nonprivileged tests,
visual inspection, preserved qualification labels and matching frozen artifact
hashes. Manual privileged checks are separate and must be terminal-authorized;
no long native replay or benchmark repetition is required.

No staging, commit, push, reset, cleaning or discarded work is part of this stage.
After acceptance, a separately approved checkpoint can group performance code,
dashboard/demo infrastructure and Stage 4 integration into reviewable commits.
Use an explicit allowlist and inspect secrets, large files and absolute paths.
The external evidence dependency remains documented rather than force-added.

### Verified Stage 4 acceptance record — 11 October 2026

| Check | Result |
|---|---|
| `make test` | **315 passed**: 131 historical/evidence/page/startup tests, 88 synthetic monitoring tests and 96 PCAP/Make dispatch tests |
| Research registry | 26/26 pinned artifacts verified |
| Historical catalogue | 33/33 summaries verified; failed and recovered runs retained |
| Controlled detail evidence | 145 parent-sealed detail files verified; tests cover all 2,078 decisions per model |
| Frozen inputs | All four P4 artifacts and both integer forest files match the pre-Stage-4 hashes |
| Dashboard lifecycle | Start, reuse, read-only status and owned shutdown verified; server left running on port 8501 |
| Seven-page visual review | Completed in the existing browser, including timing toggles, normalized confusion matrices, actual score totals, native packet inspection, qualification tabs, live views and original-failure history filtering |
| Narrow-window usability | Sidebar collapse control made visible without hover; native inspector names the source capture |
| Git boundary | No staged files, commits, pushes, resets, cleaning or discarded work |

Fresh **nonprivileged** integration checks also passed:

- Synthetic preparation:
  `results/live_demo_preparation/20261010T232034Z_d2c848d7dd`.
  Check evidence: `results/live_demo_checks/20261010T232050Z_a6efb2b49c`.
  All eight configuration/workload combinations forwarded 64/64 unchanged
  file-port frames. RF modes recorded eight classification-heavy or two cached
  decisions as expected.
- Paired PCAP preparation:
  `results/pcap_demo_preparation/20261010T232036Z_07372c52cf`.
  Check evidence: `results/pcap_demo_checks/20261010T232054Z_1a7c9cfd5f`.
  RF-B and RF-C each passed all eight file-port feature/leaf/score/prediction checks.

These file-port checks are not privileged native-interface integration runs,
timing qualification or new research experiments. The exact final manual checks
are the two `make demo` examples in Sections 3 and 4. They create fresh preparation
and request sudo authorization in the launching Ubuntu terminal.

The current Live Monitor retains the user's last completed synthetic demo.
Consequently its PCAP tab correctly says no PCAP demo is currently attached;
it does not fabricate a paired result. The paired rendering is regression-tested,
and the manual paired demo will attach actual observations again.

Local browser proof images are saved separately under the Windows project:
`C:/Users/user/OneDrive/Documents/EEE4022/output/dashboard_stage4/`.
They are UI review artifacts, not replacements for research evidence. The
11 GiB results tree was not copied or added to Git.
