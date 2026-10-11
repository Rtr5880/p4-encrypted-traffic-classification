# Dashboard Stage 1 - read-only research interface

Stage 1 provides one Streamlit application for inspecting saved project evidence.
It does **not** start BMv2, transmit packets, run a benchmark, train models, change
clocks, or modify the frozen evidence. The browser is a presentation interface,
not a privileged experiment controller.

This document records the Stage 1 foundation. Stage 2 now changes dashboard
startup to managed start/reuse and adds a bounded terminal-authorized synthetic
demonstration. Follow [dashboard-stage2.md](dashboard-stage2.md) for the current
commands; the original Stage 1 tests and historical evidence remain intact.

## Files created for Stage 1

All source additions remain uncommitted for review:

```text
/home/geleza/p4/etc-training/dashboard/__init__.py
/home/geleza/p4/etc-training/dashboard/app.py
/home/geleza/p4/etc-training/dashboard/components.py
/home/geleza/p4/etc-training/dashboard/evidence.py
/home/geleza/p4/etc-training/dashboard/views/__init__.py
/home/geleza/p4/etc-training/dashboard/views/overview.py
/home/geleza/p4/etc-training/dashboard/views/performance.py
/home/geleza/p4/etc-training/dashboard/views/live.py
/home/geleza/p4/etc-training/config/dashboard-evidence.json
/home/geleza/p4/etc-training/.streamlit/config.toml
/home/geleza/p4/etc-training/requirements-dashboard.txt
/home/geleza/p4/etc-training/Makefile
/home/geleza/p4/etc-training/tools/dashboard_status.py
/home/geleza/p4/etc-training/tools/test_dashboard_evidence.py
/home/geleza/p4/etc-training/tools/test_dashboard_performance.py
/home/geleza/p4/etc-training/tools/test_dashboard_app.py
/home/geleza/p4/etc-training/docs/dashboard-stage1.md
```

Streamlit 1.65.0 and Plotly 6.9.0 were installed into the existing virtual
environment with their required dependencies. The existing NumPy, pandas,
scikit-learn, SciPy, Matplotlib and XGBoost versions were preserved.

## Where to run the commands

Use the ordinary Ubuntu/WSL shell, **without sudo**, in this directory:

```bash
cd /home/geleza/p4/etc-training
```

The Makefile selects the project's existing `.venv/bin/python` directly. You do
not have to activate the virtual environment, although an already activated
environment is harmless. Do not run the dashboard from `p4c`, `p4c-build`, or
`behavioral-model`.

## Check, test, and open the dashboard

```bash
make help
make dashboard-status
make dashboard-test
make dashboard
```

What these do:

| Command | Purpose and scope |
|---|---|
| `make help` | Explains only the targets actually implemented in Stage 1. |
| `make dashboard-status` | Reports pinned saved-evidence availability, file hashes and schema status. It does not install anything or launch an experiment. |
| `make dashboard-test` | Runs the three named dashboard test modules, including a bounded nonprivileged Streamlit startup check. It does not discover or execute the existing project's full test suite. |
| `make dashboard` | Starts the foreground Streamlit server on `127.0.0.1:8501` as the normal user. It reads saved evidence but creates no traffic. |

Open **http://localhost:8501** in your Windows browser. The server deliberately
does not invoke a browser-opening utility, so it also works when WSL has no
`wslview` or `xdg-open`. Keep this Ubuntu terminal open while using the app.
Press **Ctrl+C** in that terminal to stop this dashboard server. There is no
BMv2 child or network experiment to stop in Stage 1.

If another application already occupies port 8501, use an explicit alternative:

```bash
make dashboard DASHBOARD_PORT=8502
```

Then open `http://localhost:8502`. Do not start several copies on the same port.
The foreground server reports startup errors rather than silently replacing
another process. `PYTHON=/absolute/path/to/python` can select a compatible
environment on another Linux machine; the default remains the repository's
existing `.venv`.

## One app, seven navigation entries

The architecture remains one application, with these navigation destinations:

| Page | Stage 1 intention |
|---|---|
| Overview | Research introduction, architecture, selected results and explicit limitations. |
| Classification | Foundation for the classification-analysis page; only implemented saved-evidence content is shown. |
| P4 Correctness | Foundation for parity and implementation-correctness evidence. |
| Native Clock Evaluation | Foundation for native-ingress classification evidence; distinct from later benchmark clock qualification. |
| Performance Evaluation | Historical performance presentation with per-metric validity and provenance. |
| Live Experiment Monitor | Explicitly inactive in Stage 1. No fabricated live counters or traffic. |
| Experiment History | Foundation for browsing evidence categories and saved run identities. |

Some pages intentionally contain honest stage-limited placeholders. A visible
navigation entry is not a claim that a live launcher, automatic telemetry, or
all seven final analysis pages have been implemented.

## Scientific interpretation

Saved results retain their original experiment and evaluation population.
Implementation parity is not classification accuracy. Synthetic performance
traffic is not ground-truth multimedia activity. The earlier qualified RAW
calibration is displayed separately from the completed repeated campaign whose
independent clock qualification remained inconclusive.

In particular:

- Missing or unqualified values are not replaced with zero.
- Qualified calibration rates are not pooled with unqualified repeated rates.
- The repeated campaign can support valid packet accounting, RF completion,
  OS-accounted CPU work and memory observations without qualifying every
  absolute rate or CPU percentage.
- Kernel forwarding-delay percentiles, isolated RF execution latency, ASIC
  performance and maximum switch capacity are not established findings.
- Both RF-B and RF-C deployments already extract directional features; their
  runtime comparison does not isolate direction-extraction cost.

The historical-evidence loader validates pinned file SHA-256 hashes and schemas.
Failures or missing artifacts remain visible instead of triggering new runs or
silently recomputing scientific results. Loading a large evidence tree can take
time; cached presentation data is still tied to its evidence identity.

## Test scope and evidence protection

`make dashboard-test` explicitly names:

```text
tools.test_dashboard_evidence
tools.test_dashboard_performance
tools.test_dashboard_app
```

The application tests exercise the navigation contract, page rendering and a
short local HTTP health check. Any test-created fixtures or server artifacts
belong to temporary test directories. The tests do not use sudo, create veth
pairs, start `simple_switch`, train RF/XGBoost, change synchronization, or write
inside historical result directories. Only the owned temporary Streamlit server
is terminated by the startup test.

## What comes later - not implemented yet

The future live stage may add a thin supervisor and versioned telemetry sidecar
around the existing experiment runners. Approval and implementation are still
required for `dashboard-live`, `benchmark-live`, `demo`, reproduction targets,
live counters and automatic phase/trial charts. These are **not** Makefile
targets in Stage 1.

The future design keeps Streamlit unprivileged, authorizes experiments in the
Ubuntu terminal, uses owned processes and private interfaces, and saves every
new demonstration separately from frozen research evidence. Simultaneous UI
activity must not be advertised as a qualified benchmark without accounting for
its possible observer effect on this WSL laptop.
