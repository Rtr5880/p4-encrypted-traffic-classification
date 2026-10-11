# First full dashboard: read-only research pages and terminal-authorized demos.
SHELL := /bin/bash
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PYTHON ?= $(REPO_ROOT)/.venv/bin/python
DASHBOARD_PORT ?= 8501
DEMO ?= synthetic
MODE ?= $(if $(filter pcap,$(DEMO)),compare,rf_c)
RATE ?= 250
WORKLOAD ?= classification-heavy
EXAMPLE ?= voip

ifneq ($(DEMO),synthetic)
ifneq ($(DEMO),pcap)
$(error Unsupported DEMO '$(DEMO)'; choose synthetic or pcap)
endif
endif

.PHONY: help dashboard dashboard-status dashboard-evidence-status dashboard-stop dashboard-live dashboard-test dashboard-live-test dashboard-pcap-examples dashboard-pcap-test test status demo

help:
	@printf '%s\n' \
	  'P4 research dashboard - historical evidence and bounded live demo' \
	  'Run from the repository root; virtual-environment activation is unnecessary.' \
	  '' \
	  'make dashboard        Start or safely reuse the normal-user dashboard.' \
	  'make dashboard-status Show owned dashboard and live telemetry state.' \
	  'make dashboard-stop   Stop only our owned dashboard, not an experiment.' \
	  'make dashboard-evidence-status Check pinned saved research evidence.' \
	  'make dashboard-live   Default bounded RF-C synthetic demo; terminal sudo worker.' \
	  'make dashboard-live DEMO=pcap  Real capture prefixes through native BMv2.' \
	  'make dashboard-pcap-examples List metadata-derived examples; no replay.' \
  'make dashboard-test   Historical pages, evidence and nonprivileged startup tests.' \
	  'make dashboard-live-test Run focused Stage 2 nonprivileged tests.' \
	  'make dashboard-pcap-test Run focused Stage 3 nonprivileged tests.' \
  'make test             All three named dashboard/live test groups; no research reruns.' \
  'make status           Owned process state plus pinned research evidence verification.' \
  'make demo             Alias for dashboard-live; announces terminal sudo authorization.' \
	  '' \
	  'Overrides: PYTHON=/absolute/path/to/python DASHBOARD_PORT=8502' \
	  'Synthetic: DEMO=synthetic MODE=rf_c RATE=250 WORKLOAD=classification-heavy' \
	  'PCAP: DEMO=pcap MODE=compare (or rf_b/rf_c) EXAMPLE=voip' \
  'Run make as the ordinary user. Browser never authorizes privileged traffic.' \
  'Deferred (not targets): figures, replay-all, native-pilot, native-full, benchmark,' \
  'reproduce-eval and reproduce-all. See docs/dashboard-stage4.md for existing tools/scope.'

dashboard:
	@test "$$(id -u)" -ne 0 || { printf '%s\n' 'Refusing root dashboard: run make dashboard without sudo.' >&2; exit 1; }
	@test -x "$(PYTHON)" || { printf '%s\n' 'Python is missing. Use the existing .venv or set PYTHON explicitly.' >&2; exit 1; }
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B "$(REPO_ROOT)/tools/dashboard_process.py" start --port "$(DASHBOARD_PORT)"

dashboard-status:
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B "$(REPO_ROOT)/tools/dashboard_process.py" status --port "$(DASHBOARD_PORT)"

dashboard-evidence-status:
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B "$(REPO_ROOT)/tools/dashboard_status.py"

dashboard-stop:
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B "$(REPO_ROOT)/tools/dashboard_process.py" stop --port "$(DASHBOARD_PORT)"

dashboard-live:
ifeq ($(DEMO),pcap)
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B "$(REPO_ROOT)/tools/run_pcap_demo.py" launch \
	  --mode "$(MODE)" --example "$(EXAMPLE)" --dashboard-port "$(DASHBOARD_PORT)"
else
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B "$(REPO_ROOT)/tools/run_live_demo.py" launch \
	  --mode "$(MODE)" --rate "$(RATE)" --workload "$(WORKLOAD)" --dashboard-port "$(DASHBOARD_PORT)"
endif

dashboard-pcap-examples:
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B "$(REPO_ROOT)/tools/pcap_demo_examples.py" list

dashboard-test:
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B -m unittest -v \
	  tools.test_dashboard_evidence tools.test_dashboard_performance tools.test_dashboard_app \
	  tools.test_dashboard_details tools.test_dashboard_classification tools.test_dashboard_correctness \
	  tools.test_dashboard_native_clock tools.test_dashboard_history

dashboard-live-test:
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B -m unittest -v \
	  tools.test_dashboard_process tools.test_live_telemetry tools.test_live_demo_transport \
	  tools.test_run_live_demo tools.test_live_dashboard

dashboard-pcap-test:
	@cd "$(REPO_ROOT)" && "$(PYTHON)" -B -m unittest -v \
	  tools.test_pcap_demo_examples tools.test_pcap_demo_replay tools.test_run_pcap_demo tools.test_pcap_live_dashboard \
	  tools.test_dashboard_makefile

# Explicitly named groups: no dataset extraction, fitting or privileged traffic.
test: dashboard-test dashboard-live-test dashboard-pcap-test

status: dashboard-status dashboard-evidence-status

demo:
	@printf '%s\n' 'BOUNDED LIVE DEMO: preparation + nonprivileged smoke, then terminal sudo authorization.' \
	  'This transmits packets through a private BMv2 topology. Browser remains read-only.' \
	  'Run make without sudo; cancel at the terminal authorization prompt if not ready.'
	@$(MAKE) --no-print-directory dashboard-live DEMO="$(DEMO)" MODE="$(MODE)" \
	  RATE="$(RATE)" WORKLOAD="$(WORKLOAD)" EXAMPLE="$(EXAMPLE)" DASHBOARD_PORT="$(DASHBOARD_PORT)" PYTHON="$(PYTHON)"
