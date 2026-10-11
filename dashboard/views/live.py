"""Read-only live synthetic BMv2 monitor; no privileged browser actions."""
from __future__ import annotations

import math
import streamlit as st
import plotly.graph_objects as go
from dashboard.components import (
    hero, section_header, metric_row, notice, empty_panel, pill, plot, MODEL_COLORS,
)

TERMINAL = {"completed", "failed", "interrupted", "cancelled"}
MODE_LABELS = {"forwarding":"Forwarding", "features":"Features only", "rf_b":"RF-B", "rf_c":"RF-C"}


def finite(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def fmt(value, digits=0, unit=""):
    value = finite(value)
    return "Not available" if value is None else f"{value:,.{digits}f}{unit}"


def resource_point(sample, role):
    """Percent is the saved OS-accounted one-core observation, never clamped."""
    row = sample.get("resources", {}).get(role, {})
    cpu, rss = finite(row.get("cpu_percent_one_core")), finite(row.get("rss_mib"))
    return (cpu if cpu is not None and cpu >= 0 else None,
            rss if rss is not None and rss >= 0 else None)


def counter_completion(trial):
    """No decision accuracy or inferred completion from packet rate."""
    gates, metrics = trial.get("metric_validity", {}), trial.get("metrics", {})
    expected = finite(metrics.get("expected_decisions"))
    observed = finite(metrics.get("decisions"))
    if gates.get("classification_counts") is not True or expected is None or expected <= 0 or observed is None:
        return None
    return 100 * observed / expected


def elapsed_seconds(snapshot):
    """Freeze at saved heartbeat even for stale/completed sessions."""
    begin, end = finite(snapshot.get("started_raw_ns")), finite(snapshot.get("heartbeat_raw_ns"))
    return (end - begin) / 1e9 if begin is not None and end is not None and end >= begin else None


def sample_rows(snapshot):
    rows = []
    begin = finite(snapshot.get("started_raw_ns"))
    for entry in snapshot.get("samples", []):
        sample = entry.get("sample", entry)
        raw = finite(sample.get("raw_ns", entry.get("raw_ns")))
        if raw is None or begin is None or raw < begin:
            continue
        traffic = sample.get("traffic", {})
        row = {"seconds": (raw - begin) / 1e9, "phase":sample.get("phase", "unknown"),
               "trial":sample.get("trial", entry.get("trial", 1)),
               "input":finite(traffic.get("input_observed_pps")),
               "output":finite(traffic.get("output_observed_pps"))}
        for role in ("bmv2", "runner"):
            row[role + "_cpu"], row[role + "_rss"] = resource_point(sample, role)
            observed = sample.get("resources", {}).get(role, {})
            actual_raw = finite(observed.get("sample_raw_ns", raw))
            row[role + "_seconds"] = (actual_raw - begin) / 1e9 if actual_raw is not None and actual_raw >= begin else None
        rows.append(row)
    return rows


def observation_figure(rows, kind):
    definitions = {
        "traffic": [("input", "Input capture observations", "#60a5fa"),
                    ("output", "Output capture observations", "#2dd4bf")],
        "cpu": [("bmv2_cpu", "BMv2 (provisional)", "#60a5fa"),
                ("runner_cpu", "Runner (provisional)", "#94a3b8")],
        "memory": [("bmv2_rss", "BMv2 RSS", "#60a5fa"),
                   ("runner_rss", "Runner RSS", "#94a3b8")],
    }
    fig = go.Figure()
    for field, name, color in definitions[kind]:
        points = [row for row in rows if row[field] is not None]
        xfield = "seconds"
        if kind != "traffic":
            xfield = field.split("_",1)[0] + "_seconds"
            # Retained last-known resources during drain are not fresh measurements.
            unique, seen = [], set()
            for row in points:
                timestamp = row.get(xfield)
                if timestamp is not None and timestamp not in seen:
                    unique.append(row)
                    seen.add(timestamp)
            points = unique
        if not points:
            continue
        # Separate trials/phases so no invented interpolation spans unavailable windows.
        groups = {(row["trial"], row["phase"]) for row in points}
        for index, (trial, phase) in enumerate(sorted(groups)):
            subset = [row for row in points if (row["trial"],row["phase"]) == (trial,phase)]
            fig.add_trace(go.Scatter(x=[row[xfield] for row in subset],
                y=[row[field] for row in subset], name=name, legendgroup=field,
                showlegend=index == 0, mode="lines+markers", connectgaps=False,
                line=dict(color=color, width=2), marker=dict(size=4),
                customdata=[[trial,phase] for row in subset],
                hovertemplate="Elapsed RAW: %{x:.2f}s<br>Observed: %{y:.2f}<br>Trial %{customdata[0]} / %{customdata[1]}<extra>%{fullData.name}</extra>"))
    titles = {"traffic":"Userspace observation rate (pps)",
              "cpu":"OS-accounted CPU (% of one core) / DEMO ONLY",
              "memory":"Resident memory (MiB)"}
    fig.update_layout(xaxis_title="Elapsed CLOCK_MONOTONIC_RAW seconds", yaxis_title=titles[kind])
    fig.update_yaxes(rangemode="tozero")
    return fig


def _empty():
    notice("Inactive / No active experiment", "No demonstration is attached. Values are unavailable, not zero. "
           "Launch from your ordinary Ubuntu terminal; this browser never starts privileged work.")
    st.code("cd /home/geleza/p4/etc-training\nmake dashboard-live MODE=rf_c RATE=250 WORKLOAD=classification-heavy", language="bash")
    section_header("Traffic & resources", "Real observations appear only after an authorized demonstration starts.")
    metric_row([
        dict(label="Input / output observed",value="Not available", note="No capture samples"),
        dict(label="Pending matches",value="Not available", note="Pending is not packet loss"),
        dict(label="BMv2 CPU / RSS",value="Not available", note="Resources collected during measurement"),
        dict(label="RF decision count",value="Not available", note="Counter reads occur at phase boundaries"),
    ])
    left,right = st.columns(2)
    with left:
        empty_panel("Traffic observations", "No samples; no simulated switch or fabricated trend lines.")
    with right:
        empty_panel("CPU & resident memory", "Measurement-only OS accounting; percentages remain provisional/demo-only.")


def _health(snapshot, trial):
    verdicts = trial.get("verdicts", {})
    def status(key):
        value = verdicts.get(key, {})
        return value.get("status", "Not finalized") if isinstance(value, dict) else str(value)
    section_header("Experiment health", "Local integrity, independent clock qualification and pacing are different verdicts.")
    columns = st.columns(3)
    for col, label, value in zip(columns,
            ["Measurement integrity", "Independent RAW clock", "Sender pacing conformance"],
            [status("measurement_integrity"),status("independent_raw_qualification"),status("sender_pacing_conformance")]):
        with col:
            with st.container(border=True):
                st.caption(label)
                tone = "success" if value == "PASS" else "error" if value == "FAIL" else "warning"
                st.markdown(pill(value,tone), unsafe_allow_html=True)
    health = snapshot.get("sample", {}).get("clock", {})
    if health:
        st.caption("Live clock observations are provisional: " + "; ".join(f"{key}: {value}" for key,value in health.items()))
    messages = list(trial.get("failures", []))
    for value in verdicts.values():
        if isinstance(value, dict):
            messages.extend(value.get("warnings", []))
    if messages:
        notice("Preserved warnings / failures", " | ".join(dict.fromkeys(map(str,messages))), "warning")
    with st.expander("Capture integrity and finalized socket statistics"):
        integrity = trial.get("capture_integrity", {})
        if integrity:
            st.json(integrity, expanded=False)
        else:
            st.caption("Socket drop counts and full capture integrity are unavailable until capture closes and accounting completes.")
    st.caption("A short demo cannot inherit a calibration certificate. The existing independent reference-span and quality rules still apply.")


def render_evidence(evidence):
    if evidence.status == "corrupt":
        notice("Telemetry integrity failure", "No metrics are displayed from corrupted or mismatched live evidence. "
               + " | ".join(map(str,evidence.messages)), "error")
        return
    snapshot = evidence.snapshot or {}
    if not snapshot:
        _empty()
        for message in evidence.messages:
            notice("Telemetry unavailable", str(message), "warning")
        return
    metadata, sample = snapshot.get("metadata", {}), snapshot.get("sample", {})
    phase, state = snapshot.get("phase", "preparing"), evidence.status
    if state in ("stale", "interrupted", "failed", "corrupt"):
        notice("Experiment " + state, "The last saved observations are retained. Do not treat an unfinished run as a completed measurement.", "warning")
    for message in evidence.messages:
        notice("Telemetry notice", str(message), "warning")
    summary = snapshot.get("final_summary") or {}
    trials = summary.get("trials", []) if isinstance(summary, dict) else []
    trial = trials[-1] if trials else {}
    latest_trial = sample.get("trial", snapshot.get("trial", 1))
    with st.container(border=True):
        left,right = st.columns([2,1])
        with left:
            st.markdown("#### " + MODE_LABELS.get(metadata.get("mode"), str(metadata.get("mode", "Preparing"))))
            st.caption(f"Run: {evidence.run_id} / Session: {snapshot.get('session_id','Not available')}")
            st.caption(f"{metadata.get('workload','Not selected')} / Nominal target: {metadata.get('rate_pps','Not selected')} pps")
        with right:
            tone = "success" if state == "completed" else "error" if state == "failed" else "warning" if state in ("stale","interrupted") else "info"
            st.markdown(pill(state.upper(),tone) + pill(phase.replace("_"," "),"neutral"),unsafe_allow_html=True)
            st.caption(f"Trial {latest_trial} / {snapshot.get('total_trials', metadata.get('total_trials',1))} | Elapsed {fmt(elapsed_seconds(snapshot),1,' s')}")
    seconds = finite(sample.get("phase_elapsed_seconds"))
    duration = metadata.get("warmup_seconds",5) if phase == "warmup" else metadata.get("measurement_seconds",20) if phase == "measurement" else None
    if seconds is not None and finite(duration) and duration > 0:
        st.progress(min(1.,max(0.,seconds/duration)), text=f"{phase.capitalize()} observation: {min(seconds,duration):.1f} / {duration:.0f} RAW seconds")
    elif state == "completed":
        st.progress(1., text="Acquisition finished. Metric verdicts shown separately below.")
    traffic = sample.get("traffic", {})
    bcpu, brss = resource_point(sample,"bmv2")
    rcpu, rrss = resource_point(sample,"runner")
    section_header("Observed traffic", "Cumulative observations are phase-specific. Exact sender counts are finalized separately.")
    metric_row([
        dict(label="Input packets observed", value=fmt(traffic.get("input_unique")), note="Exact-frame userspace capture matches"),
        dict(label="Output packets observed", value=fmt(traffic.get("output_unique")), note="Cumulative output observations"),
        dict(label="Input / output observations", value=f"{fmt(traffic.get('input_observed_pps'),1)} / {fmt(traffic.get('output_observed_pps'),1)}",note="pps over the last capture-sample interval; provisional"),
        dict(label="Pending output matches", value=fmt(traffic.get("pending")), note="Not confirmed path non-delivery"),
    ])
    rows = sample_rows(snapshot)
    if any(row["input"] is not None or row["output"] is not None for row in rows):
        plot(observation_figure(rows,"traffic"),key="live_traffic",height=280)
    else:
        empty_panel("Capture observations", "Waiting for real samples; exact native sender statistics arrive only after sending finishes.")
    st.caption(f"Output duplicate observations: {fmt(traffic.get('output_duplicates'))} / Reordering observations: {fmt(traffic.get('output_reordered'))}. Neither is a final capture-integrity verdict.")
    section_header("CPU & resident memory", "OS-accounted one-core CPU percentages are PROVISIONAL / DEMO ONLY. Resources are collected during measurement, not warm-up or drain. Cards retain last-known samples; charts use actual resource-sample times.")
    metric_row([
        dict(label="BMv2 CPU",value=fmt(bcpu,1,"%"),note="100% = one accounted core; can exceed 100%",tone="blue"),
        dict(label="Runner CPU",value=fmt(rcpu,1,"%"),note="Includes capture, audit and telemetry overhead"),
        dict(label="BMv2 RSS",value=fmt(brss,1," MiB"),note="Observed resident memory, not exact peak",tone="blue"),
        dict(label="Runner RSS",value=fmt(rrss,1," MiB"),note="Measured worker process; dashboard separate"),
    ])
    for column,kind in zip(st.columns(2),("cpu","memory")):
        with column:
            present = any(row["bmv2_" + ("cpu" if kind == "cpu" else "rss")] is not None for row in rows)
            if present:
                plot(observation_figure(rows,kind),key="live_" + kind,height=300)
            else:
                empty_panel("CPU accounting" if kind == "cpu" else "Resident memory", "Not collected until the measurement phase. No replacement values are invented.")
    _health(snapshot,trial)
    if trial:
        section_header("Completed trial", "Final packet/decision counts are separate from provisional observation graphs.")
        metrics, gates = trial.get("metrics",{}), trial.get("metric_validity",{})
        packet_valid = gates.get("packet_accounting") is True
        decision_valid = gates.get("classification_counts") is True
        metric_row([
            dict(label="Final sent / delivered",value=f"{fmt(metrics.get('packets_sent'))} / {fmt(metrics.get('packets_received'))}",note="Supported accounting" if packet_valid else "Raw observations: packet accounting INVALID or unverified"),
            dict(label="RF decisions / expected",value=f"{fmt(metrics.get('decisions'))} / {fmt(metrics.get('expected_decisions'))}",note="Verified completion, not accuracy" if decision_valid else "Not applicable or accounting unverified"),
            dict(label="Decision completion",value=fmt(counter_completion(trial),1,"%"),note="Synthetic traffic has no ground-truth activity label"),
        ])
        with st.expander("Final sender statistics / provisional rates"):
            st.caption("Exact successful sender count and RAW timing are now available. Independent qualification is still required for research rate claims.")
            st.json({key:metrics.get(key) for key in ("packets_sent","raw_window_seconds","offered_pps","delivered_pps","bmv2_cpu_one_core_percent","runner_cpu_one_core_percent")},expanded=False)
        if summary.get("evidence"):
            st.caption("Separate demonstration evidence: " + str(summary["evidence"]))
    elif snapshot.get("sender_statistics"):
        with st.expander("Sender phase completed / statistics available"):
            st.json(snapshot["sender_statistics"],expanded=False)
            st.caption("Capture drain and final counter accounting may still be pending.")
    section_header("Experiment event log", "Append-only lifecycle evidence; newest observations at the bottom.")
    events = evidence.events[-18:]
    if events:
        lines = [f"{row.get('seq','?'):>4}  {row.get('event','event')}  {row.get('phase','')}" for row in events]
        st.code("\n".join(lines),language=None)
    else:
        st.caption("No complete event records available yet.")
    telemetry = snapshot.get("telemetry",{})
    if telemetry.get("dropped_events") or telemetry.get("errors"):
        notice("Telemetry reliability warning", str(telemetry),"warning")
    st.caption("Reopening this page reads the persisted snapshot and retains completed graphs. No experiment is started by viewing it.")


@st.fragment(run_every=1.0)
def monitor_fragment():
    from dashboard.live_evidence import read_live
    evidence=read_live()
    if evidence.snapshot and evidence.snapshot.get("metadata",{}).get("demo_kind")=="pcap":
        notice("A real-PCAP demonstration is current","Select the Real-PCAP Classification tab for its inference results. "
               "Synthetic traffic and PCAP classification observations are not combined.")
        return
    render_evidence(evidence)


def render(store):
    hero("EXPERIMENTS / LIVE MONITOR", "Live BMv2 experiment monitor.",
         "Synthetic runtime monitoring and real-PCAP classification in one terminal-authorized workspace. "
         "Actual switch observations; separate from frozen research results.", "DEMONSTRATION / ACTUAL OBSERVATIONS")
    synthetic,pcap=st.tabs(["Synthetic Performance Demo","Real-PCAP Classification"])
    with synthetic:
        monitor_fragment()
    with pcap:
        from dashboard.views.pcap_live import render as render_pcap
        render_pcap()
    notice("Research limitations remain unchanged", "Streamlit and telemetry add observer activity on this WSL laptop. "
           "Kernel forwarding latency, isolated RF inference latency, maximum capacity and synthetic classification accuracy are not established. "
           "No previous clock certificate is inherited.", "warning")
