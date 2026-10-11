"""Historical performance evidence; never launches or requalifies experiments.

Pure presentation helpers are dependency-free. Streamlit/Plotly imports are
delayed until rendering so scientific gating can be tested independently.
"""
from __future__ import annotations

import math
from typing import Any

MODES = ("forwarding", "features", "rf_b", "rf_c")
MODE_NAMES = {"forwarding": "Forwarding", "features": "Features only", "rf_b": "RF-B", "rf_c": "RF-C"}
WORKLOADS = ("classification-heavy", "cached-forwarding")
RESOURCE_LABELS = {
    "bmv2_cpu_seconds": ("BMv2 CPU accounting", "OS-accounted CPU seconds"),
    "runner_cpu_seconds": ("Runner CPU accounting", "OS-accounted CPU seconds"),
    "bmv2_rss_peak_mib": ("BMv2 sampled RSS", "Sampled-window RSS maximum (MiB)"),
    "runner_rss_peak_mib": ("Runner sampled RSS", "Sampled-window RSS maximum (MiB)"),
    "bmv2_hwm_mib": ("BMv2 lifetime HWM", "Process-lifetime high-water RSS (MiB)"),
    "runner_hwm_mib": ("Runner lifetime HWM", "Process-lifetime high-water RSS (MiB)"),
}


def number(value: Any, digits: int = 2, suffix: str = "") -> str:
    """Unavailable is not zero; reject nonfinite values from metric cards."""
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        return "Unavailable"
    return f"{value:,.{digits}f}{suffix}"


def selected_cells(data: dict, workload: str, modes: list[str], rates: list[int]) -> list[dict]:
    return [c for c in data.get("cells", []) if c.get("workload") == workload
            and c.get("mode") in modes and c.get("nominal_target_pps") in rates]


def repeated_rows(cells: list[dict]) -> list[dict]:
    """Flatten only saved, supported aggregate quantities; no rate promotion."""
    rows = []
    for c in cells:
        q, delivery, rf = c.get("quality", {}), c.get("supported_delivery", {}), c.get("classification_counts", {})
        row = {"Configuration": MODE_NAMES.get(c.get("mode"), c.get("mode")),
               "Nominal target (pps)": c.get("nominal_target_pps"),
               "Acquired / planned": f"{c.get('acquired_repetitions', 0)} / {c.get('planned_repetitions', 0)}",
               "Local integrity PASS": q.get("local_pass"), "Local integrity FAIL": q.get("local_fail"),
               "Pacing WARNING": q.get("pacing_warning"), "Clock-qualified n": q.get("clock_qualified"),
               "Packet-accounting n": delivery.get("eligible_trials"),
               "Supported sent": delivery.get("sent"), "Supported delivered": delivery.get("output_unique"),
               "Observed path non-delivery": delivery.get("path_non_delivery"),
               "Supported delivery (%)": 100 * delivery["delivery_fraction"] if delivery.get("delivery_fraction") is not None else None,
               "RF-count n": rf.get("eligible_trials"), "Expected decisions": rf.get("expected"),
               "Verified decisions": rf.get("observed")}
        rows.append(row)
    return rows


def resource_rows(cells: list[dict], key: str) -> list[dict]:
    rows = []
    for c in cells:
        s = c.get("resource_statistics", {}).get(key, {})
        rows.append({"Configuration": MODE_NAMES.get(c.get("mode"), c.get("mode")),
                     "Nominal target (pps)": c.get("nominal_target_pps"),
                     "Eligible n": s.get("n", 0), "Median": s.get("median"),
                     "Minimum": s.get("minimum"), "Maximum": s.get("maximum"),
                     "Mean": s.get("mean"), "Sample SD": s.get("sample_sd"), "IQR": s.get("iqr")})
    return rows


def completion_points(cells: list[dict], kind: str) -> list[dict]:
    """Count-based percentages, gated on eligible n and positive denominator.

    These summarize saved supported counts, never time-normalized throughput
    or semantic accuracy. Missing and inapplicable cells are omitted.
    """
    if kind not in ("delivery", "rf_completion"):
        raise ValueError("Unknown count-completion metric")
    points=[]
    for c in cells:
        if kind=="rf_completion" and not c.get("mode","").startswith("rf_"):
            continue
        block=c.get("supported_delivery" if kind=="delivery" else "classification_counts",{})
        denominator=block.get("sent" if kind=="delivery" else "expected")
        numerator=block.get("output_unique" if kind=="delivery" else "observed")
        eligible=block.get("eligible_trials",0)
        if (not isinstance(eligible,int) or isinstance(eligible,bool) or eligible<=0
                or not isinstance(denominator,int) or isinstance(denominator,bool) or denominator<=0
                or not isinstance(numerator,int) or isinstance(numerator,bool)
                or not 0<=numerator<=denominator):
            continue
        points.append({"mode":c.get("mode"),"rate":c.get("nominal_target_pps"),
                       "percentage":100*numerator/denominator,"numerator":numerator,
                       "denominator":denominator,"eligible_trials":eligible})
    return points


def higher_attempt_rows(data: dict) -> list[dict]:
    """Parent-pinned identities/acquisition only; no invented child verdicts."""
    return [{"Original ordinal":a.get("ordinal"),"Configuration":MODE_NAMES.get(a.get("mode"),a.get("mode")),
             "Workload":a.get("workload"),"Target (pps)":a.get("rate_pps"),
             "Acquisition status":a.get("status"),"Trial identity":a.get("trial_directory"),
             "Individual metric/verdict scope":"Not individually loaded here"}
            for a in data.get("attempts",[])]


def failed_trial_rows(data: dict) -> list[dict]:
    rows = []
    for t in data.get("trials", []):
        identity, verdict, m = t.get("identity", {}), t.get("verdicts", {}), t.get("measurement", {})
        if verdict.get("local_integrity") == "PASS" and verdict.get("pacing") == "PASS":
            continue
        rows.append({"Trial": identity.get("trial_directory"), "Session": identity.get("execution_session_id"),
                     "Configuration": MODE_NAMES.get(identity.get("mode"), identity.get("mode")),
                     "Workload": identity.get("workload"), "Nominal target (pps)": identity.get("rate_pps"),
                     "Local integrity": verdict.get("local_integrity"), "Pacing": verdict.get("pacing"),
                     "Observed missing outputs": m.get("missing_output"),
                     "Path accounting valid": m.get("path_non_delivery_valid"),
                     "RAW sample gap (ms)": m.get("raw_max_sample_gap_ms"),
                     "Original failure reasons": "; ".join(t.get("saved_local_failure_reasons", []))})
    return rows


def calibration_rows(loaded_trials: list) -> list[dict]:
    """Each rate/CPU value needs its own saved eligibility gate and certificate."""
    rows = []
    for evidence in loaded_trials:
        if getattr(evidence, "status", None) != "verified" or not isinstance(getattr(evidence, "data", None), dict):
            continue
        t = evidence.data
        metrics, gates, verdicts = t.get("metrics", {}), t.get("metric_validity", {}), t.get("verdicts", {})
        clock = verdicts.get("independent_raw_qualification", {})
        local = verdicts.get("measurement_integrity", {}).get("status") == "PASS"
        certified = (clock.get("status") == "PASS" and clock.get("absolute_rate_claims_qualified") is True
                     and t.get("raw_rate_qualified") is True and t.get("valid") is True and local)
        def qualified(name: str, gate: str):
            return metrics.get(name) if certified and gates.get(gate) is True else None
        rows.append({"Configuration": MODE_NAMES.get(t.get("mode"), t.get("mode")),
                     "mode": t.get("mode"), "Workload": t.get("workload"), "Target (pps)": t.get("rate_pps"),
                     "Offered (pps)": qualified("offered_pps", "offered_load"),
                     "Delivered (pps)": qualified("delivered_pps", "delivered_throughput"),
                     "Ethernet throughput (Mb/s)": qualified("delivered_ethernet_mbps", "delivered_throughput"),
                     "BMv2 CPU (% of one core)": qualified("bmv2_cpu_one_core_percent", "cpu"),
                     "Runner CPU (% of one core)": qualified("runner_cpu_one_core_percent", "cpu"),
                     "Classification decisions/s": qualified("decision_rate_pps", "classification_rate"),
                     "Sent": metrics.get("packets_sent") if gates.get("packet_accounting") is True else None,
                     "Delivered": metrics.get("packets_received") if gates.get("packet_accounting") is True else None,
                     "Verified decisions": metrics.get("decisions") if gates.get("classification_counts") is True else None,
                     "BMv2 sampled RSS (MiB)": metrics.get("bmv2_rss_peak_mib") if gates.get("memory") is True else None,
                     "Local integrity": verdicts.get("measurement_integrity", {}).get("status", "Unavailable"),
                     "Independent clock": clock.get("status", "Unavailable"),
                     "Pacing": verdicts.get("sender_pacing_conformance", {}).get("status", "Unavailable"),
                     "Evidence": str(getattr(evidence, "path", ""))})
    return rows


def _verified(store, role: str):
    from dashboard.components import notice
    evidence = store.load(role)
    if evidence.status != "verified":
        notice("Evidence unavailable", f"{role}: {evidence.message}. No values have been substituted.",
               kind="error" if evidence.status == "corrupt" else "warning")
        return None
    return evidence


def _resource_figure(cells: list[dict], metric: str):
    import plotly.graph_objects as go
    from dashboard.components import MODEL_COLORS
    fig = go.Figure()
    for mode in MODES:
        points = sorted((c for c in cells if c.get("mode") == mode), key=lambda c: c["nominal_target_pps"])
        points = [c for c in points if c.get("resource_statistics", {}).get(metric, {}).get("n", 0) > 0]
        if not points:
            continue
        stats = [c["resource_statistics"][metric] for c in points]
        fig.add_trace(go.Scatter(x=[c["nominal_target_pps"] for c in points], y=[s["median"] for s in stats],
            name=MODE_NAMES[mode], mode="lines+markers", line=dict(color=MODEL_COLORS[mode], width=2),
            marker=dict(size=8), error_y=dict(type="data", symmetric=False,
                array=[s["maximum"]-s["median"] for s in stats],
                arrayminus=[s["median"]-s["minimum"] for s in stats]),
            customdata=[[s["n"],s["minimum"],s["maximum"],s["sample_sd"],s["iqr"]] for s in stats],
            hovertemplate="Nominal target: %{x} pps<br>Median: %{y:.3f}<br>Eligible n=%{customdata[0]}<br>Range: %{customdata[1]:.3f}–%{customdata[2]:.3f}<br>SD: %{customdata[3]:.3f}<br>IQR: %{customdata[4]:.3f}<extra>%{fullData.name}</extra>"))
    fig.update_layout(xaxis_title="Nominal target rate (pps) — achieved rate unqualified",
                      yaxis_title=RESOURCE_LABELS[metric][1], legend_title_text="Configuration")
    return fig


def _quality_figure(cells: list[dict]):
    import plotly.graph_objects as go
    rates = sorted({c["nominal_target_pps"] for c in cells})
    modes = [m for m in MODES if any(c.get("mode") == m for c in cells)]
    index = {(c["mode"],c["nominal_target_pps"]):c for c in cells}
    z, text, details = [], [], []
    for mode in modes:
        zr, tr, dr = [], [], []
        for rate in rates:
            c=index.get((mode,rate),{});q=c.get("quality",{});n=c.get("acquired_repetitions",0)
            p=q.get("local_pass",0)
            zr.append(p/n if n else None);tr.append(f"{p}/{n}")
            dr.append([q.get("local_fail",0),q.get("pacing_warning",0),q.get("clock_qualified",0)])
        z.append(zr);text.append(tr);details.append(dr)
    fig=go.Figure(go.Heatmap(x=[str(r) for r in rates], y=[MODE_NAMES[m] for m in modes], z=z,
        text=text, texttemplate="%{text}", customdata=details, zmin=0,zmax=1, showscale=False,
        colorscale=[[0,"#873c58"],[.6,"#8c6d41"],[1,"#118d84"]],
        hovertemplate="%{y} / %{x} nominal pps<br>Local integrity PASS: %{text}<br>FAIL: %{customdata[0]}<br>Pacing warnings: %{customdata[1]}<br>Clock-qualified: %{customdata[2]}<extra></extra>"))
    fig.update_layout(xaxis_title="Nominal target (pps)",yaxis_title="Local integrity only; not clock qualification")
    return fig


def _completion_figure(cells: list[dict],kind: str):
    import plotly.graph_objects as go
    from dashboard.components import MODEL_COLORS
    points=completion_points(cells,kind)
    fig=go.Figure()
    for mode in MODES:
        values=sorted((p for p in points if p["mode"]==mode),key=lambda p:p["rate"])
        if not values:
            continue
        fig.add_trace(go.Scatter(x=[p["rate"] for p in values],y=[p["percentage"] for p in values],
            name=MODE_NAMES[mode],mode="lines+markers",line=dict(color=MODEL_COLORS[mode]),marker=dict(size=9),
            customdata=[[p["numerator"],p["denominator"],p["eligible_trials"]] for p in values],
            hovertemplate="Nominal target: %{x} pps<br>Supported completion: %{y:.5f}%<br>Counts: %{customdata[0]:,} / %{customdata[1]:,}<br>Eligible trials: %{customdata[2]}<extra>%{fullData.name}</extra>"))
    title="Supported packet delivery (%)" if kind=="delivery" else "Verified RF decision completion (%) — not accuracy"
    fig.update_layout(xaxis_title="Nominal target (pps) — no qualified time rate",yaxis_title=title)
    fig.update_yaxes(range=[0,105])
    return fig


def _repeated(store):
    import streamlit as st
    from dashboard.components import metric_card, notice, plot, provenance, section_header
    evidence = _verified(store, "performance_campaign")
    if evidence is None:
        return
    data = evidence.data
    notice("160 acquisitions. Partial-metric characterization.",
        "The repeated campaign has no qualified absolute throughput or CPU percentages. "
        "Packet accounting, supported RF decision counts, OS-accounted CPU seconds and memory remain useful. "
        "The earlier 16-trial calibration is separate evidence, not a replacement clock certificate.", kind="warning")
    h, delivery, rf = data.get("headline_counts", {}), data.get("supported_packet_delivery", {}), data.get("supported_rf_completion", {})
    for col, label, value, note, tone in zip(st.columns(4),
            ["Trials acquired", "Local integrity", "Supported packet delivery", "RF counter completion"],
            [f"{h.get('acquired', '—')} / {h.get('planned', '—')}",
             f"{h.get('local_integrity_pass', '—')} PASS", number(100*delivery["delivery_fraction"],4,"%") if delivery.get("delivery_fraction") is not None else "Unavailable",
             number(100*rf["fraction"],1,"%") if rf.get("fraction") is not None else "Unavailable"],
            ["All original attempts retained", f"{h.get('local_integrity_fail', '—')} FAIL · clock-qualified n=0",
             f"{delivery.get('eligible_trials', '—')} capture-valid trials · not proven BMv2 loss",
             f"{rf.get('eligible_trials', '—')} RF-count eligible trials · not accuracy"],
            ["neutral","warning","success","success"]):
        with col:
            metric_card(label,value,note,tone=tone)
    st.caption("Four configurations × two workloads × four nominal rates × five repetitions. "
               "Normal builds; 5 s warm-up and 20 s sending window. Both RF deployments already extract direction.")
    controls = st.columns([1.15,1.7,1.1])
    with controls[0]:
        workload = st.selectbox("Workload", list(WORKLOADS), key="perf_workload")
    with controls[1]:
        modes = st.multiselect("Configurations", list(MODES), default=list(MODES), format_func=lambda m: MODE_NAMES[m], key="perf_modes")
    with controls[2]:
        available = sorted({c["nominal_target_pps"] for c in data.get("cells",[])})
        rates = st.multiselect("Nominal rates (pps)", available, default=available, key="perf_rates")
    cells = selected_cells(data,workload,modes,rates)
    if not cells:
        notice("No selection", "Select at least one configuration and nominal rate.",kind="info")
        provenance(evidence)
        return
    section_header("Resources across repeated trials", "Saved medians; whiskers retain the full min–max range. Hover for n, SD and IQR.")
    left,right=st.columns(2)
    with left:
        cpu_key=st.selectbox("CPU-accounting process", ["bmv2_cpu_seconds","runner_cpu_seconds"],
                            format_func=lambda k: RESOURCE_LABELS[k][0],key="perf_cpu_metric")
        plot(_resource_figure(cells,cpu_key), key="perf_cpu")
    with right:
        memory_key=st.selectbox("Memory observation", ["bmv2_rss_peak_mib","runner_rss_peak_mib","bmv2_hwm_mib","runner_hwm_mib"],
                               format_func=lambda k: RESOURCE_LABELS[k][0],key="perf_memory_metric")
        plot(_resource_figure(cells,memory_key),key="perf_memory")
    st.caption("CPU seconds are Linux-accounted work, not independently frequency-calibrated physical execution time. "
               "RSS maxima are sampled, not exact peaks. HWM includes process lifetime; the long-lived runner includes earlier trials. "
               "These curves do not establish qualified achieved-load-matched overhead or a faster classifier.")
    with st.expander("Resource statistics and variability"):
        st.caption("All entries are saved aggregate statistics. Null means unavailable, not zero.")
        st.dataframe(resource_rows(cells,cpu_key),hide_index=True,width="stretch")
        st.dataframe(resource_rows(cells,memory_key),hide_index=True,width="stretch")
    section_header("Accounting and quality", "Metric eligibility is distinct from a trial's overall integrity verdict.")
    left,right=st.columns([1,1.2])
    with left:
        plot(_quality_figure(cells),key="perf_quality",height=300)
    with right:
        total=data.get("packet_totals_all_observations",{})
        with st.container(border=True):
            st.markdown("#### Do not pool every missing output as switch loss")
            st.write(f"All attempts recorded {number(total.get('measurement_missing_output'),0)} missing output observations. "
                     f"The supported subset establishes {number(delivery.get('path_non_delivery'),0)} observed path non-deliveries.")
            st.write("One trial had capture-instrumentation loss. Two capture-valid trials recorded path non-delivery; neither establishes BMv2 as the cause.")
            st.caption("Pending packets are not involved here: these are completed, drained historical observations. Warm-up is accounted separately.")
    st.dataframe(repeated_rows(cells),hide_index=True,width="stretch",
                 column_config={"Supported delivery (%)":st.column_config.NumberColumn(format="%.4f%%")})
    count_metric=st.selectbox("Count-based comparison",["delivery","rf_completion"],
        format_func=lambda k:"Supported packet delivery" if k=="delivery" else "RF decision completion (not accuracy)",
        key="perf_completion_metric")
    if completion_points(cells,count_metric):
        plot(_completion_figure(cells,count_metric),key="perf_completion",height=300)
        st.caption("Each point is a ratio of supported saved counts pooled over the cell's eligible trials. "
                   "Hover for numerator, denominator and eligible n; not a time rate or confidence interval. "
                   "Forwarding/features have no RF decision metric. Non-delivery is not proven BMv2 loss; RF completion is not accuracy.")
    else:
        notice("No applicable count observations", "No selected cells have a positive supported denominator and eligible trials. "
               "Forwarding/features have no classifier decisions; unavailable is not zero.",kind="info")
    rf_cells=[c for c in cells if c.get("mode","").startswith("rf_")]
    if rf_cells:
        st.caption("RF completion counts packet-eight inference events over eligible synthetic trials; "
                   "neither these counts nor the predicted class distribution measures semantic classification accuracy.")
    with st.expander("Original integrity failures and pacing warnings — retained, not waived"):
        st.dataframe(failed_trial_rows(data),hide_index=True,width="stretch")
        st.caption("A pacing WARNING is separate from hard local integrity FAIL. The original failed first trial and its 50 missing output packets remain unchanged.")
    with st.expander("Why independent clock qualification is INCONCLUSIVE"):
        diag=data.get("clock_diagnosis",{});session=diag.get("continuation_session",{});timeout=diag.get("single_reference_timeout",{})
        st.write(f"The separate continuation session collected {session.get('query_records','—')} reference queries: "
                 f"{session.get('valid_reference_records','—')} valid and {session.get('failed_reference_records','—')} failed. "
                 "The unchanged all-provider/no-acquisition-failure rule prevented qualification.")
        st.write(f"The preserved failure was {timeout.get('provider','—')}: {timeout.get('error','—')}, "
                 f"during {timeout.get('trial','—')}, {number(timeout.get('request_start_seconds_into_measurement'),3)} s into measurement.")
        providers=[]
        for name,p in diag.get("providers",{}).items():
            bounds=p.get("raw_rate",{})
            providers.append({"Provider":name,"Saved status":p.get("status"),"Queries":p.get("queries"),
                "Failed acquisitions":p.get("failed_queries"),"Estimate (ppm)":bounds.get("midpoint_estimate_ppm"),
                "Lower bound (ppm)":bounds.get("lower_ppm"),"Upper bound (ppm)":bounds.get("upper_ppm")})
        st.dataframe(providers,hide_index=True,width="stretch")
        st.caption("The numerical bounds lie inside ±1,000 ppm, but that alone does not override the acquisition criterion. "
                   "These are conservative network-reference uncertainty intervals, not statistical confidence intervals. "
                   "The original failed trial's execution session is not pooled into the continuation's clock certificate.")
    with st.expander("Matched-block resource diagnostics — NOT qualified overhead"):
        pairs=[]
        for p in data.get("diagnostic_resource_pairs_NOT_qualified_overhead",[]):
            if p.get("workload")!=workload or p.get("target_pps_UNQUALIFIED") not in rates:
                continue
            if p.get("first_mode") not in modes or p.get("second_mode") not in modes:
                continue
            cpu=p.get("difference_second_minus_first",{}).get("bmv2_cpu_seconds",{})
            rss=p.get("difference_second_minus_first",{}).get("bmv2_rss_peak_mib",{})
            pairs.append({"Comparison (second − first)":f"{MODE_NAMES[p['second_mode']]} − {MODE_NAMES[p['first_mode']]}",
                "Nominal target (pps)":p.get("target_pps_UNQUALIFIED"),"Diagnostic paired n":cpu.get("n"),
                "Protocol-qualified pairs":p.get("protocol_qualified_pairs"),"CPU median difference (s)":cpu.get("median"),
                "CPU min (s)":cpu.get("minimum"),"CPU max (s)":cpu.get("maximum"),
                "RSS median difference (MiB)":rss.get("median")})
        notice("Descriptive differences only", "No achieved-load qualification/comparability was established for this campaign. "
               "The saved differences retain all paired observations but cannot establish computational overhead, statistical superiority or standalone direction-extraction cost.",kind="warning")
        st.dataframe(pairs,hide_index=True,width="stretch")
    with st.expander("Unqualified rate diagnostics — hidden from headline results"):
        notice("Not validated performance metrics", "The following saved RAW-normalized numbers are diagnostics only. "
               "They do not qualify throughput or CPU percentages and are not plotted as established findings.",kind="warning")
        diagnostics=[]
        for c in cells:
            r={"Configuration":MODE_NAMES[c["mode"]],"Nominal target (pps)":c["nominal_target_pps"],"Qualification":"UNQUALIFIED"}
            for key in ("offered_pps","delivered_pps","delivered_ethernet_mbps","bmv2_cpu_one_core_percent"):
                r[key+" — diagnostic median"]=c.get("diagnostic_rate_statistics_UNQUALIFIED",{}).get(key,{}).get("median")
            diagnostics.append(r)
        st.dataframe(diagnostics,hide_index=True,width="stretch")
    provenance(evidence)


def _calibration(store):
    import streamlit as st
    import plotly.graph_objects as go
    from dashboard.components import MODEL_COLORS,metric_card,notice,plot,provenance,section_header
    root=_verified(store,"raw_calibration")
    if root is None:
        return
    loaded=store.calibration_trials()
    rows=calibration_rows(loaded)
    missing=[e for e in loaded if e.status!="verified"]
    if missing:
        notice("Some pinned child evidence is unavailable", f"{len(missing)} trial files could not be verified. "
               "Their values are omitted, not replaced by zero or the parent summary.",kind="warning")
    notice("Qualified calibration — a separate execution session", "These 16 trials support qualified average rates and "
           "OS-accounted CPU percentages at 100 and 1,000 pps. There is one observation per configuration/workload/rate, "
           "not five repetitions. They do not retroactively qualify the 160-trial campaign.",kind="success")
    s=root.data
    for col,label,value,note in zip(st.columns(3),["Verified child files","Independent RAW clock","Pacing warnings"],
            [f"{len(rows)} / {s.get('expected_trials','—')}",s.get("verdicts",{}).get("independent_raw_qualification",{}).get("status","Unavailable"),
             str(s.get("pacing_warning_trials","—"))],
            ["Saved per-trial gates applied","Campaign-average coarse rate certificate","Numerical thresholds unchanged"]):
        with col:
            metric_card(label,value,note)
    if not rows:
        provenance(root)
        return
    left,right=st.columns(2)
    with left:
        workload=st.selectbox("Calibration workload",list(WORKLOADS),key="cal_workload")
    with right:
        rate=st.selectbox("Calibration target (pps)", sorted({r["Target (pps)"] for r in rows}),key="cal_rate")
    shown=[r for r in rows if r["Workload"]==workload and r["Target (pps)"]==rate]
    section_header("Supported absolute-rate and CPU observations", "No error bars: n=1 per configuration. Values are not a saturation or latency result.")
    left,right=st.columns(2)
    for col,key,title in [(left,"Delivered (pps)","Delivered packet rate (pps)"),
                          (right,"BMv2 CPU (% of one core)","BMv2 CPU (% of one core)")]:
        with col:
            fig=go.Figure()
            for mode in MODES:
                values=[r for r in shown if r["mode"]==mode and r[key] is not None]
                if values:
                    fig.add_trace(go.Bar(x=[MODE_NAMES[mode]],y=[values[0][key]],name=MODE_NAMES[mode],
                        marker_color=MODEL_COLORS[mode],hovertemplate="%{x}: %{y:.4f}<extra>Single qualified observation</extra>"))
            fig.update_layout(yaxis_title=title,showlegend=False)
            plot(fig,key="cal_"+key,height=320)
    table=[{k:v for k,v in r.items() if k not in ("mode","Evidence")} for r in shown]
    st.dataframe(table,hide_index=True,width="stretch")
    st.caption("Delivered rate = unique outputs, including bounded drain, divided by the RAW offered window. "
               "Ethernet Mb/s counts 128-byte synthetic frames; no physical-wire preamble or inter-frame gaps. "
               "CPU uses Linux accounting ticks / independently qualified RAW elapsed time with the one-core convention. "
               "100% means one core's accounted CPU time, not the whole laptop; physical CPU accounting is not separately calibrated.")
    with st.expander("All 16 calibration observations and provenance"):
        st.dataframe([{k:v for k,v in r.items() if k not in ("mode",)} for r in rows],hide_index=True,width="stretch")
    notice("What this calibration does not establish", "One observation cannot establish that a classifier is inherently faster. "
           "Kernel forwarding delay, isolated RF inference latency, ASIC performance and maximum sustainable capacity remain unqualified.",kind="info")
    provenance(root)


def _higher(store):
    import streamlit as st
    from dashboard.components import metric_card,notice,provenance,section_header
    evidence=_verified(store,"higher_calibration")
    if evidence is None:
        return
    data=evidence.data
    notice("Supplementary calibration, not the final repeated campaign", "The historical higher-rate attempt stopped at trial 21/32. "
           "Its first 20 trials qualified; the original trial-21 integrity failure remains a failure. "
           "No 5,000-pps result is inferred from the planned schedule.",kind="warning")
    for col,label,value,note in zip(st.columns(3),["Attempts retained","Qualified trials","Campaign result"],
            [f"{data.get('attempted_trials','—')} / {data.get('expected_trials','—')}",str(data.get("valid_trials","—")),
             data.get("status","Unavailable").replace("_"," ")],
            ["No selective retries","Historical certificate; not pooled","All original failures preserved"]):
        with col:
            metric_card(label,value,note,tone="warning" if label=="Campaign result" else "neutral")
    section_header("Trial 21 · RF-B · classification-heavy · 2,000 pps", "Measurement integrity is separate from packet accounting and independent clock qualification.")
    t=_verified(store,"higher_calibration_trial_21")
    if t is not None:
        row=t.data;m=row.get("metrics",{});v=row.get("verdicts",{});g=row.get("metric_validity",{})
        st.dataframe([{"Local integrity":v.get("measurement_integrity",{}).get("status"),
            "Independent clock":v.get("independent_raw_qualification",{}).get("status"),
            "Pacing":v.get("sender_pacing_conformance",{}).get("status"),
            "Original failure":"; ".join(row.get("failures",[])),
            "Supported sent":m.get("packets_sent") if g.get("packet_accounting") is True else None,
            "Supported delivered":m.get("packets_received") if g.get("packet_accounting") is True else None,
            "Supported decisions":m.get("decisions") if g.get("classification_counts") is True else None,
            "Qualified absolute-rate claims":False}],hide_index=True,width="stretch")
        notice("Original hard failure retained", "; ".join(row.get("failures",[])) or "See original verdict.",kind="error")
        provenance(t)
    st.write("The decision was to close high-rate qualification and use the previously qualified common range "
             "for final acquisition. Complete delivery at a tested rate is not an experimentally established saturation point.")
    st.caption(f"Preserved abort reason: {data.get('abort_reason','Unavailable')}")
    with st.expander("Earlier completed higher-rate identities — parent-verified acquisition"):
        attempts=higher_attempt_rows(data)
        st.dataframe([a for a in attempts if a.get("Original ordinal",0)<21],hide_index=True,width="stretch")
        st.caption("The pinned parent summary reports 20 qualified earlier trials. This table exposes their original identities "
                   "and completed acquisition status only: individual earlier child metrics/verdicts are not loaded or invented. "
                   "Trial 21 is shown separately above using its own pinned scientific verdict.")
    provenance(evidence)


def render(store):
    import streamlit as st
    from dashboard.components import hero
    hero("RUNTIME EVIDENCE", "Performance Evaluation", "Inspect accounting, qualification and resource observations without launching an experiment.",
         badge="Historical · read-only")
    repeated,calibrated,higher=st.tabs(["Repeated campaign · 160 trials","Qualified RAW calibration · 16 trials","Supplementary higher-rate evidence"])
    with repeated:
        _repeated(store)
    with calibrated:
        _calibration(store)
    with higher:
        _higher(store)
