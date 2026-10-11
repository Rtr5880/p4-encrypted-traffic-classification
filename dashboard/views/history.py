"""Curated, read-only experiment history; browsing never replaces a headline pin."""
from datetime import datetime
import plotly.graph_objects as go
import streamlit as st

from dashboard.components import hero, section_header, metric_row, notice, provenance, plot, unavailable


def _verdict(value):
    if isinstance(value, str):
        return value.upper()
    if isinstance(value, dict):
        return _verdict(value.get("status", value.get("verdict")))
    return "UNAVAILABLE"


def saved_health(data, key):
    """Read saved verdicts, never infer scientific qualification from completion."""
    if not isinstance(data, dict):
        return "UNAVAILABLE"
    aliases = {
        "measurement_integrity": ("measurement_integrity",),
        "independent_raw_qualification": ("independent_raw_qualification", "clock_rate_qualification"),
        "sender_pacing_conformance": ("sender_pacing_conformance",),
    }
    for name in aliases[key]:
        result = _verdict(data.get("verdicts", {}).get(name))
        if result == "UNAVAILABLE":
            result = _verdict(data.get(name))
        if result != "UNAVAILABLE":
            return result
    # Live synthetic summaries retain complete local per-trial verdicts.
    values = {_verdict(trial.get("verdicts", {}).get(key)) for trial in data.get("trials", [])
              if isinstance(trial, dict)}
    values.discard("UNAVAILABLE")
    if len(values) == 1:
        return next(iter(values))
    if values:
        return "MIXED: " + ", ".join(sorted(values))
    return "UNAVAILABLE"


def execution_label(data):
    status = str(data.get("status", "UNAVAILABLE"))
    if data.get("historical_final_summary_absent"):
        return "RECOVERED / ORIGINAL SUMMARY ABSENT"
    if status == "UNAVAILABLE" and data.get("execution_completed") is True:
        return "COMPLETED"
    return status


def history_row(evidence):
    entry = evidence.entry or {}
    run = entry.get("run_id", "")
    try:
        date = datetime.strptime(run[:16], "%Y%m%dT%H%M%SZ").date().isoformat()
    except ValueError:
        date = "Not recorded"
    data = evidence.data if evidence.verified and isinstance(evidence.data, dict) else {}
    return {
        "id": entry.get("id", evidence.role),
        "Date (UTC)": date,
        "Category": entry.get("category", entry.get("family", "Unspecified")),
        "Run": run,
        "Configuration": entry.get("mode", entry.get("model", "Not applicable / not recorded")),
        "Workload": entry.get("workload", "Not applicable / not recorded"),
        "Target (pps)": entry.get("target_pps"),
        "Saved execution status": execution_label(data) if evidence.verified else evidence.status.upper(),
        "Measurement integrity": saved_health(data, "measurement_integrity"),
        "Independent RAW clock": saved_health(data, "independent_raw_qualification"),
        "Pacing": saved_health(data, "sender_pacing_conformance"),
        "File identity": evidence.status.upper(),
    }


def filter_rows(rows, categories=(), configurations=(), statuses=(), query="", dates=()):
    query = query.strip().lower()
    selected = []
    for row in rows:
        status_values = [row[field] for field in ("Saved execution status", "Measurement integrity", "Independent RAW clock", "Pacing", "File identity")]
        if categories and row["Category"] not in categories:
            continue
        if configurations and row["Configuration"] not in configurations:
            continue
        if statuses and not any(choice in str(value).upper() for choice in statuses for value in status_values):
            continue
        if dates and row["Date (UTC)"] not in dates:
            continue
        if query and query not in " ".join(str(value) for value in row.values()).lower():
            continue
        selected.append(row)
    return selected


def render(store):
    hero("EVIDENCE / EXPERIMENT HISTORY", "Every outcome belongs in the research record.",
         "Browse explicitly catalogued saved experiments, including failures, recovery reports "
         "and separate execution sessions. Selection never changes the pinned research headlines.",
         "READ-ONLY / CURATED PROVENANCE")
    notice("Completion is not qualification",
           "Execution status, measurement integrity, independent clock qualification and sender pacing "
           "are separate fields. UNAVAILABLE means this verdict is not present in the selected summary; "
           "it is not a failure, zero or an inferred PASS. Target pps is not achieved offered load.")
    evidence = store.load_history()
    if not evidence:
        st.error("The explicit history registry is empty or unavailable. No latest-run scan or substitute data was used.")
        return
    rows = [history_row(item) for item in evidence]
    metric_row([
        dict(label="Catalogued records", value=str(len(rows)), note="Explicit historical sources, not an unrestricted results scan"),
        dict(label="Verified summaries", value=str(sum(item.verified for item in evidence)), note="Pinned file/schema identity; qualification is separate", tone="teal"),
        dict(label="Evidence categories", value=str(len({row['Category'] for row in rows})), note="Research, diagnostic and demonstration records retained"),
    ])
    cols = st.columns(3)
    with cols[0]:
        categories = st.multiselect("Experiment category", sorted({row["Category"] for row in rows}), key="history-categories")
    with cols[1]:
        configurations = st.multiselect("Configuration / model", sorted({str(row["Configuration"]) for row in rows}), key="history-configurations")
    with cols[2]:
        statuses = st.multiselect("Status / health contains", ["PASS", "FAIL", "WARNING", "INCONCLUSIVE", "COMPLETED", "INCOMPLETE", "RECOVERED", "UNAVAILABLE"], key="history-statuses")
    left, right = st.columns([2, 1])
    with left:
        query = st.text_input("Find run, workload, rate or status", key="history-query", placeholder="For example: 20261008, cached-forwarding, 1000, FAIL")
    with right:
        dates = st.multiselect("Run date (UTC)", sorted({row["Date (UTC)"] for row in rows}), key="history-dates")
    selected = filter_rows(rows, categories, configurations, statuses, query, dates)
    section_header("Saved experiment catalogue", "Failed and incomplete runs are retained. No comparison is promoted merely because it is newer.")
    st.caption(f"{len(selected)} of {len(rows)} catalogued records match the filters.")
    if not selected:
        st.info("No saved records match these filters. Clear a filter to inspect the retained history.")
        return
    st.dataframe([{key: value for key, value in row.items() if key != "id"} for row in selected], width="stretch", hide_index=True)
    counts = {}
    for row in selected:
        counts[row["Category"]] = counts.get(row["Category"], 0) + 1
    fig = go.Figure(go.Bar(x=list(counts), y=list(counts.values()), marker_color="#60a5fa",
                           hovertemplate="%{x}: %{y} catalogued record(s)<extra></extra>"))
    fig.update_yaxes(title="Catalogued records", dtick=1)
    fig.update_xaxes(title="Experiment category")
    plot(fig, key="history-category-count", height=270)
    section_header("Inspect a saved record", "Summary provenance is verified independently of its historical verdict.")
    by_id = {item.entry.get("id", item.role): item for item in evidence}
    labels = {row["id"]: f"{row['Run']} · {row['Category']}" for row in selected}
    chosen = st.selectbox("Saved experiment", list(labels), format_func=labels.get, key="history-record")
    item = by_id[chosen]
    if not item.verified:
        unavailable(item)
        return
    st.markdown(f"**{item.entry.get('label', chosen)}**")
    st.caption(item.entry.get("scope", "Saved historical evidence."))
    chosen_row = next(row for row in selected if row["id"] == chosen)
    st.dataframe([{key: chosen_row[key] for key in ("Saved execution status", "Measurement integrity", "Independent RAW clock", "Pacing")}], width="stretch", hide_index=True)
    for limitation in item.entry.get("limitations", []):
        st.caption(str(limitation))
    data = item.data
    flags = {key: data[key] for key in ("execution_completed", "passed", "acquisition_complete", "raw_rate_qualified", "demo_only", "accuracy_scored", "kernel_forwarding_latency_qualified", "historical_final_summary_absent", "abort_reason", "error") if key in data}
    if flags:
        with st.expander("Original summary flags and failure context"):
            st.json(flags)
            for field in ("failures", "limitations", "prominent_warning", "abort_reason", "verdicts"):
                if field in data:
                    st.write(field)
                    st.json(data[field])
    provenance(item)
    st.caption("History is a curated catalogue at this dashboard checkpoint. Future demo runs remain in the Live Monitor and on disk until explicitly added to this registry.")
