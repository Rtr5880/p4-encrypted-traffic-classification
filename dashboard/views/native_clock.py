"""Read-only inspection of saved actual BMv2 ingress timing and classification."""
from __future__ import annotations

import math

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.components import (MODEL_COLORS, hero, metric_card, notice, plot,
                                  provenance, section_header, unavailable)
from dashboard.evidence import CLASS_ORDER
from dashboard.views.classification import (confusion_figure, load_pairs,
                                            outcome_prediction, percent)


def numeric_list(value, length=None):
    if not isinstance(value, list) or (length is not None and len(value) != length):
        return None
    if any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) for x in value):
        return None
    return list(value)


def timing_rows(row):
    timing = row.get("timing", {})
    original = numeric_list(timing.get("original_iats_us"), 7)
    raw = numeric_list(timing.get("raw_native_iats_us"), 7)
    effective = numeric_list(timing.get("effective_native_iats_us"), 7)
    if original is None or raw is None or effective is None:
        raise ValueError("Expected seven saved original, raw-native and effective IAT gaps")
    return [{"Gap": i + 1, "Packets": f"{i + 1} → {i + 2}", "Capture IAT (µs)": a,
             "Native raw IAT (µs)": b, "Native effective IAT (µs)": c,
             "Raw − capture (µs)": b - a, "Effective − capture (µs)": c - a}
            for i, (a, b, c) in enumerate(zip(original, raw, effective))]


def timing_distribution(pairs, models=("B", "C"), changed_only=False):
    rows, skipped = [], []
    for pair in pairs:
        for model in models:
            row = pair[model]
            changed = outcome_prediction(row, "capture") != outcome_prediction(row, "native")
            if changed_only and not changed:
                continue
            try:
                gaps = timing_rows(row)
            except ValueError:
                skipped.append((pair["case_id"], model))
                continue
            for gap in gaps:
                rows.append({"model": model, "case_id": pair["case_id"], "label": pair["label"],
                             "gap": gap["Gap"], "original_us": gap["Capture IAT (µs)"],
                             "native_us": gap["Native raw IAT (µs)"],
                             "signed_us": gap["Raw − capture (µs)"],
                             "absolute_us": abs(gap["Raw − capture (µs)"]), "prediction_changed": changed})
    return rows, skipped


def changed_case_rows(pairs):
    rows = []
    for pair in pairs:
        for model in ("B", "C"):
            row = pair[model]
            capture, native = outcome_prediction(row, "capture"), outcome_prediction(row, "native")
            if capture is None or native is None:
                raise ValueError("Saved prediction identity unavailable")
            if capture != native:
                rows.append({"Case ID": pair["case_id"], "Model": f"RF-{model}",
                             "Capture-derived label": pair["label"], "Capture-time prediction": capture,
                             "Native prediction": native, "Capture correct": capture == pair["label"],
                             "Native correct": native == pair["label"],
                             "Max |IAT difference| (µs)": row.get("timing", {}).get("max_absolute_iat_deviation_us")})
    return rows


def ecdf_values(values):
    values = sorted(values)
    return values, [(i + 1) / len(values) for i in range(len(values))] if values else []


def packet_rows(row):
    reports = row.get("packet_checks")
    observed = numeric_list(row.get("timing", {}).get("observed_ingress_us"), 8)
    effective = numeric_list(row.get("timing", {}).get("effective_ingress_us"), 8)
    if not isinstance(reports, list) or len(reports) != 8 or observed is None or effective is None:
        raise ValueError("Eight saved packet reports and native timestamps required")
    result = []
    for i, packet in enumerate(reports):
        feature = packet.get("feature_report", {})
        result.append({"Packet": i + 1, "Original frame": packet.get("original_frame"),
                       "Direction": "F" if feature.get("direction") == 0 else "R" if feature.get("direction") == 1 else None,
                       "BMv2 raw ingress (µs)": observed[i], "Effective ingress (µs)": effective[i],
                       "Clamping adjustment (µs)": effective[i] - observed[i],
                       "RF report valid": packet.get("rf_report", {}).get("valid") == 1})
    return result


def forest_rows(row):
    packets = row.get("packet_checks", [])
    report = packets[-1].get("rf_report", {}) if packets else {}
    expected = row.get("decision", {}).get("expected_rf", {})
    actual_leaves, reference_leaves = report.get("leaves"), expected.get("leaves")
    actual_scores, reference_scores = report.get("scores"), expected.get("scores")
    if (numeric_list(actual_leaves, 10) is None or numeric_list(reference_leaves, 10) is None
            or numeric_list(actual_scores, 6) is None or numeric_list(reference_scores, 6) is None):
        raise ValueError("Actual packet-eight and reference forest arrays are incomplete")
    leaves = [{"Tree": i + 1, "P4 leaf": a, "Python leaf": b, "Match": a == b}
              for i, (a, b) in enumerate(zip(actual_leaves, reference_leaves))]
    scores = [{"Class": label, "P4 integer score": a, "Python integer score": b, "Match": a == b}
              for label, a, b in zip(CLASS_ORDER, actual_scores, reference_scores)]
    return leaves, scores


def _inspection(pairs):
    section_header("Inspect an actual eight-packet instance", "Immutable saved observations—not a live replay or a simulated timing animation.")
    controls = st.columns([1, 1, 2])
    with controls[0]:
        model = st.selectbox("Replay model", ["B", "C"], format_func=lambda x: f"RF-{x}", key="native_inspect_model")
    with controls[1]:
        category = st.selectbox("Label", ["All classes", *CLASS_ORDER], key="native_inspect_label")
    with controls[2]:
        changes = st.checkbox("Only changed predictions", value=True, key="native_inspect_changed")
    selected = [p for p in pairs if (category == "All classes" or p["label"] == category)
                and (not changes or outcome_prediction(p[model], "capture") != outcome_prediction(p[model], "native"))]
    if not selected:
        st.info("No saved instance meets those filters. Disable the change filter or choose another label.")
        return
    identity = st.selectbox("Saved case", [p["case_id"] for p in selected],
                            format_func=lambda x: x[:16] + "… " + x.split(":")[-2], key="native_inspect_case")
    pair = next(p for p in selected if p["case_id"] == identity)
    row = pair[model]
    st.code(identity, language=None)
    st.caption("Source capture: " + str(row.get("oracle_audit", {}).get("capture_id", "unavailable"))
               + " · Original frame numbers below refer to this capture, not the replay wrapper.")
    cols = st.columns(3)
    for col, label, value in zip(cols, ("Capture-derived label", "Capture-time prediction", "Native prediction"),
                                 (pair["label"], outcome_prediction(row, "capture"), outcome_prediction(row, "native"))):
        with col:
            metric_card(label, value, "RF-" + model + " · same saved case", "blue" if model == "B" else "teal")
    clock = row.get("clock_quality", {})
    st.caption(f"Replay status: {row.get('status', 'Unavailable')} · parity: {row.get('parity_passed', 'Unavailable')} · raw clock clean: {clock.get('clean', 'Unavailable')} · native feature clamping follows the running-maximum rule.")
    try:
        gaps = timing_rows(row)
        packets = packet_rows(row)
    except ValueError as exc:
        notice("Timing details unavailable", str(exc), "warning")
        return
    fig = go.Figure()
    for label, key, color in [("Capture", "Capture IAT (µs)", "#94a3b8"),
                              ("Native raw", "Native raw IAT (µs)", MODEL_COLORS[model])]:
        fig.add_scatter(name=label, x=[g["Gap"] for g in gaps], y=[g[key] for g in gaps],
                        mode="lines+markers", line=dict(color=color),
                        hovertemplate="Gap %{x}<br>%{y:,} µs<extra>%{fullData.name}</extra>")
    fig.update_layout(xaxis_title="Consecutive eligible-packet gap", yaxis_title="IAT (µs)")
    plot(fig, key="native_instance_gaps")
    st.caption("Lines connect discrete saved packet gaps only; they do not estimate forwarding or forest-execution latency.")
    st.dataframe(pd.DataFrame(gaps), width="stretch", hide_index=True)
    with st.expander("Packet timestamps, feature values and classifier intermediates"):
        st.dataframe(pd.DataFrame(packets), width="stretch", hide_index=True)
        features = row.get("features_C" if model == "C" else "features_B", {})
        st.dataframe(pd.DataFrame([{"Feature": k, "Observed value": v} for k, v in features.items()]), width="stretch", hide_index=True)
        try:
            leaves, scores = forest_rows(row)
            left, right = st.columns(2)
            with left:
                st.dataframe(pd.DataFrame(leaves), width="stretch", hide_index=True)
            with right:
                st.dataframe(pd.DataFrame(scores), width="stretch", hide_index=True)
        except ValueError as exc:
            notice("Forest intermediates unavailable", str(exc), "warning")


def render(store):
    hero("RESEARCH / NATIVE CLOCK", "Timing changes the feature vector.",
         "Follow actual BMv2 ingress observations from the frozen native replay to the RF prediction. These timing differences are not packet forwarding delay or RF execution latency.",
         "SAVED REPLAY · 398 CASES / MODEL")
    evidence = store.load("native_metrics")
    if not evidence.verified:
        unavailable(evidence)
        return
    metrics = evidence.data
    clock = metrics["clock_quality"]
    clean_label = "CLEAN" if clock.get("clean") is True else "NOT CLEAN" if clock.get("clean") is False else "UNAVAILABLE"
    cards = [("Raw ingress clock", clean_label, "Saved native ingress quality; not absolute rate qualification", "teal" if clock.get("clean") is True else "warning"),
             ("Reported outcomes", f"{clock.get('reported_records', '—')} / {clock.get('expected_records', '—')}", "B and C acquisition results", "neutral"),
             ("Backward steps", str(clock.get("raw_backward_steps", "—")), "Original raw observations preserved", "blue"),
             ("Timestamp adjustments", str(clock.get("timestamp_adjustments", "—")), "Running-maximum clamp audit", "neutral")]
    for col, (label, value, note, tone) in zip(st.columns(4), cards):
        with col:
            metric_card(label, value, note, tone)
    notice("Two distinct timing questions", "The native evaluation verifies raw ingress behaviour and executes the frozen classifier against the observed feature vector. It does not independently qualify an absolute clock rate, forwarding latency or CPU percentage. Later RAW benchmark qualification is separate evidence.", "warning")
    notice("Native comparison is not a pure direction ablation", "The B and C replay runs have separate actual arrival timings. Their accuracy difference includes the deployed forests and arrival variation. Capture-time predictions on the same features provide the cleaner direction comparison.")
    child, pairs, error = load_pairs(store, metrics)
    if error:
        notice("Native instance evidence unavailable", error + ". No timings or predictions were synthesized.", "error")
        provenance(evidence)
        return
    changes = changed_case_rows(pairs)
    section_header("Capture-time → native prediction changes", "A changed prediction may fix an error, create an error, or move between two wrong classes.")
    summary_rows = []
    for model in ("B", "C"):
        entries = [r for r in changes if r["Model"] == "RF-" + model]
        saved = metrics["common_paired_population"]
        capture = saved["capture_time_metrics_on_same_records"][model]
        native = saved["native_metrics"][model]
        summary_rows.append({"Model": f"RF-{model}", "Paired cases": len(pairs), "Prediction changes": len(entries),
                             "Changed (%)": len(entries) / len(pairs) if pairs else None,
                             "Capture accuracy": capture["accuracy"], "Native accuracy": native["accuracy"],
                             "Native − capture accuracy (pp)": 100 * (native["accuracy"] - capture["accuracy"]),
                             "Fixed errors": sum(not r["Capture correct"] and r["Native correct"] for r in entries),
                             "Introduced errors": sum(r["Capture correct"] and not r["Native correct"] for r in entries)})
    st.dataframe(pd.DataFrame(summary_rows).style.format({"Changed (%)": "{:.2%}", "Capture accuracy": "{:.2%}", "Native accuracy": "{:.2%}", "Native − capture accuracy (pp)": "{:+.2f}"}), width="stretch", hide_index=True)
    tabs = st.tabs(["Prediction transitions", "Timing distributions", "Instance inspection"])
    with tabs[0]:
        normalized = st.radio("Transition matrix", ["Counts", "Row-normalized"], horizontal=True, key="native_transition_matrix") == "Row-normalized"
        for col, model in zip(st.columns(2), ("B", "C")):
            with col:
                matrix = metrics["common_paired_population"]["native_vs_capture"][model]["capture_to_native_prediction_matrix"]
                plot(confusion_figure(matrix, normalized, f"RF-{model}: prediction transitions", "Native prediction", "Capture-time prediction"), key=f"native_transition_{model}", height=430)
        st.caption("Rows here are capture-time predictions, NOT activity labels; diagonal cells mean unchanged predictions.")
        st.dataframe(pd.DataFrame(changes), width="stretch", hide_index=True)
        st.download_button("Download changed predictions (CSV)", pd.DataFrame(changes).to_csv(index=False), "native_prediction_changes.csv", "text/csv", key="native_changes_download")
    with tabs[1]:
        model = st.selectbox("Timing models", ["Both", "B", "C"], key="native_distribution_model")
        changed = st.checkbox("Only instances with a changed prediction", key="native_distribution_changed")
        rows, skipped = timing_distribution(pairs, ("B", "C") if model == "Both" else (model,), changed)
        if skipped:
            notice("Incomplete timing rows", f"{len(skipped)} case/model observations have incomplete timing fields and are omitted from these plots only; no replacement values or accuracy exclusions were made.", "warning")
        st.caption(f"{len(rows):,} actual saved gap observations. Each complete eight-packet prefix contributes seven gaps; gaps are related within an instance and are not independent test samples.")
        if rows:
            left, right = st.columns(2)
            histogram, ecdf = go.Figure(), go.Figure()
            for m in ("B", "C"):
                values = [r["signed_us"] for r in rows if r["model"] == m]
                if not values:
                    continue
                histogram.add_histogram(name=f"RF-{m}", x=values, nbinsx=60, opacity=.65, marker_color=MODEL_COLORS[m])
                x, y = ecdf_values([abs(v) for v in values])
                ecdf.add_scatter(name=f"RF-{m}", x=x, y=y, mode="lines", line=dict(color=MODEL_COLORS[m], shape="hv"))
            histogram.update_layout(barmode="overlay", xaxis_title="Raw native − capture IAT (µs)", yaxis_title="Gap observations")
            ecdf.update_layout(xaxis_title="Absolute IAT difference (µs)", yaxis_title="Empirical cumulative fraction", yaxis_tickformat=".0%")
            with left:
                plot(histogram, key="native_gap_histogram")
            with right:
                plot(ecdf, key="native_gap_ecdf")
        st.caption("All saved outliers remain included. Percentiles describe replay scheduling / ingress IAT differences, not qualified forwarding latency.")
        aggregates = []
        for m in ("B", "C"):
            for name, title in [("absolute_gap_deviation_us", "|Gap difference|"), ("absolute_prefix_span_deviation_us", "|Prefix span difference|"), ("sender_lateness_us_all_observed_sends", "Sender lateness")]:
                stats = metrics.get("timing_deviation", {}).get(m, {}).get(name, {})
                aggregates.append({"Model": f"RF-{m}", "Saved quantity": title, **{k: stats.get(k) for k in ("count", "mean", "median", "p95", "p99", "maximum")}})
        st.dataframe(pd.DataFrame(aggregates), width="stretch", hide_index=True)
        st.caption("Aggregate table is the complete saved population in microseconds; interactive filters above apply only to the charts.")
    with tabs[2]:
        _inspection(pairs)
    st.caption(f"Instance source: sealed {child.path}; no original PCAP reads or new replay occurred.")
    provenance(evidence)
