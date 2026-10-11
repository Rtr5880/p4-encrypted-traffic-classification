"""Saved paired RF classification results; no training or experiment execution."""
from __future__ import annotations

import math
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.components import (MODEL_COLORS, hero, metric_card, notice, plot,
                                  provenance, section_header, unavailable)
from dashboard.evidence import CLASS_ORDER

DOMAINS = {"Capture-time reference": "capture", "Native-clock replay": "native"}


def class_name(value: Any) -> str | None:
    if isinstance(value, str) and value in CLASS_ORDER:
        return value
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < len(CLASS_ORDER):
        return CLASS_ORDER[value]
    return None


def paired_outcomes(outcomes: list[dict], case_ids: list[str] | None = None) -> list[dict]:
    """Join by identity, never row position; reject duplicates/incompatible labels."""
    if not isinstance(outcomes, list):
        raise ValueError("Native outcomes must be a saved JSONL list")
    by_model: dict[str, dict[str, dict]] = {"B": {}, "C": {}}
    for row in outcomes:
        if not isinstance(row, dict) or row.get("model") not in by_model:
            raise ValueError("Unexpected native model outcome")
        identity = row.get("case_id")
        if not isinstance(identity, str) or not identity:
            raise ValueError("Outcome has no case identity")
        model = row["model"]
        if identity in by_model[model]:
            raise ValueError(f"Duplicate RF-{model} case identity")
        by_model[model][identity] = row
    expected = list(case_ids) if case_ids is not None else sorted(by_model["B"])
    if len(expected) != len(set(expected)):
        raise ValueError("Paired population has duplicate identifiers")
    if set(by_model["B"]) != set(expected) or set(by_model["C"]) != set(expected):
        raise ValueError("B/C outcomes differ from the saved common paired population")
    pairs = []
    for identity in expected:
        b, c = by_model["B"][identity], by_model["C"][identity]
        if b.get("label") not in CLASS_ORDER or b.get("label") != c.get("label"):
            raise ValueError("Paired case labels disagree or are unsupported")
        if b.get("record_id") != c.get("record_id"):
            raise ValueError("Paired original record identities disagree")
        pairs.append({"case_id": identity, "label": b["label"], "B": b, "C": c})
    return pairs


def outcome_prediction(row: dict, domain: str) -> str | None:
    if domain == "capture":
        return class_name(row.get("capture_time_prediction")) or class_name(row.get("capture_time_class"))
    if domain == "native":
        return class_name(row.get("prediction")) or class_name(row.get("class"))
    raise ValueError("Unsupported evaluation domain")


def comparison_rows(pairs: list[dict], domain: str) -> list[dict]:
    rows = []
    for pair in pairs:
        b, c = (outcome_prediction(pair[m], domain) for m in ("B", "C"))
        if b is None or c is None:
            raise ValueError("Saved paired prediction is missing or outside class order")
        truth = pair["label"]
        rows.append({"Case ID": pair["case_id"], "Capture-derived label": truth,
                     "RF-B": b, "RF-C": c, "B correct": b == truth,
                     "C correct": c == truth, "Models disagree": b != c,
                     "C fixes B": b != truth and c == truth,
                     "C introduces error": b == truth and c != truth})
    return rows


def confusion_values(matrix: list[list[int]], normalized: bool = False) -> list[list[float | int | None]]:
    if (not isinstance(matrix, list) or len(matrix) != len(CLASS_ORDER)
            or any(not isinstance(row, list) or len(row) != len(CLASS_ORDER) for row in matrix)
            or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for row in matrix for v in row)):
        raise ValueError("Expected six-class nonnegative count confusion matrix")
    if not normalized:
        return [list(row) for row in matrix]
    return [[value / sum(row) if sum(row) else None for value in row] for row in matrix]


def confusion_figure(matrix: list[list[int]], normalized: bool, title: str,
                     x_title: str = "Predicted class", y_title: str = "Capture-derived label") -> go.Figure:
    values = confusion_values(matrix, normalized)
    text = [[("—" if value is None else f"{value:.1%}") if normalized else str(value)
             for value in row] for row in values]
    custom = [[[matrix[i][j], sum(matrix[i])] for j in range(6)] for i in range(6)]
    fig = go.Figure(go.Heatmap(z=values, x=CLASS_ORDER, y=CLASS_ORDER, text=text,
                             texttemplate="%{text}", customdata=custom,
                             colorscale=[[0, "#122238"], [1, "#2dd4bf"]],
                             zmin=0, zmax=1 if normalized else None,
                             colorbar=dict(title="Fraction" if normalized else "Cases"),
                             hovertemplate="Row: %{y}<br>Column: %{x}<br>Cases: %{customdata[0]}"
                             "<br>Row support: %{customdata[1]}<extra></extra>"))
    fig.update_layout(title=title, xaxis_title=x_title, yaxis_title=y_title)
    fig.update_yaxes(autorange="reversed")
    return fig


def metric_blocks(metrics: dict, domain: str) -> dict[str, dict]:
    paired = metrics.get("common_paired_population", {})
    key = "capture_time_metrics_on_same_records" if domain == "capture" else "native_metrics"
    if domain not in ("capture", "native"):
        raise ValueError("Unsupported evaluation domain")
    blocks = paired.get(key)
    if not isinstance(blocks, dict) or set(blocks) != {"B", "C"}:
        raise ValueError("Saved paired metric blocks are unavailable")
    count = paired.get("records")
    for model, block in blocks.items():
        if block.get("records") != count or block.get("class_order") != CLASS_ORDER:
            raise ValueError(f"RF-{model} metric population/order differs from common population")
        confusion_values(block.get("confusion_matrix"))
        if sum(map(sum, block["confusion_matrix"])) != count:
            raise ValueError("Saved metric matrix and common population disagree")
    return blocks


def per_class_rows(blocks: dict[str, dict]) -> list[dict]:
    rows = []
    for label in CLASS_ORDER:
        b, c = (blocks[m]["per_class"][label] for m in ("B", "C"))
        if b["support"] != c["support"]:
            raise ValueError("Class support differs between the paired models")
        rows.append({"Class": label, "Support": b["support"],
                     "B precision": b["precision"], "C precision": c["precision"],
                     "B recall": b["recall"], "C recall": c["recall"],
                     "B F1": b["f1"], "C F1": c["f1"],
                     "C − B F1 (pp)": 100 * (c["f1"] - b["f1"]),
                     "C − B recall (pp)": 100 * (c["recall"] - b["recall"])})
    return rows


def load_pairs(store, metrics: dict):
    """Only expose details authenticated by the acquisition summary's seal."""
    child = store.load_child("native_run", "outcomes.jsonl", format="jsonl")
    if not child.verified:
        return child, [], child.message
    try:
        return child, paired_outcomes(child.data, metrics["common_paired_population"]["case_ids"]), None
    except (ValueError, KeyError, TypeError) as exc:
        return child, [], str(exc)


def percent(value):
    return f"{100 * value:.2f}%" if isinstance(value, (float, int)) and math.isfinite(value) else "Unavailable"


def _metric_chart(blocks):
    keys = [("Accuracy", "accuracy"), ("Macro-F1", "macro_f1"),
            ("Macro precision", "macro_precision"), ("Macro recall", "macro_recall")]
    fig = go.Figure()
    for m in ("B", "C"):
        fig.add_bar(name=f"RF-{m}", x=[label for label, _ in keys],
                    y=[blocks[m][key] * 100 for _, key in keys], marker_color=MODEL_COLORS[m],
                    text=[f"{blocks[m][key] * 100:.2f}%" for _, key in keys], textposition="outside",
                    hovertemplate="%{x}: %{y:.2f}%<extra>%{fullData.name}</extra>")
    fig.update_layout(barmode="group", yaxis_title="Score (%)", yaxis_range=[0, 105])
    return fig


def _render_error_browser(pairs, domain):
    rows = comparison_rows(pairs, domain)
    section_header("Paired error explorer", "The same case ID and provisional label are used for RF-B and RF-C.")
    cols = st.columns([1, 2, 2])
    with cols[0]:
        label = st.selectbox("Capture-derived class", ["All classes", *CLASS_ORDER], key="classification_error_label")
    with cols[1]:
        kind = st.selectbox("Cases to inspect", ["Any model error", "C fixes B", "C introduces error", "Models disagree", "All paired cases"], key="classification_error_kind")
    with cols[2]:
        search = st.text_input("Find case ID", key="classification_error_search")
    selected = []
    for row in rows:
        keep = {"Any model error": not (row["B correct"] and row["C correct"]),
                "C fixes B": row["C fixes B"], "C introduces error": row["C introduces error"],
                "Models disagree": row["Models disagree"], "All paired cases": True}[kind]
        if keep and (label == "All classes" or row["Capture-derived label"] == label) and search.lower() in row["Case ID"].lower():
            selected.append(row)
    st.caption(f"{len(selected)} displayed / {len(rows)} paired cases. Correct means agreement with a capture-derived label, not independently verified media ground truth.")
    st.dataframe(pd.DataFrame(selected, columns=list(rows[0]) if rows else []), width="stretch", hide_index=True)
    st.download_button("Download displayed comparisons (CSV)", pd.DataFrame(selected).to_csv(index=False),
                       "paired_rf_comparisons.csv", "text/csv", key="classification_download")
    if selected:
        identity = st.selectbox("Inspect one paired instance", [row["Case ID"] for row in selected],
                                format_func=lambda value: value[:16] + "… " + value.split(":")[-2],
                                key="classification_case")
        pair = next(p for p in pairs if p["case_id"] == identity)
        st.code(identity, language=None)
        st.caption("Native feature values below were observed in separate replay runs. They are not identical arrival schedules merely because the case ID matches.")
        feature_rows = []
        for name in pair["C"].get("features_C", {}):
            feature_rows.append({"Feature": name, "RF-B replay": pair["B"].get("features_C", {}).get(name),
                                 "RF-C replay": pair["C"].get("features_C", {}).get(name),
                                 "Used by B": name not in ("reverse_packet_count", "direction_change_count")})
        st.dataframe(pd.DataFrame(feature_rows), width="stretch", hide_index=True)


def render(store):
    hero("RESEARCH / CLASSIFICATION", "What does direction add?",
         "Inspect the frozen RF-B/RF-C comparison on the same held-out eight-packet instances. Separate classification quality from faithful switch execution.",
         "PRELIMINARY · CAPTURE-DERIVED LABELS")
    evidence = store.load("native_metrics")
    if not evidence.verified:
        unavailable(evidence)
        return
    metrics = evidence.data
    notice("Scope of the research result", "Six provisional capture-derived classes; parent-conversation-disjoint, not fully capture/session-disjoint. STREAMING is not separately labelled audio versus video. These are frozen selected RF models, not the earlier XGBoost or tuning populations.", "warning")
    selection = st.radio("Evaluation timing", list(DOMAINS), horizontal=True, key="classification_domain")
    domain = DOMAINS[selection]
    try:
        blocks = metric_blocks(metrics, domain)
        class_rows = per_class_rows(blocks)
    except (ValueError, KeyError, TypeError) as exc:
        notice("Saved metric inconsistency", str(exc), "error")
        provenance(evidence)
        return
    paired = metrics["common_paired_population"]
    cards = [("RF-B macro-F1", percent(blocks["B"]["macro_f1"]), "Six size / inter-arrival features", "blue"),
             ("RF-C macro-F1", percent(blocks["C"]["macro_f1"]), "B + reverse count / direction changes", "teal"),
             ("C − B macro-F1", f"{100 * (blocks['C']['macro_f1'] - blocks['B']['macro_f1']):+.2f} pp", "Percentage points, not relative percent", "teal"),
             ("Common paired cases", str(paired["records"]), f"Coverage: {percent(paired['coverage'])}", "neutral")]
    for col, (label, value, note, tone) in zip(st.columns(4), cards):
        with col:
            metric_card(label, value, note, tone)
    if domain == "native":
        notice("Separate native arrivals", "Native RF-B and RF-C were replayed separately and observed different IATs. Their difference describes deployed results; the same-feature capture-time comparison is the cleaner direction ablation.")
    else:
        notice("Same-feature reference comparison", "Both classifiers use the same capture-time size/IAT values. C adds direction, while the trained forests themselves also differ. This is the matched feature-set experiment—not a comparison with Akem's headline accuracy.")
    section_header("Overall classification quality", "Accuracy counts correct labels; macro-F1 gives each of the six classes equal weight.")
    plot(_metric_chart(blocks), key="classification_metrics", height=350)
    metric_table = [{"Model": f"RF-{m}", "Cases": blocks[m]["records"],
                     **{k: blocks[m][k] for k in ("accuracy", "macro_f1", "macro_precision", "macro_recall", "weighted_f1") if k in blocks[m]}}
                    for m in ("B", "C")]
    st.dataframe(pd.DataFrame(metric_table).style.format({k: "{:.2%}" for k in ("accuracy", "macro_f1", "macro_precision", "macro_recall", "weighted_f1")}), width="stretch", hide_index=True)
    section_header("Where do the errors go?", "Rows are capture-derived labels; columns are predictions. Row-normalized values use each class's support.")
    normalized = st.radio("Confusion matrix display", ["Counts", "Row-normalized"], horizontal=True, key="classification_matrix") == "Row-normalized"
    for col, model in zip(st.columns(2), ("B", "C")):
        with col:
            plot(confusion_figure(blocks[model]["confusion_matrix"], normalized, f"RF-{model}"),
                 key=f"classification_confusion_{model}", height=430)
    section_header("Class-level direction comparison", "Support is unchanged between models. Positive differences favour C for the selected metric; they are not significance tests.")
    chosen = st.selectbox("Class metric", ["F1", "Recall", "Precision"], key="classification_class_metric")
    field = chosen.lower()
    fig = go.Figure()
    for model in ("B", "C"):
        fig.add_bar(name=f"RF-{model}", x=CLASS_ORDER,
                    y=[blocks[model]["per_class"][label][field] * 100 for label in CLASS_ORDER],
                    customdata=[[blocks[model]["per_class"][label]["support"]] for label in CLASS_ORDER],
                    marker_color=MODEL_COLORS[model],
                    hovertemplate="%{x}: %{y:.2f}%<br>Support: %{customdata[0]}<extra>%{fullData.name}</extra>")
    fig.update_layout(barmode="group", yaxis_title=chosen + " (%)", yaxis_range=[0, 105])
    plot(fig, key="classification_class_bars")
    formats = {key: "{:.2%}" for key in class_rows[0] if key not in ("Class", "Support") and "(pp)" not in key}
    formats.update({"C − B F1 (pp)": "{:+.2f}", "C − B recall (pp)": "{:+.2f}"})
    st.dataframe(pd.DataFrame(class_rows).style.format(formats), width="stretch", hide_index=True)
    child, pairs, error = load_pairs(store, metrics)
    if error:
        notice("Instance details withheld", error + ". Aggregate verified metrics remain visible; no substitute examples were generated.", "warning")
    else:
        _render_error_browser(pairs, domain)
        st.caption(f"Instance source: sealed {child.path}; joined by case ID, never file order.")
    with st.expander("How to interpret these metrics"):
        st.markdown("Precision asks how often a predicted class is correct. Recall asks how much of a labelled class is found. F1 balances both; macro-F1 averages six class F1 values. Prediction parity asks whether P4 implements the reference classifier—it is not classification accuracy. Neither high parity nor complete eight-packet coverage establishes accuracy on excluded short flows.")
    provenance(evidence)
