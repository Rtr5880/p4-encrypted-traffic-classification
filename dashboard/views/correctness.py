"""Read-only inspection of the sealed controlled real-PCAP correctness replay.

Arithmetic describes saved evidence; no classifier, capture reader, switch or
experiment runner is executed. Actual features come from P4's feature_report,
not the expected feature dictionaries copied into decision metadata.
"""
from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from dashboard.components import (
    hero, section_header, metric_row, notice, provenance, plot, unavailable,
)
from dashboard.evidence import CLASS_ORDER

FEATURES = (
    "size_min", "size_max", "size_sum", "iat_min", "iat_max", "iat_sum",
    "reverse_packet_count", "direction_change_count",
)
REPORT_FIELDS = {"reverse_packet_count": "reverse_count",
                 "direction_change_count": "direction_changes"}
PARITY_FIELDS = ("feature_mismatches", "leaf_mismatches",
                 "score_mismatches", "class_mismatches")
INTEGRITY_FIELDS = ("eligibility_mismatches", "instance_mismatches",
                    "raw_packet_byte_mismatches", "missing_or_extra_decisions")


def count(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Invalid saved count: {name}")
    return value


def replay_summary(data):
    """Aggregate original saved counts without replacing an unavailable value."""
    result = {key: 0 for key in (
        "packets", "eligible_packets", "admitted_packets", "collision_packets",
        "expected_n8_instances", "expected_classifications",
        "collision_excluded_n8_instances", "collision_excluded_parents",
        "collision_excluded_instances_all_lengths", "collision_excluded_short_instances",
        "instances", "short_instances",
    )}
    result["captures"] = count(data["captures_checked"], "captures_checked")
    if result["captures"] != len(data["captures"]):
        raise ValueError("Saved capture population is inconsistent")
    result["models"] = {
        model: {key: 0 for key in ("packets_checked", "classifications")
                + PARITY_FIELDS + INTEGRITY_FIELDS}
        for model in ("B", "C")
    }
    for capture in data["captures"]:
        prep = capture["preparation"]
        for key in result:
            if key not in ("captures", "models", "instances", "short_instances"):
                result[key] += count(prep[key], key)
        result["instances"] += count(prep["reference_audit"]["instances"], "instances")
        result["short_instances"] += count(
            prep["reference_audit"]["windows"]["8"]["short_instances"], "short_instances")
        for model in ("B", "C"):
            for key in result["models"][model]:
                result["models"][model][key] += count(capture["models"][model][key], key)
    if result["short_instances"] + result["expected_n8_instances"] != result["instances"]:
        raise ValueError("Saved short/N8 instance accounting does not reconcile")
    if (result["expected_n8_instances"] - result["collision_excluded_n8_instances"]
            != result["expected_classifications"]):
        raise ValueError("Saved collision/N8 accounting does not reconcile")
    return result


def capture_quality_rows(data):
    rows = []
    for capture in data["captures"]:
        prep = capture["preparation"]
        for model in ("B", "C"):
            report = capture["models"][model]
            expected = count(prep["expected_classifications"], "expected_classifications")
            actual = count(report["classifications"], "classifications")
            rows.append({
                "Capture": capture["capture"], "Model": "RF-" + model,
                "Saved status": capture["status"],
                "Activity hint": prep["reference_audit"]["provisional_class"],
                "Checked packets": count(report["packets_checked"], "packets_checked"),
                "Eligible packets": count(prep["eligible_packets"], "eligible_packets"),
                "All instances": count(prep["reference_audit"]["instances"], "instances"),
                "Short instances": count(prep["reference_audit"]["windows"]["8"]["short_instances"], "short_instances"),
                "N8 instances": count(prep["expected_n8_instances"], "expected_n8_instances"),
                "Collision-excluded N8": count(prep["collision_excluded_n8_instances"], "collision_excluded_n8_instances"),
                "Expected decisions": expected, "Actual decisions": actual,
                "Admitted-N8 completion (%)": 100 * actual / expected if expected else None,
                **{key.replace("_", " ").capitalize(): count(report[key], key)
                   for key in PARITY_FIELDS + INTEGRITY_FIELDS},
            })
    return rows


def _index(rows, name):
    if not isinstance(rows, list):
        raise ValueError(f"{name} is not a saved record list")
    result = {}
    for row in rows:
        key = row["record_id"]
        if key in result:
            raise ValueError(f"Duplicate saved record ID in {name}")
        result[key] = row
    return result


def _vector(values, length, name):
    if not isinstance(values, list) or len(values) != length:
        raise ValueError(f"{name} must contain {length} saved values")
    return [count(value, name) for value in values]


def decision_detail(instance, expected, actual, model):
    """Compare authentic displayed records; do not rerun RF inference."""
    if model not in ("B", "C"):
        raise ValueError("Unsupported RF model")
    if instance["collision_excluded"]:
        if expected is not None or actual is not None:
            raise ValueError("A collision-excluded instance unexpectedly has a decision")
        return {"state": "collision_excluded", "instance": instance}
    if expected is None or actual is None:
        return {"state": "missing_decision", "instance": instance,
                "expected_present": expected is not None, "actual_present": actual is not None}
    feature = actual["feature_report"]
    rf = actual["rf_report"]
    features = []
    for name in FEATURES:
        want = count(instance["features_C"][name], name)
        got = count(feature[REPORT_FIELDS.get(name, name)], name)
        features.append({"Feature": name, "Unit": "bytes" if name.startswith("size_")
                         else "microseconds" if name.startswith("iat_") else "count",
                         "Forest input": model == "C" or name in FEATURES[:6],
                         "Python reference": want, "P4 report": got, "Match": got == want})
    expected_leaves = _vector(expected["leaves"], 10, "Python leaves")
    actual_leaves = _vector(rf["leaves"], 10, "P4 leaves")
    expected_scores = _vector(expected["scores"], 6, "Python scores")
    actual_scores = _vector(rf["scores"], 6, "P4 scores")
    want_class = count(expected["prediction"], "Python class index")
    got_class = count(rf["prediction"], "P4 class index")
    if max(want_class, got_class) >= len(CLASS_ORDER):
        raise ValueError("Saved class index is outside the six-class ordering")
    try:
        instance_number = int(instance["instance_id"].rsplit(":", 1)[1])
    except (ValueError, IndexError):
        raise ValueError("Saved flow instance identity has no integer generation") from None
    # Decision metadata is copied from the reference by the historical runner.
    # Its equality alone is not proof of the switch's state identity: also use
    # the actual decoded report's slot and instance-generation fields.
    identities = (
        all(actual[key] == instance[key] == expected[key]
            for key in ("record_id", "instance_id", "parent_candidate_conversation_id",
                        "packet_id", "slot"))
        and feature["slot"] == instance["slot"]
        and feature["instance"] == instance_number
    )
    trigger = (feature["count"] == 8 and feature["status"] == 2
               and feature["packet_id"] == instance["packet_id"] and rf["valid"] == 1
               and rf["model"] == (0 if model == "B" else 1))
    verdicts = {"Features": all(row["Match"] for row in features),
                "Ten leaves": expected_leaves == actual_leaves,
                "Six scores": expected_scores == actual_scores,
                "Prediction": want_class == got_class,
                "Identity": identities, "Packet-eight trigger": trigger}
    return {"state": "compared", "instance": instance, "features": features,
            "leaves": [{"Tree": i + 1, "Python leaf": want, "P4 leaf": got, "Match": want == got}
                       for i, (want, got) in enumerate(zip(expected_leaves, actual_leaves))],
            "scores": [{"Class": label, "Python integer total": want, "P4 integer total": got,
                        "Match": want == got}
                       for label, want, got in zip(CLASS_ORDER, expected_scores, actual_scores)],
            "prediction": CLASS_ORDER[got_class], "expected_prediction": CLASS_ORDER[want_class],
            "verdicts": verdicts, "all_match": all(verdicts.values()),
            "feature_report": feature}


def _render_instance(store, capture, model):
    directory = capture["evidence_directory"]
    paths = (f"{directory}/expected_n8_instances.jsonl",
             f"{directory}/expected_rf_{model}.jsonl",
             f"{directory}/RF_{model}/decisions.jsonl")
    children = [store.load_child("controlled_replay", path, format="jsonl") for path in paths]
    for child in children:
        if not child.verified:
            unavailable(child)
    if not all(child.verified for child in children):
        st.caption("Instance detail is withheld: every expected/actual child must match the parent seal.")
        return
    try:
        instances, expected, actual = [_index(child.data, path) for child, path in zip(children, paths)]
        if not instances:
            notice("No N8 instances", "This capture has no saved eight-packet instances to inspect.", "warning")
            return
        selected = st.selectbox(
            "Saved flow instance", list(instances), key="correctness-instance",
            format_func=lambda key: f"packet {instances[key]['packet_id']:,} / slot {instances[key]['slot']} / "
            + ("collision excluded" if instances[key]["collision_excluded"] else key[:18]))
        detail = decision_detail(instances[selected], expected.get(selected), actual.get(selected), model)
    except (KeyError, TypeError, ValueError) as error:
        notice("Saved instance schema cannot be interpreted", str(error), "error")
        return
    instance = detail["instance"]
    with st.expander("Instance identity and sealed child files", expanded=False):
        st.json({key: instance[key] for key in (
            "record_id", "instance_id", "parent_candidate_conversation_id", "packet_id", "slot",
            "collision_excluded")})
        for child in children:
            st.caption(str(child.path))
            st.code(child.sha256, language=None)
    if detail["state"] == "collision_excluded":
        notice("Collision-excluded N8 instance",
               "The reference instance reaches eight packets, but its hash slot is owned by another tuple. "
               "No RF decision is expected or fabricated. This is a state-capacity exclusion, not a classification error.", "warning")
        st.dataframe([{"Feature": key, "Python reference": value}
                      for key, value in instance["features_C"].items()], hide_index=True, width="stretch")
        return
    if detail["state"] == "missing_decision":
        notice("Decision evidence missing",
               f"Expected record present: {detail['expected_present']}; actual record present: {detail['actual_present']}. "
               "No parity verdict or prediction is substituted.", "error")
        return
    notice("Saved instance agreement" if detail["all_match"] else "Saved instance mismatch",
           "; ".join(f"{key}: {'PASS' if value else 'FAIL'}" for key, value in detail["verdicts"].items()),
           "success" if detail["all_match"] else "error")
    metric_row([
        dict(label=f"RF-{model} / P4 prediction", value=detail["prediction"],
             note=f"Python integer reference: {detail['expected_prediction']}", tone="teal"),
        dict(label="Eligible packet count", value=detail["feature_report"]["count"],
             note=f"Decision at original capture frame {instance['packet_id']:,}; this frame number need not equal 8."),
        dict(label="Controlled effective time", value=f"{detail['feature_report']['effective_us']:,} us",
             note="Injected capture-time reference, not measured native-clock forwarding delay."),
    ])
    tabs = st.tabs(["Eight feature values", "Ten tree leaves", "Six class-score totals"])
    with tabs[0]:
        st.dataframe(detail["features"], hide_index=True, width="stretch")
        st.caption("Actual values are decoded from P4 feature_report. Both deployed programs maintain "
                   "directional state; RF-B does not consume its two direction values as forest inputs.")
    with tabs[1]:
        st.dataframe(detail["leaves"], hide_index=True, width="stretch")
    with tabs[2]:
        st.dataframe(detail["scores"], hide_index=True, width="stretch")
        st.caption("Integer probability contributions summed over ten trees, scale 2^24 per tree. "
                   "These totals are not independent class counts or a measured inference duration.")


def render(store):
    hero("P4 / IMPLEMENTATION ASSURANCE", "Does the switch execute the reference?",
         "Inspect the sealed 29-capture controlled replay: eligibility, flow boundaries, packet-eight "
         "decisions, exact features, tree leaves, class-score sums and predictions.", "SAVED / CONTROLLED PARITY")
    notice("Parity is not classification accuracy",
           "This experiment compares the P4 implementation with Python's integer reference, not with verified activity labels. "
           "It uses BMv2 file-port replay and injected capture timestamps; it is not a live throughput or latency benchmark.", "warning")
    evidence = store.load("controlled_replay")
    if not evidence.verified:
        unavailable(evidence)
        return
    try:
        totals = replay_summary(evidence.data)
        rows = capture_quality_rows(evidence.data)
    except (KeyError, TypeError, ValueError) as error:
        notice("Saved correctness schema cannot be interpreted", str(error), "error")
        provenance(evidence)
        return
    all_mismatches = sum(totals["models"][m][key] for m in ("B", "C")
                         for key in PARITY_FIELDS + INTEGRITY_FIELDS)
    section_header("Controlled-replay result", "A checked packet is not necessarily eligible for feature extraction.")
    metric_row([
        dict(label="Real captures checked", value=f"{totals['captures']:,}",
             note=f"Saved run status: {evidence.data['status']}"),
        dict(label="Packets checked / model", value=f"{totals['models']['B']['packets_checked']:,}",
             note=f"{totals['eligible_packets']:,} reference-eligible packets, before hash-slot exclusions."),
        dict(label="Decisions / model", value=f"{totals['models']['B']['classifications']:,}",
             note=f"{totals['expected_n8_instances']:,} N8 instances; {totals['collision_excluded_n8_instances']} excluded by collisions."),
        dict(label="Saved mismatch counts / B + C", value=f"{all_mismatches:,}",
             note="Features, leaves, scores, class, eligibility, instance, bytes and decision IDs.",
             tone="teal" if all_mismatches == 0 else "warning"),
    ])
    st.dataframe([{
        "Model": "RF-" + model, "Checked packets": totals["models"][model]["packets_checked"],
        "Decisions": totals["models"][model]["classifications"],
        **{key.replace("_", " ").capitalize(): totals["models"][model][key]
           for key in PARITY_FIELDS + INTEGRITY_FIELDS},
    } for model in ("B", "C")], hide_index=True, width="stretch")
    provenance(evidence)

    section_header("Coverage is a separate question", "The frozen classifier makes one decision only after eight eligible packets.")
    classified = totals["models"]["B"]["classifications"]
    metric_row([
        dict(label="N8 decision coverage", value=f"{100*classified/totals['expected_n8_instances']:.2f}%",
             note=f"{classified:,} / {totals['expected_n8_instances']:,}, including collision exclusions in the denominator."),
        dict(label="All-instance classification coverage", value=f"{100*classified/totals['instances']:.2f}%",
             note=f"{classified:,} / {totals['instances']:,}; short flows are outside the N8 decision policy."),
        dict(label="Short instances / fewer than 8", value=f"{totals['short_instances']:,}",
             note="Unclassified by design, not prediction errors or a missing-report repair."),
    ])
    left, right = st.columns([1.35, 1], gap="large")
    with left:
        fig = go.Figure(go.Bar(
            x=["Admitted N8", "Collision-excluded N8", "Short instances"],
            y=[totals["expected_classifications"], totals["collision_excluded_n8_instances"], totals["short_instances"]],
            marker_color=["#2dd4bf", "#fbbf24", "#94a3b8"],
            text=[f"{n:,}" for n in (totals["expected_classifications"], totals["collision_excluded_n8_instances"], totals["short_instances"])],
            textposition="outside", hovertemplate="%{x}: %{y:,} instances<extra></extra>"))
        fig.update_yaxes(title="Saved flow instances")
        plot(fig, key="correctness-coverage", height=290)
    with right:
        notice("Hash-state accounting",
               f"{totals['collision_excluded_parents']} parent conversations collide; "
               f"{totals['collision_excluded_instances_all_lengths']} instances are affected across all lengths "
               f"({totals['collision_excluded_n8_instances']} N8 and {totals['collision_excluded_short_instances']} short). "
               f"{totals['collision_packets']:,} packets report collision exclusion. "
               "Short/collision categories overlap only for the short affected instances; do not add all-length collisions again.", "warning")
        st.caption("State collision is not a training-label error. This controlled run checks the whole "
                   "included dataset, not only the frozen held-out accuracy population.")

    section_header("Per-capture quality", "Every model/capture retains its saved eligibility, byte, decision and four-level parity counts.")
    filter_model = st.selectbox("Quality-table model", ["Both", "RF-B", "RF-C"], key="correctness-model-filter")
    st.dataframe([row for row in rows if filter_model == "Both" or row["Model"] == filter_model],
                 hide_index=True, width="stretch")
    st.caption("The file-port replay verifies one output report per input in sequence and checks "
               "the unchanged original IP bytes. These are controlled packet/report accounting results, "
               "not a native packet-loss or saturation measurement.")

    section_header("Inspect a real flow decision", "Only parent-sealed expected and actual records are read. No model is re-evaluated.")
    captures = evidence.data["captures"]
    capture_name = st.selectbox("Capture", [row["capture"] for row in captures], key="correctness-capture")
    model = st.radio("Deployed forest", ["B", "C"], horizontal=True,
                     format_func=lambda value: "RF-" + value, key="correctness-forest")
    selected = next(row for row in captures if row["capture"] == capture_name)
    _render_instance(store, selected, model)
    with st.expander("Scientific limits and interpretation", expanded=False):
        st.markdown("- Exact parity establishes implementation agreement, not correct activity recognition.\n"
                    "- Capture-time injection removes native replay jitter from this correctness comparison.\n"
                    "- The first-eight policy excludes short instances; collision exclusions remain visible.\n"
                    "- RF probabilities are aggregated in fixed point; this is not hard majority voting.\n"
                    "- Native timing, held-out accuracy and normal-build performance have separate evidence pages.\n"
                    "- No ASIC feasibility, maximum throughput, forwarding-delay or isolated RF-latency claim follows.")
