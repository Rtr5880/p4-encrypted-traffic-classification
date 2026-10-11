"""Saved, pinned research evidence. No fitting or packet processing."""
import plotly.graph_objects as go
import streamlit as st
from dashboard.components import (
    MODEL_COLORS, hero, section_header, metric_card, metric_row,
    notice, provenance, plot, pipeline, unavailable,
)

def model_metadata(data):
    """Structural model metadata only; never re-evaluate a classifier."""
    trees = data["trees"]
    return {
        "trees": len(trees),
        "depth": data["parameters"]["max_depth"],
        "leaves": sum(n["kind"] == "leaf" for t in trees for n in t["nodes"]),
        "nodes": sum(len(t["nodes"]) for t in trees),
        "features": data["feature_order"],
        "score_scale": data["score_scale"],
    }

def replay_totals(data):
    """Add saved per-capture accounting; do not recompute parity or accuracy."""
    captures = data["captures"]
    result = {"captures":data["captures_checked"], "expected":0, "excluded":0}
    for field in ("expected_n8_instances", "collision_excluded_n8_instances"):
        result["expected" if field.startswith("expected") else "excluded"] = sum(
            row["preparation"][field] for row in captures)
    for model in ("B","C"):
        result[model] = {
            "decisions":sum(row["models"][model]["classifications"] for row in captures),
            "packets":sum(row["models"][model]["packets_checked"] for row in captures),
            "mismatches":sum(row["models"][model][field] for row in captures for field in (
                "feature_mismatches","leaf_mismatches","score_mismatches","class_mismatches")),
        }
    return result

def render(store):
    hero("EEE4022 / RESEARCH CONSOLE", "Encrypted traffic. In-switch intelligence.",
         "Early-flow classification of encrypted multimedia traffic using P4, BMv2 "
         "and compact Random Forests. One evidence-backed view of the models, "
         "implementation and runtime characterization.", "FROZEN EVIDENCE / LIVE DEMOS")
    notice("Research question",
           "What measurable classification information does packet direction add "
           "to early packet-size and inter-arrival-time features, and can the "
           "selected compact forests execute faithfully inside BMv2?", "info")
    native = store.load("native_metrics")
    section_header("Held-out classification", "Paired N=8 evaluation. Saved metrics, not a new model fit.")
    if native.verified:
        data = native.data
        basis = st.selectbox("Evaluation timing", [
            "Capture-time features", "Actual native ingress-time features"],
            help="Native timing changed some feature values. Neither choice measures forwarding latency.")
        capture_time = basis.startswith("Capture")
        metrics = (
            data["common_paired_population"]["capture_time_metrics_on_same_records"]
            if capture_time else data["common_paired_population"]["native_metrics"]
        )
        b,c = metrics["B"],metrics["C"]
        metric_row([
            dict(label="RF-B / Accuracy", value=f'{b["accuracy"]*100:.2f}%',
                 note=f'{b["records"]} held-out instances; six provisional classes', tone="blue"),
            dict(label="RF-C / Accuracy", value=f'{c["accuracy"]*100:.2f}%',
                 note=f'{c["records"]} held-out instances; direction-aware inputs', tone="teal"),
            dict(label="RF-B / Macro-F1", value=f'{b["macro_f1"]*100:.2f}%',
                 note="Equal-weight class F1; not the percentage correctly classified", tone="blue"),
            dict(label="RF-C / Macro-F1", value=f'{c["macro_f1"]*100:.2f}%',
                 note="Same evaluation population; frozen deployed model", tone="teal"),
        ])
        left,right = st.columns([1.6,1],gap="large")
        with left:
            fig=go.Figure()
            labels=["Accuracy","Macro-F1","Macro precision","Macro recall"]
            keys=["accuracy","macro_f1","macro_precision","macro_recall"]
            for model in ("B","C"):
                fig.add_bar(name=f"RF-{model}",x=labels,y=[100*metrics[model][k] for k in keys],
                            marker_color=MODEL_COLORS[model],
                            hovertemplate="%{x}: %{y:.2f}%<extra>%{fullData.name}</extra>")
            fig.update_layout(barmode="group")
            fig.update_yaxes(title="Saved score (%)",range=[0,100])
            plot(fig,key="overview-classification",height=310)
        with right:
            with st.container(border=True):
                st.markdown("#### Direction-aware comparison")
                st.metric("C minus B / Macro-F1",
                          f'{100*(c["macro_f1"]-b["macro_f1"]):+.2f} pp',
                          help="Percentage-point arithmetic on saved metrics; not a confidence interval.")
                st.metric("C minus B / Accuracy",
                          f'{100*(c["accuracy"]-b["accuracy"]):+.2f} pp')
                st.caption("Matched 10-tree, depth-7 configurations. "
                           + ("Same capture-time feature population." if capture_time else
                              "Actual arrivals differed between native B and C runs; not a pure direction ablation."))
        provenance(native)
    else:
        unavailable(native)

    section_header("Inside the programmable switch",
                   "No payload decryption. Classification is triggered by the eighth eligible packet.")
    pipeline()
    st.caption("Size means IPv4 ip.len, not Ethernet frame length. IAT statistics use seven "
               "gaps in microseconds. Direction is relative to the first observed sender.")
    section_header("Two feature configurations. One shared extractor.",
                   "Both deployed P4 variants maintain direction state; B simply does not use it as a forest input.")
    for model,col in zip(("B","C"),st.columns(2,gap="large")):
        with col:
            evidence=store.load(f"rf_{model.lower()}")
            with st.container(border=True):
                st.markdown(f"### RF-{model}")
                st.caption("SIZE + TIMING" if model=="B" else "SIZE + TIMING + DIRECTION")
                if evidence.verified:
                    meta=model_metadata(evidence.data)
                    st.markdown(f'**{meta["trees"]} trees** / maximum depth **{meta["depth"]}** / '
                                f'**{meta["leaves"]:,} leaves**')
                    st.caption(f'{meta["nodes"]:,} nodes; fixed-point class probability aggregation, scale 2^24.')
                    st.markdown("Size: minimum, maximum, sum  \nIAT: minimum, maximum, sum")
                    if model=="C":
                        st.markdown("Direction: reverse-packet count, direction-change count")
                    st.caption("Average class probabilities, not hard majority voting. Lowest class index wins ties.")
                    provenance(evidence)
                else:
                    unavailable(evidence)

    section_header("Implementation assurance",
                   "Correctness evidence answers whether P4 executes the reference, not whether an activity label is correct.")
    replay=store.load("controlled_replay")
    if replay.verified:
        totals=replay_totals(replay.data)
        metric_row([
            dict(label="Controlled real captures",value=f'{totals["captures"]}',
                 note=f'{totals["B"]["packets"]:,} packets checked per model'),
            dict(label="Verified decisions / model",value=f'{totals["B"]["decisions"]:,}',
                 note=f'{totals["expected"]:,} N=8 instances; {totals["excluded"]} collision exclusions'),
            dict(label="Four-level mismatches",value=f'{totals["B"]["mismatches"]+totals["C"]["mismatches"]:,}',
                 note="Saved feature, leaf, score and class checks across B and C",tone="teal"),
        ])
        provenance(replay)
    else:
        unavailable(replay)

    section_header("Interpretation boundaries", "The interface never promotes an unsupported result to a qualified claim.")
    l,r=st.columns(2,gap="large")
    with l:
        notice("Classification scope",
               "Six capture-derived activity hints, not independently verified per-flow truth. "
               "Parent-conversation-disjoint is not fully capture/session-disjoint. "
               "BROWSING is absent; STREAMING does not separately establish music-versus-video recognition.", "warning")
    with r:
        notice("Runtime scope",
               "The 16-trial RAW calibration and 160-trial repeated campaign are separate experiments. "
               "Repeated-campaign absolute rates and CPU percentages remain unqualified. "
               "Forwarding-delay percentiles, isolated RF latency and maximum capacity are not established.", "warning")
    st.caption("One-shot N=8 policy leaves short instances unclassified. All displayed research results "
               "come from explicitly pinned saved evidence. No experiment is started by this application.")
    section_header("Explore the research", "Each page answers a different question; no result is promoted across experiment types.")
    destinations = [
        ("Classification", "/classification", "How well do the frozen models classify the held-out activity hints?"),
        ("P4 Correctness", "/correctness", "Does the switch faithfully execute the feature and forest references?"),
        ("Native Clock Evaluation", "/native-clock", "What changes when packets arrive with actual BMv2 ingress timing?"),
        ("Performance Evaluation", "/performance", "Which packet, resource and timing observations are supported?"),
        ("Live Experiment Monitor", "/live", "Observe a separately authorized synthetic or real-PCAP demonstration."),
        ("Experiment History", "/history", "Inspect successful, failed and incomplete evidence without selecting a new headline."),
    ]
    for col, items in zip(st.columns(2, gap="large"), (destinations[:3], destinations[3:])):
        with col:
            for title, url, description in items:
                st.markdown(f"**[{title}]({url})** — {description}")
