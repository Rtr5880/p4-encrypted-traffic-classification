"""Read-only real-PCAP classification and paired frozen RF presentation."""
from __future__ import annotations

import math
import os
from html import escape
from pathlib import Path
import sys
import streamlit as st
import plotly.graph_objects as go
from dashboard.components import (
    metric_card, metric_row, notice, empty_panel, pill, plot, section_header, MODEL_COLORS,
)
from dashboard.live_evidence import read_live
from dashboard.views.live import resource_point, observation_figure
from dashboard.live_presentation import install_live_style, render_journey

CLASSES = ("CHAT", "FT", "MAIL", "P2P", "STREAMING", "VOIP")
B_FEATURES = ("size_min","size_max","size_sum","iat_min","iat_max","iat_sum")
C_FEATURES = B_FEATURES + ("reverse_packet_count","direction_change_count")
RF_SCORE_MAX = 10 * 2**24
TOOLS = Path(__file__).resolve().parents[2] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0,str(TOOLS))


def number(value, digits=0):
    if type(value) not in (int,float) or not math.isfinite(value):
        return "Not available"
    return f"{value:,.{digits}f}"


def is_pcap(evidence):
    return bool(evidence.snapshot and
                evidence.snapshot.get("metadata",{}).get("demo_kind") == "pcap")


@st.cache_data(show_spinner=False)
def _catalogue(project_root, manifest_ns, population_ns):
    from pcap_demo_examples import list_examples
    return list_examples(Path(project_root))


def catalogue():
    repo = Path(os.environ.get("ETC_PROJECT_ROOT",Path(__file__).resolve().parents[2]))
    directory = repo / "results/native_evaluation_preparation/20261007T182217Z_a93176dc1f"
    keys = [(directory/name).stat().st_mtime_ns for name in ("manifest.json","population.json")]
    return _catalogue(str(repo),*keys)


def result_issues(result, model):
    """Intermediate arrays must be present and model/class identities explicit."""
    errors=[]
    if not isinstance(result,dict):
        return ["Result is unavailable"]
    if result.get("feature_set") != model:
        errors.append("Wrong model identity")
    if result.get("class_order") != list(CLASSES):
        errors.append("Class mapping differs from frozen six-class order")
    leaves,scores=result.get("leaf_ids"),result.get("scores")
    if not isinstance(leaves,list) or len(leaves)!=10 or any(type(v)is not int or v<0 for v in leaves):
        errors.append("Ten actual leaf IDs are unavailable or invalid")
    if not isinstance(scores,list) or len(scores)!=6 or any(type(v)is not int or v<0 or v>RF_SCORE_MAX for v in scores):
        errors.append("Six actual integer class-score totals are unavailable or invalid")
    if result.get("p4_prediction") not in CLASSES or result.get("python_prediction") not in CLASSES:
        errors.append("Recorded P4/Python predictions are missing or invalid")
    features=result.get("features_used")
    names=B_FEATURES if model=="B" else C_FEATURES
    if not isinstance(features,dict) or set(features)!=set(names):
        errors.append("Extracted model feature vector is incomplete")
    elif any(type(value) is not int or value < 0 for value in features.values()):
        errors.append("Feature values must be actual nonnegative integer measurements")
    if isinstance(scores,list) and len(scores)==6 and all(type(v)is int and v>=0 for v in scores):
        expected_class=CLASSES[max(range(6),key=lambda index:scores[index])]
        if result.get("p4_prediction") != expected_class:
            errors.append("Prediction does not match lowest-index argmax of recorded scores")
    return errors


def score_figure(result,model):
    fig=go.Figure(go.Bar(y=list(CLASSES),x=result["scores"],orientation="h",
        marker_color=[MODEL_COLORS[model] if name==result["p4_prediction"] else "#263c59" for name in CLASSES],
        hovertemplate="%{y}<br>Accumulated fixed-point score: %{x:,.0f}<extra>RF-"+model+"</extra>"))
    fig.update_layout(xaxis_title="Sum of ten leaf class scores (fixed point)",showlegend=False)
    # Both frozen forests contain ten Q24 trees. Keep raw evidence unchanged
    # and use one common scale rather than independently autoscaling the pair.
    fig.update_xaxes(range=[0,RF_SCORE_MAX],tickformat="~s",fixedrange=False)
    fig.update_yaxes(autorange="reversed",gridcolor="rgba(0,0,0,0)")
    return fig


def parity_status(result,model):
    """A completed acquisition or a named status is not itself parity PASS."""
    if not isinstance(result,dict) or not result or result.get("status")=="collecting":
        return "PENDING"
    values=[(result.get("parity") or {}).get(key)
            for key in ("feature","leaf","score","prediction")]
    if any(value is False for value in values):
        return "FAIL"
    if result.get("status")=="classified_unverified":
        return "PENDING"
    if result_issues(result,model):
        return "INCOMPLETE"
    return "PASS" if all(value is True for value in values) else "PENDING"


def pcap_journey(results,progress,monitoring,models,evidence_status):
    """Show only stages supported by recorded model observations/results."""
    active=evidence_status not in ("completed","failed","interrupted","cancelled","stale","corrupt")
    steps=[]
    for model in models:
        result=results.get(model) or {}
        observed=count((progress.get(model) or {}).get("eligible_packets"))
        observed=observed if observed is not None and observed<=8 else None
        complete=bool(result and result.get("status") not in ("collecting","classified_unverified")
                      and not result_issues(result,model))
        decision=complete or result.get("status")=="classified_unverified"
        row=monitoring.get(model) or {}
        started=bool(observed is not None or result or row.get("phase"))
        prefix_state="observed" if decision or observed==8 else "active" if active and started else "pending"
        prefix_detail=(f"{observed}/8 switch-reported" if observed is not None else
                       "Packet-eight report recorded" if decision else "No packet count assumed")
        verdict=parity_status(result,model)
        verify_state=("observed" if verdict=="PASS" else "failed" if verdict=="FAIL" else
                      "warning" if verdict=="INCOMPLETE" else "active" if active and decision else "pending")
        steps.extend([
            {"label":"RF-"+model+" · collect","state":prefix_state,"detail":prefix_detail},
            {"label":"RF-"+model+" · decision","state":"observed" if decision else
             "active" if active and observed==8 else "pending",
             "detail":"Actual packet-eight event" if decision else "Waiting for a recorded event"},
            {"label":"RF-"+model+" · parity","state":verify_state,
             "detail":"Features · leaves · scores · class: "+verdict},
        ])
    return steps


def packet_strip_rows(source):
    """Eight source positions, not eight fabricated switch observations."""
    saved={}
    for entry in source.get("packet_summary") or []:
        if not isinstance(entry,dict):
            continue
        position=entry.get("position")
        if type(position)is int and 1<=position<=8 and position not in saved:
            saved[position]=entry
    frames=source.get("original_frames") or []
    rows=[]
    for position in range(1,9):
        entry=saved.get(position,{})
        direction=entry.get("direction")
        if type(direction)is bool:
            direction=None
        direction="F" if direction in ("F","forward",0) else "R" if direction in ("R","reverse",1) else None
        frame=entry.get("original_frame",frames[position-1] if len(frames)>=position else None)
        size=count(entry.get("ip_size_bytes"))
        rows.append({"position":position,"original_frame":count(frame),"ip_size_bytes":size,
                     "direction":direction,"capture_offset_us":count(entry.get("capture_offset_us")),
                     "trigger":position==8})
    return rows


def _packet_strip(source,progress,results,models):
    st.markdown("#### The eight-packet observation window")
    st.caption("Source packet metadata, not an animated arrival timeline. F = first eligible sender; R = peer. "
               "Packet 8 is the inference trigger for an admitted instance.")
    st.markdown("""<style>
      .etc-live-packet-strip{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:8px;margin:12px 0}
      .etc-live-packet{background:#111d30;border:1px solid #293d56;border-radius:10px;padding:12px 8px;min-width:0;text-align:center}
      .etc-live-packet.trigger{border-color:#2dd4bf;background:#102b31}
      .etc-live-packet strong{display:block;color:#e8eef8;font-size:15px;margin-bottom:6px}
      .etc-live-packet span{display:block;color:#acbfd3;font-size:12px;overflow-wrap:anywhere;margin-top:4px}
      .etc-live-packet .etc-live-trigger{color:#5eead4;font-weight:600}
      @media(max-width:1050px){.etc-live-packet-strip{grid-template-columns:repeat(4,minmax(0,1fr))}}
      @media(max-width:420px){.etc-live-packet-strip{grid-template-columns:repeat(2,minmax(0,1fr))}}
    </style>""",unsafe_allow_html=True)
    cards=[]
    for row in packet_strip_rows(source):
        direction=row["direction"] or "Direction unavailable"
        size=(number(row["ip_size_bytes"])+" IP bytes" if row["ip_size_bytes"] is not None else "Size unavailable")
        frame=("Frame "+number(row["original_frame"]) if row["original_frame"] is not None else "Frame unavailable")
        cards.append('<div class="etc-live-packet'+(' trigger' if row["trigger"] else '')+'">'
                     '<strong>Packet '+str(row["position"])+"</strong><span>"+escape(direction)+"</span><span>"+
                     escape(size)+"</span><span>"+escape(frame)+"</span>"+
                     ('<span class="etc-live-trigger">Inference trigger</span>' if row["trigger"] else '')+'</div>')
    st.markdown('<div class="etc-live-packet-strip">'+''.join(cards)+'</div>',unsafe_allow_html=True)
    observations=[]
    for model in models:
        observed=count((progress.get(model) or {}).get("eligible_packets"))
        if observed is not None and observed<=8:
            observations.append(f"RF-{model}: {observed}/8 switch-reported eligible packets")
        elif results.get(model) and results[model].get("status")=="classified_unverified":
            observations.append("RF-"+model+": decision observed; verification pending")
        elif results.get(model) and not result_issues(results[model],model):
            observations.append("RF-"+model+": packet-eight decision recorded")
        else:
            observations.append("RF-"+model+": switch progress not yet available")
    st.caption("Observed progress — "+" · ".join(observations))


def _outcome_summary(source,results,models):
    """Compact interpretation first; no whole-run or semantic accuracy PASS."""
    lines=[]
    for model in models:
        result=results.get(model)
        if result and result.get("status")=="classified_unverified":
            lines.append("RF-"+model+": decision observed / verification pending")
        elif result and not result_issues(result,model):
            lines.append("RF-"+model+": "+result["p4_prediction"]+" / Python-P4 parity "+parity_status(result,model))
        elif result and result.get("status")!="collecting":
            lines.append("RF-"+model+": intermediate evidence incomplete")
        else:
            lines.append("RF-"+model+": awaiting a recorded prediction")
    if models=="BC":
        title,interpretation=comparison_interpretation(results)
    else:
        title="Recorded classification outcome"
        interpretation="The prediction is the deployed forest's activity class, not a verified application identity."
    notice(title," | ".join(lines)+" "+interpretation,"info")
    st.caption("Source activity hint: "+str(source.get("capture_activity_hint",source.get("label","Unavailable")))+
               ". Hint agreement is not independently verified per-flow accuracy.")
    if models=="BC":
        st.caption("RF-B and RF-C execute sequentially. The source bytes are the same; actual native IATs may differ. "
                   "A live prediction difference is not a direction-only ablation.")


def _classification_reading_help():
    with st.expander("How to read predictions, score bars and parity"):
        st.markdown("- **Score bars:** classes are on the vertical axis; the horizontal axis is the sum of ten actual Q24 leaf scores. "
                    "Both models use the same 0–167,772,160 scale. The highest total determines the prediction; equal totals choose the lowest class index.\n"
                    "- **Scores are not calibrated confidence:** these are integer model outputs, not a percentage chance that the activity label is correct.\n"
                    "- **Four parity checks:** features, tree leaves, score sums and predicted class are compared with Python using each model's observed timing. "
                    "PASS means implementation agreement on this example, not classification accuracy.\n"
                    "- **Model inputs:** RF-B uses six size/IAT statistics. RF-C adds reverse-packet and direction-change counts; both P4 builds already maintain directional state.")


def feature_comparison(results):
    rows=[]
    for name in C_FEATURES:
        rows.append({"Feature":name,"RF-B native":results.get("B",{}).get("features_used",{}).get(name),
                     "RF-C native":results.get("C",{}).get("features_used",{}).get(name),
                     "Role":"C-only model input" if name not in B_FEATURES else "Shared model input",
                     "Unit":"microseconds" if name.startswith("iat_") else "IPv4 bytes" if name.startswith("size_") else "count"})
    return rows


def timing_rows(results,source):
    original=source.get("relative_us",[])
    original_gaps=[b-a for a,b in zip(original,original[1:])] if len(original)==8 else source.get("capture_iats_us",[])
    rows=[]
    for index in range(7):
        row={"Gap":index+1,"Source capture (us)":original_gaps[index] if len(original_gaps)==7 else None}
        for model in "BC":
            gaps=results.get(model,{}).get("native_iats_us",[])
            row["RF-"+model+" native (us)"]=gaps[index] if len(gaps)==7 else None
        if row["RF-B native (us)"] is not None and row["RF-C native (us)"] is not None:
            row["C minus B (us)"]=row["RF-C native (us)"]-row["RF-B native (us)"]
        rows.append(row)
    return rows


def comparison_interpretation(results):
    b,c=results.get("B"),results.get("C")
    if not b or not c or result_issues(b,"B") or result_issues(c,"C"):
        return "Pair incomplete","Wait for both actual model runs; no missing prediction is inferred."
    agreement=b["p4_prediction"]==c["p4_prediction"]
    iat_equal=all(b["features_used"][name]==c["features_used"][name] for name in B_FEATURES if name.startswith("iat_"))
    message=("Both frozen classifiers predicted "+b["p4_prediction"]+"." if agreement else
             "RF-B predicted "+b["p4_prediction"]+"; RF-C predicted "+c["p4_prediction"]+".")
    if not iat_equal:
        message+=" Their native IAT feature values differ. This is not a direction-only ablation."
    else:
        message+=" Shared IAT summary values match on this example; that does not establish identical packet-arrival timing or a general direction effect."
    return "Models agree" if agreement else "Models disagree",message


def count(value):
    """Unknown is not zero; packet counters must be nonnegative integers."""
    return value if type(value)is int and value>=0 else None


def monitoring_counts(row,progress):
    traffic=row.get("traffic") or {}
    final=row.get("completed_accounting") or {}
    return {
        "sent":count(final.get("sent_packets")),
        "input":count(final.get("input_observed",traffic.get("input_observed",progress.get("input_observed")))),
        "output":count(final.get("output_observed",traffic.get("output_observed",progress.get("output_observed")))),
        "pending":count(traffic.get("pending_output")),
        "decisions":count(final.get("decisions")) if final.get("counters_verified") is True else None,
        "expected_decisions":count(final.get("expected_decisions")),
    }


def resource_rows(row):
    """Reuse Stage 2 chart shapes with actual sample times, never heartbeat time."""
    entries=row.get("resource_samples") or []
    raw_times=[entry.get("raw_ns") for entry in entries
               if isinstance(entry,dict) and type(entry.get("raw_ns"))is int and entry["raw_ns"]>0]
    raw_times.extend(current["sample_raw_ns"] for entry in entries if isinstance(entry,dict)
                     for current in (entry.get("resources") or {}).values()
                     if isinstance(current,dict) and type(current.get("sample_raw_ns"))is int and current["sample_raw_ns"]>0)
    if not raw_times:
        return []
    origin=min(raw_times)
    rows=[]
    for entry in entries:
        if not isinstance(entry,dict):
            continue
        raw=entry.get("raw_ns")
        if type(raw)is not int or raw<origin:
            continue
        point={"seconds":(raw-origin)/1e9,"trial":row.get("model","unknown"),
               "phase":entry.get("phase","unknown"),"input":None,"output":None}
        for role in ("bmv2","runner"):
            current=(entry.get("resources") or {}).get(role) or {}
            cpu,rss=resource_point(entry,role)
            aggregate=(row.get("resources") or {}).get(role) or {}
            if current.get("valid") is False or aggregate.get("valid") is False:
                cpu=rss=None
            # A CPU delta spanning different phases is not phase-specific CPU.
            interval_phase=current.get("cpu_interval_phase")
            if interval_phase=="mixed" or (interval_phase and interval_phase!=point["phase"]):
                cpu=None
            stamp=current.get("sample_raw_ns")
            if type(stamp)is not int or stamp<origin:
                cpu=rss=None
                seconds=None
            else:
                seconds=(stamp-origin)/1e9
            point.update({role+"_cpu":cpu,role+"_rss":rss,role+"_seconds":seconds})
        rows.append(point)
    return rows


def resource_figure(row,kind):
    """At least two real, distinct observations per role AND phase; markers only."""
    rows=resource_rows(row)
    suffix="cpu" if kind=="cpu" else "rss"
    for role in ("bmv2","runner"):
        field=role+"_"+suffix
        groups={}
        for point in rows:
            if point[field] is not None and point[role+"_seconds"] is not None:
                groups.setdefault(point["phase"],set()).add(point[role+"_seconds"])
        for point in rows:
            if len(groups.get(point["phase"],()))<2:
                point[field]=None
    figure=observation_figure(rows,kind)
    if not figure.data:
        return None
    figure.update_traces(mode="markers",connectgaps=False)
    figure.update_layout(xaxis_title="RAW seconds since first resource observation",
                        yaxis_title="OS-accounted CPU (% of one core), provisional" if kind=="cpu" else "Sampled RSS (MiB)")
    return figure


def monitoring_health(row,result):
    final=row.get("completed_accounting") or {}
    transport=final.get("transport_passed")
    counters=final.get("counters_verified")
    clock=(result or {}).get("clock_quality") or {}
    return {
        "Tagged packet accounting":"PASS" if transport is True else "FAIL" if transport is False else "PENDING",
        "Decision counters":"PASS" if counters is True else "FAIL" if counters is False else "PENDING",
        "Native ingress sequence":"CLEAN" if clock.get("clean") is True else
                                  "WARNING" if clock.get("clean") is False else "PENDING",
        "Resource observations":"WARNING" if row.get("monitoring_errors") else
                                 "AVAILABLE" if row.get("resources") else "NOT AVAILABLE",
    }


def _monitoring(row,model,progress,result):
    st.markdown("#### Traffic & resources / RF-"+model)
    st.caption("Live observations - not benchmark-qualified. Sequential model runs remain separate.")
    st.caption("Model phase: "+str(row.get("phase","not yet started")))
    values=monitoring_counts(row,progress)
    metric_row([
        dict(label="Input observed",value=number(values["input"]),note="Actual tagged input matches"),
        dict(label="Output observed",value=number(values["output"]),note="Actual tagged output matches"),
        dict(label="RF decisions",value=number(values["decisions"]),note="Verified boundary counters; expected one"),
    ])
    final=row.get("completed_accounting") or {}
    st.caption("Final sender count: "+number(values["sent"])+" / pending output observations: "+
               number(values["pending"])+". Pending is not confirmed packet loss.")
    for column,role,label in zip(st.columns(2),("bmv2","runner"),("BMv2","Runner")):
        with column:
            current=(row.get("resources") or {}).get(role) or {}
            cpu,rss=resource_point({"resources":{role:current}},role)
            window_cpu=current.get("window_cpu_percent_one_core")
            window_available=type(window_cpu) in (int,float) and math.isfinite(window_cpu) and window_cpu>=0
            if window_available:
                cpu=window_cpu
            if current.get("valid") is False:
                cpu=rss=None
            st.metric(label+" CPU",number(cpu,1)+("%" if cpu is not None else ""))
            st.metric(label+" RSS",number(rss,1)+(" MiB" if rss is not None else ""))
            st.caption("CPU scope: "+("whole replay/capture window" if window_available else
                                     "last observed interval / "+str(current.get("cpu_window_label","not available"))))
    st.caption(row.get("window_label") or "Resource window not yet recorded. Missing values are unavailable, not zero.")
    st.caption("CPU is OS-accounted / RAW elapsed, 100% = one core; short windows can be tick-quantized. "
               "This includes replay/capture work and idle drain, not isolated RF inference or direction-extraction overhead.")
    st.markdown("##### Experiment health")
    st.dataframe([{"Check":key,"Observation":value} for key,value in monitoring_health(row,result).items()],
                 hide_index=True,width="stretch")
    with st.expander("What these PCAP health observations mean"):
        st.markdown("- **Packet accounting / counters PASS:** the recorded transport or decision-counter check succeeded; neither is a semantic accuracy score.\n"
                    "- **PENDING:** the required final observation has not been recorded. Missing evidence is not a passing or zero-valued result.\n"
                    "- **Native ingress CLEAN:** the saved ingress sequence check was clean; this is not independent clock-rate qualification.\n"
                    "- **WARNING / FAIL:** inspect the preserved reasons below. Resource warnings do not automatically negate a separately verified classifier result.\n"
                    "- **Resource graphs:** horizontal position is RAW elapsed seconds from the first resource observation; CPU is OS-accounted percent of one core and RSS is MiB. "
                    "Only sufficiently sampled actual phases are plotted. This is not isolated RF inference overhead.")
    if row.get("monitoring_errors"):
        notice("Preserved monitoring warnings"," | ".join(map(str,row["monitoring_errors"])),"warning")
    if final.get("errors"):
        notice("Preserved packet-accounting errors"," | ".join(map(str,final["errors"])),"warning")
    missing=final.get("missing_output_indices")
    if isinstance(missing,list):
        st.caption(f"Missing output observations after drain: {len(missing)}. A missing observation alone does not identify BMv2 as the cause.")
    st.caption("Capture socket-drop statistics: not available from this native replay transport. "
               "Clean ingress sequencing is not independent clock-rate qualification. Forwarding/inference latency remains unqualified.")
    figures={kind:resource_figure(row,kind) for kind in ("cpu","memory")}
    with st.expander("Resource observations / sufficient-sample charts",expanded=False):
        if not any(figures.values()):
            st.caption("No resource time-series graph: fewer than two distinct usable observations in a common phase. "
                       "No values are padded, interpolated or carried across RF-B/RF-C.")
        for kind,figure in figures.items():
            if figure is not None:
                for trace in figure.data:
                    if trace.name.startswith("BMv2"):
                        trace.update(marker=dict(color=MODEL_COLORS[model]))
                plot(figure,key="pcap_resource_"+model+"_"+kind,height=230)
        if row.get("resource_samples"):
            st.caption(f"Recorded compact resource samples: {len(row['resource_samples'])}. Full sampler reports remain in the saved evidence.")


def _selection():
    section_header("Choose your next terminal demonstration","These read-only controls generate a command; they never launch BMv2.")
    try:
        examples=catalogue()
    except (OSError,ValueError,KeyError,RuntimeError) as error:
        notice("Example catalogue unavailable",str(error)+". No substitute examples are invented.","error")
        return
    if not examples:
        notice("No eligible examples","The bounded catalogue has no verified entries.","warning")
        return
    labels={row["slug"]:row for row in examples}
    left,right=st.columns([2,1])
    with left:
        default=list(labels).index("voip") if "voip" in labels else 0
        chosen=st.selectbox("Capture / frozen flow example",list(labels),index=default,
            format_func=lambda slug:labels[slug]["capture_activity_hint"]+" / "+labels[slug]["capture_name"],
            key="pcap_example_selection")
    with right:
        mode=st.selectbox("Classifier selection",["compare","rf_b","rf_c"],
            format_func=lambda value:{"compare":"Compare RF-B versus RF-C","rf_b":"RF-B only","rf_c":"RF-C only"}[value],
            key="pcap_model_selection")
    row=labels[chosen]
    st.code("cd /home/geleza/p4/etc-training\nmake dashboard-live DEMO=pcap MODE="+mode+" EXAMPLE="+chosen,language="bash")
    st.caption(f"Selected source example: {row['record_id']} / eight packets / original span {number(row.get('duration_us'),0)} us. "
               "Original capture bytes are reverified during preparation. Selection is not based on predicted class.")


def _source(source):
    with st.container(border=True):
        left,right=st.columns([2,1])
        with left:
            st.markdown("#### "+str(source.get("capture_name",source.get("capture_id","Selected capture"))))
            st.caption("Capture ID: "+str(source.get("capture_id","Not available")))
            st.caption("Frozen flow / instance: "+str(source.get("record_id","Not available")))
        with right:
            st.markdown(pill("Capture hint: "+str(source.get("capture_activity_hint",source.get("label","Unavailable"))),"neutral")+
                        pill("Native ingress timing","info"),unsafe_allow_html=True)
            st.caption("Capture-derived activity hint, not independently verified per-flow ground truth.")
    with st.expander("The same selected eight source packets and flow identity",expanded=False):
        rows=source.get("packet_summary",[])
        if rows:
            st.dataframe(rows,width="stretch",hide_index=True)
        else:
            frames=source.get("original_frames",[])
            st.dataframe([{"Position":i+1,"Original frame":frame} for i,frame in enumerate(frames)],width="stretch",hide_index=True)
        st.caption("Bidirectional source key: "+str(source.get("wire_key","Unavailable")))
        st.caption("Each model receives the same source IP bytes, Ethernet wrapping and original within-prefix offsets. "
                   "Replay is not a new capture of live multimedia activity. Dataset/capture association does not independently "
                   "establish encryption or multimedia payload for every selected flow.")
        if source.get("capture_sha256"):
            st.caption("Original capture SHA-256: "+source["capture_sha256"])


def _model(result,model,progress):
    st.markdown("### RF-"+model)
    st.markdown(pill("Size + IAT" if model=="B" else "Size + IAT + direction",
                    "info" if model=="B" else "success"),unsafe_allow_html=True)
    if not result or result.get("status") in ("collecting","classified_unverified"):
        observed=progress.get(model,{}).get("eligible_packets")
        if type(observed)is int and 0<=observed<=8:
            st.progress(observed/8,text=f"{observed}/8 switch-reported eligible packets")
        else:
            st.caption("Packet progress not yet available; no switch count is assumed.")
        pending=bool(result and result.get("status")=="classified_unverified")
        empty_panel("Packet-eight classification observed" if pending else "Waiting for packet-eight classification",
                    "Python verification is pending at the flow boundary." if pending else
                    "No prediction, tree leaf or score is invented before an actual result is available.")
        return
    issues=result_issues(result,model)
    if issues:
        notice("Intermediate evidence incomplete"," | ".join(issues),"warning")
        return
    st.progress(1.,text="8/8 observed / packet-eight inference recorded")
    metric_card("P4 prediction",result["p4_prediction"],"Actual frozen forest output; not a semantic accuracy claim",tone="blue" if model=="B" else "teal")
    parity=result.get("parity",{})
    verdicts={key:parity.get(key) for key in ("feature","leaf","score","prediction")}
    passed=all(value is True for value in verdicts.values())
    st.markdown(pill("Python / P4 parity PASS" if passed else "Parity incomplete or failed","success" if passed else "warning"),
                unsafe_allow_html=True)
    st.markdown("".join(pill(label+" "+("PASS" if verdicts[key] is True else "FAIL" if verdicts[key] is False else "PENDING"),
                              "success" if verdicts[key] is True else "error" if verdicts[key] is False else "warning")
                         for key,label in (("feature","Features"),("leaf","Leaves"),("score","Scores"),("prediction","Class"))),
                unsafe_allow_html=True)
    st.caption("Python reference on this run's observed timing: "+result["python_prediction"])
    plot(score_figure(result,model),key="pcap_scores_"+model,height=290)
    with st.expander("Feature vector / ten tree leaves / parity details"):
        st.dataframe([{"Feature":name,"Actual value":result["features_used"][name],
                       "Unit":"us" if name.startswith("iat_") else "IPv4 bytes" if name.startswith("size_") else "count"}
                      for name in (B_FEATURES if model=="B" else C_FEATURES)],hide_index=True,width="stretch")
        expected=result.get("python_leaf_ids",[])
        st.dataframe([{"Tree":i+1,"P4 leaf ID":leaf,"Python leaf ID":expected[i] if len(expected)==10 else None}
                      for i,leaf in enumerate(result["leaf_ids"])],hide_index=True,width="stretch")
        st.caption("Recorded parity: "+", ".join(f"{key}={value}" for key,value in verdicts.items()))
        if result.get("decision_counters") is not None:
            st.caption("Boundary RF decision counters:")
            st.dataframe([{"Class":name,**value} for name,value in zip(CLASSES,result["decision_counters"])],hide_index=True,width="stretch")
    clock=result.get("clock_quality",{})
    st.caption("Native ingress clock quality: "+("clean" if clock.get("clean") is True else "see recorded warnings / not established"))
    if clock.get("clean") is not True:
        notice("Native ingress clock quality not verified",
               "The recorded prediction and parity are retained, but parity alone does not establish a clean clock. "
               "Review the preserved clock observations below.","warning")
        with st.expander("Recorded native ingress clock-quality evidence"):
            st.json(clock,expanded=False)
    capture_prediction=result.get("reference_capture_prediction",result.get("capture_time_prediction"))
    if capture_prediction:
        st.caption("Capture-time Python reference: "+str(capture_prediction)+" (offline timing comparison, not a controlled BMv2 run).")
        st.caption("Native versus capture-time reference prediction: "+
                   ("changed" if result["p4_prediction"]!=capture_prediction else "unchanged")+
                   ". This is a timing/reference comparison, not activity-label accuracy.")


def render_pcap_evidence(evidence):
    install_live_style()
    if evidence.status=="corrupt":
        notice("PCAP telemetry integrity failure"," | ".join(evidence.messages)+". No classification data are trusted.","error")
        return
    if not is_pcap(evidence):
        notice("No PCAP demonstration attached","The current run is synthetic or no PCAP run has started. "
               "Use the terminal command above; saved synthetic results remain separate.")
        empty_panel("RF-B versus RF-C","Actual feature vectors, tree leaves, class scores and predictions appear after real replay observations.")
        return
    snap=evidence.snapshot
    meta=snap.get("metadata",{})
    final=snap.get("final_summary") or {}
    source=snap.get("source_example") or meta.get("source_example") or meta.get("selected_example") or final.get("source_example",{})
    results=dict(snap.get("classification_results") or {})
    # Saved boundary verification is authoritative even when asynchronous
    # presentation failed after an otherwise completed model replay.
    results.update(final.get("classification_results") or {})
    progress=snap.get("packet_progress",{})
    monitoring=dict(snap.get("pcap_monitoring") or {})
    monitoring.update(final.get("pcap_monitoring") or {})
    section_header("Current real-PCAP run","Run "+str(evidence.run_id)+" / "+str(snap.get("phase","preparing")))
    tone="success" if evidence.status=="completed" else "warning" if evidence.status in ("stale","interrupted","failed") else "info"
    st.markdown(pill(evidence.status.upper(),tone)+pill("Debug / correctness demonstration","neutral"),unsafe_allow_html=True)
    recorded_error=final.get("error") or snap.get("error")
    if recorded_error:
        notice("Recorded demonstration failure / interruption",str(recorded_error),"warning")
    for message in evidence.messages:
        notice("Telemetry notice",message,"warning")
    _source(source)
    selected=meta.get("mode","compare")
    models="BC" if selected=="compare" else "B" if selected=="rf_b" else "C"
    _outcome_summary(source,results,models)
    render_journey(pcap_journey(results,progress,monitoring,models,evidence.status),
                   caption="Recorded per-model stages. Unobserved steps remain pending; a completed acquisition is not automatically verified.")
    _packet_strip(source,progress,results,models)
    _classification_reading_help()
    for column,model in zip(st.columns(len(models)),models):
        with column:
            _model(results.get(model),model,progress)
    complete=False
    if models=="BC":
        complete=all(results.get(model) and not result_issues(results[model],model) for model in "BC")
        if complete:
            with st.expander("Compare the native feature vectors",expanded=False):
                st.dataframe(feature_comparison(results),width="stretch",hide_index=True)
                st.caption("RF-C's two directional inputs are highlighted as C-only. Both P4 variants already maintain direction state.")
    for column,model in zip(st.columns(len(models)),models):
        with column:
            _monitoring(monitoring.get(model) or {},model,progress.get(model) or {},results.get(model))
    if models=="BC" and complete:
            section_header("Packet-arrival timing across the two runs","Identical source packets do not imply identical native ingress timestamps.")
            rows=timing_rows(results,source)
            fig=go.Figure()
            for name,color in (("Source capture (us)","#94a3b8"),("RF-B native (us)",MODEL_COLORS["B"]),("RF-C native (us)",MODEL_COLORS["C"])):
                if any(row.get(name) is not None for row in rows):
                    fig.add_trace(go.Scatter(x=[row["Gap"] for row in rows],y=[row.get(name) for row in rows],
                        name=name,mode="lines+markers",connectgaps=False,line=dict(color=color),
                        hovertemplate="Gap %{x}: %{y:,.0f} us<extra>%{fullData.name}</extra>"))
            fig.update_layout(xaxis_title="Gap between eligible packets (1-7)",yaxis_title="Recorded inter-arrival gap (us)")
            plot(fig,key="pcap_native_timing",height=290)
            st.caption("Read this chart: gap 1 is between eligible packets 1 and 2, through gap 7 between packets 7 and 8. "
                       "The vertical axis is inter-arrival microseconds, not packet forwarding delay. Separate model runs may observe different gaps.")
            with st.expander("Exact native timestamp / IAT differences"):
                st.dataframe(rows,width="stretch",hide_index=True)
                for model in "BC":
                    st.caption("RF-"+model+" observed ingress timestamps (us): "+str(results[model].get("native_times_us","Not available")))
            notice("Interpret the pair carefully","These are separately executed frozen forests on the same source example. "
                   "Actual timing may change IAT features and predictions. This is neither a timing-controlled direction-only ablation "
                   "nor a measurement of standalone direction-extraction overhead.","warning")
    with st.expander("Classification event log / provenance"):
        events=[row for row in evidence.events if row.get("event")!="heartbeat"]
        st.code("\n".join(f"{row.get('seq','?')}  {row.get('event','event')}  {row.get('phase','')}" for row in events[-20:]),language=None)
        if final.get("evidence"):
            st.caption("Separate demonstration evidence: "+str(final["evidence"]))
        for name in ("telemetry_observer_errors","cleanup_errors","normalization_errors"):
            if final.get(name):
                st.caption("Preserved "+name+": "+str(final[name]))
    st.caption("Short prefixes may finish between browser refreshes. Progress jumps reflect actual observations, not artificially delayed packets. "
               "Class scores and per-model verification remain visible after completion.")


@st.fragment(run_every=1.0)
def classification_fragment():
    render_pcap_evidence(read_live())


def render():
    _selection()
    classification_fragment()
