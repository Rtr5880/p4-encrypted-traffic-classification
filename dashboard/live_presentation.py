"""Presentation-only helpers for the two Live Monitor views.

No timing, qualification, evidence or experiment execution is changed here.
"""
from __future__ import annotations

from html import escape

import streamlit as st


LIVE_STYLE = """
<style>
.etc-live-journey {display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px;margin:12px 0 8px;}
.etc-live-stage {background:#111d30;border:1px solid #293c55;border-radius:10px;padding:12px;min-width:0;overflow-wrap:anywhere;}
.etc-live-stage strong {display:block;color:#e8eef8;font-size:12px;font-weight:600;margin:5px 0;}
.etc-live-stage small {display:block;color:#9caec5;font-size:11px;line-height:1.45;}
.etc-live-stage .etc-live-stage-index {color:#99acc4;font-size:11px;}
.etc-live-stage.active {background:#133345;border-color:#3b839a;}
.etc-live-stage.observed {border-top:3px solid #60a5fa;}
.etc-live-stage.warning {background:#30291d;border-color:#806536;}
.etc-live-stage.failed {background:#351f2b;border-color:#985169;}
.etc-live-stage.pending {opacity:.8;}
.etc-live-health {display:flex;flex-wrap:wrap;gap:8px 18px;margin:8px 0 12px;}
.etc-live-health-item {color:#c4d2e4;font-size:12px;}
.etc-live-reading {color:#a9bbd0;font-size:12px;line-height:1.6;}
@media(max-width:1000px) {.etc-live-journey {grid-template-columns:repeat(3,minmax(0,1fr));}}
@media(max-width:650px) {.etc-live-journey {grid-template-columns:repeat(2,minmax(0,1fr));}}
</style>
"""


def install_live_style():
    """All selectors are live-only; no shared/global dashboard styling changes."""
    st.markdown(LIVE_STYLE, unsafe_allow_html=True)


def render_journey(steps, caption=""):
    state_labels = {"pending":"Not recorded", "active":"In progress",
                    "observed":"Recorded", "warning":"Last observed",
                    "failed":"Stopped / failed"}
    parts = []
    for index, step in enumerate(steps, 1):
        state = step.get("state", "pending")
        if state not in state_labels:
            state = "pending"
        parts.append(
            '<div class="etc-live-stage ' + state + '" role="listitem">'
            '<span class="etc-live-stage-index">' + str(index) + ' / '
            + escape(state_labels[state]) + '</span><strong>'
            + escape(str(step.get("label", "Stage"))) + '</strong><small>'
            + escape(str(step.get("detail") or state_labels[state])) + '</small></div>'
        )
    st.markdown('<div class="etc-live-journey" role="list" aria-label="Recorded experiment journey">'
                + ''.join(parts) + '</div>', unsafe_allow_html=True)
    if caption:
        st.caption(caption)


def synthetic_journey(snapshot, events, evidence_state):
    """Show recorded milestones, not assumed success of all earlier phases."""
    labels = ("Preparation", "Switch startup", "Warm-up", "Measurement",
              "Accounting", "Acquisition complete")
    phases = {"preparing":0, "warmup":2, "measurement":3, "draining":4,
              "accounting":4, "finalizing":4, "completed":5}
    event_stages = {"experiment_preparing":0, "experiment_started":0,
                    "switch_starting":1, "switch_ready":1,
                    "warmup_started":2, "warmup_completed":2,
                    "measurement_started":3, "measurement_completed":3,
                    "trial_completed":4, "experiment_completed":5}
    seen = set()
    last = None
    records = list(snapshot.get("recent_events") or []) + list(events or [])
    for record in records:
        if not isinstance(record, dict):
            continue
        index = event_stages.get(record.get("event"), phases.get(record.get("phase")))
        if index is not None:
            seen.add(index)
            last = index
    current = phases.get(snapshot.get("phase"))
    # A specific startup event is more informative than its enclosing preparing phase.
    if current == 0 and last == 1:
        current = last
    if current is not None:
        seen.add(current)
    elif last is not None:
        current = last
    if evidence_state == "completed":
        seen.add(5)
        current = 5
    terminal = evidence_state in {"completed", "failed", "interrupted", "cancelled", "stale", "corrupt"}
    steps = []
    for index, label in enumerate(labels):
        state = "observed" if index in seen else "pending"
        detail = "Recorded milestone" if index in seen else "No retained milestone"
        if index == current and evidence_state in {"failed", "corrupt"}:
            state, detail = "failed", "Review preserved failure reasons"
        elif index == current and evidence_state in {"stale", "interrupted", "cancelled"}:
            state, detail = "warning", "No active progress is assumed"
        elif index == current and not terminal:
            state, detail = "active", "Latest recorded phase"
        if index == 5:
            detail = "Metric verdicts remain separate" if state == "observed" else "No completed acquisition recorded"
        steps.append({"label":label, "state":state, "detail":detail})
    return steps


def health_explanation(check, status):
    """Interpret statuses without inventing the run-specific failure cause."""
    status = str(status).upper()
    explanations = {
        "measurement_integrity": {
            "PASS":"The local measurement checks passed; this is not independent clock qualification.",
            "FAIL":"A local measurement check failed. Only separately supported metrics may be used.",
            "WARNING":"Review the preserved local measurement warnings before interpreting this run.",
        },
        "independent_raw_qualification": {
            "PASS":"This session met its independent RAW qualification requirements; kernel latency is still separate.",
            "FAIL":"The independent RAW qualification requirements were not met; no qualified absolute-rate claim follows.",
            "INCONCLUSIVE":"Independent timing qualification is insufficient under the protocol; this does not itself mean the classifier failed.",
        },
        "sender_pacing_conformance": {
            "PASS":"The recorded pacing met the unchanged engineering limits, not a maximum-capacity test.",
            "WARNING":"Pacing departed from its limits. Reliable counts can remain valid; uniform-load claims need additional justification.",
            "FAIL":"Review the pacing evidence. Packet counts and timing qualification are separate assessments.",
        },
    }
    return explanations.get(check, {}).get(status, "Not finalized or not available; no PASS or zero value is assumed.")
