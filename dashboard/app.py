"""Research console. Read-only browser; experiments are terminal-authorized."""
from functools import partial
from pathlib import Path
import os
import sys

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import streamlit as st
from dashboard.evidence import EvidenceStore
from dashboard.components import install_style, pill

PAGE_SPECS = (
    {"title":"Overview","slug":"overview","state":"ready","icon":":material/dashboard:"},
    {"title":"Classification","slug":"classification","state":"ready","icon":":material/account_tree:"},
    {"title":"P4 Correctness","slug":"correctness","state":"ready","icon":":material/verified:"},
    {"title":"Native Clock Evaluation","slug":"native-clock","state":"ready","icon":":material/timer:"},
    {"title":"Performance Evaluation","slug":"performance","state":"ready","icon":":material/monitoring:"},
    {"title":"Live Experiment Monitor","slug":"live","state":"ready","icon":":material/sensors:"},
    {"title":"Experiment History","slug":"history","state":"ready","icon":":material/history:"},
)

def render_page(title, store):
    if title=="Overview":
        from dashboard.views.overview import render
    elif title=="Performance Evaluation":
        from dashboard.views.performance import render
    elif title=="Live Experiment Monitor":
        from dashboard.views.live import render
    elif title=="Classification":
        from dashboard.views.classification import render
    elif title=="P4 Correctness":
        from dashboard.views.correctness import render
    elif title=="Native Clock Evaluation":
        from dashboard.views.native_clock import render
    elif title=="Experiment History":
        from dashboard.views.history import render
    else:
        raise ValueError(f"Unknown dashboard page: {title}")
    render(store)

def build_pages(store):
    return [
        st.Page(partial(render_page,spec["title"],store),title=spec["title"],
                icon=spec["icon"],url_path=spec["slug"],default=index==0)
        for index,spec in enumerate(PAGE_SPECS)
    ]

@st.cache_resource(show_spinner=False)
def _store(registry,project_root,external_root,registry_mtime):
    """Cache loader state, not rewritten or requalified scientific results."""
    return EvidenceStore(registry_path=registry,project_root=project_root)

def main():
    st.set_page_config(page_title="ETC Research Console",page_icon=":material/hub:",layout="wide",
                       initial_sidebar_state="expanded")
    install_style()
    if hasattr(os,"geteuid") and os.geteuid()==0:
        st.error("Run this dashboard as the normal project user, not with sudo.")
        st.stop()
    registry=os.environ.get("ETC_DASHBOARD_REGISTRY",str(REPO/"config/dashboard-evidence.json"))
    registry_path=Path(registry)
    mtime=registry_path.stat().st_mtime_ns if registry_path.is_file() else 0
    store=_store(registry,os.environ.get("ETC_PROJECT_ROOT",str(REPO)),
                 os.environ.get("ETC_EXTERNAL_EVIDENCE_ROOT",""),mtime)
    with st.sidebar:
        st.markdown(
            '<div class="etc-brand"><div class="etc-mark">ETC</div><div>'
            '<strong>Research Console</strong><small>P4 / BMv2 / Compact RF</small>'
            '</div></div>',unsafe_allow_html=True)
    page=st.navigation(build_pages(store),position="sidebar",expanded=True)
    with st.sidebar:
        st.divider()
        st.markdown(pill("READ-ONLY / FIRST FULL VERSION","success"),unsafe_allow_html=True)
        st.caption("Terminal-authorized synthetic and real-PCAP demos. No browser launch or model fitting.")
        st.caption("Pinned file hashes preserve provenance. Scientific validity is shown separately.")
        st.caption("Historical research and separate live demos share this one application.")
    page.run()
    st.divider()
    st.caption("EEE4022 / Encrypted Traffic Classification / Evidence-backed research interface")

if __name__=="__main__":
    main()
