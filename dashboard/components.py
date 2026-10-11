"""Small presentation components; no experiment execution or evidence mutation."""
from html import escape
import plotly.graph_objects as go
import streamlit as st

MODEL_COLORS = {
    "forwarding": "#94a3b8", "features": "#c4b5fd",
    "rf_b": "#60a5fa", "rf_c": "#2dd4bf", "B": "#60a5fa", "C": "#2dd4bf",
}
MODEL_LABELS = {
    "forwarding": "Forwarding", "features": "Features only",
    "rf_b": "RF-B", "rf_c": "RF-C",
}

CSS = """
<style>
 :root { --etc-blue:#60a5fa; --etc-teal:#2dd4bf; }
 .stApp { background:#0b1220; color:#e8eef8; }
 .block-container { max-width:1480px; padding-top:2rem; padding-bottom:3rem; }
 [data-testid="stSidebar"] { background:#0e1828; border-right:1px solid #203047; }
 [data-testid="stSidebar"] > div:first-child { padding-top:1.5rem; }
 h1,h2,h3 { letter-spacing:-.035em; }
 h1 { line-height:1.12; }
 [data-testid="stHeader"] { background:#0b1220; }
 [data-testid="stSidebarCollapseButton"] { visibility:visible; }
 .etc-brand { display:flex; gap:12px; align-items:center; margin-bottom:22px; }
 .etc-mark { width:42px; height:42px; border-radius:12px; background:#153c51;
   color:#5eead4; display:grid; place-items:center; font-weight:700; }
 .etc-brand strong { font-size:17px; letter-spacing:-.02em; }
 .etc-brand small { display:block; color:#97a9bf; margin-top:2px; }
 .etc-eyebrow { color:#5eead4; font-size:11px; letter-spacing:.14em;
   font-weight:600; text-transform:uppercase; margin-bottom:12px; }
 .etc-hero { padding:8px 0 20px; }
 .etc-hero h1 { margin:0 0 12px; font-size:clamp(28px,3vw,42px); max-width:1000px; }
 .etc-hero p { color:#adbed1; line-height:1.65; max-width:920px; margin:0 0 12px; }
 .etc-pill { display:inline-block; border-radius:999px; padding:5px 10px;
   font-size:11px; font-weight:600; background:#183246; color:#93c5fd;
   border:1px solid #294a66; margin:0 6px 6px 0; }
 .etc-pill.success { color:#5eead4; background:#10392f; border-color:#236051; }
 .etc-pill.warning { color:#fcd34d; background:#382c19; border-color:#5e4822; }
 .etc-pill.error { color:#fda4af; background:#3a202d; border-color:#693143; }
 .etc-pill.neutral { color:#bccbdc; background:#192638; border-color:#304258; }
 .etc-metric { background:#111d30; border:1px solid #24364f; border-radius:14px;
   padding:19px 20px; min-height:150px; margin-bottom:14px; overflow-wrap:anywhere; }
 .etc-metric.blue { border-top:3px solid #60a5fa; }
 .etc-metric.teal { border-top:3px solid #2dd4bf; }
 .etc-metric.warning { border-top:3px solid #fbbf24; }
 .etc-metric-label { color:#afbdd0; font-size:12px; font-weight:500; }
 .etc-metric-value { font-size:30px; line-height:1.3; font-weight:650;
   margin:10px 0 8px; font-variant-numeric:tabular-nums; letter-spacing:-.04em; }
 .etc-metric-note { color:#97aac0; font-size:12px; line-height:1.55; }
 .etc-section { margin:22px 0 12px; }
 .etc-section h2 { font-size:22px; margin:0 0 6px; }
 .etc-section p { color:#97aac0; font-size:13px; margin:0; line-height:1.6; }
 .etc-notice { border-left:3px solid #60a5fa; background:#122138;
   padding:14px 18px; border-radius:0 10px 10px 0; margin:12px 0 20px; }
 .etc-notice.warning { border-color:#fbbf24; background:#282319; }
 .etc-notice.success { border-color:#2dd4bf; background:#112b29; }
 .etc-notice.error { border-color:#fb7185; background:#2e1b28; }
 .etc-notice strong { display:block; margin-bottom:5px; font-size:13px; }
 .etc-notice p { color:#b9c7d9; margin:0; font-size:13px; line-height:1.6; }
 .etc-source { color:#91a3bb; font-size:11px; line-height:1.6;
   margin:8px 0 16px; overflow-wrap:anywhere; }
 .etc-pipeline { display:grid; grid-template-columns:repeat(5,minmax(0,1fr));
   gap:10px; margin:16px 0; }
 .etc-step { background:#111d30; border:1px solid #263950; border-radius:12px;
   padding:16px 12px; min-height:132px; }
 .etc-step small { display:block; color:#5eead4; font-size:10px;
   letter-spacing:.1em; margin-bottom:12px; }
 .etc-step strong { display:block; font-size:14px; margin-bottom:7px; }
 .etc-step p { color:#a9bbd0; font-size:12px; line-height:1.5; margin:0; }
 .etc-empty { border:1px dashed #314763; background:#0e192b; border-radius:12px;
   min-height:170px; padding:26px; display:flex; flex-direction:column;
   justify-content:center; align-items:center; text-align:center; margin:12px 0; }
 .etc-empty strong { color:#c5d3e5; font-size:15px; }
 .etc-empty span { color:#8fa4c0; font-size:12px; line-height:1.6;
   max-width:470px; margin-top:10px; }
 [data-testid="stVerticalBlockBorderWrapper"] { border-radius:14px; }
 [data-testid="stTabs"] button { font-size:13px; }
 [data-testid="stExpander"] { background:#0f1b2d; }
 @media(max-width:800px) {
   .block-container { padding:4rem 1rem 1.4rem; }
   .etc-pipeline { grid-template-columns:1fr; }
   .etc-step { min-height:90px; }
   .etc-metric-value { font-size:26px; }
 }
</style>
"""

def install_style():
    st.markdown(CSS, unsafe_allow_html=True)

def pill(text, kind="info"):
    return f'<span class="etc-pill {escape(kind)}">{escape(str(text))}</span>'

def hero(kicker, title, subtitle, badge=None):
    st.markdown(
        '<div class="etc-hero"><div class="etc-eyebrow">'
        + escape(kicker) + '</div><h1>' + escape(title) + '</h1><p>'
        + escape(subtitle) + '</p>' + (pill(badge) if badge else "") + '</div>',
        unsafe_allow_html=True,
    )

def section_header(title, subtitle=""):
    st.markdown('<div class="etc-section"><h2>' + escape(title) + '</h2><p>'
                + escape(subtitle) + '</p></div>', unsafe_allow_html=True)

def metric_card(label, value, note="", tone="neutral"):
    st.markdown(
        f'<div class="etc-metric {escape(tone)}"><div class="etc-metric-label">'
        f'{escape(str(label))}</div><div class="etc-metric-value">{escape(str(value))}'
        f'</div><div class="etc-metric-note">{escape(str(note))}</div></div>',
        unsafe_allow_html=True,
    )

def metric_row(items):
    for col, item in zip(st.columns(len(items), gap="small"), items):
        with col:
            metric_card(**item)

def notice(title, body, kind="info"):
    st.markdown(f'<div class="etc-notice {escape(kind)}"><strong>{escape(title)}</strong>'
                f'<p>{escape(body)}</p></div>', unsafe_allow_html=True)

def provenance(evidence):
    entry = evidence.entry or {}
    status = "File hash verified" if evidence.status == "verified" else evidence.status
    st.markdown('<div class="etc-source">' + escape(
        f"Source: {entry.get('run_id', evidence.role)} | {status} | {evidence.path}"
    ) + '</div>', unsafe_allow_html=True)
    if evidence.status == "verified":
        with st.expander("Evidence provenance", expanded=False):
            st.caption("SHA-256 verification establishes file identity, not metric qualification.")
            st.code(str(evidence.path), language=None)
            st.code(evidence.sha256, language=None)
            st.caption(entry.get("scope", "Pinned saved evidence; no latest-run selection."))

def style_figure(fig, height=340):
    fig.update_layout(
        height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Segoe UI, Arial, sans-serif", color="#b8c9de", size=12),
        margin=dict(l=14,r=20,t=35,b=45),
        colorway=list(MODEL_COLORS.values())[:4],
        legend=dict(orientation="h",yanchor="bottom",y=1.04,xanchor="left",x=0),
        hoverlabel=dict(bgcolor="#17263c",font_color="#e8eef8"),
    )
    fig.update_xaxes(gridcolor="#1f3048", zeroline=False, title_font_size=12)
    fig.update_yaxes(gridcolor="#1f3048", zeroline=False, title_font_size=12)
    return fig

def plot(fig, key=None, height=340):
    st.plotly_chart(style_figure(fig,height), width="stretch", key=key,
                    config={"displaylogo":False,"scrollZoom":False})

def empty_panel(title, explanation):
    st.markdown(f'<div class="etc-empty"><strong>{escape(title)}</strong>'
                f'<span>{escape(explanation)}</span></div>', unsafe_allow_html=True)

def pipeline():
    steps = [
        ("01 / INPUT","Encrypted traffic","Original IPv4 packets inside Ethernet frames"),
        ("02 / PARSER","P4 eligibility","IPv4 + TCP/UDP; bidirectional flow identification"),
        ("03 / STATE","First 8 packets","Size, IAT and directional state; 60-second idle policy"),
        ("04 / INFERENCE","Compact Random Forest","10 trees; fixed-point probability aggregation"),
        ("05 / OUTPUT","Decision + forwarding","One prediction per eligible instance; counter evidence"),
    ]
    st.markdown('<div class="etc-pipeline">' + "".join(
        '<div class="etc-step"><small>' + escape(n) + '</small><strong>'
        + escape(t) + '</strong><p>' + escape(d) + '</p></div>'
        for n,t,d in steps) + '</div>', unsafe_allow_html=True)

def unavailable(evidence):
    notice("Evidence unavailable", evidence.message or evidence.status, "error")
    st.caption(f"Pinned source: {evidence.path}. No replacement values were generated.")
