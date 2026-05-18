import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

st.set_page_config(
    page_title="ForensiQ — Network Threat Analysis",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Animations ── */
@keyframes fadeInUp   { from{opacity:0;transform:translateY(18px)} to{opacity:1;transform:translateY(0)} }
@keyframes fadeIn     { from{opacity:0} to{opacity:1} }
@keyframes slideRight { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:translateX(0)} }
@keyframes pulse      { 0%,100%{opacity:1} 50%{opacity:0.35} }
@keyframes spin       { to{transform:rotate(360deg)} }
@keyframes gradShift  { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
@keyframes borderGlow { 0%,100%{box-shadow:0 0 0 0 rgba(59,130,246,0)} 50%{box-shadow:0 0 0 3px rgba(59,130,246,0.18)} }
@keyframes countPop   { from{opacity:0;transform:scale(0.75)} to{opacity:1;transform:scale(1)} }
@keyframes shimmer    { 0%{background-position:-200% 0} 100%{background-position:200% 0} }
@keyframes scanLine   { 0%{top:0%;opacity:0.5} 100%{top:100%;opacity:0} }

/* ── Variables ── */
:root {
  --bg:  #070B14; --bg2: #0F1523; --bg3: #161D2F; --bg4: #1E263C;
  --ac:  #3B82F6; --ac2: #6366F1; --ac3: #8B5CF6;
  --crit:#EF4444; --high:#F97316; --med:#EAB308; --low:#22C55E;
  --tx:  #F1F5F9; --tx2: #94A3B8; --tx3: #475569;
  --br:  #1E2D45; --br2: #253349;
}

/* ── Base ── */
html,body,[data-testid="stAppViewContainer"],[data-testid="stApp"] {
  background:var(--bg) !important; color:var(--tx);
  font-family:'Inter',-apple-system,sans-serif;
}
[data-testid="stAppViewContainer"] > .main { background:var(--bg) !important; }
.block-container { padding:1.5rem 2rem !important; max-width:1440px !important; }
#MainMenu,footer,[data-testid="stDecoration"],header[data-testid="stHeader"] { display:none !important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
  background:var(--bg2) !important;
  border-right:1px solid var(--br);
}
[data-testid="stSidebar"] > div:first-child { padding-top:1.5rem; }

/* ── Logo ── */
.sl-logo {
  font-size:1.65rem; font-weight:900; letter-spacing:-0.045em; line-height:1; margin-bottom:3px;
  background:linear-gradient(135deg,#F1F5F9 0%,#94A3B8 100%);
  background-size:200% 200%;
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;
}
.sl-logo em {
  font-style:normal;
  background:linear-gradient(135deg,var(--ac) 0%,var(--ac2) 50%,var(--ac3) 100%);
  background-size:200% 200%;
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;
  animation:gradShift 4s ease infinite;
}
.sl-sub { font-size:0.7rem; color:var(--tx3); letter-spacing:0.08em; text-transform:uppercase; margin-bottom:18px; }

/* ── File uploader ── */
[data-testid="stFileUploader"] {
  background:var(--bg3) !important; border:1px dashed var(--br2) !important;
  border-radius:10px !important; transition:border-color 0.2s,background 0.2s;
}
[data-testid="stFileUploader"]:hover { border-color:var(--ac) !important; background:var(--bg4) !important; }
[data-testid="stFileUploadDropzone"] { background:transparent !important; }

/* ── Primary button ── */
[data-testid="stButton"]>button[kind="primary"] {
  background:linear-gradient(135deg,var(--ac),var(--ac2),var(--ac3)) !important;
  background-size:200% 200% !important; border:none !important; border-radius:8px !important;
  font-weight:600 !important; font-size:0.9rem !important; padding:0.55rem 1.2rem !important;
  color:#fff !important; transition:opacity 0.2s,transform 0.15s !important;
  animation:gradShift 5s ease infinite;
}
[data-testid="stButton"]>button[kind="primary"]:hover { opacity:0.88 !important; transform:translateY(-1px) !important; }
[data-testid="stButton"]>button[kind="primary"]:active { transform:translateY(0) !important; }

/* ── Secondary button ── */
[data-testid="stButton"]>button[kind="secondary"] {
  background:var(--bg3) !important; border:1px solid var(--br) !important;
  border-radius:8px !important; color:var(--tx2) !important;
  transition:border-color 0.2s,color 0.2s !important;
}
[data-testid="stButton"]>button[kind="secondary"]:hover {
  border-color:var(--ac) !important; color:var(--tx) !important;
}

/* ── Download button ── */
[data-testid="stDownloadButton"]>button {
  background:var(--bg3) !important; border:1px solid var(--br) !important;
  border-radius:8px !important; color:var(--ac) !important;
  font-weight:500 !important; transition:background 0.2s,border-color 0.2s,transform 0.15s !important;
}
[data-testid="stDownloadButton"]>button:hover {
  background:var(--bg4) !important; border-color:var(--ac) !important; transform:translateY(-1px) !important;
}

/* ── Metrics ── */
[data-testid="metric-container"] {
  background:var(--bg3) !important; border:1px solid var(--br) !important;
  border-radius:12px !important; padding:18px 20px !important;
  animation:fadeInUp 0.45s ease both;
  transition:border-color 0.2s,transform 0.2s,box-shadow 0.2s;
}
[data-testid="metric-container"]:hover {
  border-color:var(--br2) !important; transform:translateY(-2px);
  box-shadow:0 8px 28px rgba(0,0,0,0.4);
}
[data-testid="metric-container"] label {
  color:var(--tx3) !important; font-size:0.69rem !important;
  text-transform:uppercase; letter-spacing:0.1em; font-weight:700 !important;
}
[data-testid="stMetricValue"] {
  color:var(--tx) !important; font-size:1.75rem !important;
  font-weight:800 !important; letter-spacing:-0.03em !important;
  animation:countPop 0.5s cubic-bezier(0.34,1.56,0.64,1) both;
}
[data-testid="stMetricDelta"] { display:none; }

/* ── Expanders ── */
[data-testid="stExpander"] {
  background:var(--bg3) !important; border:1px solid var(--br) !important;
  border-radius:10px !important; margin-bottom:10px !important;
  animation:fadeInUp 0.35s ease both;
  transition:border-color 0.2s,transform 0.2s,box-shadow 0.2s;
}
[data-testid="stExpander"]:hover {
  border-color:var(--br2) !important; transform:translateY(-1px);
  box-shadow:0 6px 24px rgba(0,0,0,0.35);
}
details[data-testid="stExpander"] summary { padding:14px 16px !important; }

/* ── Tabs ── */
[data-testid="stTabs"] [role="tablist"] { border-bottom:1px solid var(--br); gap:0; }
[data-testid="stTabs"] [role="tab"] {
  color:var(--tx3) !important; font-size:0.85rem !important;
  font-weight:500 !important; padding:8px 16px !important;
  border-radius:6px 6px 0 0; transition:color 0.15s;
}
[data-testid="stTabs"] [role="tab"]:hover { color:var(--tx2) !important; }
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
  color:var(--ac) !important; border-bottom:2px solid var(--ac) !important; font-weight:600 !important;
}

/* ── Progress bar ── */
[data-testid="stProgressBar"]>div>div {
  background:linear-gradient(90deg,var(--ac),var(--ac2),var(--ac3)) !important;
  background-size:200% 100% !important; border-radius:99px !important;
  animation:gradShift 2s linear infinite !important;
}
[data-testid="stProgressBar"]>div { background:var(--bg3) !important; border-radius:99px !important; height:4px !important; }

/* ── Status widget ── */
[data-testid="stStatusWidget"] {
  background:var(--bg3) !important; border:1px solid var(--br) !important; border-radius:10px !important;
}

/* ── Inputs ── */
[data-testid="stTextInput"] input {
  background:var(--bg3) !important; border:1px solid var(--br) !important;
  border-radius:8px !important; color:var(--tx) !important; font-size:0.9rem !important;
}
[data-testid="stTextInput"] input:focus {
  border-color:var(--ac) !important; box-shadow:0 0 0 3px rgba(59,130,246,0.1) !important;
  outline:none !important;
}
[data-testid="stMultiSelect"] [data-baseweb="select"] {
  background:var(--bg3) !important; border:1px solid var(--br) !important; border-radius:8px !important;
}

/* ── Tables ── */
table { border-collapse:collapse; width:100%; }
th { background:var(--bg4); color:var(--tx3); padding:10px 14px; font-size:0.7rem;
     text-transform:uppercase; letter-spacing:0.09em; font-weight:700; border-bottom:1px solid var(--br); }
td { padding:10px 14px; border-bottom:1px solid var(--br); font-size:0.87rem; color:var(--tx2); }
tr:hover td { background:var(--bg4); transition:background 0.15s; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--br2); border-radius:3px; }
hr { border:none; border-top:1px solid var(--br); margin:14px 0; }

/* ── Badges ── */
.badge {
  display:inline-flex; align-items:center; gap:5px;
  border-radius:6px; padding:3px 10px;
  font-size:0.7rem; font-weight:700; letter-spacing:0.05em; text-transform:uppercase;
}
.badge::before {
  content:''; width:5px; height:5px; border-radius:50%;
  background:currentColor; animation:pulse 2s ease infinite;
}
.badge-crit { background:rgba(239,68,68,0.12);  color:#F87171; border:1px solid rgba(239,68,68,0.25); }
.badge-high { background:rgba(249,115,22,0.12); color:#FB923C; border:1px solid rgba(249,115,22,0.25); }
.badge-med  { background:rgba(234,179,8,0.12);  color:#FBBF24; border:1px solid rgba(234,179,8,0.25); }
.badge-low  { background:rgba(34,197,94,0.12);  color:#4ADE80; border:1px solid rgba(34,197,94,0.25); }
.badge-info { background:rgba(59,130,246,0.12); color:#60A5FA; border:1px solid rgba(59,130,246,0.25); }
.badge-clean{ background:rgba(34,197,94,0.12);  color:#4ADE80; border:1px solid rgba(34,197,94,0.25); }

/* ── Section header ── */
.sh { font-size:0.68rem; font-weight:700; color:var(--tx3); text-transform:uppercase; letter-spacing:0.1em; margin-bottom:10px; }

/* ── Cards ── */
.card {
  background:var(--bg3); border:1px solid var(--br); border-radius:12px; padding:20px;
  animation:fadeInUp 0.4s ease both;
  transition:border-color 0.2s,transform 0.2s,box-shadow 0.2s;
}
.card:hover { border-color:var(--br2); transform:translateY(-2px); box-shadow:0 10px 36px rgba(0,0,0,0.45); }

/* ── Flow viz ── */
.flow-wrap {
  background:var(--bg4); border:1px solid var(--br); border-radius:10px;
  padding:16px 20px; text-align:center;
  font-family:'JetBrains Mono',monospace; font-size:0.82rem; animation:fadeIn 0.4s ease;
}

/* ── Code ── */
code {
  background:var(--bg4); border:1px solid var(--br); border-radius:4px;
  padding:1px 6px; font-family:'JetBrains Mono',monospace;
  font-size:0.82em; color:#60A5FA;
}

/* ── Alert boxes ── */
[data-testid="stAlert"] {
  background:var(--bg3) !important; border:1px solid var(--br) !important;
  border-radius:8px !important; color:var(--tx2) !important;
}

/* ── Finding severity strip ── */
.finding-crit { border-left:3px solid var(--crit) !important; }
.finding-high { border-left:3px solid var(--high) !important; }
.finding-med  { border-left:3px solid var(--med)  !important; }
.finding-low  { border-left:3px solid var(--low)  !important; }

/* ── Sidebar divider ── */
[data-testid="stSidebar"] hr { border-top:1px solid var(--br) !important; }

/* ── Priority box ── */
.priority-box {
  border-radius:0 10px 10px 0; padding:14px 18px; margin-bottom:12px;
  animation:slideRight 0.3s ease;
}

/* ── Stagger ── */
.stagger-1{animation-delay:0.05s} .stagger-2{animation-delay:0.1s}
.stagger-3{animation-delay:0.15s} .stagger-4{animation-delay:0.2s}
.stagger-5{animation-delay:0.25s}

</style>
""", unsafe_allow_html=True)

# ── Constants ──────────────────────────────────────────────────────────────────
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_SEV_COLOR = {"CRITICAL": "#EF4444", "HIGH": "#F97316", "MEDIUM": "#EAB308", "LOW": "#22C55E"}
_SEV_CLASS = {"CRITICAL": "badge-crit", "HIGH": "badge-high", "MEDIUM": "badge-med", "LOW": "badge-low"}
_SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
_SEV_STRIP = {"CRITICAL": "finding-crit", "HIGH": "finding-high", "MEDIUM": "finding-med", "LOW": "finding-low"}


# ── Helpers ────────────────────────────────────────────────────────────────────
def _badge(text: str, cls: str) -> str:
    return f'<span class="badge {cls}">{text}</span>'

def _sev_badge(sev: str) -> str:
    return _badge(sev, _SEV_CLASS.get(sev, "badge-info"))

def _human_bytes(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def _vt_badge(score: str) -> str:
    if not score or score == "—":
        return '<span style="color:var(--tx3);">—</span>'
    try:
        det, tot = map(int, score.split("/"))
        ratio = det / tot if tot else 0
        if ratio > 0.3:   c = "#F87171"; bg = "rgba(239,68,68,0.12)"
        elif ratio > 0:   c = "#FB923C"; bg = "rgba(249,115,22,0.12)"
        else:              c = "#4ADE80"; bg = "rgba(34,197,94,0.12)"
        return f'<span style="background:{bg};color:{c};border-radius:5px;padding:2px 8px;font-size:0.78rem;font-weight:700;">{score}</span>'
    except Exception:
        return f'<span style="color:var(--tx3);">{score}</span>'

def _flow_diagram(src: str, dst: str, sev: str) -> str:
    c = _SEV_COLOR.get(sev, "#3B82F6")
    return f"""
<div class="flow-wrap">
  <span style="background:var(--bg3);border:1px solid var(--br2);border-radius:6px;padding:5px 12px;color:#60A5FA;">{src}</span>
  <span style="color:{c};margin:0 12px;font-size:1.1rem;">→→→</span>
  <span style="background:rgba(239,68,68,0.06);border:1px solid {c};border-radius:6px;padding:5px 12px;color:{c};">{dst}</span>
  <div style="color:var(--tx3);font-size:0.72rem;margin-top:8px;letter-spacing:0.05em;">ATTACKER → TARGET</div>
</div>"""

def _port_chips(ports_str: str) -> str:
    _CRIT = {21,22,23,25,53,3389,445,135,139}
    _DB   = {3306,5432,1433,1521,27017,6379}
    _MAL  = {4444,1337,31337,8080,8888}
    try:
        ports = [int(p.strip()) for p in str(ports_str).split(",") if p.strip().isdigit()]
    except Exception:
        return f"<code>{ports_str}</code>"
    chips = []
    for p in sorted(ports)[:40]:
        if p in _CRIT: bg,fg = "rgba(239,68,68,0.1)","#F87171"
        elif p in _DB: bg,fg = "rgba(59,130,246,0.1)","#60A5FA"
        elif p in _MAL:bg,fg = "rgba(139,92,246,0.1)","#C084FC"
        else:          bg,fg = "var(--bg4)","var(--tx3)"
        chips.append(f'<span style="background:{bg};color:{fg};border-radius:4px;padding:3px 8px;margin:3px;display:inline-block;font-size:0.76rem;font-family:\'JetBrains Mono\',monospace;">{p}</span>')
    if len(ports) > 40:
        chips.append(f'<span style="color:var(--tx3);font-size:0.76rem;margin:3px;">+{len(ports)-40} more</span>')
    legend = ('<div style="margin-top:10px;display:flex;gap:14px;flex-wrap:wrap;">'
              '<span style="color:#F87171;font-size:0.73rem;">■ Critical service</span>'
              '<span style="color:#60A5FA;font-size:0.73rem;">■ Database</span>'
              '<span style="color:#C084FC;font-size:0.73rem;">■ Malware port</span>'
              '<span style="color:var(--tx3);font-size:0.73rem;">■ Other</span>'
              '</div>')
    return '<div>' + "".join(chips) + legend + '</div>'

def _parse_explanation(text: str) -> dict:
    res = {"what": "", "why": "", "todo": ""}
    cur, buf = None, []
    for line in (text or "").split("\n"):
        low = line.lower().strip()
        if "what happened" in low:
            cur = "what"; buf = []
        elif "why it matters" in low:
            if cur: res[cur] = "\n".join(buf)
            cur = "why"; buf = []
        elif any(k in low for k in ("what to do", "actions", "remediation", "recommended")):
            if cur: res[cur] = "\n".join(buf)
            cur = "todo"; buf = []
        elif cur is not None:
            buf.append(line)
    if cur:
        res[cur] = "\n".join(buf)
    return res

def _generic_remediation(rule_name: str):
    recs = {
        "PORT_SCAN_DETECTED":     ["Block scanning IP at perimeter firewall", "Enable port-scan alerts in IDS/IPS", "Review exposed services and disable unused ones"],
        "BRUTE_FORCE_DETECTED":   ["Enable account lockout after failed attempts", "Enforce MFA on the targeted service", "Rate-limit authentication attempts"],
        "C2_BEACON_DETECTED":     ["Isolate the compromised host immediately", "Block C2 IPs and domains at DNS and firewall", "Run a full endpoint malware scan and memory analysis"],
        "DATA_EXFILTRATION":      ["Block outbound traffic to destination IP", "Audit data access logs for scope", "Engage incident response — assume breach"],
        "DNS_TUNNELING_DETECTED": ["Block DNS queries to suspicious domains", "Enable DNSSEC and DNS query logging", "Monitor per-host query volume for anomalies"],
    }
    items = recs.get(rule_name, ["Review related logs", "Update firewall rules", "Escalate to security team"])
    c = _SEV_COLOR.get("HIGH", "#F97316")
    html = f'<div class="priority-box" style="border-left:3px solid {c};background:rgba(249,115,22,0.05);">'
    html += '<p style="color:var(--tx);font-weight:700;margin-bottom:10px;font-size:0.9rem;">Recommended Actions</p>'
    html += '<ol style="color:var(--tx2);font-size:0.87rem;padding-left:20px;margin:0;">'
    for item in items:
        html += f'<li style="margin-bottom:7px;">{item}</li>'
    html += "</ol></div>"
    st.markdown(html, unsafe_allow_html=True)


# ── Landing hero ───────────────────────────────────────────────────────────────
def _landing():
    # CSS and HTML in ONE call so classes are guaranteed in scope
    st.markdown("""
<style>
@keyframes _fadeUp  { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
@keyframes _grad    { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
@keyframes _pulse   { 0%,100%{opacity:1} 50%{opacity:0.35} }

.fq-hero { text-align:center; padding:52px 20px 36px; animation:_fadeUp 0.6s ease both; }

.fq-pill {
  display:inline-flex; align-items:center; gap:7px;
  background:#161D2F; border:1px solid #1E2D45; border-radius:99px;
  padding:5px 16px; font-size:0.74rem; color:#475569; margin-bottom:28px;
}
.fq-dot {
  width:6px; height:6px; border-radius:50%; background:#22C55E;
  display:inline-block; animation:_pulse 2s ease infinite;
}

.fq-title {
  font-size:2.9rem; font-weight:900; letter-spacing:-0.05em; line-height:1.1;
  background:linear-gradient(135deg,#F1F5F9 0%,#94A3B8 50%,#3B82F6 100%);
  background-size:300% 300%;
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;
  animation:_grad 7s ease infinite; margin-bottom:12px;
}
.fq-accent {
  background:linear-gradient(135deg,#3B82F6,#6366F1,#8B5CF6);
  background-size:200% 200%;
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text;
  animation:_grad 3s ease infinite;
}
.fq-sub { font-size:1rem; color:#475569; margin-bottom:36px; }

.fq-grid {
  display:grid; grid-template-columns:repeat(3,1fr); gap:14px;
  max-width:820px; margin:0 auto 36px;
}
.fq-card {
  background:#161D2F; border:1px solid #1E2D45; border-radius:12px;
  padding:22px 20px; text-align:left;
  animation:_fadeUp 0.5s ease both;
  transition:border-color 0.25s, transform 0.25s, box-shadow 0.25s;
}
.fq-card:nth-child(1) { animation-delay:0.1s; }
.fq-card:nth-child(2) { animation-delay:0.2s; }
.fq-card:nth-child(3) { animation-delay:0.3s; }
.fq-card:hover {
  border-color:rgba(59,130,246,0.5);
  transform:translateY(-3px);
  box-shadow:0 14px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(59,130,246,0.12);
}
.fq-step  { font-size:0.67rem; font-weight:700; color:#3B82F6; letter-spacing:0.07em; text-transform:uppercase; margin-bottom:8px; }
.fq-ctitle{ font-size:0.92rem; font-weight:700; color:#F1F5F9; margin-bottom:6px; }
.fq-cdesc { font-size:0.8rem; color:#475569; line-height:1.55; }
.fq-icon  { font-size:1.4rem; margin-bottom:10px; }

.fq-tags  { display:flex; flex-wrap:wrap; gap:8px; justify-content:center; }
.fq-tag {
  background:#161D2F; border:1px solid #1E2D45; border-radius:99px;
  padding:4px 14px; font-size:0.73rem; color:#475569; font-weight:500;
  transition:border-color 0.2s, color 0.2s;
}
.fq-tag:hover { border-color:#3B82F6; color:#3B82F6; }
</style>

<div class="fq-hero">
  <div class="fq-pill"><span class="fq-dot"></span>System ready &nbsp;·&nbsp; All engines operational</div>
  <div class="fq-title">Forensi<span class="fq-accent">Q</span></div>
  <div class="fq-sub">Upload a PCAP file. Get a professional threat report in seconds.</div>

  <div class="fq-grid">
    <div class="fq-card">
      <div class="fq-icon">📁</div>
      <div class="fq-step">Step 01</div>
      <div class="fq-ctitle">Upload PCAP</div>
      <div class="fq-cdesc">Drop a .pcap or .pcapng file in the sidebar. Up to 500 MB supported.</div>
    </div>
    <div class="fq-card">
      <div class="fq-icon">🔬</div>
      <div class="fq-step">Step 02</div>
      <div class="fq-ctitle">Auto-Analyze</div>
      <div class="fq-cdesc">ForensiQ runs 5 detection rules, ML scoring, and threat intel enrichment.</div>
    </div>
    <div class="fq-card">
      <div class="fq-icon">📊</div>
      <div class="fq-step">Step 03</div>
      <div class="fq-ctitle">Investigate</div>
      <div class="fq-cdesc">Browse findings, IOC table, AI explanations, and download a PDF report.</div>
    </div>
  </div>

  <div class="fq-tags">
    <span class="fq-tag">Port Scan</span>
    <span class="fq-tag">Brute Force</span>
    <span class="fq-tag">C2 Beaconing</span>
    <span class="fq-tag">Data Exfiltration</span>
    <span class="fq-tag">DNS Tunneling</span>
    <span class="fq-tag">VirusTotal Enrichment</span>
  </div>

  <div style="margin-top:40px;font-size:0.75rem;color:#2D3A50;">
    Built by <span style="color:#3B82F6;font-weight:600;">Sangeeth</span>
  </div>
</div>
""", unsafe_allow_html=True)


# ── Analysis pipeline ──────────────────────────────────────────────────────────
def _run_analysis(pcap_path: Path):
    from core.validator import validate_pcap_file, ValidationError
    from core.parser import parse_pcap, PcapParseError
    from core.models import AnalysisReport
    from detection.engine import DetectionEngine
    from enrichment.enricher import Enricher
    from ai.explainer import LLMExplainer, Guardrails
    from output.report import generate_pdf

    result = {}
    prog = st.progress(0, text="Starting…")
    status = st.status("Running ForensiQ analysis…", expanded=True)

    try:
        with status:
            # 1 — validate
            st.write("**[1/6]** Validating file…")
            try:
                safe_name, file_hash = validate_pcap_file(pcap_path)
            except ValidationError as e:
                st.error(f"Validation failed: {e}")
                return None
            result.update({"safe_name": safe_name, "file_hash": file_hash})
            prog.progress(1/6, text=f"✓ File validated · SHA-256: {file_hash[:12]}…")

            # 2 — parse
            st.write("**[2/6]** Parsing PCAP…")
            t0 = datetime.now()
            try:
                flows, stats = parse_pcap(pcap_path)
            except PcapParseError as e:
                st.error(f"Parse failed: {e}")
                return None
            result.update({"flows": flows, "stats": stats, "analysis_start": t0})
            prog.progress(2/6, text=f"✓ Parsed {stats['flow_count']:,} flows · {stats['packet_count']:,} packets")

            # 3 — detect
            st.write("**[3/6]** Running detection rules…")
            engine = DetectionEngine()
            findings = engine.run(flows)
            result["analysis_end"] = datetime.now()
            prog.progress(3/6, text=f"✓ {len(findings)} finding(s) detected")

            # 4 — enrich
            st.write("**[4/6]** Enriching IOCs with threat intel…")
            enricher = Enricher()
            findings = enricher.enrich_all(findings)
            prog.progress(4/6, text="✓ Threat intel enrichment complete")

            # 5 — AI
            st.write("**[5/6]** Generating AI explanations…")
            explainer = LLMExplainer()
            for f in findings:
                expl = explainer.explain(f)
                if expl and Guardrails.validate_explanation(expl):
                    f.explanation = expl
            prog.progress(5/6, text="✓ AI analysis complete")

            # 6 — PDF
            st.write("**[6/6]** Building PDF report…")
            report = AnalysisReport(
                pcap_filename=safe_name, pcap_hash=file_hash,
                analysis_start=result["analysis_start"], analysis_end=result["analysis_end"],
                total_flows=stats["flow_count"], total_packets=stats["packet_count"],
                total_bytes=stats["bytes_total"], findings=findings,
            )
            pdf_path  = Path(tempfile.mktemp(suffix=".pdf"))
            json_path = Path(tempfile.mktemp(suffix=".json"))
            generate_pdf(report, pdf_path)
            json_path.write_text(report.to_json())
            result.update({"report": report, "pdf_path": pdf_path, "json_path": json_path})

            prog.progress(1.0, text="✓ Analysis complete!")
            status.update(label="Analysis complete!", state="complete")

    except Exception as e:
        st.error(f"Unexpected error: {e}")
        return None

    return result


# ── Sidebar ────────────────────────────────────────────────────────────────────
def _sidebar():
    with st.sidebar:
        st.markdown(
            '<div class="sl-logo">Forensi<em>Q</em></div>'
            '<div class="sl-sub">Network Threat Analysis</div>',
            unsafe_allow_html=True,
        )

        uploaded = st.file_uploader(
            "Upload PCAP",
            type=["pcap", "pcapng"],
            label_visibility="collapsed",
            help="Max 500 MB · .pcap and .pcapng supported",
        )
        if uploaded:
            st.caption(f"📎 {uploaded.name} · {_human_bytes(uploaded.size)}")

        run = st.button("Run Analysis", use_container_width=True, type="primary")
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("---")

        res = st.session_state.get("result")
        if res:
            st.markdown('<div class="sh">Downloads</div>', unsafe_allow_html=True)
            stem = res["safe_name"].rsplit(".", 1)[0]
            c1, c2 = st.columns(2)
            c1.download_button("PDF", data=res["pdf_path"].read_bytes(),
                               file_name=f"{stem}_forensiq.pdf", mime="application/pdf",
                               use_container_width=True)
            c2.download_button("JSON", data=res["json_path"].read_bytes(),
                               file_name=f"{stem}_forensiq.json", mime="application/json",
                               use_container_width=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown('<div class="sh">Severity Summary</div>', unsafe_allow_html=True)
            sev = res["report"].finding_count_by_severity
            for s in _SEV_ORDER:
                cnt = sev.get(s, 0)
                if cnt:
                    c = _SEV_COLOR[s]
                    st.markdown(
                        f'<div style="display:flex;align-items:center;justify-content:space-between;'
                        f'padding:5px 8px;background:var(--bg3);border-radius:6px;margin-bottom:5px;">'
                        f'<span style="color:{c};font-size:0.82rem;font-weight:600;">{_SEV_EMOJI[s]} {s}</span>'
                        f'<span style="color:var(--tx);font-weight:800;font-size:0.9rem;">{cnt}</span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("New Analysis", use_container_width=True):
                for k in ("result", "pcap_name"):
                    st.session_state.pop(k, None)
                st.rerun()

    return uploaded, run


# ── Dashboard tab ──────────────────────────────────────────────────────────────
def _tab_dashboard(report, safe_name, file_hash):
    import altair as alt
    import pandas as pd

    sev = report.finding_count_by_severity
    dur = report.duration_seconds

    # Metrics row
    cols = st.columns(5)
    for col, label, val in zip(cols, ["Flows","Packets","Bytes","Findings","Duration"],
                                [f"{report.total_flows:,}", f"{report.total_packets:,}",
                                 _human_bytes(report.total_bytes), str(len(report.findings)),
                                 f"{dur:.1f}s"]):
        col.metric(label, val)

    st.markdown("<br>", unsafe_allow_html=True)
    cl, cr = st.columns([3, 2])

    with cl:
        st.markdown('<div class="sh">Findings by Severity</div>', unsafe_allow_html=True)
        df = pd.DataFrame([{"Severity": s, "Count": sev.get(s, 0), "color": _SEV_COLOR[s]} for s in _SEV_ORDER])
        chart = (
            alt.Chart(df)
            .mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5)
            .encode(
                x=alt.X("Severity:N", sort=_SEV_ORDER,
                         axis=alt.Axis(labelColor="#475569", titleColor="#475569", labelFontSize=11)),
                y=alt.Y("Count:Q",
                         axis=alt.Axis(labelColor="#475569", titleColor="#475569",
                                       grid=True, gridColor="#1E2D45", labelFontSize=11)),
                color=alt.Color("color:N", scale=None, legend=None),
                tooltip=["Severity", "Count"],
            )
            .properties(height=230, background="#161D2F")
            .configure_view(stroke="#1E2D45")
            .configure_axis(domainColor="#1E2D45", tickColor="#1E2D45")
        )
        st.altair_chart(chart, use_container_width=True)

    with cr:
        st.markdown('<div class="sh">Risk Profile</div>', unsafe_allow_html=True)
        total = max(len(report.findings), 1)
        for s in _SEV_ORDER:
            cnt = sev.get(s, 0)
            pct = (cnt / total) * 100
            c = _SEV_COLOR[s]
            st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;margin-bottom:9px;">
  <span style="width:68px;color:{c};font-size:0.78rem;font-weight:600;">{s}</span>
  <div style="flex:1;background:var(--bg4);border-radius:99px;height:6px;overflow:hidden;">
    <div style="width:{pct:.0f}%;background:{c};height:100%;border-radius:99px;
      transition:width 1s ease;"></div>
  </div>
  <span style="width:18px;text-align:right;color:var(--tx);font-size:0.82rem;font-weight:700;">{cnt}</span>
</div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sh">File Details</div>', unsafe_allow_html=True)
        rows = [("Filename", safe_name),
                ("SHA-256", f'<code style="font-size:0.7rem;">{file_hash[:20]}…</code>'),
                ("Analyzed", report.analysis_start.strftime("%Y-%m-%d %H:%M"))]
        html = '<table style="width:100%;">'
        for k, v in rows:
            html += f'<tr><td style="color:var(--tx3);width:40%;padding:7px 0;">{k}</td><td>{v}</td></tr>'
        html += "</table>"
        st.markdown(html, unsafe_allow_html=True)


# ── Findings tab ───────────────────────────────────────────────────────────────
def _tab_findings(findings):
    if not findings:
        st.info("No threats detected in this PCAP file.")
        return

    col_filter, col_count = st.columns([4, 1])
    with col_filter:
        sev_filter = st.multiselect(
            "Severity", options=_SEV_ORDER, default=_SEV_ORDER, label_visibility="collapsed"
        )
    visible = [f for f in findings if f.severity.value in sev_filter]
    col_count.markdown(
        f'<div style="text-align:right;color:var(--tx3);font-size:0.82rem;padding-top:10px;">'
        f'{len(visible)} finding(s)</div>',
        unsafe_allow_html=True,
    )

    if not visible:
        st.info("No findings match the selected filter.")
        return

    for i, finding in enumerate(visible, 1):
        sev = finding.severity.value
        strip = _SEV_STRIP.get(sev, "")
        with st.expander(
            f"{_SEV_EMOJI.get(sev, '⚪')}  [{sev}]  {finding.title}",
            expanded=(i == 1 and sev in ("CRITICAL", "HIGH")),
        ):
            # Apply severity strip via extra div
            st.markdown(f'<div class="{strip}" style="margin:-8px -16px 12px;padding:0 0 0 12px;"></div>',
                        unsafe_allow_html=True)

            t1, t2, t3, t4 = st.tabs(["Overview", "Evidence", "AI Analysis", "Remediation"])

            with t1:
                oc1, oc2 = st.columns([1, 1])
                with oc1:
                    st.markdown('<div class="sh">Detection Details</div>', unsafe_allow_html=True)
                    details = [
                        ("Severity",     _sev_badge(sev)),
                        ("Rule",         f"<code>{finding.rule_name}</code>"),
                        ("MITRE ATT&CK", f'<code>{finding.mitre_technique}</code> — {finding.mitre_tactic}'),
                        ("Source IP",    finding.src_ip or "—"),
                        ("Target IP",    finding.dst_ip or "—"),
                        ("Timestamp",    str(finding.timestamp)[:19] if finding.timestamp else "—"),
                    ]
                    html = '<table style="width:100%;">'
                    for k, v in details:
                        html += (f'<tr><td style="color:var(--tx3);width:40%;padding:7px 14px;">{k}</td>'
                                 f'<td style="padding:7px 14px;">{v}</td></tr>')
                    html += "</table>"
                    st.markdown(html, unsafe_allow_html=True)

                with oc2:
                    st.markdown('<div class="sh">Network Flow</div>', unsafe_allow_html=True)
                    st.markdown(_flow_diagram(finding.src_ip or "?", finding.dst_ip or "?", sev),
                                unsafe_allow_html=True)
                    st.markdown(
                        f'<p style="color:var(--tx2);font-size:0.88rem;margin-top:12px;line-height:1.55;">'
                        f'{finding.description}</p>',
                        unsafe_allow_html=True,
                    )

            with t2:
                if not finding.evidence:
                    st.info("No evidence collected.")
                else:
                    ev = finding.evidence
                    ports_raw = ev.get("ports_scanned", "")
                    if ports_raw:
                        st.markdown('<div class="sh">Port Heatmap</div>', unsafe_allow_html=True)
                        st.markdown(_port_chips(str(ports_raw)), unsafe_allow_html=True)
                        st.markdown("<br>", unsafe_allow_html=True)
                    st.markdown('<div class="sh">Raw Evidence</div>', unsafe_allow_html=True)
                    html = '<table style="width:100%;">'
                    for k, v in ev.items():
                        html += (f'<tr><td style="color:var(--tx3);width:40%;padding:7px 14px;">{k}</td>'
                                 f'<td style="padding:7px 14px;"><code>{v}</code></td></tr>')
                    html += "</table>"
                    st.markdown(html, unsafe_allow_html=True)

            with t3:
                expl = getattr(finding, "explanation", None)
                if not expl:
                    st.info("No AI explanation available. Set GROQ_API_KEY to enable.")
                else:
                    sections = _parse_explanation(expl)
                    for label, key, icon in [("What Happened","what","📋"),
                                              ("Why It Matters","why","⚠️"),
                                              ("Actions Required","todo","✅")]:
                        content = sections.get(key, "").strip()
                        if content:
                            st.markdown(
                                f'<div style="background:var(--bg4);border:1px solid var(--br);'
                                f'border-radius:8px;padding:14px 16px;margin-bottom:12px;">'
                                f'<div style="color:var(--tx);font-weight:700;margin-bottom:8px;font-size:0.9rem;">'
                                f'{icon} {label}</div>'
                                f'<div style="color:var(--tx2);font-size:0.87rem;line-height:1.6;">'
                                f'{content.replace(chr(10),"<br>")}</div></div>',
                                unsafe_allow_html=True,
                            )

            with t4:
                expl = getattr(finding, "explanation", None)
                sections = _parse_explanation(expl) if expl else {}
                todo = sections.get("todo", "").strip()
                if todo:
                    c = _SEV_COLOR.get(sev, "#F97316")
                    st.markdown(
                        f'<div class="priority-box" style="border-left:3px solid {c};'
                        f'background:rgba(249,115,22,0.05);">'
                        f'<p style="color:var(--tx);font-weight:700;margin-bottom:10px;">Priority Actions</p>'
                        f'<div style="color:var(--tx2);font-size:0.87rem;line-height:1.6;">'
                        f'{todo.replace(chr(10),"<br>")}</div></div>',
                        unsafe_allow_html=True,
                    )
                else:
                    _generic_remediation(finding.rule_name)


# ── IOC tab ────────────────────────────────────────────────────────────────────
def _tab_iocs(findings):
    iocs, seen = [], set()
    for f in findings:
        for ioc in f.iocs:
            if ioc.value not in seen:
                seen.add(ioc.value)
                iocs.append({"value": ioc.value, "type": ioc.ioc_type.value,
                             "source": f.rule_name, "vt": ioc.vt_score or "—",
                             "mal": ioc.malicious})

    if not iocs:
        st.info("No IOCs extracted from findings.")
        return

    search = st.text_input("Search IOCs", placeholder="IP, domain…", label_visibility="collapsed")
    if search:
        iocs = [i for i in iocs if search.lower() in i["value"].lower()]

    html = ('<div class="ioc-table-wrap"><table><tr>'
            '<th>Value</th><th>Type</th><th>Source Rule</th><th>VT Score</th><th>Status</th>'
            '</tr>')
    for ioc in iocs:
        mal = '<span style="color:#F87171;font-weight:600;">Malicious</span>' if ioc["mal"] else '<span style="color:#4ADE80;">Clean</span>'
        html += (f'<tr><td><code style="color:var(--tx2);">{ioc["value"]}</code></td>'
                 f'<td style="color:var(--tx3);">{ioc["type"]}</td>'
                 f'<td><code>{ioc["source"]}</code></td>'
                 f'<td>{_vt_badge(ioc["vt"])}</td>'
                 f'<td>{mal}</td></tr>')
    html += '</table></div>'
    st.markdown(html, unsafe_allow_html=True)
    st.markdown(f'<div style="color:var(--tx3);font-size:0.78rem;margin-top:8px;">{len(iocs)} unique IOC(s)</div>',
                unsafe_allow_html=True)


# ── Raw JSON tab ───────────────────────────────────────────────────────────────
def _tab_raw(json_path):
    try:
        st.json(json.loads(json_path.read_text()), expanded=False)
    except Exception as e:
        st.error(f"Could not load JSON: {e}")


# ── Report header ──────────────────────────────────────────────────────────────
def _report_header(report, safe_name):
    sev = report.finding_count_by_severity
    top = next((s for s in _SEV_ORDER if sev.get(s, 0) > 0), None)
    badge = _sev_badge(top) if top else _badge("CLEAN", "badge-clean")

    chips = ""
    for s in _SEV_ORDER:
        cnt = sev.get(s, 0)
        if cnt:
            c = _SEV_COLOR[s]
            chips += (f'<div style="background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.06);'
                      f'border-radius:8px;padding:6px 14px;text-align:center;">'
                      f'<div style="font-size:1.2rem;font-weight:800;color:{c};">{cnt}</div>'
                      f'<div style="font-size:0.65rem;color:{c};opacity:0.8;text-transform:uppercase;'
                      f'letter-spacing:0.07em;font-weight:600;">{s}</div></div>')

    st.markdown(f"""
<div style="background:var(--bg3);border:1px solid var(--br);border-radius:14px;
  padding:20px 24px;margin-bottom:20px;animation:fadeInUp 0.4s ease;">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px;">
    <div>
      <div style="font-size:1.15rem;font-weight:700;color:var(--tx);margin-bottom:3px;">
        Analysis Report &nbsp;{badge}
      </div>
      <div style="font-size:0.78rem;color:var(--tx3);font-family:'JetBrains Mono',monospace;">
        {safe_name} · {len(report.findings)} finding(s) · {report.duration_seconds:.1f}s
      </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">{chips}</div>
  </div>
</div>""", unsafe_allow_html=True)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    uploaded, run_clicked = _sidebar()
    if "result" not in st.session_state:
        st.session_state["result"] = None

    if run_clicked and uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded.name).suffix) as tmp:
            tmp.write(uploaded.read())
        st.session_state["result"] = _run_analysis(Path(tmp.name))
        st.rerun()
    elif run_clicked and not uploaded:
        st.warning("Upload a PCAP file first.")

    res = st.session_state.get("result")
    if not res:
        _landing()
        return

    _report_header(res["report"], res["safe_name"])

    tab1, tab2, tab3, tab4 = st.tabs(["Dashboard", "Findings", "IOCs", "Raw JSON"])
    with tab1: _tab_dashboard(res["report"], res["safe_name"], res["file_hash"])
    with tab2: _tab_findings(res["report"].findings)
    with tab3: _tab_iocs(res["report"].findings)
    with tab4: _tab_raw(res["json_path"])


if __name__ == "__main__":
    main()
