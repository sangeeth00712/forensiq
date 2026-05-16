import sys
import json
import tempfile
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

st.set_page_config(
    page_title="ForensiQ",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Dark theme CSS ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* ── Global ── */
  html, body, [data-testid="stAppViewContainer"] {
    background-color: #0D1117;
    color: #C9D1D9;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  }
  [data-testid="stSidebar"] {
    background-color: #161B22;
    border-right: 1px solid #30363D;
  }
  /* ── Metric cards ── */
  [data-testid="metric-container"] {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 10px;
    padding: 16px 20px;
  }
  [data-testid="metric-container"] label {
    color: #8B949E !important;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  [data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: #E6EDF3 !important;
    font-size: 1.6rem;
    font-weight: 700;
  }
  /* ── Expanders ── */
  [data-testid="stExpander"] {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 8px;
    margin-bottom: 10px;
  }
  /* ── Tabs ── */
  [data-testid="stTabs"] button {
    color: #8B949E;
    font-size: 0.85rem;
  }
  [data-testid="stTabs"] button[aria-selected="true"] {
    color: #E94560;
    border-bottom: 2px solid #E94560;
  }
  /* ── Buttons ── */
  [data-testid="stButton"] button {
    background: linear-gradient(135deg, #E94560, #C0392B);
    color: #fff;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 0.5rem 1.5rem;
    transition: opacity 0.2s;
  }
  [data-testid="stButton"] button:hover { opacity: 0.85; }
  /* ── File uploader ── */
  [data-testid="stFileUploader"] {
    background-color: #0D1117;
    border: 1px dashed #30363D;
    border-radius: 8px;
  }
  /* ── Tables ── */
  table { border-collapse: collapse; width: 100%; }
  th {
    background-color: #1A1A2E;
    color: #E6EDF3;
    padding: 10px 14px;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  td {
    padding: 9px 14px;
    border-bottom: 1px solid #21262D;
    font-size: 0.88rem;
    color: #C9D1D9;
  }
  tr:hover td { background-color: #1C2128; }
  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #0D1117; }
  ::-webkit-scrollbar-thumb { background: #30363D; border-radius: 3px; }
  /* ── Divider ── */
  hr { border-color: #21262D; }
  /* ── Code blocks ── */
  code { background: #161B22; border-radius: 4px; padding: 2px 6px; color: #79C0FF; }
  /* ── Download buttons ── */
  .dl-btn a {
    display: inline-block;
    background: #161B22;
    color: #58A6FF !important;
    border: 1px solid #30363D;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 0.85rem;
    font-weight: 500;
    text-decoration: none;
    transition: background 0.2s;
  }
  .dl-btn a:hover { background: #1C2128; }
  /* ── Status badge ── */
  .badge {
    display: inline-block;
    border-radius: 20px;
    padding: 2px 10px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.04em;
  }
  .badge-crit { background: #4A0E0E; color: #FF6B6B; }
  .badge-high { background: #4A2B0E; color: #FFA94D; }
  .badge-med  { background: #4A3D0E; color: #FFD43B; }
  .badge-low  { background: #0E3A1A; color: #69DB7C; }
  .badge-info { background: #0E2A4A; color: #74C0FC; }
  /* ── Flow diagram ── */
  .flow-wrap {
    background: #0D1117;
    border: 1px solid #21262D;
    border-radius: 8px;
    padding: 14px;
    text-align: center;
    font-family: monospace;
  }
  /* ── Priority box ── */
  .priority-box {
    border-left: 4px solid #E94560;
    background: #1A1020;
    border-radius: 0 8px 8px 0;
    padding: 12px 16px;
    margin-bottom: 12px;
  }
  /* ── Section header ── */
  .section-head {
    color: #8B949E;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 6px;
  }
  /* ── Logo text ── */
  .logo-text {
    font-size: 1.5rem;
    font-weight: 800;
    color: #E6EDF3;
    letter-spacing: -0.03em;
  }
  .logo-accent { color: #E94560; }
  /* ── Landing cards ── */
  .landing-card {
    background: #161B22;
    border: 1px solid #30363D;
    border-radius: 12px;
    padding: 24px;
    height: 100%;
  }
  .landing-card h3 { color: #E6EDF3; margin-bottom: 8px; }
  .landing-card p  { color: #8B949E; font-size: 0.9rem; }
  .step-num {
    background: #E94560;
    color: #fff;
    border-radius: 50%;
    width: 28px; height: 28px;
    display: inline-flex;
    align-items: center; justify-content: center;
    font-weight: 700; font-size: 0.9rem;
    margin-bottom: 10px;
  }
</style>
""", unsafe_allow_html=True)

# ── Severity helpers ───────────────────────────────────────────────────────────
_SEV_EMOJI  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
_SEV_CLASS  = {"CRITICAL": "badge-crit", "HIGH": "badge-high", "MEDIUM": "badge-med", "LOW": "badge-low"}
_SEV_COLOR  = {"CRITICAL": "#FF6B6B", "HIGH": "#FFA94D", "MEDIUM": "#FFD43B", "LOW": "#69DB7C"}
_SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _badge(text: str, cls: str) -> str:
    return f'<span class="badge {cls}">{text}</span>'


def _sev_badge(sev: str) -> str:
    return _badge(sev, _SEV_CLASS.get(sev, "badge-info"))


# ── Core pipeline ──────────────────────────────────────────────────────────────
def _run_analysis(pcap_path: Path):
    from core.validator import validate_pcap_file, ValidationError
    from core.parser import parse_pcap, PcapParseError
    from core.models import AnalysisReport
    from detection.engine import DetectionEngine
    from enrichment.enricher import Enricher
    from ai.explainer import LLMExplainer, Guardrails
    from output.report import generate_pdf

    steps = [
        ("Validating file…",        "validate"),
        ("Parsing PCAP…",           "parse"),
        ("Running detection rules…","detect"),
        ("Enriching with threat intel…", "enrich"),
        ("Generating AI explanations…",  "ai"),
        ("Building PDF report…",    "pdf"),
    ]

    result = {}
    progress = st.progress(0, text="Starting analysis…")
    status   = st.status("Running ForensiQ analysis…", expanded=True)

    try:
        with status:
            # 1 — validate
            st.write("**[1/6]** Validating file…")
            try:
                safe_name, file_hash = validate_pcap_file(pcap_path)
            except ValidationError as e:
                st.error(f"Validation failed: {e}")
                return None
            result["safe_name"]  = safe_name
            result["file_hash"]  = file_hash
            progress.progress(1/6, text="File validated")

            # 2 — parse
            st.write("**[2/6]** Parsing PCAP…")
            analysis_start = datetime.now()
            try:
                flows, stats = parse_pcap(pcap_path)
            except PcapParseError as e:
                st.error(f"Parse failed: {e}")
                return None
            result["flows"]  = flows
            result["stats"]  = stats
            progress.progress(2/6, text=f"Parsed {stats['flow_count']:,} flows")

            # 3 — detect
            st.write("**[3/6]** Running detection rules…")
            engine   = DetectionEngine()
            findings = engine.run(flows)
            analysis_end = datetime.now()
            result["analysis_start"] = analysis_start
            result["analysis_end"]   = analysis_end
            progress.progress(3/6, text=f"Detected {len(findings)} findings")

            # 4 — enrich
            st.write("**[4/6]** Enriching with threat intel…")
            enricher = Enricher()
            findings = enricher.enrich_all(findings)
            progress.progress(4/6, text="Enrichment complete")

            # 5 — AI
            st.write("**[5/6]** Generating AI explanations…")
            explainer = LLMExplainer()
            for f in findings:
                expl = explainer.explain(f)
                if expl and Guardrails.validate_explanation(expl):
                    f.explanation = expl
            progress.progress(5/6, text="AI explanations generated")

            # 6 — build report + PDF
            st.write("**[6/6]** Building PDF report…")
            report = AnalysisReport(
                pcap_filename=safe_name,
                pcap_hash=file_hash,
                analysis_start=analysis_start,
                analysis_end=analysis_end,
                total_flows=stats["flow_count"],
                total_packets=stats["packet_count"],
                total_bytes=stats["bytes_total"],
                findings=findings,
            )

            pdf_path  = Path(tempfile.mktemp(suffix=".pdf"))
            json_path = Path(tempfile.mktemp(suffix=".json"))
            generate_pdf(report, pdf_path)
            json_path.write_text(report.to_json())

            result["report"]    = report
            result["pdf_path"]  = pdf_path
            result["json_path"] = json_path
            progress.progress(1.0, text="Analysis complete!")
            status.update(label="Analysis complete!", state="complete")

    except Exception as e:
        st.error(f"Unexpected error: {e}")
        return None

    return result


# ── Sidebar ────────────────────────────────────────────────────────────────────
def _sidebar():
    with st.sidebar:
        st.markdown('<div class="logo-text">Forensi<span class="logo-accent">Q</span></div>', unsafe_allow_html=True)
        st.markdown('<p style="color:#8B949E;font-size:0.8rem;margin-top:-6px;margin-bottom:20px;">Evidence-Driven Network Forensics</p>', unsafe_allow_html=True)
        st.markdown("---")

        uploaded = st.file_uploader(
            "Upload PCAP file",
            type=["pcap", "pcapng"],
            help="Max 500 MB. Both .pcap and .pcapng formats supported.",
            label_visibility="visible",
        )

        run_clicked = st.button("Run Analysis", use_container_width=True, type="primary")

        st.markdown("---")

        # Download buttons (shown only when results exist)
        if st.session_state.get("result"):
            res = st.session_state["result"]
            st.markdown('<p class="section-head">Downloads</p>', unsafe_allow_html=True)

            pdf_bytes  = res["pdf_path"].read_bytes()
            json_bytes = res["json_path"].read_bytes()
            stem = res["safe_name"].replace(".pcap", "").replace(".pcapng", "")

            st.download_button(
                "⬇ Download PDF Report",
                data=pdf_bytes,
                file_name=f"{stem}_forensiq.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
            st.download_button(
                "⬇ Download JSON Report",
                data=json_bytes,
                file_name=f"{stem}_forensiq.json",
                mime="application/json",
                use_container_width=True,
            )

            st.markdown("---")

            report = res["report"]
            sev = report.finding_count_by_severity
            st.markdown('<p class="section-head">Summary</p>', unsafe_allow_html=True)
            for s in _SEV_ORDER:
                cnt = sev.get(s, 0)
                if cnt:
                    col_a, col_b = st.columns([3, 1])
                    col_a.markdown(f'<span style="color:{_SEV_COLOR[s]};font-size:0.85rem;">{_SEV_EMOJI[s]} {s}</span>', unsafe_allow_html=True)
                    col_b.markdown(f'<span style="color:#E6EDF3;font-weight:700;">{cnt}</span>', unsafe_allow_html=True)

            st.markdown("---")
            if st.button("Clear Results", use_container_width=True):
                st.session_state.pop("result", None)
                st.session_state.pop("pcap_name", None)
                st.rerun()

    return uploaded, run_clicked


# ── Landing page ───────────────────────────────────────────────────────────────
def _landing():
    st.markdown("""
<div style="text-align:center; padding:40px 0 30px;">
  <div style="font-size:3rem;font-weight:900;color:#E6EDF3;letter-spacing:-0.04em;">
    Forensi<span style="color:#E94560;">Q</span>
  </div>
  <p style="color:#8B949E;font-size:1.1rem;margin-top:6px;">
    Evidence-driven network threat detection &amp; forensics
  </p>
</div>
""", unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    cards = [
        ("1", "Upload", "Drop a .pcap or .pcapng file in the sidebar to get started. Files up to 500 MB are supported."),
        ("2", "Analyze", "ForensiQ validates, parses, and runs 5 detection rules powered by ML confidence scoring."),
        ("3", "Investigate", "Browse findings, IOCs, AI-generated explanations, and download a professional PDF report."),
    ]
    for col, (n, title, desc) in zip([c1, c2, c3], cards):
        col.markdown(f"""
<div class="landing-card">
  <div class="step-num">{n}</div>
  <h3>{title}</h3>
  <p>{desc}</p>
</div>
""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
<div style="text-align:center;">
  <p style="color:#8B949E;font-size:0.85rem;">
    Detects: Port Scans · Brute Force · C2 Beaconing · Data Exfiltration · DNS Tunneling
  </p>
</div>
""", unsafe_allow_html=True)


# ── Dashboard tab ──────────────────────────────────────────────────────────────
def _tab_dashboard(report, safe_name, file_hash):
    import altair as alt
    import pandas as pd

    # Metric row
    dur = report.duration_seconds
    sev = report.finding_count_by_severity

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Flows",    f"{report.total_flows:,}")
    m2.metric("Packets",  f"{report.total_packets:,}")
    m3.metric("Bytes",    _human_bytes(report.total_bytes))
    m4.metric("Findings", len(report.findings))
    m5.metric("Duration", f"{dur:.1f}s")

    st.markdown("<br>", unsafe_allow_html=True)

    col_left, col_right = st.columns([2, 1])

    # Severity bar chart
    with col_left:
        st.markdown('<p class="section-head">Findings by Severity</p>', unsafe_allow_html=True)
        sev_data = pd.DataFrame([
            {"Severity": s, "Count": sev.get(s, 0), "color": _SEV_COLOR[s]}
            for s in _SEV_ORDER
        ])
        chart = (
            alt.Chart(sev_data)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X("Severity:N", sort=_SEV_ORDER, axis=alt.Axis(labelColor="#8B949E", titleColor="#8B949E")),
                y=alt.Y("Count:Q", axis=alt.Axis(labelColor="#8B949E", titleColor="#8B949E", grid=True, gridColor="#21262D")),
                color=alt.Color("color:N", scale=None, legend=None),
                tooltip=["Severity", "Count"],
            )
            .properties(height=220, background="#161B22")
            .configure_view(stroke="#30363D")
        )
        st.altair_chart(chart, use_container_width=True)

    # File info
    with col_right:
        st.markdown('<p class="section-head">File Information</p>', unsafe_allow_html=True)
        rows = [
            ("Filename", safe_name),
            ("SHA-256",  f'<code style="font-size:0.72rem;">{file_hash[:16]}…</code>'),
            ("Analysis", report.analysis_start.strftime("%Y-%m-%d %H:%M:%S")),
        ]
        html = '<table style="width:100%;">'
        for k, v in rows:
            html += f'<tr><td style="color:#8B949E;width:45%;">{k}</td><td>{v}</td></tr>'
        html += "</table>"
        st.markdown(html, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<p class="section-head">Risk Profile</p>', unsafe_allow_html=True)
        for s in _SEV_ORDER:
            cnt = sev.get(s, 0)
            pct = (cnt / max(len(report.findings), 1)) * 100
            st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
  <span style="width:64px;color:{_SEV_COLOR[s]};font-size:0.8rem;">{s}</span>
  <div style="flex:1;background:#21262D;border-radius:4px;height:8px;overflow:hidden;">
    <div style="width:{pct:.0f}%;background:{_SEV_COLOR[s]};height:100%;border-radius:4px;"></div>
  </div>
  <span style="width:20px;text-align:right;color:#E6EDF3;font-size:0.8rem;">{cnt}</span>
</div>
""", unsafe_allow_html=True)


# ── Findings tab ───────────────────────────────────────────────────────────────
def _tab_findings(findings):
    if not findings:
        st.info("No threats detected in this PCAP file.")
        return

    # Filter row
    col_f1, col_f2 = st.columns([3, 1])
    with col_f2:
        sev_filter = st.multiselect(
            "Filter by severity",
            options=_SEV_ORDER,
            default=_SEV_ORDER,
            label_visibility="collapsed",
        )

    visible = [f for f in findings if f.severity.value in sev_filter]

    if not visible:
        st.info("No findings match the selected severity filter.")
        return

    for i, finding in enumerate(visible, 1):
        sev  = finding.severity.value
        icon = _SEV_EMOJI.get(sev, "⚪")

        with st.expander(f"{icon} [{sev}]  {finding.title}", expanded=(i == 1 and sev in ("CRITICAL", "HIGH"))):
            t_overview, t_evidence, t_ai, t_remediation = st.tabs(
                ["Overview", "Evidence", "AI Analysis", "Remediation"]
            )

            # ─ Overview ───────────────────────────────────────────────────────
            with t_overview:
                oc1, oc2 = st.columns([1, 1])
                with oc1:
                    st.markdown('<p class="section-head">Detection Details</p>', unsafe_allow_html=True)
                    details = [
                        ("Severity",    _sev_badge(sev)),
                        ("Rule",        f"<code>{finding.rule_name}</code>"),
                        ("MITRE ATT&CK",f'<code>{finding.mitre_technique}</code> — {finding.mitre_tactic}'),
                        ("Source IP",   finding.src_ip),
                        ("Target IP",   finding.dst_ip),
                        ("Detected At", str(finding.timestamp)[:19] if finding.timestamp else "—"),
                    ]
                    html = '<table style="width:100%;">'
                    for k, v in details:
                        html += f'<tr><td style="color:#8B949E;width:40%;">{k}</td><td>{v}</td></tr>'
                    html += "</table>"
                    st.markdown(html, unsafe_allow_html=True)

                with oc2:
                    st.markdown('<p class="section-head">Network Flow</p>', unsafe_allow_html=True)
                    st.markdown(_flow_diagram(finding.src_ip, finding.dst_ip, sev), unsafe_allow_html=True)
                    st.markdown("<br>", unsafe_allow_html=True)
                    st.markdown(f'<p style="color:#C9D1D9;font-size:0.9rem;">{finding.description}</p>', unsafe_allow_html=True)

            # ─ Evidence ───────────────────────────────────────────────────────
            with t_evidence:
                if not finding.evidence:
                    st.info("No evidence collected.")
                else:
                    ev = finding.evidence
                    ports_raw = ev.get("ports_scanned", "")
                    if ports_raw:
                        st.markdown('<p class="section-head">Port Heatmap</p>', unsafe_allow_html=True)
                        st.markdown(_port_heatmap_html(str(ports_raw)), unsafe_allow_html=True)
                        st.markdown("<br>", unsafe_allow_html=True)

                    st.markdown('<p class="section-head">Raw Evidence</p>', unsafe_allow_html=True)
                    html = '<table style="width:100%;">'
                    for k, v in ev.items():
                        html += f'<tr><td style="color:#8B949E;width:40%;">{k}</td><td><code>{v}</code></td></tr>'
                    html += "</table>"
                    st.markdown(html, unsafe_allow_html=True)

            # ─ AI Analysis ────────────────────────────────────────────────────
            with t_ai:
                expl = getattr(finding, "explanation", None)
                if not expl:
                    st.info("No AI explanation available. Set GROQ_API_KEY in .env to enable.")
                else:
                    sections = _parse_explanation(expl)
                    for label, key, icon in [
                        ("What Happened", "what", "📋"),
                        ("Why It Matters", "why",  "⚠️"),
                        ("Actions Required", "todo", "✅"),
                    ]:
                        content = sections.get(key, "").strip()
                        if content:
                            st.markdown(f"**{icon} {label}**")
                            st.markdown(f'<div style="background:#161B22;border:1px solid #30363D;border-radius:8px;padding:14px;margin-bottom:12px;color:#C9D1D9;font-size:0.9rem;">{content}</div>', unsafe_allow_html=True)

            # ─ Remediation ────────────────────────────────────────────────────
            with t_remediation:
                expl = getattr(finding, "explanation", None)
                sections = _parse_explanation(expl) if expl else {}
                todo = sections.get("todo", "").strip()
                if todo:
                    border = _SEV_COLOR.get(sev, "#E94560")
                    st.markdown(f"""
<div style="border-left:4px solid {border};background:#1A1020;border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:12px;">
  <p style="color:#E6EDF3;font-weight:700;margin-bottom:8px;">Priority Actions</p>
  <div style="color:#C9D1D9;font-size:0.9rem;">{todo.replace(chr(10), "<br>")}</div>
</div>
""", unsafe_allow_html=True)
                else:
                    _generic_remediation(finding.rule_name)


# ── IOC tab ────────────────────────────────────────────────────────────────────
def _tab_iocs(findings):
    all_iocs = []
    for f in findings:
        for ioc in f.iocs:
            all_iocs.append({
                "Value":    ioc.value,
                "Type":     ioc.ioc_type.value,
                "Source":   f.rule_name,
                "VT Score": ioc.vt_score or "—",
                "Malicious":ioc.malicious,
            })

    if not all_iocs:
        st.info("No IOCs extracted from findings.")
        return

    # Deduplicate by value
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        if ioc["Value"] not in seen:
            seen.add(ioc["Value"])
            unique_iocs.append(ioc)

    search = st.text_input("Search IOCs…", placeholder="IP address, domain…", label_visibility="collapsed")
    if search:
        unique_iocs = [i for i in unique_iocs if search.lower() in i["Value"].lower()]

    html  = "<table style='width:100%;'>"
    html += "<tr><th>Value</th><th>Type</th><th>Source Rule</th><th>VT Score</th><th>Malicious</th></tr>"
    for ioc in unique_iocs:
        mal_cell = '<span style="color:#FF6B6B;">Yes</span>' if ioc["Malicious"] else '<span style="color:#69DB7C;">No</span>'
        vt_cell  = _vt_badge_html(ioc["VT Score"])
        html += f"<tr><td><code>{ioc['Value']}</code></td><td>{ioc['Type']}</td><td><code>{ioc['Source']}</code></td><td>{vt_cell}</td><td>{mal_cell}</td></tr>"
    html += "</table>"
    st.markdown(html, unsafe_allow_html=True)
    st.markdown(f'<p style="color:#8B949E;font-size:0.8rem;margin-top:8px;">{len(unique_iocs)} unique IOCs</p>', unsafe_allow_html=True)


# ── Raw JSON tab ───────────────────────────────────────────────────────────────
def _tab_raw(json_path):
    st.markdown('<p class="section-head">JSON Report</p>', unsafe_allow_html=True)
    try:
        data = json.loads(json_path.read_text())
        st.json(data, expanded=False)
    except Exception as e:
        st.error(f"Could not load JSON: {e}")


# ── Helpers ────────────────────────────────────────────────────────────────────
def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _flow_diagram(src: str, dst: str, sev: str) -> str:
    color = _SEV_COLOR.get(sev, "#E94560")
    return f"""
<div class="flow-wrap">
  <span style="background:#1A1A2E;border:1px solid #30363D;border-radius:6px;padding:6px 14px;color:#79C0FF;">{src}</span>
  <span style="color:{color};margin:0 12px;font-size:1.2rem;">&#x2192;&#x2192;&#x2192;</span>
  <span style="background:#2A0A0A;border:1px solid {color};border-radius:6px;padding:6px 14px;color:{color};">{dst}</span>
  <br><span style="color:#8B949E;font-size:0.75rem;margin-top:6px;display:inline-block;">ATTACKER → TARGET</span>
</div>
"""


def _vt_badge_html(score: str) -> str:
    if score == "—" or not score:
        return '<span style="color:#8B949E;">—</span>'
    try:
        detected, total = map(int, score.split("/"))
        ratio = detected / total if total else 0
        if ratio > 0.3:
            color = "#FF6B6B"
        elif ratio > 0:
            color = "#FFA94D"
        else:
            color = "#69DB7C"
        return f'<span style="color:{color};font-weight:600;">{score}</span>'
    except Exception:
        return f'<span style="color:#8B949E;">{score}</span>'


def _port_heatmap_html(ports_str: str) -> str:
    _CRITICAL = {21, 22, 23, 25, 53, 3389, 445, 135, 139}
    _DATABASE = {3306, 5432, 1433, 1521, 27017, 6379}
    _MALWARE  = {4444, 1337, 31337, 8080, 8888}

    chips = []
    try:
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
    except Exception:
        return f"<code>{ports_str}</code>"

    for p in sorted(ports)[:40]:
        if p in _CRITICAL:
            bg, fg = "#4A0E0E", "#FF6B6B"
        elif p in _DATABASE:
            bg, fg = "#0E2A4A", "#74C0FC"
        elif p in _MALWARE:
            bg, fg = "#3D0E4A", "#DA77F2"
        else:
            bg, fg = "#1C2128", "#8B949E"
        chips.append(f'<span style="background:{bg};color:{fg};border-radius:4px;padding:3px 8px;margin:3px;display:inline-block;font-size:0.78rem;font-family:monospace;">{p}</span>')

    if len(ports) > 40:
        chips.append(f'<span style="color:#8B949E;font-size:0.78rem;margin:3px;">+{len(ports)-40} more</span>')

    legend = (
        '<div style="margin-top:8px;display:flex;gap:16px;flex-wrap:wrap;">'
        '<span style="color:#FF6B6B;font-size:0.75rem;">■ Critical service</span>'
        '<span style="color:#74C0FC;font-size:0.75rem;">■ Database</span>'
        '<span style="color:#DA77F2;font-size:0.75rem;">■ Known malware port</span>'
        '<span style="color:#8B949E;font-size:0.75rem;">■ Other</span>'
        '</div>'
    )
    return '<div>' + "".join(chips) + legend + '</div>'


def _parse_explanation(text: str) -> dict:
    if not text:
        return {}
    result: dict = {"what": "", "why": "", "todo": ""}
    current = None
    buf: list = []
    for line in text.split("\n"):
        low = line.lower().strip()
        if "what happened" in low:
            current = "what"; buf = []
        elif "why it matters" in low:
            if current: result[current] = "\n".join(buf)
            current = "why"; buf = []
        elif "what to do" in low or "actions" in low or "remediation" in low:
            if current: result[current] = "\n".join(buf)
            current = "todo"; buf = []
        else:
            if current is not None:
                buf.append(line)
    if current:
        result[current] = "\n".join(buf)
    return result


def _generic_remediation(rule_name: str):
    recs = {
        "PORT_SCAN_DETECTED":     ["Block scanning IP at perimeter firewall", "Enable port-scan alerts in IDS/IPS", "Review exposed services"],
        "BRUTE_FORCE_DETECTED":   ["Enable account lockout policy", "Enforce MFA on targeted service", "Rate-limit authentication attempts"],
        "C2_BEACON_DETECTED":     ["Isolate the compromised host immediately", "Block C2 IPs/domains at DNS and firewall", "Run full malware scan"],
        "DATA_EXFILTRATION":      ["Block outbound traffic to destination IP", "Audit data access logs", "Engage incident response team"],
        "DNS_TUNNELING_DETECTED": ["Block DNS queries to suspicious domains", "Enable DNSSEC validation", "Monitor DNS query volume per host"],
    }
    items = recs.get(rule_name, ["Review logs", "Update firewall rules", "Escalate to security team"])
    html  = '<div style="border-left:4px solid #30363D;background:#161B22;border-radius:0 8px 8px 0;padding:14px 18px;">'
    html += '<p style="color:#8B949E;font-weight:700;margin-bottom:8px;">Recommended Actions</p><ol style="color:#C9D1D9;font-size:0.9rem;padding-left:20px;margin:0;">'
    for item in items:
        html += f"<li style='margin-bottom:6px;'>{item}</li>"
    html += "</ol></div>"
    st.markdown(html, unsafe_allow_html=True)


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    uploaded, run_clicked = _sidebar()

    if "result" not in st.session_state:
        st.session_state["result"] = None

    # Trigger analysis
    if run_clicked and uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded.name).suffix) as tmp:
            tmp.write(uploaded.read())
            tmp_path = Path(tmp.name)

        st.session_state["pcap_name"] = uploaded.name
        result = _run_analysis(tmp_path)
        st.session_state["result"] = result
        st.rerun()

    elif run_clicked and not uploaded:
        st.warning("Please upload a PCAP file first.")

    # ── Render results ──────────────────────────────────────────────────────────
    res = st.session_state.get("result")

    if res is None:
        _landing()
        return

    report    = res["report"]
    safe_name = res["safe_name"]
    file_hash = res["file_hash"]
    json_path = res["json_path"]

    # Page header
    sev       = report.finding_count_by_severity
    top_sev   = next((s for s in _SEV_ORDER if sev.get(s, 0) > 0), None)
    badge_html = _sev_badge(top_sev) if top_sev else _badge("CLEAN", "badge-info")

    st.markdown(f"""
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
  <div>
    <h2 style="color:#E6EDF3;margin:0;font-size:1.4rem;">Analysis Report</h2>
    <p style="color:#8B949E;margin:2px 0 0;font-size:0.85rem;">{safe_name}</p>
  </div>
  <div style="text-align:right;">
    {badge_html}
    <br><span style="color:#8B949E;font-size:0.75rem;">{len(report.findings)} finding(s)</span>
  </div>
</div>
""", unsafe_allow_html=True)

    tab_dash, tab_find, tab_ioc, tab_raw = st.tabs(["Dashboard", "Findings", "IOCs", "Raw JSON"])

    with tab_dash:
        _tab_dashboard(report, safe_name, file_hash)

    with tab_find:
        _tab_findings(report.findings)

    with tab_ioc:
        _tab_iocs(report.findings)

    with tab_raw:
        _tab_raw(json_path)


if __name__ == "__main__":
    main()
