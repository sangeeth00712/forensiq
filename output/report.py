from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

import config
from core.models import AnalysisReport, Finding, IOC
from core.logger import get_logger

logger = get_logger(__name__)

TOOL_VERSION = "1.0.0"
PAGE_W, PAGE_H = letter

C_NAVY   = colors.HexColor("#1A1A2E")
C_ACCENT = colors.HexColor("#E94560")
C_LGREY  = colors.HexColor("#F4F6F9")
C_MGREY  = colors.HexColor("#BDC3C7")
C_TEXT   = colors.HexColor("#2C3E50")
C_MUTED  = colors.HexColor("#95A5A6")
C_WHITE  = colors.white

SEV_BG = {
    "CRITICAL": colors.HexColor("#C0392B"),
    "HIGH":     colors.HexColor("#E67E22"),
    "MEDIUM":   colors.HexColor("#F39C12"),
    "LOW":      colors.HexColor("#27AE60"),
}

# Ports color-coded by risk tier
_PORT_CRITICAL  = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389}
_PORT_DATABASE  = {1433, 1521, 3306, 5432, 5900, 6379}
_PORT_MALWARE   = {4444, 6666, 6667, 6668, 8888, 9999, 1337, 31337}


# ── canvas callbacks ─────────────────────────────────────────────────────────

def _draw_watermark(canvas):
    w, h = letter
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#EEEEEE"))
    canvas.setFont("Helvetica-Bold", 58)
    canvas.translate(w / 2, h / 2)
    canvas.rotate(45)
    canvas.drawCentredString(0, 0, "CONFIDENTIAL")
    canvas.restoreState()


def _draw_title_page_canvas(canvas, doc):
    _draw_watermark(canvas)


def _draw_content_page(canvas, doc):
    _draw_watermark(canvas)
    w, h = letter
    canvas.saveState()
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, h - 0.55 * inch, w, 0.55 * inch, fill=1, stroke=0)
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(0.6 * inch, h - 0.34 * inch, "ForensiQ")
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(w - 0.6 * inch, h - 0.34 * inch, "CONFIDENTIAL — FORENSIC REPORT")
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, h - 0.58 * inch, w, 0.03 * inch, fill=1, stroke=0)
    canvas.setFillColor(C_LGREY)
    canvas.rect(0, 0, w, 0.42 * inch, fill=1, stroke=0)
    canvas.setFillColor(C_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.6 * inch, 0.15 * inch,
                      f"ForensiQ v{TOOL_VERSION}  |  {datetime.now().strftime('%Y-%m-%d')}")
    canvas.drawRightString(w - 0.6 * inch, 0.15 * inch, f"Page {doc.page}")
    canvas.restoreState()


# ── styles ────────────────────────────────────────────────────────────────────

def _build_styles() -> Dict[str, ParagraphStyle]:
    return {
        "h1":           ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=18,
                                       textColor=C_NAVY, spaceAfter=8),
        "h2":           ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13,
                                       textColor=C_NAVY, spaceBefore=6, spaceAfter=6),
        "body":         ParagraphStyle("body", fontName="Helvetica", fontSize=10,
                                       textColor=C_TEXT, leading=14, spaceAfter=4),
        "small":        ParagraphStyle("small", fontName="Helvetica", fontSize=8,
                                       textColor=C_MUTED, leading=11),
        "mono":         ParagraphStyle("mono", fontName="Courier", fontSize=9,
                                       textColor=C_TEXT, leading=12),
        "label":        ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8,
                                       textColor=C_MUTED, spaceAfter=2),
        "key":          ParagraphStyle("key", fontName="Helvetica-Bold", fontSize=10,
                                       textColor=C_MUTED),
        "val":          ParagraphStyle("val", fontName="Helvetica", fontSize=10,
                                       textColor=C_TEXT),
        "white_title":  ParagraphStyle("white_title", fontName="Helvetica-Bold",
                                       fontSize=36, textColor=C_WHITE, alignment=TA_CENTER),
        "white_sub":    ParagraphStyle("white_sub", fontName="Helvetica", fontSize=13,
                                       textColor=colors.HexColor("#A0AEC0"),
                                       alignment=TA_CENTER),
        "muted_center": ParagraphStyle("muted_center", fontName="Helvetica", fontSize=8,
                                       textColor=C_MUTED, alignment=TA_CENTER),
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_explanation(text: str) -> Dict[str, str]:
    sections: Dict[str, str] = {"what": "", "why": "", "todo": ""}
    if not text:
        return sections
    current, buf = None, []
    for line in text.splitlines():
        low = line.strip().lower()
        if "what happened" in low:
            current, buf = "what", []
        elif "why it matters" in low:
            sections["what"] = " ".join(buf).strip()
            current, buf = "why", []
        elif "what to do" in low:
            sections["why"] = " ".join(buf).strip()
            current, buf = "todo", []
        elif current and line.strip():
            buf.append(line.strip())
    if current:
        sections[current] = ("\n".join(buf) if current == "todo"
                             else " ".join(buf).strip())
    return sections


def _kv_table(rows: List[tuple], styles: Dict, col_widths=None) -> Table:
    usable = PAGE_W - 1.5 * inch
    if col_widths is None:
        col_widths = [2.0 * inch, usable - 2.0 * inch]
    data = [[Paragraph(str(k), styles["key"]), Paragraph(str(v), styles["val"])]
            for k, v in rows]
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_LGREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_MGREY),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _section_title(text: str, styles: Dict) -> List:
    return [
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=4),
        Paragraph(text, styles["h2"]),
    ]


def _navy_header_table(rows_data, col_widths, header_color=None) -> Table:
    hc = header_color or C_NAVY
    t = Table(rows_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), hc),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LGREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_MGREY),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


# ── Feature 1: Severity Pie Chart ─────────────────────────────────────────────

def _severity_pie(sev_counts: Dict[str, int]) -> Drawing:
    data = [(k, v) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if (v := sev_counts.get(k, 0)) > 0]
    if not data:
        data = [("CLEAN", 1)]
        pie_colors = [colors.HexColor("#27AE60")]
    else:
        pie_colors = [SEV_BG[k] for k, _ in data]

    d = Drawing(180, 140)
    pie = Pie()
    pie.x = 10
    pie.y = 15
    pie.width = 110
    pie.height = 110
    pie.data = [v for _, v in data]
    pie.labels = [f"{k}\n{v}" for k, v in data]
    pie.sideLabels = True
    pie.sideLabelsOffset = 0.08
    for i, c in enumerate(pie_colors):
        pie.slices[i].fillColor = c
        pie.slices[i].strokeColor = C_WHITE
        pie.slices[i].strokeWidth = 1.5
        pie.slices.labelRadius = 1.15
    d.add(pie)
    return d


# ── Feature 2: Network Flow Diagram ───────────────────────────────────────────

def _network_diagram(src_ip: str, dst_ip: str, rule_name: str) -> Drawing:
    w, h = 460, 70
    d = Drawing(w, h)

    # Attacker box
    d.add(Rect(5, 18, 120, 34, fillColor=SEV_BG["HIGH"],
               strokeColor=None, rx=4, ry=4))
    d.add(String(65, 38, "ATTACKER", fontSize=9, textAnchor="middle",
                 fillColor=C_WHITE, fontName="Helvetica-Bold"))
    d.add(String(65, 25, src_ip, fontSize=7, textAnchor="middle",
                 fillColor=colors.HexColor("#FFE0C0"), fontName="Helvetica"))

    # Arrow shaft
    d.add(Line(125, 35, 330, 35, strokeColor=C_ACCENT, strokeWidth=2))
    # Arrowhead
    d.add(Polygon([330, 35, 320, 29, 320, 41],
                  fillColor=C_ACCENT, strokeColor=None))
    # Label above arrow
    label = rule_name.replace("_DETECTED", "").replace("_", " ")
    d.add(String(227, 44, label, fontSize=7, textAnchor="middle",
                 fillColor=C_ACCENT, fontName="Helvetica-Bold"))

    # Target box
    d.add(Rect(335, 18, 120, 34, fillColor=C_NAVY,
               strokeColor=None, rx=4, ry=4))
    d.add(String(395, 38, "TARGET", fontSize=9, textAnchor="middle",
                 fillColor=C_WHITE, fontName="Helvetica-Bold"))
    d.add(String(395, 25, dst_ip, fontSize=7, textAnchor="middle",
                 fillColor=colors.HexColor("#A0AEC0"), fontName="Helvetica"))

    return d


# ── Feature 3: MITRE Badge ────────────────────────────────────────────────────

def _mitre_badge(technique_id: str, tactic: str, styles: Dict) -> Table:
    badge_sty = ParagraphStyle("mb", fontName="Helvetica-Bold", fontSize=9,
                               textColor=C_WHITE, alignment=TA_CENTER)
    tactic_sty = ParagraphStyle("mt", fontName="Helvetica", fontSize=10,
                                textColor=C_TEXT)
    t = Table(
        [[Paragraph(technique_id, badge_sty),
          Paragraph(tactic, tactic_sty)]],
        colWidths=[0.75 * inch, PAGE_W - 1.5 * inch - 2.0 * inch - 0.75 * inch],
    )
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), C_NAVY),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (0, 0), 6),
        ("RIGHTPADDING", (0, 0), (0, 0), 6),
        ("LEFTPADDING", (1, 0), (1, 0), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


# ── Feature 4: VT Score Badge ─────────────────────────────────────────────────

def _vt_badge(score_str: Optional[str]) -> Paragraph:
    if not score_str or score_str == "—":
        return Paragraph("—", ParagraphStyle("vtn", fontName="Helvetica",
                                              fontSize=8, textColor=C_MUTED))
    try:
        detected, total = (int(x) for x in score_str.split("/"))
        ratio = detected / total if total else 0
        if ratio >= 0.3:
            c = SEV_BG["CRITICAL"]
        elif ratio > 0:
            c = SEV_BG["MEDIUM"]
        else:
            c = colors.HexColor("#27AE60")
    except (ValueError, ZeroDivisionError):
        return Paragraph(score_str, ParagraphStyle("vtx", fontName="Helvetica",
                                                    fontSize=8, textColor=C_MUTED))
    return Paragraph(
        f'<font color="#{c.hexval()[2:]}">{score_str}</font>',
        ParagraphStyle("vtb", fontName="Helvetica-Bold", fontSize=9, textColor=c),
    )


# ── Feature 5: Priority Action Box ───────────────────────────────────────────

def _priority_box(todo_text: str, sev: str, styles: Dict) -> Table:
    lines = [l.strip() for l in todo_text.splitlines() if l.strip()][:3]
    if not lines:
        return None
    usable = PAGE_W - 1.5 * inch
    bg = SEV_BG.get(sev, C_NAVY)
    header_sty = ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=10,
                                 textColor=C_WHITE)
    item_sty = ParagraphStyle("pi", fontName="Helvetica", fontSize=9,
                               textColor=C_WHITE, leading=14)
    rows = [[Paragraph("⚡  PRIORITY ACTIONS — Next 24 Hours", header_sty)]]
    for line in lines:
        rows.append([Paragraph(f"  {line}", item_sty)])
    t = Table(rows, colWidths=[usable])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("TOPPADDING", (0, 0), (0, 0), 10),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
        ("TOPPADDING", (0, 1), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -2), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#FFFFFF40")),
    ]))
    return t


# ── Feature 6: Port Heatmap ───────────────────────────────────────────────────

def _port_heatmap(ports: List[int], styles: Dict) -> Table:
    usable = PAGE_W - 1.5 * inch
    chip_w = 0.72 * inch
    cols = int(usable / chip_w)

    def _port_color(p: int):
        if p in _PORT_MALWARE:
            return SEV_BG["CRITICAL"], C_WHITE
        if p in _PORT_DATABASE:
            return SEV_BG["MEDIUM"], C_WHITE
        if p in _PORT_CRITICAL:
            return SEV_BG["HIGH"], C_WHITE
        return C_LGREY, C_TEXT

    chips = []
    for port in sorted(ports):
        bg, fg = _port_color(port)
        chips.append((str(port), bg, fg))

    # Pad to fill last row
    while len(chips) % cols:
        chips.append(("", C_WHITE, C_WHITE))

    rows = []
    for i in range(0, len(chips), cols):
        row = []
        for label, bg, fg in chips[i: i + cols]:
            sty = ParagraphStyle(f"pt{i}", fontName="Helvetica-Bold", fontSize=8,
                                 textColor=fg, alignment=TA_CENTER)
            row.append(Paragraph(label, sty))
        rows.append(row)

    t = Table(rows, colWidths=[chip_w] * cols)
    style_cmds = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, C_MGREY),
    ]
    for ri, row_chips in enumerate([chips[i: i + cols]
                                     for i in range(0, len(chips), cols)]):
        for ci, (_, bg, _) in enumerate(row_chips):
            style_cmds.append(("BACKGROUND", (ci, ri), (ci, ri), bg))
    t.setStyle(TableStyle(style_cmds))

    # Legend
    legend_items = [
        ("Critical service", SEV_BG["HIGH"]),
        ("Database port", SEV_BG["MEDIUM"]),
        ("Malware / C2", SEV_BG["CRITICAL"]),
        ("Other", C_LGREY),
    ]
    legend_row = []
    legend_widths = []
    for label, bg in legend_items:
        sty = ParagraphStyle("leg", fontName="Helvetica", fontSize=7,
                             textColor=C_WHITE if bg != C_LGREY else C_TEXT,
                             alignment=TA_CENTER)
        legend_row.append(Paragraph(label, sty))
        legend_widths.append(usable / 4)
    legend = Table([legend_row], colWidths=legend_widths)
    legend.setStyle(TableStyle([
        *[("BACKGROUND", (i, 0), (i, 0), bg) for i, (_, bg) in enumerate(legend_items)],
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("GRID", (0, 0), (-1, -1), 0.5, C_MGREY),
    ]))

    return Table([[t], [legend]], colWidths=[usable])


# ── Page 1: Title Page ────────────────────────────────────────────────────────

def _title_page(report: AnalysisReport, styles: Dict) -> List:
    usable = PAGE_W - 1.5 * inch
    sev = report.finding_count_by_severity

    banner = Table(
        [[Paragraph("ForensiQ", styles["white_title"])],
         [Paragraph("Network Forensics Report", styles["white_sub"])],
         [Paragraph("Evidence-Driven Threat Analysis",
                    ParagraphStyle("_s2", fontName="Helvetica", fontSize=11,
                                   textColor=colors.HexColor("#718096"),
                                   alignment=TA_CENTER))]],
        colWidths=[usable],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (0, 0), 32),
        ("TOPPADDING", (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 32),
        ("BOTTOMPADDING", (0, 0), (-1, -2), 3),
    ]))

    accent_bar = Table([[""]], colWidths=[usable], rowHeights=[5])
    accent_bar.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    meta = _kv_table([
        ("File Name",     report.pcap_filename),
        ("SHA-256 Hash",  report.pcap_hash),
        ("Analysis Date", report.analysis_start.strftime("%Y-%m-%d %H:%M:%S")),
        ("Tool Version",  f"ForensiQ v{TOOL_VERSION}"),
    ], styles)

    stat_w = usable / 4
    _sv = lambda n: ParagraphStyle(f"sv{n}", fontName="Helvetica-Bold", fontSize=22,
                                   textColor=C_WHITE, alignment=TA_CENTER)
    _sl = lambda n: ParagraphStyle(f"sl{n}", fontName="Helvetica", fontSize=8,
                                   textColor=C_MGREY, alignment=TA_CENTER)
    stats = Table(
        [[Paragraph(f"{report.total_flows:,}", _sv(1)),
          Paragraph(f"{report.total_packets:,}", _sv(2)),
          Paragraph(str(len(report.findings)), _sv(3)),
          Paragraph(str(sev.get("CRITICAL", 0) + sev.get("HIGH", 0)), _sv(4))],
         [Paragraph("FLOWS", _sl(1)),
          Paragraph("PACKETS", _sl(2)),
          Paragraph("FINDINGS", _sl(3)),
          Paragraph("CRITICAL+HIGH", _sl(4))]],
        colWidths=[stat_w] * 4,
    )
    stats.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 0), 14),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING", (0, 1), (-1, 1), 2),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 14),
        ("LINEAFTER", (0, 0), (2, 1), 0.5, colors.HexColor("#2D3748")),
    ]))

    return [
        Spacer(1, 0.2 * inch),
        banner,
        accent_bar,
        Spacer(1, 0.3 * inch),
        Paragraph("FILE INFORMATION", styles["label"]),
        Spacer(1, 0.08 * inch),
        meta,
        Spacer(1, 0.3 * inch),
        Paragraph("QUICK STATISTICS", styles["label"]),
        Spacer(1, 0.08 * inch),
        stats,
        Spacer(1, 0.5 * inch),
        HRFlowable(width="100%", thickness=0.5, color=C_MGREY),
        Spacer(1, 0.1 * inch),
        Paragraph(
            "This document contains confidential forensic analysis data. "
            "Authorized security personnel only. "
            "Handle in accordance with your organization's data classification policy.",
            styles["muted_center"],
        ),
    ]


# ── Page 2: Executive Summary ─────────────────────────────────────────────────

def _exec_summary(report: AnalysisReport, styles: Dict) -> List:
    sev = report.finding_count_by_severity

    if sev.get("CRITICAL", 0) > 0:
        risk, risk_bg = "CRITICAL", SEV_BG["CRITICAL"]
        risk_desc = "Active threats requiring immediate response were detected."
    elif sev.get("HIGH", 0) > 0:
        risk, risk_bg = "HIGH", SEV_BG["HIGH"]
        risk_desc = "Significant threats requiring prompt investigation were detected."
    elif sev.get("MEDIUM", 0) > 0:
        risk, risk_bg = "MEDIUM", SEV_BG["MEDIUM"]
        risk_desc = "Suspicious activity warranting further investigation was detected."
    elif sev.get("LOW", 0) > 0:
        risk, risk_bg = "LOW", SEV_BG["LOW"]
        risk_desc = "Low-severity indicators detected for informational awareness."
    else:
        risk, risk_bg = "CLEAN", colors.HexColor("#27AE60")
        risk_desc = "No threats detected in the analyzed network traffic."

    usable = PAGE_W - 1.5 * inch
    risk_box = Table(
        [[Paragraph(f"OVERALL RISK: {risk}",
                    ParagraphStyle("rl", fontName="Helvetica-Bold", fontSize=16,
                                   textColor=C_WHITE, alignment=TA_CENTER))],
         [Paragraph(risk_desc,
                    ParagraphStyle("rd", fontName="Helvetica", fontSize=10,
                                   textColor=C_WHITE, alignment=TA_CENTER))]],
        colWidths=[usable],
    )
    risk_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), risk_bg),
        ("TOPPADDING", (0, 0), (0, 0), 14),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 14),
        ("TOPPADDING", (0, 1), (-1, 1), 4),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))

    stats_table = _kv_table([
        ("Total Flows",       f"{report.total_flows:,}"),
        ("Total Packets",     f"{report.total_packets:,}"),
        ("Total Bytes",       f"{report.total_bytes:,}"),
        ("Analysis Duration", f"{report.duration_seconds:.2f} seconds"),
        ("CRITICAL Findings", str(sev.get("CRITICAL", 0))),
        ("HIGH Findings",     str(sev.get("HIGH", 0))),
        ("MEDIUM Findings",   str(sev.get("MEDIUM", 0))),
        ("LOW Findings",      str(sev.get("LOW", 0))),
        ("Total Findings",    str(len(report.findings))),
    ], styles)

    # Pie chart + stats side by side
    pie = _severity_pie(sev)
    chart_col_w = 2.2 * inch
    stats_col_w = usable - chart_col_w
    side_by_side = Table(
        [[pie, stats_table]],
        colWidths=[chart_col_w, stats_col_w],
    )
    side_by_side.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    return [
        Paragraph("Executive Summary", styles["h1"]),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=12),
        *_section_title("Risk Assessment", styles),
        risk_box,
        Spacer(1, 0.25 * inch),
        *_section_title("Traffic Statistics", styles),
        side_by_side,
    ]


# ── Pages 3+: One Finding per Page ───────────────────────────────────────────

def _finding_page(finding: Finding, num: int, total: int, styles: Dict) -> List:
    usable = PAGE_W - 1.5 * inch
    sev = finding.severity.value
    bg = SEV_BG.get(sev, C_MGREY)

    header = Table(
        [[Paragraph(finding.title,
                    ParagraphStyle("ft", fontName="Helvetica-Bold", fontSize=14,
                                   textColor=C_WHITE)),
          Paragraph(sev,
                    ParagraphStyle("fb", fontName="Helvetica-Bold", fontSize=12,
                                   textColor=C_WHITE, alignment=TA_CENTER))],
         [Paragraph(f"Finding {num} of {total}",
                    ParagraphStyle("fs", fontName="Helvetica", fontSize=9,
                                   textColor=colors.HexColor("#FFDDD5"))),
          Paragraph(finding.rule_name,
                    ParagraphStyle("fr", fontName="Helvetica", fontSize=8,
                                   textColor=colors.HexColor("#FFDDD5"),
                                   alignment=TA_CENTER))]],
        colWidths=[usable - 1.4 * inch, 1.4 * inch],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("SPAN", (1, 0), (1, 1)),
    ]))

    # Network diagram
    diagram = _network_diagram(finding.src_ip, finding.dst_ip, finding.rule_name)

    # Metadata table with MITRE badge (feature 3) in a dedicated row
    mitre_row_val = _mitre_badge(finding.mitre_technique, finding.mitre_tactic, styles)
    meta_rows = [
        ("MITRE Technique", mitre_row_val),
        ("Source IP",       finding.src_ip),
        ("Destination IP",  finding.dst_ip),
        ("Timestamp",       str(finding.timestamp) if finding.timestamp else "N/A"),
        ("Confidence",      f"{finding.confidence * 100:.0f}%"),
    ]
    key_col = 2.0 * inch
    val_col = usable - key_col
    meta_data = [
        [Paragraph(str(k), styles["key"]),
         v if isinstance(v, Table) else Paragraph(str(v), styles["val"])]
        for k, v in meta_rows
    ]
    meta_table = Table(meta_data, colWidths=[key_col, val_col])
    meta_table.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_LGREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_MGREY),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # Evidence table with severity-colored header (feature 4)
    ev_rows = (
        [[Paragraph("Key", styles["key"]), Paragraph("Value", styles["key"])]]
        + [[Paragraph(str(k), styles["mono"]), Paragraph(str(v), styles["mono"])]
           for k, v in finding.evidence.items()]
    )
    ev_table = _navy_header_table(ev_rows, [2.0 * inch, usable - 2.0 * inch],
                                   header_color=bg)

    exp = _parse_explanation(finding.explanation or "")

    story = [header, Spacer(1, 0.12 * inch)]

    # Priority action box (feature 5) — right after header
    if exp["todo"]:
        pbox = _priority_box(exp["todo"], sev, styles)
        if pbox:
            story += [pbox, Spacer(1, 0.12 * inch)]

    # Network diagram (feature 2)
    story += [
        *_section_title("Attack Flow", styles),
        diagram,
        Spacer(1, 0.12 * inch),
        *_section_title("MITRE ATT&CK & Metadata", styles),
        meta_table,
        Spacer(1, 0.15 * inch),
        *_section_title("Description", styles),
        Paragraph(finding.description, styles["body"]),
        Spacer(1, 0.15 * inch),
        *_section_title("Evidence", styles),
        ev_table,
    ]

    # Port heatmap (feature 8) — only when ports list is present
    ports = finding.evidence.get("ports_scanned")
    if isinstance(ports, list) and ports:
        story += [
            Spacer(1, 0.15 * inch),
            *_section_title("Port Risk Heatmap", styles),
            _port_heatmap(ports, styles),
        ]

    # IOC table with VT badge (feature 6)
    if finding.iocs:
        ioc_rows = (
            [[Paragraph("IOC", styles["key"]),
              Paragraph("Type", styles["key"]),
              Paragraph("Status", styles["key"]),
              Paragraph("VT Score", styles["key"]),
              Paragraph("Known Malware", styles["key"])]]
            + [[Paragraph(ioc.value, styles["mono"]),
                Paragraph(ioc.ioc_type.value.upper(), styles["small"]),
                Paragraph(
                    "MALICIOUS" if ioc.malicious else "Unknown",
                    ParagraphStyle("is", fontName="Helvetica-Bold", fontSize=9,
                                   textColor=(SEV_BG["CRITICAL"] if ioc.malicious
                                              else colors.HexColor("#27AE60")))),
                _vt_badge(ioc.vt_score),
                Paragraph(ioc.known_malware or "—", styles["small"])]
               for ioc in finding.iocs]
        )
        story += [
            Spacer(1, 0.15 * inch),
            *_section_title("IOCs Involved", styles),
            _navy_header_table(
                ioc_rows,
                [2.2 * inch, 0.7 * inch, 0.9 * inch, 0.8 * inch, usable - 4.6 * inch],
            ),
        ]

    if exp["what"] or exp["why"]:
        parts = []
        if exp["what"]:
            parts.append(f"<b>What happened:</b> {exp['what']}")
        if exp["why"]:
            parts.append(f"<b>Why it matters:</b> {exp['why']}")
        story += [
            Spacer(1, 0.15 * inch),
            *_section_title("AI Explanation (Plain English)", styles),
            Paragraph("<br/><br/>".join(parts), styles["body"]),
        ]

    if exp["todo"]:
        story += [
            Spacer(1, 0.15 * inch),
            *_section_title("Remediation Steps", styles),
        ]
        for line in exp["todo"].splitlines():
            if line.strip():
                story.append(Paragraph(line, styles["body"]))

    return story


# ── IOC Reference Page ────────────────────────────────────────────────────────

def _ioc_page(all_iocs: List[IOC], styles: Dict) -> List:
    usable = PAGE_W - 1.5 * inch
    seen: set = set()
    unique: List[IOC] = []
    for ioc in all_iocs:
        if ioc.value not in seen:
            seen.add(ioc.value)
            unique.append(ioc)

    rows = (
        [[Paragraph("IOC", styles["key"]),
          Paragraph("Type", styles["key"]),
          Paragraph("Status", styles["key"]),
          Paragraph("VT Score", styles["key"]),
          Paragraph("Known Malware", styles["key"])]]
        + [[Paragraph(ioc.value, styles["mono"]),
            Paragraph(ioc.ioc_type.value.upper(), styles["small"]),
            Paragraph(
                "MALICIOUS" if ioc.malicious else "Unknown",
                ParagraphStyle("is2", fontName="Helvetica-Bold", fontSize=9,
                               textColor=(SEV_BG["CRITICAL"] if ioc.malicious
                                          else colors.HexColor("#27AE60")))),
            _vt_badge(ioc.vt_score),
            Paragraph(ioc.known_malware or "—", styles["small"])]
           for ioc in unique]
    )
    t = _navy_header_table(
        rows,
        [2.4 * inch, 0.75 * inch, 0.95 * inch, 0.8 * inch, usable - 4.9 * inch],
    )

    return [
        Paragraph("IOC Reference", styles["h1"]),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=12),
        Paragraph(f"{len(unique)} unique indicator(s) extracted from all findings.",
                  styles["body"]),
        Spacer(1, 0.15 * inch),
        t,
    ]


# ── Chain of Custody Page ─────────────────────────────────────────────────────

def _custody_page(report: AnalysisReport, styles: Dict) -> List:
    return [
        Paragraph("Chain of Custody", styles["h1"]),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=12),

        *_section_title("File Integrity", styles),
        _kv_table([
            ("Original Filename", report.pcap_filename),
            ("SHA-256 Hash",      report.pcap_hash),
            ("Hash Algorithm",    "SHA-256 (FIPS 180-4)"),
            ("Integrity Status",  "Hash computed at ingestion; file was not modified"),
        ], styles),

        Spacer(1, 0.2 * inch),
        *_section_title("Tool Information", styles),
        _kv_table([
            ("Tool Name",        "ForensiQ — Evidence-Driven Network Forensics"),
            ("Version",          f"v{TOOL_VERSION}"),
            ("Detection Engine", "Rule-based + ML Anomaly Detection (Isolation Forest)"),
            ("Threat Intel",     "VirusTotal API v3"),
            ("AI Analysis",      f"Groq API ({config.LLM_MODEL})"),
        ], styles),

        Spacer(1, 0.2 * inch),
        *_section_title("Analysis Timeline", styles),
        _kv_table([
            ("Analysis Start",   report.analysis_start.strftime("%Y-%m-%d %H:%M:%S")),
            ("Analysis End",     report.analysis_end.strftime("%Y-%m-%d %H:%M:%S")),
            ("Total Duration",   f"{report.duration_seconds:.2f} seconds"),
            ("Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ], styles),

        Spacer(1, 0.2 * inch),
        *_section_title("Forensic Validity Statement", styles),
        Paragraph(
            "This report was generated by ForensiQ, an automated network forensics tool. "
            "All findings are derived directly from captured network traffic and include "
            "verifiable evidence. The SHA-256 hash above ensures file integrity can be "
            "independently verified. Detection logic is deterministic — re-running analysis "
            "on the same file will produce identical results. This report is suitable for "
            "use in incident response, security investigations, and forensic documentation.",
            styles["body"],
        ),

        Spacer(1, 0.2 * inch),
        *_section_title("Reproducibility Statement", styles),
        Paragraph(
            f"To reproduce: <font name='Courier'>python3 main.py {report.pcap_filename}</font>. "
            "Verify the SHA-256 hash before re-analysis. "
            "Rule-based and ML detections are deterministic. "
            "LLM explanations may vary between runs as they are non-deterministic.",
            styles["body"],
        ),
    ]


# ── Appendix ──────────────────────────────────────────────────────────────────

_MITRE_DESC = {
    "T1046":     "Network Service Discovery — scanning to enumerate open ports/services",
    "T1110":     "Brute Force — repeated authentication attempts to gain access",
    "T1071":     "Application Layer Protocol — C2 communication via standard protocols",
    "T1048":     "Exfiltration Over Alternative Protocol — data theft via non-standard channel",
    "T1071.004": "DNS — using DNS for C2 or covert data exfiltration",
}


def _appendix_page(findings: List[Finding], styles: Dict) -> List:
    usable = PAGE_W - 1.5 * inch
    mitre_map = {f.mitre_technique: f.mitre_tactic for f in findings}

    mitre_rows = (
        [[Paragraph("Technique ID", styles["key"]),
          Paragraph("Tactic", styles["key"]),
          Paragraph("Description", styles["key"])]]
        + [[Paragraph(tid, styles["mono"]),
            Paragraph(tactic, styles["body"]),
            Paragraph(_MITRE_DESC.get(tid, "See MITRE ATT&CK framework"), styles["body"])]
           for tid, tactic in mitre_map.items()]
    )
    mitre_table = _navy_header_table(
        mitre_rows, [1.0 * inch, 1.5 * inch, usable - 2.5 * inch]
    )

    sev_defs = [
        ("CRITICAL", "Active attack in progress. Immediate response required."),
        ("HIGH",     "Likely real threat. Prompt investigation required."),
        ("MEDIUM",   "Suspicious activity. Investigation recommended."),
        ("LOW",      "Informational. Not an immediate threat."),
    ]
    sev_rows = (
        [[Paragraph("Level", styles["key"]), Paragraph("Definition", styles["key"])]]
        + [[Paragraph(level,
                      ParagraphStyle("sd", fontName="Helvetica-Bold", fontSize=9,
                                     textColor=C_WHITE)),
            Paragraph(defn, styles["body"])]
           for level, defn in sev_defs]
    )
    sev_table = _navy_header_table(sev_rows, [1.1 * inch, usable - 1.1 * inch])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BACKGROUND", (0, 1), (0, 1), SEV_BG["CRITICAL"]),
        ("BACKGROUND", (0, 2), (0, 2), SEV_BG["HIGH"]),
        ("BACKGROUND", (0, 3), (0, 3), SEV_BG["MEDIUM"]),
        ("BACKGROUND", (0, 4), (0, 4), SEV_BG["LOW"]),
        ("ROWBACKGROUNDS", (1, 1), (-1, -1), [C_WHITE, C_LGREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_MGREY),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    return [
        Paragraph("Appendix", styles["h1"]),
        HRFlowable(width="100%", thickness=2, color=C_ACCENT, spaceAfter=12),

        *_section_title("MITRE ATT&CK Legend", styles),
        (mitre_table if mitre_map
         else Paragraph("No MITRE techniques recorded.", styles["body"])),

        Spacer(1, 0.2 * inch),
        *_section_title("Severity Definitions", styles),
        sev_table,

        Spacer(1, 0.2 * inch),
        *_section_title("Tool Documentation", styles),
        _kv_table([
            ("Tool",            "ForensiQ — Evidence-Driven Network Forensics"),
            ("Version",         f"v{TOOL_VERSION}"),
            ("Author",          "Sangeeth"),
            ("Detection Rules", "Port Scan (T1046), Brute Force (T1110), C2 Beaconing, "
                                "Data Exfiltration (T1048), DNS Tunneling (T1071.004)"),
            ("ML Model",        "Isolation Forest (scikit-learn) — unsupervised anomaly detection"),
            ("Threat Intel",    "VirusTotal API v3 — IP/domain reputation"),
            ("AI Analysis",     f"Groq API — {config.LLM_MODEL}"),
            ("Output Formats",  "JSON report, PDF report"),
        ], styles),
    ]


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_pdf(report: AnalysisReport, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.55 * inch,
    )

    styles = _build_styles()
    story = []

    story += _title_page(report, styles)
    story.append(PageBreak())

    story += _exec_summary(report, styles)
    story.append(PageBreak())

    total = len(report.findings)
    for i, finding in enumerate(report.findings, 1):
        story += _finding_page(finding, i, total, styles)
        story.append(PageBreak())

    all_iocs = [ioc for f in report.findings for ioc in f.iocs]
    if all_iocs:
        story += _ioc_page(all_iocs, styles)
        story.append(PageBreak())

    story += _custody_page(report, styles)
    story.append(PageBreak())

    story += _appendix_page(report.findings, styles)

    doc.build(
        story,
        onFirstPage=_draw_title_page_canvas,
        onLaterPages=_draw_content_page,
    )

    logger.info(f"PDF report saved: {output_path}")
    return output_path
