"""
reporter.py - PDF & HTML report generation for Phishing Email Detector
Uses ReportLab for PDF, Jinja2-style string templates for HTML.
"""

import os
import datetime
from pathlib import Path
from dataclasses import asdict
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.pdfgen import canvas

from utils import REPORT_DIR, risk_color

# ── Color palette ─────────────────────────────────────────────────────────────
C_DARK   = colors.HexColor("#0d1117")
C_PANEL  = colors.HexColor("#161b22")
C_ACCENT = colors.HexColor("#58a6ff")
C_SAFE   = colors.HexColor("#2a9d8f")
C_WARN   = colors.HexColor("#f4a261")
C_DANGER = colors.HexColor("#e63946")
C_WHITE  = colors.white
C_GRAY   = colors.HexColor("#8b949e")
C_LGRAY  = colors.HexColor("#21262d")

def label_color(label: str):
    return {"PHISHING": C_DANGER, "SUSPICIOUS": C_WARN, "SAFE": C_SAFE}.get(label, C_GRAY)

# ── Helpers ───────────────────────────────────────────────────────────────────

def score_bar_svg(score: float, label: str) -> str:
    """Tiny SVG bar used in HTML report."""
    color = risk_color(label)
    w = int(score * 3.5)
    return (
        f'<svg width="350" height="24" style="border-radius:4px;background:#21262d;">'
        f'<rect width="{w}" height="24" rx="4" fill="{color}"/>'
        f'<text x="8" y="17" font-family="monospace" font-size="12" fill="white">'
        f'{score:.0f}%</text></svg>'
    )

# ── PDF Report ────────────────────────────────────────────────────────────────

class NumberedCanvas(canvas.Canvas):
    """Canvas that adds page numbers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        n = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(n)
            super().showPage()
        super().save()

    def _draw_page_number(self, page_count):
        self.setFont("Helvetica", 8)
        self.setFillColor(C_GRAY)
        self.drawRightString(
            A4[0] - 1.5 * cm, 1 * cm,
            f"Page {self._pageNumber} of {page_count}  |  Phishing Email Detector"
        )


def generate_pdf_report(result, output_path: str | None = None) -> bytes:
    """
    Generate a professional PDF report from an AnalysisResult.
    Returns PDF bytes and optionally saves to file.
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.8 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Phishing Report – {result.scan_id}",
    )

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    normal.fontName = "Helvetica"
    normal.fontSize = 9
    normal.textColor = C_DARK

    def H1(text):
        return Paragraph(text, ParagraphStyle(
            "H1", fontName="Helvetica-Bold", fontSize=18,
            textColor=C_DARK, spaceAfter=4
        ))

    def H2(text):
        return Paragraph(text, ParagraphStyle(
            "H2", fontName="Helvetica-Bold", fontSize=12,
            textColor=C_ACCENT, spaceBefore=12, spaceAfter=6
        ))

    def Body(text, color=C_DARK, size=9):
        return Paragraph(text, ParagraphStyle(
            "Body", fontName="Helvetica", fontSize=size,
            textColor=color, spaceAfter=3, leading=14
        ))

    def Mono(text):
        return Paragraph(f"<font name='Courier' size='8'>{text}</font>",
                         ParagraphStyle("Mono", spaceAfter=2,
                                        backColor=colors.HexColor("#f6f8fa"),
                                        borderPadding=4))

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    label = result.label
    lc    = label_color(label)

    header_data = [[
        Paragraph(
            f"<font color='#0d1117' size='20'><b>🛡️ Phishing Email Detector</b></font><br/>"
            f"<font color='#8b949e' size='9'>Security Analysis Report  •  Scan ID: {result.scan_id}</font>",
            ParagraphStyle("hdr", spaceAfter=0)
        ),
        Paragraph(
            f"<font size='22'><b>{label}</b></font><br/>"
            f"<font color='#8b949e' size='9'>Risk Score: {result.risk_score:.0f}%</font>",
            ParagraphStyle("verdict", alignment=TA_RIGHT, spaceAfter=0,
                           textColor=lc)
        ),
    ]]
    header_tbl = Table(header_data, colWidths=["65%", "35%"])
    header_tbl.setStyle(TableStyle([
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
    ]))
    story.append(header_tbl)
    story.append(HRFlowable(width="100%", thickness=2, color=lc, spaceAfter=12))

    # ── Timestamp ─────────────────────────────────────────────────────────────
    story.append(Body(
        f"<font color='#8b949e'>Generated: {result.timestamp}  •  "
        f"Analyst: Automated System</font>"
    ))
    story.append(Spacer(1, 8))

    # ── Email Metadata ────────────────────────────────────────────────────────
    story.append(H2("📧 Email Metadata"))
    meta_data = [
        ["Field", "Value"],
        ["Subject",  result.subject[:90] or "(none)"],
        ["From",     result.sender[:90]  or "(unknown)"],
        ["Reply-To", result.reply_to[:90] or "(none)"],
        ["URLs Found", str(len(result.raw_urls))],
        ["Spoofed Sender", "YES ⚠️" if result.sender_spoofed else "No"],
    ]
    meta_tbl = Table(meta_data, colWidths=["25%", "75%"])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
        ("TEXTCOLOR",    (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("FONTNAME",     (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",    (0, 1), (0, -1), C_ACCENT),
        ("BACKGROUND",   (0, 1), (-1, -1), colors.HexColor("#f6f8fa")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
            [colors.HexColor("#f6f8fa"), colors.HexColor("#eef2f5")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("PADDING",      (0, 0), (-1, -1), 5),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 10))

    # ── Risk Score breakdown ──────────────────────────────────────────────────
    story.append(H2("📊 Risk Score Breakdown"))
    score_data = [
        ["Component",      "Score",   "Weight", "Contribution"],
        ["ML Model",       f"{result.ml_score:.1f}%",   "40%",
         f"{result.ml_score * 0.4:.1f}"],
        ["Rule-Based",     f"{result.rule_score:.1f}%", "35%",
         f"{result.rule_score * 0.35:.1f}"],
        ["URL Analysis",
         f"{sum(u.get('risk_score',0) for u in result.url_results)/max(len(result.url_results),1):.1f}%"
         if result.url_results else "0%",
         "25%",
         f"{sum(u.get('risk_score',0) for u in result.url_results)/max(len(result.url_results),1)*0.25:.1f}"
         if result.url_results else "0"],
        ["FINAL SCORE", f"{result.risk_score:.1f}%", "—", f"{result.risk_score:.1f}"],
    ]
    score_tbl = Table(score_data, colWidths=["35%", "20%", "20%", "25%"])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_DARK),
        ("TEXTCOLOR",    (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("BACKGROUND",   (0, -1), (-1, -1), lc),
        ("TEXTCOLOR",    (0, -1), (-1, -1), C_WHITE),
        ("FONTNAME",     (0, -1), (-1, -1), "Helvetica-Bold"),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -2),
            [colors.HexColor("#f6f8fa"), colors.HexColor("#eef2f5")]),
        ("PADDING",      (0, 0), (-1, -1), 5),
        ("ALIGN",        (1, 0), (-1, -1), "CENTER"),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 10))

    # ── Flags / Findings ──────────────────────────────────────────────────────
    if result.flags:
        story.append(H2(f"🚩 Detected Red Flags ({len(result.flags)})"))
        for i, flag in enumerate(result.flags[:20], 1):
            story.append(Body(f"&nbsp;&nbsp;<b>{i}.</b> {flag}", color=C_DARK))
        story.append(Spacer(1, 6))

    # ── URL Analysis ──────────────────────────────────────────────────────────
    if result.url_results:
        story.append(H2(f"🔗 URL Analysis ({len(result.url_results)} scanned)"))
        for ur in result.url_results[:8]:
            url_score = ur.get("risk_score", 0)
            url_label = "HIGH RISK" if url_score >= 50 else ("SUSPICIOUS" if url_score >= 20 else "OK")
            uc = label_color({"HIGH RISK":"PHISHING","SUSPICIOUS":"SUSPICIOUS","OK":"SAFE"}.get(url_label,"SAFE"))
            url_data = [
                [Paragraph(f"<b><font color='#0550ae'>{ur['url'][:70]}…</font></b>"
                           if len(ur['url']) > 70 else
                           f"<b><font color='#0550ae'>{ur['url']}</font></b>",
                           ParagraphStyle("ul", fontSize=8)),
                 Paragraph(f"<b><font color='#{uc.hexval()}'>{url_label} ({url_score:.0f}%)</font></b>",
                           ParagraphStyle("urs", fontSize=8, alignment=TA_RIGHT))],
            ]
            if ur.get("flags"):
                for fl in ur["flags"][:3]:
                    url_data.append([
                        Paragraph(f"  ⚠ {fl}", ParagraphStyle("uf", fontSize=7, textColor=C_WARN)),
                        Paragraph("", ParagraphStyle("empty", fontSize=7)),
                    ])
            url_tbl = Table(url_data, colWidths=["70%", "30%"])
            url_tbl.setStyle(TableStyle([
                ("BOX",          (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#f6f8fa")),
                ("PADDING",      (0, 0), (-1, -1), 5),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(url_tbl)
            story.append(Spacer(1, 4))

    # ── LLM Analysis ─────────────────────────────────────────────────────────
    if result.llm_analysis and result.llm_used:
        story.append(H2("🤖 AI Semantic Analysis"))
        story.append(Body(result.llm_analysis, color=colors.HexColor("#24292f")))
        story.append(Spacer(1, 6))

    # ── Keyword Hits ──────────────────────────────────────────────────────────
    if result.keyword_hits:
        story.append(H2("🔍 Keyword Analysis"))
        for category, words in result.keyword_hits.items():
            story.append(Body(f"<b>{category}:</b> {', '.join(words[:8])}"))
        story.append(Spacer(1, 6))

    # ── Recommendations ───────────────────────────────────────────────────────
    story.append(H2("💡 Recommendations"))
    recs = _get_recommendations(result)
    for rec in recs:
        story.append(Body(f"• {rec}"))
    story.append(Spacer(1, 8))

    # ── Email Body Preview ────────────────────────────────────────────────────
    if result.body_snippet:
        story.append(H2("📄 Email Body (Preview)"))
        snippet = result.body_snippet[:800].replace("<", "&lt;").replace(">", "&gt;")
        story.append(Paragraph(
            f"<font name='Courier' size='7' color='#24292f'>{snippet}…</font>",
            ParagraphStyle("snippet", backColor=colors.HexColor("#f6f8fa"),
                           borderPadding=6, spaceAfter=4, leading=11)
        ))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=C_GRAY))
    story.append(Body(
        "<font color='#8b949e' size='8'>This report was generated automatically by the Phishing Email Detector. "
        "Results should be reviewed by a qualified security professional. "
        "Do not click any suspicious links or reply to phishing emails.</font>"
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buf.getvalue()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes


def _get_recommendations(result) -> list[str]:
    recs = []
    if result.label == "PHISHING":
        recs += [
            "DO NOT click any links or download attachments from this email.",
            "DO NOT reply to or forward this email.",
            "Report this email to your IT/security team immediately.",
            "Delete this email from your inbox and trash folder.",
            "If you already clicked a link, change your passwords and scan your device.",
        ]
    elif result.label == "SUSPICIOUS":
        recs += [
            "Exercise caution – verify the sender through an independent channel before taking action.",
            "Hover over links to verify they match the expected destination before clicking.",
            "Contact the purported sender via phone or official website to confirm authenticity.",
            "Do not provide any personal or financial information requested in this email.",
        ]
    else:
        recs += [
            "This email appears legitimate but always remain vigilant.",
            "Verify sender identity if you receive unexpected requests.",
            "Keep your email client and security software up to date.",
        ]
    if result.sender_spoofed:
        recs.append("⚠️ Sender spoofing detected – the From address may be forged.")
    if any(u.get("is_ip_url") for u in result.url_results):
        recs.append("⚠️ URLs using raw IP addresses are highly suspicious.")
    return recs

# ── HTML Report ───────────────────────────────────────────────────────────────

def generate_html_report(result) -> str:
    """Generate a self-contained HTML report."""
    label  = result.label
    lcolor = risk_color(label)
    ts     = result.timestamp

    flags_html = "".join(
        f'<li class="flag-item">⚠️ {f}</li>' for f in result.flags[:20]
    ) or "<li>No flags detected.</li>"

    urls_html = ""
    for ur in result.url_results[:10]:
        rs = ur.get("risk_score", 0)
        ul = "HIGH RISK" if rs >= 50 else ("SUSPICIOUS" if rs >= 20 else "OK")
        uc = {"HIGH RISK":"#e63946","SUSPICIOUS":"#f4a261","OK":"#2a9d8f"}.get(ul,"#888")
        url_flags = "".join(f"<div class='url-flag'>⚠ {f}</div>" for f in ur.get("flags",[])[:3])
        urls_html += f"""
        <div class="url-card">
          <div class="url-header">
            <span class="url-text">{ur['url'][:80]}</span>
            <span class="url-badge" style="background:{uc}">{ul} {rs:.0f}%</span>
          </div>
          {url_flags}
        </div>"""

    kw_html = ""
    for cat, words in result.keyword_hits.items():
        kw_html += f"<div class='kw-cat'><b>{cat}:</b> {', '.join(words[:6])}</div>"

    llm_html = ""
    if result.llm_used and result.llm_analysis:
        llm_html = f"""
        <section>
          <h2>🤖 AI Semantic Analysis</h2>
          <div class="llm-box">{result.llm_analysis}</div>
        </section>"""

    recs = _get_recommendations(result)
    recs_html = "".join(f"<li>{r}</li>" for r in recs)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phishing Report – {result.scan_id}</title>
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --safe: #2a9d8f; --warn: #f4a261; --danger: #e63946;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: var(--bg); color: var(--text); padding: 2rem; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center;
             border-bottom: 2px solid {lcolor}; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
  .title {{ font-size: 1.6rem; font-weight: 700; }}
  .verdict {{ font-size: 2rem; font-weight: 800; color: {lcolor}; text-align: right; }}
  .score-sub {{ font-size: 0.85rem; color: var(--muted); }}
  section {{ background: var(--panel); border: 1px solid var(--border);
             border-radius: 8px; padding: 1.2rem; margin-bottom: 1rem; }}
  h2 {{ font-size: 1rem; margin-bottom: 0.8rem; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: #21262d; color: var(--muted); text-align: left;
        padding: 6px 10px; font-weight: 600; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}
  .score-bar-wrap {{ background: #21262d; border-radius: 6px; height: 20px;
                     overflow: hidden; margin-top: 4px; }}
  .score-bar {{ height: 100%; border-radius: 6px; background: {lcolor};
                width: {result.risk_score}%; transition: width 1s; }}
  .flag-list {{ list-style: none; }}
  .flag-item {{ padding: 4px 0; border-bottom: 1px solid var(--border); font-size: 0.85rem; }}
  .url-card {{ background: #0d1117; border: 1px solid var(--border);
               border-radius: 6px; padding: 8px 12px; margin-bottom: 6px; }}
  .url-header {{ display: flex; justify-content: space-between; align-items: center; }}
  .url-text {{ font-family: monospace; font-size: 0.78rem; color: var(--accent);
               word-break: break-all; flex: 1; margin-right: 8px; }}
  .url-badge {{ font-size: 0.7rem; font-weight: 700; padding: 2px 8px;
                border-radius: 4px; color: white; white-space: nowrap; }}
  .url-flag {{ font-size: 0.78rem; color: var(--warn); padding: 2px 0; }}
  .kw-cat {{ font-size: 0.85rem; margin-bottom: 4px; }}
  .llm-box {{ background: #0d1117; border-left: 3px solid var(--accent);
              padding: 10px 14px; font-size: 0.85rem; line-height: 1.6; border-radius: 4px; }}
  .rec-list li {{ padding: 4px 0; font-size: 0.85rem; }}
  .footer {{ text-align: center; font-size: 0.75rem; color: var(--muted);
             margin-top: 1.5rem; padding-top: 1rem;
             border-top: 1px solid var(--border); }}
  .meta-label {{ color: var(--muted); font-weight: 600; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="title">🛡️ Phishing Email Detector</div>
      <div class="score-sub">Security Analysis Report • Scan ID: {result.scan_id} • {ts}</div>
    </div>
    <div>
      <div class="verdict">{label}</div>
      <div class="score-sub" style="text-align:right">Risk Score: {result.risk_score:.0f}%</div>
    </div>
  </div>

  <section>
    <h2>📧 Email Metadata</h2>
    <table>
      <tr><th>Field</th><th>Value</th></tr>
      <tr><td class="meta-label">Subject</td><td>{result.subject}</td></tr>
      <tr><td class="meta-label">From</td><td>{result.sender}</td></tr>
      <tr><td class="meta-label">Reply-To</td><td>{result.reply_to or '(none)'}</td></tr>
      <tr><td class="meta-label">Spoofed Sender</td>
          <td>{'<span style="color:var(--danger)">⚠️ YES – ' + result.spoof_reason + '</span>' if result.sender_spoofed else 'No'}</td></tr>
      <tr><td class="meta-label">URLs Found</td><td>{len(result.raw_urls)}</td></tr>
    </table>
  </section>

  <section>
    <h2>📊 Risk Score</h2>
    <div class="score-bar-wrap"><div class="score-bar"></div></div>
    <table style="margin-top:10px">
      <tr><th>Component</th><th>Score</th><th>Weight</th></tr>
      <tr><td>ML Model</td><td>{result.ml_score:.1f}%</td><td>40%</td></tr>
      <tr><td>Rule-Based</td><td>{result.rule_score:.1f}%</td><td>35%</td></tr>
      <tr><td>URL Analysis</td>
          <td>{sum(u.get("risk_score",0) for u in result.url_results)/max(len(result.url_results),1):.1f}% if result.url_results else 0%</td>
          <td>25%</td></tr>
      <tr style="font-weight:700;background:#21262d"><td>FINAL</td>
          <td style="color:{lcolor}">{result.risk_score:.1f}%</td><td>—</td></tr>
    </table>
  </section>

  <section>
    <h2>🚩 Detected Red Flags ({len(result.flags)})</h2>
    <ul class="flag-list">{flags_html}</ul>
  </section>

  {f'<section><h2>🔗 URL Analysis ({len(result.url_results)} scanned)</h2>{urls_html}</section>' if urls_html else ''}

  {f'<section><h2>🔍 Keyword Hits</h2>{kw_html}</section>' if kw_html else ''}

  {llm_html}

  <section>
    <h2>💡 Recommendations</h2>
    <ul class="rec-list">{recs_html}</ul>
  </section>

  <div class="footer">
    Generated by Phishing Email Detector • {ts} •
    This report is for informational purposes only.
  </div>
</div>
</body>
</html>"""
