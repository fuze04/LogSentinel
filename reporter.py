"""
reporter.py
-----------
Builds the PDF deliverable from a list of finding dicts (see log_analyzer.py
for the exact shape). Layout:

    1. Cover page
    2. Index  (severity summary + findings index table)
    3. Executive summary
    4. Severity classification legend
    5. Detailed findings (grouped Critical -> Info), each with an evidence
       table keyed by file / location / timestamp
    6. Appendix: methodology, detector coverage, disclaimer
"""

from __future__ import annotations

from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageBreak, PageTemplate, Paragraph, Spacer,
    Table, TableStyle, KeepTogether,
)

SEV_COLORS = {
    "Critical": colors.HexColor("#8B0000"),
    "High":     colors.HexColor("#C0392B"),
    "Medium":   colors.HexColor("#E67E22"),
    "Low":      colors.HexColor("#2980B9"),
    "Info":     colors.HexColor("#7F8C8D"),
}
SEV_BG = {
    "Critical": colors.HexColor("#F5D6D6"),
    "High":     colors.HexColor("#F8DDD8"),
    "Medium":   colors.HexColor("#FCEBD7"),
    "Low":      colors.HexColor("#D9E8F5"),
    "Info":     colors.HexColor("#E5E8E8"),
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

NAVY = colors.HexColor("#1F2D3D")
LIGHT = colors.HexColor("#F4F6F8")
BORDER = colors.HexColor("#D0D7DE")


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle("CoverTitle", parent=s["Title"], fontSize=26,
                         textColor=NAVY, spaceAfter=6, leading=30))
    s.add(ParagraphStyle("CoverSub", parent=s["Normal"], fontSize=13,
                         textColor=colors.HexColor("#566573"), alignment=TA_CENTER,
                         spaceAfter=4))
    s.add(ParagraphStyle("H1", parent=s["Heading1"], fontSize=16, textColor=NAVY,
                         spaceBefore=10, spaceAfter=8))
    s.add(ParagraphStyle("H2", parent=s["Heading2"], fontSize=13, textColor=NAVY,
                         spaceBefore=8, spaceAfter=4))
    s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=9.5, leading=14,
                         spaceAfter=4))
    s.add(ParagraphStyle("Small", parent=s["Normal"], fontSize=8, leading=10,
                         textColor=colors.HexColor("#2C3E50")))
    s.add(ParagraphStyle("SmallMono", parent=s["Normal"], fontSize=7.5,
                         leading=9.5, fontName="Courier",
                         textColor=colors.HexColor("#34495E")))
    s.add(ParagraphStyle("Label", parent=s["Normal"], fontSize=9,
                         textColor=colors.HexColor("#566573"),
                         fontName="Helvetica-Bold", spaceBefore=4))
    s.add(ParagraphStyle("FindingTitle", parent=s["Heading2"], fontSize=12,
                         textColor=NAVY, spaceAfter=2))
    return s


def _sev_chip(sev: str, st) -> Table:
    p = Paragraph(f'<b>{sev.upper()}</b>', ParagraphStyle(
        "chip", fontSize=8.5, textColor=colors.white, alignment=TA_CENTER))
    t = Table([[p]], colWidths=[2.3 * cm], rowHeights=[0.55 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_COLORS.get(sev, colors.grey)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return t


def build_report(findings: list[dict], meta: dict, output_path: str,
                 max_evidence_rows: int = 25):
    st = _styles()
    doc = BaseDocTemplate(
        output_path, pagesize=A4,
        leftMargin=1.8 * cm, rightMargin=1.8 * cm,
        topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        title=meta.get("report_title", "Log Sensitive Data Exposure Report"),
        author=meta.get("tester", "VAPT Team"),
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="main")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setStrokeColor(BORDER)
        canvas.line(doc.leftMargin, 1.2 * cm, A4[0] - doc.rightMargin, 1.2 * cm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#7F8C8D"))
        canvas.drawString(doc.leftMargin, 0.8 * cm,
                          "CONFIDENTIAL — " + meta.get("client", "Client"))
        canvas.drawRightString(A4[0] - doc.rightMargin, 0.8 * cm,
                               f"Page {d.page}")
        canvas.drawCentredString(A4[0] / 2, 0.8 * cm,
                                 meta.get("tester", "VAPT Team"))
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=footer)])

    story: list = []
    story += _cover(meta, findings, st)
    story.append(PageBreak())
    story += _index(findings, st)
    story.append(PageBreak())
    story += _exec_summary(findings, meta, st)
    story += _severity_legend(st)
    story.append(PageBreak())
    story += _detailed_findings(findings, st, max_evidence_rows)
    story.append(PageBreak())
    story += _appendix(meta, st)

    doc.build(story)
    return output_path


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #

def _counts(findings):
    c = {s: 0 for s in SEV_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


def _cover(meta, findings, st):
    counts = _counts(findings)
    total_inst = sum(f["count"] for f in findings)
    e = []
    e.append(Spacer(1, 2.5 * cm))
    e.append(Paragraph(meta.get("report_title",
             "Log File Sensitive Data Exposure Assessment"), st["CoverTitle"]))
    e.append(Spacer(1, 0.2 * cm))
    e.append(Paragraph("VAPT — Log Review of Mobile / Web Application APIs",
                       st["CoverSub"]))
    e.append(Spacer(1, 1.4 * cm))

    rows = [
        ["Client", meta.get("client", "—")],
        ["Target / Scope", meta.get("target", "Mobile & Web Application API logs")],
        ["Assessed by", meta.get("tester", "—")],
        ["Assessment date", meta.get("date", datetime.now().strftime("%d %b %Y"))],
        ["Files analysed", str(meta.get("total_files", "—"))],
        ["Log records scanned", str(meta.get("total_records", "—"))],
        ["Total findings", f"{len(findings)} issue type(s) / {total_inst} instance(s)"],
    ]
    t = Table(rows, colWidths=[5 * cm, 10.4 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    e.append(t)
    e.append(Spacer(1, 1 * cm))

    # severity bar
    bar = [["Critical", "High", "Medium", "Low", "Info"],
           [counts["Critical"], counts["High"], counts["Medium"],
            counts["Low"], counts["Info"]]]
    bt = Table(bar, colWidths=[3.08 * cm] * 5)
    style = [("FONTSIZE", (0, 0), (-1, -1), 10),
             ("ALIGN", (0, 0), (-1, -1), "CENTER"),
             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 6),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
             ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
             ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTSIZE", (0, 1), (-1, 1), 16)]
    for i, s in enumerate(SEV_ORDER):
        style.append(("BACKGROUND", (i, 0), (i, 0), SEV_COLORS[s]))
        style.append(("BACKGROUND", (i, 1), (i, 1), SEV_BG[s]))
        style.append(("TEXTCOLOR", (i, 1), (i, 1), SEV_COLORS[s]))
    bt.setStyle(TableStyle(style))
    e.append(bt)
    e.append(Spacer(1, 1.6 * cm))
    e.append(Paragraph(
        "<b>CONFIDENTIAL.</b> This document contains the results of a security "
        "assessment and references to sensitive data discovered in log files. "
        "Sensitive values are masked. Distribute on a need-to-know basis only.",
        st["Small"]))
    return e


def _index(findings, st):
    e = [Paragraph("Index of Findings", st["H1"])]
    counts = _counts(findings)
    total_inst = sum(f["count"] for f in findings)

    summ = [["Severity", "Issue types", "Total instances"]]
    for s in SEV_ORDER:
        inst = sum(f["count"] for f in findings if f["severity"] == s)
        summ.append([s, str(counts[s]), str(inst)])
    summ.append(["TOTAL", str(len(findings)), str(total_inst)])
    stb = Table(summ, colWidths=[5 * cm, 5.2 * cm, 5.2 * cm])
    sstyle = [("BACKGROUND", (0, 0), (-1, 0), NAVY),
              ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
              ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
              ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
              ("BACKGROUND", (0, -1), (-1, -1), LIGHT),
              ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
              ("FONTSIZE", (0, 0), (-1, -1), 9.5),
              ("ALIGN", (1, 0), (-1, -1), "CENTER"),
              ("TOPPADDING", (0, 0), (-1, -1), 5),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    for i, s in enumerate(SEV_ORDER, 1):
        sstyle.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLORS[s]))
        sstyle.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    stb.setStyle(TableStyle(sstyle))
    e.append(stb)
    e.append(Spacer(1, 0.6 * cm))

    e.append(Paragraph("Findings", st["H2"]))
    idx = [["ID", "Vulnerability", "Severity", "Instances"]]
    for f in findings:
        idx.append([f["id"],
                    Paragraph(f["name"], st["Small"]),
                    f["severity"],
                    str(f["count"])])
    it = Table(idx, colWidths=[2.6 * cm, 8.4 * cm, 2.6 * cm, 1.8 * cm], repeatRows=1)
    istyle = [("BACKGROUND", (0, 0), (-1, 0), NAVY),
              ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
              ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
              ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
              ("FONTSIZE", (0, 0), (-1, -1), 8.5),
              ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
              ("ALIGN", (2, 1), (-1, -1), "CENTER"),
              ("ALIGN", (0, 1), (0, -1), "CENTER"),
              ("TOPPADDING", (0, 0), (-1, -1), 4),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    for i, f in enumerate(findings, 1):
        istyle.append(("TEXTCOLOR", (2, i), (2, i), SEV_COLORS[f["severity"]]))
        istyle.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
        if i % 2 == 0:
            istyle.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAFBFC")))
    it.setStyle(TableStyle(istyle))
    e.append(it)
    return e


def _exec_summary(findings, meta, st):
    counts = _counts(findings)
    crit_high = counts["Critical"] + counts["High"]
    e = [Paragraph("Executive Summary", st["H1"])]
    if findings:
        verdict = (
            f"The log review identified <b>{len(findings)}</b> distinct type(s) "
            f"of sensitive data being written to the application/API logs, across "
            f"<b>{sum(f['count'] for f in findings)}</b> instance(s). "
        )
        if crit_high:
            verdict += (f"Of these, <b>{crit_high}</b> are rated High or Critical "
                        "and represent an immediate risk of credential theft, "
                        "session hijacking, payment fraud or privacy/regulatory "
                        "breach (CWE-532). These should be remediated as a priority.")
        else:
            verdict += ("No High/Critical sensitive-data exposure was detected, "
                        "but the items below still constitute personal-data leakage "
                        "that should be addressed under data-minimisation principles.")
    else:
        verdict = ("No sensitive data matching the configured detectors was found "
                   "in the supplied log files. This is a point-in-time result limited "
                   "to the detectors and samples provided.")
    e.append(Paragraph(verdict, st["Body"]))
    e.append(Spacer(1, 0.2 * cm))
    e.append(Paragraph(
        "Logging sensitive data (credentials, tokens, OTPs, payment data, "
        "national IDs and other PII) violates CWE-532 and exposes that data to "
        "everyone with access to logs, SIEM pipelines, and backups. Logs are "
        "frequently retained far longer and shared more widely than the "
        "application's primary data store, which amplifies the breach impact.",
        st["Body"]))
    e.append(Paragraph(
        "<b>Methodology.</b> Each supplied log file was parsed into records and "
        "scanned with pattern-based detectors. Structural validators (Luhn for "
        "payment cards, the Verhoeff checksum for Aadhaar, PAN structure and IPv4 "
        "octet checks) were applied to reduce false positives. Every reported "
        "value is masked in this report and keyed to its source file, position "
        "and timestamp for verification.", st["Body"]))
    return e


def _severity_legend(st):
    e = [Spacer(1, 0.3 * cm), Paragraph("Severity Classification", st["H2"])]
    desc = {
        "Critical": "Direct compromise / regulatory breach: secrets, payment data, full auth tokens.",
        "High": "National IDs, OTPs, session IDs, API tokens enabling impersonation or ID fraud.",
        "Medium": "PII such as phone, email, DOB, banking codes — privacy and correlation risk.",
        "Low": "Lower-sensitivity disclosure (e.g. IP addresses) useful for reconnaissance.",
        "Info": "Informational observations.",
    }
    rows = [["Severity", "Meaning"]]
    for s in SEV_ORDER:
        rows.append([s, Paragraph(desc[s], st["Small"])])
    t = Table(rows, colWidths=[3 * cm, 12.4 * cm])
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
             ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
             ("FONTSIZE", (0, 0), (-1, -1), 8.5),
             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 4),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    for i, s in enumerate(SEV_ORDER, 1):
        style.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLORS[s]))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    e.append(t)
    return e


def _detailed_findings(findings, st, max_rows):
    e = [Paragraph("Detailed Findings", st["H1"])]
    if not findings:
        e.append(Paragraph("No findings to report.", st["Body"]))
        return e
    for f in findings:
        e.extend(_finding_block(f, st, max_rows))
        e.append(Spacer(1, 0.5 * cm))
    return e


def _kv(label, value, st):
    return Table(
        [[Paragraph(label, st["Label"]), Paragraph(value, st["Body"])]],
        colWidths=[3.2 * cm, 12.2 * cm],
        style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                          ("LEFTPADDING", (0, 0), (-1, -1), 0),
                          ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))


def _finding_block(f, st, max_rows):
    header = Table(
        [[Paragraph(f'{f["id"]} — {f["name"]}', st["FindingTitle"]),
          _sev_chip(f["severity"], st)]],
        colWidths=[13.1 * cm, 2.3 * cm])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, SEV_COLORS[f["severity"]]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    # Header + metadata kept together so a finding title never orphans.
    head_group = KeepTogether([
        header,
        Spacer(1, 4),
        _kv("References", f.get("references", "—"), st),
        _kv("Affected files", ", ".join(f["files"]) or "—", st),
        _kv("Occurrences", str(f["count"]), st),
        Spacer(1, 4),
        Paragraph("Description / Evidence", st["Label"]),
        Paragraph(
            "The scanner detected this sensitive data type in the logs. "
            "Representative evidence (values masked), keyed by source file, "
            "position and timestamp:", st["Body"]),
    ])

    # evidence table (may break across pages if long)
    rows = [["#", "File", "Location", "Timestamp (primary key)", "Evidence (masked)"]]
    for i, inst in enumerate(f["instances"][:max_rows], 1):
        rows.append([
            str(i),
            Paragraph(inst["file"], st["Small"]),
            Paragraph(inst["location"], st["Small"]),
            Paragraph(inst["timestamp"] or "—", st["Small"]),
            Paragraph(inst["evidence"], st["SmallMono"]),
        ])
    et = Table(rows, colWidths=[0.8 * cm, 3.4 * cm, 2.6 * cm, 3.6 * cm, 5 * cm],
               repeatRows=1)
    et.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#FAFBFC")]),
    ]))

    out = [head_group, et]
    if f["count"] > max_rows:
        out.append(Paragraph(
            f"<i>… and {f['count'] - max_rows} more instance(s) not shown.</i>",
            st["Small"]))
    out.append(Spacer(1, 4))
    out.append(KeepTogether([
        Paragraph("Impact", st["Label"]),
        Paragraph(f["impact"], st["Body"]),
        Paragraph("Recommendation / Mitigation", st["Label"]),
        Paragraph(f["recommendation"], st["Body"]),
    ]))
    return out


def _appendix(meta, st):
    e = [Paragraph("Appendix A — Detector Coverage", st["H1"])]
    from detectors import DETECTORS
    rows = [["Code", "Detects", "Severity"]]
    for d in DETECTORS:
        rows.append([d.id, Paragraph(d.name, st["Small"]), d.severity])
    t = Table(rows, colWidths=[3 * cm, 9.8 * cm, 2.6 * cm], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
             ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
             ("FONTSIZE", (0, 0), (-1, -1), 8),
             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    t.setStyle(TableStyle(style))
    e.append(t)
    e.append(Spacer(1, 0.5 * cm))
    e.append(Paragraph("Appendix B — Scope & Disclaimer", st["H2"]))
    e.append(Paragraph(
        "This assessment is a point-in-time, pattern-based review of the log "
        "samples supplied by the client. Absence of a finding is not proof of "
        "absence of sensitive data: detection is limited to the configured "
        "patterns and the data provided. Pattern matching can yield false "
        "positives and false negatives; all findings should be validated against "
        "source data before remediation sign-off. Sensitive values shown in this "
        "report are masked.", st["Body"]))
    e.append(Paragraph(
        f"Report generated by {meta.get('tool_name', 'LogScan')} on "
        f"{datetime.now().strftime('%d %b %Y %H:%M')}.", st["Small"]))
    return e
