import io
import csv
import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Response, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from models.database import get_db, Scan, Watchlist

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/export", tags=["Export Reports"])


@router.get("/{scan_id}")
def export_report(
    scan_id: str,
    format: str = Query(..., description="Export format: json, csv, or pdf"),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    format = format.lower()
    
    if format == "json":
        return _export_json(scan)
    elif format == "csv":
        return _export_csv(scan)
    elif format == "pdf":
        return _export_pdf(scan)
    else:
        raise HTTPException(status_code=400, detail="Invalid format specified. Choose 'json', 'csv', or 'pdf'.")


def _export_json(scan: Scan):
    data = {
        "id": scan.id,
        "indicator": scan.indicator,
        "type": scan.type,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "summary": scan.summary,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "raw_data": scan.raw_data
    }
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=threatmap_scan_{scan.indicator}.json"}
    )


def _export_csv(scan: Scan):
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["Field", "Value"])
    writer.writerow(["ID", scan.id])
    writer.writerow(["Indicator", scan.indicator])
    writer.writerow(["Type", scan.type])
    writer.writerow(["Risk Score", scan.risk_score])
    writer.writerow(["Risk Level", scan.risk_level])
    writer.writerow(["Summary", scan.summary])
    writer.writerow(["Scan Date (UTC)", scan.created_at.isoformat() if scan.created_at else ""])
    
    raw_data = scan.raw_data or {}
    vt = raw_data.get("virustotal", {})
    writer.writerow(["VirusTotal Malicious", vt.get("malicious", 0)])
    writer.writerow(["VirusTotal Harmless", vt.get("harmless", 0)])
    
    if scan.type == "ip":
        abuse = raw_data.get("abuseipdb", {})
        writer.writerow(["AbuseIPDB Score", abuse.get("abuseConfidenceScore", 0)])
        writer.writerow(["AbuseIPDB Reports", abuse.get("totalReports", 0)])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.read().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=threatmap_scan_{scan.indicator}.csv"}
    )


def _export_pdf(scan: Scan):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        rightMargin=36, leftMargin=36,
        topMargin=36, bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Color Palette
    PRIMARY_CYAN = colors.HexColor("#38bdf8")
    ACCENT_TEAL = colors.HexColor("#2dd4bf")
    TEXT_WHITE = colors.HexColor("#f8fafc")
    TEXT_GREY = colors.HexColor("#cbd5e1")
    TEXT_MUTED = colors.HexColor("#94a3b8")
    BG_CARD = colors.HexColor("#1e293b")
    BG_HEADER = colors.HexColor("#0f172a")
    BORDER_COLOR = colors.HexColor("#334155")
    ALERT_RED = colors.HexColor("#ef4444")
    ALERT_GREEN = colors.HexColor("#10b981")
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=TEXT_WHITE,
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=9.5,
        textColor=PRIMARY_CYAN,
        spaceAfter=12,
        fontName='Helvetica'
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=11.5,
        textColor=PRIMARY_CYAN,
        spaceBefore=10,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    
    body_text = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontSize=8.5,
        textColor=TEXT_GREY,
        spaceAfter=6,
        leading=12,
        fontName='Helvetica'
    )
    
    table_hdr_style = ParagraphStyle(
        'TableHdr',
        parent=styles['Normal'],
        fontSize=8.5,
        textColor=PRIMARY_CYAN,
        fontName='Helvetica-Bold'
    )
    
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=8,
        textColor=TEXT_WHITE,
        leading=11,
        fontName='Helvetica'
    )
    
    table_cell_mono = ParagraphStyle(
        'TableCellMono',
        parent=styles['Normal'],
        fontSize=7.5,
        textColor=TEXT_WHITE,
        leading=10,
        fontName='Courier'
    )
    
    explainer_box_style = ParagraphStyle(
        'ExplainerBox',
        parent=styles['Normal'],
        fontSize=7.5,
        textColor=TEXT_MUTED,
        leading=10.5,
        fontName='Helvetica-Oblique'
    )
    
    warning_notice = ParagraphStyle(
        'WarningNotice',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor("#fca5a5"),
        leading=11.5,
        fontName='Helvetica'
    )

    elements = []
    
    # Header Banner
    elements.append(Paragraph("<b>THREATMAP</b> | CYBERSECURITY THREAT DOSSIER", title_style))
    scan_time_str = scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.created_at else "N/A"
    export_time_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    elements.append(Paragraph(f"REPORT ID: {scan.id} &nbsp;|&nbsp; SCAN DATE: {scan_time_str} &nbsp;|&nbsp; EXPORTED: {export_time_str}", subtitle_style))
    
    # Notice Box
    notice_table = Table([[Paragraph("<b>CONFIDENTIAL THREAT DOSSIER:</b> Real-time threat telemetry aggregated across VirusTotal, AbuseIPDB, AlienVault OTX, URLScan.io, and WHOIS APIs. Verify critical indicators prior to active containment.", warning_notice)]], colWidths=[540])
    notice_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#450a0a")),
        ('BORDER', (0,0), (-1,-1), 1, ALERT_RED),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(notice_table)
    elements.append(Spacer(1, 10))
    
    # Helper to build robust table cells that wrap text
    def wrap_cell(val, is_key=False, is_mono=False):
        if is_key:
            return Paragraph(f"<b>{val}</b>", table_hdr_style)
        st = table_cell_mono if is_mono else table_cell_style
        return Paragraph(str(val), st)

    # Helper to build Explainer Box
    def build_explainer(title: str, what_why: str, missing_reason: str):
        content = [
            Paragraph(f"<b>[EXPLAINER & PROVENANCE]</b> <i>{title}</i>", ParagraphStyle('ExpTitle', parent=explainer_box_style, textColor=PRIMARY_CYAN, fontName='Helvetica-Bold')),
            Paragraph(f"<b>What & Why:</b> {what_why}", explainer_box_style),
            Paragraph(f"<b>If Data Not Shown:</b> {missing_reason}", explainer_box_style)
        ]
        t = Table([[c] for c in content], colWidths=[540])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#090d16")),
            ('BORDER', (0,0), (-1,-1), 1, colors.HexColor("#1e293b")),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        return t

    # SECTION 1: Target Overview
    s1_elements = []
    s1_elements.append(Paragraph("I. Executive Target Summary & Risk Rating", section_heading))
    
    target_info = [
        [wrap_cell("Indicator Target:", True), wrap_cell(scan.indicator, is_mono=True), wrap_cell("Target Type:", True), wrap_cell(scan.type.upper())],
        [wrap_cell("Scan ID:", True), wrap_cell(scan.id, is_mono=True), wrap_cell("Scan Date (UTC):", True), wrap_cell(scan_time_str)],
        [wrap_cell("Threat Risk Score:", True), wrap_cell(f"{scan.risk_score} / 100"), wrap_cell("Verdict Level:", True), wrap_cell(scan.risk_level.upper() if scan.risk_level else ("HIGH" if scan.risk_score>=70 else "CLEAN"))]
    ]
    
    t_info = Table(target_info, colWidths=[105, 165, 105, 165])
    t_info.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
        ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
        ('BACKGROUND', (1,0), (1,-1), BG_CARD),
        ('BACKGROUND', (3,0), (3,-1), BG_CARD),
        ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    s1_elements.append(t_info)
    s1_elements.append(Spacer(1, 4))
    s1_elements.append(build_explainer(
        "ThreatMap Risk Engine Scoring Model",
        "Calculated deterministically using multi-vendor engine consensus weights (VirusTotal 90+ vendors, AbuseIPDB reputation, AlienVault OTX community pulses, and URLScan sandbox verdicts).",
        "If risk score is 0, no commercial security vendor or threat intelligence feed has flagged this target as malicious."
    ))
    elements.append(KeepTogether(s1_elements))
    elements.append(Spacer(1, 10))

    # SECTION 2: AI Analyst Brief & Playbook
    s2_elements = []
    s2_elements.append(Paragraph("II. AI Threat Intelligence Brief & Remediation Playbook", section_heading))
    raw = scan.raw_data or {}
    ai_raw = raw.get("ai_summary", {})
    
    summary_text = scan.summary or (ai_raw.get("summary") if isinstance(ai_raw, dict) else "No AI summary generated for this indicator.")
    s2_elements.append(Paragraph(f"<b>Executive Summary:</b> {summary_text}", body_text))
    
    playbook_steps = ai_raw.get("playbook", []) if isinstance(ai_raw, dict) else []
    if playbook_steps and len(playbook_steps) > 0:
        s2_elements.append(Paragraph("<b>Recommended SOC Remediation Playbook:</b>", ParagraphStyle('SubH', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
        pb_table_data = []
        for idx, step in enumerate(playbook_steps, 1):
            pb_table_data.append([wrap_cell(f"Step {idx}", True), wrap_cell(step)])
        pb_table = Table(pb_table_data, colWidths=[55, 485])
        pb_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#2a1215")),
            ('BACKGROUND', (1,0), (1,-1), BG_CARD),
            ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        s2_elements.append(pb_table)
    
    s2_elements.append(Spacer(1, 4))
    s2_elements.append(build_explainer(
        "AI Analyst Brief & Mitigation Playbook",
        "Synthesizes cross-vendor threat telemetry into non-hallucinated, structured executive summaries and SOC action plans.",
        "If missing or minimal, the LLM provider API was unreachable or raw telemetry had insufficient threat markers to generate actionable playbooks."
    ))
    elements.append(KeepTogether(s2_elements))
    elements.append(Spacer(1, 10))

    # SECTION 3: VirusTotal Deep Inspection
    s3_elements = []
    s3_elements.append(Paragraph("III. VirusTotal Commercial Antivirus Consensus (90+ Vendors)", section_heading))
    vt = raw.get("virustotal", {})
    if vt and isinstance(vt, dict):
        vt_mal = vt.get("malicious", 0)
        vt_sus = vt.get("suspicious", 0)
        vt_harm = vt.get("harmless", 0)
        vt_und = vt.get("undetected", 0)
        vt_total = vt_mal + vt_sus + vt_harm + vt_und
        
        vt_summary = [
            [wrap_cell("Malicious Detections:", True), wrap_cell(f"{vt_mal} / {vt_total} vendors"), wrap_cell("Harmless Verdicts:", True), wrap_cell(f"{vt_harm} vendors")],
            [wrap_cell("Suspicious Verdicts:", True), wrap_cell(f"{vt_sus} vendors"), wrap_cell("Undetected Engines:", True), wrap_cell(f"{vt_und} vendors")]
        ]
        vt_table = Table(vt_summary, colWidths=[115, 155, 115, 155])
        vt_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
            ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
            ('BACKGROUND', (1,0), (1,-1), BG_CARD),
            ('BACKGROUND', (3,0), (3,-1), BG_CARD),
            ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        s3_elements.append(vt_table)
    else:
        s3_elements.append(Paragraph("<i>No VirusTotal record found for this target.</i>", body_text))

    s3_elements.append(Spacer(1, 4))
    s3_elements.append(build_explainer(
        "VirusTotal Multi-Vendor AV Telemetry",
        "Aggregates detection status across 90+ antivirus products, web security scanners, and domain/IP reputation databases.",
        "0 detections indicates clean status across commercial AV engines, or indicator is not indexed by VirusTotal."
    ))
    elements.append(KeepTogether(s3_elements))
    elements.append(Spacer(1, 10))

    # SECTION 4: AbuseIPDB Telemetry (For IPs)
    if scan.type == "ip":
        s4_elements = []
        s4_elements.append(Paragraph("IV. AbuseIPDB Forensic Abuse & Reputation Records", section_heading))
        abuse = raw.get("abuseipdb", {})
        if abuse and isinstance(abuse, dict):
            ab_score = abuse.get("abuseConfidenceScore", 0)
            ab_reports = abuse.get("totalReports", 0)
            ab_isp = abuse.get("isp", "Unknown ISP")
            ab_country = abuse.get("countryCode", "N/A")
            ab_usage = abuse.get("usageType", "N/A")
            
            ab_data = [
                [wrap_cell("Abuse Score:", True), wrap_cell(f"{ab_score}%"), wrap_cell("Total Incidents:", True), wrap_cell(str(ab_reports))],
                [wrap_cell("Network ISP:", True), wrap_cell(ab_isp), wrap_cell("Country / Usage:", True), wrap_cell(f"{ab_country} ({ab_usage})")]
            ]
            ab_table = Table(ab_data, colWidths=[115, 155, 115, 155])
            ab_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
                ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
                ('BACKGROUND', (1,0), (1,-1), BG_CARD),
                ('BACKGROUND', (3,0), (3,-1), BG_CARD),
                ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            s4_elements.append(ab_table)
        else:
            s4_elements.append(Paragraph("<i>No AbuseIPDB reports recorded for this IP address.</i>", body_text))

        s4_elements.append(Spacer(1, 4))
        s4_elements.append(build_explainer(
            "AbuseIPDB Crowd-Sourced IP Tracking",
            "Monitors real-time web server logs, SSH brute-force attempts, spam distribution, and port scanning reports.",
            "0% score indicates no malicious reports submitted by system administrators in the past 90 days."
        ))
        elements.append(KeepTogether(s4_elements))
        elements.append(Spacer(1, 10))

    # SECTION 5: AlienVault OTX Threat Feeds
    s5_elements = []
    s5_elements.append(Paragraph("V. AlienVault OTX (Open Threat Exchange) Feeds & ATT&CK", section_heading))
    otx = raw.get("alienvault", {})
    if otx and isinstance(otx, dict):
        pulse_count = otx.get("pulse_count", 0)
        malware = otx.get("malware_families", [])
        attack = otx.get("attack_ids", [])
        
        otx_data = [
            [wrap_cell("Threat Pulses:", True), wrap_cell(f"{pulse_count} Pulses"), wrap_cell("Associated Malware:", True), wrap_cell(", ".join(malware[:3]) if malware else "None")],
            [wrap_cell("MITRE ATT&CK:", True), wrap_cell(f"{len(attack)} TTPs" if attack else "None"), wrap_cell("OTX Status:", True), wrap_cell("ACTIVE FEEDS" if pulse_count > 0 else "CLEAN")]
        ]
        otx_table = Table(otx_data, colWidths=[115, 155, 115, 155])
        otx_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
            ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
            ('BACKGROUND', (1,0), (1,-1), BG_CARD),
            ('BACKGROUND', (3,0), (3,-1), BG_CARD),
            ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        s5_elements.append(otx_table)
    else:
        s5_elements.append(Paragraph("<i>No AlienVault OTX threat pulses associated with this target.</i>", body_text))

    s5_elements.append(Spacer(1, 4))
    s5_elements.append(build_explainer(
        "AlienVault OTX Global Threat Exchange",
        "Tracks adversary campaign reports (Pulses), targeted industries, malware hashes, and MITRE ATT&CK techniques.",
        "0 pulses indicates no security analyst has published a threat report referencing this specific indicator."
    ))
    elements.append(KeepTogether(s5_elements))
    elements.append(Spacer(1, 10))

    # SECTION 6: URLScan.io Sandbox Telemetry (For Domains & URLs)
    if scan.type == "domain" or scan.type == "url":
        s6_elements = []
        s6_elements.append(Paragraph("VI. URLScan.io Sandbox Telemetry & Web Footprint", section_heading))
        urlscan = raw.get("urlscan", {})
        if urlscan and isinstance(urlscan, dict) and urlscan.get("scan_id"):
            u_verdict = urlscan.get("verdicts", {}).get("overall", {})
            u_mal = u_verdict.get("malicious", False)
            u_score = u_verdict.get("score", 0)
            u_title = urlscan.get("page_title", "N/A")
            u_server = urlscan.get("server", "N/A")
            u_url = urlscan.get("final_url", scan.indicator)
            
            u_data = [
                [wrap_cell("Sandbox Verdict:", True), wrap_cell("MALICIOUS" if u_mal else f"CLEAN (Score: {u_score})"), wrap_cell("Server Software:", True), wrap_cell(u_server)],
                [wrap_cell("Page Title:", True), wrap_cell(u_title), wrap_cell("Landed URL:", True), wrap_cell(u_url, is_mono=True)]
            ]
            u_table = Table(u_data, colWidths=[115, 155, 115, 155])
            u_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
                ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
                ('BACKGROUND', (1,0), (1,-1), BG_CARD),
                ('BACKGROUND', (3,0), (3,-1), BG_CARD),
                ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            s6_elements.append(u_table)
        else:
            s6_elements.append(Paragraph("<i>No public urlscan.io sandbox scan logged for this target.</i>", body_text))

        s6_elements.append(Spacer(1, 4))
        s6_elements.append(build_explainer(
            "URLScan.io Headless Browser Telemetry",
            "Executes headless browser sandbox sessions capturing live DOM tree, network request logs, technologies, and screenshots.",
            "If not logged, no automated public scan has been executed on urlscan.io for this specific web endpoint."
        ))
        elements.append(KeepTogether(s6_elements))
        elements.append(Spacer(1, 10))

    # SECTION 7: OSINT WHOIS & Domain Infrastructure
    if scan.type == "domain":
        s7_elements = []
        s7_elements.append(Paragraph("VII. OSINT WHOIS & Domain Infrastructure", section_heading))
        whois = raw.get("whoisjson", {})
        if whois and isinstance(whois, dict):
            reg = whois.get("registrar_metadata", {}).get("name", "Unknown Registrar")
            dates = whois.get("registry_dates", {})
            created = dates.get("creation_date", "Unknown")
            expires = dates.get("expiration_date", "Unknown")
            
            w_data = [
                [wrap_cell("Domain Registrar:", True), wrap_cell(reg), wrap_cell("Creation Date:", True), wrap_cell(created)],
                [wrap_cell("Expiration Date:", True), wrap_cell(expires), wrap_cell("Status:", True), wrap_cell("RECORDS RETRIEVED")]
            ]
            w_table = Table(w_data, colWidths=[115, 155, 115, 155])
            w_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
                ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
                ('BACKGROUND', (1,0), (1,-1), BG_CARD),
                ('BACKGROUND', (3,0), (3,-1), BG_CARD),
                ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            s7_elements.append(w_table)
        else:
            s7_elements.append(Paragraph("<i>WHOIS records unavailable or privacy-protected.</i>", body_text))

        s7_elements.append(Spacer(1, 4))
        s7_elements.append(build_explainer(
            "ICANN WHOIS Domain Registration Records",
            "Provides domain age, registrar authority, expiration dates, and owner metadata for risk assessment.",
            "If missing, domain registry server rate-limited requests or WHOIS privacy protection obfuscated registration data."
        ))
        elements.append(KeepTogether(s7_elements))
        elements.append(Spacer(1, 10))

    # SECTION 8: Vendor Provenance Footer
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("<b>PROVENANCE DISCLAIMER & METHODOLOGY:</b> This threat dossier was generated by ThreatMap Platform v2.0. Telemetry data is fetched asynchronously directly from vendor API backends. Third-party findings must be manually validated prior to implementing firewall blocklists or SOC containment actions.", ParagraphStyle('FootNote', parent=body_text, fontSize=7.5, textColor=TEXT_MUTED, leading=10)))

    # Dark background canvas callback
    def add_pdf_decorations(canvas, doc):
        canvas.saveState()
        # Page background
        canvas.setFillColor(colors.HexColor("#020617"))
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
        
        # Header accent bar
        canvas.setFillColor(BG_HEADER)
        canvas.rect(0, doc.pagesize[1] - 45, doc.pagesize[0], 45, fill=1, stroke=0)
        canvas.setFillColor(PRIMARY_CYAN)
        canvas.rect(0, doc.pagesize[1] - 45, doc.pagesize[0], 2, fill=1, stroke=0)
        
        # Footer text
        canvas.setFillColor(TEXT_MUTED)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(36, 18, "THREATMAP CYBERSECURITY | INTELLIGENCE DOSSIER")
        canvas.drawRightString(doc.pagesize[0] - 36, 18, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_pdf_decorations, onLaterPages=add_pdf_decorations)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=threatmap_dossier_{scan.indicator}.pdf"}
    )


def export_json_old(scan_id: str, db: Session = Depends(get_db)):
    return export_report(scan_id, format="json", db=db)

def export_csv_old(scan_id: str, db: Session = Depends(get_db)):
    return export_report(scan_id, format="csv", db=db)

def export_pdf_old(scan_id: str, db: Session = Depends(get_db)):
    return export_report(scan_id, format="pdf", db=db)
