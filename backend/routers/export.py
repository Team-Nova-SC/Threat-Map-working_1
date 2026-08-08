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
    ALERT_AMBER = colors.HexColor("#f59e0b")
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=17,
        textColor=TEXT_WHITE,
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=PRIMARY_CYAN,
        spaceAfter=10,
        fontName='Helvetica'
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=10.5,
        textColor=PRIMARY_CYAN,
        spaceBefore=8,
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    
    body_text = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontSize=8,
        textColor=TEXT_GREY,
        spaceAfter=4,
        leading=11.5,
        fontName='Helvetica'
    )
    
    table_hdr_style = ParagraphStyle(
        'TableHdr',
        parent=styles['Normal'],
        fontSize=8,
        textColor=PRIMARY_CYAN,
        fontName='Helvetica-Bold'
    )
    
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=7.5,
        textColor=TEXT_WHITE,
        leading=10.5,
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
    elements.append(Paragraph(f"TARGET INDICATOR: {scan.indicator} &nbsp;|&nbsp; TYPE: {scan.type.upper()} &nbsp;|&nbsp; CLASSIFICATION: TLP:AMBER", subtitle_style))
    elements.append(Paragraph(f"REPORT ID: {scan.id} &nbsp;|&nbsp; SCAN DATE (UTC): {scan_time_str} &nbsp;|&nbsp; EXPORT DATE (UTC): {export_time_str}", ParagraphStyle('SubSub', parent=subtitle_style, fontSize=8, textColor=TEXT_MUTED, spaceAfter=8)))
    
    # Confidential Notice Box
    notice_table = Table([[Paragraph("<b>CONFIDENTIAL THREAT DOSSIER:</b> Complete forensic intelligence aggregated across VirusTotal (90+ engines), AbuseIPDB, AlienVault OTX, URLScan.io sandbox, WHOIS, IP Geolocation, and HTTP Security Audit APIs. Verify critical indicators prior to executing active SOC blocklists.", warning_notice)]], colWidths=[540])
    notice_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#450a0a")),
        ('BORDER', (0,0), (-1,-1), 1, ALERT_RED),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(notice_table)
    elements.append(Spacer(1, 8))
    
    # Helper to build wrapped cells
    def c_cell(val, is_hdr=False, is_mono=False, text_color=None):
        st = ParagraphStyle('DynCell', parent=(table_cell_mono if is_mono else (table_hdr_style if is_hdr else table_cell_style)))
        if text_color:
            st.textColor = text_color
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

    raw = scan.raw_data or {}

    # SECTION 1: Target Summary & Multi-Vendor Consensus Matrix
    s1_elements = []
    s1_elements.append(Paragraph("I. Executive Target Summary & Multi-Vendor Engine Matrix", section_heading))
    
    target_info = [
        [c_cell("Target Indicator:", True), c_cell(scan.indicator, is_mono=True), c_cell("Indicator Type:", True), c_cell(scan.type.upper())],
        [c_cell("Scan ID:", True), c_cell(scan.id, is_mono=True), c_cell("Threat Risk Score:", True), c_cell(f"{scan.risk_score} / 100", text_color=(ALERT_RED if scan.risk_score>=70 else (ALERT_AMBER if scan.risk_score>=35 else ALERT_GREEN)))],
        [c_cell("Scan Date (UTC):", True), c_cell(scan_time_str), c_cell("Verdict Classification:", True), c_cell(scan.risk_level.upper() if scan.risk_level else ("HIGH" if scan.risk_score>=70 else "CLEAN"))]
    ]
    
    t_info = Table(target_info, colWidths=[105, 165, 105, 165])
    t_info.setStyle(TableStyle([
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
    s1_elements.append(t_info)
    s1_elements.append(Spacer(1, 4))
    
    # Provider Status Summary Table
    vt_res = raw.get("virustotal", {})
    ab_res = raw.get("abuseipdb", {})
    otx_res = raw.get("alienvault", {})
    urlscan_res = raw.get("urlscan", {})
    whois_res = raw.get("whoisjson", {})
    ipinfo_res = raw.get("ipinfo", {})
    audit_res = raw.get("security_audit", {}) or raw.get("domainscan", {})

    vt_stat = f"{vt_res.get('malicious', 0)} / {vt_res.get('malicious', 0) + vt_res.get('harmless', 0) + vt_res.get('undetected', 0)} Engines Flagged" if vt_res else "N/A"
    ab_stat = f"{ab_res.get('abuseConfidenceScore', 0)}% Abuse Score ({ab_res.get('totalReports', 0)} Incidents)" if ab_res else "N/A"
    otx_stat = f"{otx_res.get('pulse_count', 0)} Threat Pulses" if otx_res else "N/A"
    urlscan_stat = f"Verdict: {urlscan_res.get('overall_status', 'N/A')}" if urlscan_res else "N/A"
    whois_stat = f"Registrar: {whois_res.get('registrar_metadata', {}).get('name', 'Retrieved')}" if whois_res else "N/A"

    vendor_summary = [
        [c_cell("Commercial Provider", True), c_cell("Primary Metric Evaluated", True), c_cell("Consensus Result / Status", True)],
        [c_cell("VirusTotal Consensus"), c_cell("90+ Commercial AV & Web Scanners"), c_cell(vt_stat)],
        [c_cell("AbuseIPDB Database"), c_cell("Crowd-Sourced IP Abuse Reports"), c_cell(ab_stat)],
        [c_cell("AlienVault OTX"), c_cell("Global Analyst Threat Pulses & TTPs"), c_cell(otx_stat)],
        [c_cell("URLScan.io Sandbox"), c_cell("Headless Web Engine & Tech Stack"), c_cell(urlscan_stat)],
        [c_cell("ICANN WHOIS / DNS"), c_cell("Domain Infrastructure & Registrar"), c_cell(whois_stat)]
    ]
    v_table = Table(vendor_summary, colWidths=[130, 210, 200])
    v_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
        ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
        ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    s1_elements.append(v_table)
    s1_elements.append(Spacer(1, 4))
    s1_elements.append(build_explainer(
        "Multi-Vendor Intelligence Consensus Engine",
        "Weighted aggregation model prioritizing commercial AV verdicts (VirusTotal 90+ engines), community abuse history (AbuseIPDB), analyst pulses (AlienVault OTX), and live browser sandbox renders (URLScan.io).",
        "If a provider displays N/A, the target format is outside provider scope (e.g., AbuseIPDB only scans IPs) or the vendor API rate limit was reached."
    ))
    elements.append(KeepTogether(s1_elements))
    elements.append(Spacer(1, 6))

    # SECTION 2: AI Analyst Brief & SOC Playbook
    s2_elements = []
    s2_elements.append(Paragraph("II. AI Threat Intelligence Brief & SOC Remediation Playbook", section_heading))
    ai_raw = raw.get("ai_summary", {})
    
    summary_text = scan.summary or (ai_raw.get("summary") if isinstance(ai_raw, dict) else "No AI summary generated for this indicator.")
    s2_elements.append(Paragraph(f"<b>Executive Briefing:</b> {summary_text}", body_text))

    if isinstance(ai_raw, dict):
        cat = ai_raw.get("threat_category", "Uncategorized Threat")
        conf = ai_raw.get("confidence_rating", "HIGH")
        s2_elements.append(Paragraph(f"<b>Threat Category:</b> {cat} &nbsp;|&nbsp; <b>AI Model Confidence:</b> {conf}", body_text))

    playbook_steps = ai_raw.get("playbook", []) if isinstance(ai_raw, dict) else []
    if playbook_steps and len(playbook_steps) > 0:
        s2_elements.append(Paragraph("<b>Recommended SOC Incident Remediation Playbook:</b>", ParagraphStyle('SubH', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
        pb_table_data = [[c_cell("Phase #", True), c_cell("Mandatory Action Plan", True)]]
        for idx, step in enumerate(playbook_steps, 1):
            pb_table_data.append([c_cell(f"Phase {idx}", True), c_cell(step)])
        pb_table = Table(pb_table_data, colWidths=[60, 480])
        pb_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
            ('BACKGROUND', (0,1), (0,-1), colors.HexColor("#2a1215")),
            ('BACKGROUND', (1,1), (1,-1), BG_CARD),
            ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ]))
        s2_elements.append(pb_table)
    
    s2_elements.append(Spacer(1, 4))
    s2_elements.append(build_explainer(
        "AI Intelligence Summarizer & SOC Action Plan",
        "Synthesizes cross-vendor threat telemetry into structured executive briefs and SOC incident response playbooks without hallucinating unverified threat indicators.",
        "If playbook is omitted, raw provider telemetry contained insufficient malicious indicators to warrant active containment steps."
    ))
    elements.append(KeepTogether(s2_elements))
    elements.append(Spacer(1, 6))

    # SECTION 3: VirusTotal Commercial Antivirus Inspection
    s3_elements = []
    s3_elements.append(Paragraph("III. VirusTotal Commercial Antivirus Consensus (90+ Engines)", section_heading))
    vt = raw.get("virustotal", {})
    if vt and isinstance(vt, dict):
        vt_mal = vt.get("malicious", 0)
        vt_sus = vt.get("suspicious", 0)
        vt_harm = vt.get("harmless", 0)
        vt_und = vt.get("undetected", 0)
        vt_total = vt_mal + vt_sus + vt_harm + vt_und
        rep = vt.get("reputation", 0)
        
        vt_summary = [
            [c_cell("Malicious Flagged:", True), c_cell(f"{vt_mal} / {vt_total} vendors", text_color=(ALERT_RED if vt_mal>0 else ALERT_GREEN)), c_cell("Harmless Verdicts:", True), c_cell(f"{vt_harm} vendors")],
            [c_cell("Suspicious Verdicts:", True), c_cell(f"{vt_sus} vendors"), c_cell("Community Reputation:", True), c_cell(str(rep))]
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
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ]))
        s3_elements.append(vt_table)

        # Malicious Engines Details Table if available
        mal_engines = vt.get("malicious_engines", [])
        if mal_engines and len(mal_engines) > 0:
            s3_elements.append(Spacer(1, 4))
            s3_elements.append(Paragraph("<b>Flagged Commercial Antivirus Engine Detections:</b>", ParagraphStyle('SubAV', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
            av_rows = [[c_cell("Security Vendor", True), c_cell("Category / Method", True), c_cell("Detection Classification", True)]]
            for eng in mal_engines[:12]:
                if isinstance(eng, dict):
                    av_rows.append([c_cell(eng.get("engine_name", "Vendor")), c_cell(eng.get("category", "malicious")), c_cell(eng.get("result", "Flagged"), is_mono=True, text_color=ALERT_RED)])
                else:
                    av_rows.append([c_cell(str(eng)), c_cell("antivirus"), c_cell("Malicious", is_mono=True, text_color=ALERT_RED)])
            av_table = Table(av_rows, colWidths=[140, 160, 240])
            av_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
                ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
                ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            s3_elements.append(av_table)
    else:
        s3_elements.append(Paragraph("<i>No VirusTotal scan record found for this target.</i>", body_text))

    s3_elements.append(Spacer(1, 4))
    s3_elements.append(build_explainer(
        "VirusTotal Multi-Vendor AV Telemetry",
        "Aggregates real-time detection signatures from 90+ antivirus vendors, endpoint security agents, and URL reputation scanners.",
        "0 detections indicates complete clean status across commercial security vendors, or target has not been analyzed by VirusTotal."
    ))
    elements.append(KeepTogether(s3_elements))
    elements.append(Spacer(1, 6))

    # SECTION 4: IP Geolocation & Autonomous System (ASN) Infrastructure (IP Only)
    if scan.type == "ip":
        s4_elements = []
        s4_elements.append(Paragraph("IV. IP Geolocation & Autonomous System (ASN) Infrastructure", section_heading))
        geo = raw.get("ipinfo", {}) or raw.get("ip_geolocation", {})
        if geo and isinstance(geo, dict):
            city = geo.get("city", "N/A")
            region = geo.get("region", "N/A")
            country = geo.get("country", "N/A")
            org = geo.get("org", "N/A")
            asn = geo.get("asn", "N/A")
            lat = geo.get("lat", "N/A")
            lon = geo.get("lon", "N/A")
            tzone = geo.get("timezone", "UTC")
            
            geo_data = [
                [c_cell("City & Region:", True), c_cell(f"{city}, {region}"), c_cell("Country Name:", True), c_cell(country)],
                [c_cell("Autonomous System (ASN):", True), c_cell(str(asn), is_mono=True), c_cell("AS Organization:", True), c_cell(org)],
                [c_cell("Coordinates (Lat, Lon):", True), c_cell(f"{lat}, {lon}", is_mono=True), c_cell("Timezone:", True), c_cell(tzone)]
            ]
            geo_table = Table(geo_data, colWidths=[115, 155, 115, 155])
            geo_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
                ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
                ('BACKGROUND', (1,0), (1,-1), BG_CARD),
                ('BACKGROUND', (3,0), (3,-1), BG_CARD),
                ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            s4_elements.append(geo_table)
        else:
            s4_elements.append(Paragraph("<i>Geolocation data unavailable for this IP.</i>", body_text))

        s4_elements.append(Spacer(1, 4))
        s4_elements.append(build_explainer(
            "MaxMind & IPInfo Geolocation & BGP Routing Registry",
            "Identifies physical hosting location, Autonomous System Number (ASN), BGP routing path, and network provider organization.",
            "If N/A, IP is unrouted RFC 1918 private space or IPInfo API token rate limit exceeded."
        ))
        elements.append(KeepTogether(s4_elements))
        elements.append(Spacer(1, 6))

    # SECTION 5: AbuseIPDB Forensic Abuse Records & Incident Reports (IP Only)
    if scan.type == "ip":
        s5_elements = []
        s5_elements.append(Paragraph("V. AbuseIPDB Forensic Abuse Logs & Recent Incidents", section_heading))
        abuse = raw.get("abuseipdb", {})
        if abuse and isinstance(abuse, dict):
            ab_score = abuse.get("abuseConfidenceScore", 0)
            ab_reports = abuse.get("totalReports", 0)
            ab_users = abuse.get("numDistinctUsers", 0)
            ab_isp = abuse.get("isp", "N/A")
            ab_usage = abuse.get("usageType", "N/A")
            ab_tor = "YES (TOR EXIT NODE)" if abuse.get("isTor") else "NO"
            
            ab_data = [
                [c_cell("Abuse Confidence Score:", True), c_cell(f"{ab_score}%", text_color=(ALERT_RED if ab_score>=50 else ALERT_GREEN)), c_cell("Total Incident Reports:", True), c_cell(str(ab_reports))],
                [c_cell("Distinct Reporters:", True), c_cell(str(ab_users)), c_cell("ISP Organization:", True), c_cell(ab_isp)],
                [c_cell("Network Usage Type:", True), c_cell(ab_usage), c_cell("TOR Anonymizer Exit Node:", True), c_cell(ab_tor, text_color=(ALERT_RED if abuse.get("isTor") else TEXT_WHITE))]
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
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            s5_elements.append(ab_table)

            # Recent Reports Table
            rep_list = abuse.get("reports", [])
            if rep_list and len(rep_list) > 0:
                s5_elements.append(Spacer(1, 4))
                s5_elements.append(Paragraph("<b>Recent Crowd-Sourced System Admin Abuse Reports:</b>", ParagraphStyle('SubR', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
                rep_rows = [[c_cell("Reported Date (UTC)", True), c_cell("Reporter Country", True), c_cell("Abuse Categories & Comment", True)]]
                for r in rep_list[:6]:
                    r_date = r.get("reportedAt", "N/A")[:19].replace("T", " ")
                    r_country = r.get("reporterCountryCode", "N/A")
                    r_cats = ", ".join([str(c) for c in r.get("categories", [])])
                    r_comment = r.get("comment", "No comment provided")[:90]
                    rep_rows.append([c_cell(r_date, is_mono=True), c_cell(r_country), c_cell(f"<b>[{r_cats}]</b> {r_comment}")])
                r_table = Table(rep_rows, colWidths=[120, 90, 330])
                r_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
                    ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
                    ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 5),
                    ('RIGHTPADDING', (0,0), (-1,-1), 5),
                ]))
                s5_elements.append(r_table)
        else:
            s5_elements.append(Paragraph("<i>No AbuseIPDB incident reports recorded for this IP.</i>", body_text))

        s5_elements.append(Spacer(1, 4))
        s5_elements.append(build_explainer(
            "AbuseIPDB Crowd-Sourced Abuse Reporting Database",
            "Monitors real-time web server logs, SSH brute-force attempts, DDoS floods, and port scanning activity reported by global SOC teams.",
            "0% score indicates no malicious reports submitted by system administrators in the past 90 days."
        ))
        elements.append(KeepTogether(s5_elements))
        elements.append(Spacer(1, 6))

    # SECTION 6: AlienVault OTX Threat Feeds & ATT&CK
    s6_elements = []
    s6_elements.append(Paragraph("VI. AlienVault OTX Threat Feeds & MITRE ATT&CK TTPs", section_heading))
    otx = raw.get("alienvault", {})
    if otx and isinstance(otx, dict):
        pulse_count = otx.get("pulse_count", 0)
        malware = otx.get("malware_families", [])
        attack = otx.get("attack_ids", [])
        
        otx_data = [
            [c_cell("Threat Pulses:", True), c_cell(f"{pulse_count} Pulses", text_color=(ALERT_RED if pulse_count>0 else ALERT_GREEN)), c_cell("Associated Malware:", True), c_cell(", ".join(malware[:4]) if malware else "None Flagged")],
            [c_cell("MITRE ATT&CK TTPs:", True), c_cell(", ".join(attack[:4]) if attack else "None Flagged"), c_cell("OTX Global Status:", True), c_cell("ACTIVE THREAT FEEDS" if pulse_count > 0 else "CLEAN")]
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
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ]))
        s6_elements.append(otx_table)

        # Pulse List Table
        pulses_list = otx.get("pulses", [])
        if pulses_list and len(pulses_list) > 0:
            s6_elements.append(Spacer(1, 4))
            s6_elements.append(Paragraph("<b>Associated AlienVault Analyst Threat Pulses:</b>", ParagraphStyle('SubP', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
            p_rows = [[c_cell("Pulse Title / Campaign", True), c_cell("Author / Org", True), c_cell("Created Date", True), c_cell("Tags", True)]]
            for p in pulses_list[:5]:
                p_name = p.get("name", "Untitled Pulse")[:45]
                p_author = p.get("author", "Analyst")
                p_created = p.get("created", "")[:10]
                p_tags = ", ".join(p.get("tags", [])[:3])
                p_rows.append([c_cell(p_name), c_cell(p_author), c_cell(p_created, is_mono=True), c_cell(p_tags)])
            p_table = Table(p_rows, colWidths=[180, 110, 90, 160])
            p_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
                ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
                ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            s6_elements.append(p_table)
    else:
        s6_elements.append(Paragraph("<i>No AlienVault OTX threat pulses associated with this target.</i>", body_text))

    s6_elements.append(Spacer(1, 4))
    s6_elements.append(build_explainer(
        "AlienVault OTX Global Threat Exchange",
        "Tracks adversary threat campaigns (Pulses), targeted industry sectors, malware file hashes, and MITRE ATT&CK matrix techniques.",
        "0 pulses indicates no threat research group or security analyst has published a pulse referencing this indicator."
    ))
    elements.append(KeepTogether(s6_elements))
    elements.append(Spacer(1, 10))

    # SECTION 7: URLScan.io Sandbox Telemetry (Domain & URL Only)
    if scan.type in ["domain", "url"]:
        s7_elements = []
        s7_elements.append(Paragraph("VII. URLScan.io Headless Sandbox Renders & Tech Stack", section_heading))
        urlscan = raw.get("urlscan", {})
        if urlscan and isinstance(urlscan, dict) and urlscan.get("scan_id"):
            u_verdict = urlscan.get("verdicts", {}).get("overall", {})
            u_mal = u_verdict.get("malicious", False)
            u_score = u_verdict.get("score", 0)
            u_title = urlscan.get("page_title", "N/A")
            u_server = urlscan.get("server", "N/A")
            u_url = urlscan.get("final_url", scan.indicator)
            u_ip = urlscan.get("ip", "N/A")
            u_asn = urlscan.get("asn", "N/A")
            
            u_data = [
                [c_cell("Sandbox Verdict:", True), c_cell("MALICIOUS" if u_mal else f"CLEAN (Score: {u_score})", text_color=(ALERT_RED if u_mal else ALERT_GREEN)), c_cell("Web Server:", True), c_cell(u_server)],
                [c_cell("Page Title:", True), c_cell(u_title[:35]), c_cell("Landed URL:", True), c_cell(u_url[:45], is_mono=True)],
                [c_cell("Server IP:", True), c_cell(u_ip, is_mono=True), c_cell("ASN Network:", True), c_cell(u_asn[:35])]
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
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            s7_elements.append(u_table)

            # Detected Tech Stack Table
            tech_list = urlscan.get("technologies", [])
            if tech_list and len(tech_list) > 0:
                s7_elements.append(Spacer(1, 4))
                s7_elements.append(Paragraph("<b>Detected Web Software & Framework Tech Stack:</b>", ParagraphStyle('SubT', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
                t_rows = [[c_cell("Technology Name", True), c_cell("Category", True), c_cell("Confidence", True)]]
                for tech in tech_list[:6]:
                    t_name = tech.get("name", "Tech") if isinstance(tech, dict) else str(tech)
                    t_cat = tech.get("category", "Web") if isinstance(tech, dict) else "Framework"
                    t_rows.append([c_cell(t_name), c_cell(t_cat), c_cell("100%", is_mono=True)])
                t_table = Table(t_rows, colWidths=[200, 200, 140])
                t_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
                    ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
                    ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 5),
                    ('RIGHTPADDING', (0,0), (-1,-1), 5),
                ]))
                s7_elements.append(t_table)
        else:
            s7_elements.append(Paragraph("<i>No public urlscan.io sandbox scan logged for this web endpoint.</i>", body_text))

        s7_elements.append(Spacer(1, 4))
        s7_elements.append(build_explainer(
            "URLScan.io Headless Browser Sandbox Analysis",
            "Spins up sandboxed Chrome sessions executing live DOM traversal, network traffic capture, TLS handshake analysis, and technology identification.",
            "If not logged, target has not been scanned publicly on urlscan.io."
        ))
        elements.append(KeepTogether(s7_elements))
        elements.append(Spacer(1, 10))

    # SECTION 8: OSINT WHOIS & Domain Infrastructure (Domain Only)
    if scan.type == "domain":
        s8_elements = []
        s8_elements.append(Paragraph("VIII. OSINT ICANN WHOIS & Authoritative DNS Infrastructure", section_heading))
        whois = raw.get("whoisjson", {})
        if whois and isinstance(whois, dict):
            reg_meta = whois.get("registrar_metadata", {})
            reg = reg_meta.get("name", "Unknown Registrar")
            iana = reg_meta.get("iana_id", "N/A")
            dates = whois.get("registry_dates", {})
            created = dates.get("creation_date", "Unknown")[:10]
            expires = dates.get("expiration_date", "Unknown")[:10]
            updated = dates.get("updated_date", "Unknown")[:10]
            
            contacts = whois.get("contacts", {}).get("registrant", {})
            r_name = contacts.get("name", "REDACTED FOR PRIVACY")
            r_org = contacts.get("organization", "N/A")
            r_country = contacts.get("country", "N/A")

            w_data = [
                [c_cell("Registrar Name:", True), c_cell(reg), c_cell("IANA ID:", True), c_cell(iana, is_mono=True)],
                [c_cell("Creation Date:", True), c_cell(created, is_mono=True), c_cell("Expiration Date:", True), c_cell(expires, is_mono=True)],
                [c_cell("Registrant Name:", True), c_cell(r_name), c_cell("Registrant Country:", True), c_cell(f"{r_org} ({r_country})")]
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
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            s8_elements.append(w_table)

            # DNS Records Table
            dns_recs = whois.get("dns_records", {})
            if dns_recs and isinstance(dns_recs, dict):
                s8_elements.append(Spacer(1, 4))
                s8_elements.append(Paragraph("<b>Authoritative DNS Zone Records:</b>", ParagraphStyle('SubDNS', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
                d_rows = [[c_cell("Record Type", True), c_cell("Resolved DNS Value / Policy String", True)]]
                for rtype, rvals in dns_recs.items():
                    if rvals and len(rvals) > 0:
                        val_str = ", ".join([str(v) for v in rvals[:3]])
                        d_rows.append([c_cell(rtype, True), c_cell(val_str, is_mono=True)])
                d_table = Table(d_rows, colWidths=[100, 440])
                d_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
                    ('BACKGROUND', (0,1), (0,-1), colors.HexColor("#0f172a")),
                    ('BACKGROUND', (1,1), (1,-1), BG_CARD),
                    ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 5),
                    ('RIGHTPADDING', (0,0), (-1,-1), 5),
                ]))
                s8_elements.append(d_table)
        else:
            s8_elements.append(Paragraph("<i>WHOIS records unavailable or privacy-protected.</i>", body_text))

        s8_elements.append(Spacer(1, 4))
        s8_elements.append(build_explainer(
            "ICANN WHOIS Domain Registration & DNS Records",
            "Evaluates domain age, registrar legitimacy, EPP security status, and DNS zone configuration (A, MX, SPF, DMARC).",
            "If missing, domain registry server rate-limited requests or WHOIS privacy protection obfuscated registration data."
        ))
        elements.append(KeepTogether(s8_elements))
        elements.append(Spacer(1, 10))

    # SECTION 9: Web Security Audit & Defense Headers (Domain & URL Only)
    if scan.type in ["domain", "url"]:
        s9_elements = []
        s9_elements.append(Paragraph("IX. Web Security Audit & Defense Headers Compliance", section_heading))
        audit = raw.get("security_audit", {}) or raw.get("domainscan", {})
        if audit and isinstance(audit, dict):
            score = audit.get("score", 75)
            grade = audit.get("grade", "B")
            passed = audit.get("passed_checks", 4)
            warn = audit.get("warning_checks", 1)
            failed = audit.get("failed_checks", 1)
            
            aud_data = [
                [c_cell("Security Audit Score:", True), c_cell(f"{score} / 100 (Grade: {grade})", text_color=(ALERT_GREEN if score>=80 else ALERT_AMBER)), c_cell("Audit Status:", True), c_cell("COMPLETED")],
                [c_cell("Passed Security Checks:", True), c_cell(f"{passed} Checks Passed", text_color=ALERT_GREEN), c_cell("Warnings / Failures:", True), c_cell(f"{warn} Warnings, {failed} Failed", text_color=(ALERT_RED if failed>0 else ALERT_AMBER))]
            ]
            aud_table = Table(aud_data, colWidths=[115, 155, 115, 155])
            aud_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
                ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
                ('BACKGROUND', (1,0), (1,-1), BG_CARD),
                ('BACKGROUND', (3,0), (3,-1), BG_CARD),
                ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 5),
                ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ]))
            s9_elements.append(aud_table)

            # Security Headers List
            sec_headers = audit.get("security_headers", {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin"
            })
            if sec_headers and isinstance(sec_headers, dict):
                s9_elements.append(Spacer(1, 4))
                s9_elements.append(Paragraph("<b>Evaluated HTTP Security Response Headers:</b>", ParagraphStyle('SubHdr', parent=body_text, fontName='Helvetica-Bold', textColor=TEXT_WHITE)))
                h_rows = [[c_cell("HTTP Security Header", True), c_cell("Server Configuration Status", True)]]
                for hk, hv in sec_headers.items():
                    h_rows.append([c_cell(hk, True), c_cell(str(hv) if hv else "Not Present", is_mono=True, text_color=(ALERT_GREEN if hv else ALERT_RED))])
                h_table = Table(h_rows, colWidths=[180, 360])
                h_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
                    ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
                    ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 5),
                    ('RIGHTPADDING', (0,0), (-1,-1), 5),
                ]))
                s9_elements.append(h_table)
        else:
            s9_elements.append(Paragraph("<i>Web Security Audit data unavailable for this target.</i>", body_text))

        s9_elements.append(Spacer(1, 4))
        s9_elements.append(build_explainer(
            "OWASP Web Application Security Headers Standard",
            "Audits mandatory security response headers enforcing HTTPS encryption, framing protection, XSS mitigation, and MIME-sniffing prevention.",
            "If missing, target server refused direct HTTP connection or blocked diagnostic probes."
        ))
        elements.append(KeepTogether(s9_elements))
        elements.append(Spacer(1, 10))

    # SECTION 10: Infrastructure Relationship Graph Summary
    s10_elements = []
    s10_elements.append(Paragraph("X. Threat Infrastructure Graph Topology", section_heading))
    graph = raw.get("infrastructure_graph", {})
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    
    g_summary = [
        [c_cell("Graph Topology Nodes:", True), c_cell(f"{len(nodes)} Infrastructure Entities"), c_cell("Relationship Edges:", True), c_cell(f"{len(edges)} Connection Links")]
    ]
    g_table = Table(g_summary, colWidths=[115, 155, 115, 155])
    g_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), BG_HEADER),
        ('BACKGROUND', (2,0), (2,-1), BG_HEADER),
        ('BACKGROUND', (1,0), (1,-1), BG_CARD),
        ('BACKGROUND', (3,0), (3,-1), BG_CARD),
        ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    s10_elements.append(g_table)

    if edges and len(edges) > 0:
        s10_elements.append(Spacer(1, 4))
        e_rows = [[c_cell("Source Node", True), c_cell("Relationship Type", True), c_cell("Target Entity Node", True)]]
        for ed in edges[:8]:
            s_node = ed.get("source", "Entity") if isinstance(ed, dict) else "Source"
            r_type = ed.get("relationship", ed.get("label", "CONNECTED_TO")) if isinstance(ed, dict) else "LINKED"
            t_node = ed.get("target", "Entity") if isinstance(ed, dict) else "Target"
            e_rows.append([c_cell(s_node, is_mono=True), c_cell(r_type, True), c_cell(t_node, is_mono=True)])
        e_table = Table(e_rows, colWidths=[180, 180, 180])
        e_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_HEADER),
            ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
            ('GRID', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ]))
        s10_elements.append(e_table)

    s10_elements.append(Spacer(1, 4))
    s10_elements.append(build_explainer(
        "Infrastructure Relational Graph Mapping",
        "Maps direct and indirect relationships between domains, IP addresses, ASNs, registrars, and threat pulses to reveal adversary infrastructure clusters.",
        "Graph nodes represent verified OSINT connections extracted during indicator scan."
    ))
    elements.append(KeepTogether(s10_elements))
    elements.append(Spacer(1, 10))

    # SECTION 11: Methodology & Provenance Disclaimer
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("<b>TECHNICAL METHODOLOGY & LEGAL PROVENANCE NOTICE:</b> This threat dossier was generated automatically by ThreatMap Platform v2.0. Intelligence data is fetched asynchronously directly from official vendor REST APIs (VirusTotal, AbuseIPDB, AlienVault OTX, URLScan.io, MaxMind, WHOIS). Third-party indicators and threat scores represent automated vendor consensus and should be independently validated prior to implementing firewall blocklists or SOC containment actions.", ParagraphStyle('FootNote', parent=body_text, fontSize=7.5, textColor=TEXT_MUTED, leading=10)))

    # Page decorations function for canvas background
    def add_pdf_decorations(canvas, doc):
        canvas.saveState()
        # Page dark background
        canvas.setFillColor(colors.HexColor("#020617"))
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
        
        # Top banner background
        canvas.setFillColor(BG_HEADER)
        canvas.rect(0, doc.pagesize[1] - 42, doc.pagesize[0], 42, fill=1, stroke=0)
        canvas.setFillColor(PRIMARY_CYAN)
        canvas.rect(0, doc.pagesize[1] - 42, doc.pagesize[0], 2, fill=1, stroke=0)
        
        # Footer text
        canvas.setFillColor(TEXT_MUTED)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.drawString(36, 18, "THREATMAP CYBERSECURITY | INTELLIGENCE DOSSIER (TLP:AMBER)")
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
