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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from pydantic import BaseModel

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
        raise HTTPException(status_code=400, detail="Invalid format specified.")


# Keep the old endpoints for backward compatibility with existing frontend code if needed
@router.get("/json/{scan_id}")
def export_json_old(scan_id: str, db: Session = Depends(get_db)):
    return export_report(scan_id, format="json", db=db)

@router.get("/csv/{scan_id}")
def export_csv_old(scan_id: str, db: Session = Depends(get_db)):
    return export_report(scan_id, format="csv", db=db)

@router.get("/pdf/{scan_id}")
def export_pdf_old(scan_id: str, db: Session = Depends(get_db)):
    return export_report(scan_id, format="pdf", db=db)


def format_date(dt):
    if not dt:
        return "Unknown"
    if isinstance(dt, str):
        return dt
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)

def _export_json(scan: Scan):
    data = {
        "id": scan.id,
        "indicator": scan.indicator,
        "type": scan.type,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "summary": scan.summary,
        "created_at": format_date(scan.created_at),
        "raw_data": scan.raw_data
    }
    json_bytes = json.dumps(data, indent=2).encode("utf-8")
    return Response(
        content=json_bytes,
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
    writer.writerow(["Created At", format_date(scan.created_at)])
    writer.writerow(["Summary", scan.summary])
    
    raw_data = scan.raw_data or {}
    vt = raw_data.get("virustotal", {})
    writer.writerow(["VirusTotal Malicious", vt.get("malicious", 0)])
    writer.writerow(["VirusTotal Harmless", vt.get("harmless", 0)])
    
    if scan.type == "ip":
        abuse = raw_data.get("abuseipdb", {})
        writer.writerow(["AbuseIPDB Score", abuse.get("abuseConfidenceScore", 0)])
        writer.writerow(["AbuseIPDB Reports", abuse.get("totalReports", 0)])
        gn = raw_data.get("greynoise", {})
        writer.writerow(["GreyNoise Classification", gn.get("classification", "unknown")])

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
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor("#f8fafc"),
        spaceAfter=16
    )
    
    subtitle_style = ParagraphStyle(
        'SubtitleStyle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor("#94a3b8"),
        spaceAfter=24
    )
    
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor("#cbd5e1"),
        spaceBefore=16,
        spaceAfter=8
    )
    
    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#cbd5e1"),
        spaceAfter=12,
        leading=14
    )
    
    warning_style = ParagraphStyle(
        'WarningStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#fca5a5"),
        backColor=colors.HexColor("#7f1d1d"),
        spaceAfter=16,
        leading=14,
        borderPadding=8,
        borderColor=colors.HexColor("#ef4444"),
        borderWidth=1
    )
    
    elements = []
    
    # Header / Premium Banner
    elements.append(Paragraph("<b>THREATMAP</b> CYBERSECURITY INTELLIGENCE", title_style))
    elements.append(Paragraph(f"<b>REPORT ID:</b> {scan.id} &nbsp;&nbsp;|&nbsp;&nbsp; <b>DATE:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
    elements.append(Paragraph("<b>CONFIDENTIAL:</b> AI Analyst Briefs are generated automatically by ThreatMap engines. Please verify findings.", warning_style))
    elements.append(Spacer(1, 12))
    
    # Basic Info Table
    elements.append(Paragraph("I. Indicator Overview", heading_style))
    
    info_data = [
        ["Indicator Target:", scan.indicator],
        ["Indicator Type:", scan.type.upper()],
        ["Scan ID:", scan.id],
        ["Scan Date:", format_date(scan.created_at)],
        ["Risk Score:", f"{scan.risk_score} / 100"],
        ["Risk Level:", scan.risk_level]
    ]
    
    info_table = Table(info_data, colWidths=[120, 380])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor("#38bdf8")),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor("#f8fafc")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
        ('LINEBELOW', (0, -1), (-1, -1), 2, colors.HexColor("#38bdf8")),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 20))
    
    # AI Analysis
    elements.append(Paragraph("II. AI Analyst Brief", heading_style))
    summary_text = scan.summary if scan.summary else "No AI analyst summary was generated for this scan."
    elements.append(Paragraph(summary_text.replace('\n', '<br/>'), normal_style))
    elements.append(Spacer(1, 20))
    
    # OSINT Telemetry
    elements.append(Paragraph("III. OSINT Vendor Telemetry", heading_style))
    
    raw = scan.raw_data or {}
    telemetry_data = [["Vendor / Source", "Finding / Result"]]
    
    vt = raw.get("virustotal", {})
    vt_malicious = vt.get("malicious", 0)
    vt_total = vt_malicious + vt.get("harmless", 0) + vt.get("suspicious", 0) + vt.get("undetected", 0)
    telemetry_data.append(["VirusTotal", f"{vt_malicious} engines detected as malicious (out of {vt_total})"])
    
    if scan.type == "ip":
        abuse = raw.get("abuseipdb", {})
        gn = raw.get("greynoise", {})
        ipinfo = raw.get("ipinfo", {})
        domainscan = raw.get("domainscan", {}).get("performance_metrics", {})
        whois = raw.get("whoisjson", {})
        
        telemetry_data.append(["AbuseIPDB", f"{abuse.get('abuseConfidenceScore', 0)}% abuse confidence with {abuse.get('totalReports', 0)} reports"])
        telemetry_data.append(["GreyNoise", f"Classification: {gn.get('classification', 'unknown')}"])
        telemetry_data.append(["IPInfo (ASN)", f"Network: {ipinfo.get('org', 'Unknown')}"])
        
        if domainscan:
            telemetry_data.append(["DomainScan Latency", f"{domainscan.get('latency_ms', 'N/A')} ms"])
            
        if whois:
            contacts = whois.get("contacts", {}).get("registrant", {})
            telemetry_data.append(["Network Registrar", contacts.get("name", "Unknown")])
            telemetry_data.append(["Registry Country", contacts.get("country", "Unknown")])
            
    elif scan.type == "domain" or scan.type == "url":
        whois = raw.get("whoisjson", {})
        domainscan = raw.get("domainscan", {})
        
        if whois:
            reg = whois.get("registrar_metadata", {})
            dates = whois.get("registry_dates", {})
            telemetry_data.append(["WHOIS Registrar", reg.get('name', 'Unknown')])
            telemetry_data.append(["Creation Date", dates.get('creation_date', 'Unknown')])
            telemetry_data.append(["Expiration Date", dates.get('expiration_date', 'Unknown')])
            
        if domainscan:
            ai = domainscan.get("ai_readiness", {})
            telemetry_data.append(["AI Readiness Grade", f"{ai.get('grade', 'Unknown')} (Score: {ai.get('score', 0)})"])
        
    tel_table = Table(telemetry_data, colWidths=[150, 350])
    tel_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#38bdf8")),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
        ('LINEBELOW', (0, -1), (-1, -1), 2, colors.HexColor("#38bdf8")),
    ]))
    
    elements.append(tel_table)
    
    # Footer Note
    elements.append(Spacer(1, 50))
    elements.append(Paragraph("<i>This document is proprietary and generated by ThreatMap. Aggregated findings from third-party OSINT sources must be manually verified.</i>", normal_style))
    
    def add_page_styling(canvas, doc):
        canvas.saveState()
        # Full page dark background
        canvas.setFillColor(colors.HexColor("#020617"))
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
        
        # Header banner decoration
        canvas.setFillColor(colors.HexColor("#0f172a"))
        canvas.rect(0, doc.pagesize[1] - 80, doc.pagesize[0], 80, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#38bdf8"))
        canvas.rect(0, doc.pagesize[1] - 80, doc.pagesize[0], 2, fill=1, stroke=0)
        
        # Footer
        canvas.setFillColor(colors.HexColor("#475569"))
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(40, 25, "THREATMAP CYBERSECURITY")
        canvas.setFont("Helvetica", 9)
        canvas.drawString(40, 15, "Automated Intelligence Aggregation Platform")
        
        canvas.drawRightString(doc.pagesize[0] - 40, 25, f"Page {doc.page}")
        canvas.restoreState()
        
    doc.build(elements, onFirstPage=add_page_styling, onLaterPages=add_page_styling)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=threatmap_report_{scan.indicator}.pdf"}
    )


@router.get("/stix/{scan_id}")
def export_stix(scan_id: str, db: Session = Depends(get_db)):
    """Export scan data as STIX 2.1 bundle JSON."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    raw = scan.raw_data or {}
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build the STIX indicator pattern
    if scan.type == "ip":
        pattern = f"[ipv4-addr:value = '{scan.indicator}']"
        stix_type = "ipv4-addr"
    elif scan.type == "domain":
        pattern = f"[domain-name:value = '{scan.indicator}']"
        stix_type = "domain-name"
    elif scan.type == "url":
        pattern = f"[url:value = '{scan.indicator}']"
        stix_type = "url"
    elif scan.type == "hash":
        pattern = f"[file:hashes.SHA256 = '{scan.indicator}']"
        stix_type = "file"
    else:
        pattern = f"[artifact:payload_bin = '{scan.indicator}']"
        stix_type = "artifact"

    indicator_id = f"indicator--{scan.id}"
    report_id = f"report--{scan.id}"

    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{scan.id}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": f"ThreatMap IOC: {scan.indicator}",
                "description": scan.summary or f"Automated OSINT scan of {scan.indicator}",
                "indicator_types": ["malicious-activity"] if scan.risk_score >= 50 else ["anomalous-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "confidence": min(100, scan.risk_score),
                "labels": [scan.risk_level.lower()],
            },
            {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": now,
                "modified": now,
                "name": f"ThreatMap Scan Report: {scan.indicator}",
                "description": f"Automated OSINT intelligence report. Risk Score: {scan.risk_score}/100. Level: {scan.risk_level}.",
                "published": now,
                "report_types": ["threat-report"],
                "object_refs": [indicator_id],
                "external_references": [
                    {
                        "source_name": "ThreatMap",
                        "url": f"http://localhost:3000/results/{scan.id}",
                        "description": "ThreatMap scan result"
                    }
                ],
            }
        ]
    }

    stix_json = json.dumps(stix_bundle, indent=2).encode("utf-8")
    return Response(
        content=stix_json,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=threatmap_stix_{scan.indicator}.json"}
    )


@router.get("/watchlist/bulk")
def export_watchlist_bulk(
    format: str = Query("csv", description="Export format: json or csv"),
    db: Session = Depends(get_db)
):
    items = db.query(Watchlist).all()
    
    if format.lower() == "json":
        data = [
            {
                "id": i.id,
                "indicator": i.indicator,
                "type": i.type,
                "added_at": i.added_at.isoformat(),
                "last_risk_score": i.last_risk_score,
                "notes": i.notes,
                "tags": i.tags
            } for i in items
        ]
        json_bytes = json.dumps(data, indent=2).encode("utf-8")
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=threatmap_watchlist.json"}
        )
    elif format.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Indicator", "Type", "Added At", "Last Risk Score", "Notes", "Tags"])
        for i in items:
            writer.writerow([i.id, i.indicator, i.type, i.added_at.isoformat(), i.last_risk_score, i.notes, i.tags])
        
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.read().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threatmap_watchlist.csv"}
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid format specified.")


@router.get("/feed/rss")
def export_rss_feed(db: Session = Depends(get_db)):
    """Generate an RSS feed of recent HIGH and CRITICAL threats."""
    scans = db.query(Scan).filter(
        Scan.risk_level.in_(["HIGH", "CRITICAL"])
    ).order_by(Scan.created_at.desc()).limit(50).all()

    output = io.StringIO()
    output.write('<?xml version="1.0" encoding="UTF-8" ?>\n')
    output.write('<rss version="2.0">\n')
    output.write('<channel>\n')
    output.write('  <title>ThreatMap High Risk Intelligence Feed</title>\n')
    output.write('  <link>http://localhost:3000</link>\n')
    output.write('  <description>Automated OSINT alerts for critical threats</description>\n')
    
    for scan in scans:
        output.write('  <item>\n')
        output.write(f'    <title>{scan.risk_level} Threat Detected: {scan.indicator}</title>\n')
        output.write(f'    <link>http://localhost:3000/results/{scan.id}</link>\n')
        output.write(f'    <description>{scan.summary or "Automated scan finding"}. Score: {scan.risk_score}</description>\n')
        output.write(f'    <pubDate>{scan.created_at.strftime("%a, %d %b %Y %H:%M:%S GMT")}</pubDate>\n')
        output.write(f'    <guid>{scan.id}</guid>\n')
        output.write('  </item>\n')
        
    output.write('</channel>\n')
    output.write('</rss>\n')

    return Response(
        content=output.getvalue().encode("utf-8"),
        media_type="application/rss+xml",
        headers={"Content-Disposition": "attachment; filename=threatmap_feed.xml"}
    )


class DriveUploadRequest(BaseModel):
    scan_id: str
    access_token: str

@router.post("/drive")
def export_to_drive(request: DriveUploadRequest, db: Session = Depends(get_db)):
    """Uploads a generated PDF report directly to the user's Google Drive."""
    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseUpload
    except ImportError:
        raise HTTPException(status_code=500, detail="Google Drive API dependencies not installed.")

    scan = db.query(Scan).filter(Scan.id == request.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    # 1. Generate the PDF bytes
    try:
        pdf_response = _export_pdf(scan)
        pdf_bytes = pdf_response.body
    except Exception as e:
        logger.error(f"Failed to generate PDF for drive export: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF report.")

    # 2. Authenticate to Google Drive
    try:
        credentials = Credentials(token=request.access_token)
        service = build('drive', 'v3', credentials=credentials)
    except Exception as e:
        logger.error(f"Failed to authenticate with Google Drive API: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired Google access token.")

    # 3. Find or Create "ThreatMap Reports" folder
    folder_name = "ThreatMap Reports"
    folder_id = None
    try:
        # Search for the folder
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        results = service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        items = results.get('files', [])
        
        if not items:
            # Create the folder
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder = service.files().create(body=folder_metadata, fields='id').execute()
            folder_id = folder.get('id')
        else:
            folder_id = items[0].get('id')
    except Exception as e:
        logger.error(f"Failed to find/create Drive folder: {e}")
        raise HTTPException(status_code=500, detail="Failed to access Google Drive.")

    # 4. Upload the PDF
    file_name = f"threatmap_report_{scan.indicator}.pdf"
    file_metadata = {
        'name': file_name,
        'parents': [folder_id]
    }
    try:
        media = MediaIoBaseUpload(io.BytesIO(pdf_bytes), mimetype='application/pdf', resumable=True)
        uploaded_file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, webViewLink'
        ).execute()
        
        return {
            "status": "success",
            "file_id": uploaded_file.get("id"),
            "webViewLink": uploaded_file.get("webViewLink")
        }
    except Exception as e:
        logger.error(f"Failed to upload file to Google Drive: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload report to Google Drive.")

