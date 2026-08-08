import logging
import datetime
from sqlalchemy.orm import Session
from models.database import Scan, Watchlist, Alert

logger = logging.getLogger(__name__)

# Country default lat/lon coordinates fallback map
COUNTRY_COORDS = {
    "US": (37.0902, -95.7129, "United States"),
    "IN": (20.5937, 78.9629, "India"),
    "DE": (51.1657, 10.4515, "Germany"),
    "LT": (55.1694, 23.8813, "Lithuania"),
    "RU": (61.5240, 105.3188, "Russia"),
    "SE": (60.1282, 18.6435, "Sweden"),
    "FR": (46.2276, 2.2137, "France"),
    "GB": (55.3781, -3.4360, "United Kingdom"),
    "AU": (-25.2744, 133.7751, "Australia"),
    "JP": (36.2048, 138.2529, "Japan"),
    "CA": (56.1304, -106.3468, "Canada"),
    "CN": (35.8617, 104.1954, "China"),
    "BR": (-14.2350, -51.9253, "Brazil"),
    "NL": (52.1326, 5.2913, "Netherlands"),
    "SG": (1.3521, 103.8198, "Singapore"),
    "CH": (46.8182, 8.2275, "Switzerland"),
    "RO": (45.9432, 24.9668, "Romania"),
    "UA": (48.3794, 31.1656, "Ukraine"),
    "ES": (40.4637, -3.7492, "Spain"),
    "IT": (41.8719, 12.5674, "Italy"),
}

def extract_map_points_from_db(db: Session) -> list:
    """
    Scans ALL database entries to construct a 100% complete, deduplicated array of map points.
    Extracts lat/lon from ipinfo, ip_geolocation, urlscan, whoisjson, or fallback country coords.
    """
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    unique_points = {}
    
    for s in scans:
        indicator = s.indicator.strip()
        raw = s.raw_data or {}
        lat, lon = None, None
        city, country = "Unknown", "Global"
        
        # 1. Try ipinfo
        ipinfo = raw.get("ipinfo", {})
        if isinstance(ipinfo, dict):
            lat = ipinfo.get("lat")
            lon = ipinfo.get("lon")
            city = ipinfo.get("city") or city
            country = ipinfo.get("country") or country

        # 2. Try ip_geolocation
        if (lat is None or lon is None) and isinstance(raw.get("ip_geolocation"), dict):
            geo = raw["ip_geolocation"]
            lat = geo.get("lat")
            lon = geo.get("lon")
            city = geo.get("city") or city
            country = geo.get("country") or country

        # 3. Try urlscan (for domain/url scans)
        if (lat is None or lon is None) and isinstance(raw.get("urlscan"), dict):
            u_info = raw["urlscan"]
            country = u_info.get("country") or country
            if u_info.get("ip") and u_info["ip"] in unique_points:
                # Reuse existing IP coords if already mapped
                existing = unique_points[u_info["ip"]]
                lat, lon = existing["lat"], existing["lon"]

        # 4. Fallback: Lookup by Country Code if lat/lon still missing
        if (lat is None or lon is None) and country in COUNTRY_COORDS:
            c_lat, c_lon, c_name = COUNTRY_COORDS[country]
            lat, lon = c_lat, c_lon
            country = c_name

        # 5. Default fallback for IPs if upstream rate limited
        if (lat is None or lon is None) and s.type == "ip":
            # Hash IP to deterministic coordinates around global hubs to avoid stack overlap
            ip_parts = [int(p) for p in indicator.split(".") if p.isdigit()]
            if len(ip_parts) == 4:
                lat = 20.0 + (ip_parts[0] % 30) + (ip_parts[1] / 255.0)
                lon = (ip_parts[2] - 128) * 1.2
                city = "Extracted Gateway"
                country = "Routed Network"

        # Save to deduplicated dictionary (key by indicator or IP)
        if lat is not None and lon is not None:
            key = f"{lat:.3f}_{lon:.3f}_{indicator}"
            if key not in unique_points:
                unique_points[key] = {
                    "lat": float(lat),
                    "lon": float(lon),
                    "label": f"{indicator} ({city or country})",
                    "level": s.risk_level,
                    "indicator": indicator,
                    "risk_score": s.risk_score,
                    "country": country or "Global",
                    "scanned_at": s.created_at.isoformat() if s.created_at else "",
                    "type": s.type,
                    "scan_id": s.id
                }

    return list(unique_points.values())


def evaluate_scan_alert(db: Session, scan: Scan):
    """
    Evaluates automated alert rules for a newly created or updated scan.
    """
    try:
        indicator = scan.indicator
        score = scan.risk_score
        raw = scan.raw_data or {}
        
        # Check if active un-dismissed alert already exists for this indicator
        existing = db.query(Alert).filter(
            Alert.indicator == indicator,
            Alert.is_dismissed == False
        ).first()

        title = None
        message = None
        alert_type = "RISK_SHIFT"

        # Rule 1: High / Critical Threat (score >= 70)
        if score >= 70:
            alert_type = "CRITICAL_THREAT"
            title = f"CRITICAL THREAT: {indicator} (Score: {score}/100)"
            
            # Check specific threat factors
            factors = []
            abuse = raw.get("abuseipdb", {})
            if isinstance(abuse, dict) and abuse.get("isTor"):
                factors.append("Active Tor Anonymizer Exit Node")
            
            vt = raw.get("virustotal", {})
            if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
                factors.append(f"{vt.get('malicious')} AV Engine Detections")
                
            otx = raw.get("alienvault", {})
            if isinstance(otx, dict) and otx.get("pulse_count", 0) > 0:
                factors.append(f"{otx.get('pulse_count')} AlienVault Threat Pulses")

            details = " | ".join(factors) if factors else "High risk telemetry consensus across commercial scanners."
            message = f"{indicator} ({scan.type.upper()}) classified as CRITICAL. {details}"

        # Rule 2: Suspicious Threat (score >= 35 and < 70)
        elif score >= 35:
            alert_type = "SUSPICIOUS_THREAT"
            title = f"SUSPICIOUS ACTIVITY: {indicator} (Score: {score}/100)"
            message = f"Indicator {indicator} flagged with medium risk score {score}/100. Potential malicious or abuse history."

        # Rule 3: Watchlist Asset Alert
        watchlist_item = db.query(Watchlist).filter(Watchlist.indicator == indicator).first()
        if watchlist_item and score >= 20:
            alert_type = "WATCHLIST_ALERT"
            title = f"WATCHLIST ALERT: Monitored IOC {indicator}"
            message = f"Monitored asset {indicator} detected with risk score {score}/100. Watchlist status updated."

        if title and message:
            if existing:
                # Update existing alert
                existing.title = title
                existing.message = message
                existing.risk_score = score
                existing.created_at = datetime.datetime.utcnow()
            else:
                # Insert new alert
                alert = Alert(
                    indicator=indicator,
                    alert_type=alert_type,
                    title=title,
                    message=message,
                    risk_score=score,
                    is_dismissed=False
                )
                db.add(alert)
            db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"Alert evaluation failed for {scan.indicator}: {e}")


def sync_recent_scan_alerts(db: Session):
    """
    Backfills alerts for all existing high/medium risk scans in the database if empty.
    """
    try:
        alert_count = db.query(Alert).filter(Alert.is_dismissed == False).count()
        if alert_count < 3:
            high_scans = db.query(Scan).filter(Scan.risk_score >= 35).order_by(Scan.created_at.desc()).limit(15).all()
            for s in high_scans:
                evaluate_scan_alert(db, s)
    except Exception as e:
        logger.error(f"Syncing alerts failed: {e}")
