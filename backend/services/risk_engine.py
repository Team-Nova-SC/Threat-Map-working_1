import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class RiskEngine:
    def calculate_risk(self, indicator_type: str, vt_data: Dict[str, Any], abuse_data: Dict[str, Any] = None, greynoise_data: Dict[str, Any] = None) -> Dict[str, Any]:
        if abuse_data is None:
            abuse_data = {}
        if greynoise_data is None:
            greynoise_data = {}
            
        score = 0
        reasons = []

        # VirusTotal — 35% weight
        vt_malicious = 0
        vt_total = 0
        try:
            stats = vt_data.get("data", {}).get(
                "attributes", {}).get(
                "last_analysis_stats", {})
            
            # Sometimes VT data is passed as the stats directly (depending on how threat_intel.py parses it)
            if not stats:
                vt_malicious = vt_data.get("malicious", 0)
                vt_total = vt_data.get("malicious", 0) + vt_data.get("harmless", 0) + vt_data.get("suspicious", 0) + vt_data.get("undetected", 0)
            else:
                vt_malicious = stats.get("malicious", 0)
                vt_total = stats.get("total", 0)
        except:
            vt_malicious = 0
        
        if vt_malicious == 0:
            vt_score = 0
        elif vt_malicious <= 3:
            vt_score = 25
        elif vt_malicious <= 10:
            vt_score = 60
        else:
            vt_score = 100
        reasons.append(f"VT: {vt_malicious} detections")

        # AbuseIPDB — 40% weight  
        abuse_score = 0
        try:
            abuse_score = abuse_data.get(
                "data", {}).get("abuseConfidenceScore", 0)
            if not abuse_score:
                abuse_score = abuse_data.get("abuseConfidenceScore", 0)
        except:
            abuse_score = 0
        reasons.append(f"Abuse: {abuse_score}%")

        # GreyNoise — 25% weight
        gn_score = 0
        classification = "unknown"
        try:
            classification = greynoise_data.get(
                "classification", "unknown")
            if classification == "benign":
                gn_score = 0
            elif classification == "malicious":
                gn_score = 100
            else:
                gn_score = 10
        except:
            gn_score = 0
        reasons.append(f"GN: {classification}")

        # Weighted final score
        final = (vt_score * 0.35) + \
                (abuse_score * 0.40) + \
                (gn_score * 0.25)
        final = round(final)

        # HARD CAPS — cannot be overridden
        if vt_malicious == 0 and abuse_score < 10:
            final = min(final, 15)
        if vt_malicious == 0 and abuse_score == 0 \
           and gn_score == 0:
            final = 0

        # Risk level
        if final < 30:
            level = "LOW"
        elif final < 60:
            level = "MEDIUM"
        elif final < 80:
            level = "HIGH"
        else:
            level = "CRITICAL"

        # Confidence Scoring
        apis_tried = 1 # VT always tried
        apis_succeeded = 0
        if vt_data and (vt_data.get("data") or vt_data.get("malicious") is not None):
            apis_succeeded += 1
            
        if indicator_type == "ip":
            apis_tried += 2
            if abuse_data and (abuse_data.get("data") or abuse_data.get("abuseConfidenceScore") is not None):
                apis_succeeded += 1
            if greynoise_data and greynoise_data.get("ip") or greynoise_data.get("classification"):
                apis_succeeded += 1
                
        confidence_ratio = apis_succeeded / apis_tried if apis_tried > 0 else 0
        confidence_score = int(confidence_ratio * 100)
        
        if confidence_ratio >= 0.8:
            confidence_level = "HIGH"
        elif confidence_ratio >= 0.4:
            confidence_level = "MEDIUM"
        else:
            confidence_level = "LOW"

        return {
            "score": final,
            "level": level,
            "reasons": reasons,
            "components": {
                "vt_score": vt_score,
                "abuse_score": abuse_score,
                "greynoise_score": gn_score
            },
            "vt_malicious": vt_malicious,
            "abuse_score": abuse_score,
            "greynoise": classification,
            "confidence_score": confidence_score,
            "confidence_level": confidence_level
        }

risk_engine = RiskEngine()
