import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)
SUCCESS_STATUSES = {"success", "not_found", "not_seen"}


class RiskEngine:
    def calculate_risk(self, indicator_type: str, vt_data: Dict[str, Any],
                       abuse_data: Dict[str, Any] | None = None,
                       greynoise_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
        abuse_data = abuse_data or {}
        greynoise_data = greynoise_data or {}
        components: Dict[str, Dict[str, Any]] = {}

        if vt_data.get("status") in SUCCESS_STATUSES:
            malicious = int(vt_data.get("malicious") or 0)
            vt_score = 0 if malicious == 0 else 25 if malicious <= 3 else 60 if malicious <= 10 else 100
            components["virustotal"] = {"score": vt_score, "weight": 35, "source": "VirusTotal", "retrieved_at": vt_data.get("retrieved_at")}

        if indicator_type == "ip" and abuse_data.get("status") in SUCCESS_STATUSES:
            components["abuseipdb"] = {"score": int(abuse_data.get("abuseConfidenceScore") or 0), "weight": 40, "source": "AbuseIPDB", "retrieved_at": abuse_data.get("retrieved_at")}

        if indicator_type == "ip" and greynoise_data.get("status") in SUCCESS_STATUSES:
            classification = greynoise_data.get("classification")
            gn_score = 100 if classification == "malicious" else 0 if classification == "benign" else 10
            components["greynoise"] = {"score": gn_score, "weight": 25, "source": "GreyNoise", "retrieved_at": greynoise_data.get("retrieved_at")}

        total_weight = sum(item["weight"] for item in components.values())
        final = round(sum(item["score"] * item["weight"] for item in components.values()) / total_weight) if total_weight else 0
        level = "LOW" if final < 30 else "MEDIUM" if final < 60 else "HIGH" if final < 80 else "CRITICAL"
        expected = 3 if indicator_type == "ip" else 1
        provider_count = len(components)
        confidence_score = round(provider_count / expected * 100)
        confidence_level = "HIGH" if confidence_score >= 80 else "MEDIUM" if confidence_score >= 40 else "LOW"

        return {
            "score": final,
            "level": level,
            "components": components,
            "provider_count": provider_count,
            "expected_provider_count": expected,
            "confidence_score": confidence_score,
            "confidence_level": confidence_level,
            "method": "Weighted mean of available providers; unavailable providers are excluded.",
        }


risk_engine = RiskEngine()
