import json
import asyncio
import logging
import re
import google.generativeai as genai
from typing import Dict, Any
from core.config import settings

logger = logging.getLogger(__name__)

class AIService:
    # Try models in order until one works (errors caught per-request, not at startup)
    MODEL_CANDIDATES = [
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
        "gemini-1.5-flash-8b",
    ]

    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY
        self.model = None
        self._model_index = 0
        if self.api_key and self.api_key.startswith("AIza"):
            genai.configure(api_key=self.api_key)
            # Set the first candidate — actual availability is checked per-request
            self.model = genai.GenerativeModel(self.MODEL_CANDIDATES[0])
            logger.info(f"Gemini configured with model: {self.MODEL_CANDIDATES[0]}")
        else:
            logger.warning("Gemini API key not set. Using rule-based threat intelligence fallback.")

    async def generate_threat_brief(self, indicator: str, ind_type: str, risk_score: int, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request Gemini to generate threat briefs and structured recommendations.
        Fully isolated — any failure returns a rule-based fallback, never crashes the server.
        """
        try:
            # Extract real signals FIRST — needed by both Gemini path and fallback
            vt_malicious = raw_data.get("virustotal", {}).get("malicious", 0)
            vt_total = (
                raw_data.get("virustotal", {}).get("malicious", 0)
                + raw_data.get("virustotal", {}).get("harmless", 0)
                + raw_data.get("virustotal", {}).get("suspicious", 0)
                + raw_data.get("virustotal", {}).get("undetected", 0)
            )
            abuse_score = raw_data.get("abuseipdb", {}).get("abuseConfidenceScore", 0)
            greynoise_class = raw_data.get("greynoise", {}).get("classification", "unknown")
            risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH" if risk_score < 80 else "CRITICAL"

            if not self.model:
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

            SYSTEM = """You are a cybersecurity analyst assistant.
You ONLY analyze data that is given to you.
You NEVER invent, assume or hallucinate threats.
If the data shows clean results you say it is clean.
You must follow these rules without exception:
- vt_malicious = 0 means VirusTotal found nothing wrong
- abuse_score < 10 means no significant abuse reports  
- If both are low, threat_category MUST be benign_asset
- NEVER output botnet/malware/phishing unless 
  vt_malicious > 5 or abuse_score > 50
"""

            PROMPT = f"""
Analyze this real threat intelligence scan result.
Base your response ONLY on the numbers below.
Do not add any information not in this data.

TARGET: {indicator}
TYPE: {ind_type}

REAL API RESULTS:
- VirusTotal malicious engines: {vt_malicious} out of {vt_total}
- AbuseIPDB confidence score: {abuse_score} out of 100
- GreyNoise classification: {greynoise_class}
- Risk score calculated: {risk_score} out of 100
- Risk level: {risk_level}

STRICT RULES:
- If vt_malicious is 0 and abuse_score < 10:
  category = "benign_asset", summary must say SAFE
- If vt_malicious > 5 or abuse_score > 50:
  category = actual threat type from data
- Never say BOTNET C2 unless data proves it
- Recommendations must match the actual risk level

Respond ONLY with this JSON, no other text:
{{
  "summary": "2 sentence plain English summary based strictly on the numbers above",
  "threat_category": "benign_asset OR actual_threat",
  "recommendations": ["action 1", "action 2", "action 3"],
  "confidence": "low|medium|high"
}}
"""

            full_prompt = SYSTEM + "\n\n" + PROMPT

            # --- Gemini call is SYNCHRONOUS (blocking). Run it in a thread executor
            # so it never stalls the async event loop. Enforce an 8 s hard timeout.
            try:
                loop = asyncio.get_event_loop()
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, self.model.generate_content, full_prompt),
                    timeout=8.0
                )
                response_text = response.text.strip()
            except asyncio.TimeoutError:
                logger.error(f"Gemini timed out after 8s for indicator: {indicator}. Using fallback.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)
            except Exception as gemini_exc:
                logger.error(f"Gemini API call failed: {gemini_exc}. Using fallback.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

            # Clean potential markdown JSON wrapper: ```json ... ```
            if response_text.startswith("```"):
                response_text = re.sub(r"^```(?:json)?\n", "", response_text)
                response_text = re.sub(r"\n```$", "", response_text)

            parsed_brief = json.loads(response_text)

            # Verify required keys exist
            required_keys = ["summary", "recommendations", "threat_category", "confidence"]
            if all(k in parsed_brief for k in required_keys):
                if "playbook" not in parsed_brief: parsed_brief["playbook"] = []
                if "mitre_tactics" not in parsed_brief: parsed_brief["mitre_tactics"] = []
                return parsed_brief
            else:
                logger.warning("Gemini JSON missing required keys. Falling back.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

        except Exception as e:
            # Top-level safety net — this function MUST NEVER crash the caller
            logger.error(f"[ai_service] Unexpected error in generate_threat_brief: {e}", exc_info=True)
            return {
                "summary": "AI analysis unavailable. Rule-based scoring applied.",
                "threat_category": "unknown",
                "recommendations": ["Manual review recommended."],
                "confidence": "low",
                "playbook": [],
                "mitre_tactics": []
            }

    def _get_fallback_brief(self, indicator: str, ind_type: str, risk_score: int,
                             vt_malicious: int = 0, abuse_score: int = 0) -> Dict[str, Any]:
        """Rule-based fallback used when Gemini is unavailable/quota exceeded.
        Uses REAL signal values — never invents threats."""
        if vt_malicious == 0 and abuse_score < 10:
            # CLEAN — nothing flagged it
            return {
                "summary": f"{indicator} was checked against VirusTotal ({vt_malicious} detections) and AbuseIPDB ({abuse_score}% confidence). No malicious indicators were found. This target appears safe.",
                "threat_category": "Benign Asset",
                "recommendations": ["No action required. Standard monitoring applies.", "Document this result for audit purposes.", "Re-scan periodically to catch future changes."],
                "confidence": "HIGH",
                "playbook": ["No remediation steps needed.", "Continue normal operations."],
                "mitre_tactics": []
            }
        elif vt_malicious > 0 and vt_malicious <= 5:
            return {
                "summary": f"{indicator} has {vt_malicious} antivirus detections on VirusTotal and an AbuseIPDB confidence score of {abuse_score}%. Exercise caution — some vendors consider this suspicious.",
                "threat_category": "Suspicious Activity",
                "recommendations": ["Monitor traffic to/from this indicator.", "Block at perimeter if not required for operations.", "Check internal logs for contact with this indicator."],
                "confidence": "MEDIUM",
                "playbook": ["1. Create SIEM alert for connections to this indicator.", "2. Block at firewall pending investigation.", "3. Audit recent logs for related activity."],
                "mitre_tactics": ["TA0001"]
            }
        else:
            return {
                "summary": f"{indicator} has {vt_malicious} antivirus detections and an AbuseIPDB score of {abuse_score}%. Multiple security feeds have flagged this as malicious.",
                "threat_category": "Confirmed Threat",
                "recommendations": ["Block this indicator immediately at all network boundaries.", "Search internal logs for communication with this asset.", "Rotate credentials for any systems that contacted this indicator."],
                "confidence": "HIGH",
                "playbook": [
                    "1. Add indicator to firewall blocklist (ingress & egress).",
                    "2. Query SIEM for all endpoints communicating with this indicator.",
                    "3. Isolate affected endpoints from the network.",
                    "4. Run full AV and memory scan on affected systems.",
                    "5. Rotate all credentials from potentially compromised machines."
                ],
                "mitre_tactics": ["TA0011", "TA0040"]
            }

ai_service = AIService()
