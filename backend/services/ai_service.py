import json
import logging
from typing import Dict, Any
from groq import Groq
from core.config import settings

logger = logging.getLogger(__name__)

class AIService:
    def __init__(self):
        self.api_key = settings.GROQ_API_KEY
        self.client = None
        if self.api_key:
            try:
                self.client = Groq(api_key=self.api_key)
                logger.info("Groq API configured for AI analysis.")
            except Exception as e:
                logger.error(f"Failed to initialize Groq client: {e}")
        else:
            logger.warning("Groq API key not set. AI analysis will fall back to rule-based scoring.")

    async def generate_threat_brief(self, indicator: str, ind_type: str, risk_score: int, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request Groq to generate threat briefs and structured recommendations.
        Fully isolated — any failure returns a clear fallback state, never crashes the server.
        """
        try:
            # Extract real signals FIRST — needed by both AI path and fallback
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

            if not self.client:
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

You MUST return your response as a raw JSON object and nothing else.
Do not wrap it in markdown block quotes like ```json ... ```. Just the JSON object.
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
            # Call Groq synchronously via the client (as we are inside an async def, but Groq python client provides async support if we use AsyncGroq, but since we are using Groq we should use it carefully. Wait, the groq library provides AsyncGroq. Let's just use it in a thread or directly if it's blocking. Actually, we can just use the blocking call in a thread or use AsyncGroq. But groq_service.py uses client.chat.completions.create synchronously in an async function which is bad. Let's use run_in_executor here.)
            import asyncio
            def call_groq():
                return self.client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": SYSTEM},
                        {"role": "user", "content": PROMPT}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    max_completion_tokens=500
                )
            
            try:
                loop = asyncio.get_event_loop()
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, call_groq),
                    timeout=10.0
                )
                response_text = response.choices[0].message.content.strip()
            except asyncio.TimeoutError:
                logger.error(f"Groq AI timed out after 10s for indicator: {indicator}. Using fallback.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)
            except Exception as groq_exc:
                logger.error(f"Groq API call failed: {groq_exc}. Using fallback.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

            try:
                parsed_brief = json.loads(response_text)
            except json.JSONDecodeError as je:
                logger.error(f"Failed to parse Groq JSON: {je}. Raw: {response_text}")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

            # Verify required keys exist
            required_keys = ["summary", "recommendations", "threat_category", "confidence"]
            if all(k in parsed_brief for k in required_keys):
                if "playbook" not in parsed_brief: parsed_brief["playbook"] = []
                if "mitre_tactics" not in parsed_brief: parsed_brief["mitre_tactics"] = []
                parsed_brief["status"] = "success"
                return parsed_brief
            else:
                logger.warning("Groq JSON missing required keys. Falling back.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

        except Exception as e:
            # Top-level safety net — this function MUST NEVER crash the caller
            logger.error(f"[ai_service] Unexpected error in generate_threat_brief: {e}", exc_info=True)
            return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

    def _get_fallback_brief(self, indicator: str, ind_type: str, risk_score: int,
                             vt_malicious: int = 0, abuse_score: int = 0) -> Dict[str, Any]:
        return {
            "status": "unavailable",
            "summary": "AI analysis unavailable.",
            "threat_category": "unknown",
            "recommendations": ["Manual review recommended."],
            "confidence": "low",
            "playbook": [],
            "mitre_tactics": []
        }

ai_service = AIService()
