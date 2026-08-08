import json
import logging
import os
import re
from typing import Dict, Any
from groq import Groq
from core.config import settings

logger = logging.getLogger(__name__)

class AIService:
    def _get_client(self):
        api_key = settings.GROQ_API_KEY or os.getenv("GROQ_API_KEY")
        if api_key and api_key != "your_key_here":
            try:
                return Groq(api_key=api_key)
            except Exception as e:
                logger.error(f"Failed to initialize Groq client: {e}")
                return None
        return None

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

            client = self._get_client()
            if not client:
                logger.warning("Groq API key not set or client unavailable. Returning fallback brief.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

            SYSTEM = """You are a senior cybersecurity analyst.
You ONLY analyze data that is given to you.
You NEVER invent, assume or hallucinate threats.
You must return your response as a raw JSON object and nothing else.
Do not wrap it in markdown block quotes like ```json ... ```. Just the JSON object.
"""

            # Dump relevant data context to prompt
            context = {
                "virustotal": raw_data.get("virustotal", {}),
                "abuseipdb": raw_data.get("abuseipdb", {}),
                "greynoise": raw_data.get("greynoise", {}),
                "alienvault": raw_data.get("alienvault_otx", {})
            }

            PROMPT = f"""
Analyze this threat intelligence scan result. Base your response ONLY on the provided JSON data.

TARGET: {indicator}
TYPE: {ind_type}
RISK LEVEL: {risk_level} ({risk_score}/100)

RAW DATA CONTEXT:
{json.dumps(context, indent=2)[:3000]}

STRICT RULES:
1. 'summary' must be a 2-sentence plain English summary.
2. 'detailed_markdown' must be a highly detailed report formatted in GitHub Flavored Markdown.
   - Use Markdown tables to visualize the breakdown of vendor detections or scores.
   - You MUST include "Proof & Citations" linking back to the trusted sources (e.g., https://www.virustotal.com/gui/search/{indicator} or https://www.abuseipdb.com/check/{indicator}).
   - Use bolding, lists, and headers to make it look professional and beautiful.
   - Do NOT wrap the JSON itself in markdown, just put the markdown string inside the JSON field.

Respond ONLY with this JSON, no other text:
{{
  "summary": "2 sentence summary",
  "threat_category": "benign_asset OR actual_threat",
  "recommendations": ["action 1", "action 2", "action 3"],
  "confidence": "low|medium|high",
  "detailed_markdown": "Full markdown report string here..."
}}
"""
            import asyncio
            def call_groq():
                return client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": SYSTEM},
                        {"role": "user", "content": PROMPT}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    max_tokens=1500
                )
            
            try:
                loop = asyncio.get_event_loop()
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, call_groq),
                    timeout=12.0
                )
                response_text = response.choices[0].message.content.strip()
            except asyncio.TimeoutError:
                logger.error(f"Groq AI timed out after 12s for indicator: {indicator}. Using fallback.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)
            except Exception as groq_exc:
                logger.error(f"Groq API call failed: {groq_exc}. Using fallback.")
                return self._get_fallback_brief(indicator, ind_type, risk_score, vt_malicious, abuse_score)

            # Clean markdown formatting if present
            cleaned_text = re.sub(r"^```json\s*", "", response_text)
            cleaned_text = re.sub(r"^```\s*", "", cleaned_text)
            cleaned_text = re.sub(r"\s*```$", "", cleaned_text).strip()

            try:
                parsed_brief = json.loads(cleaned_text)
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

