import base64
import logging
import httpx
from typing import Dict, Any, Optional
from core.config import settings

logger = logging.getLogger(__name__)

class VirusTotalService:
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        url = f"{self.base_url}/ip_addresses/{ip}"
        return await self._make_request(url)

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        url = f"{self.base_url}/domains/{domain}"
        return await self._make_request(url)

    async def get_hash_report(self, file_hash: str) -> Dict[str, Any]:
        url = f"{self.base_url}/files/{file_hash}"
        return await self._make_request(url)

    async def get_url_report(self, target_url: str) -> Dict[str, Any]:
        # VirusTotal v3 URL identifier is base64 representation of URL without padding '='
        encoded_url = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = f"{self.base_url}/urls/{encoded_url}"
        return await self._make_request(url)

    async def _make_request(self, url: str) -> Dict[str, Any]:
        if not self.api_key or len(self.api_key) < 10:
            logger.warning("VT API key missing. Returning fallback data.")
            return self._get_fallback_data()

        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": attributes.get("reputation", 0),
                        "status": "success",
                        "raw": data
                    }
                elif response.status_code == 404:
                    return {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0,
                        "reputation": 0,
                        "status": "not_found",
                        "raw": None
                    }
                else:
                    logger.warning(f"VirusTotal request failed with status {response.status_code}. Returning fallback.")
                    return self._get_fallback_data()
            except Exception as e:
                logger.error(f"VirusTotal query failed: {e}. Returning fallback.")
                return self._get_fallback_data()

    def _get_fallback_data(self) -> Dict[str, Any]:
        # Return CLEAN zeros — API failures must never inflate risk scores
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "reputation": 0,
            "status": "fallback",
            "raw": None
        }

virustotal_service = VirusTotalService()
