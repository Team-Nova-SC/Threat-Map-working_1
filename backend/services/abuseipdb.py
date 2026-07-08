import logging
import httpx
from typing import Dict, Any
from core.config import settings

logger = logging.getLogger(__name__)

class AbuseIPDBService:
    def __init__(self):
        self.api_key = settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        url = f"{self.base_url}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "true"
        }
        
        if not self.api_key or len(self.api_key) < 10:
            logger.warning("AbuseIPDB API key missing or invalid. Returning clean fallback.")
            return self._get_fallback_data(ip)

        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                response = await client.get(url, headers=self.headers, params=params)
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    return {
                        "ipAddress": data.get("ipAddress", ip),
                        "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                        "totalReports": data.get("totalReports", 0),
                        "countryCode": data.get("countryCode", "US"),
                        "countryName": data.get("countryName", "United States"),
                        "domain": data.get("domain", ""),
                        "isp": data.get("isp", ""),
                        "isTor": data.get("isTor", False),
                        "status": "success",
                        "raw": data
                    }
                else:
                    logger.warning(f"AbuseIPDB request failed with status {response.status_code}. Returning fallback.")
                    return self._get_fallback_data(ip)
            except Exception as e:
                logger.error(f"AbuseIPDB query failed: {e}. Returning fallback.")
                return self._get_fallback_data(ip)

    def _get_fallback_data(self, ip: str) -> Dict[str, Any]:
        # Return CLEAN zeros — API failures must never inflate risk scores
        return {
            "ipAddress": ip,
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "countryCode": "US",
            "countryName": "United States",
            "domain": "",
            "isp": "Unknown",
            "isTor": False,
            "status": "fallback",
            "raw": None
        }

abuse_ipdb_service = AbuseIPDBService()
