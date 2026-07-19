import logging
import httpx
from typing import Dict, Any
from core.config import settings
from services.provider_result import provider_result, unavailable

logger = logging.getLogger(__name__)

class GreyNoiseService:
    def __init__(self):
        self.api_key = settings.GREYNOISE_API_KEY
        self.base_url = "https://api.greynoise.io/v3/community"
        self.headers = {
            "accept": "application/json",
            "key": self.api_key
        }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        url = f"{self.base_url}/{ip}"
        
        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    data = response.json()
                    return provider_result("GreyNoise", "success", {
                        "noise": data.get("noise", False),
                        "riot": data.get("riot", False),
                        "classification": data.get("classification", "unknown"),
                        "name": data.get("name", "Unknown Scanner"),
                        "link": data.get("link", ""),
                        "raw": data
                    })
                elif response.status_code == 404:
                    return provider_result("GreyNoise", "not_found", {"raw": None})
                else:
                    logger.warning(f"GreyNoise check failed with status {response.status_code}. Returning fallback.")
                    return self._get_fallback_data(ip)
            except Exception as e:
                logger.error(f"GreyNoise query failed: {e}. Returning fallback.")
                return self._get_fallback_data(ip)

    def _get_fallback_data(self, ip: str) -> Dict[str, Any]:
        # Return CLEAN unknown — API failures must never inflate risk scores
        return unavailable("GreyNoise", "Provider did not return a result")

greynoise_service = GreyNoiseService()
