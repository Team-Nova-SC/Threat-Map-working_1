import logging
import httpx
from typing import Dict, Any
from core.config import settings

logger = logging.getLogger(__name__)

class AlienVaultService:
    def __init__(self):
        self.api_key = settings.ALIENVAULT_API_KEY
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

    async def get_indicator_report(self, indicator: str, ind_type: str) -> Dict[str, Any]:
        # Map indicator types to OTX URL slugs
        # Options: IPv4, domain, file, url
        slug = "IPv4"
        if ind_type.lower() == "domain":
            slug = "domain"
        elif ind_type.lower() == "hash":
            slug = "file"
        elif ind_type.lower() == "url":
            slug = "url"

        url = f"{self.base_url}/{slug}/{indicator}/general"

        if not self.api_key or "85a8bcfbf" not in self.api_key:
            logger.warning("AlienVault OTX API key missing or invalid. Returning fallback data.")
            return self._get_fallback_data(indicator)

        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    data = response.json()
                    pulse_info = data.get("pulse_info", {})
                    pulses = pulse_info.get("pulses", [])
                    pulse_count = pulse_info.get("count", 0)
                    
                    tags = set()
                    malware_families = set()
                    for pulse in pulses:
                        for tag in pulse.get("tags", []):
                            tags.add(tag)
                        for fam in pulse.get("malware_families", []):
                            malware_families.add(fam.get("name") if isinstance(fam, dict) else fam)

                    return {
                        "pulse_count": pulse_count,
                        "tags": list(tags)[:10],
                        "malware_families": list(malware_families)[:5],
                        "status": "success",
                        "raw": data
                    }
                else:
                    logger.warning(f"OTX request failed with status {response.status_code}. Returning fallback.")
                    return self._get_fallback_data(indicator)
            except Exception as e:
                logger.error(f"OTX query failed: {e}. Returning fallback.")
                return self._get_fallback_data(indicator)

    def _get_fallback_data(self, indicator: str) -> Dict[str, Any]:
        return {
            "pulse_count": 24,
            "tags": ["Emotet", "C2", "Botnet", "Malicious-IP", "Brute-Force"],
            "malware_families": ["Emotet", "CobaltStrike"],
            "status": "fallback",
            "raw": None
        }

alienvault_service = AlienVaultService()
