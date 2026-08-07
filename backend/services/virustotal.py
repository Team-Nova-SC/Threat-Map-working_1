import base64
import logging
import httpx
import asyncio
from typing import Dict, Any, Optional
from core.config import settings
from services.provider_result import provider_result, unavailable

logger = logging.getLogger(__name__)

class VirusTotalService:
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        url = f"{self.base_url}/ip_addresses/{ip}"
        rel_url = f"{url}/resolutions?limit=10"
        return await self._fetch_combined(url, rel_url, "resolutions")

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        url = f"{self.base_url}/domains/{domain}"
        rel_url = f"{url}/subdomains?limit=10"
        return await self._fetch_combined(url, rel_url, "subdomains")

    async def get_hash_report(self, file_hash: str) -> Dict[str, Any]:
        url = f"{self.base_url}/files/{file_hash}"
        rel_url = f"{url}/contacted_domains?limit=10"
        return await self._fetch_combined(url, rel_url, "contacted_domains")

    async def get_url_report(self, target_url: str) -> Dict[str, Any]:
        # VirusTotal v3 URL identifier is base64 representation of URL without padding '='
        encoded_url = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = f"{self.base_url}/urls/{encoded_url}"
        rel_url = f"{url}/network_location?limit=10"
        return await self._fetch_combined(url, rel_url, "network_location")

    async def _fetch_combined(self, url: str, rel_url: str, rel_key: str) -> Dict[str, Any]:
        if not self.api_key or len(self.api_key) < 10:
            logger.warning("VT API key missing. Returning fallback data.")
            return unavailable("VirusTotal", "API key is not configured")

        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                # Fire both requests concurrently
                main_req, rel_req = await asyncio.gather(
                    client.get(url, headers=self.headers),
                    client.get(rel_url, headers=self.headers),
                    return_exceptions=True
                )
                
                # Check main request
                if isinstance(main_req, Exception):
                    raise main_req
                    
                if main_req.status_code == 200:
                    data = main_req.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    
                    # Process relationship request safely
                    relationships = {}
                    if not isinstance(rel_req, Exception) and rel_req.status_code == 200:
                        rel_data = rel_req.json()
                        relationships[rel_key] = rel_data.get("data", [])
                    
                    # Return massively enriched data object
                    return provider_result("VirusTotal", "success", {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": attributes.get("reputation", 0),
                        "attributes": attributes,          # FULL Deep inspection data
                        "relationships": relationships,    # Relational graph data
                        "raw": data
                    })
                elif main_req.status_code == 404:
                    return provider_result("VirusTotal", "not_found", {"raw": None})
                else:
                    logger.warning(f"VirusTotal request failed with status {main_req.status_code}.")
                    return unavailable("VirusTotal", f"HTTP {main_req.status_code}", "error")
            except Exception as e:
                logger.error(f"VirusTotal query failed: {e}. Returning fallback.")
                return unavailable("VirusTotal", str(e), "error")

    def _get_fallback_data(self) -> Dict[str, Any]:
        return unavailable("VirusTotal", "Provider did not return a result")

virustotal_service = VirusTotalService()
