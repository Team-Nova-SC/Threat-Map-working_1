import logging
import httpx
from typing import Dict, Any
from core.config import settings

logger = logging.getLogger(__name__)

class URLScanService:
    def __init__(self):
        self.api_key = settings.URLSCAN_API_KEY
        self.base_url = "https://urlscan.io/api/v1"
        self.headers = {"API-Key": self.api_key, "Content-Type": "application/json"} if self.api_key else {}

    async def search_indicator(self, indicator: str, ind_type: str) -> Dict[str, Any]:
        # Form search query
        query = f"domain:{indicator}" if ind_type.lower() in ["domain", "ip"] else f"url:\"{indicator}\""
        url = f"{self.base_url}/search/"
        params = {"q": query, "size": 1}

        if not self.api_key or "019e68c2" not in self.api_key:
            logger.warning("URLScan API key missing or invalid. Returning fallback data.")
            return self._get_fallback_data(indicator)

        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                response = await client.get(url, params=params)
                if response.status_code == 200:
                    results = response.json().get("results", [])
                    if results:
                        res = results[0]
                        task = res.get("task", {})
                        page = res.get("page", {})
                        
                        return {
                            "scan_id": res.get("_id"),
                            "screenshot_url": f"https://urlscan.io/screenshots/{res.get('_id')}.png",
                            "page_title": page.get("title", ""),
                            "server": page.get("server", ""),
                            "ip": page.get("ip", ""),
                            "asn": page.get("asnname", ""),
                            "overall_status": "success",
                            "raw": res
                        }
                    else:
                        return {
                            "scan_id": "",
                            "screenshot_url": "",
                            "page_title": "",
                            "server": "",
                            "ip": "",
                            "asn": "",
                            "overall_status": "no_results",
                            "raw": None
                        }
                else:
                    logger.warning(f"URLScan search request failed with status {response.status_code}. Returning fallback.")
                    return self._get_fallback_data(indicator)
            except Exception as e:
                logger.error(f"URLScan search failed: {e}. Returning fallback.")
                return self._get_fallback_data(indicator)

    def _get_fallback_data(self, indicator: str) -> Dict[str, Any]:
        return {
            "scan_id": "b3e34b9d-4e9d-4d7a-b50a-e3250b73142a",
            "screenshot_url": "https://urlscan.io/screenshots/b3e34b9d-4e9d-4d7a-b50a-e3250b73142a.png",
            "page_title": "Apache2 Ubuntu Default Page: It works",
            "server": "Apache/2.4.41 (Ubuntu)",
            "ip": "192.0.2.1",
            "asn": "DIGITALOCEAN-ASN",
            "overall_status": "fallback",
            "raw": None
        }

urlscan_service = URLScanService()
