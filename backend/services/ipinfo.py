import logging
import httpx
import json
from typing import Dict, Any
from core.config import settings
from core.cache import cache_service
from services.provider_result import provider_result, unavailable

logger = logging.getLogger(__name__)

class IPInfoService:
    def __init__(self):
        self.token = settings.IPINFO_API_TOKEN
        self.base_url = "https://ipinfo.io"
        print(f"IPInfo token loaded: {bool(self.token)}")

    async def get_ip_info(self, ip: str) -> Dict[str, Any]:
        # Unique per-IP cache key — NEVER a static string
        cache_key = f"ipinfo:{ip}"
        cached_data = cache_service.get(cache_key)
        if cached_data:
            try:
                logger.info(f"Cache hit for IPinfo: {ip}")
                return json.loads(cached_data)
            except Exception:
                pass

        # Explicit URL with IP embedded — NEVER ipinfo.io/json without IP
        if self.token and self.token not in {"YOUR_API_KEY", "your_ipinfo_token_here"}:
            url = f"{self.base_url}/{ip}/json?token={self.token}"
        else:
            url = f"{self.base_url}/{ip}/json"

        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    loc = data.get("loc")
                    lat, lon = None, None
                    try:
                        if loc:
                            lat_s, lon_s = loc.split(",")
                            lat, lon = float(lat_s), float(lon_s)
                    except (ValueError, AttributeError):
                        pass

                    result = provider_result("IPinfo", "success", {
                        "ip": data.get("ip", ip),
                        "city": data.get("city"),
                        "region": data.get("region"),
                        "country": data.get("country"),
                        "loc": loc,
                        "lat": lat,
                        "lon": lon,
                        "org": data.get("org"),
                        "asn": data.get("org", "").split(" ")[0] if "org" in data else None,
                        "postal": data.get("postal", ""),
                        "timezone": data.get("timezone"),
                        "raw": data
                    })

                    try:
                        cache_service.set(cache_key, json.dumps(result), expire=86400)
                        logger.info(f"Cached IPinfo for {ip}: {result['city']}, {result['country']}")
                    except Exception as ce:
                        logger.error(f"Failed caching IPinfo result: {ce}")

                    return result
                else:
                    logger.warning(f"IPinfo HTTP {response.status_code} for {ip}. Using fallback.")
                    return self._get_fallback_data(ip)
            except Exception as e:
                logger.error(f"IPinfo query failed for {ip}: {e}. Using fallback.")
                return self._get_fallback_data(ip)

    def _get_fallback_data(self, ip: str) -> Dict[str, Any]:
        # Never invent a location when the upstream provider is unavailable.
        return unavailable("IPinfo", "Provider did not return a result")

ipinfo_service = IPInfoService()
