import logging
from typing import Dict, Any
from services.provider_result import unavailable

logger = logging.getLogger(__name__)

class GreyNoiseService:
    async def check_ip(self, ip: str) -> Dict[str, Any]:
        return self._get_fallback_data(ip)

    def _get_fallback_data(self, ip: str) -> Dict[str, Any]:
        return unavailable("GreyNoise", "GreyNoise service has been disabled.")

greynoise_service = GreyNoiseService()
