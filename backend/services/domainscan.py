import asyncio
import logging
import random
import ipaddress
from typing import Dict, Any

logger = logging.getLogger(__name__)

class DomainScanService:
    def __init__(self):
        self.api_key = "dsk_2d791a64"
        self.base_url = "https://api.domainscan.fake/v1"

    async def get_scan_data(self, indicator: str) -> Dict[str, Any]:
        """
        Simulates fetching high-performance DomainScan diagnostic data.
        Handles both domains and IPs.
        """
        try:
            # Simulate sub-second latency (~240ms)
            await asyncio.sleep(0.24)

            is_malicious = "malicious" in indicator.lower() or "phish" in indicator.lower()
            
            is_ip = False
            try:
                ipaddress.ip_address(indicator)
                is_ip = True
            except ValueError:
                pass
            
            ai_score = random.randint(10, 40) if is_malicious else random.randint(70, 100)
            if ai_score >= 90:
                grade = "A"
            elif ai_score >= 80:
                grade = "B"
            elif ai_score >= 70:
                grade = "C"
            elif ai_score >= 60:
                grade = "D"
            else:
                grade = "F"

            return {
                "status": "success",
                "performance_metrics": {
                    "latency_ms": random.randint(120, 450),
                    "http_handshake_code": random.choice([200, 200, 200, 301, 302, 403, 500]) if not is_malicious else random.choice([403, 404, 500, 502, 522]),
                    "server_delay_ms": random.randint(50, 200)
                },
                "ai_readiness": {
                    "score": ai_score,
                    "grade": grade,
                    "robots_txt_present": not is_malicious and not is_ip,
                    "sitemap_present": not is_malicious and not is_ip,
                },
                "bot_access_matrix": {
                    "GPTBot": not is_malicious and random.choice([True, False]),
                    "ClaudeBot": not is_malicious and random.choice([True, False]),
                    "Googlebot": True,
                    "Bingbot": True,
                    "Applebot": not is_malicious,
                    "CCBot": not is_malicious and random.choice([True, False]),
                    "Anthropic-ai": not is_malicious and random.choice([True, False]),
                    "PerplexityBot": not is_malicious and random.choice([True, False]),
                } if not is_ip else {
                    "SSH_Open": random.choice([True, False]),
                    "HTTP_Open": True,
                    "HTTPS_Open": True,
                    "FTP_Open": False,
                    "SMTP_Open": False
                },
                "metadata_validation": {
                    "has_title": not is_ip,
                    "has_description": not is_malicious and not is_ip,
                    "has_open_graph": not is_malicious and not is_ip,
                    "has_twitter_cards": not is_malicious and not is_ip,
                    "schema_org_types": ["WebSite", "Organization"] if not is_malicious and not is_ip else []
                },
                "network_path_health": "Healthy - Direct Path" if not is_malicious else "Warning - Proxied/Obfuscated",
                "live_browser_rendering": {
                    "snapshot_status": "captured" if not is_malicious and not is_ip else "failed_timeout",
                    "dom_elements_count": random.randint(50, 1500) if not is_ip else 0
                }
            }
        except Exception as e:
            logger.error(f"DomainScan query failed for {indicator}: {e}")
            return {"status": "error", "message": str(e)}

domainscan_service = DomainScanService()
