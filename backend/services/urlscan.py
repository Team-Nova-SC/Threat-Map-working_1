import logging
import httpx
from typing import Dict, Any
from core.config import settings
from services.provider_result import provider_result, unavailable

logger = logging.getLogger(__name__)

class URLScanService:
    def __init__(self):
        self.api_key = getattr(settings, "URLSCAN_API_KEY", "")
        self.base_url = "https://urlscan.io/api/v1"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"accept": "application/json"}
        if self.api_key and self.api_key != "YOUR_API_KEY" and len(self.api_key) > 10:
            headers["API-Key"] = self.api_key
        return headers

    async def search_indicator(self, indicator: str, ind_type: str) -> Dict[str, Any]:
        indicator = indicator.strip()
        ind_type_lower = ind_type.lower().strip()

        if ind_type_lower in ["domain"]:
            query = f"domain:{indicator}"
        elif ind_type_lower in ["ip"]:
            query = f"ip:{indicator}"
        elif ind_type_lower in ["url"]:
            query = f"url:\"{indicator}\""
        else:
            query = f"\"{indicator}\""

        headers = self._get_headers()
        search_url = f"{self.base_url}/search/"
        params = {"q": query, "size": 1}

        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
        async with httpx.AsyncClient(transport=transport, timeout=20.0) as client:
            try:
                # 1. Search for existing scan
                resp = await client.get(search_url, params=params, headers=headers)
                if resp.status_code != 200:
                    logger.warning(f"URLScan search returned status {resp.status_code} for {indicator}")
                    return self._get_fallback_data(indicator)

                data = resp.json()
                results = data.get("results", [])
                if not results:
                    return {
                        "status": "no_results",
                        "scan_id": "",
                        "screenshot_url": "",
                        "overall_status": "no_results",
                        "detail": "No public sandbox scans recorded on urlscan.io for this indicator."
                    }

                search_item = results[0]
                scan_id = search_item.get("_id")
                task_info = search_item.get("task", {})
                page_info = search_item.get("page", {})
                verdicts_search = search_item.get("verdicts", {})
                stats_search = search_item.get("stats", {})

                # Default values from search
                result_payload = {
                    "scan_id": scan_id,
                    "report_url": f"https://urlscan.io/result/{scan_id}/",
                    "screenshot_url": f"https://urlscan.io/screenshots/{scan_id}.png",
                    "dom_url": f"https://urlscan.io/dom/{scan_id}/",
                    "overall_status": "success",
                    "page_title": page_info.get("title", ""),
                    "final_url": page_info.get("url", search_item.get("task", {}).get("url", indicator)),
                    "server": page_info.get("server", ""),
                    "ip": page_info.get("ip", ""),
                    "asn": page_info.get("asnname") or page_info.get("asn", ""),
                    "country": page_info.get("country", ""),
                    "verdicts": verdicts_search,
                    "stats": stats_search,
                    "lists": search_item.get("lists", {}),
                    "technologies": [],
                    "requests": [],
                    "cookies": [],
                    "console_logs": [],
                    "links": [],
                    "certificates": []
                }

                # 2. Fetch full result details if scan_id exists
                if scan_id:
                    try:
                        result_url = f"{self.base_url}/result/{scan_id}/"
                        res_detail = await client.get(result_url, headers=headers)
                        if res_detail.status_code == 200:
                            det_data = res_detail.json()
                            det_verdicts = det_data.get("verdicts", verdicts_search)
                            det_page = det_data.get("page", page_info)
                            det_lists = det_data.get("lists", {})
                            det_stats = det_data.get("stats", stats_search)
                            meta = det_data.get("meta", {})
                            det_data_sec = det_data.get("data", {})

                            # Technologies (Wappalyzer)
                            techs = []
                            wappa = meta.get("processors", {}).get("wappalyzer", {}).get("data", [])
                            for t in wappa:
                                if isinstance(t, dict):
                                    techs.append({
                                        "name": t.get("app", t.get("name", "")),
                                        "confidence": t.get("confidence", 100),
                                        "categories": t.get("categories", [])
                                    })
                                elif isinstance(t, str):
                                    techs.append({"name": t, "confidence": 100, "categories": []})

                            # Requests
                            raw_reqs = det_data_sec.get("requests", [])
                            parsed_reqs = []
                            for r in raw_reqs[:25]:
                                req_item = r.get("request", {}).get("request", {})
                                resp_item = r.get("response", {}).get("response", {})
                                parsed_reqs.append({
                                    "url": req_item.get("url", ""),
                                    "method": req_item.get("method", "GET"),
                                    "status": resp_item.get("status", "N/A"),
                                    "mime": resp_item.get("mimeType", ""),
                                    "size": resp_item.get("encodedDataLength", 0),
                                    "ip": resp_item.get("remoteIPAddress", "")
                                })

                            # Cookies
                            raw_cookies = det_data_sec.get("cookies", [])
                            parsed_cookies = []
                            for c in raw_cookies[:15]:
                                parsed_cookies.append({
                                    "name": c.get("name", ""),
                                    "domain": c.get("domain", ""),
                                    "httpOnly": c.get("httpOnly", False),
                                    "secure": c.get("secure", False)
                                })

                            # Console logs
                            raw_console = det_data_sec.get("console", [])
                            parsed_console = []
                            for con in raw_console[:10]:
                                parsed_console.append({
                                    "type": con.get("message", {}).get("level", "log"),
                                    "text": con.get("message", {}).get("text", "")
                                })

                            # Links
                            raw_links = det_data_sec.get("links", [])
                            parsed_links = []
                            for l in raw_links[:15]:
                                parsed_links.append({
                                    "href": l.get("href", ""),
                                    "text": l.get("text", "")
                                })

                            # Certificates
                            certs = det_lists.get("certificates", [])

                            result_payload.update({
                                "verdicts": det_verdicts,
                                "page_title": det_page.get("title") or result_payload["page_title"],
                                "final_url": det_page.get("url") or result_payload["final_url"],
                                "server": det_page.get("server") or result_payload["server"],
                                "ip": det_page.get("ip") or result_payload["ip"],
                                "asn": det_page.get("asnname") or det_page.get("asn") or result_payload["asn"],
                                "country": det_page.get("country") or result_payload["country"],
                                "stats": det_stats,
                                "lists": det_lists,
                                "technologies": techs[:15],
                                "requests": parsed_reqs,
                                "cookies": parsed_cookies,
                                "console_logs": parsed_console,
                                "links": parsed_links,
                                "certificates": certs[:10],
                                "raw": det_data
                            })
                    except Exception as de:
                        logger.warning(f"Failed fetching full URLScan detail for {scan_id}: {de}")

                return provider_result("urlscan.io", "success", result_payload)

            except Exception as e:
                logger.error(f"URLScan lookup failed for {indicator}: {e}")
                return self._get_fallback_data(indicator)

    def _get_fallback_data(self, indicator: str) -> Dict[str, Any]:
        return unavailable("urlscan.io", "Provider did not return a result")

urlscan_service = URLScanService()
