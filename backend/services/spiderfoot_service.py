import httpx
import logging
import asyncio
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class SpiderfootService:
    def __init__(self):
        self.base_url = "http://127.0.0.1:5001"
    
    async def start_scan(self, target: str) -> Dict[str, Any]:
        """Start a new SpiderFoot scan on the target."""
        try:
            transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
            async with httpx.AsyncClient(transport=transport, timeout=60.0) as client:
                data = {
                    "scanname": f"ThreatMap_{target}",
                    "scantarget": target,
                    "usecase": "all",
                    "modulelist": "",
                    "typelist": ""
                }
                response = await client.post(f"{self.base_url}/startscan", data=data)
                
                # SpiderFoot API typically returns the scan ID directly or redirects
                if response.status_code in (200, 302, 303):
                    # For a simple local integration, let's just grab the scan ID from the scanlist if not clearly returned
                    # Wait a tiny bit for it to register
                    await asyncio.sleep(3)
                    scanlist = await self._get_scan_list()
                    if scanlist and len(scanlist) > 0:
                        # Find the scan we just started
                        for scan in scanlist:
                            if scan[1] == f"ThreatMap_{target}":
                                return {"status": "started", "scan_id": scan[0]}
                    return {"status": "error", "message": "Scan started but ID not found"}
                return {"status": "error", "message": f"Failed to start scan: HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Failed to start SpiderFoot scan for {target}: {repr(e)}")
            return {"status": "error", "message": f"Connection error: {str(e) or repr(e)}"}

    async def _get_scan_list(self) -> List[Any]:
        """Get list of scans to find our scan ID."""
        try:
            transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
            async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
                response = await client.get(f"{self.base_url}/scanlist")
                if response.status_code == 200:
                    return response.json()
                return []
        except Exception:
            return []

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Check the status of a specific scan."""
        try:
            transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
            async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
                response = await client.get(f"{self.base_url}/scaninfo?id={scan_id}")
                if response.status_code == 200:
                    # Parse SpiderFoot scaninfo (usually returns a list [id, name, target, status, started, finished])
                    data = response.json()
                    if data and len(data) > 0:
                        status_str = data[0][3]
                        return {"scan_id": scan_id, "status": status_str}
                return {"status": "UNKNOWN"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    async def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Fetch categorized results from a running or finished scan."""
        # The user requested these data types
        target_types = {
            "EMAILADDR": "emails",
            "INTERNET_NAME": "subdomains",
            "IP_ADDRESS": "related_ips",
            "DARKNET_MENTION": "darkweb",
            "LEAKSITE_CONTENT": "leaks",
            "SOCIAL_MEDIA": "social",
            "WEBSERVER_BANNER": "tech_stack",
            "SSL_CERTIFICATE_ISSUED": "ssl_certs"
        }
        
        results = {val: [] for val in target_types.values()}
        
        try:
            transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')
            async with httpx.AsyncClient(transport=transport, timeout=30.0) as client:
                # Get the event summary first
                response = await client.get(f"{self.base_url}/scaneventinfo?id={scan_id}")
                if response.status_code == 200:
                    event_info = response.json()
                    # event_info is typically a list of [type, desc, last_seen, data_count]
                    
                    for event_type in event_info:
                        type_name = event_type[0]
                        if type_name in target_types:
                            key = target_types[type_name]
                            # Fetch the actual data for this type
                            data_resp = await client.get(f"{self.base_url}/scaneventresultstype?id={scan_id}&eventType={type_name}")
                            if data_resp.status_code == 200:
                                # result data is typically a list of lists, where [4] is the actual data string
                                event_data = data_resp.json()
                                items = []
                                for row in event_data:
                                    if len(row) > 4:
                                        items.append(row[4])
                                results[key] = list(set(items)) # deduplicate
        except Exception as e:
            logger.error(f"Failed to fetch SpiderFoot results for {scan_id}: {e}")
            
        return results

spiderfoot_service = SpiderfootService()
