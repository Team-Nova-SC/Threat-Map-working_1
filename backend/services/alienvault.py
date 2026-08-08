import logging
import httpx
import asyncio
from typing import Dict, Any, List
from core.config import settings
from services.provider_result import provider_result, unavailable

logger = logging.getLogger(__name__)

class AlienVaultService:
    def __init__(self):
        self.api_key = getattr(settings, "ALIENVAULT_API_KEY", "")
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"accept": "application/json"}
        if self.api_key and self.api_key != "YOUR_API_KEY" and len(self.api_key) > 10:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    async def get_indicator_report(self, indicator: str, ind_type: str) -> Dict[str, Any]:
        indicator = indicator.strip()
        ind_type_lower = ind_type.lower().strip()

        # Map indicator types to OTX URL slugs
        slug = "IPv4"
        if ind_type_lower in ("domain", "hostname"):
            slug = "domain"
        elif ind_type_lower in ("hash", "file"):
            slug = "file"
        elif ind_type_lower == "url":
            slug = "url"
        elif ind_type_lower == "cve":
            slug = "cve"

        headers = self._get_headers()
        transport = httpx.AsyncHTTPTransport(local_address='0.0.0.0')

        async with httpx.AsyncClient(transport=transport, timeout=12.0) as client:
            try:
                # 1. Primary query: /general
                gen_url = f"{self.base_url}/{slug}/{indicator}/general"
                gen_resp = await client.get(gen_url, headers=headers)
                
                if gen_resp.status_code != 200:
                    logger.warning(f"OTX general endpoint returned status {gen_resp.status_code} for {indicator}")
                    return self._get_fallback_data(indicator)

                gen_data = gen_resp.json()

                # Extract Pulses & Pulse Aggregations
                pulse_info = gen_data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                raw_pulses = pulse_info.get("pulses", [])

                pulses = []
                tags_set = set()
                malware_families_set = set()
                attack_ids_set = set()
                target_countries_set = set()
                target_industries_set = set()
                references_set = set()

                for pulse in raw_pulses[:15]:
                    p_name = pulse.get("name", "Untitled Pulse")
                    p_desc = pulse.get("description", "")
                    p_author = pulse.get("author", {}).get("username") if isinstance(pulse.get("author"), dict) else pulse.get("author_name", "Anonymous Analyst")
                    p_created = pulse.get("created", "")
                    p_modified = pulse.get("modified", "")
                    p_tlp = pulse.get("tlp", "white")
                    p_tags = pulse.get("tags", [])
                    
                    # Malware families
                    p_mf = []
                    for mf in pulse.get("malware_families", []):
                        mf_name = mf.get("name") if isinstance(mf, dict) else str(mf)
                        if mf_name:
                            p_mf.append(mf_name)
                            malware_families_set.add(mf_name)

                    # MITRE ATT&CK
                    p_attack = []
                    for att in pulse.get("attack_ids", []):
                        if isinstance(att, dict):
                            att_id = att.get("id") or att.get("name")
                            att_name = f"{att.get('id', '')}: {att.get('name', '')}".strip(": ")
                        else:
                            att_id = str(att)
                            att_name = str(att)
                        if att_id:
                            p_attack.append(att_name)
                            attack_ids_set.add(att_name)

                    # Targeted Countries & Industries
                    p_countries = pulse.get("targeted_countries", [])
                    p_industries = pulse.get("industries", [])
                    p_refs = pulse.get("references", [])

                    for tag in p_tags: tags_set.add(str(tag))
                    for c in p_countries: target_countries_set.add(str(c))
                    for ind in p_industries: target_industries_set.add(str(ind))
                    for ref in p_refs: references_set.add(str(ref))

                    pulses.append({
                        "id": pulse.get("id"),
                        "name": p_name,
                        "description": p_desc[:300] if p_desc else "",
                        "author": p_author,
                        "created": p_created,
                        "modified": p_modified,
                        "tlp": p_tlp,
                        "tags": p_tags[:8],
                        "malware_families": p_mf[:5],
                        "attack_ids": p_attack[:5],
                        "targeted_countries": p_countries[:5],
                        "industries": p_industries[:5],
                        "references": p_refs[:3]
                    })

                # 2. Parallel secondary queries based on slug type
                sub_queries = {}
                if slug == "IPv4":
                    sub_queries["reputation"] = client.get(f"{self.base_url}/{slug}/{indicator}/reputation", headers=headers)
                    sub_queries["geo"] = client.get(f"{self.base_url}/{slug}/{indicator}/geo", headers=headers)
                    sub_queries["passive_dns"] = client.get(f"{self.base_url}/{slug}/{indicator}/passive_dns", headers=headers)
                    sub_queries["malware"] = client.get(f"{self.base_url}/{slug}/{indicator}/malware", headers=headers)
                    sub_queries["url_list"] = client.get(f"{self.base_url}/{slug}/{indicator}/url_list", headers=headers)
                elif slug == "domain":
                    sub_queries["geo"] = client.get(f"{self.base_url}/{slug}/{indicator}/geo", headers=headers)
                    sub_queries["passive_dns"] = client.get(f"{self.base_url}/{slug}/{indicator}/passive_dns", headers=headers)
                    sub_queries["malware"] = client.get(f"{self.base_url}/{slug}/{indicator}/malware", headers=headers)
                    sub_queries["url_list"] = client.get(f"{self.base_url}/{slug}/{indicator}/url_list", headers=headers)
                elif slug == "url":
                    sub_queries["url_list"] = client.get(f"{self.base_url}/{slug}/{indicator}/url_list", headers=headers)
                elif slug == "file":
                    sub_queries["analysis"] = client.get(f"{self.base_url}/{slug}/{indicator}/analysis", headers=headers)

                sub_results = {}
                if sub_queries:
                    keys = list(sub_queries.keys())
                    coros = list(sub_queries.values())
                    res_list = await asyncio.gather(*coros, return_exceptions=True)
                    for k, res in zip(keys, res_list):
                        if isinstance(res, httpx.Response) and res.status_code == 200:
                            try:
                                sub_results[k] = res.json()
                            except Exception:
                                pass

                # Parse Geo
                geo_raw = sub_results.get("geo") or gen_data
                geo_info = {
                    "country_name": geo_raw.get("country_name") or gen_data.get("country_name", "Unknown"),
                    "country_code": geo_raw.get("country_code") or gen_data.get("country_code", ""),
                    "city": geo_raw.get("city") or gen_data.get("city", "Unknown"),
                    "asn": geo_raw.get("asn") or gen_data.get("asn", "N/A"),
                    "latitude": geo_raw.get("latitude") or gen_data.get("latitude"),
                    "longitude": geo_raw.get("longitude") or gen_data.get("longitude")
                }

                # Parse Reputation
                rep_raw = sub_results.get("reputation", {})
                reputation_info = {
                    "threat_score": rep_raw.get("reputation", {}).get("threat_score") if isinstance(rep_raw.get("reputation"), dict) else rep_raw.get("reputation"),
                    "activities": rep_raw.get("activities", [])
                }

                # Parse Passive DNS
                pdns_raw = sub_results.get("passive_dns", {}).get("passive_dns", [])
                passive_dns = []
                for entry in pdns_raw[:15]:
                    passive_dns.append({
                        "hostname": entry.get("hostname") or entry.get("address", "N/A"),
                        "record_type": entry.get("record_type", "A"),
                        "first": entry.get("first", ""),
                        "last": entry.get("last", ""),
                        "asn": entry.get("asn", "")
                    })

                # Parse Malware Samples
                mw_raw = sub_results.get("malware", {}).get("data", []) or sub_results.get("malware", {}).get("instances", [])
                malware_samples = []
                for entry in mw_raw[:15]:
                    malware_samples.append({
                        "hash": entry.get("hash") or entry.get("sha256") or entry.get("md5", "N/A"),
                        "name": entry.get("name") or entry.get("title", "Suspicious File"),
                        "date": entry.get("datetime") or entry.get("date", "")
                    })

                # Parse URL List
                urls_raw = sub_results.get("url_list", {}).get("url_list", [])
                url_list = []
                for entry in urls_raw[:15]:
                    url_list.append({
                        "url": entry.get("url", ""),
                        "httpcode": entry.get("result", {}).get("httpcode") if isinstance(entry.get("result"), dict) else entry.get("httpcode", "N/A"),
                        "date": entry.get("date", "")
                    })

                # Parse File Analysis
                analysis_raw = sub_results.get("analysis", {}).get("analysis", {})
                file_analysis = {
                    "file_type": gen_data.get("type") or analysis_raw.get("info", {}).get("file", {}).get("file_type"),
                    "file_size": gen_data.get("size") or analysis_raw.get("info", {}).get("file", {}).get("file_size"),
                    "yara_matches": analysis_raw.get("yara", []),
                    "av_detections": analysis_raw.get("plugins", {})
                }

                # Parse CVE info if slug == "cve"
                cve_info = {}
                if slug == "cve":
                    cve_info = {
                        "cve_id": gen_data.get("cve") or indicator,
                        "description": gen_data.get("description", ""),
                        "cvss_score": gen_data.get("cvss", {}).get("base_score") if isinstance(gen_data.get("cvss"), dict) else gen_data.get("cvss"),
                        "published": gen_data.get("date_created", "")
                    }

                return provider_result("AlienVault OTX", "success", {
                    "pulse_count": pulse_count,
                    "pulses": pulses,
                    "tags": list(tags_set)[:20],
                    "malware_families": list(malware_families_set)[:15],
                    "attack_ids": list(attack_ids_set)[:15],
                    "target_countries": list(target_countries_set)[:10],
                    "target_industries": list(target_industries_set)[:10],
                    "references": list(references_set)[:10],
                    "geo": geo_info,
                    "reputation": reputation_info,
                    "passive_dns": passive_dns,
                    "malware_samples": malware_samples,
                    "url_list": url_list,
                    "file_analysis": file_analysis,
                    "cve_info": cve_info,
                    "raw": gen_data
                })

            except Exception as e:
                logger.error(f"OTX query failed for {indicator}: {e}")
                return self._get_fallback_data(indicator)

    def _get_fallback_data(self, indicator: str) -> Dict[str, Any]:
        return unavailable("AlienVault OTX", "Provider did not return a result")

alienvault_service = AlienVaultService()
