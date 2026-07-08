import asyncio
import logging
import random
import ipaddress
from typing import Dict, Any

logger = logging.getLogger(__name__)

class WhoisJsonService:
    def __init__(self):
        self.api_key = "43b0c1aa36fcb49caab044a866c2052e5681b137e71e5d9fb94f3057fde7081b"
        self.base_url = "https://api.whoisjson.fake/v1" # Mock endpoint

    async def get_domain_data(self, domain: str) -> Dict[str, Any]:
        """
        Simulates fetching comprehensive WHOIS/DNS data from WhoisJSON.
        Handles both Domains and IPs.
        """
        try:
            # Simulate network latency (200-500ms)
            await asyncio.sleep(random.uniform(0.2, 0.5))

            is_malicious = "malicious" in domain.lower() or "phish" in domain.lower()
            
            is_ip = False
            try:
                ipaddress.ip_address(domain)
                is_ip = True
            except ValueError:
                pass
            
            # Subdomains mock (only relevant for domains)
            subdomains = ["www", "mail", "api", "dev", "test", "staging", "admin"]
            active_subs = []
            if not is_ip:
                active_subs = random.sample(subdomains, random.randint(1, 5))
                active_subs = [f"{sub}.{domain}" for sub in active_subs]
            else:
                # Mock reverse DNS for IPs
                active_subs = [f"crawl-{domain.replace('.', '-')}.googlebot.com" if not is_malicious else f"unknown-{domain.replace('.', '-')}.hacker.net"]

            return {
                "status": "success",
                "registrar_metadata": {
                    "name": "Cloudflare, Inc." if not is_ip and not is_malicious else ("ARIN (American Registry for Internet Numbers)" if is_ip else "Namecheap, Inc."),
                    "iana_id": "1337" if not is_malicious else "1068",
                    "url": "http://www.cloudflare.com" if not is_ip and not is_malicious else ("https://www.arin.net" if is_ip else "http://www.namecheap.com")
                },
                "registry_dates": {
                    "creation_date": "2010-01-15T00:00:00Z" if not is_malicious else "2024-05-10T00:00:00Z",
                    "updated_date": "2023-01-10T00:00:00Z",
                    "expiration_date": "2026-01-15T00:00:00Z" if not is_malicious else "2025-05-10T00:00:00Z"
                },
                "epp_status": [
                    "clientTransferProhibited",
                    "clientUpdateProhibited",
                    "clientDeleteProhibited"
                ] if not is_ip else ["serverDeleteProhibited", "serverUpdateProhibited"],
                "contacts": {
                    "registrant": {
                        "name": "REDACTED FOR PRIVACY" if not is_ip else "Google LLC",
                        "organization": "Privacy Protect, LLC" if not is_ip else "Google LLC",
                        "email": "contact@privacyprotect.fake" if not is_ip else "network-abuse@google.com",
                        "country": "IS" if not is_ip else "US"
                    },
                    "admin": {
                        "name": "REDACTED FOR PRIVACY" if not is_ip else "Google Cloud Support",
                        "organization": "Privacy Protect, LLC" if not is_ip else "Google LLC",
                        "email": "admin@privacyprotect.fake" if not is_ip else "admin@google.com"
                    },
                    "tech": {
                        "name": "REDACTED FOR PRIVACY" if not is_ip else "Google Network Engineering",
                        "organization": "Privacy Protect, LLC" if not is_ip else "Google LLC",
                        "email": "tech@privacyprotect.fake" if not is_ip else "noc@google.com"
                    }
                },
                "dns_records": {
                    "A": [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"],
                    "AAAA": ["2606:4700:4700::1111"],
                    "MX": [f"mail.{domain} (Priority: 10)"],
                    "TXT": [
                        "v=spf1 include:_spf.google.com ~all",
                        "google-site-verification=xyz123"
                    ],
                    "NS": [f"ns1.{domain}", f"ns2.{domain}"],
                    "CNAME": [],
                    "SOA": [f"ns1.{domain} admin.{domain} 2024010101 7200 3600 1209600 3600"],
                    "CAA": ["0 issue \"letsencrypt.org\""],
                    "DMARC": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
                },
                "ssl_tls_state": {
                    "status": "valid" if not is_malicious else "invalid_or_expired",
                    "issuer": "Let's Encrypt Authority X3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "valid_to": "2024-04-01T00:00:00Z"
                },
                "active_subdomains": active_subs,
                "availability": "registered",
                "reverse_whois_count": random.randint(1, 50) if not is_malicious else random.randint(50, 500)
            }
        except Exception as e:
            logger.error(f"WhoisJSON query failed for {domain}: {e}")
            return {"status": "error", "message": str(e)}

whoisjson_service = WhoisJsonService()
