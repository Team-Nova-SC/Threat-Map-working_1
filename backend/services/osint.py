import socket
import ssl
import logging
from typing import Dict, Any, List
import dns.resolver
import whois
from datetime import datetime
import asyncio
from services.provider_result import provider_result, unavailable

logger = logging.getLogger(__name__)

class OSINTService:
    async def get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        results = {"A": [], "MX": [], "TXT": [], "NS": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        for rtype in results.keys():
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    results[rtype].append(str(rdata))
            except Exception as e:
                # Silently skip missing records
                pass
        return provider_result("DNS", "success", results)

    async def get_whois_data(self, domain: str) -> Dict[str, Any]:
        try:
            # Run whois in a thread with a 5 second timeout to prevent event loop blocking
            w = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=5.0)
            
            # WHOIS libraries often return lists of dates or registrars
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            return provider_result("WHOIS", "success", {
                "registrar": w.registrar or "Unknown",
                "creation_date": creation_date.strftime("%Y-%m-%d") if isinstance(creation_date, datetime) else str(creation_date or ""),
                "expiration_date": expiration_date.strftime("%Y-%m-%d") if isinstance(expiration_date, datetime) else str(expiration_date or ""),
                "registrant_org": w.org or "Unknown",
            })
        except Exception as e:
            logger.warning(f"WHOIS query failed for {domain}: {e}")
            return unavailable("WHOIS", str(e), "error")

    async def get_ssl_metadata(self, host: str, port: int = 443) -> Dict[str, Any]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            # Set socket timeout to prevent long hangs
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.5)
            
            sslsock = context.wrap_socket(sock, server_hostname=host)
            sslsock.connect((host, port))
            cert = sslsock.getpeercert(binary_form=False)
            
            issuer = {}
            for rd in cert.get("issuer", []):
                for key, val in rd:
                    issuer[key] = val
                    
            subject = {}
            for rd in cert.get("subject", []):
                for key, val in rd:
                    subject[key] = val

            sslsock.close()
            valid_to = cert.get("notAfter", "")
            certificate_status = "valid"
            if valid_to:
                try:
                    if datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z") <= datetime.utcnow():
                        certificate_status = "expired"
                except ValueError:
                    certificate_status = "unknown"
            return provider_result("TLS certificate", "success", {
                "issuer": issuer.get("commonName", issuer.get("organizationName", "Unknown")),
                "subject": subject.get("commonName", "Unknown"),
                "valid_from": cert.get("notBefore", ""),
                "valid_to": valid_to,
                "serial_number": cert.get("serialNumber", ""),
                "version": cert.get("version"),
                "certificate_status": certificate_status
            })
        except Exception as e:
            logger.warning(f"SSL handshake failed for {host}:{port}: {e}")
            return unavailable("TLS certificate", str(e), "error")

osint_service = OSINTService()
