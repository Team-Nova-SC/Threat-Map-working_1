import asyncio
import base64
import binascii
import email.parser
import ipaddress
import urllib.parse
import re
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel
import httpx

try:
    import dns.asyncresolver
except ImportError:
    pass

router = APIRouter(prefix="/tools", tags=["Tools"])

class EmailHeadersRequest(BaseModel):
    raw_headers: str

class DecodeRequest(BaseModel):
    payload: str
    decode_type: str = "auto" # 'auto', 'base64', 'hex'

@router.post("/email-headers")
async def analyze_email_headers(request: EmailHeadersRequest):
    try:
        parser = email.parser.HeaderParser()
        msg = parser.parsestr(request.raw_headers)
        
        headers_dict = {}
        for k, v in msg.items():
            k_lower = k.lower()
            if k_lower not in headers_dict:
                headers_dict[k_lower] = []
            headers_dict[k_lower].append(v)

        # Extract key security indicators
        received_hops = headers_dict.get("received", [])
        auth_results = headers_dict.get("authentication-results", [])
        return_path = msg.get("return-path", "")
        from_header = msg.get("from", "")
        
        # Risk Analysis Layer
        risk_score = 0
        red_flags = []
        
        auth_str = " ".join(auth_results).lower()
        if "spf=fail" in auth_str or "spf=softfail" in auth_str:
            risk_score += 30
            red_flags.append("SPF authentication failed")
        
        if "dkim=fail" in auth_str:
            risk_score += 25
            red_flags.append("DKIM signature failed")
            
        if "dmarc=fail" in auth_str and "p=reject" in auth_str:
            risk_score += 30
            red_flags.append("DMARC policy violation (reject)")

        def extract_domain(email_str):
            match = re.search(r'@([\w.-]+)', str(email_str))
            return match.group(1).lower() if match else ""

        from_domain = extract_domain(from_header)
        return_domain = extract_domain(return_path)
        
        if from_domain and return_domain and from_domain != return_domain:
            risk_score += 20
            red_flags.append(f"Sender mismatch: From ({from_domain}) != Return-Path ({return_domain})")

        display_name_match = re.search(r'^(.*?)\s*<', str(from_header))
        if display_name_match and from_domain:
            display_name = display_name_match.group(1).lower().strip(' "\'')
            brands = ["paypal", "microsoft", "apple", "google", "amazon", "bank", "netflix", "facebook"]
            for brand in brands:
                if brand in display_name and brand not in from_domain:
                    risk_score += 20
                    red_flags.append(f"Brand impersonation detected: '{brand}' in display name but domain is {from_domain}")
                    break

        originating_ip = None
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for hop in reversed(received_hops):
            ips = re.findall(ip_pattern, str(hop))
            for ip in ips:
                if not ip.startswith("10.") and not ip.startswith("192.168.") and not (ip.startswith("172.") and int(ip.split('.')[1]) in range(16,32)) and not ip.startswith("127."):
                    originating_ip = ip
                    break
            if originating_ip:
                break
        
        if originating_ip:
            from services.abuseipdb import abuse_ipdb_service
            abuse_data = await abuse_ipdb_service.check_ip(originating_ip)
            abuse_score = abuse_data.get("abuseConfidenceScore", 0)
            if abuse_score > 0:
                risk_score += 25
                red_flags.append(f"Originating IP ({originating_ip}) has AbuseIPDB score of {abuse_score}%")

        risk_score = min(risk_score, 100)
        
        if risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Generate Plain English Verdict with Groq AI
        ai_summary = "Email analyzed successfully."
        if red_flags:
            try:
                from services.groq_service import chat_with_ai
                prompt = f"Analyze these email header findings and write a 1-2 sentence plain-English verdict. Do NOT use markdown or bold text. Be direct and professional. Risk Level: {risk_level}, Score: {risk_score}, Flags: {', '.join(red_flags)}."
                ai_summary = await chat_with_ai(prompt, model="openai/gpt-oss-120b")
            except Exception as e:
                ai_summary = f"This email shows a {risk_level} risk level based on header analysis. Identified flags: {', '.join(red_flags)}."
        else:
            ai_summary = "No significant risk indicators were found in the email headers."

        return {
            "verdict": {
                "risk_level": risk_level,
                "risk_score": risk_score,
                "red_flags": red_flags,
                "summary": ai_summary.strip()
            },
            "summary": {
                "from": from_header,
                "return_path": return_path,
                "hop_count": len(received_hops),
                "auth_results": auth_results,
                "originating_ip": originating_ip
            },
            "headers": headers_dict
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/typosquatting")
async def check_typosquatting(domain: str = Query(..., description="Domain to check")):
    if "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    
    parts = domain.split(".")
    base = parts[0]
    tld = ".".join(parts[1:])
    
    variations = set()
    # Omission
    for i in range(len(base)):
        variations.add(base[:i] + base[i+1:] + "." + tld)
    # Repetition
    for i in range(len(base)):
        variations.add(base[:i] + base[i] + base[i:] + "." + tld)
    # Transposition
    for i in range(len(base)-1):
        variations.add(base[:i] + base[i+1] + base[i] + base[i+2:] + "." + tld)
    
    variations.discard(domain)
    # Limit to 20 variations to avoid extreme overhead
    variations_list = list(variations)[:20]
    
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    results = []
    
    async def check_domain(var):
        try:
            answers = await resolver.resolve(var, "A")
            ips = [rdata.address for rdata in answers]
            return {"domain": var, "resolves": True, "ips": ips}
        except Exception:
            return {"domain": var, "resolves": False, "ips": []}

    tasks = [check_domain(var) for var in variations_list]
    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for res in batch_results:
        if isinstance(res, dict):
            results.append(res)
            
    active = [r for r in results if r["resolves"]]
    inactive = [r for r in results if not r["resolves"]]
    
    return {
        "original": domain,
        "variations_checked": len(variations_list),
        "active_typosquats": active,
        "inactive_typosquats": inactive
    }

@router.post("/decode")
async def decode_string(req: DecodeRequest):
    payload = req.payload.strip()
    result = None
    detected_type = None

    if req.decode_type in ["auto", "base64"]:
        try:
            # Fix padding
            padded = payload + "=" * ((4 - len(payload) % 4) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            if req.decode_type == "base64" or (decoded and decoded != payload):
                result = decoded
                detected_type = "base64"
        except Exception:
            pass

    if result is None and req.decode_type in ["auto", "hex"]:
        try:
            decoded = binascii.unhexlify(payload.replace(" ", "").replace("0x", "")).decode('utf-8', errors='ignore')
            if req.decode_type == "hex" or decoded:
                result = decoded
                detected_type = "hex"
        except Exception:
            pass

    if result is None:
        return {"decoded": "Could not decode payload", "type": "unknown"}
        
    return {"decoded": result, "type": detected_type}

@router.get("/dns")
async def enumerate_dns(domain: str = Query(..., description="Domain to enumerate")):
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA"]
    results = {}
    
    async def fetch_record(rtype):
        try:
            answers = await resolver.resolve(domain, rtype)
            return rtype, [rdata.to_text() for rdata in answers]
        except Exception:
            return rtype, []

    tasks = [fetch_record(rt) for rt in record_types]
    batch_results = await asyncio.gather(*tasks)
    
    for rtype, data in batch_results:
        results[rtype] = data
        
    return {
        "domain": domain,
        "records": results
    }

@router.get("/shodan")
async def shodan_internetdb(ip: str = Query(..., description="IP to scan via InternetDB")):
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=5.0)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"ip": ip, "message": "No data found in InternetDB"}
            else:
                return {"error": f"InternetDB returned {resp.status_code}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/mac")
async def mac_lookup(mac: str = Query(..., description="MAC Address")):
    try:
        # url encode mac just in case
        safe_mac = urllib.parse.quote(mac)
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"https://api.macvendors.com/{safe_mac}", timeout=5.0)
            if resp.status_code == 200:
                return {"mac": mac, "vendor": resp.text}
            elif resp.status_code == 404:
                return {"mac": mac, "vendor": "Unknown"}
            else:
                return {"error": f"MAC API returned {resp.status_code}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network-range")
async def network_range(cidr: str = Query(..., description="CIDR block e.g. 192.168.1.0/24")):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        num_addresses = network.num_addresses
        
        # Sample first 3 and last 3 to check Shodan InternetDB
        hosts = list(network.hosts())
        samples = []
        if len(hosts) <= 6:
            samples = hosts
        else:
            samples = hosts[:3] + hosts[-3:]
            
        async def check_ip(ip_obj):
            ip_str = str(ip_obj)
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"https://internetdb.shodan.io/{ip_str}", timeout=2.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        return {"ip": ip_str, "ports": data.get("ports", []), "hostnames": data.get("hostnames", [])}
            except Exception:
                pass
            return {"ip": ip_str, "ports": [], "hostnames": []}
            
        tasks = [check_ip(ip) for ip in samples]
        sample_results = await asyncio.gather(*tasks)

        return {
            "cidr": cidr,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "num_addresses": num_addresses,
            "netmask": str(network.netmask),
            "version": network.version,
            "sample_shodan_checks": sample_results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/http-headers")
async def analyze_http_headers(url: str = Query(..., description="URL to analyze")):
    if not url.startswith("http"):
        url = "https://" + url
        
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(url, timeout=10.0, follow_redirects=True)
            
            headers = dict(resp.headers)
            security_headers = {
                "Strict-Transport-Security": headers.get("strict-transport-security"),
                "Content-Security-Policy": headers.get("content-security-policy"),
                "X-Frame-Options": headers.get("x-frame-options"),
                "X-Content-Type-Options": headers.get("x-content-type-options"),
                "Server": headers.get("server"),
                "X-Powered-By": headers.get("x-powered-by")
            }
            
            # Grade basic presence
            score = 100
            missing = []
            for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                if not security_headers[h]:
                    score -= 20
                    missing.append(h)
                    
            if security_headers["Server"] or security_headers["X-Powered-By"]:
                score -= 10 # Information disclosure
                
            return {
                "url": url,
                "final_url": str(resp.url),
                "status_code": resp.status_code,
                "score": max(0, score),
                "missing_headers": missing,
                "security_headers": security_headers,
                "all_headers": headers
            }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
