import uuid
import json
import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.cache import cache_service
from models.database import get_db, Scan
from models.schemas import ScanResponse, ScanCreate
from services.virustotal import virustotal_service
from services.urlscan import urlscan_service
from services.alienvault import alienvault_service
from services.osint import osint_service
from services.risk_engine import risk_engine
from services.ai_service import ai_service
from services.whoisjson import whoisjson_service
from services.domainscan import domainscan_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["Domain Analysis"])

@router.post("/domain", response_model=ScanResponse)
async def analyze_domain(payload: ScanCreate, db: Session = Depends(get_db)):
    try:
        domain = payload.indicator.strip()
        if not domain:
            raise HTTPException(status_code=400, detail="Domain indicator cannot be empty.")

        # 1. Cache lookup
        cache_key = f"scan:domain:{domain}"
        if not payload.refresh:
            cached_data = cache_service.get(cache_key)
            if cached_data:
                try:
                    logger.info(f"Cache hit for domain: {domain}")
                    return ScanResponse(**json.loads(cached_data))
                except Exception:
                    pass

        # 2. Parallel scans
        try:
            vt_task = asyncio.wait_for(virustotal_service.get_domain_report(domain), timeout=30.0)
            urlscan_task = asyncio.wait_for(urlscan_service.search_indicator(domain, "domain"), timeout=8.0)
            otx_task = asyncio.wait_for(alienvault_service.get_indicator_report(domain, "domain"), timeout=8.0)

            # Local OSINT tasks
            dns_task = asyncio.wait_for(osint_service.get_dns_records(domain), timeout=30.0)
            whois_task = asyncio.wait_for(osint_service.get_whois_data(domain), timeout=30.0)
            ssl_task = asyncio.wait_for(osint_service.get_ssl_metadata(domain), timeout=30.0)
            
            # Advanced Analytical Tasks
            whoisjson_task = asyncio.wait_for(whoisjson_service.get_domain_data(domain), timeout=30.0)
            domainscan_task = asyncio.wait_for(domainscan_service.get_scan_data(domain), timeout=30.0)

            vt_res, urlscan_res, otx_res, dns_res, whois_res, ssl_res, whoisjson_res, domainscan_res = await asyncio.gather(
                vt_task, urlscan_task, otx_task, dns_task, whois_task, ssl_task, whoisjson_task, domainscan_task,
                return_exceptions=True
            )

            vt_res = vt_res if not isinstance(vt_res, Exception) else virustotal_service._get_fallback_data()
            urlscan_res = urlscan_res if not isinstance(urlscan_res, Exception) else urlscan_service._get_fallback_data(domain)
            otx_res = otx_res if not isinstance(otx_res, Exception) else alienvault_service._get_fallback_data(domain)
            dns_res = dns_res if not isinstance(dns_res, Exception) else {"A": [], "MX": [], "TXT": [], "NS": []}
            whois_res = whois_res if not isinstance(whois_res, Exception) else {"registrar": "Unknown", "creation_date": "", "expiration_date": "", "registrant_org": ""}
            ssl_res = ssl_res if not isinstance(ssl_res, Exception) else {"issuer": "Unknown", "subject": domain, "valid_from": "", "valid_to": "", "serial_number": "", "version": 3}
            whoisjson_res = whoisjson_res if not isinstance(whoisjson_res, Exception) else {}
            domainscan_res = domainscan_res if not isinstance(domainscan_res, Exception) else {}

        except Exception as e:
            logger.error(f"[domain] Parallel lookups failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed resolving DNS configuration."
            )

        # 3. Calculate Risk
        risk_results = risk_engine.calculate_risk(
            indicator_type="domain",
            vt_data=vt_res
        )
        risk_score = risk_results["score"]
        risk_level = risk_results["level"]

        # Historical WHOIS Comparison
        whois_changes = []
        try:
            last_scan = db.query(Scan).filter(
                Scan.indicator == domain, 
                Scan.type == "domain"
            ).order_by(Scan.created_at.desc()).first()

            if last_scan and last_scan.raw_data and "whois_records" in last_scan.raw_data:
                old_whois = last_scan.raw_data["whois_records"]
                
                # Check Registrar changes
                old_reg = old_whois.get("registrar", "")
                new_reg = whois_res.get("registrar", "")
                if old_reg and new_reg and str(old_reg).lower() != str(new_reg).lower():
                    whois_changes.append(f"Registrar changed from {old_reg} to {new_reg}")
                
                # Check Creation Date changes
                old_create = old_whois.get("creation_date", "")
                new_create = whois_res.get("creation_date", "")
                if old_create and new_create and str(old_create) != str(new_create):
                    whois_changes.append(f"Creation date changed (domain re-registered?). Was {old_create}, now {new_create}")
        except Exception as e:
            logger.warning(f"[domain] WHOIS comparison failed: {e}")

        raw_aggregation = {
            "virustotal": vt_res,
            "urlscan": urlscan_res,
            "alienvault_otx": otx_res,
            "dns_records": dns_res,
            "whois_records": whois_res,
            "ssl_metadata": ssl_res,
            "whoisjson": whoisjson_res,
            "domainscan": domainscan_res,
            "historical_whois_changes": whois_changes,
            "risk_confidence": {"score": risk_results.get("confidence_score", 0), "level": risk_results.get("confidence_level", "LOW")}
        }

        # 4. Request AI brief — isolated, never crashes the route
        try:
            ai_brief = await ai_service.generate_threat_brief(
                indicator=domain,
                ind_type="domain",
                risk_score=risk_score,
                raw_data=raw_aggregation
            )
        except Exception:
            logger.error("[domain] AI brief failed unexpectedly; using inline fallback.", exc_info=True)
            ai_brief = {
                "summary": "AI unavailable", "threat_category": "unknown",
                "confidence": "low", "recommendations": [], "playbook": [], "mitre_tactics": []
            }

        full_raw_data = {**raw_aggregation, "ai_insights": ai_brief}

        # 5. DB Logging
        scan_id = str(uuid.uuid4())
        db_scan = Scan(
            id=scan_id,
            indicator=domain,
            type="domain",
            risk_score=risk_score,
            risk_level=risk_level,
            summary=ai_brief.get("summary", ""),
            raw_data=full_raw_data
        )

        try:
            db.add(db_scan)
            db.commit()
            db.refresh(db_scan)
        except Exception as dbe:
            db.rollback()
            logger.error(f"[domain] Failed to record domain scan: {dbe}")

        response = ScanResponse.model_validate(db_scan)

        # 6. Cache output
        try:
            cache_service.set(cache_key, json.dumps(response.model_dump(mode="json")), expire=3600)
        except Exception as ce:
            logger.error(f"[domain] Failed to cache domain analysis: {ce}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error("[domain] Scan crashed — FULL TRACEBACK:", exc_info=True)
        return {"error": str(e), "risk_score": 0, "risk_level": "UNKNOWN"}
