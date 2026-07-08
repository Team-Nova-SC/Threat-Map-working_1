import uuid
import json
import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import settings
from core.cache import cache_service
from models.database import get_db, Scan
from models.schemas import ScanResponse, ScanCreate
from services.virustotal import virustotal_service
from services.abuseipdb import abuse_ipdb_service
from services.ipinfo import ipinfo_service
from services.greynoise import greynoise_service
from services.alienvault import alienvault_service
from services.risk_engine import risk_engine
from services.ai_service import ai_service
from services.whoisjson import whoisjson_service
from services.domainscan import domainscan_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["IP Analysis"])

@router.post("/ip", response_model=ScanResponse)
async def analyze_ip(payload: ScanCreate, db: Session = Depends(get_db)):
    try:
        ip = payload.indicator.strip()

        # Simple validation for IP structure
        if not ip:
            raise HTTPException(status_code=400, detail="IP indicator value cannot be empty.")

        # 1. Check cache (skip if refresh=True or if cached data has stale fallback ipinfo)
        cache_key = f"scan:ip:{ip}"
        if not payload.refresh:
            cached_data = cache_service.get(cache_key)
            if cached_data:
                try:
                    parsed = json.loads(cached_data)
                    # Invalidate cache if ipinfo is fallback (Ashburn/Virginia placeholder)
                    ipinfo_in_cache = parsed.get("raw_data", {}).get("ipinfo", {})
                    if ipinfo_in_cache.get("status") == "fallback":
                        logger.info(f"Stale fallback ipinfo in cache for {ip}, forcing fresh scan.")
                        cache_service.delete(cache_key)
                    else:
                        logger.info(f"Cache hit for IP: {ip}")
                        return ScanResponse(**parsed)
                except Exception:
                    pass

        # 2. Parallel Queries
        try:
            vt_task = asyncio.wait_for(virustotal_service.get_ip_report(ip), timeout=30.0)
            abuse_task = asyncio.wait_for(abuse_ipdb_service.check_ip(ip), timeout=30.0)
            ipinfo_task = asyncio.wait_for(ipinfo_service.get_ip_info(ip), timeout=30.0)
            greynoise_task = asyncio.wait_for(greynoise_service.check_ip(ip), timeout=30.0)
            otx_task = asyncio.wait_for(alienvault_service.get_indicator_report(ip, "ip"), timeout=8.0)
            whoisjson_task = asyncio.wait_for(whoisjson_service.get_domain_data(ip), timeout=30.0)
            domainscan_task = asyncio.wait_for(domainscan_service.get_scan_data(ip), timeout=30.0)

            vt_res, abuse_res, ipinfo_res, gn_res, otx_res, whoisjson_res, domainscan_res = await asyncio.gather(
                vt_task, abuse_task, ipinfo_task, greynoise_task, otx_task, whoisjson_task, domainscan_task,
                return_exceptions=True
            )

            # Handle potential exceptions during parallel queries
            vt_res = vt_res if isinstance(vt_res, dict) else virustotal_service._get_fallback_data()
            abuse_res = abuse_res if isinstance(abuse_res, dict) else abuse_ipdb_service._get_fallback_data(ip)
            ipinfo_res = ipinfo_res if isinstance(ipinfo_res, dict) else ipinfo_service._get_fallback_data(ip)
            gn_res = gn_res if isinstance(gn_res, dict) else greynoise_service._get_fallback_data(ip)
            otx_res = otx_res if isinstance(otx_res, dict) else alienvault_service._get_fallback_data(ip)
            whoisjson_res = whoisjson_res if not isinstance(whoisjson_res, Exception) else {}
            domainscan_res = domainscan_res if not isinstance(domainscan_res, Exception) else {}

            logger.info(f"IPinfo for {ip}: {ipinfo_res.get('city')}, {ipinfo_res.get('country')} (status={ipinfo_res.get('status')})") 

        except Exception as e:
            logger.error(f"[ip] Parallel lookups failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed gathering threat vectors: {str(e)}"
            )

        # 3. Calculate Risk
        risk_results = risk_engine.calculate_risk(
            indicator_type="ip",
            vt_data=vt_res,
            abuse_data=abuse_res,
            greynoise_data=gn_res
        )
        risk_score = risk_results["score"]
        risk_level = risk_results["level"]

        # 4. Generate AI brief — isolated, never crashes the route
        raw_aggregation = {
            "virustotal": vt_res,
            "abuseipdb": abuse_res,
            "greynoise": gn_res,
            "ipinfo": ipinfo_res,
            "alienvault_otx": otx_res,
            "whoisjson": whoisjson_res,
            "domainscan": domainscan_res,
            "risk_confidence": {"score": risk_results.get("confidence_score", 0), "level": risk_results.get("confidence_level", "LOW")}
        }

        try:
            ai_brief = await ai_service.generate_threat_brief(
                indicator=ip,
                ind_type="ip",
                risk_score=risk_score,
                raw_data=raw_aggregation
            )
        except Exception:
            logger.error("[ip] AI brief generation failed unexpectedly; using inline fallback.", exc_info=True)
            ai_brief = {"summary": "AI unavailable", "threat_category": "unknown", "confidence": "low", "recommendations": [], "playbook": [], "mitre_tactics": []}

        # Compile the final raw data bundle
        full_raw_data = {**raw_aggregation, "ai_insights": ai_brief}

        # 5. Write to Database
        scan_id = str(uuid.uuid4())
        db_scan = Scan(
            id=scan_id,
            indicator=ip,
            type="ip",
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
            logger.error(f"[ip] Failed storing scan history: {dbe}")

        # Create response model
        response = ScanResponse.model_validate(db_scan)

        # 6. Cache output (1 hour)
        try:
            cache_service.set(cache_key, json.dumps(response.model_dump(mode="json")), expire=3600)
        except Exception as ce:
            logger.error(f"[ip] Failed caching response: {ce}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ip] Scan crashed — FULL TRACEBACK:", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )
