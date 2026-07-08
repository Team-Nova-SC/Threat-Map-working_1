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
from services.risk_engine import risk_engine
from services.ai_service import ai_service
from services.whoisjson import whoisjson_service
from services.domainscan import domainscan_service
import urllib.parse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["URL Analysis"])

@router.post("/url", response_model=ScanResponse)
async def analyze_url(payload: ScanCreate, db: Session = Depends(get_db)):
    try:
        target_url = payload.indicator.strip()

        if not target_url:
            raise HTTPException(status_code=400, detail="URL target value cannot be empty.")

        # 1. Check cache
        cache_key = f"scan:url:{target_url}"
        if not payload.refresh:
            cached_data = cache_service.get(cache_key)
            if cached_data:
                try:
                    logger.info(f"Cache hit for URL: {target_url}")
                    return ScanResponse(**json.loads(cached_data))
                except Exception:
                    pass

        # 2. Parallel queries
        try:
            domain_part = urllib.parse.urlparse(target_url).hostname or target_url
            
            vt_task = asyncio.wait_for(virustotal_service.get_url_report(target_url), timeout=30.0)
            urlscan_task = asyncio.wait_for(urlscan_service.search_indicator(target_url, "url"), timeout=8.0)
            otx_task = asyncio.wait_for(alienvault_service.get_indicator_report(target_url, "url"), timeout=8.0)
            whoisjson_task = asyncio.wait_for(whoisjson_service.get_domain_data(domain_part), timeout=30.0)
            domainscan_task = asyncio.wait_for(domainscan_service.get_scan_data(target_url), timeout=30.0)

            vt_res, urlscan_res, otx_res, whoisjson_res, domainscan_res = await asyncio.gather(
                vt_task, urlscan_task, otx_task, whoisjson_task, domainscan_task,
                return_exceptions=True
            )

            vt_res = vt_res if not isinstance(vt_res, Exception) else virustotal_service._get_fallback_data()
            urlscan_res = urlscan_res if not isinstance(urlscan_res, Exception) else urlscan_service._get_fallback_data(target_url)
            otx_res = otx_res if not isinstance(otx_res, Exception) else alienvault_service._get_fallback_data(target_url)
            whoisjson_res = whoisjson_res if not isinstance(whoisjson_res, Exception) else {}
            domainscan_res = domainscan_res if not isinstance(domainscan_res, Exception) else {}

        except Exception as e:
            logger.error(f"[url] Parallel lookups failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed querying web analytics."
            )

        # 3. Calculate Risk
        risk_results = risk_engine.calculate_risk(
            indicator_type="url",
            vt_data=vt_res
        )
        risk_score = risk_results["score"]
        risk_level = risk_results["level"]

        raw_aggregation = {
            "virustotal": vt_res,
            "urlscan": urlscan_res,
            "alienvault_otx": otx_res,
            "whoisjson": whoisjson_res,
            "domainscan": domainscan_res,
            "risk_confidence": {"score": risk_results.get("confidence_score", 0), "level": risk_results.get("confidence_level", "LOW")}
        }

        # Phishing Kit Fingerprinting (DOM/Header Analysis)
        phishing_kit_matches = []
        try:
            import httpx
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.get(target_url, timeout=5.0, follow_redirects=True)
                body = resp.text.lower()
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                
                if "x-mailer" in headers and "phish" in headers["x-mailer"]:
                    phishing_kit_matches.append("Generic Phishing Mailer")
                if "paypal" in body and "login" in body and "paypal.com" not in target_url.lower():
                    phishing_kit_matches.append("PayPal Credential Harvester")
                if "microsoft" in body and "sign in" in body and "microsoft.com" not in target_url.lower():
                    phishing_kit_matches.append("Microsoft 365 Phishing Kit")
                if 'name="generator"' in body and "mura cms" in body:
                    phishing_kit_matches.append("Mura CMS (Potentially Compromised)")
        except Exception as e:
            logger.warning(f"[url] Phishing Kit Check failed: {e}")

        raw_aggregation["phishing_kit_matches"] = phishing_kit_matches

        # 4. Generate AI Threat Brief — isolated, never crashes the route
        try:
            ai_brief = await ai_service.generate_threat_brief(
                indicator=target_url,
                ind_type="url",
                risk_score=risk_score,
                raw_data=raw_aggregation
            )
        except Exception:
            logger.error("[url] AI brief failed unexpectedly; using inline fallback.", exc_info=True)
            ai_brief = {
                "summary": "AI unavailable", "threat_category": "unknown",
                "confidence": "low", "recommendations": [], "playbook": [], "mitre_tactics": []
            }

        full_raw_data = {**raw_aggregation, "ai_insights": ai_brief}

        # 5. DB Logging
        scan_id = str(uuid.uuid4())
        db_scan = Scan(
            id=scan_id,
            indicator=target_url,
            type="url",
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
            logger.error(f"[url] Failed storing scan data: {dbe}")

        response = ScanResponse.model_validate(db_scan)

        # 6. Cache output
        try:
            cache_service.set(cache_key, json.dumps(response.model_dump(mode="json")), expire=3600)
        except Exception as ce:
            logger.error(f"[url] Failed to cache URL result: {ce}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error("[url] Scan crashed — FULL TRACEBACK:", exc_info=True)
        return {"error": str(e), "risk_score": 0, "risk_level": "UNKNOWN"}
