import uuid
import json
import asyncio
import logging
import re
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.cache import cache_service
from models.database import get_db, Scan
from models.schemas import ScanResponse, ScanCreate
from services.virustotal import virustotal_service
from services.alienvault import alienvault_service
from services.risk_engine import risk_engine
from services.ai_service import ai_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["File Hash Analysis"])

@router.post("/hash", response_model=ScanResponse)
async def analyze_hash(payload: ScanCreate, db: Session = Depends(get_db)):
    try:
        file_hash = payload.indicator.strip().lower()

        # MD5, SHA-1, SHA-256 validation pattern
        if not re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", file_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file hash format. Must be MD5, SHA-1 or SHA-256 hex string."
            )

        # 1. Cache Check
        cache_key = f"scan:hash:{file_hash}"
        if not payload.refresh:
            cached_data = cache_service.get(cache_key)
            if cached_data:
                try:
                    logger.info(f"Cache hit for hash: {file_hash}")
                    return ScanResponse(**json.loads(cached_data))
                except Exception:
                    pass

        # 2. Parallel scans (8 s per task)
        try:
            vt_task = asyncio.wait_for(virustotal_service.get_hash_report(file_hash), timeout=30.0)
            otx_task = asyncio.wait_for(alienvault_service.get_indicator_report(file_hash, "hash"), timeout=8.0)

            vt_res, otx_res = await asyncio.gather(
                vt_task, otx_task,
                return_exceptions=True
            )

            vt_res = vt_res if not isinstance(vt_res, Exception) else virustotal_service._get_fallback_data()
            otx_res = otx_res if not isinstance(otx_res, Exception) else alienvault_service._get_fallback_data(file_hash)

        except Exception as e:
            logger.error(f"[hash] Parallel lookups failed: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed executing indicator lookup."
            )

        # 3. Calculate Risk
        risk_results = risk_engine.calculate_risk(
            indicator_type="hash",
            vt_data=vt_res
        )
        risk_score = risk_results["score"]
        risk_level = risk_results["level"]

        raw_aggregation = {
            "virustotal": vt_res,
            "alienvault_otx": otx_res,
            "risk_confidence": {"score": risk_results.get("confidence_score", 0), "level": risk_results.get("confidence_level", "LOW")}
        }

        # 4. Generate AI Threat Brief — isolated, never crashes the route
        try:
            ai_brief = await ai_service.generate_threat_brief(
                indicator=file_hash,
                ind_type="hash",
                risk_score=risk_score,
                raw_data=raw_aggregation
            )
        except Exception:
            logger.error("[hash] AI brief failed unexpectedly; using inline fallback.", exc_info=True)
            ai_brief = {
                "summary": "AI unavailable", "threat_category": "unknown",
                "confidence": "low", "recommendations": [], "playbook": [], "mitre_tactics": []
            }

        full_raw_data = {**raw_aggregation, "ai_insights": ai_brief}

        # 5. DB Logging
        scan_id = str(uuid.uuid4())
        db_scan = Scan(
            id=scan_id,
            indicator=file_hash,
            type="hash",
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
            logger.error(f"[hash] Failed to record hash scan: {dbe}")

        response = ScanResponse.model_validate(db_scan)

        # 6. Cache output
        try:
            cache_service.set(cache_key, json.dumps(response.model_dump(mode="json")), expire=3600)
        except Exception as ce:
            logger.error(f"[hash] Failed to cache hash scan: {ce}")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error("[hash] Scan crashed — FULL TRACEBACK:", exc_info=True)
        return {"error": str(e), "risk_score": 0, "risk_level": "UNKNOWN"}
