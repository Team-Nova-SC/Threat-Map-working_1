from fastapi import APIRouter, HTTPException, Path
from typing import Dict, Any
from pydantic import BaseModel
import logging
from services.spiderfoot_service import spiderfoot_service

router = APIRouter(prefix="/spiderfoot", tags=["Deep OSINT"])
logger = logging.getLogger(__name__)

class ScanRequest(BaseModel):
    target: str

@router.post("/scan")
async def start_spiderfoot_scan(request: ScanRequest):
    """Starts a new SpiderFoot deep OSINT scan."""
    result = await spiderfoot_service.start_scan(request.target)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
    return result

@router.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str = Path(...)):
    """Check the status of a running scan."""
    return await spiderfoot_service.get_scan_status(scan_id)

@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str = Path(...)):
    """Fetch categorized deep OSINT results for a scan."""
    return await spiderfoot_service.get_scan_results(scan_id)
