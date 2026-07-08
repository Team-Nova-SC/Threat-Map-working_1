import logging
import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models.database import get_db, Watchlist, Alert, Scan
from models.schemas import WatchlistResponse, WatchlistCreate, WatchlistUpdate, AlertResponse, AlertUpdate
from services.virustotal import virustotal_service
from services.abuseipdb import abuse_ipdb_service
from services.greynoise import greynoise_service
from services.risk_engine import risk_engine
from services.webhook_service import fire_webhook
import asyncio

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/watchlist", tags=["Watchlist & Alerts"])

@router.get("/", response_model=List[WatchlistResponse])
def get_watchlist(db: Session = Depends(get_db)):
    return db.query(Watchlist).order_by(Watchlist.added_at.desc()).all()

@router.post("/", response_model=WatchlistResponse)
def add_to_watchlist(payload: WatchlistCreate, db: Session = Depends(get_db)):
    indicator = payload.indicator.strip()
    ind_type = payload.type.strip().lower()

    if not indicator:
        raise HTTPException(status_code=400, detail="Indicator cannot be empty.")

    # Check if already exists
    existing = db.query(Watchlist).filter(Watchlist.indicator == indicator).first()
    if existing:
        return existing

    # Create new item
    item = Watchlist(
        indicator=indicator,
        type=ind_type,
        notes=payload.notes,
        custom_threshold=payload.custom_threshold,
        tags=payload.tags,
        schedule_frequency=payload.schedule_frequency,
        webhook_url=payload.webhook_url,
        last_risk_score=0
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

@router.patch("/{indicator}", response_model=WatchlistResponse)
def update_watchlist_item(indicator: str, payload: WatchlistUpdate, db: Session = Depends(get_db)):
    item = db.query(Watchlist).filter(Watchlist.indicator == indicator).first()
    if not item:
        raise HTTPException(status_code=404, detail="Indicator not found in watchlist.")
    
    if payload.notes is not None:
        item.notes = payload.notes
    if payload.custom_threshold is not None:
        item.custom_threshold = payload.custom_threshold
    if payload.tags is not None:
        item.tags = payload.tags
    if payload.schedule_frequency is not None:
        item.schedule_frequency = payload.schedule_frequency
    if payload.webhook_url is not None:
        item.webhook_url = payload.webhook_url

    db.commit()
    db.refresh(item)
    return item

@router.delete("/{indicator}", status_code=status.HTTP_204_NO_CONTENT)
def remove_from_watchlist(indicator: str, db: Session = Depends(get_db)):
    item = db.query(Watchlist).filter(Watchlist.indicator == indicator).first()
    if not item:
        raise HTTPException(status_code=404, detail="Indicator not found in watchlist.")
    
    db.delete(item)
    db.commit()
    return None


@router.post("/scan-all")
async def scan_watchlist_items(db: Session = Depends(get_db)):
    """
    Manually triggers a scanning job across the watchlist.
    Compares risk scores against database baselines and triggers system alerts if risk changes.
    """
    items = db.query(Watchlist).all()
    updates = []
    
    for item in items:
        try:
            # Query simplified analytics to calculate new risk
            # For speed, query VirusTotal and calculate
            vt_res = await virustotal_service.get_indicator_report(item.indicator, item.type)
            
            abuse_res = None
            gn_res = None
            if item.type == "ip":
                abuse_res = await abuse_ipdb_service.check_ip(item.indicator)
                gn_res = await greynoise_service.check_ip(item.indicator)
                
            risk_res = risk_engine.calculate_risk(
                indicator_type=item.type,
                vt_data=vt_res,
                abuse_data=abuse_res,
                greynoise_data=gn_res
            )
            
            new_score = risk_res["score"]
            old_score = item.last_risk_score
            
            # Check for variance
            if new_score != old_score:
                variance = new_score - old_score
                alert_type = "RISK_INCREASE" if variance > 0 else "RISK_DECREASE"
                title = f"Risk Score Shift for {item.indicator}"
                message = f"Indicator threat score shifted from {old_score} to {new_score} ({'+' if variance > 0 else ''}{variance} pts)."
                
                # If high risk variance or critical threshold crossed, add alert
                if abs(variance) >= 5 or new_score >= 70:
                    alert = Alert(
                        indicator=item.indicator,
                        alert_type=alert_type,
                        title=title,
                        message=message,
                        risk_score=new_score
                    )
                    db.add(alert)

                # Fire Webhook if threshold met
                if item.webhook_url and item.custom_threshold and new_score >= item.custom_threshold:
                    asyncio.create_task(fire_webhook(item.webhook_url, {
                        "indicator": item.indicator,
                        "old_score": old_score,
                        "new_score": new_score,
                        "alert_type": alert_type,
                        "message": message
                    }))

                item.last_risk_score = new_score

            item.last_scanned_at = datetime.datetime.utcnow()
            db.add(item)
            updates.append({"indicator": item.indicator, "old_score": old_score, "new_score": new_score})
            
        except Exception as e:
            logger.error(f"Error scanning watchlist item {item.indicator}: {e}")

    db.commit()
    return {"status": "success", "scanned_count": len(items), "updates": updates}


# Alert System endpoints
@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).filter(Alert.is_dismissed == False).order_by(Alert.created_at.desc()).all()

@router.put("/alerts/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    
    alert.is_dismissed = payload.is_dismissed
    db.commit()
    db.refresh(alert)
    return alert
