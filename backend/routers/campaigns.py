import uuid
import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from models.database import get_db, Campaign, CampaignIOC, Scan

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class CampaignCreate(BaseModel):
    name: str
    description: Optional[str] = None

class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class CampaignIOCCreate(BaseModel):
    scan_id: str

class CampaignIOCResponse(BaseModel):
    id: int
    campaign_id: str
    scan_id: str
    added_at: datetime.datetime
    # Enriched from Scan join
    indicator: Optional[str] = None
    type: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None

    class Config:
        from_attributes = True

class CampaignResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime.datetime
    updated_at: datetime.datetime
    ioc_count: int = 0

    class Config:
        from_attributes = True


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[CampaignResponse])
def list_campaigns(db: Session = Depends(get_db)):
    campaigns = db.query(Campaign).order_by(Campaign.updated_at.desc()).all()
    result = []
    for c in campaigns:
        count = db.query(CampaignIOC).filter(CampaignIOC.campaign_id == c.id).count()
        result.append(CampaignResponse(
            id=c.id, name=c.name, description=c.description,
            created_at=c.created_at, updated_at=c.updated_at, ioc_count=count
        ))
    return result


@router.post("/", response_model=CampaignResponse)
def create_campaign(payload: CampaignCreate, db: Session = Depends(get_db)):
    camp = Campaign(
        id=str(uuid.uuid4()),
        name=payload.name,
        description=payload.description,
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow(),
    )
    db.add(camp)
    db.commit()
    db.refresh(camp)
    return CampaignResponse(id=camp.id, name=camp.name, description=camp.description,
                            created_at=camp.created_at, updated_at=camp.updated_at, ioc_count=0)


@router.get("/{campaign_id}")
def get_campaign(campaign_id: str, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    iocs = db.query(CampaignIOC).filter(CampaignIOC.campaign_id == campaign_id).all()
    enriched_iocs = []
    for ioc in iocs:
        scan = db.query(Scan).filter(Scan.id == ioc.scan_id).first()
        enriched_iocs.append({
            "id": ioc.id,
            "campaign_id": ioc.campaign_id,
            "scan_id": ioc.scan_id,
            "added_at": ioc.added_at,
            "indicator": scan.indicator if scan else "Unknown",
            "type": scan.type if scan else "unknown",
            "risk_score": scan.risk_score if scan else 0,
            "risk_level": scan.risk_level if scan else "LOW",
        })
    
    return {
        "id": camp.id, "name": camp.name, "description": camp.description,
        "created_at": camp.created_at, "updated_at": camp.updated_at,
        "iocs": enriched_iocs
    }


@router.patch("/{campaign_id}", response_model=CampaignResponse)
def update_campaign(campaign_id: str, payload: CampaignUpdate, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if payload.name is not None:
        camp.name = payload.name
    if payload.description is not None:
        camp.description = payload.description
    camp.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(camp)
    count = db.query(CampaignIOC).filter(CampaignIOC.campaign_id == campaign_id).count()
    return CampaignResponse(id=camp.id, name=camp.name, description=camp.description,
                            created_at=camp.created_at, updated_at=camp.updated_at, ioc_count=count)


@router.delete("/{campaign_id}")
def delete_campaign(campaign_id: str, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    db.query(CampaignIOC).filter(CampaignIOC.campaign_id == campaign_id).delete()
    db.delete(camp)
    db.commit()
    return {"message": "Campaign deleted successfully"}


@router.post("/{campaign_id}/iocs")
def add_ioc_to_campaign(campaign_id: str, payload: CampaignIOCCreate, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    existing = db.query(CampaignIOC).filter(
        CampaignIOC.campaign_id == campaign_id,
        CampaignIOC.scan_id == payload.scan_id
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="IOC already in this campaign")
    
    ioc = CampaignIOC(
        campaign_id=campaign_id,
        scan_id=payload.scan_id,
        added_at=datetime.datetime.utcnow()
    )
    db.add(ioc)
    camp.updated_at = datetime.datetime.utcnow()
    db.commit()
    return {"message": "IOC added to campaign", "scan_id": payload.scan_id}


@router.delete("/{campaign_id}/iocs/{scan_id}")
def remove_ioc_from_campaign(campaign_id: str, scan_id: str, db: Session = Depends(get_db)):
    ioc = db.query(CampaignIOC).filter(
        CampaignIOC.campaign_id == campaign_id,
        CampaignIOC.scan_id == scan_id
    ).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not in this campaign")
    db.delete(ioc)
    db.commit()
    return {"message": "IOC removed from campaign"}
