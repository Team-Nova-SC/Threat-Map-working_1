from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session
from typing import List
from models.database import get_db, ThreatActor
from services.mitre_service import sync_threat_actors
from pydantic import BaseModel
import datetime

router = APIRouter(prefix="/threat-actors", tags=["Threat Actors"])

class ThreatActorResponse(BaseModel):
    id: str
    name: str
    aliases: str | None
    country: str | None
    description: str | None
    threat_level: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

@router.get("/", response_model=List[ThreatActorResponse])
def get_threat_actors(db: Session = Depends(get_db)):
    actors = db.query(ThreatActor).order_by(ThreatActor.name).all()
    return actors

@router.post("/sync")
async def trigger_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(sync_threat_actors)
    return {"message": "MITRE ATT&CK sync started in background."}
