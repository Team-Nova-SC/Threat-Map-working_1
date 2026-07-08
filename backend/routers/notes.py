import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from models.database import get_db, CommunityNote

router = APIRouter(prefix="/notes", tags=["Community Notes"])


class NoteCreate(BaseModel):
    indicator: str
    text: str
    author: Optional[str] = "Anonymous"


class NoteResponse(BaseModel):
    id: int
    indicator: str
    author: str
    text: str
    upvotes: int
    created_at: datetime.datetime

    class Config:
        from_attributes = True


@router.get("/{indicator}", response_model=List[NoteResponse])
def get_notes(indicator: str, db: Session = Depends(get_db)):
    notes = (
        db.query(CommunityNote)
        .filter(CommunityNote.indicator == indicator)
        .order_by(CommunityNote.upvotes.desc(), CommunityNote.created_at.desc())
        .all()
    )
    return notes


@router.post("/", response_model=NoteResponse)
def create_note(payload: NoteCreate, db: Session = Depends(get_db)):
    if not payload.text.strip():
        raise HTTPException(status_code=400, detail="Note text cannot be empty.")
    if len(payload.text) > 1000:
        raise HTTPException(status_code=400, detail="Note text is too long (max 1000 chars).")
    
    note = CommunityNote(
        indicator=payload.indicator,
        author=payload.author or "Anonymous",
        text=payload.text.strip(),
        upvotes=0,
        created_at=datetime.datetime.utcnow(),
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.post("/{note_id}/upvote", response_model=NoteResponse)
def upvote_note(note_id: int, db: Session = Depends(get_db)):
    note = db.query(CommunityNote).filter(CommunityNote.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found.")
    note.upvotes += 1
    db.commit()
    db.refresh(note)
    return note


@router.delete("/{note_id}")
def delete_note(note_id: int, db: Session = Depends(get_db)):
    note = db.query(CommunityNote).filter(CommunityNote.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found.")
    db.delete(note)
    db.commit()
    return {"message": "Note deleted"}
