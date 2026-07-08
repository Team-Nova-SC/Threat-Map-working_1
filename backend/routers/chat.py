from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from typing import List, Dict, Any
from services.groq_service import chat_with_ai, chat_with_image
import base64

router = APIRouter()

class ChatRequest(BaseModel):
    message: str
    history: List[Dict[str, Any]] = []
    model: str = "openai/gpt-oss-120b"

class ChatResponse(BaseModel):
    response: str

@router.post("/chat", response_model=ChatResponse)
async def ai_chat_endpoint(req: ChatRequest):
    try:
        response_text = await chat_with_ai(req.message, req.history, req.model)
        return ChatResponse(response=response_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/chat/image", response_model=ChatResponse)
async def ai_chat_image_endpoint(message: str = Form(...), file: UploadFile = File(...)):
    try:
        contents = await file.read()
        base64_image = base64.b64encode(contents).decode("utf-8")
        response_text = await chat_with_image(message, base64_image)
        return ChatResponse(response=response_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
