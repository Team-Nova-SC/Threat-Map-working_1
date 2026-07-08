import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

async def fire_webhook(url: str, payload: dict):
    if not url:
        return
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, json=payload, timeout=5.0)
            logger.info(f"Webhook fired to {url} - Status: {resp.status_code}")
    except Exception as e:
        logger.error(f"Failed to fire webhook to {url}: {e}")
