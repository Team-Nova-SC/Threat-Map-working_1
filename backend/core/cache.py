import time
import logging
from typing import Optional
import redis
from core.config import settings

logger = logging.getLogger(__name__)

# ─── Redis availability flag ──────────────────────────────────────────────────
# Redis is fully optional. If unreachable, we fall back to an in-process
# dictionary store. All cache operations below check REDIS_AVAILABLE first.
REDIS_AVAILABLE = False
_redis_client = None

if settings.REDIS_URL:
    try:
        _redis_client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=3.0,
            socket_connect_timeout=3.0,
        )
        _redis_client.ping()
        REDIS_AVAILABLE = True
        logger.info("Connected to Redis successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}. Running without cache persistence.")
        _redis_client = None
else:
    logger.warning("No REDIS_URL configured. Running with in-memory cache only.")


# ─── In-memory fallback ───────────────────────────────────────────────────────
class _MemoryStore:
    def __init__(self):
        self._store: dict = {}
        self._expires: dict = {}

    def get(self, key: str) -> Optional[str]:
        now = time.time()
        if key in self._store:
            exp = self._expires.get(key, 0)
            if exp == 0 or now < exp:
                return self._store[key]
            else:
                self.delete(key)
        return None

    def set(self, key: str, value: str, expire: int = 3600) -> bool:
        self._store[key] = value
        self._expires[key] = (time.time() + expire) if expire > 0 else 0
        return True

    def delete(self, key: str) -> bool:
        self._store.pop(key, None)
        self._expires.pop(key, None)
        return True

    def flush_all(self) -> bool:
        self._store.clear()
        self._expires.clear()
        return True


_memory_store = _MemoryStore()


# ─── Public helpers ───────────────────────────────────────────────────────────
def cache_get(key: str) -> Optional[str]:
    """Return cached value or None. Never raises."""
    if REDIS_AVAILABLE and _redis_client:
        try:
            return _redis_client.get(key)
        except Exception as e:
            logger.error(f"Redis GET error: {e}")
            return None
    return _memory_store.get(key)


def cache_set(key: str, value: str, ttl: int = 3600) -> bool:
    """Store a value. Never raises."""
    if REDIS_AVAILABLE and _redis_client:
        try:
            return bool(_redis_client.setex(key, ttl, value))
        except Exception as e:
            logger.error(f"Redis SET error: {e}")
            return False
    return _memory_store.set(key, value, ttl)


def cache_delete(key: str) -> bool:
    if REDIS_AVAILABLE and _redis_client:
        try:
            return bool(_redis_client.delete(key))
        except Exception:
            return False
    return _memory_store.delete(key)


def cache_flush() -> bool:
    if REDIS_AVAILABLE and _redis_client:
        try:
            _redis_client.flushall()
            return True
        except Exception:
            return False
    return _memory_store.flush_all()


# ─── Legacy CacheService wrapper ──────────────────────────────────────────────
# Kept for backward compatibility with existing router/service code that
# calls cache_service.get(...) / cache_service.set(...).
class CacheService:
    def get(self, key: str) -> Optional[str]:
        return cache_get(key)

    def set(self, key: str, value: str, expire: int = 3600) -> bool:
        return cache_set(key, value, expire)

    def delete(self, key: str) -> bool:
        return cache_delete(key)

    def flush_all(self) -> bool:
        return cache_flush()


cache_service = CacheService()
