from datetime import datetime, timezone
from typing import Any, Dict


def provider_result(source: str, status: str, data: Dict[str, Any] | None = None,
                    error: str | None = None) -> Dict[str, Any]:
    """Attach provenance to provider output without inventing missing values."""
    result = dict(data or {})
    result["status"] = status
    result["source"] = source
    result["retrieved_at"] = datetime.now(timezone.utc).isoformat()
    if error:
        result["error"] = error
    return result


def unavailable(source: str, error: str, status: str = "unavailable") -> Dict[str, Any]:
    return provider_result(source, status, error=error)


def ensure_provenance(data: Dict[str, Any], source: str) -> Dict[str, Any]:
    result = dict(data or {})
    result.setdefault("status", "success")
    result.setdefault("source", source)
    result.setdefault("retrieved_at", datetime.now(timezone.utc).isoformat())
    return result
