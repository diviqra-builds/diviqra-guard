# MIT License — Copyright (c) 2026 Diviqra
import hashlib
import json
from typing import Any

import redis.asyncio as aioredis
import structlog

from service.config import settings

log = structlog.get_logger()

_redis: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


def _cache_key(text: str, agent_type: str, direction: str) -> str:
    payload = f"{text}|{agent_type}|{direction}"
    return f"guard:wall2:{hashlib.sha256(payload.encode()).hexdigest()}"


async def get(text: str, agent_type: str, direction: str) -> dict | None:
    try:
        redis = await _get_redis()
        key = _cache_key(text, agent_type, direction)
        value = await redis.get(key)
        if value:
            return json.loads(value)
    except Exception as exc:
        log.warning("wall2.cache.get_error", error=str(exc))
    return None


async def set(text: str, agent_type: str, direction: str, result: dict) -> None:
    try:
        redis = await _get_redis()
        key = _cache_key(text, agent_type, direction)
        await redis.setex(key, settings.WALL2_CACHE_TTL, json.dumps(result))
    except Exception as exc:
        log.warning("wall2.cache.set_error", error=str(exc))
