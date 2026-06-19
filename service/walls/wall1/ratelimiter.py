# MIT License — Copyright (c) 2026 Diviqra
import time

import redis.asyncio as aioredis
import structlog

from service.config import settings
from service.models import ScanRequest, WallResult

log = structlog.get_logger()

_redis: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


async def check(request: ScanRequest) -> WallResult:
    try:
        redis = await _get_redis()
        return await _check(redis, request)
    except Exception as exc:
        log.warning("ratelimiter.redis_error", error=str(exc))
        return WallResult()


async def _check(redis: aioredis.Redis, request: ScanRequest) -> WallResult:
    company_key = f"guard:rate:{request.company_id}:req"
    now = int(time.time())
    window_key = f"{company_key}:{now // 60}"

    count = await redis.incr(window_key)
    if count == 1:
        await redis.expire(window_key, 60)

    if count > settings.MAX_REQUESTS_PER_MINUTE:
        return WallResult(
            score=0.70,
            threats=["rate_limit_exceeded"],
            layer="rate_limit",
            reason=f"Rate limit exceeded: {count} requests/min (max {settings.MAX_REQUESTS_PER_MINUTE})",
        )

    # Token budget check
    token_count = len(request.text.split())
    max_tokens = (
        settings.MAX_TOKENS_PER_REQUEST_INGRESS
        if request.direction == "ingress"
        else settings.MAX_TOKENS_PER_REQUEST_EGRESS
    )

    if token_count > max_tokens:
        return WallResult(
            score=0.70,
            threats=["token_budget_exceeded"],
            layer="token_budget",
            reason=f"Token count {token_count} exceeds limit {max_tokens}",
        )

    return WallResult()
