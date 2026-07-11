# MIT License — Copyright (c) 2026 Diviqra
"""
Real-time SSE feed for Guard events.
Redis pub/sub channel: guard:events:{company_id} and guard:events:*
write_event() publishes; this router streams to connected clients.

Usage:
  GET /v1/events/stream?company_id=<uuid>
  Authorization: Bearer <guard_api_key_or_guard_jwt>

Client receives newline-delimited SSE:
  data: {"action":"block","score":0.98,"threats":["direct_injection"],...}
"""
import asyncio
import json
from typing import AsyncGenerator

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from service.config import settings

log = structlog.get_logger()
router = APIRouter(tags=["stream"])

_redis: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


CHANNEL_ALL = "guard:events:all"


def _channel(company_id: str | None) -> str:
    return f"guard:events:{company_id}" if company_id else CHANNEL_ALL


async def _event_generator(
    request: Request,
    company_id: str | None,
) -> AsyncGenerator[str, None]:
    redis = get_redis()
    pubsub = redis.pubsub()

    channels = [CHANNEL_ALL]
    if company_id:
        channels.append(_channel(company_id))

    await pubsub.subscribe(*channels)
    log.info("sse.client_connected", company_id=company_id)

    try:
        # Heartbeat every 15s to keep connection alive
        heartbeat_task = asyncio.create_task(_heartbeat())

        async for message in pubsub.listen():
            if await request.is_disconnected():
                break

            if message["type"] == "message":
                data = message["data"]
                yield f"data: {data}\n\n"

            # Yield heartbeat comment to prevent proxy timeout
            if heartbeat_task.done():
                yield ": heartbeat\n\n"
                heartbeat_task = asyncio.create_task(_heartbeat())

    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(*channels)
        await pubsub.close()
        log.info("sse.client_disconnected", company_id=company_id)


async def _heartbeat():
    await asyncio.sleep(15)


@router.get("/v1/events/stream")
async def event_stream(
    request: Request,
    company_id: str | None = Query(None),
    token: str | None = Query(None),  # fallback for EventSource (no custom headers)
):
    """
    Real-time SSE stream of Guard scan events.
    Connect with: EventSource('/v1/events/stream?token=<api_key>')
    """
    # Auth — either Authorization header or ?token= query param
    auth_header = request.headers.get("Authorization", "")
    api_key = None

    if auth_header.startswith("Bearer "):
        api_key = auth_header.split(" ", 1)[1]
    elif token:
        api_key = token

    if not api_key or api_key != settings.GUARD_API_KEY:
        # Also accept valid guard JWTs
        if api_key:
            try:
                from jose import jwt as jose_jwt
                payload = jose_jwt.decode(api_key, settings.GUARD_JWT_PUBLIC_KEY, algorithms=["RS256"])
                if payload.get("type") != "guard":
                    from fastapi import HTTPException
                    raise HTTPException(status_code=401, detail="Invalid token")
            except Exception:
                from fastapi import HTTPException
                raise HTTPException(status_code=401, detail="Invalid credentials")
        else:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="Missing credentials")

    return StreamingResponse(
        _event_generator(request, company_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable Nginx buffering
            "Connection": "keep-alive",
        },
    )


async def publish_event(company_id: str | None, event_data: dict) -> None:
    """Called from write_event() to push to Redis pub/sub."""
    try:
        redis = get_redis()
        payload = json.dumps(event_data, default=str)
        # Publish to both company channel and global channel
        await redis.publish(CHANNEL_ALL, payload)
        if company_id:
            await redis.publish(_channel(company_id), payload)
    except Exception as exc:
        log.warning("sse.publish_failed", error=str(exc))
