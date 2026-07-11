# MIT License — Copyright (c) 2026 Diviqra
import uuid
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

log = structlog.get_logger()

INSERT_EVENT = text("""
    INSERT INTO guard_events
        (company_id, agent_type, direction, action, score, threats, reason,
         text_preview, wall_triggered, layer_triggered, language, latency_ms)
    VALUES
        (:company_id, :agent_type, :direction, :action, :score, :threats, :reason,
         :text_preview, :wall_triggered, :layer_triggered, :language, :latency_ms)
    RETURNING id
""")


async def write_event(
    session: AsyncSession,
    *,
    company_id: str,
    agent_type: str,
    direction: str,
    action: str,
    score: float,
    threats: list[str],
    reason: str,
    text_preview: str,
    wall_triggered: str | None,
    layer_triggered: str | None,
    language: str,
    latency_ms: int,
) -> str:
    event_id = str(uuid.uuid4())
    try:
        result = await session.execute(
            INSERT_EVENT,
            {
                "company_id": company_id or None,
                "agent_type": agent_type,
                "direction": direction,
                "action": action,
                "score": score,
                "threats": threats,
                "reason": reason,
                "text_preview": text_preview[:100] if text_preview else None,
                "wall_triggered": wall_triggered,
                "layer_triggered": layer_triggered,
                "language": language,
                "latency_ms": latency_ms,
            },
        )
        await session.commit()
        row = result.fetchone()
        if row:
            event_id = str(row[0])
    except Exception as exc:
        log.error("events.write_failed", error=str(exc))
        await session.rollback()
        return event_id

    # Build event payload for SSE + webhooks
    event_data = {
        "id": event_id,
        "company_id": company_id,
        "agent_type": agent_type,
        "direction": direction,
        "action": action,
        "score": score,
        "threats": threats,
        "reason": reason,
        "wall_triggered": wall_triggered,
        "layer_triggered": layer_triggered,
        "language": language,
        "latency_ms": latency_ms,
    }

    # SSE — publish to Redis (non-blocking, fire and forget)
    try:
        from routers.sse import publish_event
        import asyncio
        asyncio.create_task(publish_event(company_id, event_data))
    except Exception as exc:
        log.warning("events.sse_publish_failed", error=str(exc))

    # Webhooks — fire on block or warn (non-blocking)
    if action in ("block", "warn"):
        try:
            from routers.webhooks import fire_webhooks
            import asyncio
            asyncio.create_task(fire_webhooks(company_id, action, event_data))
        except Exception as exc:
            log.warning("events.webhook_fire_failed", error=str(exc))

    return event_id
