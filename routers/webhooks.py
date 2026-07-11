# MIT License — Copyright (c) 2026 Diviqra
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from service.config import settings

log = structlog.get_logger()
router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])
_bearer = HTTPBearer()

_engine = create_async_engine(settings.DATABASE_URL, pool_size=5, max_overflow=10)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def _get_session() -> AsyncSession:
    async with _session_factory() as session:
        yield session


def _get_customer(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, settings.GUARD_JWT_PUBLIC_KEY, algorithms=["RS256"])
        if payload.get("type") != "guard":
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


class WebhookCreate(BaseModel):
    url: str
    events: list[str] = ["block", "warn"]


@router.post("")
async def create_webhook(
    body: WebhookCreate,
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    webhook_id = str(uuid.uuid4())
    secret = f"whsec_{secrets.token_urlsafe(32)}"
    valid_events = {"block", "warn", "allow"}
    events = [e for e in body.events if e in valid_events] or ["block", "warn"]
    await session.execute(
        text("INSERT INTO guard_webhooks (id, customer_id, url, secret, events) VALUES (:id, :customer_id, :url, :secret, :events)"),
        {"id": webhook_id, "customer_id": customer["sub"], "url": body.url, "secret": secret, "events": events},
    )
    await session.commit()
    log.info("webhook.created", customer_id=customer["sub"], url=body.url)
    return {"id": webhook_id, "url": body.url, "secret": secret, "events": events, "active": True,
            "created_at": datetime.now(timezone.utc).isoformat()}


@router.get("")
async def list_webhooks(
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    rows = await session.execute(
        text("SELECT id, url, events, active, created_at FROM guard_webhooks WHERE customer_id = :cid ORDER BY created_at DESC"),
        {"cid": customer["sub"]},
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    result = await session.execute(
        text("DELETE FROM guard_webhooks WHERE id = :id AND customer_id = :cid RETURNING id"),
        {"id": webhook_id, "cid": customer["sub"]},
    )
    if not result.fetchone():
        raise HTTPException(status_code=404, detail="Webhook not found")
    await session.commit()
    return {"success": True}


@router.patch("/{webhook_id}/toggle")
async def toggle_webhook(
    webhook_id: str,
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    result = await session.execute(
        text("UPDATE guard_webhooks SET active = NOT active, updated_at = NOW() WHERE id = :id AND customer_id = :cid RETURNING id, active"),
        {"id": webhook_id, "cid": customer["sub"]},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await session.commit()
    return {"id": str(row.id), "active": row.active}


def _sign_payload(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


async def fire_webhooks(company_id: str, action: str, event_data: dict) -> None:
    try:
        async with _session_factory() as session:
            rows = await session.execute(
                text("SELECT id, url, secret FROM guard_webhooks WHERE active = TRUE AND :action = ANY(events)"),
                {"action": action},
            )
            webhooks = rows.fetchall()
        if not webhooks:
            return
        payload = json.dumps({"event": f"guard.{action}", "timestamp": datetime.now(timezone.utc).isoformat(), "data": event_data}).encode()
        async with httpx.AsyncClient(timeout=5.0) as client:
            for wh in webhooks:
                sig = _sign_payload(wh.secret, payload)
                try:
                    await client.post(wh.url, content=payload, headers={
                        "Content-Type": "application/json",
                        "X-Diviqra-Guard-Signature": f"sha256={sig}",
                        "X-Diviqra-Guard-Event": f"guard.{action}",
                    })
                    log.info("webhook.fired", webhook_id=str(wh.id), action=action)
                except Exception as exc:
                    log.warning("webhook.delivery_failed", webhook_id=str(wh.id), error=str(exc))
    except Exception as exc:
        log.error("webhook.fire_error", error=str(exc))
