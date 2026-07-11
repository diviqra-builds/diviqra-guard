# MIT License — Copyright (c) 2026 Diviqra
"""WhatsApp middleware — scan inbound Meta Cloud API messages through Guard.

Registration billing reuses the existing generic /v1/billing/create-order
endpoint (see billing.py's "whatsapp_number" plan entry) to obtain a Razorpay
order id; this router only verifies the resulting payment and never touches
guard_customers.plan — a WhatsApp number is a per-number add-on, not a plan
upgrade.
"""
import asyncio
import hashlib
import hmac
import json
import secrets

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Security
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from service.config import settings
from service.events import write_event
from service.models import ScanRequest
from service.scanner import scan as run_scan

log = structlog.get_logger()
router = APIRouter(prefix="/guard/whatsapp", tags=["whatsapp"])
_bearer = HTTPBearer(auto_error=False)

_engine = create_async_engine(settings.DATABASE_URL, pool_size=5, max_overflow=10)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)

WEBHOOK_BASE_URL = "https://api.guard.diviqra.com"


async def _get_session() -> AsyncSession:
    async with _session_factory() as session:
        yield session


def _get_customer(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        payload = jwt.decode(credentials.credentials, settings.GUARD_JWT_PUBLIC_KEY, algorithms=["RS256"])
        if payload.get("type") != "guard":
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _verify_razorpay_signature(order_id: str, payment_id: str, signature: str) -> bool:
    body = f"{order_id}|{payment_id}"
    expected = hmac.new(settings.RAZORPAY_KEY_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _verify_meta_signature(body: bytes, signature_header: str) -> bool:
    if not settings.META_APP_SECRET:
        return True  # signature verification not configured — allow (dev mode)
    expected = "sha256=" + hmac.new(settings.META_APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ── Alerting / auto-reply ──────────────────────────────────────

async def _send_threat_alert(email: str, full_name: str, phone_number_id: str, sender: str, text_body: str, result) -> None:
    if not settings.RESEND_API_KEY:
        log.warning("whatsapp.alert_skipped", reason="RESEND_API_KEY not configured", email=email)
        return
    preview = text_body[:200]
    html = f"""<p>Hi {full_name},</p>
<p>Guard blocked a suspicious WhatsApp message on number <strong>{phone_number_id}</strong>:</p>
<blockquote style="border-left:3px solid #C62828;padding:8px 12px;color:#333;">{preview}</blockquote>
<p><strong>From:</strong> {sender}<br/><strong>Reason:</strong> {result.reason}<br/><strong>Threats:</strong> {', '.join(result.threats) or 'n/a'}</p>
<p><a href="https://guard.diviqra.com/whatsapp">View in dashboard</a></p>
<p>— Diviqra Guard Team</p>"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}", "Content-Type": "application/json"},
                json={
                    "from": settings.GUARD_FROM_EMAIL,
                    "to": [email],
                    "subject": f"⚠️ Guard blocked a threat on WhatsApp ({phone_number_id})",
                    "html": html,
                },
            )
            resp.raise_for_status()
        log.info("whatsapp.alert_sent", email=email, phone_number_id=phone_number_id)
    except Exception as exc:
        log.warning("whatsapp.alert_failed", error=str(exc), email=email)


async def _send_whatsapp_reply(phone_number_id: str, to: str, body: str) -> None:
    if not settings.META_WHATSAPP_ACCESS_TOKEN:
        log.warning("whatsapp.reply_skipped", reason="META_WHATSAPP_ACCESS_TOKEN not configured")
        return
    url = f"{settings.META_GRAPH_BASE_URL}/{settings.META_GRAPH_API_VERSION}/{phone_number_id}/messages"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {settings.META_WHATSAPP_ACCESS_TOKEN}"},
                json={"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": body}},
            )
            resp.raise_for_status()
        log.info("whatsapp.auto_reply_sent", phone_number_id=phone_number_id)
    except Exception as exc:
        log.warning("whatsapp.auto_reply_failed", error=str(exc), phone_number_id=phone_number_id)


async def _alert_and_reply(customer_id: str, phone_number_id: str, sender: str, text_body: str, result) -> None:
    try:
        async with _session_factory() as session:
            row = (await session.execute(
                text("SELECT email, full_name FROM guard_customers WHERE id = CAST(:id AS UUID)"),
                {"id": customer_id},
            )).fetchone()
        if row:
            await _send_threat_alert(row.email, row.full_name, phone_number_id, sender, text_body, result)
    except Exception as exc:
        log.warning("whatsapp.alert_lookup_failed", error=str(exc), customer_id=customer_id)

    await _send_whatsapp_reply(phone_number_id, sender, "Sorry, I can't help with that request.")


# ── Inbound message processing ─────────────────────────────────

async def _process_inbound_message(session: AsyncSession, number_row, phone_number_id: str, sender: str, text_body: str) -> None:
    scan_request = ScanRequest(
        text=text_body,
        direction="ingress",
        agent_type=f"whatsapp:{phone_number_id}",
        company_id=str(number_row.customer_id),
        profile="balanced",
        language="en",
        context="user_input",
    )
    result = await run_scan(scan_request)

    await write_event(
        session,
        company_id=str(number_row.customer_id),
        agent_type=f"whatsapp:{phone_number_id}",
        direction="ingress",
        action=result.action,
        score=float(result.score),
        threats=result.threats,
        reason=result.reason or "",
        text_preview=text_body,
        wall_triggered=result.wall_triggered,
        layer_triggered=result.layer_triggered,
        language="en",
        latency_ms=result.latency_ms,
    )

    is_blocked = result.action == "block"
    await session.execute(
        text("""
            UPDATE guard_whatsapp_numbers
            SET scans_this_month = scans_this_month + 1,
                threats_this_month = threats_this_month + CASE WHEN :blocked THEN 1 ELSE 0 END
            WHERE id = :id
        """),
        {"blocked": is_blocked, "id": str(number_row.id)},
    )
    await session.commit()

    if is_blocked:
        asyncio.create_task(_alert_and_reply(str(number_row.customer_id), phone_number_id, sender, text_body, result))


# ── Webhook (Meta Cloud API) ────────────────────────────────────

@router.get("/webhook")
async def verify_webhook(request: Request, session: AsyncSession = Depends(_get_session)):
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge", "")

    if mode != "subscribe" or not token:
        raise HTTPException(status_code=403, detail="Invalid verification request")

    row = (await session.execute(
        text("SELECT id FROM guard_whatsapp_numbers WHERE webhook_verify_token = :token AND is_active = true"),
        {"token": token},
    )).fetchone()
    if not row:
        raise HTTPException(status_code=403, detail="Invalid verify token")

    return PlainTextResponse(challenge)


@router.post("/webhook")
async def receive_webhook(request: Request, session: AsyncSession = Depends(_get_session)):
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_meta_signature(body, signature):
        raise HTTPException(status_code=403, detail="Invalid webhook signature")

    payload = json.loads(body)

    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            phone_number_id = value.get("metadata", {}).get("phone_number_id")
            messages = value.get("messages", [])
            if not phone_number_id or not messages:
                continue

            number_row = (await session.execute(
                text("SELECT id, customer_id FROM guard_whatsapp_numbers WHERE phone_number_id = :pid AND is_active = true"),
                {"pid": phone_number_id},
            )).fetchone()
            if not number_row:
                log.warning("whatsapp.unregistered_number", phone_number_id=phone_number_id)
                continue

            for msg in messages:
                if msg.get("type") != "text":
                    continue
                text_body = msg.get("text", {}).get("body", "")
                sender = msg.get("from", "")
                if not text_body or not sender:
                    continue
                await _process_inbound_message(session, number_row, phone_number_id, sender, text_body)

    # Always 200 — Meta disables webhooks after repeated non-2xx responses.
    return {"status": "ok"}


# ── Number registration ──────────────────────────────────────────

class RegisterNumberRequest(BaseModel):
    phone_number_id: str
    display_name: str | None = None
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


@router.post("/register-number")
async def register_number(
    body: RegisterNumberRequest,
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    if not _verify_razorpay_signature(body.razorpay_order_id, body.razorpay_payment_id, body.razorpay_signature):
        raise HTTPException(status_code=400, detail="Invalid payment signature")

    verify_token = secrets.token_urlsafe(24)
    try:
        row = (await session.execute(
            text("""
                INSERT INTO guard_whatsapp_numbers
                    (customer_id, phone_number_id, display_name, webhook_verify_token, razorpay_payment_id)
                VALUES (CAST(:customer_id AS UUID), :phone_number_id, :display_name, :verify_token, :payment_id)
                RETURNING id, created_at
            """),
            {
                "customer_id": customer["sub"],
                "phone_number_id": body.phone_number_id,
                "display_name": body.display_name,
                "verify_token": verify_token,
                "payment_id": body.razorpay_payment_id,
            },
        )).fetchone()
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=409, detail="This WhatsApp number is already registered")

    log.info("whatsapp.number_registered", customer_id=customer["sub"], phone_number_id=body.phone_number_id)
    return {
        "id": str(row.id),
        "phone_number_id": body.phone_number_id,
        "display_name": body.display_name,
        "webhook_verify_token": verify_token,
        "webhook_url": f"{WEBHOOK_BASE_URL}/guard/whatsapp/webhook",
        "price_inr_paise": settings.WHATSAPP_PRICE_INR_PAISE,
        "created_at": row.created_at.isoformat(),
    }


@router.get("/numbers")
async def list_numbers(
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    rows = await session.execute(
        text("""
            SELECT id, phone_number_id, display_name, is_active,
                   scans_this_month, threats_this_month, created_at
            FROM guard_whatsapp_numbers
            WHERE customer_id = CAST(:customer_id AS UUID)
            ORDER BY created_at DESC
        """),
        {"customer_id": customer["sub"]},
    )
    return {"items": [dict(r._mapping) for r in rows]}


@router.get("/events")
async def whatsapp_events(
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
    phone_number_id: str | None = Query(None),
    limit: int = Query(50, le=200),
):
    agent_type_filter = f"whatsapp:{phone_number_id}" if phone_number_id else None
    where = "company_id = CAST(:customer_id AS UUID) AND action IN ('block','warn')"
    params: dict = {"customer_id": customer["sub"], "limit": limit}
    if agent_type_filter:
        where += " AND agent_type = :agent_type"
        params["agent_type"] = agent_type_filter
    else:
        where += " AND agent_type LIKE 'whatsapp:%'"

    rows = await session.execute(
        text(f"SELECT * FROM guard_events WHERE {where} ORDER BY created_at DESC LIMIT :limit"),
        params,
    )
    return {"items": [dict(r._mapping) for r in rows]}
