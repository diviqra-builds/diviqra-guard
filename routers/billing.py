# MIT License — Copyright (c) 2026 Diviqra
import asyncio
import hashlib
import hmac
import json
import secrets
from datetime import datetime

import httpx
import stripe
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from service.config import settings

log = structlog.get_logger()
router = APIRouter(prefix="/v1/billing", tags=["billing"])
_bearer = HTTPBearer(auto_error=False)

_engine = create_async_engine(settings.DATABASE_URL, pool_size=5, max_overflow=10)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)

stripe.api_key = settings.STRIPE_SECRET_KEY

# A high sentinel stands in for "unlimited" since scan_limit/scans_limit are
# NOT NULL integer columns — translated back to None at the API boundary.
UNLIMITED_SCAN_LIMIT = 999_999_999

PLANS = {
    "pro": {
        "name": "Guard Pro",
        "price_inr_paise": 499_900,
        "price_usd_cents": 4_900,
        "scan_limit": 500_000,
    },
    "enterprise": {
        "name": "Guard Enterprise",
        "price_inr_paise": 1_999_900,
        "price_usd_cents": 19_900,
        "scan_limit": None,
    },
    "whatsapp_number": {
        "name": "WhatsApp Number Protection",
        "price_inr_paise": settings.WHATSAPP_PRICE_INR_PAISE,
        "price_usd_cents": 0,
        "scan_limit": None,
    },
}

_STRIPE_PRICE_IDS = {
    "pro": settings.STRIPE_PRO_PRICE_ID,
    "enterprise": settings.STRIPE_ENTERPRISE_PRICE_ID,
}

_PLAN_KEY_PREFIX = {"free": "dg_dev_", "pro": "dg_pro_", "enterprise": "dg_ent_"}


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


def _resolved_scan_limit(plan: dict) -> int:
    return plan["scan_limit"] or UNLIMITED_SCAN_LIMIT


def _display_scan_limit(value: int | None) -> int | None:
    if value is None or value >= UNLIMITED_SCAN_LIMIT:
        return None
    return value


def _generate_api_key(plan_id: str) -> tuple[str, str, str]:
    prefix = _PLAN_KEY_PREFIX.get(plan_id, "dg_dev_")
    secret = secrets.token_urlsafe(32)
    full_key = prefix + secret
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    key_prefix = prefix + secret[:8]
    return full_key, key_prefix, key_hash


class CreateOrderRequest(BaseModel):
    plan: str = "pro"


class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    plan: str = "pro"


class CreateCheckoutRequest(BaseModel):
    plan: str = "pro"


async def _create_razorpay_order(amount: int, currency: str, receipt: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://api.razorpay.com/v1/orders",
            auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET),
            json={"amount": amount, "currency": currency, "receipt": receipt, "payment_capture": 1},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Payment gateway error")
        return resp.json()


def _verify_signature(order_id: str, payment_id: str, signature: str) -> bool:
    body = f"{order_id}|{payment_id}"
    expected = hmac.new(settings.RAZORPAY_KEY_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


async def _send_upgrade_email(email: str, full_name: str, plan_name: str, full_key: str) -> None:
    if not settings.RESEND_API_KEY:
        log.warning("billing.upgrade_email_skipped", reason="RESEND_API_KEY not configured", email=email)
        return
    html = f"""<p>Hi {full_name},</p>
<p>You're upgraded to <strong>{plan_name}</strong>. A new Guard API key has been issued for your account:</p>
<pre style="background:#0D1117;color:#C9D1D9;padding:12px;border-radius:4px;font-family:monospace">{full_key}</pre>
<p>⚠️ Store this safely — it won't be shown again. Your previous key has been deactivated.</p>
<p>
  <a href="https://guard.diviqra.com/billing">Dashboard</a> ·
  <a href="https://guard.diviqra.com/docs">Docs</a>
</p>
<p>— Diviqra Guard Team</p>"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {settings.RESEND_API_KEY}", "Content-Type": "application/json"},
                json={
                    "from": settings.GUARD_FROM_EMAIL,
                    "to": [email],
                    "subject": f"You're upgraded to {plan_name} — new Guard API key inside",
                    "html": html,
                },
            )
            resp.raise_for_status()
        log.info("billing.upgrade_email_sent", email=email)
    except Exception as exc:
        log.warning("billing.upgrade_email_failed", error=str(exc), email=email)


async def _upgrade_customer_from_stripe(customer_id: str, plan_id: str, stripe_payment_id: str) -> None:
    plan = PLANS[plan_id]
    scan_limit = _resolved_scan_limit(plan)
    full_key, key_prefix, key_hash = _generate_api_key(plan_id)

    async with _session_factory() as session:
        row = (await session.execute(
            text("SELECT email, full_name FROM guard_customers WHERE id = CAST(:id AS UUID)"),
            {"id": customer_id},
        )).fetchone()
        if not row:
            log.error("stripe.webhook_unknown_customer", customer_id=customer_id)
            return

        await session.execute(
            text("""
                UPDATE guard_customers
                SET plan = :plan, scan_limit = :limit, scans_limit = :limit,
                    stripe_payment_id = :payment_id, updated_at = NOW()
                WHERE id = CAST(:id AS UUID)
            """),
            {"plan": plan_id, "limit": scan_limit, "payment_id": stripe_payment_id, "id": customer_id},
        )
        await session.execute(
            text("""
                UPDATE guard_api_keys SET is_active = false
                WHERE customer_id = CAST(:id AS UUID) AND is_active = true
            """),
            {"id": customer_id},
        )
        await session.execute(
            text("""
                INSERT INTO guard_api_keys (customer_id, name, key_prefix, key_hash, plan, scans_limit)
                VALUES (CAST(:id AS UUID), 'Stripe upgrade', :prefix, :hash, :plan, :limit)
            """),
            {"id": customer_id, "prefix": key_prefix, "hash": key_hash, "plan": plan_id, "limit": scan_limit},
        )
        await session.commit()

    log.info("stripe.upgrade_complete", customer_id=customer_id, plan=plan_id)
    await _send_upgrade_email(row.email, row.full_name, plan["name"], full_key)


@router.post("/create-order")
async def create_order(
    body: CreateOrderRequest,
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    plan = PLANS.get(body.plan)
    if not plan:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {body.plan}")
    receipt = f"guard_{customer['sub'][:8]}_{int(datetime.now().timestamp())}"
    order = await _create_razorpay_order(plan["price_inr_paise"], "INR", receipt)
    return {"order_id": order["id"], "amount": plan["price_inr_paise"], "currency": "INR",
            "plan": body.plan, "plan_name": plan["name"], "key_id": settings.RAZORPAY_KEY_ID}


@router.post("/verify")
async def verify_payment(
    body: VerifyPaymentRequest,
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    if not _verify_signature(body.razorpay_order_id, body.razorpay_payment_id, body.razorpay_signature):
        raise HTTPException(status_code=400, detail="Invalid payment signature")
    plan = PLANS.get(body.plan)
    if not plan:
        raise HTTPException(status_code=400, detail="Unknown plan")
    scan_limit = _resolved_scan_limit(plan)
    await session.execute(
        text("""
            UPDATE guard_customers
            SET plan = :plan, scan_limit = :limit, scans_limit = :limit,
                razorpay_payment_id = :payment_id, updated_at = NOW()
            WHERE id = :customer_id
        """),
        {"plan": body.plan, "limit": scan_limit, "payment_id": body.razorpay_payment_id, "customer_id": customer["sub"]},
    )
    await session.commit()
    log.info("billing.upgrade_complete", customer_id=customer["sub"], plan=body.plan)
    return {"success": True, "plan": body.plan, "scan_limit": _display_scan_limit(scan_limit), "payment_id": body.razorpay_payment_id}


@router.get("/status")
async def billing_status(
    customer: dict = Depends(_get_customer),
    session: AsyncSession = Depends(_get_session),
):
    row = (await session.execute(
        text("SELECT plan, scan_limit, scan_count, razorpay_payment_id FROM guard_customers WHERE id = :id"),
        {"id": customer["sub"]},
    )).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found")
    current_plan = row.plan or "developer"
    return {
        "plan": current_plan,
        "scan_limit": _display_scan_limit(row.scan_limit or 10_000),
        "scan_count": row.scan_count or 0,
        "payment_id": row.razorpay_payment_id,
        "razorpay_key_id": settings.RAZORPAY_KEY_ID,
        "stripe_publishable_key": settings.STRIPE_PUBLISHABLE_KEY,
        "available_plans": [
            {"id": "developer", "name": "Developer", "price_inr": 0, "price_usd": 0,
             "scan_limit": 10_000, "current": current_plan == "developer"},
            {"id": "pro", "name": "Guard Pro", "price_inr": 4_999, "price_usd": 49,
             "scan_limit": 500_000, "current": current_plan == "pro"},
            {"id": "enterprise", "name": "Enterprise", "price_inr": 19_999, "price_usd": 199,
             "scan_limit": None, "current": current_plan == "enterprise"},
        ],
    }


@router.post("/webhook")
async def razorpay_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")
    expected = hmac.new(settings.RAZORPAY_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    event = json.loads(body)
    if event.get("event") == "payment.captured":
        payment_id = event.get("payload", {}).get("payment", {}).get("entity", {}).get("id")
        log.info("razorpay.payment_captured", payment_id=payment_id)
    return {"status": "ok"}


@router.post("/stripe/create-checkout")
async def stripe_create_checkout(
    body: CreateCheckoutRequest,
    customer: dict = Depends(_get_customer),
):
    plan = PLANS.get(body.plan)
    if not plan:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {body.plan}")
    price_id = _STRIPE_PRICE_IDS.get(body.plan)
    if not price_id:
        raise HTTPException(status_code=500, detail=f"Stripe price not configured for plan: {body.plan}")

    try:
        checkout_session = await asyncio.to_thread(
            stripe.checkout.Session.create,
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url="https://guard.diviqra.com/billing?success=true",
            cancel_url="https://guard.diviqra.com/billing",
            client_reference_id=customer["sub"],
            customer_email=customer.get("email"),
            metadata={"guard_customer_id": customer["sub"], "plan": body.plan},
            subscription_data={"metadata": {"guard_customer_id": customer["sub"], "plan": body.plan}},
        )
    except stripe.error.StripeError as exc:
        log.error("stripe.checkout_create_failed", error=str(exc), customer_id=customer["sub"])
        raise HTTPException(status_code=502, detail="Payment gateway error")

    log.info("stripe.checkout_created", customer_id=customer["sub"], plan=body.plan, session_id=checkout_session.id)
    return {"checkout_url": checkout_session.url, "session_id": checkout_session.id}


@router.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    if event["type"] == "checkout.session.completed":
        session_obj = event["data"]["object"]
        metadata = session_obj.get("metadata") or {}
        customer_id = session_obj.get("client_reference_id") or metadata.get("guard_customer_id")
        plan_id = metadata.get("plan", "pro")
        stripe_payment_id = session_obj.get("subscription") or session_obj.get("id")

        if not customer_id or plan_id not in PLANS:
            log.warning("stripe.webhook_missing_context", customer_id=customer_id, plan=plan_id)
            return {"status": "ignored"}

        await _upgrade_customer_from_stripe(customer_id, plan_id, stripe_payment_id)

    return {"status": "ok"}
