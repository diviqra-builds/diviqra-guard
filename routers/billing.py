# MIT License — Copyright (c) 2026 Diviqra
import hashlib
import hmac
import json
from datetime import datetime, timezone

import httpx
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

PLANS = {
    "pro": {
        "name": "Guard Pro",
        "amount_paise": 499900,
        "currency": "INR",
        "scan_limit": 500_000,
    }
}


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


class CreateOrderRequest(BaseModel):
    plan: str = "pro"


class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
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
    order = await _create_razorpay_order(plan["amount_paise"], plan["currency"], receipt)
    return {"order_id": order["id"], "amount": plan["amount_paise"], "currency": plan["currency"],
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
    await session.execute(
        text("UPDATE guard_customers SET plan = :plan, scan_limit = :scan_limit, razorpay_payment_id = :payment_id, updated_at = NOW() WHERE id = :customer_id"),
        {"plan": body.plan, "scan_limit": plan["scan_limit"], "payment_id": body.razorpay_payment_id, "customer_id": customer["sub"]},
    )
    await session.commit()
    log.info("billing.upgrade_complete", customer_id=customer["sub"], plan=body.plan)
    return {"success": True, "plan": body.plan, "scan_limit": plan["scan_limit"], "payment_id": body.razorpay_payment_id}


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
    return {
        "plan": row.plan or "developer",
        "scan_limit": row.scan_limit or 10_000,
        "scan_count": row.scan_count or 0,
        "payment_id": row.razorpay_payment_id,
        "available_plans": [
            {"id": "developer", "name": "Developer", "price_inr": 0, "scan_limit": 10_000, "current": (row.plan or "developer") == "developer"},
            {"id": "pro", "name": "Guard Pro", "price_inr": 4_999, "scan_limit": 500_000, "current": row.plan == "pro"},
            {"id": "enterprise", "name": "Enterprise", "price_inr": None, "scan_limit": None, "current": row.plan == "enterprise"},
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
