# MIT License — Copyright (c) 2026 Diviqra
"""Per-API-key monthly scan quota enforcement for /v1/scan.

Two callers hit /v1/scan with different trust levels:
  - the platform backend, using the shared GUARD_API_KEY (it already checked
    the customer's quota itself before forwarding — see guard_auth.py's
    scan_with_enforcement) — treated as internal, not re-metered here.
  - the public SDK, using the customer's own dg_dev_/dg_pro_/dg_ent_ key,
    calling this service directly — metered here since nothing else does it.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from service.config import settings

UPGRADE_URL = "https://guard.diviqra.com/billing"


@dataclass(frozen=True)
class ScanAuthContext:
    is_internal: bool
    api_key_id: str | None = None
    company_id: str | None = None
    plan: str | None = None
    scans_used_month: int = 0
    scans_limit: int = 0


def next_month_reset_iso() -> str:
    now = datetime.now(timezone.utc)
    year, month = (now.year + 1, 1) if now.month == 12 else (now.year, now.month + 1)
    return datetime(year, month, 1, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def authenticate_scan_request(
    credentials: HTTPAuthorizationCredentials,
    session: AsyncSession,
) -> ScanAuthContext:
    token = credentials.credentials

    if settings.GUARD_API_KEY and hmac.compare_digest(token, settings.GUARD_API_KEY):
        return ScanAuthContext(is_internal=True)

    key_hash = hashlib.sha256(token.encode()).hexdigest()
    row = (
        await session.execute(
            text("""
                SELECT id, customer_id, plan, scans_used_month, scans_limit, is_active
                FROM guard_api_keys WHERE key_hash = :hash
            """),
            {"hash": key_hash},
        )
    ).fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not row.is_active:
        raise HTTPException(status_code=403, detail="API key is inactive")

    return ScanAuthContext(
        is_internal=False,
        api_key_id=str(row.id),
        company_id=str(row.customer_id),
        plan=row.plan,
        scans_used_month=row.scans_used_month,
        scans_limit=row.scans_limit,
    )


def quota_exceeded_body(auth_ctx: ScanAuthContext) -> dict:
    return {
        "error": "scan_limit_exceeded",
        "message": "Monthly scan limit reached. Upgrade at guard.diviqra.com/billing",
        "scans_used": auth_ctx.scans_used_month,
        "scans_limit": auth_ctx.scans_limit,
        "plan": auth_ctx.plan,
        "upgrade_url": UPGRADE_URL,
    }


async def charge_scan_usage(session: AsyncSession, auth_ctx: ScanAuthContext) -> None:
    await session.execute(
        text("""
            UPDATE guard_api_keys
            SET scans_used_month = scans_used_month + 1, last_used_at = NOW()
            WHERE id = :id
        """),
        {"id": auth_ctx.api_key_id},
    )
    await session.commit()
