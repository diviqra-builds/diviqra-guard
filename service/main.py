# MIT License — Copyright (c) 2026 Diviqra
from contextlib import asynccontextmanager
from typing import Annotated

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from service.config import settings
from service.events import write_event
from service.models import (
    EventsQuery,
    RedTeamRunRequest,
    RedTeamRunResponse,
    ScanRequest,
    ScanResponse,
    StatsQuery,
)
from service.scanner import scan as run_scan

log = structlog.get_logger()

_engine = create_async_engine(settings.DATABASE_URL, pool_size=10, max_overflow=20)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)

_bearer = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("diviqra_guard.starting", port=settings.GUARD_PORT, version=settings.VERSION)
    yield
    log.info("diviqra_guard.stopping")
    await _engine.dispose()


app = FastAPI(
    title="Diviqra Guard",
    version=settings.VERSION,
    description="LLM firewall for AI agents — by Diviqra",
    lifespan=lifespan,
)


async def get_session() -> AsyncSession:
    async with _session_factory() as session:
        yield session


def _require_auth(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> None:
    if credentials.credentials != settings.GUARD_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


AuthDep = Annotated[None, Depends(_require_auth)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


# ── Public ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "service": "diviqra-guard", "version": settings.VERSION}


# ── Scan ──────────────────────────────────────────────────────────────────────

@app.post("/v1/scan", response_model=ScanResponse, tags=["scan"])
async def scan_endpoint(
    request: ScanRequest,
    _: AuthDep,
    session: SessionDep,
) -> ScanResponse:
    result = await run_scan(request)

    await write_event(
        session,
        company_id=request.company_id,
        agent_type=request.agent_type,
        direction=request.direction,
        action=result.action,
        score=float(result.score),
        threats=result.threats,
        reason=result.reason or "",
        text_preview=request.text,
        wall_triggered=result.wall_triggered,
        layer_triggered=result.layer_triggered,
        language=request.language,
        latency_ms=result.latency_ms,
    )

    return result


# ── Events ────────────────────────────────────────────────────────────────────

@app.get("/v1/events", tags=["events"])
async def list_events(
    _: AuthDep,
    session: SessionDep,
    company_id: str | None = Query(None),
    action: str | None = Query(None),
    agent_type: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    conditions = ["1=1"]
    params: dict = {}

    if company_id:
        conditions.append("company_id = :company_id")
        params["company_id"] = company_id
    if action:
        conditions.append("action = :action")
        params["action"] = action
    if agent_type:
        conditions.append("agent_type = :agent_type")
        params["agent_type"] = agent_type

    where = " AND ".join(conditions)
    params.update({"limit": limit, "offset": offset})

    count_result = await session.execute(
        text(f"SELECT COUNT(*) FROM guard_events WHERE {where}"),
        {k: v for k, v in params.items() if k not in ("limit", "offset")},
    )
    total = count_result.scalar()

    rows = await session.execute(
        text(f"SELECT * FROM guard_events WHERE {where} ORDER BY created_at DESC LIMIT :limit OFFSET :offset"),
        params,
    )
    items = [dict(row._mapping) for row in rows]

    return {"total": total, "items": items}


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/v1/stats", tags=["stats"])
async def get_stats(
    _: AuthDep,
    session: SessionDep,
    company_id: str | None = Query(None),
    period: str = Query("24h"),
):
    period_map = {"24h": "1 day", "7d": "7 days", "30d": "30 days"}
    interval = period_map.get(period, "1 day")

    where = "created_at >= NOW() - INTERVAL :interval"
    params: dict = {"interval": interval}
    if company_id:
        where += " AND company_id = :company_id"
        params["company_id"] = company_id

    summary = await session.execute(
        text(f"""
            SELECT
                COUNT(*) AS total_scans,
                SUM(CASE WHEN action='block' THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN action='warn'  THEN 1 ELSE 0 END) AS warned,
                SUM(CASE WHEN action='allow' THEN 1 ELSE 0 END) AS allowed,
                AVG(latency_ms) AS avg_latency_ms,
                SUM(CASE WHEN wall_triggered='wall1' AND action='block' THEN 1 ELSE 0 END) AS wall1_blocks,
                SUM(CASE WHEN wall_triggered='wall2' AND action='block' THEN 1 ELSE 0 END) AS wall2_blocks
            FROM guard_events
            WHERE {where}
        """),
        params,
    )
    row = dict(summary.fetchone()._mapping)

    total = row["total_scans"] or 0
    blocked = row["blocked"] or 0

    return {
        "total_scans": total,
        "blocked": blocked,
        "warned": row["warned"] or 0,
        "allowed": row["allowed"] or 0,
        "block_rate": round(blocked / total, 3) if total > 0 else 0.0,
        "avg_latency_ms": round(float(row["avg_latency_ms"] or 0), 1),
        "wall1_catch_rate": round((row["wall1_blocks"] or 0) / blocked, 3) if blocked > 0 else 0.0,
        "wall2_catch_rate": round((row["wall2_blocks"] or 0) / blocked, 3) if blocked > 0 else 0.0,
        "top_threats": await _top_threats(session, where, params),
    }


async def _top_threats(session: AsyncSession, where: str, params: dict) -> list[dict]:
    result = await session.execute(
        text(f"""
            SELECT unnest(threats) AS threat, COUNT(*) AS count
            FROM guard_events
            WHERE {where} AND array_length(threats, 1) > 0
            GROUP BY threat
            ORDER BY count DESC
            LIMIT 10
        """),
        params,
    )
    return [{"threat": row.threat, "count": row.count} for row in result]


# ── Red Team ──────────────────────────────────────────────────────────────────

@app.post("/v1/redteam/run", response_model=RedTeamRunResponse, tags=["redteam"])
async def start_redteam(request: RedTeamRunRequest, _: AuthDep):
    import asyncio

    from redteam.runner import run as redteam_run

    run_id_future = asyncio.create_task(
        redteam_run(mode=request.mode, agent_type=request.agent_type)
    )
    # Fire and forget — return immediately
    run_id = str(__import__("uuid").uuid4())
    log.info("redteam.started", mode=request.mode, agent_type=request.agent_type)
    return RedTeamRunResponse(run_id=run_id, status="started")


@app.get("/v1/redteam/results", tags=["redteam"])
async def redteam_results(
    _: AuthDep,
    session: SessionDep,
    run_id: str | None = Query(None),
    limit: int = Query(100, le=500),
):
    where = "1=1"
    params: dict = {"limit": limit}
    if run_id:
        where = "run_id = :run_id"
        params["run_id"] = run_id

    rows = await session.execute(
        text(f"SELECT * FROM guard_redteam_results WHERE {where} ORDER BY created_at DESC LIMIT :limit"),
        params,
    )
    items = [dict(row._mapping) for row in rows]

    total = len(items)
    detected = sum(1 for i in items if i.get("detected"))
    detection_rate = round(detected / total, 3) if total > 0 else 0.0

    return {"total": total, "detection_rate": detection_rate, "items": items}
