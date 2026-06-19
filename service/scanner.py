# MIT License — Copyright (c) 2026 Diviqra
import time
import uuid

import structlog

from service import agent_rules
from service.models import ScanRequest, ScanResponse, WallResult
from service.walls import wall1, wall2

log = structlog.get_logger()

# Profile thresholds: (block_threshold, warn_threshold)
_THRESHOLDS: dict[str, tuple[float, float]] = {
    "strict":     (0.40, 0.20),
    "balanced":   (0.60, 0.35),
    "permissive": (0.80, 0.55),
}


def _profile_action(score: float, profile: str) -> str:
    block_t, warn_t = _THRESHOLDS.get(profile, _THRESHOLDS["balanced"])
    if score >= block_t:
        return "block"
    if score >= warn_t:
        return "warn"
    return "allow"


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _make_response(
    action: str,
    wall: WallResult,
    wall_name: str,
    start: float,
    scan_id: str,
) -> ScanResponse:
    return ScanResponse(
        action=action,
        score=wall.score,
        threats=wall.threats,
        reason=wall.reason or f"Scanned by {wall_name}",
        wall_triggered=wall_name if wall.score > 0 else None,
        layer_triggered=wall.layer,
        latency_ms=_elapsed_ms(start),
        scan_id=scan_id,
    )


async def scan(request: ScanRequest) -> ScanResponse:
    start = time.monotonic()
    scan_id = str(uuid.uuid4())

    # Agent-specific rules run alongside Wall 1
    w1_task, agent_task = (
        wall1.orchestrator.scan(request),
        agent_rules.scan(request),
    )

    import asyncio
    w1_result, agent_result = await asyncio.gather(w1_task, agent_task)

    # Merge agent rules into wall1 result
    merged_score = max(w1_result.score, agent_result.score)
    merged_threats = list(set(w1_result.threats + agent_result.threats))
    merged_layer = w1_result.layer if w1_result.score >= agent_result.score else agent_result.layer
    merged_reason = w1_result.reason if w1_result.score >= agent_result.score else agent_result.reason

    w1 = WallResult(
        score=merged_score,
        threats=merged_threats,
        layer=merged_layer,
        reason=merged_reason,
    )

    log.debug("scanner.wall1", score=w1.score, threats=w1.threats)

    # Fast path: definite block
    if w1.score >= 0.85:
        action = "block"
        log.info("scanner.blocked_wall1", scan_id=scan_id, score=w1.score, threats=w1.threats)
        return _make_response(action, w1, "wall1", start, scan_id)

    # Fast path: clearly safe
    if w1.score < 0.30:
        action = _profile_action(w1.score, request.profile)
        return _make_response(action, w1, "wall1", start, scan_id)

    # Uncertain zone (0.30-0.85) → Wall 2
    w2 = await wall2.orchestrator.scan(request)
    log.debug("scanner.wall2", score=w2.score, threats=w2.threats)

    combined_score = round((w1.score * 0.4) + (w2.score * 0.6), 3)
    combined_threats = list(set(w1.threats + w2.threats))
    action = _profile_action(combined_score, request.profile)

    combined = WallResult(
        score=combined_score,
        threats=combined_threats,
        layer=w2.layer,
        reason=w2.reason or w1.reason,
    )

    log.info("scanner.wall2_decision", scan_id=scan_id, score=combined_score, action=action)
    return ScanResponse(
        action=action,
        score=combined_score,
        threats=combined_threats,
        reason=combined.reason,
        wall_triggered="wall2",
        layer_triggered=w2.layer,
        latency_ms=_elapsed_ms(start),
        scan_id=scan_id,
    )
