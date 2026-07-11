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

# Context-aware block thresholds — higher = more lenient. Applied when the
# caller supplies a `context` (internal agent traffic). External SDK callers
# omit context and fall through to the profile thresholds above.
#   user_input   — external users, full sensitivity
#   agent_prompt — agent-generated, semi-trusted
#   web_scrape   — scraped content, lenient
#   llm_response — LLM output, semi-trusted
_CONTEXT_BLOCK_THRESHOLD: dict[str, float] = {
    "user_input":   0.50,
    "agent_prompt": 0.85,
    "web_scrape":   0.90,
    "llm_response": 0.85,
}

# Warn band sits this far below the block threshold.
_WARN_MARGIN = 0.15

# Wall 1 must clear this confidence to auto-block without a Wall 2 second opinion.
_FAST_BLOCK_FLOOR = 0.85


def _resolve_thresholds(request: ScanRequest) -> tuple[float, float]:
    """Return (block_threshold, warn_threshold) for this request.

    Context-aware when a context is supplied (internal agent traffic);
    otherwise fall back to the customer's profile (external SDK callers).
    """
    if request.context:
        block_t = _CONTEXT_BLOCK_THRESHOLD.get(
            request.context, _CONTEXT_BLOCK_THRESHOLD["user_input"]
        )
        warn_t = max(block_t - _WARN_MARGIN, 0.0)
        return block_t, warn_t
    return _THRESHOLDS.get(request.profile, _THRESHOLDS["balanced"])


def _action(score: float, block_t: float, warn_t: float) -> str:
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

    log.debug("scanner.wall1", score=w1.score, threats=w1.threats, context=request.context)

    block_t, warn_t = _resolve_thresholds(request)

    # Fast path: clearly safe → skip Wall 2
    if w1.score < 0.30:
        action = _action(w1.score, block_t, warn_t)
        return _make_response(action, w1, "wall1", start, scan_id)

    # Fast path: high-confidence block → skip Wall 2.
    # Requires clearing both the context block threshold AND the confidence floor,
    # so lenient contexts (web_scrape 0.90) are not auto-blocked below their cutoff
    # and strict contexts (user_input 0.50) still get a Wall 2 review in the mid band.
    if w1.score >= max(_FAST_BLOCK_FLOOR, block_t):
        log.info("scanner.blocked_wall1", scan_id=scan_id, score=w1.score,
                 threats=w1.threats, context=request.context)
        return _make_response("block", w1, "wall1", start, scan_id)

    # Uncertain zone → Wall 2
    w2 = await wall2.orchestrator.scan(request)
    log.debug("scanner.wall2", score=w2.score, threats=w2.threats)

    combined_score = round((w1.score * 0.4) + (w2.score * 0.6), 3)
    combined_threats = list(set(w1.threats + w2.threats))
    action = _action(combined_score, block_t, warn_t)

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
