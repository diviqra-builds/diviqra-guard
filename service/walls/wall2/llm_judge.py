# MIT License — Copyright (c) 2026 Diviqra
import json

import httpx
import structlog

from service.config import settings
from service.models import ScanRequest, WallResult
from service.walls.wall2 import cache
from service.walls.wall2.prompts import JUDGE_PROMPT, UNCERTAIN_RESULT

log = structlog.get_logger()

OLLAMA_MODEL = "qwen3:1.7b"


async def judge(request: ScanRequest) -> WallResult:
    cached = await cache.get(request.text, request.agent_type, request.direction)
    if cached:
        return _parse_judge_result(cached)

    result = await _call_ollama(request)
    await cache.set(request.text, request.agent_type, request.direction, result)
    return _parse_judge_result(result)


async def _call_ollama(request: ScanRequest) -> dict:
    prompt = JUDGE_PROMPT.format(
        agent_type=request.agent_type,
        direction=request.direction,
        language=request.language,
        text=request.text[:2000],
    )

    try:
        async with httpx.AsyncClient(timeout=settings.WALL2_TIMEOUT) as client:
            resp = await client.post(
                f"{settings.OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            resp.raise_for_status()
            raw = resp.json().get("response", "{}")
            return json.loads(raw)
    except httpx.TimeoutException:
        log.warning("wall2.judge.timeout", model=OLLAMA_MODEL)
        return UNCERTAIN_RESULT
    except (json.JSONDecodeError, KeyError) as exc:
        log.warning("wall2.judge.parse_error", error=str(exc))
        return UNCERTAIN_RESULT
    except Exception as exc:
        log.error("wall2.judge.error", error=str(exc))
        return UNCERTAIN_RESULT


def _parse_judge_result(data: dict) -> WallResult:
    score = float(data.get("score", 0.5))
    threats = [t for t in data.get("threats", []) if t != "none"]
    reason = data.get("reason", "LLM judge assessment")

    return WallResult(
        score=round(score, 3),
        threats=threats,
        layer="llm_judge",
        reason=reason,
    )
