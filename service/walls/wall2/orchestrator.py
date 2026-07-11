# MIT License — Copyright (c) 2026 Diviqra
import asyncio
from service.models import ScanRequest, WallResult
from service.walls.wall2 import llm_judge, intent_coherence


async def scan(request: ScanRequest) -> WallResult:
    # Run LLM judge + intent coherence scorer in parallel
    results = await asyncio.gather(
        llm_judge.judge(request),
        intent_coherence.scan(request),
        return_exceptions=True,
    )

    best = WallResult()
    all_threats = []

    for r in results:
        if isinstance(r, Exception):
            continue
        if isinstance(r, WallResult):
            all_threats.extend(r.threats)
            if r.score > best.score:
                best = r

    if not all_threats and best.score == 0:
        return WallResult()

    return WallResult(
        score=round(best.score, 3),
        threats=list(set(all_threats)),
        layer=best.layer,
        reason=best.reason,
    )
