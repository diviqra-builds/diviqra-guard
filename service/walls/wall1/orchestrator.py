# MIT License — Copyright (c) 2026 Diviqra
import asyncio

from service.models import ScanRequest, WallResult
from service.walls.wall1 import classifier, hindi, pii, ratelimiter, rules


async def scan(request: ScanRequest) -> WallResult:
    results: list[WallResult] = await asyncio.gather(
        rules.scan(request),
        pii.scan(request),
        hindi.scan(request),
        ratelimiter.check(request),
        classifier.scan(request),
    )

    # Aggregate: highest score wins, collect all threats
    best = WallResult()
    all_threats: list[str] = []

    for r in results:
        all_threats.extend(r.threats)
        if r.score > best.score:
            best = r

    return WallResult(
        score=round(best.score, 3),
        threats=list(set(all_threats)),
        layer=best.layer,
        reason=best.reason,
    )
