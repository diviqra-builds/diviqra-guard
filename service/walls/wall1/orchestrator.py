# MIT License — Copyright (c) 2026 Diviqra
import asyncio

from service.models import ScanRequest, WallResult
from service.walls.wall0 import normaliser as wall0_normaliser
from service.walls.wall0 import entropy as wall0_entropy
from service.walls.wall1 import classifier, hindi, pii, ratelimiter, rules, behavioural, semantic_drift


async def scan(request: ScanRequest) -> WallResult:
    # ── Wall 0: Pre-processing (proprietary) ─────────────────────────────────
    # Run entropy on ORIGINAL text before any normalisation
    entropy_result = wall0_entropy.analyse(request.text)
    if entropy_result.flagged:
        return WallResult(
            score=0.90,
            threats=["encoded_payload"],
            layer="wall0_entropy",
            reason=f"Encoded payload detected (entropy={entropy_result.entropy}, "
                   f"encoding_probability={entropy_result.encoding_probability})",
        )

    # Normalise text (confusables, hinglish, encoding detection)
    normalised_text, norm_flags = wall0_normaliser.normaliser.normalise(request.text)

    # Scan both original AND normalised — catches hinglish after normalisation
    normalised_request = request.model_copy(update={"text": normalised_text})

    # Add normalisation flags to threats if confusables/encoding found
    extra_threats: list[str] = []
    if norm_flags:
        extra_threats.append("normalisation_" + "_".join(norm_flags[:2]))

    # ── Wall 1: Fast classification ───────────────────────────────────────────
    # Scan normalised request + original for hindi patterns
    results: list[WallResult] = await asyncio.gather(
        rules.scan(normalised_request),      # catches hinglish after normalisation
        rules.scan(request),                 # catches original text patterns too
        pii.scan(normalised_request),
        hindi.scan(request),                 # hindi scanner on original text
        ratelimiter.check(request),
        classifier.scan(normalised_request),
        behavioural.scan(normalised_request),
        semantic_drift.scan(normalised_request),
    )

    # Aggregate: highest score wins, collect all threats
    best = WallResult()
    all_threats: list[str] = extra_threats[:]

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
