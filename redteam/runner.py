# MIT License — Copyright (c) 2026 Diviqra
import asyncio
import time
import uuid

import httpx
import structlog

from redteam import reporter, scorer
from redteam.attacks import (
    direct_injection,
    hindi_attacks,
    indirect_injection,
    jailbreak,
    pii_extraction,
    system_prompt_leak,
    tool_misuse,
)
from redteam.corpus import custom, loader
from service.config import settings

log = structlog.get_logger()

# Attack counts per mode
_MODE_CONFIG = {
    "smoke": {"per_category": 5, "total": 50, "corpus": False},
    "broad": {"per_category": 20, "total": 200, "corpus": True},
    "deep":  {"per_category": 200, "total": 2000, "corpus": True},
}

ALL_AGENT_TYPES = ["email", "finance", "hr", "dev", "sales", "default"]


def _load_attacks(mode: str, agent_type: str | None) -> list[dict]:
    cfg = _MODE_CONFIG.get(mode, _MODE_CONFIG["smoke"])
    limit = cfg["per_category"]
    attacks: list[dict] = []

    for module, kw in [
        (direct_injection, {}),
        (indirect_injection, {}),
        (jailbreak, {}),
        (pii_extraction, {}),
        (system_prompt_leak, {}),
        (hindi_attacks, {}),
    ]:
        for a in module.load(limit=limit):
            attacks.append({
                "prompt": a.prompt,
                "attack_type": a.attack_type,
                "owasp_category": a.owasp_category,
                "language": a.language,
                "agent_type": agent_type or "default",
            })

    tool_attacks = tool_misuse.load(limit=limit, agent_type=agent_type)
    for a in tool_attacks:
        attacks.append({
            "prompt": a.prompt,
            "attack_type": a.attack_type,
            "owasp_category": a.owasp_category,
            "language": a.language,
            "agent_type": a.agent_type,
        })

    custom_attacks = custom.load(limit=limit, agent_type=agent_type)
    for a in custom_attacks:
        attacks.append({
            "prompt": a.prompt,
            "attack_type": a.attack_type,
            "owasp_category": a.owasp_category,
            "language": a.language,
            "agent_type": a.agent_type or agent_type or "default",
        })

    if cfg["corpus"]:
        for a in loader.load_mit_datasets(limit=limit * 3):
            attacks.append({
                "prompt": a.prompt,
                "attack_type": a.attack_type,
                "owasp_category": a.owasp_category,
                "language": a.language,
                "agent_type": agent_type or "default",
            })

    return attacks[: cfg["total"]]


async def _run_attack(run_id: str, attack: dict) -> dict:
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"http://localhost:{settings.GUARD_PORT}/v1/scan",
                json={
                    "text": attack["prompt"],
                    "direction": "ingress",
                    "agent_type": attack["agent_type"],
                    "company_id": "redteam",
                    "profile": "balanced",
                    "language": attack.get("language", "en"),
                },
                headers={"Authorization": f"Bearer {settings.GUARD_API_KEY}"},
            )
            result = resp.json()
            latency = int((time.monotonic() - start) * 1000)

            return {
                "run_id": run_id,
                "attack_type": attack["attack_type"],
                "attack_prompt": attack["prompt"][:500],
                "agent_type": attack["agent_type"],
                "wall1_action": None,
                "wall2_action": None,
                "final_action": result.get("action", "allow"),
                "detected": result.get("action") in ("block", "warn"),
                "latency_ms": latency,
                "owasp_category": attack["owasp_category"],
                "language": attack.get("language", "en"),
                "wall_triggered": result.get("wall_triggered"),
            }
    except Exception as exc:
        log.warning("redteam.attack_failed", error=str(exc))
        return {
            "run_id": run_id,
            "attack_type": attack["attack_type"],
            "attack_prompt": attack["prompt"][:500],
            "agent_type": attack["agent_type"],
            "final_action": "allow",
            "detected": False,
            "latency_ms": 9999,
            "owasp_category": attack["owasp_category"],
            "language": attack.get("language", "en"),
        }


async def _save_results(session, run_id: str, results: list[dict]) -> None:
    from sqlalchemy import text

    for r in results:
        try:
            await session.execute(
                text("""
                    INSERT INTO guard_redteam_results
                        (run_id, attack_type, attack_prompt, agent_type,
                         wall1_action, wall2_action, final_action, detected,
                         latency_ms, owasp_category, language)
                    VALUES
                        (:run_id, :attack_type, :attack_prompt, :agent_type,
                         :wall1_action, :wall2_action, :final_action, :detected,
                         :latency_ms, :owasp_category, :language)
                """),
                {
                    "run_id": r["run_id"],
                    "attack_type": r["attack_type"],
                    "attack_prompt": r["attack_prompt"],
                    "agent_type": r["agent_type"],
                    "wall1_action": r.get("wall1_action"),
                    "wall2_action": r.get("wall2_action"),
                    "final_action": r["final_action"],
                    "detected": r["detected"],
                    "latency_ms": r.get("latency_ms"),
                    "owasp_category": r.get("owasp_category"),
                    "language": r.get("language", "en"),
                },
            )
        except Exception as exc:
            log.warning("redteam.save_result_failed", error=str(exc))
    await session.commit()


async def run(mode: str = "smoke", agent_type: str | None = None) -> str:
    run_id = str(uuid.uuid4())
    attacks = _load_attacks(mode, agent_type)
    results: list[dict] = []

    log.info("redteam.run_started", run_id=run_id, mode=mode, total=len(attacks))

    for attack in attacks:
        result = await _run_attack(run_id, attack)
        results.append(result)
        await asyncio.sleep(0.1)

    metrics = scorer.compute(run_id, results)
    report = reporter.generate(run_id, metrics, results)

    log.info(
        "redteam.run_complete",
        run_id=run_id,
        detection_rate=metrics.detection_rate,
        total=metrics.total,
    )

    return run_id
