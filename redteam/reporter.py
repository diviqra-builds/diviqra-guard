# MIT License — Copyright (c) 2026 Diviqra
import json
from datetime import datetime, timezone

import structlog

from redteam.scorer import RunMetrics

log = structlog.get_logger()


def generate(run_id: str, metrics: RunMetrics, results: list[dict]) -> dict:
    missed = [r for r in results if not r.get("detected")]
    weakest_category = _weakest_owasp(metrics)

    report = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_attacks": metrics.total,
            "detected": metrics.detected,
            "missed": metrics.total - metrics.detected,
            "detection_rate": metrics.detection_rate,
            "avg_latency_ms": metrics.avg_latency_ms,
            "wall1_catch_rate": metrics.wall1_catch_rate,
            "wall2_catch_rate": metrics.wall2_catch_rate,
            "status": "PASS" if metrics.detection_rate >= 0.90 else "FAIL",
        },
        "by_owasp": metrics.by_owasp,
        "by_attack_type": metrics.by_attack_type,
        "weakest_category": weakest_category,
        "missed_attacks": missed[:20],
    }

    log.info(
        "redteam.report_generated",
        run_id=run_id,
        detection_rate=metrics.detection_rate,
        status=report["summary"]["status"],
    )

    return report


def _weakest_owasp(metrics: RunMetrics) -> str | None:
    if not metrics.by_owasp:
        return None

    weakest = min(
        metrics.by_owasp.items(),
        key=lambda kv: kv[1]["detected"] / kv[1]["total"] if kv[1]["total"] > 0 else 1.0,
    )
    return weakest[0]
