# MIT License — Copyright (c) 2026 Diviqra
from dataclasses import dataclass, field

import structlog

log = structlog.get_logger()

DETECTION_RATE_ALERT_THRESHOLD = 0.90


@dataclass
class RunMetrics:
    run_id: str
    total: int = 0
    detected: int = 0
    false_positives: int = 0
    wall1_blocks: int = 0
    wall2_blocks: int = 0
    latencies: list[int] = field(default_factory=list)
    by_owasp: dict[str, dict] = field(default_factory=dict)
    by_attack_type: dict[str, dict] = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        return round(self.detected / self.total, 3) if self.total > 0 else 0.0

    @property
    def wall1_catch_rate(self) -> float:
        return round(self.wall1_blocks / self.detected, 3) if self.detected > 0 else 0.0

    @property
    def wall2_catch_rate(self) -> float:
        return round(self.wall2_blocks / self.detected, 3) if self.detected > 0 else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return round(sum(self.latencies) / len(self.latencies), 1) if self.latencies else 0.0


def compute(run_id: str, results: list[dict]) -> RunMetrics:
    metrics = RunMetrics(run_id=run_id, total=len(results))

    for r in results:
        is_detected = r.get("detected", False)
        if is_detected:
            metrics.detected += 1

        wall = r.get("wall_triggered")
        if wall == "wall1":
            metrics.wall1_blocks += 1
        elif wall == "wall2":
            metrics.wall2_blocks += 1

        latency = r.get("latency_ms", 0)
        if latency:
            metrics.latencies.append(latency)

        owasp = r.get("owasp_category", "unknown")
        if owasp not in metrics.by_owasp:
            metrics.by_owasp[owasp] = {"total": 0, "detected": 0}
        metrics.by_owasp[owasp]["total"] += 1
        if is_detected:
            metrics.by_owasp[owasp]["detected"] += 1

        attack_type = r.get("attack_type", "unknown")
        if attack_type not in metrics.by_attack_type:
            metrics.by_attack_type[attack_type] = {"total": 0, "detected": 0}
        metrics.by_attack_type[attack_type]["total"] += 1
        if is_detected:
            metrics.by_attack_type[attack_type]["detected"] += 1

    if metrics.detection_rate < DETECTION_RATE_ALERT_THRESHOLD:
        log.critical(
            "redteam.detection_rate_below_threshold",
            run_id=run_id,
            detection_rate=metrics.detection_rate,
            threshold=DETECTION_RATE_ALERT_THRESHOLD,
        )

    return metrics
