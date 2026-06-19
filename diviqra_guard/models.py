# MIT License — Copyright (c) 2026 Diviqra
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    action: str
    score: float
    threats: list[str]
    reason: str
    latency_ms: int
    scan_id: str

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def warned(self) -> bool:
        return self.action == "warn"


@dataclass
class ScanRequest:
    text: str
    direction: str = "ingress"
    agent_type: str = "default"
    company_id: str = ""
    profile: str = "balanced"
    language: str = "en"
