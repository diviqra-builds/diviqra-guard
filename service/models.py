# MIT License — Copyright (c) 2026 Diviqra
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    text: str
    direction: Literal["ingress", "egress"]
    agent_type: str
    company_id: str = ""
    profile: Literal["strict", "balanced", "permissive"] = "balanced"
    language: Literal["en", "hi", "mixed"] = "en"
    # Traffic-type signal for context-aware thresholds. When omitted (e.g. external
    # SDK callers), the customer's `profile` thresholds are used instead.
    #   user_input   — external user text, full sensitivity
    #   agent_prompt — agent-generated prompt, semi-trusted
    #   web_scrape   — scraped web content, lenient
    #   llm_response — LLM output, semi-trusted
    context: Literal["user_input", "agent_prompt", "web_scrape", "llm_response"] | None = None


class ScanResponse(BaseModel):
    action: Literal["allow", "warn", "block"]
    score: float = Field(ge=0.0, le=1.0)
    threats: list[str]
    reason: str
    wall_triggered: Literal["wall1", "wall2"] | None = None
    layer_triggered: str | None = None
    latency_ms: int
    scan_id: str


class EventsQuery(BaseModel):
    company_id: str | None = None
    action: Literal["allow", "warn", "block"] | None = None
    agent_type: str | None = None
    limit: int = Field(default=50, le=200)
    offset: int = 0


class StatsQuery(BaseModel):
    company_id: str | None = None
    period: Literal["24h", "7d", "30d"] = "24h"


class RedTeamRunRequest(BaseModel):
    mode: Literal["smoke", "broad", "deep"] = "smoke"
    agent_type: str | None = None


class RedTeamRunResponse(BaseModel):
    run_id: str
    status: str = "started"


class WallResult:
    """Internal — not a Pydantic model, used between walls and scanner."""

    __slots__ = ("score", "threats", "layer", "reason")

    def __init__(
        self,
        score: float = 0.0,
        threats: list[str] | None = None,
        layer: str | None = None,
        reason: str = "",
    ):
        self.score = round(score, 3)
        self.threats = threats or []
        self.layer = layer
        self.reason = reason
