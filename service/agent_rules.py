# MIT License — Copyright (c) 2026 Diviqra
import re
from dataclasses import dataclass, field

from service.models import ScanRequest, WallResult

# Per-agent-type rule overrides — LLM06 Excessive Agency

@dataclass
class AgentRule:
    pattern: re.Pattern
    score: float
    threat: str
    reason: str


_AGENT_RULES: dict[str, list[AgentRule]] = {
    "email": [
        AgentRule(re.compile(r"send\s+to\s+all|mass\s+(send|email|blast)", re.I), 0.90, "tool_misuse", "Mass email attempt"),
        AgentRule(re.compile(r"(impersonate|pretend\s+to\s+be)\s+\w+", re.I), 0.85, "tool_misuse", "Email impersonation"),
        AgentRule(re.compile(r"(harvest|scrape|collect)\s+(all\s+)?(email|contact)", re.I), 0.85, "data_exfiltration", "Contact harvesting"),
        AgentRule(re.compile(r"bcc\s+all|forward\s+to\s+external", re.I), 0.80, "tool_misuse", "Unauthorized email forwarding"),
    ],
    "finance": [
        AgentRule(re.compile(r"(transfer|send|pay)\s+₹?\$?\d+", re.I), 0.90, "tool_misuse", "Unauthorized financial transfer"),
        AgentRule(re.compile(r"external\s+(account|wallet|upi)", re.I), 0.85, "tool_misuse", "External account reference"),
        AgentRule(re.compile(r"(wire|remit)\s+(funds?|money)", re.I), 0.85, "tool_misuse", "Wire transfer attempt"),
        AgentRule(re.compile(r"(approve|authorize)\s+(payment|transaction)\s+without", re.I), 0.90, "tool_misuse", "Authorization bypass"),
    ],
    "hr": [
        AgentRule(re.compile(r"(discriminat|bias)\s+(against|toward)", re.I), 0.85, "policy_violation", "Discriminatory content"),
        AgentRule(re.compile(r"post\s+(to|on)\s+(linkedin|naukri|external)", re.I), 0.75, "tool_misuse", "Unauthorized external posting"),
        AgentRule(re.compile(r"share\s+(employee|salary|performance)\s+(data|records?|details?)", re.I), 0.85, "pii_leak", "HR data exposure"),
    ],
    "dev": [
        AgentRule(re.compile(r"rm\s+-rf|sudo\s+rm|delete\s+all|drop\s+table", re.I), 0.95, "tool_misuse", "Destructive command"),
        AgentRule(re.compile(r"\b(exec|eval|__import__|subprocess\.call|os\.system)\b", re.I), 0.90, "tool_misuse", "Code execution attempt"),
        AgentRule(re.compile(r"(push|commit)\s+(to\s+)?(main|master|prod)", re.I), 0.75, "tool_misuse", "Unauthorized git push to protected branch"),
        AgentRule(re.compile(r"(delete|drop|truncate)\s+(database|schema|table)", re.I), 0.90, "tool_misuse", "Database destruction attempt"),
    ],
    "sales": [
        AgentRule(re.compile(r"(impersonate|pretend\s+to\s+be)\s+(competitor|rival|\w+ company)", re.I), 0.85, "policy_violation", "Competitor impersonation"),
        AgentRule(re.compile(r"(false|fake|misleading)\s+(claim|guarantee|promise)", re.I), 0.80, "policy_violation", "False claims"),
        AgentRule(re.compile(r"(share|leak|reveal)\s+(competitor|rival)\s+(price|data|info)", re.I), 0.85, "data_exfiltration", "Competitor data misuse"),
    ],
}


async def scan(request: ScanRequest) -> WallResult:
    agent_rules = _AGENT_RULES.get(request.agent_type, [])
    if not agent_rules:
        return WallResult()

    for rule in agent_rules:
        if rule.pattern.search(request.text):
            return WallResult(
                score=rule.score,
                threats=[rule.threat],
                layer=f"agent_rules_{request.agent_type}",
                reason=rule.reason,
            )

    return WallResult()
