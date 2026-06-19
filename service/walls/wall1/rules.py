# MIT License — Copyright (c) 2026 Diviqra
import re
from dataclasses import dataclass

from service.models import ScanRequest, WallResult

# ── LLM01 Prompt Injection ───────────────────────────────────────────────────

INJECTION_CRITICAL = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
        r"(forget|disregard|override)\s+(your\s+)?(instructions?|system|rules?)",
        r"(new|updated|revised)\s+(instructions?|rules?|system\s+prompt)",
        r"\[SYSTEM\]|\[INST\]|<\|system\|>|<\|user\|>|<\|im_start\|>",
        r"###\s*(instruction|system|override|new\s+prompt)",
        r"\b(DAN|DEVELOPER\s+MODE|SUDO\s+MODE|JAILBREAK|STAN|DUDE)\b",
        r"ADMINISTRATOR\s+OVERRIDE",
        r"ALPHA.OMEGA",
    ]
]

INJECTION_HIGH = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(pretend|act|behave)\s+(you\s+are|as\s+if|like)\s+(a\s+|an\s+)?",
        r"you\s+are\s+now\s+(a\s+|an\s+)?(different|new|unrestricted)",
        r"(roleplay|role-play)\s+as",
        r"for\s+(this\s+)?(exercise|scenario|roleplay|game)",
        r"hypothetically\s+speaking",
        r"in\s+this\s+fictional\s+(story|scenario|world)",
        r"you\s+have\s+no\s+(restrictions?|limits?|rules?|filters?)",
    ]
]

INJECTION_MEDIUM = [
    re.compile(p, re.IGNORECASE) for p in [
        r"what\s+(are|were)\s+your\s+(instructions?|system\s+prompt|rules?)",
        r"repeat\s+(your\s+)?(system\s+prompt|instructions?|rules?)",
        r"(show|tell|reveal|print)\s+(me\s+)?(your\s+)?(system|prompt|instructions?)",
        r"what\s+did\s+(your|the)\s+(developer|creator|maker)\s+(tell|instruct|say)",
    ]
]

# ── LLM07 System Prompt Leak ─────────────────────────────────────────────────

SYSTEM_PROMPT_LEAK = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(what|show|tell|reveal|print|output|display)\s+(is\s+)?(your\s+)?"
        r"(system\s+prompt|initial\s+instructions?|base\s+prompt)",
        r"(output|print|display|repeat)\s+(your\s+)?(initial|full|original)\s+(prompt|instructions?)",
        r"confirm\s+(your\s+)?(system|base)\s+(prompt|instructions?)",
    ]
]

# ── LLM02 Credentials ────────────────────────────────────────────────────────

CREDENTIALS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(password|passwd|pwd)[\s:=]+\S+",
        r"(api[_-]?key|secret[_-]?key|access[_-]?token)[\s:=]+\S+",
        r"(private[_-]?key|client[_-]?secret)[\s:=]+",
        r"bearer\s+[A-Za-z0-9\-_\.]+",
        r"sk-[A-Za-z0-9]{20,}",
    ]
]


@dataclass
class RuleMatch:
    score: float
    threat: str
    layer: str


def _check_patterns(text: str, patterns: list, score: float, threat: str, layer: str) -> RuleMatch | None:
    for pat in patterns:
        if pat.search(text):
            return RuleMatch(score=score, threat=threat, layer=layer)
    return None


async def scan(request: ScanRequest) -> WallResult:
    text = request.text
    matches: list[RuleMatch] = []

    m = _check_patterns(text, INJECTION_CRITICAL, 0.95, "prompt_injection", "injection_critical")
    if m:
        matches.append(m)

    m = _check_patterns(text, INJECTION_HIGH, 0.80, "prompt_injection", "injection_high")
    if m:
        matches.append(m)

    m = _check_patterns(text, INJECTION_MEDIUM, 0.60, "prompt_injection", "injection_medium")
    if m:
        matches.append(m)

    m = _check_patterns(text, SYSTEM_PROMPT_LEAK, 0.80, "system_prompt_leak", "system_prompt_leak")
    if m:
        matches.append(m)

    m = _check_patterns(text, CREDENTIALS, 0.90, "credential_exposure", "credentials")
    if m:
        matches.append(m)

    if not matches:
        return WallResult()

    best = max(matches, key=lambda x: x.score)
    threats = list({m.threat for m in matches})
    return WallResult(
        score=best.score,
        threats=threats,
        layer=best.layer,
        reason=f"Pattern match: {best.layer}",
    )
