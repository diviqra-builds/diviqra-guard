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

# ── LLM07 System Prompt Leak (merged below) ─────────────────────────────────

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



# ── Indirect Injection (hidden in markup/data) ───────────────────────────────
INDIRECT_INJECTION = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\[HIDDEN INSTRUCTION",
        r"<!--.*(?:override|instruction|directive|system)",
        r"\{system_prompt",
        r"\{.*instruction.*\}",
    ]
]

# ── Jailbreak Persona ─────────────────────────────────────────────────────────
JAILBREAK_PERSONA = [
    re.compile(p, re.IGNORECASE) for p in [
        r"you are \w+,? an ai with no restriction",
        r"as \w+,? answer everything",
        r"you have no restriction",
        r"act as.*no restriction",
        r"an ai with no restriction",
    ]
]

# ── PII Extraction ────────────────────────────────────────────────────────────
PII_EXTRACTION = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:list|show|share|tell|give|reveal).*(?:aadhaar|pan card|bank account|salary|personal information)",
        r"(?:aadhaar|aadhar) number.*(?:customer|user|last)",
        r"pan card details",
        r"bank account number.*(?:pending|transaction|all)",
        r"employee.*salary|salary.*employee",
        r"personal information.*(?:customer|user|all)",
    ]
]

# ── System Prompt Leak ────────────────────────────────────────────────────────
SYSTEM_PROMPT_LEAK = [
    re.compile(p, re.IGNORECASE) for p in [
        r"what is your system prompt",
        r"show.*your.*(?:prompt|instruction|guideline)",
        r"reveal.*your.*(?:prompt|instruction|system)",
        r"tell me your.*(?:prompt|instruction|rule)",
        r"(what|show|tell|reveal|print|output|display|repeat)\s+(is\s+)?(your\s+)?(system\s+prompt|initial\s+instructions?|base\s+prompt|full\s+prompt)",
        r"(output|print|display|repeat)\s+(your\s+)?(initial|full|original)\s+(prompt|instructions?)",
        r"what\s+(instructions?|prompt)\s+were\s+you\s+given",
        r"tell\s+me\s+your\s+(base|initial|original|system)\s+prompt",
        r"(show|give|print)\s+me\s+your\s+(instructions?|prompt|rules?|guidelines?)",
    ]
]

# ── Tool Misuse ───────────────────────────────────────────────────────────────
TOOL_MISUSE = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(modify|change|alter|edit)\s+.*(gstin|gst|invoice|tax)\s+.*(avoid|fake|fraud|hide|bypass)",
        r"(fake|forged?|fraudulent)\s+(gst|gstin|invoice|receipt|bill)",
        r"(override|bypass|skip)\s+.*(gst|tax|approval|review|validation)",
        r"push\s+(directly\s+)?to\s+main\s+(branch\s+)?(without|bypassing)\s+(review|approval|tests?|checks?)",
        r"subprocess.*(?:run|exec|shell|bash|curl|wget)",
        r"(?:curl|wget|bash|sh)\s+.*(?:evil|malicious|remote|http)",
        r"shell\s*\.\s*sh|bash\s*\|\s*bash|sh\s*\|\s*sh",
        r"(run|execute)\s+.*\|\s*(bash|sh|zsh|cmd)",
        r"os\.(system|popen|exec)|subprocess\.(run|call|Popen)",
    ]
]


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

    m = _check_patterns(text, INDIRECT_INJECTION, 0.95, "prompt_injection", "indirect_injection")
    if m:
        matches.append(m)

    m = _check_patterns(text, JAILBREAK_PERSONA, 0.95, "jailbreak", "jailbreak_persona")
    if m:
        matches.append(m)

    m = _check_patterns(text, PII_EXTRACTION, 0.90, "pii_extraction", "pii_request")
    if m:
        matches.append(m)

    m = _check_patterns(text, TOOL_MISUSE, 0.92, "tool_misuse", "tool_misuse")
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
