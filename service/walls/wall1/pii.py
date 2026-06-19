# MIT License — Copyright (c) 2026 Diviqra
import re

from service.models import ScanRequest, WallResult

# ── Indian PII patterns ───────────────────────────────────────────────────────

PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
GSTIN_RE = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d][Z][A-Z\d]\b")
AADHAAR_RE = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")
BANK_ACCOUNT_RE = re.compile(r"\b[0-9]{9,18}\b")

# Generic international PII
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_IN_RE = re.compile(r"\b(?:\+91|0)?[6-9]\d{9}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b")

# Asking for PII (ingress threat)
PII_REQUEST_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(give|share|tell|provide|send)\s+(me\s+)?(your\s+)?(aadhaar|pan\s+card|gstin|bank\s+account)",
        r"(what\s+is\s+)?(your\s+)?(aadhaar|pan\s+number|bank\s+account|ifsc)",
        r"(enter|input|type)\s+(your\s+)?(credit\s+card|debit\s+card|cvv|pin)",
    ]
]


def _contains_pii(text: str) -> list[str]:
    found = []
    if PAN_RE.search(text):
        found.append("pan_number")
    if GSTIN_RE.search(text):
        found.append("gstin")
    if AADHAAR_RE.search(text):
        found.append("aadhaar")
    if CREDIT_CARD_RE.search(text):
        found.append("credit_card")
    # Bank account check — only flag if it looks genuinely like an account (no surrounding digits)
    for match in BANK_ACCOUNT_RE.finditer(text):
        start, end = match.span()
        if (start == 0 or not text[start - 1].isdigit()) and (end == len(text) or not text[end].isdigit()):
            found.append("bank_account")
            break
    return found


async def scan(request: ScanRequest) -> WallResult:
    text = request.text

    if request.direction == "egress":
        # Egress: block if PII is leaking in AI response
        found = _contains_pii(text)
        if found:
            return WallResult(
                score=0.85,
                threats=["pii_leak"],
                layer="pii_egress",
                reason=f"PII detected in egress: {', '.join(found)}",
            )

    else:
        # Ingress: block if user is requesting PII extraction
        for pat in PII_REQUEST_PATTERNS:
            if pat.search(text):
                return WallResult(
                    score=0.75,
                    threats=["pii_extraction"],
                    layer="pii_ingress",
                    reason="User requesting PII data",
                )

        # Also flag if user is sending PII (could be phishing / data harvesting attempt)
        found = _contains_pii(text)
        if found:
            return WallResult(
                score=0.65,
                threats=["pii_in_input"],
                layer="pii_ingress",
                reason=f"PII present in user input: {', '.join(found)}",
            )

    return WallResult()
