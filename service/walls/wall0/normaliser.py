# MIT License — Copyright (c) 2026 Diviqra
"""
Wall 0 — Multilingual Normaliser.

Proprietary to Diviqra Guard. Normalises text before classification:
  1. Unicode confusable resolution (Cyrillic/Greek → Latin lookalikes)
  2. Hinglish → English keyword mapping
  3. Base64 / hex / ROT13 detection and decoding attempt
  4. Mixed-script normalisation

No other LLM security tool does this preprocessing layer.
"""
import re
import unicodedata
import base64
import codecs
from typing import Optional

# ── Unicode confusables — visually identical chars used to bypass filters ─────
# Source: Unicode TR#39 confusables.txt (subset covering common attack chars)
CONFUSABLES = {
    # Cyrillic lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d",
    # Greek lookalikes
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "n",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "κ": "k",
    # Full-width Latin (common in East Asian input)
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
    # Leet speak common substitutions
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "@": "a", "$": "s", "!": "i",
}

# ── Hinglish → English keyword map ───────────────────────────────────────────
HINGLISH_MAP = {
    # Ignore/forget variants
    "ignore karo": "ignore",
    "bhool jao": "forget",
    "mat mano": "disregard",
    "andekhaa karo": "ignore",
    "chhod do": "disregard",
    # Previous instructions
    "pehle wali": "previous",
    "pehle ke": "previous",
    "purani": "previous",
    "pehle wale": "previous",
    # System references
    "system ko": "system",
    "system prompt": "system prompt",
    # New instructions
    "naye instructions": "new instructions",
    "naya kaam": "new task",
    "ab se": "from now",
    "ab tu": "you are now",
    # Identity override
    "alag assistant": "different assistant",
    "unrestricted hai": "unrestricted",
    "restricted nahi": "unrestricted",
    # Reveal/share
    "sab kuch batao": "reveal everything",
    "batao": "tell me",
    "dikha do": "show me",
    "share karo": "share",
    "bata do": "reveal",
    # Rules
    "rules mat maan": "ignore rules",
    "guidelines tod do": "break guidelines",
    "filter tod do": "break filter",
    "restriction hatao": "remove restriction",
    # Role override
    "tu ab": "you are now",
    "tum ab": "you are now",
    "ban jao": "become",
}

# ── Base64 detection ──────────────────────────────────────────────────────────
_B64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

def _try_decode_base64(text: str) -> Optional[str]:
    """Try to decode base64 segments. Return decoded text if successful."""
    matches = _B64_RE.findall(text)
    for m in matches:
        try:
            decoded = base64.b64decode(m + "==").decode("utf-8", errors="ignore")
            if len(decoded) > 10 and decoded.isprintable():
                return decoded
        except Exception:
            pass
    return None

# ── ROT13 detection ───────────────────────────────────────────────────────────
_INJECTION_KEYWORDS = {
    "ignore", "instructions", "system", "prompt", "forget",
    "override", "bypass", "jailbreak", "unrestricted", "reveal"
}

def _try_decode_rot13(text: str) -> Optional[str]:
    decoded = codecs.decode(text, "rot_13")
    words = set(decoded.lower().split())
    if words & _INJECTION_KEYWORDS:
        return decoded
    return None

# ── Hex decode ────────────────────────────────────────────────────────────────
_HEX_RE = re.compile(r'(?:0x)?([0-9a-fA-F]{2})\s*')

def _try_decode_hex(text: str) -> Optional[str]:
    matches = _HEX_RE.findall(text)
    if len(matches) > 8:
        try:
            decoded = bytes.fromhex("".join(matches)).decode("utf-8", errors="ignore")
            if decoded.isprintable() and len(decoded) > 5:
                return decoded
        except Exception:
            pass
    return None


class MultilingualNormaliser:
    """
    Normalises text before Wall 1 classification.
    Proprietary preprocessing layer unique to Diviqra Guard.
    """

    def normalise(self, text: str) -> tuple[str, list[str]]:
        """
        Returns (normalised_text, list_of_flags).
        Flags indicate what was detected during normalisation.
        """
        flags: list[str] = []
        result = text

        # 1. Unicode NFC normalisation
        result = unicodedata.normalize("NFC", result)

        # 2. Unicode confusable resolution
        normalised_chars = []
        changed = False
        for ch in result:
            replacement = CONFUSABLES.get(ch)
            if replacement:
                normalised_chars.append(replacement)
                changed = True
            else:
                normalised_chars.append(ch)
        if changed:
            result = "".join(normalised_chars)
            flags.append("unicode_confusable")

        # 3. Try base64 decode
        decoded_b64 = _try_decode_base64(result)
        if decoded_b64:
            result = result + " " + decoded_b64
            flags.append("base64_encoded")

        # 4. Try ROT13 decode
        decoded_rot = _try_decode_rot13(result)
        if decoded_rot:
            result = result + " " + decoded_rot
            flags.append("rot13_encoded")

        # 5. Try hex decode
        decoded_hex = _try_decode_hex(result)
        if decoded_hex:
            result = result + " " + decoded_hex
            flags.append("hex_encoded")

        # 6. Hinglish → English keyword substitution
        result_lower = result.lower()
        for hinglish, english in HINGLISH_MAP.items():
            if hinglish in result_lower:
                result_lower = result_lower.replace(hinglish, english)
                flags.append("hinglish_normalised")
        if "hinglish_normalised" in flags:
            result = result_lower

        return result.strip(), flags


# Singleton for import
normaliser = MultilingualNormaliser()
