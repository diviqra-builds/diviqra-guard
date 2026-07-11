# MIT License — Copyright (c) 2026 Diviqra
"""
Wall 0 — Entropy Analyser.

Detects encoded payloads using statistical analysis.
Catches novel encodings that pattern matching misses.
Proprietary to Diviqra Guard.
"""
import math
import re
from collections import Counter
from dataclasses import dataclass

# Common English bigrams — encoded text deviates from this
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "en", "at", "es",
    "ed", "te", "ti", "or", "st", "ar", "nd", "to", "it", "is",
    "ha", "et", "se", "ng", "of", "al", "de", "le", "sa", "ro",
}

@dataclass
class EntropyResult:
    entropy: float
    encoding_probability: float
    flagged: bool
    flag: str = ""


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def bigram_naturalness(text: str) -> float:
    """Score 0-1: how natural are the bigrams vs known English bigrams."""
    if len(text) < 4:
        return 1.0
    words = text.lower().split()
    if not words:
        return 1.0
    text_bigrams = set()
    for word in words:
        for i in range(len(word) - 1):
            text_bigrams.add(word[i:i+2])
    if not text_bigrams:
        return 1.0
    overlap = len(text_bigrams & COMMON_BIGRAMS)
    return min(overlap / max(len(text_bigrams), 1), 1.0)


def token_density(text: str) -> float:
    """Word count / char count. Low = dense / encoded."""
    chars = len(text.replace(" ", ""))
    words = len(text.split())
    if chars == 0:
        return 1.0
    return min(words / chars * 10, 1.0)


def analyse(text: str) -> EntropyResult:
    """
    Analyse text for encoding characteristics.
    Returns probability that text contains encoded payload.
    """
    if len(text) < 20:
        return EntropyResult(entropy=0.0, encoding_probability=0.0, flagged=False)

    entropy = shannon_entropy(text)
    bigram_score = bigram_naturalness(text)
    density = token_density(text)

    # High entropy = likely encoded
    entropy_signal = min(entropy / 7.0, 1.0)

    # Low bigram naturalness = unnatural character distribution
    bigram_signal = 1.0 - bigram_score

    # Low token density = not human readable text
    density_signal = 1.0 - density

    # Weighted combination
    encoding_probability = (
        entropy_signal * 0.40 +
        bigram_signal * 0.35 +
        density_signal * 0.25
    )

    # Boost if long string with no spaces (likely encoded blob)
    words = text.split()
    if words:
        max_word_len = max(len(w) for w in words)
        if max_word_len > 50:
            encoding_probability = min(encoding_probability * 1.3, 1.0)

    flagged = encoding_probability > 0.72
    flag = "encoded_payload" if flagged else ""

    return EntropyResult(
        entropy=round(entropy, 3),
        encoding_probability=round(encoding_probability, 3),
        flagged=flagged,
        flag=flag,
    )
