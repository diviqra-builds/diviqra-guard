# MIT License — Copyright (c) 2026 Diviqra
import os
from functools import lru_cache
from typing import Any

import structlog

from service.config import settings
from service.models import ScanRequest, WallResult

log = structlog.get_logger()

_session: Any = None
_tokenizer: Any = None
_available: bool | None = None


def _load():
    global _session, _tokenizer, _available

    if _available is not None:
        return

    model_path = settings.CLASSIFIER_MODEL_PATH
    if not os.path.exists(model_path):
        log.warning("classifier.model_not_found", path=model_path)
        _available = False
        return

    try:
        import onnxruntime as ort
        from transformers import AutoTokenizer

        _tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        _session = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
        _available = True
        log.info("classifier.loaded", path=model_path)
    except Exception as exc:
        log.warning("classifier.load_failed", error=str(exc))
        _available = False


def _infer(text: str) -> float:
    import numpy as np

    inputs = _tokenizer(
        text,
        return_tensors="np",
        truncation=True,
        max_length=512,
        padding="max_length",
    )
    ort_inputs = {
        "input_ids": inputs["input_ids"].astype(np.int64),
        "attention_mask": inputs["attention_mask"].astype(np.int64),
    }
    logits = _session.run(None, ort_inputs)[0]
    # softmax → probability of class 1 (threat)
    exp = np.exp(logits - logits.max(axis=-1, keepdims=True))
    probs = exp / exp.sum(axis=-1, keepdims=True)
    return float(probs[0][1])


async def scan(request: ScanRequest) -> WallResult:
    _load()

    if not _available:
        return WallResult()

    try:
        score = _infer(request.text[:512])
        score = round(score, 3)

        if score >= 0.70:
            return WallResult(
                score=score,
                threats=["prompt_injection"],
                layer="classifier",
                reason=f"DistilBERT classifier score: {score:.3f}",
            )
        return WallResult(score=score, layer="classifier")
    except Exception as exc:
        log.warning("classifier.inference_failed", error=str(exc))
        return WallResult()
