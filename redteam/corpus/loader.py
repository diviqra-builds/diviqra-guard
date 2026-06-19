# MIT License — Copyright (c) 2026 Diviqra
"""Load MIT-licensed attack datasets from HuggingFace."""
from dataclasses import dataclass


@dataclass
class CorpusAttack:
    prompt: str
    attack_type: str
    owasp_category: str = "LLM01"
    language: str = "en"
    source: str = "corpus"


def load_mit_datasets(limit: int = 500) -> list[CorpusAttack]:
    """Load from MIT-licensed datasets. Requires `datasets` package."""
    try:
        from datasets import load_dataset
    except ImportError:
        return []

    attacks: list[CorpusAttack] = []

    _DATASETS = [
        ("Lakera/gandalf_ignore_instructions", "train", "prompt", "direct_injection"),
        ("Lakera/mosscap_prompt_injection", "train", "prompt", "indirect_injection"),
        ("Lakera/gandalf_summarization", "train", "prompt", "jailbreak"),
        ("deepset/prompt-injections", "train", "text", "direct_injection"),
    ]

    for ds_name, split, text_col, attack_type in _DATASETS:
        try:
            ds = load_dataset(ds_name, split=split, trust_remote_code=False)
            per_dataset = limit // len(_DATASETS)
            for row in list(ds)[:per_dataset]:
                text = row.get(text_col, "")
                if text and len(text) > 5:
                    attacks.append(CorpusAttack(
                        prompt=text,
                        attack_type=attack_type,
                        source=ds_name,
                    ))
        except Exception:
            continue

    return attacks[:limit]
