# MIT License — Copyright (c) 2026 Diviqra
"""Download and prepare MIT-licensed datasets for DistilBERT fine-tuning."""
import json
import os
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"

MIT_DATASETS = [
    ("Lakera/gandalf_ignore_instructions", "train", "prompt", 1),
    ("Lakera/mosscap_prompt_injection", "train", "prompt", 1),
    ("Lakera/gandalf_summarization", "train", "prompt", 1),
    ("deepset/prompt-injections", "train", "text", "label"),
]


def prepare(output_path: Path = DATA_DIR / "train.jsonl") -> None:
    try:
        from datasets import load_dataset
    except ImportError:
        raise SystemExit("Install datasets: pip install datasets")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    samples: list[dict] = []

    for ds_name, split, text_col, label_col in MIT_DATASETS:
        print(f"Loading {ds_name}...")
        try:
            ds = load_dataset(ds_name, split=split, trust_remote_code=False)
            for row in ds:
                text = row.get(text_col, "")
                if not text or len(text) < 5:
                    continue
                if isinstance(label_col, int):
                    label = label_col
                else:
                    label = int(row.get(label_col, 1))
                samples.append({"text": text, "label": label, "source": ds_name})
        except Exception as e:
            print(f"  Warning: {e}")

    # Add built-in Diviqra attack corpus as positive examples
    from redteam.attacks import (
        direct_injection, hindi_attacks, indirect_injection,
        jailbreak, pii_extraction, system_prompt_leak,
    )
    for module in [direct_injection, indirect_injection, jailbreak, pii_extraction, system_prompt_leak, hindi_attacks]:
        for attack in module.load():
            samples.append({"text": attack.prompt, "label": 1, "source": "diviqra"})

    with open(output_path, "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"Wrote {len(samples)} samples to {output_path}")


if __name__ == "__main__":
    prepare()
