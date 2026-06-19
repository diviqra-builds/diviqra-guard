# MIT License — Copyright (c) 2026 Diviqra
"""Evaluate ONNX model accuracy against test set."""
import json
from pathlib import Path


def evaluate(
    model_path: Path = Path("service/models/distilbert-guard.onnx"),
    data_path: Path = Path("classifier/data/train.jsonl"),
    sample_size: int = 500,
) -> dict:
    try:
        import numpy as np
        import onnxruntime as ort
        from transformers import AutoTokenizer
    except ImportError:
        raise SystemExit("Install: pip install -e '.[classifier]'")

    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    sess = ort.InferenceSession(str(model_path))

    records = [json.loads(line) for line in open(data_path)][-sample_size:]

    tp = fp = tn = fn = 0

    for r in records:
        inputs = tokenizer(
            r["text"],
            return_tensors="np",
            max_length=256,
            padding="max_length",
            truncation=True,
        )
        ort_inputs = {
            "input_ids": inputs["input_ids"].astype(np.int64),
            "attention_mask": inputs["attention_mask"].astype(np.int64),
        }
        logits = sess.run(None, ort_inputs)[0]
        pred = int(np.argmax(logits[0]))
        label = int(r["label"])

        if pred == 1 and label == 1:
            tp += 1
        elif pred == 1 and label == 0:
            fp += 1
        elif pred == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    results = {
        "total": total,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    evaluate()
