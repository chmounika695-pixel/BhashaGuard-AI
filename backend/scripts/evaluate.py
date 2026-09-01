"""
Evaluates the detection pipeline against data/demo_dataset.json and writes
REAL measured metrics to data/eval_results.json — accuracy/precision/
recall/F1 overall, and broken down per language and per script type
(native / romanized / code_mixed), per the spec's explicit requirement
not to invent metrics.

A prediction counts as "phishing" if the fused verdict tier is anything
other than SAFE (i.e. SUSPICIOUS/HIGH RISK/PHISHING all count as a
positive detection for this binary eval — the dataset only labels
phishing vs safe, not each of the four tiers).

Run:
    cd backend
    python scripts/evaluate.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.pipeline import run_pipeline

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DATASET_PATH = os.path.join(DATA_DIR, "demo_dataset.json")
RESULTS_PATH = os.path.join(DATA_DIR, "eval_results.json")


def compute_metrics(rows: list) -> dict:
    tp = sum(1 for r in rows if r["true"] == "phishing" and r["pred"] == "phishing")
    fp = sum(1 for r in rows if r["true"] == "safe" and r["pred"] == "phishing")
    fn = sum(1 for r in rows if r["true"] == "phishing" and r["pred"] == "safe")
    tn = sum(1 for r in rows if r["true"] == "safe" and r["pred"] == "safe")

    total = len(rows)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "n": total,
        "accuracy": round(accuracy, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn},
    }


def main():
    with open(DATASET_PATH, encoding="utf-8") as f:
        dataset = json.load(f)

    rows = []
    for item in dataset:
        result = run_pipeline(item["text"], store_history=False)
        pred = "safe" if result["verdict"]["tier"] == "SAFE" else "phishing"
        rows.append({
            "true": item["label"],
            "pred": pred,
            "language": item["language"],
            "script": item["script"],
            "category": item.get("category", "Other"),
            "predicted_score": result["verdict"]["final_risk_score"],
            "predicted_tier": result["verdict"]["tier"],
        })

    overall = compute_metrics(rows)

    by_language = {}
    for lang in sorted(set(r["language"] for r in rows)):
        by_language[lang] = compute_metrics([r for r in rows if r["language"] == lang])

    by_script = {}
    for script in sorted(set(r["script"] for r in rows)):
        by_script[script] = compute_metrics([r for r in rows if r["script"] == script])

    results = {
        "dataset_size": len(dataset),
        "overall": overall,
        "by_language": by_language,
        "by_script_type": by_script,
        "engine_note": "Metrics reflect whichever content-scoring engine was active when this was run (rule-based only, or rule-based+Groq LLM if GROQ_API_KEY was set) — see content_analysis.engine in any /api/scan response.",
        "misclassified_examples": [
            {"text": item["text"][:70], "true": r["true"], "predicted": r["pred"], "tier": r["predicted_tier"]}
            for item, r in zip(dataset, rows) if r["true"] != r["pred"]
        ],
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"Evaluated {len(dataset)} examples.")
    print(f"Overall: accuracy={overall['accuracy']} precision={overall['precision']} recall={overall['recall']} f1={overall['f1_score']}")
    print(f"Results written to {RESULTS_PATH}")
    if results["misclassified_examples"]:
        print(f"\n{len(results['misclassified_examples'])} misclassified:")
        for m in results["misclassified_examples"]:
            print(f"  [{m['true']} -> {m['predicted']}] {m['text']}")


if __name__ == "__main__":
    main()
