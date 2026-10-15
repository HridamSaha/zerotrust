"""Orchestrate Phase 5: train LightGBM -> train GRU -> compare results."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.config import ARTIFACTS, DATA_PROCESSED  # noqa: E402
from ml.train_lgbm import train_lgbm  # noqa: E402
from ml.train_gru import train_gru  # noqa: E402


def run() -> None:
    print("=== Phase 5.1 LightGBM ===")
    lgbm_results = train_lgbm(DATA_PROCESSED, ARTIFACTS / "lgbm")

    print("\n=== Phase 5.2 GRU ===")
    gru_results = train_gru(DATA_PROCESSED, ARTIFACTS / "gru")

    # Compare on test set (primary metric: PR-AUC).
    summary = {
        "phase": 5,
        "disclaimer": "Synthetic data — preliminary comparison only.",
        "primary_metric": "pr_auc",
        "test_comparison": {
            "rule_baseline": _load_metric(ARTIFACTS / "baseline" / "rule_baseline_results.json"),
            "lightgbm": {
                "pr_auc": lgbm_results["test"].get("pr_auc"),
                "f1": lgbm_results["test"].get("f1"),
                "recall": lgbm_results["test"].get("recall"),
                "precision": lgbm_results["test"].get("precision"),
                "roc_auc": lgbm_results["test"].get("roc_auc"),
                "fpr": lgbm_results["test"].get("false_positive_rate"),
                "inference_latency_ms_mean": lgbm_results["test"].get("inference_latency_ms", {}).get("mean"),
            },
            "gru": {
                "pr_auc": gru_results["test"].get("pr_auc"),
                "f1": gru_results["test"].get("f1"),
                "recall": gru_results["test"].get("recall"),
                "precision": gru_results["test"].get("precision"),
                "roc_auc": gru_results["test"].get("roc_auc"),
                "fpr": gru_results["test"].get("false_positive_rate"),
                "inference_latency_ms_mean": gru_results["test"].get("inference_latency_ms", {}).get("mean"),
            },
        },
    }

    out = ARTIFACTS / "phase5_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nPhase 5 comparison -> {out}")
    print(json.dumps(summary["test_comparison"], indent=2))


def _load_metric(path: Path) -> dict:
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        test = data.get("test", {})
        return {
            "pr_auc": test.get("pr_auc"),
            "f1": test.get("f1"),
            "recall": test.get("recall"),
            "precision": test.get("precision"),
            "roc_auc": test.get("roc_auc"),
            "fpr": test.get("false_positive_rate"),
        }
    return {}


if __name__ == "__main__":
    run()
