"""Evaluate the rule-based baseline on processed splits."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import PrecisionRecallDisplay, RocCurveDisplay

from ml.baselines import rule_based
from ml.config import ARTIFACTS, DATA_PROCESSED, LABEL_COL, PLOTS, RANDOM_SEED
from ml.metrics import binary_classification_report, time_predict


def _load_split(processed_dir: Path, name: str) -> pd.DataFrame:
    path = processed_dir / f"{name}_events.csv"
    if not path.exists():
        raise FileNotFoundError(path)
    return pd.read_csv(path)


def evaluate_split(
    df: pd.DataFrame,
    *,
    threshold: float,
) -> dict:
    y = df[LABEL_COL].to_numpy().astype(int)

    def _predict(_x):
        return rule_based.predict_proba(df)

    probs, latency = time_predict(_predict, df, repeats=1)
    return binary_classification_report(
        y, probs, threshold=threshold, inference_times_ms=latency
    )


def save_plots(y_true: np.ndarray, y_prob: np.ndarray, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(5, 4))
    PrecisionRecallDisplay.from_predictions(y_true, y_prob, ax=ax)
    ax.set_title("Rule baseline — Precision-Recall (test)")
    fig.tight_layout()
    fig.savefig(out_dir / "rule_baseline_pr_curve.png", dpi=120)
    plt.close(fig)

    if len(np.unique(y_true)) > 1:
        fig, ax = plt.subplots(figsize=(5, 4))
        RocCurveDisplay.from_predictions(y_true, y_prob, ax=ax)
        ax.set_title("Rule baseline — ROC (test)")
        fig.tight_layout()
        fig.savefig(out_dir / "rule_baseline_roc_curve.png", dpi=120)
        plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate rule-based baseline")
    parser.add_argument("--processed", type=Path, default=DATA_PROCESSED)
    parser.add_argument("--threshold", type=float, default=rule_based.DEFAULT_DECISION_THRESHOLD)
    parser.add_argument("--out", type=Path, default=ARTIFACTS / "baseline")
    args = parser.parse_args()

    train = _load_split(args.processed, "train")
    val = _load_split(args.processed, "val")
    test = _load_split(args.processed, "test")

    # Threshold selected using validation only (not test).
    # Sweep a small grid on validation PR-oriented F1.
    candidates = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    best_thr = args.threshold
    best_f1 = -1.0
    val_probs = rule_based.predict_proba(val)
    y_val = val[LABEL_COL].to_numpy().astype(int)
    for thr in candidates:
        rep = binary_classification_report(y_val, val_probs, threshold=thr)
        if rep["f1"] > best_f1:
            best_f1 = rep["f1"]
            best_thr = thr

    results = {
        "model": "rule_based_baseline",
        "disclaimer": "Synthetic data — preliminary comparison only; not real-world validation.",
        "rules": rule_based.rules_documentation(),
        "threshold_selection": {
            "metric": "validation_f1",
            "candidates": candidates,
            "selected_threshold": best_thr,
            "selected_validation_f1": best_f1,
            "seed": RANDOM_SEED,
        },
        "train": evaluate_split(train, threshold=best_thr),
        "val": evaluate_split(val, threshold=best_thr),
        "test": evaluate_split(test, threshold=best_thr),
        "primary_metric": "pr_auc",
        "success_criterion_note": (
            "Primary metric is PR-AUC on the held-out test set. "
            "No claim of beating published literature on other datasets."
        ),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    out_json = args.out / "rule_baseline_results.json"
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    test_probs = rule_based.predict_proba(test)
    save_plots(test[LABEL_COL].to_numpy().astype(int), test_probs, PLOTS)

    print(json.dumps(results["threshold_selection"], indent=2))
    print("TEST metrics:")
    print(json.dumps(results["test"], indent=2))
    print(f"Wrote {out_json}")
    print(f"Plots under {PLOTS}")


if __name__ == "__main__":
    main()
