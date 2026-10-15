"""Train LightGBM on session-event windows.

Phase 5 — Model B.

Design decisions
----------------
- Features: tabular session-window features from ml/config.py (TABULAR_FEATURES).
- Class imbalance: scale_pos_weight derived from training-set ratio.
- Threshold: swept on validation PR-oriented F1; final evaluation on held-out test.
- Early stopping: tracked on validation binary_logloss; no test leakage.
- Artifacts saved: model .txt, threshold .json, scaler .joblib (shared from preprocess).

DISCLAIMER: Synthetic data — preliminary comparison only.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import PrecisionRecallDisplay, RocCurveDisplay

from ml.config import (
    ARTIFACTS,
    DATA_PROCESSED,
    LABEL_COL,
    MODELS,
    PLOTS,
    RANDOM_SEED,
    TABULAR_FEATURES,
)
from ml.metrics import binary_classification_report, time_predict


def load_split(processed_dir: Path, name: str) -> pd.DataFrame:
    return pd.read_csv(processed_dir / f"{name}_events.csv")


def prepare_xy(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    x = df[TABULAR_FEATURES].astype(float).to_numpy()
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    y = df[LABEL_COL].to_numpy().astype(int)
    return x, y


def sweep_threshold(y_val: np.ndarray, probs_val: np.ndarray) -> tuple[float, float]:
    """Return best threshold and its validation F1 (PR-oriented)."""
    candidates = np.arange(0.10, 0.75, 0.05)
    best_thr, best_f1 = 0.5, -1.0
    for thr in candidates:
        rep = binary_classification_report(y_val, probs_val, threshold=float(thr))
        if rep["f1"] > best_f1:
            best_f1 = rep["f1"]
            best_thr = float(thr)
    return best_thr, best_f1


def save_curves(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    prefix: str,
    out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(5, 4))
    PrecisionRecallDisplay.from_predictions(y_true, y_prob, ax=ax)
    ax.set_title(f"LightGBM — Precision-Recall ({prefix})")
    fig.tight_layout()
    fig.savefig(out_dir / f"lgbm_pr_curve_{prefix}.png", dpi=120)
    plt.close(fig)

    if len(np.unique(y_true)) > 1:
        fig, ax = plt.subplots(figsize=(5, 4))
        RocCurveDisplay.from_predictions(y_true, y_prob, ax=ax)
        ax.set_title(f"LightGBM — ROC ({prefix})")
        fig.tight_layout()
        fig.savefig(out_dir / f"lgbm_roc_curve_{prefix}.png", dpi=120)
        plt.close(fig)


def train_lgbm(processed_dir: Path, out_dir: Path, seed: int = RANDOM_SEED) -> dict:
    train = load_split(processed_dir, "train")
    val = load_split(processed_dir, "val")
    test = load_split(processed_dir, "test")

    x_train, y_train = prepare_xy(train)
    x_val, y_val = prepare_xy(val)
    x_test, y_test = prepare_xy(test)

    # Class imbalance weight.
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    spw = float(n_neg / max(n_pos, 1))
    print(f"  Train: {len(y_train)} rows | pos={n_pos} neg={n_neg} | scale_pos_weight={spw:.2f}")

    lgb_train = lgb.Dataset(x_train, label=y_train, feature_name=list(TABULAR_FEATURES))
    lgb_val = lgb.Dataset(x_val, label=y_val, reference=lgb_train, feature_name=list(TABULAR_FEATURES))

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "learning_rate": 0.05,
        "num_leaves": 63,
        "min_child_samples": 20,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "scale_pos_weight": spw,
        "random_state": seed,
        "verbose": -1,
    }

    callbacks = [
        lgb.early_stopping(stopping_rounds=50, verbose=False),
        lgb.log_evaluation(period=50),
    ]

    t0 = time.perf_counter()
    booster = lgb.train(
        params,
        lgb_train,
        num_boost_round=600,
        valid_sets=[lgb_val],
        callbacks=callbacks,
    )
    train_time = time.perf_counter() - t0
    print(f"  Training time: {train_time:.1f}s | best_iter={booster.best_iteration}")

    # Threshold selection on validation (before test).
    probs_val = booster.predict(x_val, num_iteration=booster.best_iteration)
    best_thr, best_val_f1 = sweep_threshold(y_val, probs_val)
    print(f"  Best threshold={best_thr:.2f} (val F1={best_val_f1:.4f})")

    # Inference latency on test set.
    def _predict(x):
        return booster.predict(x, num_iteration=booster.best_iteration)

    probs_test, latency_ms = time_predict(_predict, x_test, repeats=3)
    probs_train = booster.predict(x_train, num_iteration=booster.best_iteration)

    results = {
        "model": "lightgbm",
        "disclaimer": "Synthetic data — preliminary comparison only.",
        "n_features": len(TABULAR_FEATURES),
        "features": list(TABULAR_FEATURES),
        "best_iteration": int(booster.best_iteration),
        "scale_pos_weight": round(spw, 4),
        "training_time_seconds": round(train_time, 2),
        "threshold_selection": {
            "metric": "validation_f1",
            "selected_threshold": best_thr,
            "selected_validation_f1": round(best_val_f1, 4),
        },
        "train": binary_classification_report(y_train, probs_train, threshold=best_thr),
        "val": binary_classification_report(y_val, probs_val, threshold=best_thr),
        "test": binary_classification_report(y_test, probs_test, threshold=best_thr, inference_times_ms=latency_ms),
        "primary_metric": "pr_auc",
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = MODELS / "lgbm_model.txt"
    MODELS.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(model_path))

    meta = {
        "threshold": best_thr,
        "best_iteration": int(booster.best_iteration),
        "features": list(TABULAR_FEATURES),
        "scale_pos_weight": round(spw, 4),
    }
    (MODELS / "lgbm_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    out_json = out_dir / "lgbm_results.json"
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    save_curves(y_test, probs_test, "test", PLOTS)
    save_curves(y_val, probs_val, "val", PLOTS)

    print(f"  Model -> {model_path}")
    print(f"  Results -> {out_json}")
    print("TEST metrics:")
    print(json.dumps(results["test"], indent=2))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Train LightGBM session-risk model")
    parser.add_argument("--processed", type=Path, default=DATA_PROCESSED)
    parser.add_argument("--out", type=Path, default=ARTIFACTS / "lgbm")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()

    print("=== Phase 5: LightGBM Training ===")
    train_lgbm(args.processed, args.out, seed=args.seed)


if __name__ == "__main__":
    main()
