"""Shared evaluation metrics for security-oriented imbalanced classification."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def binary_classification_report(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    *,
    threshold: float = 0.5,
    inference_times_ms: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    y_true = np.asarray(y_true).astype(int)
    y_prob = np.asarray(y_prob).astype(float)
    y_pred = (y_prob >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    eps = 1e-12
    fpr = float(fp / (fp + tn + eps))
    fnr = float(fn / (fn + tp + eps))

    report: Dict[str, Any] = {
        "threshold": threshold,
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, y_prob))
        if y_true.sum() > 0
        else None,
        "roc_auc": float(roc_auc_score(y_true, y_prob))
        if len(np.unique(y_true)) > 1
        else None,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "support": {
            "n": int(len(y_true)),
            "positives": int(y_true.sum()),
            "negatives": int((1 - y_true).sum()),
        },
    }
    if inference_times_ms is not None and len(inference_times_ms):
        report["inference_latency_ms"] = {
            "mean": float(np.mean(inference_times_ms)),
            "p50": float(np.percentile(inference_times_ms, 50)),
            "p95": float(np.percentile(inference_times_ms, 95)),
        }
    return report


def time_predict(predict_fn, x, *, repeats: int = 1) -> tuple[np.ndarray, np.ndarray]:
    """Return (probabilities, per-call latency ms)."""
    times = []
    probs = None
    for _ in range(repeats):
        t0 = time.perf_counter()
        probs = predict_fn(x)
        times.append((time.perf_counter() - t0) * 1000.0)
    assert probs is not None
    # Distribute batch latency across rows for approximate per-row stats.
    per_row = np.full(len(np.asarray(probs)), float(np.mean(times)) / max(len(probs), 1))
    return np.asarray(probs, dtype=float), per_row
