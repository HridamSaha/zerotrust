"""ML model loading, inference, and risk scoring service.

Loads trained artifacts from ml/artifacts/models/ and provides a unified
predict() interface for the risk engine.

Risk score mapping (0-100)
--------------------------
The ML models output P(suspicious) in [0, 1].
We map this to a 0-100 risk score as:
    risk_score = probability * 100.0

Then policy thresholds (from settings) determine risk level:
    0-24   => low
    25-49  => medium
    50-74  => high
    75-100 => critical

This mapping is documented here and in the API. It is a provisional engineering
choice, not an experimentally validated security boundary.

Fallback strategy
-----------------
If a model artifact is unavailable, the service falls back to the rule-based
baseline so the system remains functional during early deployment phases.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Lazy imports for heavy ML dependencies — loaded once at first use.
_lgbm_booster = None
_lgbm_meta: Optional[Dict] = None
_gru_model = None
_gru_meta: Optional[Dict] = None
_hybrid_calibrated = None
_hybrid_meta: Optional[Dict] = None
_scaler_artifacts = None
_rule_based_loaded = False

# Project root relative to this file.
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_PROJECT_ROOT = _BACKEND_ROOT.parent
_MODELS_DIR = _PROJECT_ROOT / "ml" / "artifacts" / "models"
_PROCESSED_DIR = _PROJECT_ROOT / "ml" / "data" / "processed"

# Active model: "hybrid" | "lgbm" | "gru" | "rule_based"
ACTIVE_MODEL: str = "hybrid"

# Feature list must match ml/config.py TABULAR_FEATURES (same order).
TABULAR_FEATURES = [
    "failed_login_count",
    "requests_per_minute",
    "resource_sensitivity_mean",
    "resource_sensitivity_max",
    "device_trusted",
    "minutes_since_auth",
    "access_frequency",
    "unusual_context",
    "session_duration_minutes",
    "distinct_resources",
    "behavioral_deviation",
    "hour_of_day",
    "is_off_hours",
    "failed_auth_ratio",
    "sensitive_access_ratio",
    "event_burst_score",
    "event_index",
]

SEQUENCE_FEATURE_COLS = [
    "failed_login_count",
    "requests_per_minute",
    "resource_sensitivity_mean",
    "resource_sensitivity_max",
    "device_trusted",
    "unusual_context",
    "behavioral_deviation",
    "failed_auth_ratio",
    "sensitive_access_ratio",
    "event_burst_score",
]

SEQUENCE_LENGTH = 16


def _load_scaler():
    global _scaler_artifacts
    if _scaler_artifacts is None:
        artifact_path = _PROCESSED_DIR / "preprocess_artifacts.joblib"
        if artifact_path.exists():
            import joblib
            _scaler_artifacts = joblib.load(artifact_path)
            logger.info("Scaler artifacts loaded from %s", artifact_path)
        else:
            logger.warning("Scaler artifacts not found at %s — using raw features", artifact_path)
    return _scaler_artifacts


def _load_lgbm():
    global _lgbm_booster, _lgbm_meta
    if _lgbm_booster is None:
        model_path = _MODELS_DIR / "lgbm_model.txt"
        meta_path = _MODELS_DIR / "lgbm_meta.json"
        if model_path.exists():
            import lightgbm as lgb
            import json
            _lgbm_booster = lgb.Booster(model_file=str(model_path))
            if meta_path.exists():
                _lgbm_meta = json.loads(meta_path.read_text())
            logger.info("LightGBM model loaded from %s", model_path)
        else:
            logger.warning("LightGBM model not found at %s", model_path)
    return _lgbm_booster, _lgbm_meta


def _load_gru():
    global _gru_model, _gru_meta
    if _gru_model is None:
        model_path = _MODELS_DIR / "gru_model.pt"
        meta_path = _MODELS_DIR / "gru_meta.json"
        if model_path.exists():
            import json
            import torch
            # Add ml to sys.path for GRURiskModel import.
            import sys
            if str(_PROJECT_ROOT) not in sys.path:
                sys.path.insert(0, str(_PROJECT_ROOT))
            from ml.train_gru import GRURiskModel
            _gru_meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            arch = _gru_meta.get("architecture", {})
            _gru_model = GRURiskModel(
                input_dim=arch.get("input_dim", len(SEQUENCE_FEATURE_COLS)),
                hidden_dim=arch.get("hidden_dim", 64),
                num_layers=arch.get("num_layers", 2),
                dropout=arch.get("dropout", 0.3),
            )
            _gru_model.load_state_dict(
                torch.load(str(model_path), map_location="cpu")
            )
            _gru_model.eval()
            logger.info("GRU model loaded from %s", model_path)
        else:
            logger.warning("GRU model not found at %s", model_path)
    return _gru_model, _gru_meta


def _load_hybrid():
    global _hybrid_calibrated, _hybrid_meta
    if _hybrid_calibrated is None:
        model_path = _MODELS_DIR / "hybrid_calibrated.joblib"
        meta_path = _MODELS_DIR / "hybrid_meta.json"
        if model_path.exists():
            import joblib
            import json
            _hybrid_calibrated = joblib.load(model_path)
            if meta_path.exists():
                _hybrid_meta = json.loads(meta_path.read_text())
            logger.info("Hybrid model loaded from %s", model_path)
        else:
            logger.warning("Hybrid model not found at %s", model_path)
    return _hybrid_calibrated, _hybrid_meta


def _predict_rule_based(features: Dict[str, float]) -> Tuple[float, str]:
    """Rule-based fallback. Returns (probability, model_name)."""
    import sys
    if str(_PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(_PROJECT_ROOT))
    from ml.baselines.rule_based import score_frame
    import pandas as pd
    df = pd.DataFrame([features])
    # Fill any missing features with 0.
    for col in TABULAR_FEATURES:
        if col not in df.columns:
            df[col] = 0.0
    probs = score_frame(df)
    return float(probs[0]), "rule_based"


def _features_to_array(features: Dict[str, float]) -> np.ndarray:
    """Convert feature dict to ordered numpy array matching TABULAR_FEATURES."""
    arr = np.array(
        [float(features.get(col, 0.0)) for col in TABULAR_FEATURES],
        dtype=np.float32,
    ).reshape(1, -1)
    return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)


def _scale_features(arr: np.ndarray) -> np.ndarray:
    scaler = _load_scaler()
    if scaler is None:
        return arr
    try:
        return scaler.scaler.transform(arr)
    except Exception as e:
        logger.warning("Scaler transform failed: %s — using raw features", e)
        return arr


def _predict_lgbm(features: Dict[str, float]) -> float:
    booster, meta = _load_lgbm()
    if booster is None:
        return _predict_rule_based(features)[0]
    x = _features_to_array(features)
    # LightGBM was trained on raw (unscaled) features.
    best_iter = meta.get("best_iteration") if meta else None
    kwargs = {"num_iteration": best_iter} if best_iter else {}
    prob = float(booster.predict(x, **kwargs)[0])
    return np.clip(prob, 0.0, 1.0)


def _predict_gru(
    feature_sequence: List[Dict[str, float]],
) -> float:
    """Predict from a sequence of feature dicts (chronological order)."""
    gru, meta = _load_gru()
    if gru is None:
        return _predict_rule_based(feature_sequence[-1])[0]
    scaler = _load_scaler()

    try:
        import torch
        seq_len = SEQUENCE_LENGTH
        n_feats = len(SEQUENCE_FEATURE_COLS)
        seq_arr = np.zeros((seq_len, n_feats), dtype=np.float32)
        mask_arr = np.zeros(seq_len, dtype=np.float32)

        # Build the sequence from feature history.
        history = feature_sequence[-seq_len:]
        offset = seq_len - len(history)
        for i, feat in enumerate(history):
            row_full = np.array(
                [float(feat.get(col, 0.0)) for col in TABULAR_FEATURES],
                dtype=np.float32,
            ).reshape(1, -1)
            if scaler:
                row_full = scaler.scaler.transform(row_full)
            # Extract sequence feature columns.
            full_feat_names = scaler.feature_columns if scaler else TABULAR_FEATURES
            seq_indices = [
                full_feat_names.index(f)
                for f in SEQUENCE_FEATURE_COLS
                if f in full_feat_names
            ]
            row_seq = row_full[0, seq_indices]
            seq_arr[offset + i] = row_seq
            mask_arr[offset + i] = 1.0

        seq_t = torch.tensor(seq_arr, dtype=torch.float32).unsqueeze(0)
        mask_t = torch.tensor(mask_arr, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            logit = gru(seq_t, mask_t)
            prob = float(torch.sigmoid(logit).item())
        return np.clip(prob, 0.0, 1.0)
    except Exception as e:
        logger.error("GRU inference error: %s", e, exc_info=True)
        return _predict_rule_based(feature_sequence[-1])[0]


def predict(
    features: Dict[str, float],
    feature_history: Optional[List[Dict[str, float]]] = None,
    *,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Run risk inference and return probability + metadata.

    Parameters
    ----------
    features : current event feature dict
    feature_history : chronological list of past feature dicts (for GRU)
    model : override ACTIVE_MODEL; None uses ACTIVE_MODEL

    Returns
    -------
    dict with keys: probability, model_name, inference_latency_ms, explanation
    """
    chosen = (model or ACTIVE_MODEL).lower()
    history = feature_history or [features]
    if features not in history:
        history = history + [features]

    t0 = time.perf_counter()
    try:
        if chosen == "hybrid":
            lgbm_prob = _predict_lgbm(features)
            gru_prob = _predict_gru(history)
            calibrated, hmeta = _load_hybrid()
            if calibrated is not None:
                import numpy as _np
                X = _np.array([[lgbm_prob, gru_prob]])
                cal_prob = float(calibrated.predict_proba(X)[0, 1])
                blend_prob = 0.55 * lgbm_prob + 0.45 * gru_prob
                prob = max(cal_prob, blend_prob)
                model_name = "hybrid_lgbm_gru"
                explanation = (
                    f"Hybrid (stacking + blend): "
                    f"lgbm={lgbm_prob:.3f}, gru={gru_prob:.3f} -> score={prob * 100:.1f}"
                )
            else:
                # Fallback: average.
                prob = (lgbm_prob + gru_prob) / 2.0
                model_name = "hybrid_fallback"
                explanation = f"Hybrid average (calibrator not available): lgbm={lgbm_prob:.3f} gru={gru_prob:.3f}"
        elif chosen == "lgbm":
            prob = _predict_lgbm(features)
            model_name = "lightgbm"
            explanation = f"LightGBM P(suspicious)={prob:.3f}"
        elif chosen == "gru":
            prob = _predict_gru(history)
            model_name = "gru"
            explanation = f"GRU P(suspicious)={prob:.3f}"
        else:
            prob, model_name = _predict_rule_based(features)
            explanation = f"Rule-based score={prob:.3f}"

    except Exception as e:
        logger.error("Inference error (%s): %s — falling back to rule-based", chosen, e, exc_info=True)
        prob, model_name = _predict_rule_based(features)
        explanation = f"Fallback rule-based (error in {chosen}): {prob:.3f}"

    latency_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "probability": float(np.clip(prob, 0.0, 1.0)),
        "model_name": model_name,
        "inference_latency_ms": round(latency_ms, 3),
        "explanation": explanation,
    }


def probability_to_risk_score(probability: float) -> float:
    """Map [0, 1] probability to [0, 100] risk score (linear mapping).

    This is a provisional engineering choice. The mapping is documented in
    the module docstring and the API endpoint response schema.
    """
    return float(np.clip(probability * 100.0, 0.0, 100.0))


def risk_level_from_score(score: float, *, low_max: int = 24, medium_max: int = 49, high_max: int = 74) -> str:
    """Return risk level string from a 0-100 score."""
    if score <= low_max:
        return "low"
    if score <= medium_max:
        return "medium"
    if score <= high_max:
        return "high"
    return "critical"
