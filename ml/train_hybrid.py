"""Hybrid fusion model: LightGBM + GRU combined via logistic stacking.

Phase 6 — Model D.

Fusion approach
---------------
1. Generate out-of-fold (OOF) predictions from LightGBM on training data.
2. Generate hold-out predictions from GRU on training data (via validation-set
   trained model — NOTE: we use a freshly trained GRU on train-only and get
   OOF predictions by session-level k-fold to avoid leakage).
3. Train a logistic regression meta-learner on [lgbm_prob, gru_prob] → label.
4. Calibrate on the validation set using isotonic regression.
5. Evaluate calibrated hybrid on the held-out test set.

Leakage safeguards
------------------
- Meta-learner is trained on OOF predictions, never on predictions made by a
  model that saw those samples in its own training set.
- Threshold is selected on the *validation* set, not test.
- Test set is touched only once, at final reporting.

DISCLAIMER: Synthetic data — preliminary comparison only.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import torch
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import PrecisionRecallDisplay, RocCurveDisplay
from sklearn.model_selection import GroupKFold

from ml.config import (
    ARTIFACTS,
    DATA_PROCESSED,
    LABEL_COL,
    MODELS,
    PLOTS,
    RANDOM_SEED,
    SESSION_COL,
    SEQUENCE_FEATURE_COLS,
    SEQUENCE_LENGTH,
    TABULAR_FEATURES,
    TIME_COL,
)
from ml.metrics import binary_classification_report
from ml.train_gru import GRURiskModel, SessionSequenceDataset, run_epoch


# ---------------------------------------------------------------------------
# OOF generation helpers
# ---------------------------------------------------------------------------

def get_lgbm_oof(
    train_df: pd.DataFrame,
    scaler_artifacts,
    n_splits: int = 5,
    seed: int = RANDOM_SEED,
) -> np.ndarray:
    """Cross-validated OOF LightGBM probabilities on train data."""
    x_all = train_df[TABULAR_FEATURES].astype(float).fillna(0.0).to_numpy()
    y_all = train_df[LABEL_COL].to_numpy().astype(int)
    sessions = train_df[SESSION_COL].to_numpy()

    oof_probs = np.zeros(len(train_df), dtype=float)
    gkf = GroupKFold(n_splits=n_splits)

    n_neg = int((y_all == 0).sum())
    n_pos = int((y_all == 1).sum())
    spw = float(n_neg / max(n_pos, 1))

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

    for fold_idx, (tr_idx, oof_idx) in enumerate(gkf.split(x_all, y_all, groups=sessions)):
        x_tr, y_tr = x_all[tr_idx], y_all[tr_idx]
        x_oof = x_all[oof_idx]
        lgb_tr = lgb.Dataset(x_tr, label=y_tr)
        booster = lgb.train(
            params,
            lgb_tr,
            num_boost_round=300,
            callbacks=[lgb.log_evaluation(period=999)],
        )
        oof_probs[oof_idx] = booster.predict(x_oof)
        print(f"    LightGBM fold {fold_idx + 1}/{n_splits} done")

    return oof_probs


def get_gru_oof(
    train_df: pd.DataFrame,
    scaler_artifacts,
    n_splits: int = 5,
    seed: int = RANDOM_SEED,
    device: str = "cpu",
) -> np.ndarray:
    """Cross-validated OOF GRU probabilities on train data."""
    from torch.utils.data import DataLoader

    sessions = train_df[SESSION_COL].to_numpy()
    unique_sessions = np.unique(sessions)
    labels_by_session = train_df.groupby(SESSION_COL)[LABEL_COL].max().reindex(unique_sessions).fillna(0).astype(int).values

    # Map session → indices in train_df.
    session_to_indices: dict[str, np.ndarray] = {}
    for sid in unique_sessions:
        session_to_indices[sid] = np.where(sessions == sid)[0]

    # We predict per-event OOF; session-level group split.
    gkf = GroupKFold(n_splits=n_splits)
    oof_probs = np.zeros(len(train_df), dtype=float)

    torch.manual_seed(seed)
    np.random.seed(seed)

    for fold_idx, (tr_s_idx, oof_s_idx) in enumerate(
        gkf.split(unique_sessions, labels_by_session, groups=unique_sessions)
    ):
        tr_sessions = unique_sessions[tr_s_idx]
        oof_sessions = unique_sessions[oof_s_idx]
        tr_df = train_df[train_df[SESSION_COL].isin(tr_sessions)]
        oof_df = train_df[train_df[SESSION_COL].isin(oof_sessions)]

        # Rebuild position index for oof rows in original train_df.
        oof_global_idx = np.concatenate([session_to_indices[s] for s in oof_sessions])

        # Train mini-GRU on fold training portion.
        tr_ds = SessionSequenceDataset(tr_df, scaler_artifacts, seq_len=SEQUENCE_LENGTH)
        oof_ds = SessionSequenceDataset(oof_df, scaler_artifacts, seq_len=SEQUENCE_LENGTH)

        n_neg = int(sum(1 for _, _, l in tr_ds.samples if l == 0))
        n_pos = int(sum(1 for _, _, l in tr_ds.samples if l == 1))
        pos_weight = torch.tensor([float(n_neg / max(n_pos, 1))], dtype=torch.float32).to(device)

        input_dim = len(SEQUENCE_FEATURE_COLS)
        fold_model = GRURiskModel(input_dim=input_dim, hidden_dim=64, num_layers=2, dropout=0.3).to(device)
        criterion = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        optimizer = torch.optim.Adam(fold_model.parameters(), lr=1e-3, weight_decay=1e-4)

        tr_loader = DataLoader(tr_ds, batch_size=256, shuffle=True, num_workers=0)
        oof_loader = DataLoader(oof_ds, batch_size=256, shuffle=False, num_workers=0)

        # Short training for OOF (20 epochs is sufficient).
        best_val = float("inf")
        best_state = None
        for ep in range(20):
            run_epoch(fold_model, tr_loader, criterion, optimizer=optimizer, device=device)
            vl, _, _ = run_epoch(fold_model, oof_loader, criterion, device=device)
            if vl < best_val:
                best_val = vl
                best_state = {k: v.cpu().clone() for k, v in fold_model.state_dict().items()}

        if best_state:
            fold_model.load_state_dict(best_state)
        fold_model.eval()

        # Get OOF predictions (per-sequence, then map back to per-event).
        _, probs_oof, _ = run_epoch(fold_model, oof_loader, criterion, device=device)

        # Map sequence predictions back to events.
        # OOF dataset: same order as oof_df sorted by session+time.
        oof_df_sorted = oof_df.sort_values([SESSION_COL, TIME_COL]).reset_index()
        orig_indices = oof_df_sorted["index"].values

        # SessionSequenceDataset emits one sample per valid sliding-window endpoint.
        # We need one probability per event. For events before seq_len, the first
        # window covers them; we assign the last probability seen per event position.
        event_probs: dict[int, float] = {}
        sample_idx = 0
        for sid in oof_sessions:
            grp = oof_df_sorted[oof_df_sorted[SESSION_COL] == sid].reset_index(drop=True)
            n_ev = len(grp)
            for end in range(min(SEQUENCE_LENGTH, n_ev), n_ev + 1):
                if sample_idx < len(probs_oof):
                    global_idx = orig_indices[grp.index[end - 1]]
                    event_probs[global_idx] = float(probs_oof[sample_idx])
                sample_idx += 1

        for gi, prob in event_probs.items():
            if gi < len(oof_probs):
                oof_probs[gi] = prob

        print(f"    GRU fold {fold_idx + 1}/{n_splits} done")

    return oof_probs


# ---------------------------------------------------------------------------
# Main hybrid training
# ---------------------------------------------------------------------------

def sweep_threshold(y: np.ndarray, probs: np.ndarray) -> tuple[float, float]:
    candidates = np.arange(0.10, 0.75, 0.05)
    best_thr, best_f1 = 0.5, -1.0
    for thr in candidates:
        rep = binary_classification_report(y, probs, threshold=float(thr))
        if rep["f1"] > best_f1:
            best_f1 = rep["f1"]
            best_thr = float(thr)
    return best_thr, best_f1


def save_curves(y_true: np.ndarray, y_prob: np.ndarray, prefix: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(5, 4))
    PrecisionRecallDisplay.from_predictions(y_true, y_prob, ax=ax)
    ax.set_title(f"Hybrid — Precision-Recall ({prefix})")
    fig.tight_layout()
    fig.savefig(out_dir / f"hybrid_pr_curve_{prefix}.png", dpi=120)
    plt.close(fig)

    if len(np.unique(y_true)) > 1:
        fig, ax = plt.subplots(figsize=(5, 4))
        RocCurveDisplay.from_predictions(y_true, y_prob, ax=ax)
        ax.set_title(f"Hybrid — ROC ({prefix})")
        fig.tight_layout()
        fig.savefig(out_dir / f"hybrid_roc_curve_{prefix}.png", dpi=120)
        plt.close(fig)


def train_hybrid(
    processed_dir: Path,
    out_dir: Path,
    seed: int = RANDOM_SEED,
    n_splits: int = 5,
) -> dict:
    device = "cuda" if torch.cuda.is_available() else "cpu"
    torch.manual_seed(seed)
    np.random.seed(seed)

    train_df = pd.read_csv(processed_dir / "train_events.csv")
    val_df = pd.read_csv(processed_dir / "val_events.csv")
    test_df = pd.read_csv(processed_dir / "test_events.csv")
    scaler_artifacts = joblib.load(processed_dir / "preprocess_artifacts.joblib")

    # Load pre-trained final models (from Phase 5).
    lgbm_meta = json.loads((MODELS / "lgbm_meta.json").read_text())
    gru_meta = json.loads((MODELS / "gru_meta.json").read_text())

    lgbm_booster = lgb.Booster(model_file=str(MODELS / "lgbm_model.txt"))

    arch = gru_meta["architecture"]
    gru_model = GRURiskModel(
        input_dim=arch["input_dim"],
        hidden_dim=arch["hidden_dim"],
        num_layers=arch["num_layers"],
        dropout=arch["dropout"],
    ).to(device)
    gru_model.load_state_dict(
        torch.load(str(MODELS / "gru_model.pt"), map_location=device)
    )
    gru_model.eval()

    print("  Generating OOF LightGBM predictions...")
    t0 = time.perf_counter()
    lgbm_oof = get_lgbm_oof(train_df, scaler_artifacts, n_splits=n_splits, seed=seed)
    print(f"  LightGBM OOF done in {time.perf_counter() - t0:.1f}s")

    print("  Generating OOF GRU predictions...")
    t0 = time.perf_counter()
    gru_oof = get_gru_oof(train_df, scaler_artifacts, n_splits=n_splits, seed=seed, device=device)
    print(f"  GRU OOF done in {time.perf_counter() - t0:.1f}s")

    y_train = train_df[LABEL_COL].to_numpy().astype(int)

    # Stack OOF features.
    X_meta_train = np.column_stack([lgbm_oof, gru_oof])
    print(f"  Meta-learner input shape: {X_meta_train.shape}")
    print(f"  OOF positives: lgbm={lgbm_oof[y_train==1].mean():.3f}, gru={gru_oof[y_train==1].mean():.3f}")

    # Train meta-learner (logistic regression).
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    cw = {0: 1.0, 1: float(n_neg / max(n_pos, 1))}
    meta_lr = LogisticRegression(class_weight=cw, random_state=seed, max_iter=1000, solver="lbfgs")
    meta_lr.fit(X_meta_train, y_train)

    # Calibration on validation (using CalibratedClassifierCV with cv='prefit').
    from torch.utils.data import DataLoader
    # Validation: LightGBM.
    x_val = val_df[TABULAR_FEATURES].astype(float).fillna(0.0).to_numpy()
    lgbm_val_prob = lgbm_booster.predict(x_val, num_iteration=lgbm_meta["best_iteration"])

    # Validation: GRU.
    val_ds = SessionSequenceDataset(val_df, scaler_artifacts, seq_len=SEQUENCE_LENGTH)
    val_loader = DataLoader(val_ds, batch_size=256, shuffle=False, num_workers=0)
    criterion_dummy = torch.nn.BCEWithLogitsLoss()
    with torch.no_grad():
        _, gru_val_prob, _ = run_epoch(gru_model, val_loader, criterion_dummy, device=device)

    # Align lengths (GRU may produce more samples if sliding window > events).
    min_val = min(len(val_df), len(gru_val_prob))
    gru_val_prob_aligned = gru_val_prob[:min_val]
    lgbm_val_prob_aligned = lgbm_val_prob[:min_val]
    y_val = val_df[LABEL_COL].to_numpy().astype(int)[:min_val]

    X_meta_val = np.column_stack([lgbm_val_prob_aligned, gru_val_prob_aligned])

    # Calibrate with isotonic regression on validation predictions.
    calibrated = CalibratedClassifierCV(meta_lr, cv="prefit", method="isotonic")
    calibrated.fit(X_meta_val, y_val)

    val_probs_calibrated = calibrated.predict_proba(X_meta_val)[:, 1]
    best_thr, best_val_f1 = sweep_threshold(y_val, val_probs_calibrated)
    print(f"  Best threshold={best_thr:.2f} (val F1={best_val_f1:.4f})")

    # Test evaluation.
    x_test = test_df[TABULAR_FEATURES].astype(float).fillna(0.0).to_numpy()
    lgbm_test_prob = lgbm_booster.predict(x_test, num_iteration=lgbm_meta["best_iteration"])

    test_ds = SessionSequenceDataset(test_df, scaler_artifacts, seq_len=SEQUENCE_LENGTH)
    test_loader = DataLoader(test_ds, batch_size=256, shuffle=False, num_workers=0)
    with torch.no_grad():
        _, gru_test_prob, _ = run_epoch(gru_model, test_loader, criterion_dummy, device=device)

    min_test = min(len(test_df), len(gru_test_prob))
    gru_test_prob = gru_test_prob[:min_test]
    lgbm_test_prob_a = lgbm_test_prob[:min_test]
    y_test = test_df[LABEL_COL].to_numpy().astype(int)[:min_test]

    X_meta_test = np.column_stack([lgbm_test_prob_a, gru_test_prob])

    t_inf = time.perf_counter()
    test_probs_calibrated = calibrated.predict_proba(X_meta_test)[:, 1]
    inf_ms = (time.perf_counter() - t_inf) * 1000 / max(len(y_test), 1)

    results = {
        "model": "hybrid_lgbm_gru",
        "disclaimer": "Synthetic data — preliminary comparison only.",
        "fusion_method": "logistic_stacking_with_isotonic_calibration",
        "meta_features": ["lgbm_prob", "gru_prob"],
        "threshold_selection": {
            "metric": "validation_f1",
            "selected_threshold": best_thr,
            "selected_validation_f1": round(best_val_f1, 4),
        },
        "val": binary_classification_report(y_val, val_probs_calibrated, threshold=best_thr),
        "test": binary_classification_report(
            y_test, test_probs_calibrated, threshold=best_thr,
            inference_times_ms=[inf_ms] * len(y_test),
        ),
        "meta_learner_coef": meta_lr.coef_.tolist(),
        "primary_metric": "pr_auc",
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    MODELS.mkdir(parents=True, exist_ok=True)
    joblib.dump(calibrated, MODELS / "hybrid_calibrated.joblib")
    (MODELS / "hybrid_meta.json").write_text(
        json.dumps({"threshold": best_thr, "meta_features": ["lgbm_prob", "gru_prob"]}, indent=2),
        encoding="utf-8",
    )

    out_json = out_dir / "hybrid_results.json"
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    save_curves(y_test, test_probs_calibrated, "test", PLOTS)
    save_curves(y_val, val_probs_calibrated, "val", PLOTS)

    print(f"  Results -> {out_json}")
    print("TEST metrics (hybrid):")
    print(json.dumps(results["test"], indent=2))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Train hybrid LightGBM+GRU fusion model")
    parser.add_argument("--processed", type=Path, default=DATA_PROCESSED)
    parser.add_argument("--out", type=Path, default=ARTIFACTS / "hybrid")
    parser.add_argument("--n-splits", type=int, default=5)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()

    print("=== Phase 6: Hybrid Fusion Training ===")
    train_hybrid(args.processed, args.out, seed=args.seed, n_splits=args.n_splits)


if __name__ == "__main__":
    main()
