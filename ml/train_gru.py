"""GRU sequence model for session-risk classification.

Phase 5 — Model C.

Architecture
------------
Input:  (batch, seq_len=16, n_seq_features=10)
GRU:    2 layers, hidden_dim=64, dropout=0.3 between layers
Output: linear(64 → 1) with sigmoid → P(suspicious)

Sequence construction
---------------------
For each session, events are ordered chronologically.
Each event is represented by SEQUENCE_FEATURE_COLS (scaled).
Sessions with fewer than seq_len events are left-padded with zeros.
Sessions with more events use a sliding window (label = last token label).
A causal mask indicates padding positions so GRU loss excludes them.

Class imbalance: pos_weight in BCEWithLogitsLoss.
Validation used for early stopping (no test-set peeking until evaluation).
Preprocessing stats (scaler) come from the training-only fit (Phase 4).

DISCLAIMER: Synthetic data — preliminary comparison only.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
import matplotlib.pyplot as plt
from sklearn.metrics import PrecisionRecallDisplay, RocCurveDisplay

from ml.config import (
    ARTIFACTS,
    DATA_PROCESSED,
    LABEL_COL,
    MODELS,
    PLOTS,
    RANDOM_SEED,
    SEQUENCE_FEATURE_COLS,
    SEQUENCE_LENGTH,
    SESSION_COL,
    TIME_COL,
)
from ml.metrics import binary_classification_report, time_predict


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class SessionSequenceDataset(Dataset):
    """One sample per event-window; fixed-length, left-padded."""

    def __init__(
        self,
        df: pd.DataFrame,
        scaler_artifacts,
        seq_len: int = SEQUENCE_LENGTH,
    ):
        self.seq_len = seq_len
        self.features = SEQUENCE_FEATURE_COLS
        self.samples: list[tuple[np.ndarray, np.ndarray, int]] = []  # (seq, mask, label)

        sessions = df.sort_values([SESSION_COL, TIME_COL])
        for sid, grp in sessions.groupby(SESSION_COL):
            grp = grp.reset_index(drop=True)
            # Extract sequence features using scaler-transformed features.
            full_features = scaler_artifacts.feature_columns
            full_scaled = scaler_artifacts.scaler.transform(
                grp[full_features].astype(float).fillna(0.0).to_numpy()
            )
            # Map sequence feature indices.
            seq_indices = [full_features.index(f) for f in self.features if f in full_features]
            x_seq = full_scaled[:, seq_indices]

            labels = grp[LABEL_COL].to_numpy().astype(int)
            n = len(grp)

            # Sliding window with step=1; label = last event in window.
            for end in range(min(seq_len, n), n + 1):
                start = max(0, end - seq_len)
                chunk = x_seq[start:end]
                chunk_labels = labels[start:end]
                chunk_label = int(chunk_labels[-1])  # label at the endpoint

                # Pad left if needed.
                pad = seq_len - len(chunk)
                if pad > 0:
                    seq_arr = np.zeros((seq_len, len(self.features)), dtype=np.float32)
                    mask_arr = np.zeros(seq_len, dtype=np.float32)
                    seq_arr[pad:] = chunk.astype(np.float32)
                    mask_arr[pad:] = 1.0
                else:
                    seq_arr = chunk[-seq_len:].astype(np.float32)
                    mask_arr = np.ones(seq_len, dtype=np.float32)

                self.samples.append((seq_arr, mask_arr, chunk_label))

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int):
        seq, mask, label = self.samples[idx]
        return (
            torch.tensor(seq, dtype=torch.float32),
            torch.tensor(mask, dtype=torch.float32),
            torch.tensor(label, dtype=torch.float32),
        )


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class GRURiskModel(nn.Module):
    """Two-layer GRU for session behavioral risk."""

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 64,
        num_layers: int = 2,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.gru = nn.GRU(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(hidden_dim, 1)

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        # x: (B, T, F)
        out, _ = self.gru(x)  # (B, T, H)
        # Use last valid step (last non-padding position).
        if mask is not None:
            # mask: (B, T), 1 = valid, 0 = padding
            # For each sample, find index of last 1.
            lengths = mask.sum(dim=1).long()  # (B,)
            lengths = lengths.clamp(min=1)
            last_idx = (lengths - 1).unsqueeze(1).unsqueeze(2).expand(-1, 1, self.hidden_dim)
            last_hidden = out.gather(1, last_idx).squeeze(1)  # (B, H)
        else:
            last_hidden = out[:, -1, :]  # (B, H)
        logits = self.classifier(self.dropout(last_hidden)).squeeze(-1)  # (B,)
        return logits


# ---------------------------------------------------------------------------
# Training helpers
# ---------------------------------------------------------------------------

def run_epoch(
    model: GRURiskModel,
    loader: DataLoader,
    criterion,
    optimizer=None,
    device: str = "cpu",
) -> tuple[float, np.ndarray, np.ndarray]:
    training = optimizer is not None
    model.train() if training else model.eval()

    total_loss = 0.0
    all_probs: list[np.ndarray] = []
    all_labels: list[np.ndarray] = []

    ctx = torch.no_grad() if not training else torch.enable_grad()
    with ctx:
        for seq, mask, labels in loader:
            seq = seq.to(device)
            mask = mask.to(device)
            labels = labels.to(device)

            logits = model(seq, mask)
            loss = criterion(logits, labels)

            if training:
                optimizer.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
                optimizer.step()

            total_loss += loss.item() * len(labels)
            probs = torch.sigmoid(logits).detach().cpu().numpy()
            all_probs.append(probs)
            all_labels.append(labels.detach().cpu().numpy())

    n = sum(len(p) for p in all_probs)
    avg_loss = total_loss / max(n, 1)
    return avg_loss, np.concatenate(all_probs), np.concatenate(all_labels)


def sweep_threshold(y_val: np.ndarray, probs_val: np.ndarray) -> tuple[float, float]:
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
    ax.set_title(f"GRU — Precision-Recall ({prefix})")
    fig.tight_layout()
    fig.savefig(out_dir / f"gru_pr_curve_{prefix}.png", dpi=120)
    plt.close(fig)

    if len(np.unique(y_true)) > 1:
        fig, ax = plt.subplots(figsize=(5, 4))
        RocCurveDisplay.from_predictions(y_true, y_prob, ax=ax)
        ax.set_title(f"GRU — ROC ({prefix})")
        fig.tight_layout()
        fig.savefig(out_dir / f"gru_roc_curve_{prefix}.png", dpi=120)
        plt.close(fig)


# ---------------------------------------------------------------------------
# Main training routine
# ---------------------------------------------------------------------------

def train_gru(
    processed_dir: Path,
    out_dir: Path,
    seed: int = RANDOM_SEED,
    epochs: int = 40,
    batch_size: int = 256,
    hidden_dim: int = 64,
    num_layers: int = 2,
    dropout: float = 0.3,
    lr: float = 1e-3,
    patience: int = 8,
) -> dict:
    torch.manual_seed(seed)
    np.random.seed(seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"  Device: {device}")

    # Load data and preprocessing artifacts.
    train_df = pd.read_csv(processed_dir / "train_events.csv")
    val_df = pd.read_csv(processed_dir / "val_events.csv")
    test_df = pd.read_csv(processed_dir / "test_events.csv")
    scaler_artifacts = joblib.load(processed_dir / "preprocess_artifacts.joblib")

    print("  Building datasets...")
    train_ds = SessionSequenceDataset(train_df, scaler_artifacts, seq_len=SEQUENCE_LENGTH)
    val_ds = SessionSequenceDataset(val_df, scaler_artifacts, seq_len=SEQUENCE_LENGTH)
    test_ds = SessionSequenceDataset(test_df, scaler_artifacts, seq_len=SEQUENCE_LENGTH)
    print(f"  Sequences — train={len(train_ds)} val={len(val_ds)} test={len(test_ds)}")

    # Class imbalance weight.
    labels_train = np.array([s[2] for s in train_ds.samples])
    n_neg = int((labels_train == 0).sum())
    n_pos = int((labels_train == 1).sum())
    pos_weight = torch.tensor([float(n_neg / max(n_pos, 1))], dtype=torch.float32).to(device)
    print(f"  pos_weight={pos_weight.item():.2f} (n_pos={n_pos}, n_neg={n_neg})")

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False, num_workers=0)

    input_dim = len(SEQUENCE_FEATURE_COLS)
    model = GRURiskModel(input_dim=input_dim, hidden_dim=hidden_dim, num_layers=num_layers, dropout=dropout).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5, verbose=False)

    best_val_loss = float("inf")
    best_epoch = 0
    patience_counter = 0
    train_losses: list[float] = []
    val_losses: list[float] = []

    best_state = None
    t0 = time.perf_counter()

    for epoch in range(1, epochs + 1):
        tr_loss, _, _ = run_epoch(model, train_loader, criterion, optimizer=optimizer, device=device)
        val_loss, val_probs, val_labels = run_epoch(model, val_loader, criterion, device=device)
        scheduler.step(val_loss)
        train_losses.append(tr_loss)
        val_losses.append(val_loss)

        if epoch % 5 == 0 or epoch == 1:
            print(f"  Epoch {epoch:3d} | train_loss={tr_loss:.4f} val_loss={val_loss:.4f}")

        if val_loss < best_val_loss - 1e-5:
            best_val_loss = val_loss
            best_epoch = epoch
            patience_counter = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"  Early stopping at epoch {epoch} (best={best_epoch})")
                break

    train_time = time.perf_counter() - t0
    print(f"  Training time: {train_time:.1f}s | best_epoch={best_epoch}")

    # Restore best weights.
    if best_state is not None:
        model.load_state_dict(best_state)

    # Threshold selection on validation.
    model.eval()
    with torch.no_grad():
        _, val_probs, val_labels_arr = run_epoch(model, val_loader, criterion, device=device)
    best_thr, best_val_f1 = sweep_threshold(val_labels_arr, val_probs)
    print(f"  Best threshold={best_thr:.2f} (val F1={best_val_f1:.4f})")

    # Test evaluation with latency.
    t_inf = time.perf_counter()
    model.eval()
    with torch.no_grad():
        _, test_probs, test_labels_arr = run_epoch(model, test_loader, criterion, device=device)
    inf_ms = (time.perf_counter() - t_inf) * 1000 / max(len(test_ds), 1)

    _, train_probs, train_labels_arr = run_epoch(model, train_loader, criterion, device=device) if True else (None, None, None)
    with torch.no_grad():
        _, train_probs, train_labels_arr = run_epoch(model, train_loader, criterion, device=device)

    results = {
        "model": "gru",
        "disclaimer": "Synthetic data — preliminary comparison only.",
        "architecture": {
            "input_dim": input_dim,
            "hidden_dim": hidden_dim,
            "num_layers": num_layers,
            "dropout": dropout,
            "seq_len": SEQUENCE_LENGTH,
            "seq_features": SEQUENCE_FEATURE_COLS,
        },
        "best_epoch": best_epoch,
        "training_time_seconds": round(train_time, 2),
        "threshold_selection": {
            "metric": "validation_f1",
            "selected_threshold": best_thr,
            "selected_validation_f1": round(best_val_f1, 4),
        },
        "train": binary_classification_report(train_labels_arr, train_probs, threshold=best_thr),
        "val": binary_classification_report(val_labels_arr, val_probs, threshold=best_thr),
        "test": binary_classification_report(
            test_labels_arr, test_probs, threshold=best_thr,
            inference_times_ms=[inf_ms] * len(test_labels_arr),
        ),
        "primary_metric": "pr_auc",
    }

    # Save artifacts.
    out_dir.mkdir(parents=True, exist_ok=True)
    MODELS.mkdir(parents=True, exist_ok=True)
    model_path = MODELS / "gru_model.pt"
    torch.save(model.state_dict(), str(model_path))

    arch = results["architecture"]
    meta = {
        "threshold": best_thr,
        "best_epoch": best_epoch,
        "architecture": arch,
        "seq_features": SEQUENCE_FEATURE_COLS,
        "seq_len": SEQUENCE_LENGTH,
    }
    (MODELS / "gru_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    out_json = out_dir / "gru_results.json"
    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    save_curves(test_labels_arr, test_probs, "test", PLOTS)
    save_curves(val_labels_arr, val_probs, "val", PLOTS)

    # Loss curve plot.
    PLOTS.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(train_losses, label="train")
    ax.plot(val_losses, label="val")
    ax.axvline(best_epoch - 1, linestyle="--", color="red", alpha=0.6, label=f"best={best_epoch}")
    ax.set_xlabel("Epoch")
    ax.set_ylabel("BCE Loss")
    ax.set_title("GRU — Training Curve")
    ax.legend()
    fig.tight_layout()
    fig.savefig(PLOTS / "gru_loss_curve.png", dpi=120)
    plt.close(fig)

    print(f"  Model -> {model_path}")
    print(f"  Results -> {out_json}")
    print("TEST metrics:")
    print(json.dumps(results["test"], indent=2))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Train GRU sequence model for session risk")
    parser.add_argument("--processed", type=Path, default=DATA_PROCESSED)
    parser.add_argument("--out", type=Path, default=ARTIFACTS / "gru")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--patience", type=int, default=8)
    args = parser.parse_args()

    print("=== Phase 5: GRU Training ===")
    train_gru(
        args.processed,
        args.out,
        seed=args.seed,
        epochs=args.epochs,
        batch_size=args.batch_size,
        hidden_dim=args.hidden_dim,
        patience=args.patience,
    )


if __name__ == "__main__":
    main()
