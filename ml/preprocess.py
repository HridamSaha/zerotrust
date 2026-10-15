"""Validate, split, and transform session-event features without leakage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from ml.config import (
    DATA_PROCESSED,
    DATA_RAW,
    LABEL_COL,
    RANDOM_SEED,
    SESSION_COL,
    TABULAR_FEATURES,
    TIME_COL,
    USER_COL,
)

REQUIRED_COLUMNS = [
    USER_COL,
    SESSION_COL,
    TIME_COL,
    LABEL_COL,
    *TABULAR_FEATURES,
]


class PreprocessArtifacts:
    def __init__(self, scaler: StandardScaler, feature_columns: list[str]):
        self.scaler = scaler
        self.feature_columns = feature_columns

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.feature_columns if c not in frame.columns]
        if missing:
            raise ValueError(f"Missing feature columns: {missing}")
        values = frame[self.feature_columns].astype(float).to_numpy()
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
        return self.scaler.transform(values)


def validate_schema(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")
    out = df.copy()
    out[TIME_COL] = pd.to_datetime(out[TIME_COL], utc=True, format="ISO8601")
    out[LABEL_COL] = out[LABEL_COL].astype(int)
    for col in TABULAR_FEATURES:
        out[col] = pd.to_numeric(out[col], errors="coerce")
    # Invalid / missing numerics → median within session then 0
    null_counts = out[TABULAR_FEATURES].isna().sum().to_dict()
    out[TABULAR_FEATURES] = out.groupby(SESSION_COL)[TABULAR_FEATURES].transform(
        lambda s: s.fillna(s.median())
    )
    out[TABULAR_FEATURES] = out[TABULAR_FEATURES].fillna(0.0)
    out.attrs["null_counts_before_impute"] = null_counts
    return out.sort_values([SESSION_COL, TIME_COL, "event_index"]).reset_index(drop=True)


def session_level_label(df: pd.DataFrame) -> pd.Series:
    """Any positive window ⇒ suspicious session (for stratified grouping)."""
    return df.groupby(SESSION_COL)[LABEL_COL].max()


def split_by_session(
    df: pd.DataFrame,
    *,
    seed: int = RANDOM_SEED,
    test_size: float = 0.20,
    val_size: float = 0.20,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Group-aware split: entire sessions stay in one partition.

    Also ensures users in the test set are not required to appear in train
    (sessions are atomic; users may appear in multiple splits only if they
    have multiple sessions — we further filter to reduce user leakage by
    splitting on user groups when possible).
    """
    # Prefer splitting by user to prevent user leakage across partitions.
    users = df[USER_COL].unique()
    user_labels = (
        df.groupby(USER_COL)[LABEL_COL].max().reindex(users).fillna(0).astype(int)
    )
    gss_test = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_val_idx, test_idx = next(
        gss_test.split(users, user_labels, groups=users)
    )
    users_train_val = users[train_val_idx]
    users_test = users[test_idx]

    # Validation split from remaining users.
    y_tv = user_labels.loc[users_train_val]
    # val_size relative to full data ≈ val_size / (1 - test_size) of train_val
    relative_val = val_size / max(1e-6, (1.0 - test_size))
    gss_val = GroupShuffleSplit(n_splits=1, test_size=relative_val, random_state=seed + 1)
    train_idx, val_idx = next(
        gss_val.split(users_train_val, y_tv, groups=users_train_val)
    )
    users_train = users_train_val[train_idx]
    users_val = users_train_val[val_idx]

    train = df[df[USER_COL].isin(users_train)].copy()
    val = df[df[USER_COL].isin(users_val)].copy()
    test = df[df[USER_COL].isin(users_test)].copy()

    # Guarantee no session overlap (should already hold via user split).
    assert set(train[SESSION_COL]).isdisjoint(val[SESSION_COL])
    assert set(train[SESSION_COL]).isdisjoint(test[SESSION_COL])
    assert set(val[SESSION_COL]).isdisjoint(test[SESSION_COL])
    assert set(train[USER_COL]).isdisjoint(val[USER_COL])
    assert set(train[USER_COL]).isdisjoint(test[USER_COL])
    assert set(val[USER_COL]).isdisjoint(test[USER_COL])

    meta = {
        "split_unit": "user_id",
        "seed": seed,
        "test_size": test_size,
        "val_size": val_size,
        "n_users_train": int(len(users_train)),
        "n_users_val": int(len(users_val)),
        "n_users_test": int(len(users_test)),
        "n_sessions_train": int(train[SESSION_COL].nunique()),
        "n_sessions_val": int(val[SESSION_COL].nunique()),
        "n_sessions_test": int(test[SESSION_COL].nunique()),
        "n_events_train": int(len(train)),
        "n_events_val": int(len(val)),
        "n_events_test": int(len(test)),
        "positive_rate_train": float(train[LABEL_COL].mean()),
        "positive_rate_val": float(val[LABEL_COL].mean()),
        "positive_rate_test": float(test[LABEL_COL].mean()),
    }
    return train, val, test, meta


def fit_scaler(train: pd.DataFrame) -> PreprocessArtifacts:
    scaler = StandardScaler()
    x = train[TABULAR_FEATURES].astype(float).to_numpy()
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    scaler.fit(x)
    return PreprocessArtifacts(scaler=scaler, feature_columns=list(TABULAR_FEATURES))


def class_imbalance_report(df: pd.DataFrame) -> Dict[str, Any]:
    counts = df[LABEL_COL].value_counts().to_dict()
    n = len(df)
    pos = int(counts.get(1, 0))
    neg = int(counts.get(0, 0))
    return {
        "n_events": n,
        "n_positive": pos,
        "n_negative": neg,
        "positive_rate": float(pos / n) if n else 0.0,
        "negative_rate": float(neg / n) if n else 0.0,
        "imbalance_ratio_neg_pos": float(neg / pos) if pos else None,
    }


def run_preprocess(
    raw_events_path: Path,
    out_dir: Path,
    *,
    seed: int = RANDOM_SEED,
) -> Dict[str, Any]:
    raw = pd.read_csv(raw_events_path)
    df = validate_schema(raw)
    train, val, test, split_meta = split_by_session(df, seed=seed)
    artifacts = fit_scaler(train)

    out_dir.mkdir(parents=True, exist_ok=True)
    train.to_csv(out_dir / "train_events.csv", index=False)
    val.to_csv(out_dir / "val_events.csv", index=False)
    test.to_csv(out_dir / "test_events.csv", index=False)
    joblib.dump(artifacts, out_dir / "preprocess_artifacts.joblib")

    report = {
        "disclaimer": "Synthetic pipeline — not real-world validation.",
        "features": TABULAR_FEATURES,
        "split": split_meta,
        "imbalance": {
            "train": class_imbalance_report(train),
            "val": class_imbalance_report(val),
            "test": class_imbalance_report(test),
            "all": class_imbalance_report(df),
        },
        "null_counts_before_impute": df.attrs.get("null_counts_before_impute", {}),
    }
    (out_dir / "preprocess_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess session-event dataset")
    parser.add_argument("--input", type=Path, default=DATA_RAW / "session_events.csv")
    parser.add_argument("--out", type=Path, default=DATA_PROCESSED)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()
    report = run_preprocess(args.input, args.out, seed=args.seed)
    print(json.dumps(report["imbalance"], indent=2))
    print(json.dumps(report["split"], indent=2))


if __name__ == "__main__":
    main()
