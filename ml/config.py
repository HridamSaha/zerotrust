"""Shared ML configuration and paths."""

from __future__ import annotations

from pathlib import Path

# Project root: .../zerotrust
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_RAW = PROJECT_ROOT / "ml" / "data" / "raw"
DATA_PROCESSED = PROJECT_ROOT / "ml" / "data" / "processed"
ARTIFACTS = PROJECT_ROOT / "ml" / "artifacts"
PLOTS = ARTIFACTS / "plots"
MODELS = ARTIFACTS / "models"

RANDOM_SEED = 42

# Provisional engineering thresholds (same spirit as backend policy config).
RISK_LOW_MAX = 24
RISK_MEDIUM_MAX = 49
RISK_HIGH_MAX = 74

# Structured tabular feature columns used by LightGBM / rule baseline / fusion.
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

LABEL_COL = "label_suspicious"
SESSION_COL = "session_id"
USER_COL = "user_id"
TIME_COL = "event_time"

# Sequence settings for GRU (Phase 5); defined here for shared schema docs.
SEQUENCE_LENGTH = 16
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
