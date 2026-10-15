"""Transparent rule-based baseline for session-risk windows.

This baseline is an engineering comparator, NOT the research contribution.

Rules and thresholds (documented)
---------------------------------
A window is scored by summing weighted rule hits, then mapped to [0, 1]:

R1  failed_login_count >= 3                         weight 0.20
R2  requests_per_minute >= 12                        weight 0.15
R3  device_trusted == 0                              weight 0.15
R4  unusual_context == 1                             weight 0.15
R5  sensitive_access_ratio >= 0.40                   weight 0.15
R6  behavioral_deviation >= 2.0                      weight 0.10
R7  is_off_hours == 1 AND unusual_context == 1       weight 0.10

Decision threshold on the resulting score: 0.35 (tuned conceptually for
recall-oriented security demos; formal threshold selection for ML models
uses validation data in Phases 5–6).

These numeric cutoffs are provisional engineering choices, not experimentally
validated security boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from ml.config import TABULAR_FEATURES


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    weight: float


RULES: List[Rule] = [
    Rule("R1_failed_logins", "failed_login_count >= 3", 0.20),
    Rule("R2_request_rate", "requests_per_minute >= 12", 0.15),
    Rule("R3_untrusted_device", "device_trusted == 0", 0.15),
    Rule("R4_unusual_context", "unusual_context == 1", 0.15),
    Rule("R5_sensitive_ratio", "sensitive_access_ratio >= 0.40", 0.15),
    Rule("R6_behavioral_deviation", "behavioral_deviation >= 2.0", 0.10),
    Rule("R7_off_hours_context", "is_off_hours == 1 AND unusual_context == 1", 0.10),
]

DEFAULT_DECISION_THRESHOLD = 0.35


def rule_hits(row: pd.Series) -> Dict[str, bool]:
    return {
        "R1_failed_logins": float(row["failed_login_count"]) >= 3,
        "R2_request_rate": float(row["requests_per_minute"]) >= 12,
        "R3_untrusted_device": float(row["device_trusted"]) == 0,
        "R4_unusual_context": float(row["unusual_context"]) == 1,
        "R5_sensitive_ratio": float(row["sensitive_access_ratio"]) >= 0.40,
        "R6_behavioral_deviation": float(row["behavioral_deviation"]) >= 2.0,
        "R7_off_hours_context": float(row["is_off_hours"]) == 1
        and float(row["unusual_context"]) == 1,
    }


def score_frame(df: pd.DataFrame) -> np.ndarray:
    missing = [c for c in TABULAR_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f"Rule baseline missing columns: {missing}")

    weights = {r.name: r.weight for r in RULES}
    scores = np.zeros(len(df), dtype=float)
    for i, (_, row) in enumerate(df.iterrows()):
        hits = rule_hits(row)
        scores[i] = sum(weights[name] for name, hit in hits.items() if hit)
    # Already in [0, 1] because weights sum to 1.0
    return np.clip(scores, 0.0, 1.0)


def predict_proba(df: pd.DataFrame) -> np.ndarray:
    """Return P(suspicious) proxy scores in [0, 1]."""
    return score_frame(df)


def explain_row(row: pd.Series) -> Dict[str, Any]:
    hits = rule_hits(row)
    fired = [name for name, hit in hits.items() if hit]
    score = float(sum(r.weight for r in RULES if hits[r.name]))
    return {
        "score": score,
        "fired_rules": fired,
        "all_hits": hits,
    }


def rules_documentation() -> List[Dict[str, Any]]:
    return [
        {"name": r.name, "description": r.description, "weight": r.weight} for r in RULES
    ]
