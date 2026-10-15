"""Generate a documented synthetic session-event dataset.

IMPORTANT
---------
This dataset is for functional demonstration and preliminary experiments only.
It is NOT real-world validation. Do not compare scores against LANL/CERT/CIC
as if the tasks were identical (see docs/DATASET_SURVEY.md).

Label construction (multi-factor, not a single leaked column)
------------------------------------------------------------
A session window is labeled suspicious when a *combination* of latent behaviors
exceeds a composite score. Individual noisy features (e.g. high request rate
alone) can appear in normal sessions (busy legitimate users). Suspicious
sessions also include mid-session *drift*: early windows look normal, later
windows become anomalous.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

from ml.config import DATA_RAW, LABEL_COL, RANDOM_SEED, SESSION_COL, TIME_COL, USER_COL


@dataclass
class GeneratorConfig:
    n_users: int = 80
    sessions_per_user: Tuple[int, int] = (3, 8)
    events_per_session: Tuple[int, int] = (12, 40)
    suspicious_session_rate: float = 0.22
    drift_among_suspicious: float = 0.55
    seed: int = RANDOM_SEED
    start_time: str = "2025-01-01T08:00:00+00:00"


RESOURCES = [
    ("dashboard", 1),
    ("profile", 1),
    ("reports", 2),
    ("files", 2),
    ("admin_panel", 4),
    ("payroll", 5),
    ("secrets_vault", 5),
    ("audit_export", 4),
    ("api_keys", 5),
    ("public_docs", 1),
]


def _user_baseline(rng: np.random.Generator) -> Dict[str, float]:
    return {
        "req_rate": float(rng.uniform(2.0, 8.0)),
        "fail_rate": float(rng.uniform(0.0, 0.08)),
        "sens_pref": float(rng.uniform(1.0, 2.5)),
        "burstiness": float(rng.uniform(0.5, 1.5)),
        "off_hours_tol": float(rng.uniform(0.0, 0.15)),
    }


def _composite_suspicion(
    *,
    failed_login_count: float,
    requests_per_minute: float,
    unusual_context: float,
    device_trusted: float,
    sensitive_access_ratio: float,
    behavioral_deviation: float,
    event_burst_score: float,
    is_off_hours: float,
    baseline_req: float,
) -> float:
    """Latent score used only during generation. Not written as a feature."""
    rate_excess = max(0.0, requests_per_minute - baseline_req * 1.8) / max(baseline_req, 1.0)
    score = (
        0.18 * min(failed_login_count / 5.0, 1.5)
        + 0.16 * min(rate_excess, 2.0)
        + 0.14 * unusual_context
        + 0.12 * (1.0 - device_trusted)
        + 0.16 * sensitive_access_ratio
        + 0.14 * min(max(behavioral_deviation, 0.0) / 3.0, 1.5)
        + 0.10 * min(event_burst_score / 3.0, 1.5)
    )
    if is_off_hours and unusual_context:
        score += 0.08
    return float(score)


def generate_dataset(cfg: GeneratorConfig) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    rng = np.random.default_rng(cfg.seed)
    start = datetime.fromisoformat(cfg.start_time)
    event_rows: List[Dict[str, Any]] = []
    session_rows: List[Dict[str, Any]] = []

    session_counter = 0
    for user_idx in range(cfg.n_users):
        user_id = f"U{user_idx:04d}"
        baseline = _user_baseline(rng)
        n_sessions = int(rng.integers(cfg.sessions_per_user[0], cfg.sessions_per_user[1] + 1))

        for _ in range(n_sessions):
            session_counter += 1
            session_id = f"S{session_counter:06d}"
            is_suspicious_session = bool(rng.random() < cfg.suspicious_session_rate)
            has_drift = bool(
                is_suspicious_session and rng.random() < cfg.drift_among_suspicious
            )
            n_events = int(rng.integers(cfg.events_per_session[0], cfg.events_per_session[1] + 1))
            device_trusted = bool(rng.random() < (0.85 if not is_suspicious_session else 0.45))
            device_id = f"D{rng.integers(1, 40):03d}"
            context_unusual_base = float(rng.random() < (0.08 if not is_suspicious_session else 0.35))

            session_start = start + timedelta(
                days=int(rng.integers(0, 45)),
                hours=int(rng.integers(0, 24)),
                minutes=int(rng.integers(0, 60)),
            )
            auth_time = session_start
            failed_login_count = 0
            distinct_resources: set[str] = set()
            event_times: List[datetime] = []
            window_labels: List[int] = []

            # Drift: first third normal-ish, remainder elevated.
            drift_start_idx = int(n_events * 0.35) if has_drift else 0

            for event_idx in range(n_events):
                in_drift = has_drift and event_idx >= drift_start_idx
                elevate = is_suspicious_session and (in_drift or not has_drift)

                # Inter-arrival: suspicious burstiness after drift.
                if elevate:
                    delta_sec = float(rng.exponential(scale=8.0 / baseline["burstiness"]))
                else:
                    delta_sec = float(rng.exponential(scale=25.0 / baseline["burstiness"]))
                delta_sec = float(np.clip(delta_sec, 1.0, 300.0))
                if event_idx == 0:
                    event_time = session_start
                else:
                    event_time = event_times[-1] + timedelta(seconds=delta_sec)
                event_times.append(event_time)

                # Failures: noisy; normals can have occasional fails.
                fail_p = baseline["fail_rate"] + (0.25 if elevate else 0.0)
                failed = bool(rng.random() < fail_p)
                if failed:
                    failed_login_count += 1
                    resource_name, sensitivity = ("auth", 1)
                    success = False
                    event_type = "auth_failure"
                else:
                    # Resource choice biased by elevation.
                    if elevate and rng.random() < 0.45:
                        resource_name, sensitivity = RESOURCES[
                            int(rng.integers(4, len(RESOURCES)))
                        ]
                    else:
                        # Prefer low/medium sensitivity for normals.
                        weights = np.array([3, 3, 2, 2, 0.4, 0.3, 0.2, 0.3, 0.2, 3], dtype=float)
                        weights = weights / weights.sum()
                        idx = int(rng.choice(len(RESOURCES), p=weights))
                        resource_name, sensitivity = RESOURCES[idx]
                    success = True
                    event_type = "resource_access"
                    distinct_resources.add(resource_name)

                unusual_context = context_unusual_base
                if elevate and rng.random() < 0.25:
                    unusual_context = 1.0
                if (not elevate) and rng.random() < 0.03:
                    unusual_context = 1.0

                hour = event_time.hour
                is_off_hours = 1.0 if hour < 6 or hour >= 22 else 0.0

                session_duration_minutes = (event_time - auth_time).total_seconds() / 60.0
                minutes_since_auth = session_duration_minutes
                # Requests per minute over a short trailing window.
                window_start = event_time - timedelta(minutes=5)
                recent = [t for t in event_times if t >= window_start]
                requests_per_minute = len(recent) / 5.0
                access_frequency = (event_idx + 1) / max(session_duration_minutes, 0.5)

                # Behavioral deviation vs user baseline request rate (noisy).
                behavioral_deviation = (requests_per_minute - baseline["req_rate"]) / max(
                    0.5, baseline["req_rate"] * 0.5
                )
                behavioral_deviation += float(rng.normal(0.0, 0.35))

                # Burst score: coefficient of variation of recent inter-arrival.
                if len(event_times) >= 3:
                    gaps = np.diff([t.timestamp() for t in event_times[-6:]])
                    event_burst_score = float(np.std(gaps) / max(np.mean(gaps), 1.0))
                else:
                    event_burst_score = 0.0

                # Running ratios (computed after this event for cumulative features).
                # provisional placeholders updated after we know success path
                # Sensitive ratio uses distinct count so far + current.
                sens_events = sum(
                    1
                    for r in event_rows
                    if r[SESSION_COL] == session_id and r["resource_sensitivity"] >= 4
                )
                if sensitivity >= 4 and success:
                    sens_events += 1
                n_so_far = event_idx + 1
                sensitive_access_ratio = sens_events / n_so_far
                failed_auth_ratio = failed_login_count / n_so_far

                # Resource sensitivity mean/max up to now.
                prior_sens = [
                    r["resource_sensitivity"]
                    for r in event_rows
                    if r[SESSION_COL] == session_id
                ] + [sensitivity]
                resource_sensitivity_mean = float(np.mean(prior_sens))
                resource_sensitivity_max = int(np.max(prior_sens))

                latent = _composite_suspicion(
                    failed_login_count=failed_login_count,
                    requests_per_minute=requests_per_minute,
                    unusual_context=unusual_context,
                    device_trusted=1.0 if device_trusted else 0.0,
                    sensitive_access_ratio=sensitive_access_ratio,
                    behavioral_deviation=behavioral_deviation,
                    event_burst_score=event_burst_score,
                    is_off_hours=is_off_hours,
                    baseline_req=baseline["req_rate"],
                )
                # Threshold with noise; drift sessions need elevation before crossing.
                threshold = 0.72 + float(rng.normal(0.0, 0.04))
                if has_drift and not in_drift:
                    label = 0
                else:
                    label = 1 if latent >= threshold else 0
                    # Force a minority of elevated sessions to eventually be positive
                    # without copying a single feature.
                    if elevate and event_idx >= n_events - 3 and latent >= threshold * 0.85:
                        label = 1
                # Keep some elevated windows negative to avoid perfect separability.
                if label == 1 and rng.random() < 0.08:
                    label = 0

                window_labels.append(label)

                event_rows.append(
                    {
                        USER_COL: user_id,
                        SESSION_COL: session_id,
                        "event_id": f"{session_id}-E{event_idx:03d}",
                        TIME_COL: event_time.isoformat(),
                        "event_index": event_idx,
                        "event_type": event_type,
                        "resource_name": resource_name,
                        "resource_sensitivity": sensitivity,
                        "success": int(success),
                        "is_simulated": 1,
                        "device_id": device_id,
                        "device_trusted": int(device_trusted),
                        "failed_login_count": failed_login_count,
                        "requests_per_minute": round(requests_per_minute, 4),
                        "resource_sensitivity_mean": round(resource_sensitivity_mean, 4),
                        "resource_sensitivity_max": resource_sensitivity_max,
                        "minutes_since_auth": round(minutes_since_auth, 4),
                        "access_frequency": round(access_frequency, 4),
                        "unusual_context": int(unusual_context),
                        "session_duration_minutes": round(session_duration_minutes, 4),
                        "distinct_resources": len(distinct_resources),
                        "behavioral_deviation": round(behavioral_deviation, 4),
                        "hour_of_day": hour,
                        "is_off_hours": int(is_off_hours),
                        "failed_auth_ratio": round(failed_auth_ratio, 4),
                        "sensitive_access_ratio": round(sensitive_access_ratio, 4),
                        "event_burst_score": round(event_burst_score, 4),
                        "session_is_suspicious_scenario": int(is_suspicious_session),
                        "has_behavioral_drift": int(has_drift),
                        LABEL_COL: int(label),
                    }
                )

            session_rows.append(
                {
                    SESSION_COL: session_id,
                    USER_COL: user_id,
                    "n_events": n_events,
                    "session_is_suspicious_scenario": int(is_suspicious_session),
                    "has_behavioral_drift": int(has_drift),
                    "any_positive_window": int(any(window_labels)),
                    "positive_window_rate": float(np.mean(window_labels)),
                    "device_trusted": int(device_trusted),
                }
            )

    events = pd.DataFrame(event_rows)
    sessions = pd.DataFrame(session_rows)
    meta = {
        "generator": "ml/generate_synthetic.py",
        "config": asdict(cfg),
        "n_events": int(len(events)),
        "n_sessions": int(len(sessions)),
        "n_users": int(events[USER_COL].nunique()),
        "positive_window_rate": float(events[LABEL_COL].mean()),
        "suspicious_session_rate": float(sessions["session_is_suspicious_scenario"].mean()),
        "drift_session_rate": float(sessions["has_behavioral_drift"].mean()),
        "disclaimer": (
            "Synthetic data for demonstration/preliminary experiments only. "
            "Not real-world validation."
        ),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    return events, sessions, meta


def save_dataset(
    events: pd.DataFrame,
    sessions: pd.DataFrame,
    meta: Dict[str, Any],
    out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    events_path = out_dir / "session_events.csv"
    sessions_path = out_dir / "sessions.csv"
    meta_path = out_dir / "dataset_meta.json"
    events.to_csv(events_path, index=False)
    sessions.to_csv(sessions_path, index=False)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Wrote {events_path} ({len(events)} rows)")
    print(f"Wrote {sessions_path} ({len(sessions)} rows)")
    print(f"Wrote {meta_path}")
    print(
        f"Positive window rate={meta['positive_window_rate']:.3f} | "
        f"suspicious sessions={meta['suspicious_session_rate']:.3f} | "
        f"drift sessions={meta['drift_session_rate']:.3f}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic Zero-Trust session dataset")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--n-users", type=int, default=80)
    parser.add_argument("--out", type=Path, default=DATA_RAW)
    args = parser.parse_args()

    cfg = GeneratorConfig(seed=args.seed, n_users=args.n_users)
    events, sessions, meta = generate_dataset(cfg)
    save_dataset(events, sessions, meta, args.out)


if __name__ == "__main__":
    main()
