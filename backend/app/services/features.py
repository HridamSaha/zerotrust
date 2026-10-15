"""Feature extraction from live session events for ML inference.

Mirrors the feature engineering in ml/generate_synthetic.py so that
live inference uses the same feature schema as training.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np


def extract_tabular_features(
    *,
    events: List[Dict[str, Any]],
    current_event: Dict[str, Any],
    session_start: datetime,
) -> Dict[str, float]:
    """Compute tabular features from a session's event history + current event.

    Parameters
    ----------
    events:
        List of past event dicts (including current) sorted chronologically.
        Each dict should have: event_type, resource_sensitivity, success,
        unusual_context, device_trusted, created_at (datetime or ISO string).
    current_event:
        The triggering event (also present at the end of `events`).
    session_start:
        UTC datetime when the session was created.

    Returns
    -------
    dict matching TABULAR_FEATURES from ml/config.py
    """
    now = _parse_dt(current_event.get("created_at")) or datetime.now(timezone.utc)
    session_duration_minutes = (now - session_start).total_seconds() / 60.0

    # Parse all event timestamps.
    event_times: List[datetime] = []
    for ev in events:
        t = _parse_dt(ev.get("created_at"))
        if t:
            event_times.append(t)
    if not event_times:
        event_times = [now]

    # Requests per minute over trailing 5-minute window.
    window_start_ts = now.timestamp() - 300.0
    recent_count = sum(1 for t in event_times if t.timestamp() >= window_start_ts)
    requests_per_minute = recent_count / 5.0

    # Access frequency (events per minute of session).
    access_frequency = len(events) / max(session_duration_minutes, 0.5)

    # Failed login count.
    failed_login_count = sum(
        1 for ev in events
        if ev.get("event_type") == "auth_failure" or not ev.get("success", True)
    )
    failed_auth_ratio = failed_login_count / max(len(events), 1)

    # Sensitive access ratio (sensitivity >= 4).
    sens_events = sum(1 for ev in events if int(ev.get("resource_sensitivity", 1)) >= 4)
    sensitive_access_ratio = sens_events / max(len(events), 1)

    # Resource sensitivity mean and max.
    sensitivities = [int(ev.get("resource_sensitivity", 1)) for ev in events]
    resource_sensitivity_mean = float(np.mean(sensitivities)) if sensitivities else 1.0
    resource_sensitivity_max = int(np.max(sensitivities)) if sensitivities else 1

    # Distinct resources.
    distinct_resources = len({ev.get("resource_name") for ev in events if ev.get("resource_name")})

    # Device trusted (from most recent event).
    device_trusted = float(int(bool(current_event.get("device_trusted", True))))

    # Unusual context.
    unusual_context = float(int(bool(current_event.get("unusual_context", False))))

    # Minutes since auth.
    minutes_since_auth = session_duration_minutes

    # Hour of day and off-hours flag.
    hour_of_day = now.hour
    is_off_hours = float(1 if hour_of_day < 6 or hour_of_day >= 22 else 0)

    # Behavioral deviation: compare recent request rate to session average.
    avg_rate = access_frequency
    if session_duration_minutes > 2:
        behavioral_deviation = (requests_per_minute - avg_rate) / max(0.5, avg_rate * 0.5)
    else:
        behavioral_deviation = 0.0

    # Event burst score: CoV of recent inter-arrival times.
    if len(event_times) >= 3:
        recent_times = sorted(event_times)[-6:]
        gaps = np.diff([t.timestamp() for t in recent_times])
        event_burst_score = float(np.std(gaps) / max(np.mean(gaps), 1.0))
    else:
        event_burst_score = 0.0

    event_index = len(events) - 1

    return {
        "failed_login_count": float(failed_login_count),
        "requests_per_minute": round(requests_per_minute, 4),
        "resource_sensitivity_mean": round(resource_sensitivity_mean, 4),
        "resource_sensitivity_max": float(resource_sensitivity_max),
        "device_trusted": device_trusted,
        "minutes_since_auth": round(minutes_since_auth, 4),
        "access_frequency": round(access_frequency, 4),
        "unusual_context": unusual_context,
        "session_duration_minutes": round(session_duration_minutes, 4),
        "distinct_resources": float(distinct_resources),
        "behavioral_deviation": round(behavioral_deviation, 4),
        "hour_of_day": float(hour_of_day),
        "is_off_hours": is_off_hours,
        "failed_auth_ratio": round(failed_auth_ratio, 4),
        "sensitive_access_ratio": round(sensitive_access_ratio, 4),
        "event_burst_score": round(event_burst_score, 4),
        "event_index": float(event_index),
    }


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None
    return None
